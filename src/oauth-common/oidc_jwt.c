/*
 * Shared OIDC core for PgBouncer's OAuth validator modules.  See oidc_jwt.h.
 */

#include "oidc_jwt.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "oidc_crypto.h"

#define OIDC_SET_ERR(buf, len, ...) \
	do { \
		if ((buf) && (len) > 0) \
		snprintf((buf), (len), __VA_ARGS__); \
	} while (0)

/*
 * A signing key from the provider JWKS.
 */
struct oidc_jwks_key {
	char *kid;
	EVP_PKEY *pkey;
};

struct oidc_jwks_cache {
	char *url;
	int min_refresh;
	struct oidc_tls_opts tls;

	/*
	 * Guards everything below; held across a refetch so that a burst of logins
	 * produces one request rather than one per worker.
	 * */
	pthread_mutex_t mutex;
	struct oidc_jwks_key *keys;
	int nkeys;
	time_t last_fetch;
};

/*
 * Claim checking.
 */

/* Return the string value of a claim, or NULL if absent or not a string. */
static const char *claim_string(json_t *claims, const char *name)
{
	json_t *v = json_object_get(claims, name);

	return json_is_string(v) ? json_string_value(v) : NULL;
}

/* "aud" is either a string or an array of them. */
static bool audience_matches(json_t *claims, char **wanted, int nwanted)
{
	json_t *aud = json_object_get(claims, "aud");

	for (int i = 0; i < nwanted; i++) {
		if (json_is_string(aud)) {
			if (strcmp(json_string_value(aud), wanted[i]) == 0)
				return true;
		} else if (json_is_array(aud)) {
			size_t idx;
			json_t *entry;

			json_array_foreach(aud, idx, entry) {
				if (json_is_string(entry) &&
				    strcmp(json_string_value(entry), wanted[i]) == 0)
					return true;
			}
		}
	}

	return false;
}

/* True if a string-array claim contains wanted. */
static bool array_claim_contains(json_t *claims, const char *name, const char *wanted)
{
	json_t *arr = json_object_get(claims, name);
	size_t idx;
	json_t *entry;

	if (json_is_string(arr))
		return strcmp(json_string_value(arr), wanted) == 0;

	if (!json_is_array(arr))
		return false;

	json_array_foreach(arr, idx, entry) {
		if (json_is_string(entry) && strcmp(json_string_value(entry), wanted) == 0)
			return true;
	}

	return false;
}

/* The scope claim is a space-separated list. */
static bool scope_present(const char *scope_claim, const char *wanted)
{
	size_t wantedlen = strlen(wanted);
	const char *p = scope_claim;

	while (*p) {
		const char *end;

		while (*p == ' ')
			p++;
		if (!*p)
			break;
		end = strchr(p, ' ');
		if (!end)
			end = p + strlen(p);
		if ((size_t)(end - p) == wantedlen && memcmp(p, wanted, wantedlen) == 0)
			return true;
		p = end;
	}

	return false;
}

bool oidc_claims_check(json_t *claims, const struct oidc_claims_policy *policy,
		       char **authn_id, char *errbuf, size_t errlen)
{
	const char *identity;
	json_t *exp, *nbf;
	time_t now = time(NULL);

	*authn_id = NULL;

	if (!json_is_object(claims)) {
		OIDC_SET_ERR(errbuf, errlen, "claims are not a JSON object");
		return false;
	}

	/*
	 * Expiry is mandatory.  A token without one would be accepted forever,
	 * so treat its absence as a malformed token rather than as "no limit".
	 */
	exp = json_object_get(claims, "exp");
	if (!json_is_integer(exp)) {
		OIDC_SET_ERR(errbuf, errlen, "token has no \"exp\" claim");
		return false;
	}
	if (now > (time_t)json_integer_value(exp) + policy->clock_skew) {
		OIDC_SET_ERR(errbuf, errlen, "token expired");
		return false;
	}

	nbf = json_object_get(claims, "nbf");
	if (json_is_integer(nbf) && now + policy->clock_skew < (time_t)json_integer_value(nbf)) {
		OIDC_SET_ERR(errbuf, errlen, "token is not valid yet");
		return false;
	}

	if (policy->issuer) {
		const char *iss = claim_string(claims, "iss");

		if (!iss || strcmp(iss, policy->issuer) != 0) {
			OIDC_SET_ERR(errbuf, errlen, "token issuer \"%s\" is not the configured issuer",
				     iss ? iss : "(none)");
			return false;
		}
	}

	if (policy->naudiences > 0 &&
	    !audience_matches(claims, policy->audiences, policy->naudiences)) {
		OIDC_SET_ERR(errbuf, errlen, "token audience does not include the configured audience");
		return false;
	}

	for (int i = 0; i < policy->nrequired; i++) {
		const char *name = policy->required[i].name;
		const char *have = claim_string(claims, name);

		if (!have || strcmp(have, policy->required[i].value) != 0) {
			OIDC_SET_ERR(errbuf, errlen, "token \"%s\" is \"%s\", not the expected \"%s\"",
				     name, have ? have : "(none)", policy->required[i].value);
			return false;
		}
	}

	if (policy->nscopes > 0) {
		const char *name = policy->scope_claim ? policy->scope_claim : "scope";
		const char *scope = claim_string(claims, name);

		for (int i = 0; i < policy->nscopes; i++) {
			if (!scope || !scope_present(scope, policy->scopes[i])) {
				OIDC_SET_ERR(errbuf, errlen, "token is missing required scope \"%s\"",
					     policy->scopes[i]);
				return false;
			}
		}
	}

	if (policy->nroles > 0 && policy->role_claim) {
		for (int i = 0; i < policy->nroles; i++) {
			if (!array_claim_contains(claims, policy->role_claim, policy->roles[i])) {
				OIDC_SET_ERR(errbuf, errlen, "token is missing required role \"%s\"",
					     policy->roles[i]);
				return false;
			}
		}
	}

	/*
	 * The identity comes from the first of the configured claims the token
	 * actually carries, so that one policy can cover principals the provider
	 * describes differently.
	 */
	identity = NULL;
	for (int i = 0; i < policy->nauthn_claims && !identity; i++) {
		const char *val = claim_string(claims, policy->authn_claims[i]);

		if (val && *val)
			identity = val;
	}
	if (!identity) {
		OIDC_SET_ERR(errbuf, errlen, "token carries none of the %d claim(s) the identity is taken from",
			     policy->nauthn_claims);
		return false;
	}

	*authn_id = strdup(identity);
	if (!*authn_id) {
		OIDC_SET_ERR(errbuf, errlen, "out of memory");
		return false;
	}

	return true;
}

/*
 * JWKS cache.
 */

struct oidc_jwks_cache *oidc_jwks_new(const char *url, int min_refresh,
				      const struct oidc_tls_opts *tls)
{
	struct oidc_jwks_cache *cache = calloc(1, sizeof(*cache));

	if (!cache)
		return NULL;

	cache->url = strdup(url);
	if (!cache->url) {
		free(cache);
		return NULL;
	}
	cache->min_refresh = min_refresh;
	cache->tls = *tls;
	if (pthread_mutex_init(&cache->mutex, NULL) != 0) {
		free(cache->url);
		free(cache);
		return NULL;
	}

	return cache;
}

static void free_keys(struct oidc_jwks_cache *cache)
{
	for (int i = 0; i < cache->nkeys; i++) {
		free(cache->keys[i].kid);
		EVP_PKEY_free(cache->keys[i].pkey);
	}

	free(cache->keys);
	cache->keys = NULL;
	cache->nkeys = 0;
}

void oidc_jwks_free(struct oidc_jwks_cache *cache)
{
	if (!cache)
		return;

	free_keys(cache);
	pthread_mutex_destroy(&cache->mutex);
	free(cache->url);
	free(cache);
}

/* Parse a JWKS document into the cache.  Called with the mutex held. */
static bool load_jwks(struct oidc_jwks_cache *cache, const char *body,
		      char *errbuf, size_t errlen)
{
	json_error_t jerr;
	json_t *doc, *keys;
	struct oidc_jwks_key *parsed;
	size_t idx;
	json_t *jwk;
	int n = 0;
	size_t count;

	doc = json_loads(body, 0, &jerr);
	if (!doc) {
		OIDC_SET_ERR(errbuf, errlen, "JWKS is not valid JSON: %s", jerr.text);
		return false;
	}

	keys = json_object_get(doc, "keys");
	if (!json_is_array(keys)) {
		OIDC_SET_ERR(errbuf, errlen, "JWKS has no \"keys\" array");
		json_decref(doc);
		return false;
	}

	count = json_array_size(keys);
	parsed = calloc(count ? count : 1, sizeof(*parsed));
	if (!parsed) {
		OIDC_SET_ERR(errbuf, errlen, "out of memory");
		json_decref(doc);
		return false;
	}

	json_array_foreach(keys, idx, jwk) {
		const char *use = claim_string(jwk, "use");
		const char *kid = claim_string(jwk, "kid");
		const char *alg = claim_string(jwk, "alg");
		EVP_PKEY *pkey;

		/* Encryption keys share the document with signing keys. */
		if (use && strcmp(use, "sig") != 0)
			continue;
		/* Skip key types and algorithms we would never accept anyway. */
		if (alg && !oidc_alg_supported(alg))
			continue;

		pkey = oidc_jwk_to_pkey(claim_string(jwk, "kty"),
					claim_string(jwk, "n"), claim_string(jwk, "e"),
					claim_string(jwk, "crv"),
					claim_string(jwk, "x"), claim_string(jwk, "y"),
					NULL, 0);
		if (!pkey)
			continue;

		parsed[n].kid = kid ? strdup(kid) : NULL;
		parsed[n].pkey = pkey;
		n++;
	}

	json_decref(doc);

	if (n == 0) {
		OIDC_SET_ERR(errbuf, errlen, "JWKS contains no usable signing key");
		free(parsed);
		return false;
	}

	free_keys(cache);
	cache->keys = parsed;
	cache->nkeys = n;
	cache->last_fetch = time(NULL);

	return true;
}

/* Fetch and install the JWKS.  Called with the mutex held. */
static bool refresh_jwks(struct oidc_jwks_cache *cache, int timeout_ms,
			 char *errbuf, size_t errlen)
{
	struct oidc_http_response resp;
	bool ok;

	if (!oidc_http_get(cache->url, &cache->tls, timeout_ms, &resp, errbuf, errlen))
		return false;

	if (resp.status != 200) {
		OIDC_SET_ERR(errbuf, errlen, "JWKS endpoint %s returned HTTP %ld",
			     cache->url, resp.status);
		oidc_http_response_free(&resp);
		/* Remember the attempt so a failing endpoint is not hammered. */
		cache->last_fetch = time(NULL);
		return false;
	}

	ok = load_jwks(cache, resp.body ? resp.body : "", errbuf, errlen);
	if (!ok)
		cache->last_fetch = time(NULL);
	oidc_http_response_free(&resp);

	return ok;
}

/* Find a key by id, or the only key when the token names none.  Mutex held. */
static EVP_PKEY *lookup_key(struct oidc_jwks_cache *cache, const char *kid)
{
	if (!kid) {
		if (cache->nkeys == 1)
			return cache->keys[0].pkey;
		return NULL;
	}

	for (int i = 0; i < cache->nkeys; i++) {
		if (cache->keys[i].kid && strcmp(cache->keys[i].kid, kid) == 0)
			return cache->keys[i].pkey;
	}

	return NULL;
}

/*
 * Return the signing key for kid, fetching or refreshing the JWKS if needed.
 * The caller owns a reference and frees it with EVP_PKEY_free().
 */
static EVP_PKEY *get_key(struct oidc_jwks_cache *cache, const char *kid, int timeout_ms,
			 bool *internal, char *errbuf, size_t errlen)
{
	EVP_PKEY *pkey;

	pthread_mutex_lock(&cache->mutex);

	pkey = lookup_key(cache, kid);
	if (!pkey) {
		/*
		 * Either we have never fetched, or the provider has rotated its
		 * keys.  Refetch, but no more often than min_refresh, so unknown
		 * key ids cannot be used to generate traffic.
		 */
		time_t now = time(NULL);

		if (cache->nkeys == 0 || now - cache->last_fetch >= cache->min_refresh) {
			if (refresh_jwks(cache, timeout_ms, errbuf, errlen))
				pkey = lookup_key(cache, kid);
			else
				*internal = true;	/* the provider, not the token */
		} else {
			OIDC_SET_ERR(errbuf, errlen,
				     "no signing key \"%s\" in the cached JWKS", kid ? kid : "(none)");
		}
	}

	if (pkey && EVP_PKEY_up_ref(pkey) != 1)
		pkey = NULL;

	pthread_mutex_unlock(&cache->mutex);

	if (!pkey && errbuf && !errbuf[0])
		OIDC_SET_ERR(errbuf, errlen, "no signing key for key id \"%s\"", kid ? kid : "(none)");

	return pkey;
}

/*
 * JWT verification.
 */

/* Decode a base64url segment into a JSON object. */
static json_t *decode_json_segment(const char *seg, size_t seglen, const char *what,
				   char *errbuf, size_t errlen)
{
	unsigned char *raw;
	size_t rawlen;
	json_error_t jerr;
	json_t *obj;

	raw = oidc_base64url_decode(seg, seglen, &rawlen);
	if (!raw) {
		OIDC_SET_ERR(errbuf, errlen, "token %s is not valid base64url", what);
		return NULL;
	}

	obj = json_loadb((const char *)raw, rawlen, 0, &jerr);
	free(raw);
	if (!obj) {
		OIDC_SET_ERR(errbuf, errlen, "token %s is not valid JSON: %s", what, jerr.text);
		return NULL;
	}
	if (!json_is_object(obj)) {
		OIDC_SET_ERR(errbuf, errlen, "token %s is not a JSON object", what);
		json_decref(obj);
		return NULL;
	}

	return obj;
}

bool oidc_jwt_verify(const char *token, struct oidc_jwks_cache *jwks,
		     const struct oidc_claims_policy *policy, int timeout_ms,
		     char **authn_id, bool *internal, char *errbuf, size_t errlen)
{
	const char *dot1, *dot2;
	json_t *header = NULL, *claims = NULL;
	EVP_PKEY *pkey = NULL;
	unsigned char *sig = NULL;
	size_t siglen = 0;
	const char *alg, *kid, *typ;
	bool ok = false;

	*authn_id = NULL;
	*internal = false;
	if (errbuf && errlen > 0)
		errbuf[0] = '\0';

	/* Compact serialization: header.payload.signature */
	dot1 = strchr(token, '.');
	if (!dot1) {
		OIDC_SET_ERR(errbuf, errlen, "token is not a JWT");
		return false;
	}
	dot2 = strchr(dot1 + 1, '.');
	if (!dot2 || strchr(dot2 + 1, '.')) {
		OIDC_SET_ERR(errbuf, errlen, "token is not a JWT");
		return false;
	}

	header = decode_json_segment(token, dot1 - token, "header", errbuf, errlen);
	if (!header)
		goto out;

	/*
	 * The header is attacker-controlled, so nothing in it is trusted beyond
	 * selecting among the provider own keys: the algorithm is checked
	 * against a fixed list (which excludes "none" and the HMAC family), and
	 * the key comes from the JWKS, never from the token.
	 */
	typ = claim_string(header, "typ");
	if (typ && strcasecmp(typ, "JWT") != 0 && strcasecmp(typ, "at+jwt") != 0 &&
	    strcasecmp(typ, "application/at+jwt") != 0) {
		OIDC_SET_ERR(errbuf, errlen, "unexpected token type \"%s\"", typ);
		goto out;
	}

	alg = claim_string(header, "alg");
	if (!oidc_alg_supported(alg)) {
		OIDC_SET_ERR(errbuf, errlen, "unsupported token algorithm \"%s\"",
			     alg ? alg : "(none)");
		goto out;
	}
	kid = claim_string(header, "kid");

	pkey = get_key(jwks, kid, timeout_ms, internal, errbuf, errlen);
	if (!pkey)
		goto out;

	sig = oidc_base64url_decode(dot2 + 1, strlen(dot2 + 1), &siglen);
	if (!sig || siglen == 0) {
		OIDC_SET_ERR(errbuf, errlen, "token signature is not valid base64url");
		goto out;
	}

	if (!oidc_jws_verify(pkey, alg, token, (size_t)(dot2 - token), sig, siglen, errbuf, errlen))
		goto out;

	claims = decode_json_segment(dot1 + 1, dot2 - dot1 - 1, "payload", errbuf, errlen);
	if (!claims)
		goto out;

	ok = oidc_claims_check(claims, policy, authn_id, errbuf, errlen);

out:
	free(sig);
	EVP_PKEY_free(pkey);
	json_decref(header);
	json_decref(claims);

	return ok;
}
