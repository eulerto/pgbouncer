/*
 * Unit tests for the shared OIDC core used by PgBouncer's OAuth validator
 * modules.
 *
 * These need no identity provider: the tests mint their own signing keys,
 * serve a JWKS from a throwaway HTTP server on localhost (see oidc_testutil.c)
 * and sign tokens with the matching private key.  That covers everything
 * except talking to a real provider: base64url, JWK to key conversion,
 * signature verification for the RSA and ECDSA families, the claim policy,
 * and the JWKS cache.
 *
 *   make check
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <jansson.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>

#include "oidc_crypto.h"
#include "oidc_jwt.h"
#include "oidc_testutil.h"

#define TEST_ISSUER "https://idp.example.test/realms/test"

static int tests_run;

#define CHECK(cond) do { \
		tests_run++; \
		if (!(cond)) { \
			fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
			exit(1); \
		} \
} while (0)

static char *claims_json(long exp, const char *iss, const char *aud,
			 const char *scope, const char *user)
{
	json_t *obj = json_pack("{s:I, s:s, s:s, s:s, s:s}",
				"exp", (json_int_t)exp,
				"iss", iss, "aud", aud,
				"scope", scope,
				"preferred_username", user);
	char *out = json_dumps(obj, JSON_COMPACT);

	json_decref(obj);

	return out;
}

/*
 * Tests.
 */

static void test_base64url(void)
{
	size_t len = 0;
	unsigned char *out;
	char *enc;

	/* Known vector: the standard JWT header for RS256. */
	out = oidc_base64url_decode("eyJhbGciOiJSUzI1NiJ9", 20, &len);
	CHECK(out != NULL);
	CHECK(len == 15);
	CHECK(strcmp((char *)out, "{\"alg\":\"RS256\"}") == 0);
	free(out);

	/* Round trip, including lengths that need 1 and 2 padding bytes. */
	for (int n = 1; n <= 8; n++) {
		unsigned char buf[8];

		for (int i = 0; i < n; i++)
			buf[i] = (unsigned char)(i * 37 + 11);
		enc = oidc_base64url_encode(buf, (size_t)n);
		CHECK(enc != NULL);
		CHECK(strchr(enc, '=') == NULL);	/* no padding */
		CHECK(strchr(enc, '+') == NULL && strchr(enc, '/') == NULL);
		out = oidc_base64url_decode(enc, strlen(enc), &len);
		CHECK(out != NULL && len == (size_t)n && memcmp(out, buf, (size_t)n) == 0);
		free(out);
		free(enc);
	}

	/* Standard base64 characters and stray padding are not base64url. */
	CHECK(oidc_base64url_decode("ab+d", 4, &len) == NULL);
	CHECK(oidc_base64url_decode("ab/d", 4, &len) == NULL);
	CHECK(oidc_base64url_decode("abc=", 4, &len) == NULL);
	/* A trailing group of one character cannot occur. */
	CHECK(oidc_base64url_decode("abcde", 5, &len) == NULL);
}

static void test_alg_allowlist(void)
{
	/* An unsigned token must never be accepted ... */
	CHECK(!oidc_alg_supported("none"));
	CHECK(!oidc_alg_supported("None"));
	/* ... nor one whose "key" would be a shared secret. */
	CHECK(!oidc_alg_supported("HS256"));
	CHECK(!oidc_alg_supported(NULL));
	CHECK(!oidc_alg_supported(""));

	CHECK(oidc_alg_supported("RS256"));
	CHECK(oidc_alg_supported("PS512"));
	CHECK(oidc_alg_supported("ES256"));
}

static void test_signature_verification(void)
{
	EVP_PKEY *rsa = oidc_test_generate_key("RSA", 2048);
	EVP_PKEY *ec = oidc_test_generate_key("EC", NID_X9_62_prime256v1);
	EVP_PKEY *other = oidc_test_generate_key("RSA", 2048);
	char errbuf[256];
	char *n, *e, *token, *dot, *x, *y;
	EVP_PKEY *from_jwk;
	unsigned char *sig;
	size_t siglen;

	/* An RSA JWK rebuilds into a key that verifies the same signature. */
	n = oidc_test_param_b64url(rsa, "n");
	e = oidc_test_param_b64url(rsa, "e");
	from_jwk = oidc_jwk_to_pkey("RSA", n, e, NULL, NULL, NULL, errbuf, sizeof(errbuf));
	CHECK(from_jwk != NULL);

	token = oidc_test_make_token(rsa, "RS256", NULL, "{\"sub\":\"alice\"}");
	dot = strrchr(token, '.');
	sig = oidc_base64url_decode(dot + 1, strlen(dot + 1), &siglen);
	CHECK(sig != NULL);
	CHECK(oidc_jws_verify(from_jwk, "RS256", token, (size_t)(dot - token), sig, siglen,
			      errbuf, sizeof(errbuf)));

	/* The same signature must not verify under a different key ... */
	CHECK(!oidc_jws_verify(other, "RS256", token, (size_t)(dot - token), sig, siglen,
			       errbuf, sizeof(errbuf)));
	/* ... nor over tampered input ... */
	CHECK(!oidc_jws_verify(from_jwk, "RS256", "xx", 2, sig, siglen, errbuf, sizeof(errbuf)));
	/* ... nor under an algorithm the key cannot possibly have used. */
	CHECK(!oidc_jws_verify(from_jwk, "ES256", token, (size_t)(dot - token), sig, siglen,
			       errbuf, sizeof(errbuf)));
	CHECK(!oidc_jws_verify(from_jwk, "none", token, (size_t)(dot - token), sig, siglen,
			       errbuf, sizeof(errbuf)));

	free(sig);
	free(token);
	free(n);
	free(e);
	EVP_PKEY_free(from_jwk);

	/* The EC path, including the raw R||S to DER conversion. */
	x = oidc_test_param_b64url(ec, "qx");
	y = oidc_test_param_b64url(ec, "qy");

	from_jwk = oidc_jwk_to_pkey("EC", NULL, NULL, "P-256", x, y, errbuf, sizeof(errbuf));
	CHECK(from_jwk != NULL);

	token = oidc_test_make_token(ec, "ES256", NULL, "{\"sub\":\"alice\"}");
	dot = strrchr(token, '.');
	sig = oidc_base64url_decode(dot + 1, strlen(dot + 1), &siglen);
	CHECK(sig != NULL && siglen == 64);
	CHECK(oidc_jws_verify(from_jwk, "ES256", token, (size_t)(dot - token), sig, siglen,
			      errbuf, sizeof(errbuf)));

	sig[0] ^= 0xff;
	CHECK(!oidc_jws_verify(from_jwk, "ES256", token, (size_t)(dot - token), sig, siglen,
			       errbuf, sizeof(errbuf)));

	free(sig);
	free(token);
	free(x);
	free(y);
	EVP_PKEY_free(from_jwk);

	/* A JWK we cannot make sense of is refused, not guessed at. */
	CHECK(oidc_jwk_to_pkey("oct", NULL, NULL, NULL, NULL, NULL, errbuf, sizeof(errbuf)) == NULL);
	CHECK(oidc_jwk_to_pkey("EC", NULL, NULL, "P-192", "AAAA", "AAAA",
			       errbuf, sizeof(errbuf)) == NULL);

	EVP_PKEY_free(rsa);
	EVP_PKEY_free(ec);
	EVP_PKEY_free(other);
}

static void check_claims(const char *json, const struct oidc_claims_policy *policy,
			 bool expect_ok, const char *expect_id)
{
	json_error_t jerr;
	json_t *obj = json_loads(json, 0, &jerr);
	char errbuf[256] = { 0 };
	char *authn_id = NULL;
	bool ok;

	CHECK(obj != NULL);
	ok = oidc_claims_check(obj, policy, &authn_id, errbuf, sizeof(errbuf));
	CHECK(ok == expect_ok);
	if (expect_ok)
		CHECK(authn_id != NULL && strcmp(authn_id, expect_id) == 0);
	else
		CHECK(errbuf[0] != '\0');

	free(authn_id);
	json_decref(obj);
}

static void test_claims_policy(void)
{
	char *audiences[] = { "pgbouncer" };
	char *scopes[] = { "openid", "email" };
	char *authn_claims[] = { "preferred_username" };
	struct oidc_claims_policy policy;
	long now = (long)time(NULL);
	char *json;

	memset(&policy, 0, sizeof(policy));
	policy.issuer = TEST_ISSUER;
	policy.authn_claims = authn_claims;
	policy.nauthn_claims = 1;
	policy.clock_skew = 60;
	policy.audiences = audiences;
	policy.naudiences = 1;
	policy.scopes = scopes;
	policy.nscopes = 2;

	json = claims_json(now + 300, TEST_ISSUER, "pgbouncer", "openid email profile", "alice");
	check_claims(json, &policy, true, "alice");
	free(json);

	/* Expired, and not merely inside the skew. */
	json = claims_json(now - 3600, TEST_ISSUER, "pgbouncer", "openid email", "alice");
	check_claims(json, &policy, false, NULL);
	free(json);

	/* Just expired but within the tolerance. */
	json = claims_json(now - 30, TEST_ISSUER, "pgbouncer", "openid email", "alice");
	check_claims(json, &policy, true, "alice");
	free(json);

	/* Another realm token, correctly signed, is still not ours. */
	json = claims_json(now + 300, "https://evil.example.test/realms/test",
			   "pgbouncer", "openid email", "alice");
	check_claims(json, &policy, false, NULL);
	free(json);

	/* Issued for a different audience. */
	json = claims_json(now + 300, TEST_ISSUER, "account", "openid email", "alice");
	check_claims(json, &policy, false, NULL);
	free(json);

	/* Missing one of the required scopes. */
	json = claims_json(now + 300, TEST_ISSUER, "pgbouncer", "openid", "alice");
	check_claims(json, &policy, false, NULL);
	free(json);

	/* A scope that is only a prefix of a granted one does not count. */
	json = claims_json(now + 300, TEST_ISSUER, "pgbouncer", "openid emailx", "alice");
	check_claims(json, &policy, false, NULL);
	free(json);

	/* No claim to take the identity from. */
	check_claims("{\"exp\": 9999999999, \"iss\": \"" TEST_ISSUER "\","
		     " \"aud\": \"pgbouncer\", \"scope\": \"openid email\"}",
		     &policy, false, NULL);

	/* No expiry at all: never acceptable, however well-formed the rest. */
	check_claims("{\"iss\": \"" TEST_ISSUER "\", \"aud\": \"pgbouncer\","
		     " \"scope\": \"openid email\", \"preferred_username\": \"alice\"}",
		     &policy, false, NULL);

	/* "aud" may also be an array. */
	check_claims("{\"exp\": 9999999999, \"iss\": \"" TEST_ISSUER "\","
		     " \"aud\": [\"account\", \"pgbouncer\"], \"scope\": \"openid email\","
		     " \"preferred_username\": \"alice\"}",
		     &policy, true, "alice");
}

static void test_jwt_end_to_end(void)
{
	char *authn_claims[] = { "preferred_username" };
	EVP_PKEY *key = oidc_test_generate_key("RSA", 2048);
	EVP_PKEY *other = oidc_test_generate_key("RSA", 2048);
	char *jwks_doc = oidc_test_rsa_jwks(key, "kid-1");
	struct oidc_test_server *srv = oidc_test_server_start(jwks_doc);
	struct oidc_claims_policy policy;
	struct oidc_jwks_cache *cache;
	char url[128];
	char errbuf[256];
	char *authn_id = NULL;
	bool internal = false;
	long now = (long)time(NULL);
	char *claims, *token;
	struct oidc_jwks_cache *eager;
	int before;
	char *hdr, *pl;
	char unsigned_token[4096];

	CHECK(oidc_http_init(errbuf, sizeof(errbuf)));

	snprintf(url, sizeof(url), "http://127.0.0.1:%d/certs", oidc_test_server_port(srv));
	cache = oidc_jwks_new(url, 300, &(struct oidc_tls_opts) { NULL, true });
	CHECK(cache != NULL);

	memset(&policy, 0, sizeof(policy));
	policy.issuer = TEST_ISSUER;
	policy.authn_claims = authn_claims;
	policy.nauthn_claims = 1;
	policy.clock_skew = 60;

	claims = claims_json(now + 300, TEST_ISSUER, "pgbouncer", "openid", "alice");
	token = oidc_test_make_token(key, "RS256", "kid-1", claims);

	CHECK(oidc_jwt_verify(token, cache, &policy, 5000, &authn_id, &internal,
			      errbuf, sizeof(errbuf)));
	CHECK(authn_id != NULL && strcmp(authn_id, "alice") == 0);
	CHECK(!internal);
	free(authn_id);
	authn_id = NULL;

	/* The keys are cached: a second login does not refetch them. */
	CHECK(oidc_test_server_requests(srv) == 1);
	CHECK(oidc_jwt_verify(token, cache, &policy, 5000, &authn_id, &internal,
			      errbuf, sizeof(errbuf)));
	CHECK(oidc_test_server_requests(srv) == 1);
	free(authn_id);
	authn_id = NULL;
	free(token);

	/* A token signed by someone else, claiming the published key id. */
	token = oidc_test_make_token(other, "RS256", "kid-1", claims);
	CHECK(!oidc_jwt_verify(token, cache, &policy, 5000, &authn_id, &internal,
			       errbuf, sizeof(errbuf)));
	CHECK(authn_id == NULL);
	/*
	 * A bad signature is a rejection, not a failure to reach the provider:
	 * PgBouncer reports the two differently.
	 */
	CHECK(!internal);
	free(token);

	/*
	 * An unknown key id is what a rotation looks like, so it may trigger a
	 * refetch -- but no more often than min_refresh, which is what stops a
	 * stream of tokens with invented key ids from becoming a stream of
	 * requests to the provider.  This cache has just fetched, so it waits.
	 */
	token = oidc_test_make_token(key, "RS256", "kid-unknown", claims);
	CHECK(!oidc_jwt_verify(token, cache, &policy, 5000, &authn_id, &internal,
			       errbuf, sizeof(errbuf)));
	CHECK(oidc_test_server_requests(srv) == 1);
	free(token);

	/* With no rate limit, the same unknown id does refetch. */
	eager = oidc_jwks_new(url, 0, &(struct oidc_tls_opts) { NULL, true });

	token = oidc_test_make_token(key, "RS256", "kid-1", claims);
	CHECK(oidc_jwt_verify(token, eager, &policy, 5000, &authn_id, &internal,
			      errbuf, sizeof(errbuf)));
	free(authn_id);
	authn_id = NULL;
	free(token);
	before = oidc_test_server_requests(srv);

	token = oidc_test_make_token(key, "RS256", "kid-unknown", claims);
	CHECK(!oidc_jwt_verify(token, eager, &policy, 5000, &authn_id, &internal,
			       errbuf, sizeof(errbuf)));
	CHECK(oidc_test_server_requests(srv) == before + 1);
	free(token);
	oidc_jwks_free(eager);

	/* Structurally invalid tokens are refused before any crypto. */
	CHECK(!oidc_jwt_verify("not-a-jwt", cache, &policy, 5000, &authn_id, &internal,
			       errbuf, sizeof(errbuf)));
	CHECK(!oidc_jwt_verify("a.b", cache, &policy, 5000, &authn_id, &internal,
			       errbuf, sizeof(errbuf)));
	CHECK(!oidc_jwt_verify("a.b.c.d", cache, &policy, 5000, &authn_id, &internal,
			       errbuf, sizeof(errbuf)));

	/* An "alg": "none" token with no signature at all. */
	hdr = oidc_base64url_encode((const unsigned char *)"{\"alg\":\"none\"}", 14);
	pl = oidc_base64url_encode((const unsigned char *)claims, strlen(claims));

	snprintf(unsigned_token, sizeof(unsigned_token), "%s.%s.", hdr, pl);
	CHECK(!oidc_jwt_verify(unsigned_token, cache, &policy, 5000, &authn_id,
			       &internal, errbuf, sizeof(errbuf)));
	CHECK(authn_id == NULL);
	free(hdr);
	free(pl);

	free(claims);
	oidc_jwks_free(cache);
	oidc_test_server_stop(srv);
	free(jwks_doc);
	EVP_PKEY_free(key);
	EVP_PKEY_free(other);
	oidc_http_fini();
}

static void test_jwks_unreachable(void)
{
	char *authn_claims[] = { "preferred_username" };
	struct oidc_jwks_cache *cache;
	struct oidc_claims_policy policy;
	char errbuf[256];
	char *authn_id = NULL;
	bool internal = false;

	CHECK(oidc_http_init(errbuf, sizeof(errbuf)));

	memset(&policy, 0, sizeof(policy));
	policy.authn_claims = authn_claims;
	policy.nauthn_claims = 1;

	/* Port 1 on loopback: nothing is listening. */
	cache = oidc_jwks_new("http://127.0.0.1:1/certs", 300, &(struct oidc_tls_opts) { NULL, true });
	CHECK(cache != NULL);

	CHECK(!oidc_jwt_verify("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhIn0.AAAA", cache, &policy,
			       2000, &authn_id, &internal, errbuf, sizeof(errbuf)));
	/* Cannot judge the token at all: PgBouncer should log this as an error
	 * on our side, not as a rejected token. */
	CHECK(internal);
	CHECK(errbuf[0] != '\0');

	oidc_jwks_free(cache);
	oidc_http_fini();
}

int main(void)
{
	test_base64url();
	test_alg_allowlist();
	test_signature_verification();
	test_claims_policy();
	test_jwt_end_to_end();
	test_jwks_unreachable();

	printf("oidc_test: OK (%d checks)\n", tests_run);

	return 0;
}
