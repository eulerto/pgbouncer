/*
 * Unit tests for the Keycloak validator module building blocks.
 *
 * These do not need a Keycloak: the tests mint their own signing keys, serve
 * a JWKS from a throwaway HTTP server on localhost, and sign tokens with the
 * matching private key.  That covers everything except talking to a real
 * provider: base64url, JWK to key conversion, signature verification for the
 * RSA and ECDSA families, the claim policy, and the JWKS cache.
 *
 *   make check
 */

#include <assert.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <jansson.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include "kc_crypto.h"
#include "kc_jwt.h"

#define TEST_ISSUER "https://kc.example.test/realms/test"

static int tests_run;

#define CHECK(cond) do { \
		tests_run++; \
		if (!(cond)) { \
			fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
			exit(1); \
		} \
} while (0)

/*
 * A throwaway HTTP server that answers every request with the same body.
 */
struct fake_server {
	int fd;
	int port;
	char *body;
	pthread_t thread;
	volatile bool stop;
	/* Written by the server thread, read by the tests. */
	int requests;
};

static void *serve(void *arg)
{
	struct fake_server *srv = arg;

	while (!srv->stop) {
		char req[2048];
		char resp[8192];
		int client = accept(srv->fd, NULL, NULL);
		ssize_t n;

		if (client < 0)
			break;
		n = recv(client, req, sizeof(req) - 1, 0);
		if (n > 0) {
			int len = snprintf(resp, sizeof(resp),
					   "HTTP/1.1 200 OK\r\n"
					   "Content-Type: application/json\r\n"
					   "Content-Length: %zu\r\n"
					   "Connection: close\r\n"
					   "\r\n%s",
					   strlen(srv->body), srv->body);

			/*
			 * Count before answering: the client returns as soon as it has the
			 * body, and then reads this counter.
			 */
			__atomic_fetch_add(&srv->requests, 1, __ATOMIC_SEQ_CST);
			if (send(client, resp, (size_t)len, MSG_NOSIGNAL) < 0) {
				/* the client went away; nothing to do */
			}
		}
		close(client);
	}

	return NULL;
}

static int server_requests(struct fake_server *srv)
{
	return __atomic_load_n(&srv->requests, __ATOMIC_SEQ_CST);
}

static struct fake_server *server_start(const char *body)
{
	struct fake_server *srv = calloc(1, sizeof(*srv));
	struct sockaddr_in addr;
	socklen_t addrlen = sizeof(addr);
	int one = 1;

	assert(srv != NULL);
	srv->body = strdup(body);
	assert(srv->body != NULL);

	srv->fd = socket(AF_INET, SOCK_STREAM, 0);
	assert(srv->fd >= 0);
	setsockopt(srv->fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = 0;
	assert(bind(srv->fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
	assert(listen(srv->fd, 8) == 0);
	assert(getsockname(srv->fd, (struct sockaddr *)&addr, &addrlen) == 0);
	srv->port = ntohs(addr.sin_port);

	assert(pthread_create(&srv->thread, NULL, serve, srv) == 0);

	return srv;
}

static void server_stop(struct fake_server *srv)
{
	srv->stop = true;
	shutdown(srv->fd, SHUT_RDWR);
	close(srv->fd);
	pthread_join(srv->thread, NULL);
	free(srv->body);
	free(srv);
}

/*
 * Key and token helpers.
 */

static EVP_PKEY *generate_key(const char *type, int bits_or_nid)
{
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, type, NULL);
	EVP_PKEY *pkey = NULL;

	assert(ctx != NULL);
	assert(EVP_PKEY_keygen_init(ctx) > 0);
	if (strcmp(type, "RSA") == 0)
		assert(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits_or_nid) > 0);
	else
		assert(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, bits_or_nid) > 0);
	assert(EVP_PKEY_keygen(ctx, &pkey) > 0);
	EVP_PKEY_CTX_free(ctx);

	return pkey;
}

static char *bn_to_b64url(const BIGNUM *bn)
{
	int len = BN_num_bytes(bn);
	unsigned char *raw = malloc((size_t)len);
	char *out;

	assert(raw != NULL);
	BN_bn2bin(bn, raw);
	out = kc_base64url_encode(raw, (size_t)len);
	free(raw);

	return out;
}

static char *param_b64url(EVP_PKEY *pkey, const char *param)
{
	BIGNUM *bn = NULL;
	char *out;

	assert(EVP_PKEY_get_bn_param(pkey, param, &bn) == 1);
	out = bn_to_b64url(bn);
	BN_free(bn);

	return out;
}

/* Build a one-key JWKS document for an RSA key. */
static char *rsa_jwks(EVP_PKEY *pkey, const char *kid)
{
	char *n = param_b64url(pkey, "n");
	char *e = param_b64url(pkey, "e");
	json_t *jwk = json_pack("{s:s, s:s, s:s, s:s, s:s, s:s}",
				"kty", "RSA", "use", "sig", "alg", "RS256",
				"kid", kid, "n", n, "e", e);
	json_t *doc = json_pack("{s:[o]}", "keys", jwk);
	char *out = json_dumps(doc, JSON_COMPACT);

	json_decref(doc);
	free(n);
	free(e);

	return out;
}

/* Sign "<header>.<payload>" and return the compact serialization. */
static char *make_token(EVP_PKEY *pkey, const char *alg, const char *kid,
			const char *payload_json)
{
	json_t *hdr = kid ?
		      json_pack("{s:s, s:s, s:s}", "alg", alg, "typ", "JWT", "kid", kid) :
		      json_pack("{s:s, s:s}", "alg", alg, "typ", "JWT");
	char *hdr_json = json_dumps(hdr, JSON_COMPACT);
	char *hdr_b64 = kc_base64url_encode((const unsigned char *)hdr_json, strlen(hdr_json));
	char *pl_b64 = kc_base64url_encode((const unsigned char *)payload_json, strlen(payload_json));
	char *signing_input;
	unsigned char *sig = NULL;
	size_t siglen = 0;
	char *sig_b64;
	char *token;
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	const EVP_MD *md = EVP_sha256();
	size_t len;

	json_decref(hdr);

	len = strlen(hdr_b64) + 1 + strlen(pl_b64) + 1;
	signing_input = malloc(len);
	assert(signing_input != NULL);
	snprintf(signing_input, len, "%s.%s", hdr_b64, pl_b64);

	assert(EVP_DigestSignInit(ctx, NULL, md, NULL, pkey) > 0);
	assert(EVP_DigestSign(ctx, NULL, &siglen,
			      (const unsigned char *)signing_input, strlen(signing_input)) > 0);
	sig = malloc(siglen);
	assert(sig != NULL);
	assert(EVP_DigestSign(ctx, sig, &siglen,
			      (const unsigned char *)signing_input, strlen(signing_input)) > 0);
	EVP_MD_CTX_free(ctx);

	/* JWS wants ECDSA signatures as raw R||S, not DER. */
	if (alg[0] == 'E') {
		const unsigned char *p = sig;
		ECDSA_SIG *ecsig = d2i_ECDSA_SIG(NULL, &p, (long)siglen);
		const BIGNUM *r, *s;
		unsigned char raw[132];

		assert(ecsig != NULL);
		ECDSA_SIG_get0(ecsig, &r, &s);
		assert(BN_bn2binpad(r, raw, 32) == 32);
		assert(BN_bn2binpad(s, raw + 32, 32) == 32);
		ECDSA_SIG_free(ecsig);
		free(sig);
		sig = malloc(64);
		assert(sig != NULL);
		memcpy(sig, raw, 64);
		siglen = 64;
	}

	sig_b64 = kc_base64url_encode(sig, siglen);

	len = strlen(signing_input) + 1 + strlen(sig_b64) + 1;
	token = malloc(len);
	assert(token != NULL);
	snprintf(token, len, "%s.%s", signing_input, sig_b64);

	free(sig);
	free(sig_b64);
	free(signing_input);
	free(hdr_json);
	free(hdr_b64);
	free(pl_b64);

	return token;
}

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
	out = kc_base64url_decode("eyJhbGciOiJSUzI1NiJ9", 20, &len);
	CHECK(out != NULL);
	CHECK(len == 15);
	CHECK(strcmp((char *)out, "{\"alg\":\"RS256\"}") == 0);
	free(out);

	/* Round trip, including lengths that need 1 and 2 padding bytes. */
	for (int n = 1; n <= 8; n++) {
		unsigned char buf[8];

		for (int i = 0; i < n; i++)
			buf[i] = (unsigned char)(i * 37 + 11);
		enc = kc_base64url_encode(buf, (size_t)n);
		CHECK(enc != NULL);
		CHECK(strchr(enc, '=') == NULL);	/* no padding */
		CHECK(strchr(enc, '+') == NULL && strchr(enc, '/') == NULL);
		out = kc_base64url_decode(enc, strlen(enc), &len);
		CHECK(out != NULL && len == (size_t)n && memcmp(out, buf, (size_t)n) == 0);
		free(out);
		free(enc);
	}

	/* Standard base64 characters and stray padding are not base64url. */
	CHECK(kc_base64url_decode("ab+d", 4, &len) == NULL);
	CHECK(kc_base64url_decode("ab/d", 4, &len) == NULL);
	CHECK(kc_base64url_decode("abc=", 4, &len) == NULL);
	/* A trailing group of one character cannot occur. */
	CHECK(kc_base64url_decode("abcde", 5, &len) == NULL);
}

static void test_alg_allowlist(void)
{
	/* An unsigned token must never be accepted ... */
	CHECK(!kc_alg_supported("none"));
	CHECK(!kc_alg_supported("None"));
	/* ... nor one whose "key" would be a shared secret. */
	CHECK(!kc_alg_supported("HS256"));
	CHECK(!kc_alg_supported(NULL));
	CHECK(!kc_alg_supported(""));

	CHECK(kc_alg_supported("RS256"));
	CHECK(kc_alg_supported("PS512"));
	CHECK(kc_alg_supported("ES256"));
}

static void test_signature_verification(void)
{
	EVP_PKEY *rsa = generate_key("RSA", 2048);
	EVP_PKEY *ec = generate_key("EC", NID_X9_62_prime256v1);
	EVP_PKEY *other = generate_key("RSA", 2048);
	char errbuf[256];
	char *n, *e, *token, *dot, *x, *y;
	EVP_PKEY *from_jwk;
	unsigned char *sig;
	size_t siglen;

	/* An RSA JWK rebuilds into a key that verifies the same signature. */
	n = param_b64url(rsa, "n");
	e = param_b64url(rsa, "e");
	from_jwk = kc_jwk_to_pkey("RSA", n, e, NULL, NULL, NULL, errbuf, sizeof(errbuf));
	CHECK(from_jwk != NULL);

	token = make_token(rsa, "RS256", NULL, "{\"sub\":\"alice\"}");
	dot = strrchr(token, '.');
	sig = kc_base64url_decode(dot + 1, strlen(dot + 1), &siglen);
	CHECK(sig != NULL);
	CHECK(kc_jws_verify(from_jwk, "RS256", token, (size_t)(dot - token), sig, siglen,
			    errbuf, sizeof(errbuf)));

	/* The same signature must not verify under a different key ... */
	CHECK(!kc_jws_verify(other, "RS256", token, (size_t)(dot - token), sig, siglen,
			     errbuf, sizeof(errbuf)));
	/* ... nor over tampered input ... */
	CHECK(!kc_jws_verify(from_jwk, "RS256", "xx", 2, sig, siglen, errbuf, sizeof(errbuf)));
	/* ... nor under an algorithm the key cannot possibly have used. */
	CHECK(!kc_jws_verify(from_jwk, "ES256", token, (size_t)(dot - token), sig, siglen,
			     errbuf, sizeof(errbuf)));
	CHECK(!kc_jws_verify(from_jwk, "none", token, (size_t)(dot - token), sig, siglen,
			     errbuf, sizeof(errbuf)));

	free(sig);
	free(token);
	free(n);
	free(e);
	EVP_PKEY_free(from_jwk);

	/* The EC path, including the raw R||S to DER conversion. */
	x = param_b64url(ec, "qx");
	y = param_b64url(ec, "qy");

	from_jwk = kc_jwk_to_pkey("EC", NULL, NULL, "P-256", x, y, errbuf, sizeof(errbuf));
	CHECK(from_jwk != NULL);

	token = make_token(ec, "ES256", NULL, "{\"sub\":\"alice\"}");
	dot = strrchr(token, '.');
	sig = kc_base64url_decode(dot + 1, strlen(dot + 1), &siglen);
	CHECK(sig != NULL && siglen == 64);
	CHECK(kc_jws_verify(from_jwk, "ES256", token, (size_t)(dot - token), sig, siglen,
			    errbuf, sizeof(errbuf)));

	sig[0] ^= 0xff;
	CHECK(!kc_jws_verify(from_jwk, "ES256", token, (size_t)(dot - token), sig, siglen,
			     errbuf, sizeof(errbuf)));

	free(sig);
	free(token);
	free(x);
	free(y);
	EVP_PKEY_free(from_jwk);

	/* A JWK we cannot make sense of is refused, not guessed at. */
	CHECK(kc_jwk_to_pkey("oct", NULL, NULL, NULL, NULL, NULL, errbuf, sizeof(errbuf)) == NULL);
	CHECK(kc_jwk_to_pkey("EC", NULL, NULL, "P-192", "AAAA", "AAAA",
			     errbuf, sizeof(errbuf)) == NULL);

	EVP_PKEY_free(rsa);
	EVP_PKEY_free(ec);
	EVP_PKEY_free(other);
}

static void check_claims(const char *json, const struct kc_claims_policy *policy,
			 bool expect_ok, const char *expect_id)
{
	json_error_t jerr;
	json_t *obj = json_loads(json, 0, &jerr);
	char errbuf[256] = { 0 };
	char *authn_id = NULL;
	bool ok;

	CHECK(obj != NULL);
	ok = kc_claims_check(obj, policy, &authn_id, errbuf, sizeof(errbuf));
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
	struct kc_claims_policy policy;
	long now = (long)time(NULL);
	char *json;

	memset(&policy, 0, sizeof(policy));
	policy.issuer = TEST_ISSUER;
	policy.authn_claim = "preferred_username";
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
	EVP_PKEY *key = generate_key("RSA", 2048);
	EVP_PKEY *other = generate_key("RSA", 2048);
	char *jwks_doc = rsa_jwks(key, "kid-1");
	struct fake_server *srv = server_start(jwks_doc);
	struct kc_claims_policy policy;
	struct kc_jwks_cache *cache;
	char url[128];
	char errbuf[256];
	char *authn_id = NULL;
	bool internal = false;
	long now = (long)time(NULL);
	char *claims, *token;
	struct kc_jwks_cache *eager;
	int before;
	char *hdr, *pl;
	char unsigned_token[4096];

	CHECK(kc_http_init(errbuf, sizeof(errbuf)));

	snprintf(url, sizeof(url), "http://127.0.0.1:%d/certs", srv->port);
	cache = kc_jwks_new(url, 300, &(struct kc_tls_opts) { NULL, true });
	CHECK(cache != NULL);

	memset(&policy, 0, sizeof(policy));
	policy.issuer = TEST_ISSUER;
	policy.authn_claim = "preferred_username";
	policy.clock_skew = 60;

	claims = claims_json(now + 300, TEST_ISSUER, "pgbouncer", "openid", "alice");
	token = make_token(key, "RS256", "kid-1", claims);

	CHECK(kc_jwt_verify(token, cache, &policy, 5000, &authn_id, &internal,
			    errbuf, sizeof(errbuf)));
	CHECK(authn_id != NULL && strcmp(authn_id, "alice") == 0);
	CHECK(!internal);
	free(authn_id);
	authn_id = NULL;

	/* The keys are cached: a second login does not refetch them. */
	CHECK(server_requests(srv) == 1);
	CHECK(kc_jwt_verify(token, cache, &policy, 5000, &authn_id, &internal,
			    errbuf, sizeof(errbuf)));
	CHECK(server_requests(srv) == 1);
	free(authn_id);
	authn_id = NULL;
	free(token);

	/* A token signed by someone else, claiming the published key id. */
	token = make_token(other, "RS256", "kid-1", claims);
	CHECK(!kc_jwt_verify(token, cache, &policy, 5000, &authn_id, &internal,
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
	token = make_token(key, "RS256", "kid-unknown", claims);
	CHECK(!kc_jwt_verify(token, cache, &policy, 5000, &authn_id, &internal,
			     errbuf, sizeof(errbuf)));
	CHECK(server_requests(srv) == 1);
	free(token);

	/* With no rate limit, the same unknown id does refetch. */
	eager = kc_jwks_new(url, 0, &(struct kc_tls_opts) { NULL, true });

	token = make_token(key, "RS256", "kid-1", claims);
	CHECK(kc_jwt_verify(token, eager, &policy, 5000, &authn_id, &internal,
			    errbuf, sizeof(errbuf)));
	free(authn_id);
	authn_id = NULL;
	free(token);
	before = server_requests(srv);

	token = make_token(key, "RS256", "kid-unknown", claims);
	CHECK(!kc_jwt_verify(token, eager, &policy, 5000, &authn_id, &internal,
			     errbuf, sizeof(errbuf)));
	CHECK(server_requests(srv) == before + 1);
	free(token);
	kc_jwks_free(eager);

	/* Structurally invalid tokens are refused before any crypto. */
	CHECK(!kc_jwt_verify("not-a-jwt", cache, &policy, 5000, &authn_id, &internal,
			     errbuf, sizeof(errbuf)));
	CHECK(!kc_jwt_verify("a.b", cache, &policy, 5000, &authn_id, &internal,
			     errbuf, sizeof(errbuf)));
	CHECK(!kc_jwt_verify("a.b.c.d", cache, &policy, 5000, &authn_id, &internal,
			     errbuf, sizeof(errbuf)));

	/* An "alg": "none" token with no signature at all. */
	hdr = kc_base64url_encode((const unsigned char *)"{\"alg\":\"none\"}", 14);
	pl = kc_base64url_encode((const unsigned char *)claims, strlen(claims));

	snprintf(unsigned_token, sizeof(unsigned_token), "%s.%s.", hdr, pl);
	CHECK(!kc_jwt_verify(unsigned_token, cache, &policy, 5000, &authn_id,
			     &internal, errbuf, sizeof(errbuf)));
	CHECK(authn_id == NULL);
	free(hdr);
	free(pl);

	free(claims);
	kc_jwks_free(cache);
	server_stop(srv);
	free(jwks_doc);
	EVP_PKEY_free(key);
	EVP_PKEY_free(other);
	kc_http_fini();
}

static void test_jwks_unreachable(void)
{
	struct kc_jwks_cache *cache;
	struct kc_claims_policy policy;
	char errbuf[256];
	char *authn_id = NULL;
	bool internal = false;

	CHECK(kc_http_init(errbuf, sizeof(errbuf)));

	memset(&policy, 0, sizeof(policy));
	policy.authn_claim = "preferred_username";

	/* Port 1 on loopback: nothing is listening. */
	cache = kc_jwks_new("http://127.0.0.1:1/certs", 300, &(struct kc_tls_opts) { NULL, true });
	CHECK(cache != NULL);

	CHECK(!kc_jwt_verify("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhIn0.AAAA", cache, &policy,
			     2000, &authn_id, &internal, errbuf, sizeof(errbuf)));
	/* Cannot judge the token at all: PgBouncer should log this as an error
	 * on our side, not as a rejected token. */
	CHECK(internal);
	CHECK(errbuf[0] != '\0');

	kc_jwks_free(cache);
	kc_http_fini();
}

int main(void)
{
	test_base64url();
	test_alg_allowlist();
	test_signature_verification();
	test_claims_policy();
	test_jwt_end_to_end();
	test_jwks_unreachable();

	printf("kc_test: OK (%d checks)\n", tests_run);

	return 0;
}
