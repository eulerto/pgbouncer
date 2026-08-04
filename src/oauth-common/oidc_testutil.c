/*
 * Test helpers shared by the validator module unit tests.  See oidc_testutil.h.
 */

#include "oidc_testutil.h"

#include <assert.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <jansson.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include "oidc_crypto.h"

struct oidc_test_server {
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
	struct oidc_test_server *srv = arg;

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

int oidc_test_server_requests(struct oidc_test_server *srv)
{
	return __atomic_load_n(&srv->requests, __ATOMIC_SEQ_CST);
}

int oidc_test_server_port(struct oidc_test_server *srv)
{
	return srv->port;
}

struct oidc_test_server *oidc_test_server_start(const char *body)
{
	struct oidc_test_server *srv = calloc(1, sizeof(*srv));
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

void oidc_test_server_stop(struct oidc_test_server *srv)
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

EVP_PKEY *oidc_test_generate_key(const char *type, int bits_or_nid)
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
	out = oidc_base64url_encode(raw, (size_t)len);
	free(raw);

	return out;
}

char *oidc_test_param_b64url(EVP_PKEY *pkey, const char *param)
{
	BIGNUM *bn = NULL;
	char *out;

	assert(EVP_PKEY_get_bn_param(pkey, param, &bn) == 1);
	out = bn_to_b64url(bn);
	BN_free(bn);

	return out;
}

char *oidc_test_rsa_jwks(EVP_PKEY *pkey, const char *kid)
{
	char *n = oidc_test_param_b64url(pkey, "n");
	char *e = oidc_test_param_b64url(pkey, "e");
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

char *oidc_test_make_token(EVP_PKEY *pkey, const char *alg, const char *kid,
			   const char *payload_json)
{
	json_t *hdr = kid ?
		      json_pack("{s:s, s:s, s:s}", "alg", alg, "typ", "JWT", "kid", kid) :
		      json_pack("{s:s, s:s}", "alg", alg, "typ", "JWT");
	char *hdr_json = json_dumps(hdr, JSON_COMPACT);
	char *hdr_b64 = oidc_base64url_encode((const unsigned char *)hdr_json, strlen(hdr_json));
	char *pl_b64 = oidc_base64url_encode((const unsigned char *)payload_json, strlen(payload_json));
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

	sig_b64 = oidc_base64url_encode(sig, siglen);

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
