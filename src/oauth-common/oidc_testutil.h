/*
 * Test helpers shared by the validator module unit tests.
 *
 * They stand in for an identity provider: a throwaway HTTP server on
 * localhost that serves a fixed JWKS document, plus enough key and token
 * minting to sign a token the modules will accept.  Nothing here is built
 * into a module; only the test binaries link it.
 */

#ifndef OIDC_TESTUTIL_H
#define OIDC_TESTUTIL_H

#include <stdbool.h>
#include <stddef.h>

#include <openssl/evp.h>

/*
 * A throwaway HTTP server that answers every request with the same body.
 */
struct oidc_test_server;

/* Start on a free loopback port; every request is answered with body. */
struct oidc_test_server *oidc_test_server_start(const char *body);
void oidc_test_server_stop(struct oidc_test_server *srv);

int oidc_test_server_port(struct oidc_test_server *srv);

/* How many requests the server has answered so far.  Safe to call anytime. */
int oidc_test_server_requests(struct oidc_test_server *srv);

/*
 * Generate a key pair.  type is "RSA" (with bits_or_nid a key size) or "EC"
 * (with bits_or_nid a curve NID).  The caller frees it with EVP_PKEY_free().
 */
EVP_PKEY *oidc_test_generate_key(const char *type, int bits_or_nid);

/* Build a one-key JWKS document for an RSA key; caller frees. */
char *oidc_test_rsa_jwks(EVP_PKEY *pkey, const char *kid);

/*
 * Return one key parameter ("n", "e", "qx", "qy") base64url-encoded the way a
 * JWK carries it; caller frees.
 */
char *oidc_test_param_b64url(EVP_PKEY *pkey, const char *param);

/*
 * Sign payload_json and return the compact serialization; caller frees.  kid
 * may be NULL to leave it out of the header.
 */
char *oidc_test_make_token(EVP_PKEY *pkey, const char *alg, const char *kid,
			   const char *payload_json);

#endif
