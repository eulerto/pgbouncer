/*
 * Keycloak OAuth validator module for PgBouncer.
 *
 * Cryptographic primitives for JWS verification: base64url decoding, turning
 * a JWK components into an OpenSSL public key, and verifying a signature
 * over a token signing input.
 *
 * Nothing here parses JSON.  The caller extracts the JWK members and the
 * token three segments and passes them in, which keeps the code that must
 * be right about crypto free of the code that must be right about parsing.
 */

#ifndef KC_CRYPTO_H
#define KC_CRYPTO_H

#include <stdbool.h>
#include <stddef.h>

#include <openssl/evp.h>

/*
 * Decode base64url (RFC 4648 section 5, no padding).  Returns a malloc()'d
 * buffer of *outlen bytes, or NULL if the input is not valid base64url.  The
 * result is NUL-terminated as a convenience for decoding JSON segments; the
 * terminator is not counted in *outlen.
 */
unsigned char *kc_base64url_decode(const char *in, size_t inlen, size_t *outlen);

/* Encode len bytes as base64url without padding; returns a malloc()'d string. */
char *kc_base64url_encode(const unsigned char *in, size_t len);

/*
 * True if alg names a signature algorithm this module accepts.  Notably
 * false for "none": an unsigned token must never be treated as verified.
 */
bool kc_alg_supported(const char *alg);

/*
 * Build a public key from the JWK members.  For kty="RSA" pass n and e; for
 * kty="EC" pass crv, x and y; the unused ones may be NULL.  All values are
 * base64url as they appear in the JWK.  Returns NULL and fills errbuf on
 * failure.  The caller owns the key and frees it with EVP_PKEY_free().
 */
EVP_PKEY *kc_jwk_to_pkey(const char *kty, const char *n_b64, const char *e_b64,
			 const char *crv, const char *x_b64, const char *y_b64,
			 char *errbuf, size_t errlen);

/*
 * Verify a JWS signature.  signing_input is the "<header>.<payload>" part of
 * the compact serialization, exactly as it appeared in the token, and sig is
 * the decoded third segment.  Returns false both for a bad signature and for
 * an internal error; errbuf tells them apart for logging.
 */
bool kc_jws_verify(EVP_PKEY *pkey, const char *alg,
		   const char *signing_input, size_t signing_len,
		   const unsigned char *sig, size_t siglen,
		   char *errbuf, size_t errlen);

#endif
