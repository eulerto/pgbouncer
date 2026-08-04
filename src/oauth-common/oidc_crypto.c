/*
 * Shared OIDC core for PgBouncer's OAuth validator modules.  See oidc_crypto.h.
 *
 * See oidc_crypto.h.  The OpenSSL 3 provider API and the pre-3.0 low-level API
 * are both supported, because a validator module tends to be built on
 * whatever the host distribution ships.
 */

#include "oidc_crypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/rsa.h>

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#endif

#define OIDC_SET_ERR(buf, len, ...) \
	do { \
		if ((buf) && (len) > 0) \
		snprintf((buf), (len), __VA_ARGS__); \
	} while (0)

/* Decoding table: value of a base64url character, or -1. */
static int b64url_value(unsigned char c)
{
	if (c >= 'A' && c <= 'Z')
		return c - 'A';
	if (c >= 'a' && c <= 'z')
		return c - 'a' + 26;
	if (c >= '0' && c <= '9')
		return c - '0' + 52;
	if (c == '-')
		return 62;
	if (c == '_')
		return 63;
	return -1;
}

unsigned char *oidc_base64url_decode(const char *in, size_t inlen, size_t *outlen)
{
	unsigned char *out;
	size_t i, o = 0;
	uint32_t acc = 0;
	int bits = 0;

	/*
	 * Every 4 input characters yield 3 bytes; a trailing group of 2 or 3
	 * yields 1 or 2.  A trailing group of exactly 1 is not valid base64.
	 */
	if (inlen % 4 == 1)
		return NULL;

	out = malloc(inlen / 4 * 3 + 3);
	if (!out)
		return NULL;

	for (i = 0; i < inlen; i++) {
		int v = b64url_value((unsigned char)in[i]);

		if (v < 0) {
			free(out);
			return NULL;
		}
		acc = (acc << 6) | (uint32_t)v;
		bits += 6;
		if (bits >= 8) {
			bits -= 8;
			out[o++] = (unsigned char)((acc >> bits) & 0xff);
		}
	}

	/* Leftover bits must be zero padding, not dropped data. */
	if (bits > 0 && (acc & ((1u << bits) - 1)) != 0) {
		free(out);
		return NULL;
	}

	out[o] = '\0';
	*outlen = o;
	return out;
}

char *oidc_base64url_encode(const unsigned char *in, size_t len)
{
	static const char alphabet[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
	size_t i, o = 0;
	char *out = malloc((len + 2) / 3 * 4 + 1);

	if (!out)
		return NULL;

	for (i = 0; i < len; i += 3) {
		unsigned int v = (unsigned int)in[i] << 16;
		size_t rest = len - i;

		if (rest > 1)
			v |= (unsigned int)in[i + 1] << 8;
		if (rest > 2)
			v |= in[i + 2];

		out[o++] = alphabet[(v >> 18) & 0x3f];
		out[o++] = alphabet[(v >> 12) & 0x3f];
		if (rest > 1)
			out[o++] = alphabet[(v >> 6) & 0x3f];
		if (rest > 2)
			out[o++] = alphabet[v & 0x3f];
	}
	out[o] = '\0';
	return out;
}

/*
 * Split an algorithm name into the digest to use and the signature family.
 * Anything not listed is rejected, which is what keeps "none" (and the
 * HMAC "HS*" algorithms, whose "key" would be the shared secret rather than
 * the provider public key) from ever reaching the verifier.
 */
enum oidc_sig_family {
	OIDC_SIG_RSA_PKCS1,
	OIDC_SIG_RSA_PSS,
	OIDC_SIG_ECDSA
};

static bool alg_lookup(const char *alg, const EVP_MD **md, enum oidc_sig_family *family)
{
	static const struct {
		const char *name;
		const char *digest;
		enum oidc_sig_family family;
	} table[] = {
		{ "RS256", "SHA256", OIDC_SIG_RSA_PKCS1 },
		{ "RS384", "SHA384", OIDC_SIG_RSA_PKCS1 },
		{ "RS512", "SHA512", OIDC_SIG_RSA_PKCS1 },
		{ "PS256", "SHA256", OIDC_SIG_RSA_PSS },
		{ "PS384", "SHA384", OIDC_SIG_RSA_PSS },
		{ "PS512", "SHA512", OIDC_SIG_RSA_PSS },
		{ "ES256", "SHA256", OIDC_SIG_ECDSA },
		{ "ES384", "SHA384", OIDC_SIG_ECDSA },
		{ "ES512", "SHA512", OIDC_SIG_ECDSA },
		{ NULL, NULL, OIDC_SIG_RSA_PKCS1 }
	};

	if (!alg)
		return false;

	for (int i = 0; table[i].name; i++) {
		if (strcmp(table[i].name, alg) == 0) {
			if (md)
				*md = EVP_get_digestbyname(table[i].digest);
			if (family)
				*family = table[i].family;
			return true;
		}
	}
	return false;
}

bool oidc_alg_supported(const char *alg)
{
	return alg_lookup(alg, NULL, NULL);
}

/* Decode a base64url JWK member into a BIGNUM. */
static BIGNUM *jwk_bn(const char *b64, char *errbuf, size_t errlen, const char *what)
{
	unsigned char *raw;
	size_t rawlen;
	BIGNUM *bn;

	if (!b64) {
		OIDC_SET_ERR(errbuf, errlen, "JWK is missing \"%s\"", what);
		return NULL;
	}

	raw = oidc_base64url_decode(b64, strlen(b64), &rawlen);
	if (!raw) {
		OIDC_SET_ERR(errbuf, errlen, "JWK member \"%s\" is not valid base64url", what);
		return NULL;
	}
	bn = BN_bin2bn(raw, (int)rawlen, NULL);
	free(raw);
	if (!bn)
		OIDC_SET_ERR(errbuf, errlen, "JWK member \"%s\" is not a valid integer", what);

	return bn;
}

/* Map a JWK "crv" name to the OpenSSL curve it denotes. */
static int curve_nid(const char *crv)
{
	if (!crv)
		return NID_undef;
	if (strcmp(crv, "P-256") == 0)
		return NID_X9_62_prime256v1;
	if (strcmp(crv, "P-384") == 0)
		return NID_secp384r1;
	if (strcmp(crv, "P-521") == 0)
		return NID_secp521r1;
	return NID_undef;
}

static const char *curve_group_name(const char *crv)
{
	if (strcmp(crv, "P-256") == 0)
		return "prime256v1";
	if (strcmp(crv, "P-384") == 0)
		return "secp384r1";
	return "secp521r1";
}

static EVP_PKEY *rsa_pkey(const char *n_b64, const char *e_b64, char *errbuf, size_t errlen)
{
	EVP_PKEY *pkey = NULL;
	BIGNUM *n = jwk_bn(n_b64, errbuf, errlen, "n");
	BIGNUM *e = NULL;

	if (!n)
		return NULL;

	e = jwk_bn(e_b64, errbuf, errlen, "e");
	if (!e) {
		BN_free(n);
		return NULL;
	}

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	{
		OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
		OSSL_PARAM *params = NULL;
		EVP_PKEY_CTX *ctx = NULL;

		if (bld &&
		    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n) &&
		    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e))
			params = OSSL_PARAM_BLD_to_param(bld);

		if (params) {
			ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
			if (ctx && EVP_PKEY_fromdata_init(ctx) > 0)
				EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params);
		}

		EVP_PKEY_CTX_free(ctx);
		OSSL_PARAM_free(params);
		OSSL_PARAM_BLD_free(bld);
		BN_free(n);
		BN_free(e);
	}
#else
	{
		RSA *rsa = RSA_new();

		/* RSA_set0_key takes ownership of n and e on success. */
		if (rsa && RSA_set0_key(rsa, n, e, NULL)) {
			pkey = EVP_PKEY_new();
			if (pkey && EVP_PKEY_assign_RSA(pkey, rsa) <= 0) {
				EVP_PKEY_free(pkey);
				pkey = NULL;
			}
			if (!pkey)
				RSA_free(rsa);
		} else {
			RSA_free(rsa);
			BN_free(n);
			BN_free(e);
		}
	}
#endif

	if (!pkey)
		OIDC_SET_ERR(errbuf, errlen, "cannot build RSA key from JWK");

	return pkey;
}

static EVP_PKEY *ec_pkey(const char *crv, const char *x_b64, const char *y_b64,
			 char *errbuf, size_t errlen)
{
	EVP_PKEY *pkey = NULL;
	unsigned char *point = NULL;
	size_t fieldlen;
	unsigned char *x = NULL, *y = NULL;
	size_t xlen = 0, ylen = 0;
	int nid = curve_nid(crv);

	if (nid == NID_undef) {
		OIDC_SET_ERR(errbuf, errlen, "unsupported JWK curve \"%s\"", crv ? crv : "");
		return NULL;
	}
	if (!x_b64 || !y_b64) {
		OIDC_SET_ERR(errbuf, errlen, "EC JWK is missing \"x\" or \"y\"");
		return NULL;
	}

	x = oidc_base64url_decode(x_b64, strlen(x_b64), &xlen);
	y = oidc_base64url_decode(y_b64, strlen(y_b64), &ylen);
	if (!x || !y) {
		OIDC_SET_ERR(errbuf, errlen, "EC JWK coordinates are not valid base64url");
		goto out;
	}

	/*
	 * Coordinates are fixed-width for the curve and may carry leading zeros;
	 * P-521 uses 66 bytes, not 65.
	 */
	fieldlen = (nid == NID_X9_62_prime256v1) ? 32 : (nid == NID_secp384r1) ? 48 : 66;
	if (xlen > fieldlen || ylen > fieldlen) {
		OIDC_SET_ERR(errbuf, errlen, "EC JWK coordinates are too large for %s", crv);
		goto out;
	}

	/* Uncompressed point: 0x04 || X || Y, both left-padded. */
	point = calloc(1, 1 + 2 * fieldlen);
	if (!point)
		goto out;
	point[0] = 0x04;
	memcpy(point + 1 + (fieldlen - xlen), x, xlen);
	memcpy(point + 1 + fieldlen + (fieldlen - ylen), y, ylen);

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	{
		OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
		OSSL_PARAM *params = NULL;
		EVP_PKEY_CTX *ctx = NULL;

		if (bld &&
		    OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME,
						    (char *)curve_group_name(crv), 0) &&
		    OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY,
						     point, 1 + 2 * fieldlen))
			params = OSSL_PARAM_BLD_to_param(bld);

		if (params) {
			ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
			if (ctx && EVP_PKEY_fromdata_init(ctx) > 0)
				EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params);
		}

		EVP_PKEY_CTX_free(ctx);
		OSSL_PARAM_free(params);
		OSSL_PARAM_BLD_free(bld);
	}
#else
	{
		EC_KEY *ec = EC_KEY_new_by_curve_name(nid);

		if (ec && EC_KEY_oct2key(ec, point, 1 + 2 * fieldlen, NULL) == 1) {
			pkey = EVP_PKEY_new();
			if (pkey && EVP_PKEY_assign_EC_KEY(pkey, ec) <= 0) {
				EVP_PKEY_free(pkey);
				pkey = NULL;
			}
			if (!pkey)
				EC_KEY_free(ec);
		} else {
			EC_KEY_free(ec);
		}
	}
#endif

	if (!pkey)
		OIDC_SET_ERR(errbuf, errlen, "cannot build EC key from JWK");

out:
	free(point);
	free(x);
	free(y);

	return pkey;
}

EVP_PKEY *oidc_jwk_to_pkey(const char *kty, const char *n_b64, const char *e_b64,
			   const char *crv, const char *x_b64, const char *y_b64,
			   char *errbuf, size_t errlen)
{
	if (!kty) {
		OIDC_SET_ERR(errbuf, errlen, "JWK is missing \"kty\"");
		return NULL;
	}
	if (strcmp(kty, "RSA") == 0)
		return rsa_pkey(n_b64, e_b64, errbuf, errlen);
	if (strcmp(kty, "EC") == 0)
		return ec_pkey(crv, x_b64, y_b64, errbuf, errlen);

	OIDC_SET_ERR(errbuf, errlen, "unsupported JWK key type \"%s\"", kty);

	return NULL;
}

/*
 * JWS carries an ECDSA signature as the fixed-width concatenation R || S,
 * while OpenSSL verifies a DER-encoded ECDSA-Sig-Value.  Convert.
 */
static unsigned char *ecdsa_raw_to_der(const unsigned char *sig, size_t siglen, int *derlen)
{
	ECDSA_SIG *ecsig = ECDSA_SIG_new();
	unsigned char *der = NULL;
	BIGNUM *r = NULL, *s = NULL;

	if (!ecsig)
		return NULL;

	if (siglen % 2 != 0)
		goto fail;

	r = BN_bin2bn(sig, (int)(siglen / 2), NULL);
	s = BN_bin2bn(sig + siglen / 2, (int)(siglen / 2), NULL);
	if (!r || !s)
		goto fail;

	/* Takes ownership of r and s on success. */
	if (!ECDSA_SIG_set0(ecsig, r, s))
		goto fail;
	r = s = NULL;

	*derlen = i2d_ECDSA_SIG(ecsig, &der);
	if (*derlen <= 0) {
		OPENSSL_free(der);
		der = NULL;
	}
	ECDSA_SIG_free(ecsig);
	return der;

fail:
	BN_free(r);
	BN_free(s);
	ECDSA_SIG_free(ecsig);

	return NULL;
}

bool oidc_jws_verify(EVP_PKEY *pkey, const char *alg,
		     const char *signing_input, size_t signing_len,
		     const unsigned char *sig, size_t siglen,
		     char *errbuf, size_t errlen)
{
	EVP_MD_CTX *ctx = NULL;
	EVP_PKEY_CTX *pctx = NULL;
	const EVP_MD *md = NULL;
	enum oidc_sig_family family;
	unsigned char *der = NULL;
	int derlen = 0;
	bool ok = false;
	int rc;

	if (!alg_lookup(alg, &md, &family) || !md) {
		OIDC_SET_ERR(errbuf, errlen, "unsupported signature algorithm \"%s\"",
			     alg ? alg : "(none)");
		return false;
	}

	/*
	 * The key type has to match the algorithm family: a token claiming
	 * ES256 must not be verified against an RSA key just because that is
	 * what the JWKS happened to hand back for the kid.
	 */
	if (family == OIDC_SIG_ECDSA) {
		if (EVP_PKEY_base_id(pkey) != EVP_PKEY_EC) {
			OIDC_SET_ERR(errbuf, errlen, "algorithm \"%s\" does not match the key type", alg);
			return false;
		}
	} else if (EVP_PKEY_base_id(pkey) != EVP_PKEY_RSA &&
		   EVP_PKEY_base_id(pkey) != EVP_PKEY_RSA_PSS) {
		OIDC_SET_ERR(errbuf, errlen, "algorithm \"%s\" does not match the key type", alg);
		return false;
	}

	ctx = EVP_MD_CTX_new();
	if (!ctx) {
		OIDC_SET_ERR(errbuf, errlen, "out of memory");
		return false;
	}

	if (EVP_DigestVerifyInit(ctx, &pctx, md, NULL, pkey) <= 0) {
		OIDC_SET_ERR(errbuf, errlen, "cannot initialize signature verification");
		goto out;
	}

	if (family == OIDC_SIG_RSA_PSS) {
		if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0 ||
		    EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) <= 0 ||
		    EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, md) <= 0) {
			OIDC_SET_ERR(errbuf, errlen, "cannot configure PSS verification");
			goto out;
		}
	}

	if (family == OIDC_SIG_ECDSA) {
		der = ecdsa_raw_to_der(sig, siglen, &derlen);
		if (!der) {
			OIDC_SET_ERR(errbuf, errlen, "malformed ECDSA signature");
			goto out;
		}
		rc = EVP_DigestVerify(ctx, der, (size_t)derlen,
				      (const unsigned char *)signing_input, signing_len);
	} else {
		rc = EVP_DigestVerify(ctx, sig, siglen,
				      (const unsigned char *)signing_input, signing_len);
	}

	if (rc == 1) {
		ok = true;
	} else {
		OIDC_SET_ERR(errbuf, errlen, "signature does not verify");
	}

out:
	/*
	 * Clear whatever OpenSSL queued, so a later unrelated call is not confused
	 * by a stale error.
	 */
	ERR_clear_error();
	OPENSSL_free(der);
	EVP_MD_CTX_free(ctx);

	return ok;
}
