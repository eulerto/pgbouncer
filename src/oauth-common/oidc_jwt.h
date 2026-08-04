/*
 * Shared OIDC core for PgBouncer's OAuth validator modules.
 *
 * JWT verification and the JWKS cache, plus the claim checks that both
 * validation modes share: an introspection response carries the same claims
 * as the token itself, so it is held to the same policy.
 */

#ifndef OIDC_JWT_H
#define OIDC_JWT_H

#include <stdbool.h>
#include <stddef.h>

#include <jansson.h>

#include "oidc_http.h"

/* What a token has to prove before its bearer is let in. */
struct oidc_claims_policy {
	/* Required "iss", or NULL to accept any issuer (not recommended). */
	const char *issuer;

	/* If naudiences > 0, "aud" must contain one of these. */
	char **audiences;
	int naudiences;

	/* Every one of these must appear in the "scope" claim. */
	char **scopes;
	int nscopes;

	/* Claim the authenticated identity is taken from. */
	const char *authn_claim;

	/* Tolerance in seconds applied to "exp" and "nbf". */
	int clock_skew;
};

/*
 * Check a decoded claim set against the policy.  On success stores a
 * malloc()'d identity in *authn_id (the caller owns it, and hands it to
 * PgBouncer, which frees it).
 */
bool oidc_claims_check(json_t *claims, const struct oidc_claims_policy *policy,
		       char **authn_id, char *errbuf, size_t errlen);

/* Opaque cache of the provider signing keys. */
struct oidc_jwks_cache;

/*
 * Create a cache for the keys published at url.
 *
 * Keys are fetched on demand and kept until a token names a key id that is
 * not among them, which is what happens when the provider rotates: then they
 * are fetched again.  min_refresh is the shortest interval between two
 * fetches, so that tokens carrying bogus key ids cannot be turned into a
 * flood of requests to the provider.  It is a rate limit, not a lifetime:
 * making it long delays recovery from a rotation by that much.
 */
struct oidc_jwks_cache *oidc_jwks_new(const char *url, int min_refresh,
				      const struct oidc_tls_opts *tls);
void oidc_jwks_free(struct oidc_jwks_cache *cache);

/*
 * Verify a compact-serialization JWT: signature against the provider keys,
 * then the claims against the policy.  Safe to call from several worker
 * threads at once.
 *
 * Returns false both for a token that does not check out and for a failure to
 * reach the provider, which PgBouncer reports very differently: *internal is
 * set when the token could not be judged at all (no answer from the JWKS
 * endpoint) rather than judged and rejected.
 */
bool oidc_jwt_verify(const char *token, struct oidc_jwks_cache *jwks,
		     const struct oidc_claims_policy *policy, int timeout_ms,
		     char **authn_id, bool *internal, char *errbuf, size_t errlen);

#endif
