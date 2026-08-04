# Shared OIDC core for the validator modules

The parts of OpenID Connect token validation that are the same whoever issued
the token, factored out of the modules that ship with PgBouncer
(`../oauth-keycloak` and `../oauth-entra`).

This is not a module and not a library: there is nothing here for
`oauth_validator_libraries` to name, and nothing is installed.  Each module
compiles these sources into its own shared object, so an installed module is a
single self-contained `.so` that PgBouncer can `dlopen()` without a search
path.

| File | What it holds |
| --- | --- |
| `oidc_crypto.[ch]` | base64url, JWK to OpenSSL key, JWS signature verification.  Parses no JSON. |
| `oidc_jwt.[ch]` | JWT verification, the JWKS cache, and the claim policy a decoded claim set is held to. |
| `oidc_http.[ch]` | The synchronous libcurl client, bounded by the deadline PgBouncer hands to `validate_cb`. |
| `oidc_util.[ch]` | Logging through PgBouncer, string building, and parsing `[oauth:<name>]` setting values. |
| `oidc_testutil.[ch]` | A throwaway JWKS server and token minting, for the tests only. |

## Tests

    make check

runs `oidc_test`, which needs no identity provider: it mints its own signing
keys, serves a JWKS from a throwaway HTTP server on localhost, and signs its
own tokens.  Under meson it is the `oidc_test` target.

## Writing another module

A module supplies what is provider-specific — where the keys live, which
claims mean what, and how the settings are spelled — and calls
`oidc_jwt_verify()` with a `struct oidc_claims_policy` it filled in.
`../oauth-keycloak/keycloak.c` and `../oauth-entra/entra.c` are the two worked
examples; the ABI a module implements is documented in `include/oauth.h`.
