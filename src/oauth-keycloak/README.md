# Keycloak OAuth validator module

An OAuth validator module for PgBouncer that verifies OAUTHBEARER tokens
issued by a Keycloak realm.

The module is a standalone shared object.  It is not part of the `pgbouncer`
binary: PgBouncer `dlopen()`s it at startup when it is named in
`oauth_validator_libraries`.

## Building

Needs libcurl, jansson and OpenSSL (1.1.1 or newer), with their development
headers.

A tree configured for OAuth builds and installs the module along with
`pgbouncer`, into `$(libdir)/pgbouncer`.  With autoconf, from the top of the
tree,

    make                # or: make keycloak
    make check          # or: make keycloak-check
    make install        # or: make keycloak-install

and with meson, where it is an ordinary target of the build configured
`-Doauth=enabled`,

    meson compile -C build
    meson test -C build kc_test
    meson install -C build

Meson leaves the module out, with a message, if OpenSSL was not found; OAuth
itself does not need OpenSSL, this module does.

The module can also be built on its own, which needs nothing from the main
build but `include/oauth.h`:

    make
    make check          # unit tests; needs no Keycloak
    make install PREFIX=/usr/local

## Configuring PgBouncer

    [pgbouncer]
    auth_type = oauth
    oauth_validator_libraries = /usr/local/lib/pgbouncer/keycloak.so
    oauth_issuer = https://kc.example.com/realms/prod
    oauth_scope = openid email

    [oauth:keycloak]
    issuer = https://kc.example.com/realms/prod
    audience = pgbouncer

The section is named after the name the module declares, `keycloak`.  With
several validator modules loaded, an HBA line selects this one with
`validator=keycloak`.

PgBouncer reads this section once at startup and does not revisit it on
`RELOAD`; changing it requires a restart.

## Settings

| Setting | Default | Meaning |
| --- | --- | --- |
| `issuer` | *(required)* | The realm URL.  A token `iss` must equal it exactly, and the other endpoints are derived from it. |
| `mode` | `jwks` | `jwks` verifies signatures locally; `introspect` asks Keycloak about every token. |
| `audience` | *(none)* | Comma-separated.  If set, the token `aud` must contain one of them.  Strongly recommended: without it, any token from the realm is accepted, including ones issued for another client. |
| `require_scope` | *(none)* | Comma-separated scopes every token must carry.  When unset, the scope PgBouncer advertises for the connection (`oauth_scope`, or `scope=` on the HBA line) is required instead. |
| `authn_claim` | `preferred_username` | Claim the proven identity is taken from.  Unless the HBA line sets `delegate_ident_mapping=1`, PgBouncer requires this to equal the role being logged into, or to map to it through `map=`. |
| `clock_skew` | `60` | Seconds of tolerance on `exp` and `nbf`. |
| `jwks_url` | *derived* | Overrides `<issuer>/protocol/openid-connect/certs`. |
| `jwks_min_refresh` | `10` | Shortest interval, in seconds, between two fetches of the signing keys.  A rate limit, not a cache lifetime: keys are refetched when a token names a key id we do not have, which is what a rotation looks like, so raising this delays recovery from a rotation by the same amount. |
| `introspection_url` | *derived* | Overrides `<issuer>/protocol/openid-connect/token/introspect`. |
| `client_id` | *(none)* | Required for `mode=introspect`. |
| `client_secret` | *(none)* | The client secret, in the ini file. |
| `client_secret_file` | *(none)* | Path to a file holding the secret instead.  Preferred: `pgbouncer.ini` tends to be readable by more people than a mode 0600 file needs to be. |
| `ca_file` | *(system store)* | CA bundle used to verify Keycloak certificate. |
| `tls_verify` | `1` | Turning this off means the identity provider is not authenticated.  Testing only. |

Any other key is a startup error; PgBouncer cannot check the spelling of
settings it does not know, so the module does it.

## Choosing a mode

`jwks` verifies the signature and claims locally.  After the first login the
realm keys are cached, so a login costs no network round trip and an
unavailable Keycloak does not stop anyone from connecting.  The cost is that
a token stays acceptable until it expires, even if it was revoked.

`introspect` asks Keycloak about every token, so revocation takes effect at
once.  The cost is a round trip per login, on a validation worker thread; size
`oauth_validator_workers` accordingly, and remember that `oauth_validator_timeout`
is the only bound on how long a login waits for Keycloak.

## What is verified

In both modes a token is accepted only if it

* is signed by one of the realm published keys, with an algorithm from a
  fixed list of RSA and ECDSA algorithms — never `none`, and never an HMAC
  algorithm, whose "public" key would be a shared secret;
* has not expired and has become valid (within `clock_skew`);
* was issued by the configured `issuer`;
* carries one of the configured audiences, when `audience` is set;
* carries every required scope;
* names an identity in `authn_claim`.

In `introspect` mode Keycloak must additionally report it as `active`.

## Tests

`make check` runs `kc_test`, which mints its own keys, serves a JWKS from a
throwaway HTTP server on localhost, and signs its own tokens.  It covers
base64url, JWK-to-key conversion, RSA and ECDSA verification, the claim
policy, and the JWKS cache, including that a bad signature is reported as a
rejected token while an unreachable provider is reported as an internal error
— PgBouncer logs the two very differently.

It does not cover talking to a real Keycloak; point the module at a test realm
for that.
