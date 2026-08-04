# Microsoft Entra ID OAuth validator module

An OAuth validator module for PgBouncer that verifies OAUTHBEARER tokens
issued by a Microsoft Entra ID tenant (formerly Azure Active Directory).

The module is a standalone shared object.  It is not part of the `pgbouncer`
binary: PgBouncer `dlopen()`s it at startup when it is named in
`oauth_validator_libraries`.

Tokens are verified locally against the tenant's published signing keys.
Entra ID offers no RFC 7662 introspection endpoint, so unlike the Keycloak
module there is no second mode, and a token stays acceptable until it expires
even if it was revoked.  Keep access token lifetimes short if that matters to
you.

## Building

Needs libcurl, jansson and OpenSSL (1.1.1 or newer), with their development
headers.

The OIDC machinery the module is built on — JWT verification, the JWKS cache,
the HTTP client and the crypto — is shared with the other validator modules
and lives in `../oauth-common`.  It is compiled into this module rather than
linked from elsewhere, so the installed `entra.so` is self-contained.

A tree configured for OAuth builds and installs the module along with
`pgbouncer`, into `$(libdir)/pgbouncer`.  With autoconf, from the top of the
tree,

    make                # or: make entra
    make check          # or: make entra-check
    make install        # or: make entra-install

and with meson, where it is an ordinary target of the build configured
`-Doauth=enabled`,

    meson compile -C build
    meson test -C build entra_test
    meson install -C build

The module can also be built on its own, which needs nothing from the main
build but `include/oauth.h` and `../oauth-common`:

    make
    make check          # unit tests; needs no Entra ID tenant
    make install PREFIX=/usr/local

## Registering PgBouncer with Entra ID

The pooler is an API that clients ask for a token for, so it needs an app
registration of its own:

1. Register an application; its *Application (client) ID* is the `client_id`
   setting below, and the *Directory (tenant) ID* is `tenant`.
2. Under *Expose an API*, accept the default application ID URI
   (`api://<client-id>`) and add a scope, e.g. `user_impersonation`.
3. Grant the clients that will connect permission to that scope, and have
   them request it — the scope PgBouncer advertises through `oauth_scope`
   should be `api://<client-id>/<scope>`.

Tokens issued for Microsoft Graph or any other resource will not be accepted:
their audience is not this application.

## Configuring PgBouncer

    [pgbouncer]
    auth_type = oauth
    oauth_validator_libraries = /usr/local/lib/pgbouncer/entra.so
    oauth_issuer = https://login.microsoftonline.com/<tenant-id>/v2.0
    oauth_scope = api://<client-id>/user_impersonation

    [oauth:entra]
    tenant = 00000000-1111-2222-3333-444444444444
    client_id = 55555555-6666-7777-8888-999999999999

The section is named after the name the module declares, `entra`.  With
several validator modules loaded, an HBA line selects this one with
`validator=entra`.

PgBouncer reads this section once at startup and does not revisit it on
`RELOAD`; changing it requires a restart.

## Settings

| Setting | Default | Meaning |
| --- | --- | --- |
| `tenant` | *(required)* | The directory (tenant) id, or one of its verified domains.  `common`, `organizations` and `consumers` are refused: they would accept tokens from every other tenant too. |
| `client_id` | *(none)* | The pooler's application (client) id.  Accepted in `aud` both bare and as `api://<client_id>`.  Either this or `audience` is required. |
| `audience` | *(none)* | Comma-separated audiences to accept instead of, or as well as, the ones derived from `client_id`. |
| `token_version` | `2` | Which access token format to accept, `2` or `1`.  A property of the app registration (`accessTokenAcceptedVersion`), not of the request.  The two differ in their issuer and in how the identity is spelled, so only one is accepted at a time. |
| `require_scope` | *(none)* | Comma-separated scopes every token must carry in `scp` (delegated permissions).  When unset, the scope PgBouncer advertises for the connection (`oauth_scope`, or `scope=` on the HBA line) is required instead. |
| `require_role` | *(none)* | Comma-separated app roles every token must carry in `roles` (application permissions, i.e. client-credentials logins). |
| `authn_claim` | `preferred_username,oid` for v2, `upn,unique_name,oid` for v1 | Comma-separated claims the proven identity is taken from, in order; the first one the token carries wins.  Unless the HBA line sets `delegate_ident_mapping=1`, PgBouncer requires the result to equal the role being logged into, or to map to it through `map=`. |
| `clock_skew` | `60` | Seconds of tolerance on `exp` and `nbf`. |
| `authority` | `https://login.microsoftonline.com` | The login host, for the sovereign clouds (`login.microsoftonline.us`, `login.partner.microsoftonline.cn`).  Only affects derived URLs. |
| `issuer` | *derived* | Overrides `<authority>/<tenant>/v2.0`, or `https://sts.windows.net/<tenant>/` for v1.  Needed with a sovereign cloud and `token_version = 1`. |
| `jwks_url` | *derived* | Overrides `<authority>/<tenant>/discovery/v2.0/keys`. |
| `jwks_min_refresh` | `10` | Shortest interval, in seconds, between two fetches of the signing keys.  A rate limit, not a cache lifetime: keys are refetched when a token names a key id we do not have, which is what a rotation looks like, so raising this delays recovery from a rotation by the same amount. |
| `ca_file` | *(system store)* | CA bundle used to verify the login endpoint's certificate. |
| `tls_verify` | `1` | Turning this off means the identity provider is not authenticated.  Testing only. |

Any other key is a startup error; PgBouncer cannot check the spelling of
settings it does not know, so the module does it.

## What is verified

A token is accepted only if it

* is signed by one of the tenant's published keys, with an algorithm from a
  fixed list of RSA and ECDSA algorithms — never `none`, and never an HMAC
  algorithm, whose "public" key would be a shared secret;
* has not expired and has become valid (within `clock_skew`);
* was issued by the configured `issuer`;
* carries the configured tenant in `tid`, when the tenant is named by id;
* carries the expected `ver`;
* carries one of the accepted audiences;
* carries every required scope (`scp`) and role (`roles`);
* names an identity in one of the `authn_claim` claims.

`tid` matters as much as `iss` here: the login endpoint is shared by every
tenant, so a token from someone else's directory is a real, correctly signed
token — it just is not yours.

## Identities

A user's token carries `preferred_username`, which is usually their UPN, so
the PostgreSQL role has to be named for it — or mapped to it with `map=` on
the HBA line, which is what usernames like `alice@contoso.com` normally call
for.

A client-credentials (service principal) token carries no username at all,
only `oid`, the object id of the service principal.  That is what the default
`authn_claim` falls back to; map it, or set `delegate_ident_mapping=1` and let
the token's own authorization decide.

## Tests

    make check

runs `entra_test`, which needs no Entra ID tenant: it mints its own signing
key, serves a JWKS from a throwaway HTTP server on localhost, and signs
Entra-shaped tokens.  It covers the settings, the URLs derived from them, and
the claim policy — including that another tenant's correctly signed token is
turned down, and that a service principal's token is identified by `oid`.

The shared core underneath is covered by `oidc_test` in `../oauth-common`, and
the seam with PgBouncer itself by `test/test_oauth.py`.  None of them talk to
a real tenant; point the module at a test tenant for that.
