# OAuth validator modules

When `auth_type` is `oauth`, PgBouncer speaks the `OAUTHBEARER` SASL mechanism
to the client and hands the bearer token to a *validator module*: a shared
library, named in `oauth_validator_libraries`, that decides whether the token
is good and whose identity it proves.  PgBouncer never interprets tokens
itself, so everything provider-specific lives in the module.

A worked example ships in `src/oauth-keycloak`; `test/oauth_validator.c` is a
minimal dependency-free one to start from.  The interface is declared in
`include/oauth.h`, which is the only PgBouncer header a module needs.

## Contract

A module must export

    const OAuthValidatorCallbacks *_pgbouncer_oauth_validator_module_init(void);

returning a static struct whose `magic` is `OAUTH_VALIDATOR_MAGIC`.  A
mismatch is a startup error: the constant is bumped whenever the interface
changes, so that a module built against an older PgBouncer is refused rather
than mis-called.

The struct carries the module's `name` and three callbacks:

| Callback | Thread | Purpose |
| --- | --- | --- |
| `startup_cb` | main, once at startup | Read the module's settings and prepare its state.  Returning false is a fatal configuration error. |
| `validate_cb` | validation worker | Judge one token.  Required. |
| `shutdown_cb` | main | Release what `startup_cb` acquired. |

### The name

`name` is how the rest of the configuration refers to the module: it selects
the module from an HBA line (`validator=<name>`) and names its configuration
section (`[oauth:<name>]`).  It must be unique among the loaded modules and
limited to letters, digits, `_`, `-` and `.`.

### State and settings

Every callback receives a `ValidatorModuleState` belonging to this module:

* `name` — as declared;
* `options` / `noptions` — the module's `[oauth:<name>]` settings, as
  uninterpreted key/value strings in file order.  PgBouncer cannot know what
  they mean, so validating them (and rejecting misspelled ones) is the
  module's job.  They are read once at startup; `RELOAD` does not revisit
  them, and the strings stay valid for the life of the process;
* `log_cb` — write a line to PgBouncer's log, tagged with the module's name.
  Use it rather than stderr, which goes to `/dev/null` once PgBouncer
  daemonizes;
* `private_data` — the module's own, untouched by PgBouncer.

### Validating

    bool validate_cb(ValidatorModuleState *state,
                     const char *token, const char *role,
                     const char *issuer, const char *scope,
                     int timeout, ValidatorModuleResult *result);

`role` is the PostgreSQL role the client is logging in as; `issuer` and
`scope` are what PgBouncer advertises for this connection, from the
`oauth_issuer`/`oauth_scope` settings or the HBA line.

Set `result->authorized` when the token is good, and `result->authn_id` to the
identity it proves — `malloc()`'d, with PgBouncer taking ownership.  Unless
the HBA line sets `delegate_ident_mapping=1`, PgBouncer then requires that
identity to equal `role`, or to map to it through `map=`.

Return value and `authorized` mean different things: return **true** whenever
validation ran, including when the answer was "no"; return **false** only when
the token could not be judged at all, such as an identity provider that did
not answer.  The two are logged differently.

### Threads and time

`validate_cb` runs on one of `oauth_validator_workers` background threads, so
it must be thread-safe and must not touch PgBouncer's own state.  PgBouncer
cannot preempt it: `timeout` (milliseconds, 0 for none) is a *cooperative*
deadline from `oauth_validator_timeout`, and applying it to the module's own
network wait — for instance libcurl's `CURLOPT_TIMEOUT_MS` — is the module's
responsibility.  A validation that ignores it blocks every login queued behind
it.

Modules are loaded with `RTLD_LOCAL` and are never unloaded while PgBouncer
runs, so two modules with clashing internal symbols can coexist.

## Configuring a module

    [pgbouncer]
    auth_type = oauth
    oauth_validator_libraries = /usr/lib/pgbouncer/keycloak.so

    [oauth:keycloak]
    issuer = https://kc.example.com/realms/prod

With more than one module loaded, each HBA line says which to use:

    host all all 0.0.0.0/0 oauth validator=keycloak

See [pgbouncer(5)](config.md) for `oauth_validator_libraries`, the other
`oauth_*` settings, and the per-line HBA options.
