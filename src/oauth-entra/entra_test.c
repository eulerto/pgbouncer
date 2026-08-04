/*
 * Unit tests for the Microsoft Entra ID validator module.
 *
 * These need no Entra ID tenant: the tests mint their own signing key, serve
 * a JWKS from a throwaway HTTP server on localhost, and sign Entra-shaped
 * tokens with the matching private key.  What they cover is what this module
 * adds to the shared OIDC core (which ../oauth-common/oidc_test.c covers on
 * its own): the settings, the URLs derived from them, and the claim policy.
 *
 * entra.c is included rather than linked so that the configuration and policy
 * code can be reached directly; the module's public entry point is used the
 * way PgBouncer would use it.
 *
 *   make check
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <jansson.h>

#include "entra.c"

#include "oidc_testutil.h"

#define TENANT     "00000000-1111-2222-3333-444444444444"
#define OTHER_TID  "99999999-8888-7777-6666-555555555555"
#define CLIENT_ID  "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

static int tests_run;

#define CHECK(cond) do { \
		tests_run++; \
		if (!(cond)) { \
			fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
			exit(1); \
		} \
} while (0)

/*
 * A module state built by hand, the way PgBouncer builds one before calling
 * startup_cb.  Logs are collected so a test can assert on the reason a
 * configuration was refused.
 */
static char log_buf[4096];

static void test_log_cb(ValidatorModuleState *state, int level, const char *fmt, ...)
#ifdef __GNUC__
__attribute__((format(printf, 3, 4)))
#endif
;

static void test_log_cb(ValidatorModuleState *state, int level, const char *fmt, ...)
{
	va_list ap;
	size_t used = strlen(log_buf);

	va_start(ap, fmt);
	vsnprintf(log_buf + used, sizeof(log_buf) - used, fmt, ap);
	va_end(ap);
	strncat(log_buf, "\n", sizeof(log_buf) - strlen(log_buf) - 1);
}

/* Start a state with the given key=value settings, NULL-terminated. */
static ValidatorModuleState *state_new(const char *first, ...)
{
	ValidatorModuleState *state = calloc(1, sizeof(*state));
	ValidatorOption *opts = NULL;
	int n = 0;
	va_list ap;
	const char *key;

	CHECK(state != NULL);
	state->name = "entra";
	state->log_cb = test_log_cb;
	log_buf[0] = '\0';

	va_start(ap, first);
	for (key = first; key; key = va_arg(ap, const char *)) {
		const char *val = va_arg(ap, const char *);

		opts = realloc(opts, (size_t)(n + 1) * sizeof(*opts));
		CHECK(opts != NULL);
		opts[n].key = key;
		opts[n].value = val;
		n++;
	}
	va_end(ap);

	state->options = opts;
	state->noptions = n;

	return state;
}

static void state_free(ValidatorModuleState *state)
{
	free((void *)state->options);
	free(state);
}

/* A configuration that loads, for the tests that need one. */
static ValidatorModuleState *good_state(const char *extra_key, const char *extra_val)
{
	if (extra_key) {
		return state_new("tenant", TENANT, "client_id", CLIENT_ID,
				 extra_key, extra_val, NULL);
	}

	return state_new("tenant", TENANT, "client_id", CLIENT_ID, NULL);
}

/*
 * Tests.
 */

static void test_tenant_id_shape(void)
{
	CHECK(is_tenant_id(TENANT));
	CHECK(is_tenant_id("DEADBEEF-1111-2222-3333-444444444444"));

	/* A verified domain is a legitimate tenant, just not an id. */
	CHECK(!is_tenant_id("contoso.onmicrosoft.com"));
	CHECK(!is_tenant_id(""));
	/* Right shape, wrong alphabet and wrong lengths. */
	CHECK(!is_tenant_id("0000000g-1111-2222-3333-444444444444"));
	CHECK(!is_tenant_id("00000000-1111-2222-3333-44444444444"));
	CHECK(!is_tenant_id("00000000-1111-2222-3333-4444444444444"));
	CHECK(!is_tenant_id("00000000111122223333444444444444"));
}

static void test_config_defaults(void)
{
	ValidatorModuleState *state = good_state(NULL, NULL);
	struct entra_config *cfg;

	CHECK(oidc_http_init(NULL, 0));
	cfg = config_load(state);
	CHECK(cfg != NULL);

	/* v2 by default, with the endpoints that follow from the tenant. */
	CHECK(cfg->token_version == ENTRA_VER_2);
	CHECK(strcmp(cfg->issuer, "https://login.microsoftonline.com/" TENANT "/v2.0") == 0);
	CHECK(strcmp(cfg->jwks_url,
		     "https://login.microsoftonline.com/" TENANT "/discovery/v2.0/keys") == 0);

	/* client_id is accepted in either of the two forms "aud" can carry. */
	CHECK(cfg->naudiences == 2);
	CHECK(strcmp(cfg->audiences[0], CLIENT_ID) == 0);
	CHECK(strcmp(cfg->audiences[1], "api://" CLIENT_ID) == 0);

	/* A user has a username, a service principal only an object id. */
	CHECK(cfg->nauthn_claims == 2);
	CHECK(strcmp(cfg->authn_claims[0], "preferred_username") == 0);
	CHECK(strcmp(cfg->authn_claims[1], "oid") == 0);

	/* The tenant is named by id, so "tid" is pinned as well as "iss". */
	CHECK(cfg->nrequired == 2);
	CHECK(strcmp(cfg->required[0].name, "tid") == 0);
	CHECK(strcmp(cfg->required[0].value, TENANT) == 0);
	CHECK(strcmp(cfg->required[1].name, "ver") == 0);
	CHECK(strcmp(cfg->required[1].value, "2.0") == 0);

	config_free(cfg);
	state_free(state);
	oidc_http_fini();
}

static void test_config_v1(void)
{
	ValidatorModuleState *state = good_state("token_version", "1");
	struct entra_config *cfg;

	CHECK(oidc_http_init(NULL, 0));
	cfg = config_load(state);
	CHECK(cfg != NULL);

	/* v1 tokens name a different issuer, on a different host. */
	CHECK(strcmp(cfg->issuer, "https://sts.windows.net/" TENANT "/") == 0);
	CHECK(strcmp(cfg->required[1].value, "1.0") == 0);
	/* ... and spell the identity differently. */
	CHECK(cfg->nauthn_claims == 3);
	CHECK(strcmp(cfg->authn_claims[0], "upn") == 0);

	config_free(cfg);
	state_free(state);
	oidc_http_fini();
}

static void test_config_by_domain(void)
{
	ValidatorModuleState *state = state_new("tenant", "contoso.onmicrosoft.com",
						"client_id", CLIENT_ID, NULL);
	struct entra_config *cfg;

	CHECK(oidc_http_init(NULL, 0));
	cfg = config_load(state);
	CHECK(cfg != NULL);

	/*
	 * A domain cannot be compared against "tid", which is always an id, so
	 * only "ver" is pinned and the issuer carries the tenant check.
	 */
	CHECK(cfg->nrequired == 1);
	CHECK(strcmp(cfg->required[0].name, "ver") == 0);
	CHECK(strcmp(cfg->issuer,
		     "https://login.microsoftonline.com/contoso.onmicrosoft.com/v2.0") == 0);

	config_free(cfg);
	state_free(state);
	oidc_http_fini();
}

static void test_config_refusals(void)
{
	ValidatorModuleState *state;

	CHECK(oidc_http_init(NULL, 0));

	/* A tenant is required ... */
	state = state_new("client_id", CLIENT_ID, NULL);
	CHECK(config_load(state) == NULL);
	CHECK(strstr(log_buf, "\"tenant\" is required") != NULL);
	state_free(state);

	/* ... and must name one tenant, not every tenant. */
	state = state_new("tenant", "common", "client_id", CLIENT_ID, NULL);
	CHECK(config_load(state) == NULL);
	CHECK(strstr(log_buf, "must name one tenant") != NULL);
	state_free(state);

	state = state_new("tenant", "organizations", "client_id", CLIENT_ID, NULL);
	CHECK(config_load(state) == NULL);
	state_free(state);

	/*
	 * Without an audience any token from the tenant would do, including one
	 * issued for a different application.
	 */
	state = state_new("tenant", TENANT, NULL);
	CHECK(config_load(state) == NULL);
	CHECK(strstr(log_buf, "\"client_id\" or \"audience\" is required") != NULL);
	state_free(state);

	/* A misspelled setting is a startup error, not a silent no-op. */
	state = good_state("nosuchsetting", "1");
	CHECK(config_load(state) == NULL);
	CHECK(strstr(log_buf, "unrecognized setting \"nosuchsetting\"") != NULL);
	state_free(state);

	state = good_state("token_version", "3");
	CHECK(config_load(state) == NULL);
	CHECK(strstr(log_buf, "token_version must be") != NULL);
	state_free(state);

	state = good_state("clock_skew", "soon");
	CHECK(config_load(state) == NULL);
	state_free(state);

	oidc_http_fini();
}

/* Claims of an Entra v2 access token, as JSON. */
static char *entra_claims(long exp, const char *iss, const char *aud, const char *tid,
			  const char *ver, const char *scp, const char *user)
{
	json_t *obj = json_pack("{s:I, s:s, s:s, s:s, s:s, s:s, s:s}",
				"exp", (json_int_t)exp,
				"iss", iss, "aud", aud, "tid", tid,
				"ver", ver, "scp", scp,
				"preferred_username", user);
	char *out = json_dumps(obj, JSON_COMPACT);

	json_decref(obj);

	return out;
}

/*
 * A whole validation, from the module entry point down: PgBouncer hands a
 * token to validate_cb and gets an identity back.
 */
static void test_validate(void)
{
	EVP_PKEY *key = oidc_test_generate_key("RSA", 2048);
	char *jwks_doc = oidc_test_rsa_jwks(key, "kid-1");
	struct oidc_test_server *srv = oidc_test_server_start(jwks_doc);
	const OAuthValidatorCallbacks *cb = _pgbouncer_oauth_validator_module_init();
	ValidatorModuleState *state;
	ValidatorModuleResult result;
	const char *issuer = "https://login.microsoftonline.com/" TENANT "/v2.0";
	long now = (long)time(NULL);
	char jwks_url[128];
	char *claims, *token;

	CHECK(cb != NULL && cb->magic == OAUTH_VALIDATOR_MAGIC);
	CHECK(strcmp(cb->name, "entra") == 0);

	snprintf(jwks_url, sizeof(jwks_url), "http://127.0.0.1:%d/keys",
		 oidc_test_server_port(srv));

	state = state_new("tenant", TENANT, "client_id", CLIENT_ID,
			  "jwks_url", jwks_url, "require_scope", "user_impersonation", NULL);
	CHECK(cb->startup_cb(state));

	/* A token the tenant would issue for this application. */
	claims = entra_claims(now + 300, issuer, CLIENT_ID, TENANT, "2.0",
			      "user_impersonation", "alice@contoso.com");
	token = oidc_test_make_token(key, "RS256", "kid-1", claims);
	memset(&result, 0, sizeof(result));
	CHECK(cb->validate_cb(state, token, "alice", issuer, NULL, 5000, &result));
	CHECK(result.authorized);
	CHECK(result.authn_id != NULL && strcmp(result.authn_id, "alice@contoso.com") == 0);
	free(result.authn_id);
	free(token);
	free(claims);

	/* The "api://" spelling of the audience is the same application. */
	claims = entra_claims(now + 300, issuer, "api://" CLIENT_ID, TENANT, "2.0",
			      "user_impersonation", "alice@contoso.com");
	token = oidc_test_make_token(key, "RS256", "kid-1", claims);
	memset(&result, 0, sizeof(result));
	CHECK(cb->validate_cb(state, token, "alice", issuer, NULL, 5000, &result));
	CHECK(result.authorized);
	free(result.authn_id);
	free(token);
	free(claims);

	/*
	 * Another tenant's token, correctly signed by these keys, is still not
	 * ours: this is what "tid" is pinned for.  A rejection is not an error,
	 * so validate_cb still returns true.
	 */
	claims = entra_claims(now + 300, issuer, CLIENT_ID, OTHER_TID, "2.0",
			      "user_impersonation", "mallory@evil.example");
	token = oidc_test_make_token(key, "RS256", "kid-1", claims);
	memset(&result, 0, sizeof(result));
	CHECK(cb->validate_cb(state, token, "alice", issuer, NULL, 5000, &result));
	CHECK(!result.authorized);
	CHECK(result.authn_id == NULL);
	free(token);
	free(claims);

	/* A v1 token where a v2 one was configured. */
	claims = entra_claims(now + 300, issuer, CLIENT_ID, TENANT, "1.0",
			      "user_impersonation", "alice@contoso.com");
	token = oidc_test_make_token(key, "RS256", "kid-1", claims);
	memset(&result, 0, sizeof(result));
	CHECK(cb->validate_cb(state, token, "alice", issuer, NULL, 5000, &result));
	CHECK(!result.authorized);
	free(token);
	free(claims);

	/* A token for another application. */
	claims = entra_claims(now + 300, issuer, "some-other-api", TENANT, "2.0",
			      "user_impersonation", "alice@contoso.com");
	token = oidc_test_make_token(key, "RS256", "kid-1", claims);
	memset(&result, 0, sizeof(result));
	CHECK(cb->validate_cb(state, token, "alice", issuer, NULL, 5000, &result));
	CHECK(!result.authorized);
	free(token);
	free(claims);

	/* Delegated permissions live in "scp", so a missing one is a rejection. */
	claims = entra_claims(now + 300, issuer, CLIENT_ID, TENANT, "2.0",
			      "openid", "alice@contoso.com");
	token = oidc_test_make_token(key, "RS256", "kid-1", claims);
	memset(&result, 0, sizeof(result));
	CHECK(cb->validate_cb(state, token, "alice", issuer, NULL, 5000, &result));
	CHECK(!result.authorized);
	free(token);
	free(claims);

	/* Expired. */
	claims = entra_claims(now - 3600, issuer, CLIENT_ID, TENANT, "2.0",
			      "user_impersonation", "alice@contoso.com");
	token = oidc_test_make_token(key, "RS256", "kid-1", claims);
	memset(&result, 0, sizeof(result));
	CHECK(cb->validate_cb(state, token, "alice", issuer, NULL, 5000, &result));
	CHECK(!result.authorized);
	free(token);
	free(claims);

	/*
	 * Sending clients to one tenant while checking their tokens against
	 * another is a misconfiguration, not a bad token: an internal error.
	 */
	claims = entra_claims(now + 300, issuer, CLIENT_ID, TENANT, "2.0",
			      "user_impersonation", "alice@contoso.com");
	token = oidc_test_make_token(key, "RS256", "kid-1", claims);
	memset(&result, 0, sizeof(result));
	CHECK(!cb->validate_cb(state, token, "alice",
			       "https://login.microsoftonline.com/" OTHER_TID "/v2.0",
			       NULL, 5000, &result));
	CHECK(!result.authorized);
	free(token);
	free(claims);

	/* Not a JWT at all. */
	memset(&result, 0, sizeof(result));
	CHECK(cb->validate_cb(state, "not-a-jwt", "alice", issuer, NULL, 5000, &result));
	CHECK(!result.authorized);

	cb->shutdown_cb(state);
	state_free(state);
	oidc_test_server_stop(srv);
	free(jwks_doc);
	EVP_PKEY_free(key);
}

/*
 * A service principal token: no username, only an object id, and its
 * permissions in "roles" rather than "scp".
 */
static void test_validate_app_only(void)
{
	EVP_PKEY *key = oidc_test_generate_key("RSA", 2048);
	char *jwks_doc = oidc_test_rsa_jwks(key, "kid-1");
	struct oidc_test_server *srv = oidc_test_server_start(jwks_doc);
	const OAuthValidatorCallbacks *cb = _pgbouncer_oauth_validator_module_init();
	ValidatorModuleState *state;
	ValidatorModuleResult result;
	const char *issuer = "https://login.microsoftonline.com/" TENANT "/v2.0";
	const char *oid = "12121212-3434-5656-7878-909090909090";
	long now = (long)time(NULL);
	char jwks_url[128];
	json_t *obj;
	char *claims, *token;

	snprintf(jwks_url, sizeof(jwks_url), "http://127.0.0.1:%d/keys",
		 oidc_test_server_port(srv));

	state = state_new("tenant", TENANT, "client_id", CLIENT_ID,
			  "jwks_url", jwks_url, "require_role", "db.connect", NULL);
	CHECK(cb->startup_cb(state));

	obj = json_pack("{s:I, s:s, s:s, s:s, s:s, s:s, s:[s,s]}",
			"exp", (json_int_t)(now + 300),
			"iss", issuer, "aud", CLIENT_ID, "tid", TENANT,
			"ver", "2.0", "oid", oid,
			"roles", "db.connect", "db.admin");
	claims = json_dumps(obj, JSON_COMPACT);
	json_decref(obj);

	token = oidc_test_make_token(key, "RS256", "kid-1", claims);
	memset(&result, 0, sizeof(result));
	CHECK(cb->validate_cb(state, token, "svc", issuer, NULL, 5000, &result));
	CHECK(result.authorized);
	/* No preferred_username, so the identity falls through to "oid". */
	CHECK(result.authn_id != NULL && strcmp(result.authn_id, oid) == 0);
	free(result.authn_id);
	free(token);
	free(claims);

	/* The same token without the required role. */
	obj = json_pack("{s:I, s:s, s:s, s:s, s:s, s:s, s:[s]}",
			"exp", (json_int_t)(now + 300),
			"iss", issuer, "aud", CLIENT_ID, "tid", TENANT,
			"ver", "2.0", "oid", oid,
			"roles", "db.admin");
	claims = json_dumps(obj, JSON_COMPACT);
	json_decref(obj);

	token = oidc_test_make_token(key, "RS256", "kid-1", claims);
	memset(&result, 0, sizeof(result));
	CHECK(cb->validate_cb(state, token, "svc", issuer, NULL, 5000, &result));
	CHECK(!result.authorized);
	free(token);
	free(claims);

	cb->shutdown_cb(state);
	state_free(state);
	oidc_test_server_stop(srv);
	free(jwks_doc);
	EVP_PKEY_free(key);
}

int main(void)
{
	test_tenant_id_shape();
	test_config_defaults();
	test_config_v1();
	test_config_by_domain();
	test_config_refusals();
	test_validate();
	test_validate_app_only();

	printf("entra_test: OK (%d checks)\n", tests_run);

	return 0;
}
