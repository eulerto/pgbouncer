/*
 * Microsoft Entra ID OAuth validator module for PgBouncer.
 *
 * Verifies OAUTHBEARER tokens issued by an Entra ID tenant (formerly Azure
 * Active Directory).  Tokens are verified locally against the tenant's
 * published signing keys: Entra ID offers no RFC 7662 introspection endpoint,
 * so unlike the Keycloak module there is no second mode, and a token stays
 * acceptable until it expires even if it was revoked.
 *
 * The module is configured through its own section in pgbouncer.ini, named
 * after the name it declares:
 *
 *   [oauth:entra]
 *   tenant = 00000000-1111-2222-3333-444444444444
 *   client_id = 55555555-6666-7777-8888-999999999999
 *
 * See README.md in this directory for the full list of settings.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "oauth.h"

#include "oidc_http.h"
#include "oidc_jwt.h"
#include "oidc_util.h"

/* The module ABI entry point is only ever reached through dlsym(). */
const OAuthValidatorCallbacks *_pgbouncer_oauth_validator_module_init(void);

/* Where the tenant's OpenID configuration and keys live. */
#define ENTRA_AUTHORITY "https://login.microsoftonline.com"

/*
 * Entra ID issues access tokens in two shapes.  Which one an application gets
 * is a property of the application registration ("accessTokenAcceptedVersion"),
 * not of the request, so an operator knows which to expect; they differ in the
 * issuer URL and in how the identity is spelled, and accepting either without
 * saying so would mean accepting a wider set of issuers than intended.
 */
#define ENTRA_VER_2 2
#define ENTRA_VER_1 1

/*
 * The tenant placeholders Entra ID accepts in an authority URL.  A token from
 * any tenant would be validated against the same keys, so pinning "iss" and
 * "tid" is the only thing keeping another tenant's users out; refuse them
 * rather than let a pooler accept the whole world.
 */
static const char *const wildcard_tenants[] = { "common", "organizations", "consumers" };

struct entra_config {
	char *tenant;
	char *issuer;
	char *jwks_url;
	char *client_id;
	char *ca_file;

	int token_version;

	char **audiences;
	int naudiences;

	/* Scopes ("scp") required of every token, from require_scope. */
	char **scopes;
	int nscopes;

	/* Roles ("roles") required of every token, from require_role. */
	char **roles;
	int nroles;

	/* Claims the identity is taken from, in order. */
	char **authn_claims;
	int nauthn_claims;

	/* "tid", and "ver" when the version is pinned; see build_policy(). */
	struct oidc_claim_req required[2];
	int nrequired;

	int clock_skew;
	int jwks_min_refresh;

	struct oidc_tls_opts tls;
	struct oidc_jwks_cache *jwks;
};

/*
 * Configuration.
 */

static bool is_wildcard_tenant(const char *tenant)
{
	for (size_t i = 0; i < sizeof(wildcard_tenants) / sizeof(wildcard_tenants[0]); i++) {
		if (strcmp(tenant, wildcard_tenants[i]) == 0)
			return true;
	}

	return false;
}

/*
 * True for the canonical form of a tenant id, 8-4-4-4-12 hex digits.  A tenant
 * may also be named by one of its verified domains, which is why this only
 * decides whether "tid" can be pinned, not whether the setting is valid.
 */
static bool is_tenant_id(const char *tenant)
{
	static const int groups[] = { 8, 4, 4, 4, 12 };
	const char *p = tenant;

	for (size_t g = 0; g < sizeof(groups) / sizeof(groups[0]); g++) {
		for (int i = 0; i < groups[g]; i++) {
			if (!((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f') ||
			      (*p >= 'A' && *p <= 'F')))
				return false;
			p++;
		}
		if (g < 4 && *p++ != '-')
			return false;
	}

	return *p == '\0';
}

static void config_free(struct entra_config *cfg)
{
	if (!cfg)
		return;

	oidc_jwks_free(cfg->jwks);
	free(cfg->tenant);
	free(cfg->issuer);
	free(cfg->jwks_url);
	free(cfg->client_id);
	free(cfg->ca_file);
	oidc_free_list(cfg->audiences, cfg->naudiences);
	oidc_free_list(cfg->scopes, cfg->nscopes);
	oidc_free_list(cfg->roles, cfg->nroles);
	oidc_free_list(cfg->authn_claims, cfg->nauthn_claims);
	free(cfg);
}

/*
 * The audiences a token may carry.  An API registered in Entra ID is named
 * either by its application id or by an "api://" URI built from it, and which
 * one appears in "aud" depends on how the client asked for the token, so
 * accept both rather than make the operator guess.
 */
static bool add_client_id_audiences(struct entra_config *cfg)
{
	char **grown;
	char *uri = oidc_sprintf("api://%s", cfg->client_id);

	if (!uri)
		return false;

	grown = realloc(cfg->audiences, (size_t)(cfg->naudiences + 2) * sizeof(*grown));
	if (!grown) {
		free(uri);
		return false;
	}
	cfg->audiences = grown;

	cfg->audiences[cfg->naudiences] = strdup(cfg->client_id);
	if (!cfg->audiences[cfg->naudiences]) {
		free(uri);
		return false;
	}
	cfg->naudiences++;
	cfg->audiences[cfg->naudiences++] = uri;

	return true;
}

/*
 * Read the module settings.  PgBouncer does not know what any of these mean,
 * so every key is validated here and anything unrecognized is an error rather
 * than a setting that silently does nothing.
 */
static struct entra_config *config_load(ValidatorModuleState *state)
{
	struct entra_config *cfg = calloc(1, sizeof(*cfg));
	const char *authority = ENTRA_AUTHORITY;
	const char *version = NULL;
	const char *authn_claim = NULL;
	bool ok = true;

	if (!cfg) {
		oidc_log(state, OAUTH_LOG_ERROR, "out of memory");
		return NULL;
	}

	cfg->token_version = ENTRA_VER_2;
	cfg->clock_skew = 60;
	/*
	 * Short on purpose: this is the rate limit on refetching, and Entra ID
	 * rotates its signing keys regularly.  A long interval would turn every
	 * rotation into an outage of the same length.
	 */
	cfg->jwks_min_refresh = 10;
	cfg->tls.verify_peer = true;

	for (int i = 0; i < state->noptions; i++) {
		const char *key = state->options[i].key;
		const char *val = state->options[i].value;

		if (strcmp(key, "tenant") == 0) {
			cfg->tenant = strdup(val);
		} else if (strcmp(key, "authority") == 0) {
			authority = val;
		} else if (strcmp(key, "issuer") == 0) {
			cfg->issuer = strdup(val);
		} else if (strcmp(key, "jwks_url") == 0) {
			cfg->jwks_url = strdup(val);
		} else if (strcmp(key, "client_id") == 0) {
			cfg->client_id = strdup(val);
		} else if (strcmp(key, "token_version") == 0) {
			version = val;
		} else if (strcmp(key, "authn_claim") == 0) {
			authn_claim = val;
		} else if (strcmp(key, "ca_file") == 0) {
			cfg->ca_file = strdup(val);
		} else if (strcmp(key, "audience") == 0) {
			if (!oidc_split_list(val, &cfg->audiences, &cfg->naudiences)) {
				oidc_log(state, OAUTH_LOG_ERROR, "cannot parse audience");
				ok = false;
			}
		} else if (strcmp(key, "require_scope") == 0) {
			if (!oidc_split_list(val, &cfg->scopes, &cfg->nscopes)) {
				oidc_log(state, OAUTH_LOG_ERROR, "cannot parse require_scope");
				ok = false;
			}
		} else if (strcmp(key, "require_role") == 0) {
			if (!oidc_split_list(val, &cfg->roles, &cfg->nroles)) {
				oidc_log(state, OAUTH_LOG_ERROR, "cannot parse require_role");
				ok = false;
			}
		} else if (strcmp(key, "clock_skew") == 0) {
			if (!oidc_parse_int(val, &cfg->clock_skew)) {
				oidc_log(state, OAUTH_LOG_ERROR, "clock_skew must be a number of seconds");
				ok = false;
			}
		} else if (strcmp(key, "jwks_min_refresh") == 0) {
			if (!oidc_parse_int(val, &cfg->jwks_min_refresh)) {
				oidc_log(state, OAUTH_LOG_ERROR, "jwks_min_refresh must be a number of seconds");
				ok = false;
			}
		} else if (strcmp(key, "tls_verify") == 0) {
			if (!oidc_parse_bool(val, &cfg->tls.verify_peer)) {
				oidc_log(state, OAUTH_LOG_ERROR, "tls_verify must be a boolean");
				ok = false;
			}
		} else {
			oidc_log(state, OAUTH_LOG_ERROR, "unrecognized setting \"%s\" in [oauth:%s]",
				 key, state->name);
			ok = false;
		}
	}

	if (!ok)
		goto fail;

	if (!cfg->tenant || !*cfg->tenant) {
		oidc_log(state, OAUTH_LOG_ERROR, "\"tenant\" is required in [oauth:%s]", state->name);
		goto fail;
	}
	if (is_wildcard_tenant(cfg->tenant)) {
		oidc_log(state, OAUTH_LOG_ERROR,
			 "\"tenant\" must name one tenant, not \"%s\": tokens from every "
			 "other tenant would be accepted as well", cfg->tenant);
		goto fail;
	}

	if (version) {
		if (strcmp(version, "2") == 0) {
			cfg->token_version = ENTRA_VER_2;
		} else if (strcmp(version, "1") == 0) {
			cfg->token_version = ENTRA_VER_1;
		} else {
			oidc_log(state, OAUTH_LOG_ERROR, "token_version must be \"1\" or \"2\", not \"%s\"",
				 version);
			goto fail;
		}
	}

	/*
	 * v1 and v2 tokens name their issuer differently, and the v1 authority
	 * is a different host altogether.
	 */
	if (!cfg->issuer) {
		cfg->issuer = cfg->token_version == ENTRA_VER_2 ?
			      oidc_sprintf("%s/%s/v2.0", authority, cfg->tenant) :
			      oidc_sprintf("https://sts.windows.net/%s/", cfg->tenant);
		if (!cfg->issuer)
			goto fail;
	}

	/*
	 * The keys are the tenant's either way: a v1 token is signed with the
	 * same keys and published at the v2 endpoint.
	 */
	if (!cfg->jwks_url) {
		cfg->jwks_url = oidc_sprintf("%s/%s/discovery/v2.0/keys", authority, cfg->tenant);
		if (!cfg->jwks_url)
			goto fail;
	}

	if (cfg->client_id && !add_client_id_audiences(cfg)) {
		oidc_log(state, OAUTH_LOG_ERROR, "out of memory");
		goto fail;
	}
	if (cfg->naudiences == 0) {
		oidc_log(state, OAUTH_LOG_ERROR,
			 "\"client_id\" or \"audience\" is required in [oauth:%s]: without one, "
			 "any token from the tenant would be accepted, including tokens "
			 "issued for another application", state->name);
		goto fail;
	}

	/*
	 * Entra ID describes principals differently depending on what they are:
	 * a user has a username, a service principal (client credentials) has
	 * only an object id.  Take the first claim the token actually carries.
	 */
	if (!oidc_split_list(authn_claim ? authn_claim :
			     (cfg->token_version == ENTRA_VER_2 ?
			      "preferred_username,oid" : "upn,unique_name,oid"),
			     &cfg->authn_claims, &cfg->nauthn_claims)) {
		oidc_log(state, OAUTH_LOG_ERROR, "cannot parse authn_claim");
		goto fail;
	}

	/*
	 * "tid" is what actually ties a token to the tenant; the issuer says the
	 * same thing, but only when it was derived rather than configured.  Pin
	 * it whenever the tenant is named by id, which is the canonical form.
	 */
	if (is_tenant_id(cfg->tenant)) {
		cfg->required[cfg->nrequired].name = "tid";
		cfg->required[cfg->nrequired].value = cfg->tenant;
		cfg->nrequired++;
	}
	cfg->required[cfg->nrequired].name = "ver";
	cfg->required[cfg->nrequired].value = cfg->token_version == ENTRA_VER_2 ? "2.0" : "1.0";
	cfg->nrequired++;

	if (!cfg->tls.verify_peer)
		oidc_log(state, OAUTH_LOG_WARNING, "tls_verify is off, the identity provider is not authenticated");

	cfg->tls.ca_file = cfg->ca_file;

	cfg->jwks = oidc_jwks_new(cfg->jwks_url, cfg->jwks_min_refresh, &cfg->tls);
	if (!cfg->jwks) {
		oidc_log(state, OAUTH_LOG_ERROR, "cannot create the JWKS cache");
		goto fail;
	}

	return cfg;

fail:
	config_free(cfg);

	return NULL;
}

/*
 * Validation.
 */

/*
 * Assemble the claim policy for one login.  Scopes come from require_scope
 * when it is set, and otherwise from the scope PgBouncer advertises for this
 * connection (oauth_scope, or the HBA line scope=), so that what clients are
 * told to ask for is also what they are held to.
 */
static void build_policy(struct entra_config *cfg, const char *scope,
			 char ***scratch, int *nscratch,
			 struct oidc_claims_policy *policy)
{
	memset(policy, 0, sizeof(*policy));
	policy->issuer = cfg->issuer;
	policy->audiences = cfg->audiences;
	policy->naudiences = cfg->naudiences;
	policy->authn_claims = cfg->authn_claims;
	policy->nauthn_claims = cfg->nauthn_claims;
	policy->required = cfg->required;
	policy->nrequired = cfg->nrequired;
	policy->clock_skew = cfg->clock_skew;

	/* Entra ID puts delegated permissions in "scp", not "scope" ... */
	policy->scope_claim = "scp";
	/* ... and application permissions in "roles". */
	policy->role_claim = "roles";
	policy->roles = cfg->roles;
	policy->nroles = cfg->nroles;

	*scratch = NULL;
	*nscratch = 0;

	if (cfg->nscopes > 0) {
		policy->scopes = cfg->scopes;
		policy->nscopes = cfg->nscopes;
	} else if (scope && *scope && oidc_split_list(scope, scratch, nscratch)) {
		policy->scopes = *scratch;
		policy->nscopes = *nscratch;
	}
}

static bool entra_validate(ValidatorModuleState *state,
			   const char *token, const char *role,
			   const char *issuer, const char *scope,
			   int timeout, ValidatorModuleResult *result)
{
	struct entra_config *cfg = state->private_data;
	struct oidc_claims_policy policy;
	char **scratch = NULL;
	int nscratch = 0;
	char errbuf[OIDC_ERRLEN] = { 0 };
	char *authn_id = NULL;
	bool internal = false;
	bool ok;

	result->authorized = false;
	result->authn_id = NULL;

	if (!cfg) {
		oidc_log(state, OAUTH_LOG_ERROR, "module is not configured");
		return false;
	}

	/*
	 * PgBouncer advertises `issuer` to clients that connect without a
	 * token.  If that is not the tenant we validate against, clients are
	 * being sent to one provider while their tokens are checked against
	 * another; refuse rather than paper over the misconfiguration.
	 */
	if (issuer && *issuer && strcmp(issuer, cfg->issuer) != 0) {
		oidc_log(state, OAUTH_LOG_ERROR,
			 "configured issuer \"%s\" does not match the advertised issuer \"%s\"",
			 cfg->issuer, issuer);
		return false;
	}

	build_policy(cfg, scope, &scratch, &nscratch, &policy);

	ok = oidc_jwt_verify(token, cfg->jwks, &policy, timeout,
			     &authn_id, &internal, errbuf, sizeof(errbuf));
	if (ok) {
		result->authorized = true;
		result->authn_id = authn_id;
	}
	/* A token that fails to verify is a rejection, not an error. */
	ok = ok || !internal;

	if (!result->authorized && errbuf[0]) {
		/*
		 * Never log the token itself, only why it was turned down.  A
		 * rejection is routine; being unable to reach the provider is
		 * an operator problem, so it is louder.
		 */
		oidc_log(state, internal ? OAUTH_LOG_ERROR : OAUTH_LOG_WARNING,
			 "%s for user \"%s\": %s",
			 internal ? "cannot validate token" : "rejected token",
			 role ? role : "", errbuf);
	}

	oidc_free_list(scratch, nscratch);

	return ok;
}

/*
 * Module entry points.
 */

static bool entra_startup(ValidatorModuleState *state)
{
	char errbuf[OIDC_ERRLEN] = { 0 };
	struct entra_config *cfg;

	if (!oidc_http_init(errbuf, sizeof(errbuf))) {
		oidc_log(state, OAUTH_LOG_ERROR, "%s", errbuf);
		return false;
	}

	cfg = config_load(state);
	if (!cfg) {
		oidc_http_fini();
		return false;
	}

	state->private_data = cfg;

	oidc_log(state, OAUTH_LOG_INFO, "configured for issuer %s (v%d tokens)",
		 cfg->issuer, cfg->token_version);

	return true;
}

static void entra_shutdown(ValidatorModuleState *state)
{
	config_free(state->private_data);
	state->private_data = NULL;
	oidc_http_fini();
}

static const OAuthValidatorCallbacks callbacks = {
	.magic = OAUTH_VALIDATOR_MAGIC,
	.name = "entra",
	.startup_cb = entra_startup,
	.shutdown_cb = entra_shutdown,
	.validate_cb = entra_validate,
};

const OAuthValidatorCallbacks *_pgbouncer_oauth_validator_module_init(void)
{
	return &callbacks;
}
