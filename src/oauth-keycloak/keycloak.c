/*
 * Keycloak OAuth validator module for PgBouncer.
 *
 * Verifies OAUTHBEARER tokens issued by a Keycloak realm, in one of two
 * modes chosen by the "mode" setting:
 *
 *   jwks        (default) verify the token signature locally against the
 *               realm published signing keys, then check its claims.  No
 *               request to Keycloak per login once the keys are cached, at
 *               the cost of not seeing a token revoked before it expires.
 *
 *   introspect  ask Keycloak about the token on every login (RFC 7662).
 *               Revocation takes effect immediately, but each login costs a
 *               round trip and the realm needs client credentials.
 *
 * The module is configured through its own section in pgbouncer.ini, named
 * after the name it declares:
 *
 *   [oauth:keycloak]
 *   issuer = https://kc.example.com/realms/prod
 *   audience = pgbouncer
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

struct kc_config {
	bool introspect;

	char *issuer;
	char *jwks_url;
	char *introspection_url;
	char *client_id;
	char *client_secret;
	char *authn_claim;
	char *ca_file;

	char **audiences;
	int naudiences;

	/* Scopes required of every token, from require_scope. */
	char **scopes;
	int nscopes;

	int clock_skew;
	int jwks_min_refresh;

	struct oidc_tls_opts tls;
	struct oidc_jwks_cache *jwks;
};

/*
 * Configuration.
 */

static void config_free(struct kc_config *cfg)
{
	if (!cfg)
		return;

	oidc_jwks_free(cfg->jwks);
	free(cfg->issuer);
	free(cfg->jwks_url);
	free(cfg->introspection_url);
	free(cfg->client_id);
	if (cfg->client_secret) {
		/* Do not leave it lying in freed memory. */
		memset(cfg->client_secret, 0, strlen(cfg->client_secret));
		free(cfg->client_secret);
	}
	free(cfg->authn_claim);
	free(cfg->ca_file);
	oidc_free_list(cfg->audiences, cfg->naudiences);
	oidc_free_list(cfg->scopes, cfg->nscopes);
	free(cfg);
}

/*
 * Read the module settings.  PgBouncer does not know what any of these
 * mean, so every key is validated here and anything unrecognized is an error
 * rather than a setting that silently does nothing.
 */
static struct kc_config *config_load(ValidatorModuleState *state)
{
	struct kc_config *cfg = calloc(1, sizeof(*cfg));
	const char *secret_file = NULL;
	const char *mode = NULL;
	bool ok = true;

	if (!cfg) {
		oidc_log(state, OAUTH_LOG_ERROR, "out of memory");
		return NULL;
	}

	cfg->clock_skew = 60;
	/*
	 * Short on purpose: this is the rate limit on refetching, and the
	 * provider keys are refetched precisely when a token names one we do
	 * not have, i.e. just after a rotation.  A long interval would turn
	 * every rotation into an outage of the same length.
	 */
	cfg->jwks_min_refresh = 10;
	cfg->tls.verify_peer = true;

	for (int i = 0; i < state->noptions; i++) {
		const char *key = state->options[i].key;
		const char *val = state->options[i].value;

		if (strcmp(key, "mode") == 0) {
			mode = val;
		} else if (strcmp(key, "issuer") == 0) {
			cfg->issuer = strdup(val);
		} else if (strcmp(key, "jwks_url") == 0) {
			cfg->jwks_url = strdup(val);
		} else if (strcmp(key, "introspection_url") == 0) {
			cfg->introspection_url = strdup(val);
		} else if (strcmp(key, "client_id") == 0) {
			cfg->client_id = strdup(val);
		} else if (strcmp(key, "client_secret") == 0) {
			cfg->client_secret = strdup(val);
		} else if (strcmp(key, "client_secret_file") == 0) {
			secret_file = val;
		} else if (strcmp(key, "authn_claim") == 0) {
			cfg->authn_claim = strdup(val);
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
			oidc_log(state, OAUTH_LOG_ERROR, "unrecognized setting \"%s\" in [oauth:%s]", key, state->name);
			ok = false;
		}
	}

	if (!ok)
		goto fail;

	if (mode) {
		if (strcmp(mode, "introspect") == 0) {
			cfg->introspect = true;
		} else if (strcmp(mode, "jwks") != 0) {
			oidc_log(state, OAUTH_LOG_ERROR, "mode must be \"jwks\" or \"introspect\", not \"%s\"", mode);
			goto fail;
		}
	}

	if (!cfg->issuer || !*cfg->issuer) {
		oidc_log(state, OAUTH_LOG_ERROR, "\"issuer\" is required in [oauth:%s]", state->name);
		goto fail;
	}
	if (strncmp(cfg->issuer, "https://", 8) != 0 &&
	    strncmp(cfg->issuer, "http://", 7) != 0) {
		oidc_log(state, OAUTH_LOG_ERROR, "\"issuer\" must be an http(s) URL");
		goto fail;
	}

	if (secret_file) {
		if (cfg->client_secret) {
			oidc_log(state, OAUTH_LOG_ERROR, "client_secret and client_secret_file are mutually exclusive");
			goto fail;
		}
		cfg->client_secret = oidc_read_secret_file(state, secret_file);
		if (!cfg->client_secret)
			goto fail;
	}

	if (!cfg->authn_claim) {
		cfg->authn_claim = strdup("preferred_username");
		if (!cfg->authn_claim)
			goto fail;
	}

	if (cfg->introspect) {
		if (!cfg->introspection_url) {
			cfg->introspection_url =
				oidc_url_join(cfg->issuer, "/protocol/openid-connect/token/introspect");
			if (!cfg->introspection_url)
				goto fail;
		}
		if (!cfg->client_id || !cfg->client_secret) {
			oidc_log(state, OAUTH_LOG_ERROR, "mode=introspect requires client_id and "
				 "client_secret (or client_secret_file)");
			goto fail;
		}
	} else {
		if (!cfg->jwks_url) {
			cfg->jwks_url = oidc_url_join(cfg->issuer, "/protocol/openid-connect/certs");
			if (!cfg->jwks_url)
				goto fail;
		}
	}

	if (!cfg->tls.verify_peer)
		oidc_log(state, OAUTH_LOG_WARNING, "tls_verify is off, the identity provider is not authenticated");

	cfg->tls.ca_file = cfg->ca_file;

	if (!cfg->introspect) {
		cfg->jwks = oidc_jwks_new(cfg->jwks_url, cfg->jwks_min_refresh, &cfg->tls);
		if (!cfg->jwks) {
			oidc_log(state, OAUTH_LOG_ERROR, "cannot create the JWKS cache");
			goto fail;
		}
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
 * connection (oauth_scope, or the HBA line scope=), so that what clients
 * are told to ask for is also what they are held to.
 */
static void build_policy(const struct kc_config *cfg, const char *scope,
			 char ***scratch, int *nscratch,
			 struct oidc_claims_policy *policy)
{
	memset(policy, 0, sizeof(*policy));
	policy->issuer = cfg->issuer;
	policy->audiences = cfg->audiences;
	policy->naudiences = cfg->naudiences;
	policy->authn_claim = cfg->authn_claim;
	policy->clock_skew = cfg->clock_skew;

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

/* Ask Keycloak about the token (RFC 7662). */
static bool introspect_token(const struct kc_config *cfg, const char *token,
			     const struct oidc_claims_policy *policy, int timeout_ms,
			     ValidatorModuleResult *result, bool *internal,
			     char *errbuf, size_t errlen)
{
	struct oidc_http_response resp;
	char *escaped = NULL;
	char *body = NULL;
	json_t *doc = NULL;
	json_error_t jerr;
	json_t *active;
	char *authn_id = NULL;
	bool ok = false;

	*internal = true;	/* until we have an answer to judge */

	escaped = oidc_http_escape(token);
	if (!escaped) {
		snprintf(errbuf, errlen, "out of memory");
		goto out;
	}
	body = oidc_sprintf("token=%s&token_type_hint=access_token", escaped);
	if (!body) {
		snprintf(errbuf, errlen, "out of memory");
		goto out;
	}

	if (!oidc_http_post_form(cfg->introspection_url, body,
				 cfg->client_id, cfg->client_secret,
				 &cfg->tls, timeout_ms, &resp, errbuf, errlen))
		goto out;

	if (resp.status != 200) {
		snprintf(errbuf, errlen, "introspection endpoint returned HTTP %ld", resp.status);
		oidc_http_response_free(&resp);
		goto out;
	}

	doc = json_loads(resp.body ? resp.body : "", 0, &jerr);
	oidc_http_response_free(&resp);
	if (!doc || !json_is_object(doc)) {
		snprintf(errbuf, errlen, "introspection response is not a JSON object");
		goto out;
	}

	/*
	 * From here on the provider has answered, so any rejection is about the
	 * token rather than about us.
	 */
	*internal = false;
	ok = true;

	active = json_object_get(doc, "active");
	if (!json_is_true(active)) {
		snprintf(errbuf, errlen, "token is not active");
		goto out;
	}

	/*
	 * An active token still has to satisfy the same policy as a locally
	 * verified one: the introspection response carries the same claims.
	 */
	if (!oidc_claims_check(doc, policy, &authn_id, errbuf, errlen))
		goto out;

	result->authorized = true;
	result->authn_id = authn_id;

out:
	free(escaped);
	free(body);
	json_decref(doc);

	return ok;
}

static bool kc_validate(ValidatorModuleState *state,
			const char *token, const char *role,
			const char *issuer, const char *scope,
			int timeout, ValidatorModuleResult *result)
{
	struct kc_config *cfg = state->private_data;
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
	 * token.  If that is not the realm we validate against, clients are
	 * being sent to one provider while their tokens are checked against
	 * another; refuse rather than paper over the misconfiguration.
	 */
	if (issuer && *issuer && strcmp(issuer, cfg->issuer) != 0) {
		oidc_log(state, OAUTH_LOG_ERROR, "configured issuer \"%s\" does not match the advertised issuer \"%s\"",
			 cfg->issuer, issuer);
		return false;
	}

	build_policy(cfg, scope, &scratch, &nscratch, &policy);

	if (cfg->introspect) {
		ok = introspect_token(cfg, token, &policy, timeout, result, &internal,
				      errbuf, sizeof(errbuf));
	} else {
		ok = oidc_jwt_verify(token, cfg->jwks, &policy, timeout,
				     &authn_id, &internal, errbuf, sizeof(errbuf));
		if (ok) {
			result->authorized = true;
			result->authn_id = authn_id;
		}
		/* A token that fails to verify is a rejection, not an error. */
		ok = ok || !internal;
	}

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

static bool kc_startup(ValidatorModuleState *state)
{
	char errbuf[OIDC_ERRLEN] = { 0 };
	struct kc_config *cfg;

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

	oidc_log(state, OAUTH_LOG_INFO, "configured for issuer %s (mode=%s)", cfg->issuer,
		 cfg->introspect ? "introspect" : "jwks");

	return true;
}

static void kc_shutdown(ValidatorModuleState *state)
{
	config_free(state->private_data);
	state->private_data = NULL;
	oidc_http_fini();
}

static const OAuthValidatorCallbacks callbacks = {
	.magic = OAUTH_VALIDATOR_MAGIC,
	.name = "keycloak",
	.startup_cb = kc_startup,
	.shutdown_cb = kc_shutdown,
	.validate_cb = kc_validate,
};

const OAuthValidatorCallbacks *_pgbouncer_oauth_validator_module_init(void)
{
	return &callbacks;
}
