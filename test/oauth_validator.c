/*
 * Example / reference OAuth validator module for PgBouncer.
 *
 * This is a minimal, dependency-free validator intended for testing and as a
 * template for real modules.  It does NOT contact an identity provider; it
 * looks the presented bearer token up in a flat file.  Each non-empty,
 * non-comment line maps a token to the identity it proves:
 *
 *     # token            authn_id
 *     s3cr3t-token-abc   alice
 *     another-token      bob
 *
 * The module declares the name "example", so it is configured through the
 * matching section in pgbouncer.ini and selected from an HBA line with
 * validator=example:
 *
 *     [oauth:example]
 *     tokens = /etc/pgbouncer/tokens.txt
 *
 * For backwards compatibility the token file may also be named by the
 * environment variable PGBOUNCER_OAUTH_VALIDATOR_TOKENS.
 *
 * A real validator would instead verify a signed JWT against the issuer's
 * JWKS, or call the provider's RFC 7662 introspection endpoint, and derive
 * authn_id from the validated claims.  Build it as a shared object and name
 * it in oauth_validator_libraries.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "oauth.h"

#define MAX_LINE 4096

/*
 * The name this validator answers to, in validator=<name> and [oauth:<name>].
 * Overridable at compile time so the test suite can build a second, distinctly
 * named copy and exercise having several modules loaded at once.
 */
#ifndef VALIDATOR_NAME
#define VALIDATOR_NAME "example"
#endif

/* The module ABI entry point is only ever reached through dlsym(). */
const OAuthValidatorCallbacks *_pgbouncer_oauth_validator_module_init(void);

struct token_entry {
	char *token;
	char *authn_id;
	struct token_entry *next;
};

static void free_tokens(struct token_entry *e)
{
	while (e) {
		struct token_entry *next = e->next;

		free(e->token);
		free(e->authn_id);
		free(e);
		e = next;
	}
}

/*
 * Read the module's own settings.  Rejecting anything unrecognized turns a
 * misspelled key into a startup error instead of a setting that silently does
 * nothing; PgBouncer itself does not know what these keys mean.
 */
static const char *get_options(ValidatorModuleState *state, bool *ok)
{
	const char *path = NULL;
	int i;

	*ok = true;
	for (i = 0; i < state->noptions; i++) {
		const ValidatorOption *opt = &state->options[i];

		if (strcmp(opt->key, "tokens") == 0) {
			path = opt->value;
		} else {
			state->log_cb(state, OAUTH_LOG_ERROR,
				      "unrecognized option \"%s\" in [oauth:%s]",
				      opt->key, state->name);
			*ok = false;
		}
	}
	return path;
}

static bool startup(ValidatorModuleState *state)
{
	struct token_entry *tokens = NULL;
	const char *path;
	char line[MAX_LINE];
	bool ok;
	FILE *f;

	path = get_options(state, &ok);
	if (!ok)
		return false;
	if (!path)
		path = getenv("PGBOUNCER_OAUTH_VALIDATOR_TOKENS");

	if (!path) {
		state->log_cb(state, OAUTH_LOG_ERROR,
			      "no token file configured, set \"tokens\" in [oauth:%s]",
			      state->name);
		return false;
	}

	f = fopen(path, "r");
	if (!f) {
		state->log_cb(state, OAUTH_LOG_ERROR, "cannot open token file \"%s\"", path);
		return false;
	}

	while (fgets(line, sizeof(line), f)) {
		char *tok, *id, *save = NULL;
		struct token_entry *e;

		/* Ignore comments and blank lines. */
		if (line[0] == '#' || line[0] == '\n')
			continue;

		tok = strtok_r(line, " \t\r\n", &save);
		id = strtok_r(NULL, " \t\r\n", &save);
		if (!tok || !id)
			continue;

		e = calloc(1, sizeof(*e));
		if (!e)
			continue;
		e->token = strdup(tok);
		e->authn_id = strdup(id);
		e->next = tokens;
		tokens = e;
	}

	fclose(f);

	/* Only the worker threads read this from here on, so no locking. */
	state->private_data = tokens;

	return true;
}

static void shutdown(ValidatorModuleState *state)
{
	free_tokens(state->private_data);
	state->private_data = NULL;
}

static bool validate(ValidatorModuleState *state,
		     const char *token, const char *role,
		     const char *issuer, const char *scope,
		     int timeout, ValidatorModuleResult *result)
{
	struct token_entry *e;

	(void) role;
	(void) issuer;
	(void) scope;
	/*
	 * This example resolves tokens from a local file, so there is no
	 * network wait to bound; a real validator would apply timeout to
	 * its IdP request (e.g. curl_easy_setopt(..., CURLOPT_TIMEOUT_MS, ...)).
	 */
	(void) timeout;

	result->authorized = false;
	result->authn_id = NULL;

	for (e = state->private_data; e; e = e->next) {
		if (strcmp(e->token, token) == 0) {
			result->authorized = true;
			result->authn_id = strdup(e->authn_id);
			break;
		}
	}

	/* Validation ran successfully. */
	return true;
}

static const OAuthValidatorCallbacks callbacks = {
	.magic = OAUTH_VALIDATOR_MAGIC,
	.name = VALIDATOR_NAME,
	.startup_cb = startup,
	.shutdown_cb = shutdown,
	.validate_cb = validate,
};

const OAuthValidatorCallbacks *_pgbouncer_oauth_validator_module_init(void)
{
	return &callbacks;
}
