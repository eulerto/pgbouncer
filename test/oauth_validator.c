/*
 * Example / reference OAuth validator module for PgBouncer.
 *
 * This is a minimal, dependency-free validator intended for testing and as a
 * template for real modules.  It does NOT contact an identity provider; it
 * looks the presented bearer token up in a flat file whose path is given by
 * the environment variable PGBOUNCER_OAUTH_VALIDATOR_TOKENS.  Each non-empty,
 * non-comment line maps a token to the identity it proves:
 *
 *     # token            authn_id
 *     s3cr3t-token-abc   alice
 *     another-token      bob
 *
 * A real validator would instead verify a signed JWT against the issuer's
 * JWKS, or call the provider's RFC 7662 introspection endpoint, and derive
 * authn_id from the validated claims.  Build it as a shared object and point
 * oauth_validator_library at the result.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "oauth.h"

#define MAX_LINE 4096

/* The module ABI entry point is only ever reached through dlsym(). */
const OAuthValidatorCallbacks *_pgbouncer_oauth_validator_module_init(void);

struct token_entry {
	char *token;
	char *authn_id;
	struct token_entry *next;
};

static struct token_entry *token_list;

static void free_tokens(void)
{
	struct token_entry *e = token_list;

	while (e) {
		struct token_entry *next = e->next;
		free(e->token);
		free(e->authn_id);
		free(e);
		e = next;
	}
	token_list = NULL;
}

static void startup(ValidatorModuleState *state)
{
	const char *path = getenv("PGBOUNCER_OAUTH_VALIDATOR_TOKENS");
	char line[MAX_LINE];
	FILE *f;

	if (!path) {
		fprintf(stderr, "oauth_validator: PGBOUNCER_OAUTH_VALIDATOR_TOKENS is not set\n");
		return;
	}

	f = fopen(path, "r");
	if (!f) {
		fprintf(stderr, "oauth_validator: cannot open token file \"%s\"\n", path);
		return;
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
		e->next = token_list;
		token_list = e;
	}

	fclose(f);
}

static void shutdown(ValidatorModuleState *state)
{
	free_tokens();
}

static bool validate(ValidatorModuleState *state,
		     const char *token, const char *role,
		     const char *issuer, const char *scope,
		     ValidatorModuleResult *result)
{
	struct token_entry *e;

	(void) role;
	(void) issuer;
	(void) scope;

	result->authorized = false;
	result->authn_id = NULL;

	for (e = token_list; e; e = e->next) {
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
	.startup_cb = startup,
	.shutdown_cb = shutdown,
	.validate_cb = validate,
};

const OAuthValidatorCallbacks *_pgbouncer_oauth_validator_module_init(void)
{
	return &callbacks;
}
