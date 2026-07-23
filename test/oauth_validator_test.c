/*
 * Standalone smoke test for the example OAuth validator module.
 *
 * It builds no PgBouncer state: it dlopen()s a validator .so, checks the ABI
 * contract, and exercises validate_cb for a known-good and a bad token.  This
 * lets the validator interface be tested without a running server.
 */

#include <assert.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "oauth.h"

int main(int argc, char *argv[])
{
	void *handle;
	OAuthValidatorModuleInit init_fn;
	const OAuthValidatorCallbacks *cb;
	ValidatorModuleState state;
	ValidatorModuleResult result;
	const char *sopath = argc > 1 ? argv[1] : "./oauth_validator.so";
	FILE *f;
	char tokfile[] = "/tmp/pgb_oauth_tokens_XXXXXX";
	int fd;

	/* Write a token file the example validator can read. */
	fd = mkstemp(tokfile);
	assert(fd >= 0);
	f = fdopen(fd, "w");
	assert(f != NULL);
	fputs("# token authn_id\n", f);
	fputs("good-token alice\n", f);
	fclose(f);
	setenv("PGBOUNCER_OAUTH_VALIDATOR_TOKENS", tokfile, 1);

	handle = dlopen(sopath, RTLD_NOW | RTLD_LOCAL);
	if (!handle) {
		fprintf(stderr, "dlopen(%s) failed: %s\n", sopath, dlerror());
		return 1;
	}

	*(void **)(&init_fn) = dlsym(handle, OAUTH_VALIDATOR_INIT_SYMBOL);
	assert(init_fn != NULL);

	cb = init_fn();
	assert(cb != NULL);
	assert(cb->magic == OAUTH_VALIDATOR_MAGIC);
	assert(cb->validate_cb != NULL);

	memset(&state, 0, sizeof(state));
	if (cb->startup_cb)
		cb->startup_cb(&state);

	/* Known-good token: authorized, identity "alice". */
	memset(&result, 0, sizeof(result));
	assert(cb->validate_cb(&state, "good-token", "alice", NULL, NULL, 0, &result) == true);
	assert(result.authorized == true);
	assert(result.authn_id != NULL && strcmp(result.authn_id, "alice") == 0);
	free(result.authn_id);

	/* Unknown token: not authorized. */
	memset(&result, 0, sizeof(result));
	assert(cb->validate_cb(&state, "bad-token", "alice", NULL, NULL, 0, &result) == true);
	assert(result.authorized == false);
	assert(result.authn_id == NULL);
	free(result.authn_id);

	if (cb->shutdown_cb)
		cb->shutdown_cb(&state);

	dlclose(handle);
	unlink(tokfile);

	printf("oauth_validator_test: OK\n");

	return 0;
}
