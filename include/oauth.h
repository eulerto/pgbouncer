/*
 * PgBouncer - Lightweight connection pooler for PostgreSQL.
 *
 * Copyright (c) 2007-2009  Marko Kreen, Skype Technologies OÜ
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * OAuth (OAUTHBEARER) support.
 *
 * PgBouncer acts as the SASL server for the OAUTHBEARER mechanism: it
 * receives a bearer token from the client and hands it to a loadable
 * validator module, which turns the token into a proven identity.  The
 * validation is performed on a background worker thread (see oauth.c),
 * because it may block on a network round-trip to the identity provider.
 */

#ifndef OAUTH_H
#define OAUTH_H

#include <stdbool.h>
#include <stdint.h>

/*
 * Validator module ABI.
 *
 * A validator module is a shared library loaded at startup via the
 * oauth_validator_library setting.  It must export an initialization
 * function named by OAUTH_VALIDATOR_INIT_SYMBOL that returns a pointer to a
 * static OAuthValidatorCallbacks whose magic field equals
 * OAUTH_VALIDATOR_MAGIC.  The ABI intentionally mirrors PostgreSQL's OAuth
 * validator interface so that validator logic can be shared.
 */

typedef struct ValidatorModuleState {
	/* Holds the server's PACKAGE_VERSION. Reserved for future extensibility. */
	int sversion;

	/*
	 * Private data pointer for use by a validator module. This can be used to
	 * store the state for the module that will be passed to each of its
	 * callbacks.
	 */
	void *private_data;
} ValidatorModuleState;

/* Result of validating a single bearer token. */
typedef struct ValidatorModuleResult {
	/*
	 * Should be set to true if the token carries sufficient permissions for
	 * the bearer to connect.
	 */
	bool authorized;

	/*
	 * The authenticated identity the token proves (e.g. the "sub" or
	 * mapped username), or NULL if the module cannot determine one.  When
	 * non-NULL it must be malloc()'d by the module; PgBouncer takes
	 * ownership and free()s it after the identity check.
	 */
	char *authn_id;
} ValidatorModuleResult;

/*
 * Callbacks a validator module provides.  startup_cb and shutdown_cb run
 * once on the main thread at load and unload.  validate_cb runs on the
 * background worker thread and must be thread-safe and self-contained; it
 * returns false on an internal error (as opposed to a merely unauthorized
 * token, which is reported through result->authorized).
 */
typedef void (*ValidatorStartupCB) (ValidatorModuleState *state);
typedef void (*ValidatorShutdownCB) (ValidatorModuleState *state);
typedef bool (*ValidatorValidateCB) (ValidatorModuleState *state,
				     const char *token, const char *role,
				     const char *issuer, const char *scope,
				     ValidatorModuleResult *result);

/*
 * Identifies the compiled ABI version of the validator module. Bump when the
 * callback struct layout or semantic changes.
 */
#define OAUTH_VALIDATOR_MAGIC 0x20260701

typedef struct OAuthValidatorCallbacks {
	uint32_t magic;		/* must be set to OAUTH_VALIDATOR_MAGIC */

	ValidatorStartupCB startup_cb;
	ValidatorShutdownCB shutdown_cb;
	ValidatorValidateCB validate_cb;
} OAuthValidatorCallbacks;

/*
 * Maximum bearer token size accepted. Tokens are typically JWTs (several
 * kilobytes).
 */
#define OAUTH_MAX_TOKEN 8192

/* Symbol every validator module must export. */
#define OAUTH_VALIDATOR_INIT_SYMBOL "_pgbouncer_oauth_validator_module_init"

/*
 * Type of the shared library symbol _pgbouncer_oauth_validatror_init which is
 * required for all validator modules. This function will be invoked during
 * module loading.
 */
typedef const OAuthValidatorCallbacks *(*OAuthValidatorModuleInit) (void);

/*
 * Defines how many authentication requests can be placed on the waiting
 * queue.  When the queue is full, calls to oauth_auth_begin() block until
 * a slot becomes free.
 */
#define OAUTH_REQUEST_QUEUE_SIZE 20

/* Load the validator module and start the validation worker thread. */
void oauth_init(void);

/*
 * Begin validating a bearer token for a client.  The result becomes
 * available on a later oauth_poll() call.  Called only from the main
 * thread.
 */
void oauth_auth_begin(PgSocket *client, const char *token);

/* Finish any completed validation requests; returns the number handled. */
int oauth_poll(void);

#endif /* OAUTH_H */
