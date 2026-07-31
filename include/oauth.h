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
 * oauth_validator_libraries setting.  It must export an initialization
 * function named by OAUTH_VALIDATOR_INIT_SYMBOL that returns a pointer to a
 * static OAuthValidatorCallbacks whose magic field equals
 * OAUTH_VALIDATOR_MAGIC.  The ABI intentionally mirrors PostgreSQL's OAuth
 * validator interface so that validator logic can be shared.
 *
 * Several modules may be loaded at once.  Each declares a name, which both
 * selects it from an HBA line (validator=<name>) and names its configuration
 * section in pgbouncer.ini ([oauth:<name>]).
 */

/*
 * One key = value pair from the module's [oauth:<name>] configuration section.
 * Both strings are owned by PgBouncer and stay valid for the life of the
 * process; a module that keeps them past startup_cb need not copy them.
 */
typedef struct ValidatorOption {
	const char *key;
	const char *value;
} ValidatorOption;

/* Severity levels accepted by ValidatorLogCB. */
#define OAUTH_LOG_ERROR   0
#define OAUTH_LOG_WARNING 1
#define OAUTH_LOG_INFO    2
#define OAUTH_LOG_DEBUG   3

struct ValidatorModuleState;

/*
 * Write a line to PgBouncer's log, tagged with the module's name.  A module
 * should use this rather than stderr, which goes to /dev/null once PgBouncer
 * daemonizes.  Safe to call from validate_cb on a worker thread.
 */
typedef void (*ValidatorLogCB)(struct ValidatorModuleState *state, int level,
			       const char *fmt, ...)
#ifdef __GNUC__
/*
 * Spelled out rather than through libusual's _PRINTF, since a validator
 * module includes this header without being linked against libusual.
 */
__attribute__((format(printf, 3, 4)))
#endif
;

typedef struct ValidatorModuleState {
	/* Holds the server's PACKAGE_VERSION. Reserved for future extensibility. */
	int sversion;

	/* The name this module declared in OAuthValidatorCallbacks.name. */
	const char *name;

	/* Set by PgBouncer before startup_cb; never NULL. */
	ValidatorLogCB log_cb;

	/*
	 * Options read from the module's [oauth:<name>] section, in file order;
	 * noptions is 0 when the section is absent.  PgBouncer does not interpret
	 * the keys: startup_cb should validate them and return false on anything
	 * it does not recognize, so that a typo is a startup error rather than a
	 * silently ignored setting.  The section is read once at startup; RELOAD
	 * does not revisit it.
	 */
	const ValidatorOption *options;
	int noptions;

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
 * once on the main thread at load and unload.  startup_cb reads the module's
 * configuration out of state->options and returns false to reject it, which
 * is a fatal startup error.  validate_cb runs on the background worker thread
 * and must be thread-safe and self-contained; it returns false on an internal
 * error (as opposed to a merely unauthorized token, which is reported through
 * result->authorized).
 *
 * timeout (in milliseconds) that the module must apply to its own blocking
 * work (e.g. libcurl CURLOPT_TIMEOUT_MS); 0 means no limit.  PgBouncer runs
 * validate_cb on a detached worker thread it cannot preempt, so honoring the
 * timeout is the module responsibility: a validation that ignores it
 * head-of-line-blocks every other pending OAuth login.
 */
typedef bool (*ValidatorStartupCB) (ValidatorModuleState *state);
typedef void (*ValidatorShutdownCB) (ValidatorModuleState *state);
typedef bool (*ValidatorValidateCB) (ValidatorModuleState *state,
				     const char *token, const char *role,
				     const char *issuer, const char *scope,
				     int timeout,
				     ValidatorModuleResult *result);

/*
 * Identifies the compiled ABI version of the validator module. Bump when the
 * callback struct layout or semantic changes.
 */
#define OAUTH_VALIDATOR_MAGIC 0x20260730

typedef struct OAuthValidatorCallbacks {
	uint32_t magic;		/* must be set to OAUTH_VALIDATOR_MAGIC */

	/*
	 * Name of this validator, used by the validator=<name> HBA option and by
	 * the [oauth:<name>] configuration section.  Required, must be unique
	 * among the loaded modules, and limited to letters, digits, '_', '-' and
	 * '.' (at most OAUTH_MAX_VALIDATOR_NAME-1 characters).
	 */
	const char *name;

	ValidatorStartupCB startup_cb;
	ValidatorShutdownCB shutdown_cb;
	ValidatorValidateCB validate_cb;
} OAuthValidatorCallbacks;

/*
 * Maximum bearer token size accepted. Tokens are typically JWTs (several
 * kilobytes).
 */
#define OAUTH_MAX_TOKEN 8192

/* Maximum sizes for the effective issuer and scope strings. */
#define OAUTH_MAX_ISSUER 512
#define OAUTH_MAX_SCOPE 512

/* Maximum length of a per-HBA-line oauth option string. */
#define MAX_OAUTH_CONFIG 1024

/* Maximum length of a pg_ident usermap name referenced by an oauth HBA line. */
#define OAUTH_MAX_MAP 128

/* Maximum length of a validator module name, including the NUL. */
#define OAUTH_MAX_VALIDATOR_NAME 64

/* Maximum number of validator modules oauth_validator_libraries may name. */
#define OAUTH_MAX_MODULES 16

/* Symbol every validator module must export. */
#define OAUTH_VALIDATOR_INIT_SYMBOL "_pgbouncer_oauth_validator_module_init"

/*
 * Type of the shared library symbol OAUTH_VALIDATOR_INIT_SYMBOL which is
 * required for all validator modules. This function will be invoked during
 * module loading.
 */
typedef const OAuthValidatorCallbacks *(*OAuthValidatorModuleInit) (void);

/*
 * A self-contained validator module (for test purposes) needs it.
 */
typedef struct PgSocket PgSocket;

/*
 * Defines how many authentication requests can be placed on the waiting
 * queue.  When the queue is full, calls to oauth_auth_begin() block until
 * a slot becomes free.
 */
#define OAUTH_REQUEST_QUEUE_SIZE 20

/* Load the validator module and start the validation worker thread. */
void oauth_init(void);

/*
 * Resolve the effective OAuth options for a client's login into the client
 * struct, starting from the global oauth_* settings and applying any
 * per-HBA-line overrides in hba_options (NULL when auth_type=oauth is set
 * globally).  Returns false on a malformed option string.  Main thread only.
 */
bool oauth_prepare_options(PgSocket *client, const char *hba_options);

/*
 * Begin validating a bearer token for a client.  The result becomes
 * available on a later oauth_poll() call.  Called only from the main
 * thread.
 */
void oauth_auth_begin(PgSocket *client, const char *token);

/* Finish any completed validation requests; returns the number handled. */
int oauth_poll(void);

#endif /* OAUTH_H */
