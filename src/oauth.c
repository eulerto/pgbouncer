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
 * OAuth (OAUTHBEARER) authentication support.
 *
 * PgBouncer verifies the client's bearer token by handing it to a loadable
 * validator module.  Because validation may block on the identity provider,
 * it runs on a background worker thread, using the same queue/poll model as
 * the PAM and LDAP backends (see src/ldapauth.c).
 */

#include "bouncer.h"

#ifdef HAVE_OAUTH

#include <pthread.h>
#include <dlfcn.h>

/* The request is waiting in the queue or being validated */
#define OAUTH_STATUS_IN_PROGRESS  1
/* The token was successfully validated and authorized */
#define OAUTH_STATUS_SUCCESS      2
/* The token was rejected or validation failed */
#define OAUTH_STATUS_FAILED       3

/*
 * How many microseconds to sleep between calls to oauth_poll in
 * oauth_auth_begin when the queue is full.
 * Default is 100 milliseconds.
 */
#define OAUTH_QUEUE_WAIT_SLEEP_MCS      (100*1000)

struct oauth_auth_request {
	/* The socket we check authentication for */
	PgSocket *client;

	/* The socket can be closed and reused while the request is waiting in
	 * the queue. Combining its state and connect_time lets us detect that.
	 */
	usec_t connect_time;

	/* Same as in client->remote_addr.  Copied here to minimize
	 * synchronization between the worker thread and the rest of pgbouncer.
	 */
	PgAddr remote_addr;

	/* The request status, one of the OAUTH_STATUS_* constants */
	int status;
	/* Protects status from concurrent main/worker access */
	pthread_mutex_t mutex;

	/* The username (same as in client->login_user_credentials->name). */
	char username[MAX_USERNAME];

	/* Bearer token to validate, and the effective issuer/scope. */
	char token[OAUTH_MAX_TOKEN];
	char issuer[OAUTH_MAX_ISSUER];
	char scope[OAUTH_MAX_SCOPE];

	/* Result produced by the worker thread. */
	bool authorized;
	/* Identity proven by the token; malloc()'d by the validator module,
	 * free()'d by the main thread in oauth_poll(). */
	char *authn_id;
};


/*
 * All incoming requests are kept in a ring-buffer queue, which avoids memory
 * reallocation and thus minimizes cross-thread synchronization.
 *
 * oauth_first_taken_slot points to the first element in the queue;
 * oauth_first_free_slot points to the next slot after the last element.
 * They are equal when the queue is empty.
 */
volatile int oauth_first_taken_slot;
volatile int oauth_first_free_slot;
struct oauth_auth_request oauth_auth_queue[OAUTH_REQUEST_QUEUE_SIZE];

pthread_t oauth_worker_thread;

/*
 * Mutex serializes access to the queue's tail; the condition variable wakes
 * the worker when a new request is enqueued.
 */
pthread_mutex_t oauth_queue_tail_mutex;
pthread_cond_t oauth_data_available;

/* The loaded validator module. */
static ValidatorModuleState *validator_module_state;
static void *oauth_module_handle;
static const OAuthValidatorCallbacks *oauth_callbacks;

/* Forward declarations */
static void *oauth_auth_worker(void *arg);
static bool is_valid_socket(const struct oauth_auth_request *request);
static void oauth_auth_finish(struct oauth_auth_request *request, int status);
static bool check_oauth_auth(struct oauth_auth_request *request);
static int get_request_status(struct oauth_auth_request *request);
static void set_request_status(struct oauth_auth_request *request, int status);
static void load_validator_module(void);

/*
 * Initialize the OAuth subsystem: load the validator module and start the
 * validation worker thread.  A no-op if no validator library is configured.
 */
void oauth_init(void)
{
	int rc;

	if (!cf_oauth_validator_library) {
		if (cf_auth_type == AUTH_TYPE_OAUTH)
			die("auth_type=oauth requires oauth_validator_library to be set");
		return;
	}

	load_validator_module();

	oauth_first_taken_slot = 0;
	oauth_first_free_slot = 0;

	rc = pthread_mutex_init(&oauth_queue_tail_mutex, NULL);
	if (rc != 0)
		die("failed to initialize a mutex: %s", strerror(errno));

	rc = pthread_cond_init(&oauth_data_available, NULL);
	if (rc != 0)
		die("failed to initialize a condition variable: %s", strerror(errno));

	for (int i = 0; i < OAUTH_REQUEST_QUEUE_SIZE; i++) {
		rc = pthread_mutex_init(&oauth_auth_queue[i].mutex, NULL);
		if (rc != 0)
			die("failed to initialize a mutex for request[%d]: %s", i, strerror(errno));
	}

	rc = pthread_create(&oauth_worker_thread, NULL, &oauth_auth_worker, NULL);
	if (rc != 0)
		die("failed to create the authentication thread: %s", strerror(errno));
}

/*
 * Load and initialize the validator module named by oauth_validator_library.
 * Any failure is fatal, as it is a configuration error.
 */
static void load_validator_module(void)
{
	OAuthValidatorModuleInit init_fn;
	const OAuthValidatorCallbacks *cb;
	const char *err;

	oauth_module_handle = dlopen(cf_oauth_validator_library, RTLD_NOW | RTLD_LOCAL);
	if (!oauth_module_handle) {
		die("could not load oauth_validator_library \"%s\": %s",
		    cf_oauth_validator_library, dlerror());
	}

	/* Clear any stale error before resolving the symbol. */
	dlerror();
	/* The cast via a void* pointer avoids the ISO C object/function
	 * pointer-cast warning; POSIX guarantees dlsym returns a usable
	 * function pointer here. */
	*(void **)(&init_fn) = dlsym(oauth_module_handle, OAUTH_VALIDATOR_INIT_SYMBOL);
	err = dlerror();
	if (err != NULL || init_fn == NULL) {
		die("validator module \"%s\" is missing symbol %s: %s",
		    cf_oauth_validator_library, OAUTH_VALIDATOR_INIT_SYMBOL,
		    err ? err : "not found");
	}

	cb = init_fn();
	if (!cb)
		die("validator module \"%s\" returned no callbacks", cf_oauth_validator_library);
	if (cb->magic != OAUTH_VALIDATOR_MAGIC) {
		die("validator module \"%s\" has wrong magic 0x%08x (expected 0x%08x)",
		    cf_oauth_validator_library, cb->magic, OAUTH_VALIDATOR_MAGIC);
	}
	if (!cb->validate_cb) {
		die("validator module \"%s\" provides no validate callback",
		    cf_oauth_validator_library);
	}

	oauth_callbacks = cb;

	/* Allocate memory for validator library private state data */
	validator_module_state = malloc(sizeof(ValidatorModuleState));

	if (cb->startup_cb)
		cb->startup_cb(validator_module_state);

	log_info("loaded OAuth validator module \"%s\"", cf_oauth_validator_library);
}

static int get_request_status(struct oauth_auth_request *request)
{
	int rc;

	pthread_mutex_lock(&request->mutex);
	rc = request->status;
	pthread_mutex_unlock(&request->mutex);
	return rc;
}

static void set_request_status(struct oauth_auth_request *request, int status)
{
	pthread_mutex_lock(&request->mutex);
	request->status = status;
	pthread_mutex_unlock(&request->mutex);
}

/*
 * Split the next key=value pair out of *pos (HBA style).  A value may be
 * double-quoted so it can contain spaces, '=' or ':' (issuer URLs), with ""
 * as an embedded quote.  The buffer is modified in place (unescaped and
 * NUL-terminated) and *pos is advanced past the pair.  Returns false when no
 * more pairs remain; sets *ok to false on a malformed pair.
 */
static bool oauth_next_option(char **pos, char **key, char **val, bool *ok)
{
	char *p = *pos;
	char *k, *v, *w;

	while (*p && isspace((unsigned char)*p))
		p++;
	if (*p == '\0')
		return false;

	k = p;
	while (*p && *p != '=' && !isspace((unsigned char)*p))
		p++;
	if (*p != '=') {
		*ok = false;
		return false;
	}
	*p++ = '\0';

	if (*p == '"') {
		p++;
		v = w = p;
		while (*p) {
			if (*p == '"' && p[1] == '"') {
				*w++ = '"';
				p += 2;
			} else if (*p == '"') {
				p++;
				break;
			} else {
				*w++ = *p++;
			}
		}
		*w = '\0';
	} else {
		v = p;
		while (*p && !isspace((unsigned char)*p))
			p++;
		if (*p)
			*p++ = '\0';
	}

	*pos = p;
	*key = k;
	*val = v;
	return true;
}

/*
 * Resolve the effective OAuth options for a client's login: start from the
 * global oauth_* settings, then apply any per-HBA-line overrides parsed out of
 * hba_options (NULL for a global auth_type=oauth).  Main thread only.
 */
bool oauth_prepare_options(PgSocket *client, const char *hba_options)
{
	char buf[MAX_OAUTH_CONFIG];
	char *pos, *key, *val;
	bool ok = true;

	/* Defaults come from the global configuration. */
	safe_strcpy(client->oauth_issuer, cf_oauth_issuer ? cf_oauth_issuer : "", sizeof(client->oauth_issuer));
	safe_strcpy(client->oauth_scope, cf_oauth_scope ? cf_oauth_scope : "", sizeof(client->oauth_scope));
	client->oauth_delegate_ident_mapping = cf_oauth_delegate_ident_mapping;
	client->oauth_map[0] = '\0';

	if (!hba_options || !hba_options[0])
		return true;

	safe_strcpy(buf, hba_options, sizeof(buf));
	pos = buf;
	while (oauth_next_option(&pos, &key, &val, &ok)) {
		if (strcmp(key, "issuer") == 0) {
			safe_strcpy(client->oauth_issuer, val, sizeof(client->oauth_issuer));
		} else if (strcmp(key, "scope") == 0) {
			safe_strcpy(client->oauth_scope, val, sizeof(client->oauth_scope));
		} else if (strcmp(key, "delegate_ident_mapping") == 0) {
			client->oauth_delegate_ident_mapping =
				(strcmp(val, "1") == 0 || strcasecmp(val, "true") == 0);
		} else if (strcmp(key, "map") == 0) {
			safe_strcpy(client->oauth_map, val, sizeof(client->oauth_map));
		} else {
			log_warning("invalid oauth HBA option: \"%s\"", key);
			return false;
		}
	}
	if (!ok) {
		log_warning("malformed oauth HBA options: \"%s\"", hba_options);
		return false;
	}

	/*
	 * A usermap and delegation are mutually exclusive: delegation trusts the
	 * IdP for role selection, a map resolves it locally.  Refuse the
	 * ambiguous combination rather than silently ignoring one.
	 */
	if (client->oauth_map[0] && client->oauth_delegate_ident_mapping) {
		log_warning("oauth HBA options: \"map\" and \"delegate_ident_mapping\" are mutually exclusive");
		return false;
	}
	return true;
}

/*
 * Enqueue a bearer token for validation.  The result becomes available on a
 * later oauth_poll() call.  Blocks if the queue is full.  Main thread only.
 */
void oauth_auth_begin(PgSocket *client, const char *token)
{
	int next_free_slot = (oauth_first_free_slot + 1) % OAUTH_REQUEST_QUEUE_SIZE;
	struct oauth_auth_request *request;

	slog_debug(
		client,
		"oauth_auth_begin(): oauth_first_taken_slot=%d, oauth_first_free_slot=%d",
		oauth_first_taken_slot, oauth_first_free_slot);

	client->wait_for_auth = true;

	/* If there are no free slots, block until one becomes available. */
	if (next_free_slot == oauth_first_taken_slot)
		slog_warning(client, "OAuth queue is full, waiting");

	while (next_free_slot == oauth_first_taken_slot) {
		if (oauth_poll() == 0) {
			/* Sleep a bit between checks to avoid consuming too much CPU */
			usleep(OAUTH_QUEUE_WAIT_SLEEP_MCS);
		}
	}

	pthread_mutex_lock(&oauth_queue_tail_mutex);

	request = &oauth_auth_queue[oauth_first_free_slot];

	request->client = client;
	request->connect_time = client->connect_time;
	request->status = OAUTH_STATUS_IN_PROGRESS;	/* protected by oauth_queue_tail_mutex */
	memcpy(&request->remote_addr, &client->remote_addr, sizeof(client->remote_addr));
	safe_strcpy(request->username, client->login_user_credentials->name, MAX_USERNAME);
	safe_strcpy(request->token, token, sizeof(request->token));
	safe_strcpy(request->issuer, client->oauth_issuer, sizeof(request->issuer));
	safe_strcpy(request->scope, client->oauth_scope, sizeof(request->scope));
	request->authorized = false;
	request->authn_id = NULL;

	oauth_first_free_slot = next_free_slot;

	pthread_cond_signal(&oauth_data_available);
	pthread_mutex_unlock(&oauth_queue_tail_mutex);
}

/*
 * Handle any completed validation requests; returns the number handled.
 * Main thread only.
 */
int oauth_poll(void)
{
	struct oauth_auth_request *request;
	int count = 0;
	int status;

	while (oauth_first_taken_slot != oauth_first_free_slot) {
		request = &oauth_auth_queue[oauth_first_taken_slot];

		status = get_request_status(request);
		if (status == OAUTH_STATUS_IN_PROGRESS) {
			/* The oldest request is still running, so all newer ones
			 * are too; stop scanning. */
			break;
		}

		if (is_valid_socket(request))
			oauth_auth_finish(request, status);

		/* Release the identity string handed over by the worker. */
		free(request->authn_id);
		request->authn_id = NULL;

		count++;
		oauth_first_taken_slot = (oauth_first_taken_slot + 1) % OAUTH_REQUEST_QUEUE_SIZE;
	}

	return count;
}

/*
 * The validation worker thread.  Scans the queue for new requests and calls
 * the validator module for each.
 */
static void *oauth_auth_worker(void *arg)
{
	int current_slot = oauth_first_taken_slot;
	struct oauth_auth_request *request;
	int status;

	while (true) {
		/* Wait for new data in the queue */
		pthread_mutex_lock(&oauth_queue_tail_mutex);

		while (current_slot == oauth_first_free_slot)
			pthread_cond_wait(&oauth_data_available, &oauth_queue_tail_mutex);

		pthread_mutex_unlock(&oauth_queue_tail_mutex);

		log_debug("oauth_auth_worker(): processing slot %d", current_slot);

		request = &oauth_auth_queue[current_slot];
		current_slot = (current_slot + 1) % OAUTH_REQUEST_QUEUE_SIZE;

		if (check_oauth_auth(request))
			status = OAUTH_STATUS_SUCCESS;
		else
			status = OAUTH_STATUS_FAILED;

		/*
		 * The token is a secret and the validator module has now seen
		 * it; wipe it rather than leave it in the ring slot until some
		 * later login happens to overwrite it.
		 */
		explicit_bzero(request->token, sizeof(request->token));

		set_request_status(request, status);

		log_debug("oauth_auth_worker(): validation completed, status=%d", status);
	}

	return NULL;
}

/*
 * Checks that the socket is still valid to be processed, i.e. it is still in
 * the login phase and was not reused for another connection.
 */
static bool is_valid_socket(const struct oauth_auth_request *request)
{
	if (request->client->state != CL_LOGIN || request->client->connect_time != request->connect_time)
		return false;
	return true;
}

/*
 * Finishes the handshake after validation.  On success the client login is
 * resumed (the server-side connection uses stored credentials, exactly as it
 * would for cert/scram auth); on failure the client is disconnected.  Main
 * thread only.
 */
static void oauth_auth_finish(struct oauth_auth_request *request, int status)
{
	PgSocket *client = request->client;

	if (status != OAUTH_STATUS_SUCCESS || !request->authorized) {
		disconnect_client(client, true, "OAuth authentication failed");
		return;
	}

	if (client->oauth_delegate_ident_mapping) {
		/*
		 * The validator module is authoritative: it authorized this
		 * token for the requested role, so skip the identity check.
		 */
		slog_debug(client, "oauth: delegated authorization for user \"%s\" (authn_id=\"%s\")",
			   request->username, request->authn_id ? request->authn_id : "");
		sbuf_continue(&client->sbuf);
		return;
	}

	if (client->oauth_map[0]) {
		/*
		 * pg_ident usermap: the proven identity (authn_id) is the
		 * system-username and the requested role the database-username.
		 * Re-resolve against the live parsed_ident so a config reload
		 * during the async validation window cannot leave us using a
		 * freed map.
		 */
		if (!request->authn_id ||
		    !ident_map_check(parsed_ident, client->oauth_map, request->authn_id, request->username)) {
			slog_warning(client, "oauth: ident map \"%s\" has no match for identity \"%s\" -> user \"%s\"",
				     client->oauth_map, request->authn_id ? request->authn_id : "(none)", request->username);
			disconnect_client(client, true, "OAuth identity does not match requested user");
			return;
		}
		slog_debug(client, "oauth: ident map \"%s\" matched identity \"%s\" -> user \"%s\"",
			   client->oauth_map, request->authn_id, request->username);
		sbuf_continue(&client->sbuf);
		return;
	}

	/* Default 1:1 mapping: the proven identity must equal the requested role. */
	if (!request->authn_id || strcmp(request->authn_id, request->username) != 0) {
		slog_warning(client, "oauth: token identity \"%s\" does not match requested user \"%s\"",
			     request->authn_id ? request->authn_id : "(none)", request->username);
		disconnect_client(client, true, "OAuth identity does not match requested user");
		return;
	}

	sbuf_continue(&client->sbuf);
}

/*
 * Perform the actual token validation by calling into the validator module.
 * Runs on the worker thread.  Returns true if the token is authorized.
 */
static bool check_oauth_auth(struct oauth_auth_request *request)
{
	ValidatorModuleResult result;

	if (request->token[0] == '\0')
		return false;

	memset(&result, 0, sizeof(result));

	if (!oauth_callbacks->validate_cb(validator_module_state,
					  request->token,
					  request->username,
					  request->issuer[0] ? request->issuer : NULL,
					  request->scope[0] ? request->scope : NULL,
					  &result)) {
		log_warning("oauth: validator module failed to validate token for user \"%s\"",
			    request->username);
		free(result.authn_id);
		return false;
	}

	/* Hand the identity over to the main thread, which frees it. */
	request->authorized = result.authorized;
	request->authn_id = result.authn_id;

	return result.authorized;
}

#else /* !HAVE_OAUTH */

/* If OAuth is not supported these dummy functions are used. */

void oauth_init(void)
{
	/* do nothing */
}

bool oauth_prepare_options(PgSocket *client, const char *hba_options)
{
	return false;
}

void oauth_auth_begin(PgSocket *client, const char *token)
{
	die("OAuth authentication is not supported");
}

int oauth_poll(void)
{
	/* do nothing */
	return 0;
}

#endif
