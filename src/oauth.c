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

#include <usual/err.h>

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

/*
 * One loaded validator module.  Several may be loaded at once; an HBA line
 * picks one with validator=<name>.
 */
struct oauth_module {
	/* Path as it appeared in oauth_validator_libraries. */
	char *path;
	void *handle;
	const OAuthValidatorCallbacks *cb;
	/* State handed to every callback, including the module's settings. */
	ValidatorModuleState *state;
	/* Backing array for state->options; points into the parsed config. */
	ValidatorOption *options;
};

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

	/* Main-thread-only: result already delivered to the client, waiting for
	 * the head of the ring to catch up so the slot can be reclaimed. */
	bool reaped;

	/* The username (same as in client->login_user_credentials->name). */
	char username[MAX_USERNAME];

	/* Bearer token to validate, and the effective issuer/scope. */
	char token[OAUTH_MAX_TOKEN];
	char issuer[OAUTH_MAX_ISSUER];
	char scope[OAUTH_MAX_SCOPE];

	/* Validator module handling this request, resolved by the main thread in
	 * oauth_auth_begin().  Modules are loaded once at startup and never
	 * unloaded, so the pointer stays valid for the worker.
	 */
	struct oauth_module *module;

	/* Cooperative validation timeout handed to the module, in
	 * milliseconds (0 = no limit).  Copied from cf_oauth_validator_timeout
	 * so the worker thread never reads live configuration. */
	int timeout;

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
 * oauth_first_taken_slot points to the oldest element still occupying the ring;
 * oauth_first_free_slot points to the next slot after the last element;
 * oauth_claim_slot points to the next element a worker will pick up.  The
 * invariant is taken <= claim <= free (modulo the ring).  With a pool of
 * workers, requests between claim and taken may still be validating and can
 * complete out of order, so a slot carries a `reaped` flag and oauth_poll()
 * delivers each result as soon as its worker finishes, reclaiming ring space
 * contiguously from the head.
 */
volatile int oauth_first_taken_slot;
volatile int oauth_first_free_slot;
volatile int oauth_claim_slot;
struct oauth_auth_request oauth_auth_queue[OAUTH_REQUEST_QUEUE_SIZE];

/* Pool of validation worker threads; oauth_num_workers of them are started. */
pthread_t oauth_worker_threads[OAUTH_REQUEST_QUEUE_SIZE];
static int oauth_num_workers;

/*
 * Mutex serializes access to the queue's tail; the condition variable wakes
 * the worker when a new request is enqueued.
 */
pthread_mutex_t oauth_queue_tail_mutex;
pthread_cond_t oauth_data_available;

/* The loaded validator modules, in oauth_validator_libraries order. */
static struct oauth_module oauth_modules[OAUTH_MAX_MODULES];
static int oauth_nmodules;

/* Forward declarations */
static void *oauth_auth_worker(void *arg);
static bool is_valid_socket(const struct oauth_auth_request *request);
static void oauth_auth_finish(struct oauth_auth_request *request, int status);
static bool check_oauth_auth(struct oauth_auth_request *request);
static int get_request_status(struct oauth_auth_request *request);
static void set_request_status(struct oauth_auth_request *request, int status);
static void load_validator_modules(void);
static void shutdown_validator_modules(void);
static int oauth_find_module(const char *name);

/*
 * Initialize the OAuth subsystem: load the validator modules and start the
 * validation worker threads.  A no-op if no validator library is configured.
 */
void oauth_init(void)
{
	struct CustomConfig *sect;
	int rc;

	if (!cf_oauth_validator_libraries) {
		if (cf_auth_type == AUTH_TYPE_OAUTH)
			die("auth_type=oauth requires oauth_validator_libraries to be set");
		return;
	}

	load_validator_modules();
	if (oauth_nmodules == 0)
		die("oauth_validator_libraries names no validator module");

	/*
	 * Let the modules release whatever startup_cb acquired.  Registered here
	 * rather than called from main.c's cleanup(), which only runs in builds
	 * with asserts enabled; being registered after that handler also means it
	 * runs before it, while the configuration the modules were handed is
	 * still around.
	 */
	atexit(shutdown_validator_modules);

	/*
	 * A section no loaded module claims is almost always a typo in the name,
	 * and would otherwise be silently ignored: the section is parsed long
	 * before any module can say which names exist.
	 */
	for (sect = custcfg_first(); sect; sect = sect->next) {
		if (strcmp(sect->prefix, "oauth") == 0 && oauth_find_module(sect->name) < 0) {
			log_warning("no validator module named \"%s\" is loaded, ignoring section [oauth:%s]",
				    sect->name, sect->name);
		}
	}

	oauth_first_taken_slot = 0;
	oauth_first_free_slot = 0;
	oauth_claim_slot = 0;

	/* One worker preserves the original serialized behaviour; more let slow
	 * validations proceed concurrently.  Never exceed the ring size. */
	oauth_num_workers = cf_oauth_validator_workers;
	if (oauth_num_workers < 1)
		oauth_num_workers = 1;
	if (oauth_num_workers > OAUTH_REQUEST_QUEUE_SIZE)
		oauth_num_workers = OAUTH_REQUEST_QUEUE_SIZE;

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

	for (int i = 0; i < oauth_num_workers; i++) {
		rc = pthread_create(&oauth_worker_threads[i], NULL, &oauth_auth_worker, NULL);
		if (rc != 0)
			die("failed to create an authentication thread: %s", strerror(errno));
	}

	log_info("number of OAuth validation workers: %d", oauth_num_workers);
}

/*
 * Log on a module's behalf.  Modules cannot use PgBouncer's own logging
 * (they are not linked against it), and their stderr goes to /dev/null once
 * PgBouncer daemonizes, so route their messages through here, tagged with the
 * module name.  May be called from a validation worker thread.
 */
static void oauth_module_log(ValidatorModuleState *state, int level, const char *fmt, ...) _PRINTF(3, 4);

static void oauth_module_log(ValidatorModuleState *state, int level, const char *fmt, ...)
{
	char buf[1024];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	switch (level) {
	case OAUTH_LOG_ERROR:
		log_error("oauth: %s: %s", state->name, buf);
		break;
	case OAUTH_LOG_WARNING:
		log_warning("oauth: %s: %s", state->name, buf);
		break;
	case OAUTH_LOG_DEBUG:
		log_debug("oauth: %s: %s", state->name, buf);
		break;
	default:
		log_info("oauth: %s: %s", state->name, buf);
		break;
	}
}

/* Return the index of the module declaring this name, or -1. */
static int oauth_find_module(const char *name)
{
	int i;

	for (i = 0; i < oauth_nmodules; i++) {
		if (strcmp(oauth_modules[i].cb->name, name) == 0)
			return i;
	}
	return -1;
}

/*
 * Collect the module's [oauth:<name>] settings into the array handed to it
 * through its state.  The strings belong to the parsed configuration, which
 * is frozen once loaded (see include/custcfg.h), so the module may hold on to
 * them.
 */
static void attach_module_config(struct oauth_module *mod)
{
	struct CustomConfig *sect = custcfg_find("oauth", mod->cb->name);
	struct CustomOption *opt;
	int i = 0;

	if (!sect || sect->noptions == 0)
		return;

	mod->options = xmalloc(sect->noptions * sizeof(*mod->options));
	for (opt = sect->options; opt; opt = opt->next) {
		mod->options[i].key = opt->key;
		mod->options[i].value = opt->value;
		i++;
	}

	mod->state->options = mod->options;
	mod->state->noptions = i;
}

/*
 * Load and initialize one validator module.  Any failure is fatal, as it is a
 * configuration error.
 */
static void load_validator_module(const char *path)
{
	OAuthValidatorModuleInit init_fn;
	const OAuthValidatorCallbacks *cb;
	struct oauth_module *mod;
	const char *err;
	void *handle;

	handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
	if (!handle)
		die("could not load validator module \"%s\": %s", path, dlerror());

	/* Clear any stale error before resolving the symbol. */
	dlerror();
	/* The cast via a void* pointer avoids the ISO C object/function
	 * pointer-cast warning; POSIX guarantees dlsym returns a usable
	 * function pointer here. */
	*(void **)(&init_fn) = dlsym(handle, OAUTH_VALIDATOR_INIT_SYMBOL);
	err = dlerror();
	if (err != NULL || init_fn == NULL) {
		die("validator module \"%s\" is missing symbol %s: %s",
		    path, OAUTH_VALIDATOR_INIT_SYMBOL, err ? err : "not found");
	}

	cb = init_fn();
	if (!cb)
		die("validator module \"%s\" returned no callbacks", path);
	if (cb->magic != OAUTH_VALIDATOR_MAGIC) {
		die("validator module \"%s\" has wrong magic 0x%08x (expected 0x%08x)",
		    path, cb->magic, OAUTH_VALIDATOR_MAGIC);
	}
	if (!cb->validate_cb)
		die("validator module \"%s\" provides no validate callback", path);

	/*
	 * The name is how an HBA line and a configuration section refer to this
	 * module, so it must exist, fit, and be unambiguous.
	 */
	if (!cb->name || !cb->name[0])
		die("validator module \"%s\" declares no name", path);
	if (strlen(cb->name) >= OAUTH_MAX_VALIDATOR_NAME) {
		die("validator module \"%s\" declares a name longer than %d characters",
		    path, OAUTH_MAX_VALIDATOR_NAME - 1);
	}
	if (oauth_find_module(cb->name) >= 0) {
		die("validator module \"%s\" declares name \"%s\", which is already used by another module",
		    path, cb->name);
	}

	mod = &oauth_modules[oauth_nmodules];
	mod->path = xstrdup(path);
	mod->handle = handle;
	mod->cb = cb;
	mod->state = xmalloc(sizeof(*mod->state));
	memset(mod->state, 0, sizeof(*mod->state));
	mod->state->name = cb->name;
	mod->state->log_cb = oauth_module_log;

	attach_module_config(mod);

	if (cb->startup_cb && !cb->startup_cb(mod->state))
		die("validator module \"%s\" (\"%s\") failed to start", cb->name, path);

	oauth_nmodules++;

	log_info("loaded OAuth validator module \"%s\" from \"%s\" (%d option(s))",
		 cb->name, path, mod->state->noptions);
}

/*
 * Load every module named by oauth_validator_libraries, a comma-separated
 * list of paths.
 */
static void load_validator_modules(void)
{
	char *list = xstrdup(cf_oauth_validator_libraries);
	char *pos = list;
	char *path;

	while ((path = strsep(&pos, ",")) != NULL) {
		while (*path && isspace((unsigned char)*path))
			path++;
		{
			char *end = path + strlen(path);

			while (end > path && isspace((unsigned char)end[-1]))
				end--;
			*end = '\0';
		}
		if (!*path)
			continue;

		if (oauth_nmodules == OAUTH_MAX_MODULES) {
			die("oauth_validator_libraries names more than %d modules",
			    OAUTH_MAX_MODULES);
		}
		load_validator_module(path);
	}

	free(list);
}

/*
 * Call every loaded module's shutdown_cb, at exit.  Runs on the main thread
 * once the event loop is gone.
 */
static void shutdown_validator_modules(void)
{
	int i;

	/*
	 * A request still occupying the ring is inside validate_cb on a worker
	 * thread, or about to be: a slot is released only after its result was
	 * reaped.  The workers are not joined here, and tearing a module down
	 * underneath its own validation is worse than not tearing it down at
	 * all, so leave it to the exiting process.
	 */
	if (oauth_first_taken_slot != oauth_first_free_slot) {
		log_warning("oauth: token validation still in progress, skipping validator module shutdown");
		return;
	}

	for (i = 0; i < oauth_nmodules; i++) {
		struct oauth_module *mod = &oauth_modules[i];

		if (mod->cb->shutdown_cb)
			mod->cb->shutdown_cb(mod->state);

		/*
		 * The library stays mapped: the worker threads are still alive,
		 * and unloading it buys nothing in a process that is exiting.
		 */
		free(mod->options);
		free(mod->state);
		free(mod->path);
		mod->options = NULL;
		mod->state = NULL;
		mod->path = NULL;
	}
	oauth_nmodules = 0;
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
	char validator[OAUTH_MAX_VALIDATOR_NAME];
	char *pos, *key, *val;
	bool ok = true;

	/* Defaults come from the global configuration. */
	safe_strcpy(client->oauth_issuer, cf_oauth_issuer ? cf_oauth_issuer : "", sizeof(client->oauth_issuer));
	safe_strcpy(client->oauth_scope, cf_oauth_scope ? cf_oauth_scope : "", sizeof(client->oauth_scope));
	client->oauth_delegate_ident_mapping = cf_oauth_delegate_ident_mapping;
	client->oauth_map[0] = '\0';
	client->oauth_module_idx = -1;
	validator[0] = '\0';

	if (oauth_nmodules == 0) {
		log_warning("oauth: no validator module is loaded, set oauth_validator_libraries");
		return false;
	}

	if (!hba_options || !hba_options[0])
		goto pick_module;

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
		} else if (strcmp(key, "validator") == 0) {
			safe_strcpy(validator, val, sizeof(validator));
		} else {
			log_warning("invalid oauth HBA option: \"%s\"", key);
			return false;
		}
	}
	if (!ok) {
		log_warning("malformed oauth HBA options: \"%s\"", hba_options);
		return false;
	}

pick_module:
	/*
	 * Pick the validator module for this login.  The modules are loaded once
	 * at startup, long after the HBA file was parsed, so an unknown name can
	 * only be caught here; refuse the login rather than guess.
	 */
	if (validator[0]) {
		client->oauth_module_idx = oauth_find_module(validator);
		if (client->oauth_module_idx < 0) {
			log_warning("oauth: no validator module named \"%s\" is loaded", validator);
			return false;
		}
	} else if (oauth_nmodules == 1) {
		client->oauth_module_idx = 0;
	} else {
		log_warning("oauth: the \"validator\" HBA option is required when %d validator modules are loaded",
			    oauth_nmodules);
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
	request->module = &oauth_modules[client->oauth_module_idx];
	request->timeout = (int)(cf_oauth_validator_timeout / 1000);
	request->authorized = false;
	request->authn_id = NULL;
	request->reaped = false;

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
	int i;

	/*
	 * Deliver every completed result, in whatever order the workers finished
	 * them.  Requests still validating (or not yet claimed) are simply
	 * skipped; with multiple workers a later request may finish before an
	 * earlier one, and its client should not wait for the head.
	 */
	for (i = oauth_first_taken_slot; i != oauth_first_free_slot; i = (i + 1) % OAUTH_REQUEST_QUEUE_SIZE) {
		request = &oauth_auth_queue[i];

		if (request->reaped)
			continue;

		status = get_request_status(request);
		if (status == OAUTH_STATUS_IN_PROGRESS)
			continue;

		if (is_valid_socket(request))
			oauth_auth_finish(request, status);

		/* Release the identity string handed over by the worker. */
		free(request->authn_id);
		request->authn_id = NULL;
		request->reaped = true;
		count++;
	}

	/*
	 * Reclaim ring space contiguously from the head: a slot can be reused
	 * only once every older slot has been reaped, so the indices stay
	 * monotonic and the worker claim logic remains simple.
	 */
	while (oauth_first_taken_slot != oauth_first_free_slot &&
	       oauth_auth_queue[oauth_first_taken_slot].reaped) {
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
	struct oauth_auth_request *request;
	int cur_slot;
	int status;

	while (true) {
		/*
		 * Claim the next unclaimed request; block until one appears.  The
		 * shared claim index hands each worker in the pool a distinct
		 * slot, so validations run concurrently.
		 */
		pthread_mutex_lock(&oauth_queue_tail_mutex);

		while (oauth_claim_slot == oauth_first_free_slot)
			pthread_cond_wait(&oauth_data_available, &oauth_queue_tail_mutex);

		cur_slot = oauth_claim_slot;
		oauth_claim_slot = (oauth_claim_slot + 1) % OAUTH_REQUEST_QUEUE_SIZE;

		pthread_mutex_unlock(&oauth_queue_tail_mutex);

		log_debug("oauth_auth_worker(): processing slot %d", cur_slot);

		request = &oauth_auth_queue[cur_slot];

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
	const struct oauth_module *mod = request->module;
	ValidatorModuleResult result;

	if (request->token[0] == '\0')
		return false;

	memset(&result, 0, sizeof(result));

	if (!mod->cb->validate_cb(mod->state,
				  request->token,
				  request->username,
				  request->issuer[0] ? request->issuer : NULL,
				  request->scope[0] ? request->scope : NULL,
				  request->timeout,
				  &result)) {
		log_warning("oauth: validator module \"%s\" failed to validate token for user \"%s\"",
			    mod->cb->name, request->username);
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
