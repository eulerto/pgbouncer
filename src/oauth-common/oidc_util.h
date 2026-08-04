/*
 * Shared OIDC core for PgBouncer's OAuth validator modules.
 *
 * Small helpers every validator module needs before it gets to any OIDC:
 * logging through PgBouncer, string building, and parsing the values of its
 * [oauth:<name>] settings.
 */

#ifndef OIDC_UTIL_H
#define OIDC_UTIL_H

#include <stdbool.h>
#include <stddef.h>

#include "oauth.h"

/* Room for the reason a token was turned down, for the log. */
#define OIDC_ERRLEN 512

/*
 * Log through PgBouncer, which tags the line with the module name and puts it
 * wherever the pooler's own log goes.  Writing to stderr instead would lose
 * the message entirely once PgBouncer daemonizes.  Safe on a worker thread.
 */
void oidc_log(ValidatorModuleState *state, int level, const char *fmt, ...)
#ifdef __GNUC__
__attribute__((format(printf, 3, 4)))
#endif
;

/* printf into a freshly allocated string; asprintf is not portable enough. */
char *oidc_sprintf(const char *fmt, ...)
#ifdef __GNUC__
__attribute__((format(printf, 1, 2)))
#endif
;

/* Join a base URL with a path, collapsing a doubled separator. */
char *oidc_url_join(const char *base, const char *suffix);

/*
 * Split a comma- or space-separated setting into a malloc()'d array of
 * malloc()'d strings, released with oidc_free_list().
 */
bool oidc_split_list(const char *value, char ***out, int *nout);
void oidc_free_list(char **items, int n);

/* Parse a boolean ("1", "true", "yes", "on", and their negatives). */
bool oidc_parse_bool(const char *value, bool *out);

/* Parse a non-negative number of seconds; rejects trailing garbage. */
bool oidc_parse_int(const char *value, int *out);

/*
 * Read a secret from a file, without the trailing newline.  Keeping a secret
 * out of pgbouncer.ini is the recommended arrangement: the ini file is read on
 * every reload and tends to be world-readable, while this file can be 0600.
 * Logs the reason and returns NULL if it cannot be read.
 */
char *oidc_read_secret_file(ValidatorModuleState *state, const char *path);

#endif
