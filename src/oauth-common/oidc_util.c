/*
 * Shared OIDC core for PgBouncer's OAuth validator modules.  See oidc_util.h.
 */

#include "oidc_util.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* Longest secret we will read out of a file. */
#define OIDC_MAX_SECRET 4096

void oidc_log(ValidatorModuleState *state, int level, const char *fmt, ...)
{
	char buf[1024];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	state->log_cb(state, level, "%s", buf);
}

char *oidc_sprintf(const char *fmt, ...)
{
	va_list ap;
	char *out;
	int len;

	va_start(ap, fmt);
	len = vsnprintf(NULL, 0, fmt, ap);
	va_end(ap);
	if (len < 0)
		return NULL;

	out = malloc((size_t)len + 1);
	if (!out)
		return NULL;

	va_start(ap, fmt);
	vsnprintf(out, (size_t)len + 1, fmt, ap);
	va_end(ap);

	return out;
}

char *oidc_url_join(const char *base, const char *suffix)
{
	size_t len = strlen(base);
	bool slash = len > 0 && base[len - 1] == '/';

	/* Both sides carry a separator, or neither does. */
	if (slash && suffix[0] == '/')
		suffix++;
	else if (!slash && suffix[0] != '/')
		return oidc_sprintf("%s/%s", base, suffix);

	return oidc_sprintf("%s%s", base, suffix);
}

bool oidc_split_list(const char *value, char ***out, int *nout)
{
	char *copy = strdup(value);
	char **items = NULL;
	int n = 0;
	char *p;

	if (!copy)
		return false;

	for (p = copy; *p; ) {
		char *start;
		char **grown;

		while (*p == ' ' || *p == '\t' || *p == ',')
			p++;
		if (!*p)
			break;
		start = p;
		while (*p && *p != ' ' && *p != '\t' && *p != ',')
			p++;
		if (*p)
			*p++ = '\0';

		grown = realloc(items, (n + 1) * sizeof(*items));
		if (!grown)
			goto fail;
		items = grown;
		items[n] = strdup(start);
		if (!items[n])
			goto fail;
		n++;
	}

	free(copy);
	*out = items;
	*nout = n;

	return true;

fail:
	while (n > 0)
		free(items[--n]);
	free(items);
	free(copy);

	return false;
}

void oidc_free_list(char **items, int n)
{
	while (n > 0)
		free(items[--n]);
	free(items);
}

bool oidc_parse_bool(const char *value, bool *out)
{
	if (strcmp(value, "1") == 0 || strcasecmp(value, "true") == 0 ||
	    strcasecmp(value, "yes") == 0 || strcasecmp(value, "on") == 0) {
		*out = true;
		return true;
	}
	if (strcmp(value, "0") == 0 || strcasecmp(value, "false") == 0 ||
	    strcasecmp(value, "no") == 0 || strcasecmp(value, "off") == 0) {
		*out = false;
		return true;
	}

	return false;
}

bool oidc_parse_int(const char *value, int *out)
{
	char *end;
	long v;

	v = strtol(value, &end, 10);
	if (end == value || *end != '\0' || v < 0 || v > 86400 * 30)
		return false;
	*out = (int)v;

	return true;
}

char *oidc_read_secret_file(ValidatorModuleState *state, const char *path)
{
	char buf[OIDC_MAX_SECRET];
	size_t len;
	FILE *f = fopen(path, "r");

	if (!f) {
		oidc_log(state, OAUTH_LOG_ERROR, "cannot open secret file \"%s\"", path);
		return NULL;
	}

	len = fread(buf, 1, sizeof(buf) - 1, f);
	if (ferror(f)) {
		oidc_log(state, OAUTH_LOG_ERROR, "cannot read secret file \"%s\"", path);
		fclose(f);
		return NULL;
	}
	fclose(f);
	buf[len] = '\0';

	/* A secret in a file is normally followed by a newline. */
	while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r'))
		buf[--len] = '\0';

	if (len == 0) {
		oidc_log(state, OAUTH_LOG_ERROR, "secret file \"%s\" is empty", path);
		return NULL;
	}

	return strdup(buf);
}
