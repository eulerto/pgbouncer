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
 * Custom configuration sections.  See include/custcfg.h for what the sections
 * look like and why the values are kept as uninterpreted strings.
 */

#include "bouncer.h"

#include <usual/err.h>

/*
 * Section prefixes PgBouncer knows about.  A section whose prefix is not
 * listed here is a configuration error, exactly as an unknown section name
 * was before custom sections existed.  Subsystems that read custom sections
 * add their prefix here.
 */
static const char *const custcfg_prefixes[] = {
	NULL
};

static struct CustomConfig *custcfg_list;

/* Set once the first configuration file has been read; see custcfg_lock(). */
static bool custcfg_locked;

static bool valid_prefix(const char *prefix)
{
	int i;

	for (i = 0; custcfg_prefixes[i]; i++) {
		if (strcmp(custcfg_prefixes[i], prefix) == 0)
			return true;
	}
	return false;
}

/*
 * A section name ends up in log messages, in the settings that refer to it
 * and in the section name itself, so keep it to an unambiguous character set.
 */
static bool valid_name(const char *name)
{
	const char *p;

	if (!*name)
		return false;
	for (p = name; *p; p++) {
		if (!isalnum((unsigned char)*p) && *p != '_' && *p != '-' && *p != '.')
			return false;
	}
	return true;
}

/*
 * Split "<prefix>:<name>" into its parts.  Returns false when sect_name is
 * not a custom section at all, which the caller reports as an unknown section.
 */
static bool split_section(const char *sect_name, char *prefix, int prefix_len, char *name, int name_len)
{
	const char *colon = strchr(sect_name, ':');
	int len;

	if (!colon)
		return false;

	len = colon - sect_name;
	if (len <= 0 || len >= prefix_len)
		return false;
	memcpy(prefix, sect_name, len);
	prefix[len] = '\0';

	if (strlcpy(name, colon + 1, name_len) >= (size_t)name_len)
		return false;

	return valid_prefix(prefix) && valid_name(name);
}

struct CustomConfig *custcfg_first(void)
{
	return custcfg_list;
}

struct CustomConfig *custcfg_find(const char *prefix, const char *name)
{
	struct CustomConfig *sect;

	for (sect = custcfg_list; sect; sect = sect->next) {
		if (strcmp(sect->prefix, prefix) == 0 && strcmp(sect->name, name) == 0)
			return sect;
	}
	return NULL;
}

static struct CustomConfig *custcfg_add(const char *prefix, const char *name)
{
	struct CustomConfig *sect = xmalloc(sizeof(*sect));

	sect->prefix = xstrdup(prefix);
	sect->name = xstrdup(name);
	sect->options = NULL;
	sect->options_tail = &sect->options;
	sect->noptions = 0;
	sect->next = custcfg_list;
	custcfg_list = sect;

	return sect;
}

/*
 * Called by the parser for each "[...]" header.  Rejecting the name here is
 * what keeps a bogus section fatal even when it carries no keys at all.
 */
bool custcfg_section_start(void *top_base, const char *sect_name)
{
	char prefix[CUSTCFG_MAX_PREFIX];
	char name[CUSTCFG_MAX_NAME];

	if (!split_section(sect_name, prefix, sizeof(prefix), name, sizeof(name))) {
		log_error("unknown section: %s", sect_name);
		return false;
	}

	if (!custcfg_find(prefix, name))
		custcfg_add(prefix, name);

	return true;
}

void *custcfg_section_base(void *top_base, const char *sect_name)
{
	char prefix[CUSTCFG_MAX_PREFIX];
	char name[CUSTCFG_MAX_NAME];

	if (!split_section(sect_name, prefix, sizeof(prefix), name, sizeof(name)))
		return NULL;

	return custcfg_find(prefix, name);
}

bool custcfg_set_key(void *base, const char *key, const char *val)
{
	struct CustomConfig *sect = base;
	struct CustomOption *opt;

	if (!sect) {
		/* section_start refused the name, so no keys can belong to it */
		log_error("custom parameter \"%s\" outside a valid section", key);
		return false;
	}

	if (!*key) {
		log_error("empty parameter name in section [%s:%s]", sect->prefix, sect->name);
		return false;
	}

	/*
	 * A custom section takes effect when its consumer first reads it.  A
	 * RELOAD still parses the section, but keeping the stored value means
	 * the strings already handed out are never freed or rewritten.
	 */
	if (custcfg_locked)
		return true;

	for (opt = sect->options; opt; opt = opt->next) {
		if (strcmp(opt->key, key) == 0) {
			free(opt->value);
			opt->value = xstrdup(val);
			return true;
		}
	}

	opt = xmalloc(sizeof(*opt));
	opt->key = xstrdup(key);
	opt->value = xstrdup(val);
	opt->next = NULL;
	*sect->options_tail = opt;
	sect->options_tail = &opt->next;
	sect->noptions++;

	return true;
}

const char *custcfg_get_key(void *base, const char *key, char *buf, int buflen)
{
	struct CustomConfig *sect = base;
	struct CustomOption *opt;

	if (!sect)
		return NULL;

	for (opt = sect->options; opt; opt = opt->next) {
		if (strcmp(opt->key, key) == 0)
			return opt->value;
	}
	return NULL;
}

void custcfg_lock(void)
{
	custcfg_locked = true;
}

void custcfg_cleanup(void)
{
	struct CustomConfig *sect = custcfg_list;

	while (sect) {
		struct CustomConfig *next_sect = sect->next;
		struct CustomOption *opt = sect->options;

		while (opt) {
			struct CustomOption *next_opt = opt->next;

			free(opt->key);
			free(opt->value);
			free(opt);
			opt = next_opt;
		}
		free(sect->prefix);
		free(sect->name);
		free(sect);
		sect = next_sect;
	}
	custcfg_list = NULL;
}
