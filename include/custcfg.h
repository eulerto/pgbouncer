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
 * Custom configuration sections: settings PgBouncer carries but does not own.
 *
 * A subsystem may need settings whose names and types PgBouncer cannot know:
 * they belong to the subsystem, not to the pooler.  Such settings live in
 * their own section, named "<prefix>:<name>", where the prefix identifies the
 * subsystem the settings belong to and the name the individual configuration:
 *
 *     [oauth:keycloak]
 *     url = https://kc.example.com/realms/prod
 *     client_id = pgbouncer
 *
 * The parser stores these as plain strings without interpreting them; the
 * subsystem reads and validates them when it needs them, which may be well
 * after the configuration file has been read.  That deferral is the whole
 * point of the mechanism: the consumer of a section cannot be asked about its
 * parameters while the file that names it is still being parsed -- a loadable
 * module, for one, has not been loaded yet at that point.
 *
 * Custom sections are read once, at startup.  RELOAD parses them but keeps the
 * values already in effect, matching the CF_NO_RELOAD core parameters that
 * name their consumers, and letting a consumer hold on to the strings it was
 * given without them being freed underneath it.
 */

#ifndef CUSTCFG_H
#define CUSTCFG_H

/*
 * Maximum length of a section name, including the NUL.  A name ends up in log
 * messages and in the settings that refer to it, so it is kept short.
 */
#define CUSTCFG_MAX_NAME 64

/* Maximum length of a section prefix, including the NUL. */
#define CUSTCFG_MAX_PREFIX 32

/* One key = value pair, in the order it appeared in the file. */
struct CustomOption {
	char *key;
	char *value;
	struct CustomOption *next;
};

/* The options of a single "[<prefix>:<name>]" section. */
struct CustomConfig {
	char *prefix;
	char *name;
	struct CustomOption *options;
	struct CustomOption **options_tail;
	int noptions;
	struct CustomConfig *next;
};

/*
 * CfSect hooks implementing the section.  These are wired into main.c's
 * config_sects as a trailing wildcard section, so any section name that is
 * neither a core section nor a valid "<prefix>:<name>" is still rejected.
 */
bool custcfg_section_start(void *top_base, const char *sect_name);
void *custcfg_section_base(void *top_base, const char *sect_name);
bool custcfg_set_key(void *base, const char *key, const char *val);
const char *custcfg_get_key(void *base, const char *key, char *buf, int buflen);

/* Freeze the registry: later RELOADs no longer change stored values. */
void custcfg_lock(void);

/* Find a single section, or NULL if the file did not have one. */
struct CustomConfig *custcfg_find(const char *prefix, const char *name);

/* Head of the section list, for walking it with ->next. */
struct CustomConfig *custcfg_first(void);

void custcfg_cleanup(void);

#endif
