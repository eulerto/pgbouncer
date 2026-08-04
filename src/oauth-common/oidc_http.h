/*
 * Shared OIDC core for PgBouncer's OAuth validator modules.
 *
 * Minimal HTTPS client over libcurl.  Every call is synchronous and bounded
 * by the deadline PgBouncer hands to validate_cb: the module runs on a worker
 * thread the pooler cannot preempt, so a request that never returns would
 * block every login queued behind it.
 */

#ifndef OIDC_HTTP_H
#define OIDC_HTTP_H

#include <stdbool.h>
#include <stddef.h>

/* Refuse a response larger than this; a JWKS or introspection reply is tiny. */
#define OIDC_HTTP_MAX_BODY (1024 * 1024)

struct oidc_tls_opts {
	/* CA bundle to verify the provider with, or NULL for the system store. */
	const char *ca_file;
	/* Verifying the provider certificate; off only for testing. */
	bool verify_peer;
};

struct oidc_http_response {
	char *body;		/* NUL-terminated; free with oidc_http_response_free */
	size_t len;
	long status;
};

/* Process-wide libcurl setup; call once from the module startup callback. */
bool oidc_http_init(char *errbuf, size_t errlen);
void oidc_http_fini(void);

/*
 * Perform a GET (or a form POST when body is non-NULL, optionally with HTTP
 * basic credentials).  timeout_ms of 0 means no deadline.  Returns false on a
 * transport error, with the reason in errbuf; an HTTP error status is a
 * successful call with resp->status set.
 */
bool oidc_http_get(const char *url, const struct oidc_tls_opts *tls, int timeout_ms,
		   struct oidc_http_response *resp, char *errbuf, size_t errlen);
bool oidc_http_post_form(const char *url, const char *body,
			 const char *user, const char *password,
			 const struct oidc_tls_opts *tls, int timeout_ms,
			 struct oidc_http_response *resp, char *errbuf, size_t errlen);

void oidc_http_response_free(struct oidc_http_response *resp);

/* URL-encode a value for a form body; returns a malloc()'d string. */
char *oidc_http_escape(const char *value);

#endif
