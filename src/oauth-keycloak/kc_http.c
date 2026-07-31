/*
 * Keycloak OAuth validator module for PgBouncer.  See kc_http.h.
 */

#include "kc_http.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>

#define KC_SET_ERR(buf, len, ...) \
	do { \
		if ((buf) && (len) > 0) \
		snprintf((buf), (len), __VA_ARGS__); \
	} while (0)

struct body_buf {
	char *data;
	size_t len;
	bool overflow;
};

static size_t collect_body(char *ptr, size_t size, size_t nmemb, void *arg)
{
	struct body_buf *buf = arg;
	size_t chunk = size * nmemb;
	char *grown;

	if (buf->overflow)
		return 0;
	if (buf->len + chunk > KC_HTTP_MAX_BODY) {
		buf->overflow = true;
		return 0;	/* aborts the transfer */
	}

	grown = realloc(buf->data, buf->len + chunk + 1);
	if (!grown) {
		buf->overflow = true;
		return 0;
	}
	buf->data = grown;
	memcpy(buf->data + buf->len, ptr, chunk);
	buf->len += chunk;
	buf->data[buf->len] = '\0';

	return chunk;
}

bool kc_http_init(char *errbuf, size_t errlen)
{
	CURLcode rc = curl_global_init(CURL_GLOBAL_DEFAULT);

	if (rc != CURLE_OK) {
		KC_SET_ERR(errbuf, errlen, "curl_global_init failed: %s", curl_easy_strerror(rc));
		return false;
	}

	return true;
}

void kc_http_fini(void)
{
	curl_global_cleanup();
}

void kc_http_response_free(struct kc_http_response *resp)
{
	if (!resp)
		return;

	free(resp->body);
	resp->body = NULL;
	resp->len = 0;
}

char *kc_http_escape(const char *value)
{
	char *escaped;
	char *out;

	/*
	 * curl_easy_escape needs no handle in practice, but the documented
	 * signature takes one; a NULL handle is supported since 7.82 and older
	 * versions ignore it for escaping.
	 */
	escaped = curl_easy_escape(NULL, value, 0);
	if (!escaped)
		return NULL;

	out = strdup(escaped);
	curl_free(escaped);

	return out;
}

/*
 * Shared request path.  A fresh easy handle per call keeps the worker threads
 * independent: libcurl handles are not safe to share, and login traffic does
 * not justify a connection pool with its own locking.
 */
static bool do_request(const char *url, const char *post_body,
		       const char *user, const char *password,
		       const struct kc_tls_opts *tls, int timeout_ms,
		       struct kc_http_response *resp, char *errbuf, size_t errlen)
{
	struct body_buf buf = { NULL, 0, false };
	char curl_err[CURL_ERROR_SIZE] = { 0 };
	CURL *curl;
	CURLcode rc;
	bool ok = false;

	memset(resp, 0, sizeof(*resp));

	curl = curl_easy_init();
	if (!curl) {
		KC_SET_ERR(errbuf, errlen, "cannot create a curl handle");
		return false;
	}

	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, collect_body);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curl_err);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
	curl_easy_setopt(curl, CURLOPT_USERAGENT, "pgbouncer-keycloak-validator");
	/* Only ever talk HTTP(S), whatever a redirect or a config typo says. */
#if LIBCURL_VERSION_NUM >= 0x075500	/* 7.85.0 */
	curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "http,https");
#else
	curl_easy_setopt(curl, CURLOPT_PROTOCOLS, (long)(CURLPROTO_HTTP | CURLPROTO_HTTPS));
#endif

	if (timeout_ms > 0) {
		curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, (long)timeout_ms);
		/* Leave room for the response: cap connect time at half. */
		curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, (long)(timeout_ms / 2 + 1));
	}

	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, tls->verify_peer ? 1L : 0L);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, tls->verify_peer ? 2L : 0L);
	if (tls->ca_file)
		curl_easy_setopt(curl, CURLOPT_CAINFO, tls->ca_file);

	if (post_body) {
		curl_easy_setopt(curl, CURLOPT_POST, 1L);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_body);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(post_body));
	}
	if (user) {
		curl_easy_setopt(curl, CURLOPT_HTTPAUTH, (long)CURLAUTH_BASIC);
		curl_easy_setopt(curl, CURLOPT_USERNAME, user);
		curl_easy_setopt(curl, CURLOPT_PASSWORD, password ? password : "");
	}

	rc = curl_easy_perform(curl);
	if (rc != CURLE_OK) {
		if (buf.overflow) {
			KC_SET_ERR(errbuf, errlen, "response from %s is larger than %d bytes",
				   url, KC_HTTP_MAX_BODY);
		} else {
			KC_SET_ERR(errbuf, errlen, "request to %s failed: %s", url,
				   curl_err[0] ? curl_err : curl_easy_strerror(rc));
		}
		goto out;
	}

	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &resp->status);
	resp->body = buf.data;
	resp->len = buf.len;
	buf.data = NULL;
	ok = true;

out:
	free(buf.data);
	curl_easy_cleanup(curl);

	return ok;
}

bool kc_http_get(const char *url, const struct kc_tls_opts *tls, int timeout_ms,
		 struct kc_http_response *resp, char *errbuf, size_t errlen)
{
	return do_request(url, NULL, NULL, NULL, tls, timeout_ms, resp, errbuf, errlen);
}

bool kc_http_post_form(const char *url, const char *body,
		       const char *user, const char *password,
		       const struct kc_tls_opts *tls, int timeout_ms,
		       struct kc_http_response *resp, char *errbuf, size_t errlen)
{
	return do_request(url, body, user, password, tls, timeout_ms, resp, errbuf, errlen);
}
