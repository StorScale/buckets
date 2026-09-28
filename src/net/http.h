/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_NET_HTTP_H
#define BUCKETS_NET_HTTP_H

#include "core/buf.h"
#include "core/loop.h"
#include "core/str.h"

#define BUCKETS_HTTP_MAX_HEADERS 128

typedef struct {
  buckets_str name;
  buckets_str value;
} buckets_http_header;

/* A fully received request. All slices point into connection-owned memory and
 * are valid only for the duration of the handler call.
 *
 * Bodies are buffered in memory up to max_body for now. Streaming bodies (needed
 * for large PutObject/UploadPart) replace this before object handlers land. */
typedef struct {
  buckets_str method;
  buckets_str target; /* raw request-target, e.g. "/bucket/key?uploads" */
  buckets_str path;   /* raw (percent-encoded) path portion of target */
  buckets_str query;  /* raw query string without the leading '?' */
  buckets_http_header headers[BUCKETS_HTTP_MAX_HEADERS];
  size_t nheaders;
  buckets_str body;
  bool keep_alive;
  const char *remote_addr;
} buckets_http_request;

/* Case-insensitive header lookup. Returns a slice with p == NULL when absent. */
buckets_str buckets_http_header_get(const buckets_http_request *req, const char *name);

typedef struct {
  int status;
  buckets_buf headers; /* serialized "Name: value\r\n" lines */
  buckets_buf body;
  bool head_only;          /* HEAD response: send Content-Length, omit body */
  long long content_length; /* -1: use body.len */
} buckets_http_response;

void buckets_http_resp_header(buckets_http_response *resp, const char *name, const char *value);
void buckets_http_resp_headerf(buckets_http_response *resp, const char *name, const char *fmt, ...)
    BUCKETS_PRINTF(3, 4);
const char *buckets_http_status_text(int status);

typedef void (*buckets_http_handler)(const buckets_http_request *req, buckets_http_response *resp,
                                     void *ud);

typedef struct {
  const char *host; /* NULL or "" binds all interfaces */
  int port;
  size_t max_body;
  int idle_timeout_sec;
  const char *server_header; /* value of the Server response header */
} buckets_http_config;

typedef struct buckets_http_server buckets_http_server;

buckets_http_server *buckets_http_server_start(buckets_loop *loop, const buckets_http_config *cfg,
                                               buckets_http_handler handler, void *ud);
/* Stops accepting and closes idle connections; in-flight responses finish. */
void buckets_http_server_shutdown(buckets_http_server *srv);
size_t buckets_http_server_connections(const buckets_http_server *srv);
int buckets_http_server_port(const buckets_http_server *srv);
void buckets_http_server_free(buckets_http_server *srv);

#endif
