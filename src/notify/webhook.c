/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* The webhook target (MinIO internal/event/target/webhook.go): POSTs
 * event.Log {"EventName","Key","Records":[event]} as JSON, with the auth
 * token as the Authorization header ("Bearer <token>" for a single word). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "core/common.h"
#include "core/log.h"
#include "net/fetch.h"
#include "notify/event.h"
#include "notify/targets.h"

typedef struct {
  char *endpoint, *auth, *ca_file;
} webhook;

static char *get(const buckets_config *cfg, const char *target, const char *key) {
  char *v = buckets_config_get(cfg, "notify_webhook", target, key);
  return v ? v : buckets_xstrdup("");
}

static bool create(const buckets_config *cfg, const char *target, const char *ca_file, void **impl, char *err, size_t errlen) {
  char *ep = get(cfg, target, "endpoint"), *tok = get(cfg, target, "auth_token");
  char *qdir = get(cfg, target, "queue_dir"), *qlim = get(cfg, target, "queue_limit");
  char *cert = get(cfg, target, "client_cert"), *key = get(cfg, target, "client_key");
  bool ok = true;
  char *end;
  strtoull(qlim, &end, 10);
  if (!*ep) {
    snprintf(err, errlen, "endpoint empty");
    ok = false;
  } else if (strncasecmp(ep, "http://", 7) != 0 && strncasecmp(ep, "https://", 8) != 0) {
    snprintf(err, errlen, "unexpected scheme found %s", ep);
    ok = false;
  } else if (*qlim && *end) {
    snprintf(err, errlen, "strconv.Atoi: parsing \"%s\": invalid syntax", qlim);
    ok = false;
  } else if (*qdir && *qdir != '/') {
    snprintf(err, errlen, "queueDir path should be absolute");
    ok = false;
  } else if ((*cert && !*key) || (!*cert && *key)) {
    snprintf(err, errlen, "cert and key must be specified as a pair");
    ok = false;
  }
  if (ok && *cert) buckets_log_warn("notify_webhook:%s: client certificates are not supported yet; connecting without one", target);
  if (ok && impl) {
    webhook *w = buckets_xcalloc(1, sizeof(*w));
    w->endpoint = ep, w->auth = tok, ep = tok = NULL;
    w->ca_file = ca_file ? buckets_xstrdup(ca_file) : NULL;
    *impl = w;
  }
  free(ep), free(tok), free(qdir), free(qlim), free(cert), free(key);
  return ok;
}

static buckets_send_result send_event(void *impl, const char *record, size_t n, const char *event_name, const char *key,
                                      char *err, size_t errlen) {
  webhook *w = impl;
  buckets_buf body = BUCKETS_BUF_INIT;
  buckets_buf_append_c(&body, "{\"EventName\":");
  buckets_json_go_string(&body, event_name, strlen(event_name));
  buckets_buf_append_c(&body, ",\"Key\":");
  buckets_json_go_string(&body, key, strlen(key));
  buckets_buf_append_c(&body, ",\"Records\":[");
  buckets_buf_append(&body, record, n);
  buckets_buf_append_c(&body, "]}");
  buckets_http_kv h[2] = {{"Content-Type", "application/json"}};
  size_t nh = 1;
  char auth[4200];
  if (*w->auth) {
    bool two = strchr(w->auth, ' ') != NULL; /* strings.Fields: "<scheme> <token>" is used as is */
    snprintf(auth, sizeof(auth), two ? "%s" : "Bearer %s", w->auth);
    h[nh++] = (buckets_http_kv){"Authorization", auth};
  }
  buckets_http_result res;
  char ferr[256];
  buckets_send_result r;
  if (!buckets_fetch("POST", w->endpoint, w->ca_file, h, nh, body.data, body.len, 10000, &res, ferr, sizeof(ferr))) {
    snprintf(err, errlen, "%s: %s", w->endpoint, ferr);
    r = BUCKETS_SEND_NOT_CONNECTED;
  } else {
    if (res.status >= 200 && res.status <= 299) r = BUCKETS_SEND_OK;
    else {
      snprintf(err, errlen, res.status == 403 ? "%s returned '%d', please check if your auth token is correctly set"
                                               : "%s returned '%d', please check your endpoint configuration",
               w->endpoint, res.status);
      r = BUCKETS_SEND_ERROR;
    }
    buckets_http_result_free(&res);
  }
  buckets_buf_free(&body);
  return r;
}

static void webhook_free(void *impl) {
  webhook *w = impl;
  if (!w) return;
  free(w->endpoint);
  free(w->auth);
  free(w->ca_file);
  free(w);
}

static const buckets_target_ops k_ops = {"webhook", send_event, webhook_free};
const buckets_target_kind buckets_target_webhook = {"notify_webhook", &k_ops, create};
