/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* The Elasticsearch target (MinIO internal/event/target/elasticsearch.go
 * over go-elasticsearch v7): namespace format keeps one document per
 * object (PUT /<index>/_doc/<id>, the id being the URL-safe base64 of the
 * HighwayHash-256 of "bucket/object"; removal is HEAD then DELETE), access
 * format adds one per event (POST /<index>/_doc); documents are
 * {"Records":[event]}. Before the first request the client checks that the
 * server is Elasticsearch (the product check), then reads its version (7 or
 * later) and creates the index when it is missing. Requests retry up to 10
 * times on 502/503/504 and connection failures. */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <yyjson.h>

#include "core/common.h"
#include "crypto/base64.h"
#include "crypto/highwayhash.h"
#include "net/fetch.h"
#include "net/http.h"
#include "notify/event.h"
#include "notify/targets.h"

#define MAX_RETRIES 10
#define TIMEOUT_MS 5000

static const uint8_t k_magic_key[32] = {0x4b, 0xe7, 0x34, 0xfa, 0x8e, 0x23, 0x8a, 0xcd, 0x26, 0x3e, 0x83,
                                         0xe6, 0xbb, 0x96, 0x85, 0x52, 0x04, 0x0f, 0x93, 0x5d, 0xa3, 0x9f,
                                         0x44, 0x14, 0x97, 0xe0, 0x9d, 0x13, 0x22, 0xde, 0x36, 0xa0};

typedef struct {
  char *url, *index, *ca_file, *auth;
  bool access;
  pthread_mutex_t mu;
  bool product_checked, client_ready, initialized;
} es;

typedef enum { E_OK, E_CONN, E_ERR } estatus;

static char *get(const buckets_config *cfg, const char *target, const char *key) {
  char *v = buckets_config_get(cfg, "notify_elasticsearch", target, key);
  return v ? v : buckets_xstrdup("");
}

static bool create(const buckets_config *cfg, const char *target, const char *ca_file, void **impl, char *err, size_t errlen) {
  char *url = get(cfg, target, "url"), *qlim = get(cfg, target, "queue_limit"), *fmt = get(cfg, target, "format");
  char *index = get(cfg, target, "index"), *user = get(cfg, target, "username"), *pass = get(cfg, target, "password");
  bool ok = true;
  /* xnet.ParseHTTPURL */
  const char *colon = strstr(url, "://");
  char scheme[32] = "";
  if (colon && colon - url < (long)sizeof(scheme)) snprintf(scheme, sizeof(scheme), "%.*s", (int)(colon - url), url);
  const char *hostpart = colon ? colon + 3 : "";
  if (!*url) {
    snprintf(err, errlen, "unexpected scheme found ");
    ok = false;
  } else if (*scheme && !*hostpart) {
    snprintf(err, errlen, "scheme appears with empty host");
    ok = false;
  } else if (strcasecmp(scheme, "http") != 0 && strcasecmp(scheme, "https") != 0) {
    snprintf(err, errlen, "unexpected scheme found %s", scheme);
    ok = false;
  }
  if (ok) {
    char *end;
    strtol(qlim, &end, 10);
    if (!*qlim || *end) {
      snprintf(err, errlen, "strconv.Atoi: parsing \"%s\": invalid syntax", qlim);
      ok = false;
    }
  }
  if (ok && *fmt && strcasecmp(fmt, "namespace") != 0 && strcasecmp(fmt, "access") != 0) {
    snprintf(err, errlen, "format value unrecognized");
    ok = false;
  } else if (ok && !*index) {
    snprintf(err, errlen, "empty index value");
    ok = false;
  } else if (ok && !*user != !*pass) {
    snprintf(err, errlen, "username and password should be set in pairs");
    ok = false;
  }
  if (ok && impl) {
    es *e = buckets_xcalloc(1, sizeof(*e));
    size_t ul = strlen(url);
    while (ul && url[ul - 1] == '/') url[--ul] = '\0';
    e->url = url, e->index = index, url = index = NULL;
    e->ca_file = ca_file ? buckets_xstrdup(ca_file) : NULL;
    e->access = strcmp(fmt, "access") == 0;
    if (*user) {
      buckets_buf up = BUCKETS_BUF_INIT;
      buckets_buf_appendf(&up, "%s:%s", user, pass);
      char *b64 = buckets_xmalloc(up.len * 4 / 3 + 8);
      buckets_base64_encode((const uint8_t *)up.data, up.len, b64);
      buckets_buf a = BUCKETS_BUF_INIT;
      buckets_buf_appendf(&a, "Basic %s", b64);
      e->auth = a.data;
      free(b64);
      buckets_buf_free(&up);
    }
    pthread_mutex_init(&e->mu, NULL);
    *impl = e;
  }
  free(url), free(qlim), free(fmt), free(index), free(user), free(pass);
  return ok;
}

/* estransport.Perform: one request with retries. */
static estatus perform(es *e, const char *method, const char *path, const char *body, size_t n, buckets_http_result *res,
                       char *err, size_t errlen) {
  buckets_buf url = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&url, "%s%s", e->url, path);
  buckets_http_kv h[4];
  size_t nh = 0;
  char ua[128];
  snprintf(ua, sizeof(ua), "buckets/%s", BUCKETS_VERSION);
  h[nh++] = (buckets_http_kv){"User-Agent", ua};
  if (body) h[nh++] = (buckets_http_kv){"Content-Type", "application/json"};
  if (e->auth) h[nh++] = (buckets_http_kv){"Authorization", e->auth};
  estatus st = E_CONN;
  for (int attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    char ferr[256];
    memset(res, 0, sizeof(*res));
    if (!buckets_fetch(method, url.data, e->ca_file, h, nh, body, n, TIMEOUT_MS, res, ferr, sizeof(ferr))) {
      snprintf(err, errlen, "%s", ferr);
      st = E_CONN;
      continue;
    }
    if (res->status == 502 || res->status == 503 || res->status == 504) {
      if (attempt < MAX_RETRIES) {
        buckets_http_result_free(res);
        continue;
      }
    }
    st = E_OK;
    break;
  }
  buckets_buf_free(&url);
  return st;
}

/* The product check and the Info request of getServerSupportStatus. */
static estatus product_check(es *e, char *err, size_t errlen) {
  if (e->product_checked) return E_OK;
  buckets_http_result r;
  if (perform(e, "GET", "/", NULL, 0, &r, err, errlen) != E_OK) return E_CONN;
  estatus st = E_OK;
  if (r.status > 299) {
    if (r.status != 401 && r.status != 403) {
      snprintf(err, errlen, "cannot retrieve informations from Elasticsearch");
      st = E_ERR;
    }
  } else {
    size_t pl;
    const char *prod = buckets_http_result_header(&r, "X-Elastic-Product", &pl);
    if (!prod || pl != 13 || strncmp(prod, "Elasticsearch", 13) != 0) {
      yyjson_doc *doc = yyjson_read(r.body.data ? r.body.data : "", r.body.len, 0);
      yyjson_val *root = doc ? yyjson_doc_get_root(doc) : NULL, *ver = yyjson_obj_get(root, "version");
      const char *num = yyjson_get_str(yyjson_obj_get(ver, "number"));
      const char *tag = yyjson_get_str(yyjson_obj_get(root, "tagline"));
      const char *flavor = yyjson_get_str(yyjson_obj_get(ver, "build_flavor"));
      int major = num ? atoi(num) : 0, minor = num && strchr(num, '.') ? atoi(strchr(num, '.') + 1) : 0;
      bool genuine = num && major >= 6 && (major >= 7 && minor >= 14 ? false : tag && strcmp(tag, "You Know, for Search") == 0);
      if (!num) genuine = false;
      if (!genuine) {
        snprintf(err, errlen, "the client noticed that the server is not Elasticsearch and we do not support this unknown product");
        st = E_ERR;
      } else if (major == 7 && minor < 14 && (!flavor || strcmp(flavor, "default") != 0)) {
        snprintf(err, errlen, "the client noticed that the server is not a supported distribution of Elasticsearch");
        st = E_ERR;
      }
      yyjson_doc_free(doc);
    }
  }
  buckets_http_result_free(&r);
  if (st == E_OK) e->product_checked = true;
  return st;
}

/* An esapi call: the product check first, then the request. */
static estatus call(es *e, const char *method, const char *path, const char *body, size_t n, buckets_http_result *res,
                    char *err, size_t errlen) {
  estatus st = product_check(e, err, errlen);
  if (st != E_OK) {
    memset(res, 0, sizeof(*res));
    return st;
  }
  return perform(e, method, path, body, n, res, err, errlen);
}

/* checkAndInitClient: the version (7 or later), then the index. */
static estatus init_client(es *e, char *err, size_t errlen) {
  if (e->client_ready) return E_OK;
  buckets_http_result r;
  if (call(e, "GET", "/", NULL, 0, &r, err, errlen) != E_OK) {
    buckets_http_result_free(&r);
    snprintf(err, errlen, "not connected to target server/service"); /* getServerSupportStatus: store.ErrNotConnected */
    return E_CONN;
  }
  yyjson_doc *doc = yyjson_read(r.body.data ? r.body.data : "", r.body.len, 0);
  const char *num = doc ? yyjson_get_str(yyjson_obj_get(yyjson_obj_get(yyjson_doc_get_root(doc), "version"), "number")) : NULL;
  estatus st = E_OK;
  if (!doc) {
    snprintf(err, errlen, "unable to get ES Server version - json parse error");
    st = E_ERR;
  } else if (!num) {
    snprintf(err, errlen, "Unable to get ES Server Version - got INFO response");
    st = E_ERR;
  } else {
    char *end;
    long major = strtol(num, &end, 10);
    if (end == num || (*end && *end != '.')) {
      snprintf(err, errlen, "bad ES version string: %s", num);
      st = E_ERR;
    } else if (major <= 6) {
      snprintf(err, errlen, "Elasticsearch version '%s' is not supported! Please use at least version 7.x.", num);
      st = E_ERR;
    }
  }
  yyjson_doc_free(doc);
  buckets_http_result_free(&r);
  if (st != E_OK) return st;
  e->client_ready = true;
  /* createIndex (its result is not checked) */
  buckets_buf path = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&path, "/_resolve/index/%s", e->index);
  if (call(e, "GET", path.data, NULL, 0, &r, err, errlen) == E_OK) {
    doc = yyjson_read(r.body.data ? r.body.data : "", r.body.len, 0);
    bool found = false;
    yyjson_val *arr = doc ? yyjson_obj_get(yyjson_doc_get_root(doc), "indices") : NULL, *it;
    size_t i, max;
    yyjson_arr_foreach(arr, i, max, it) {
      const char *nm = yyjson_get_str(yyjson_obj_get(it, "name"));
      if (nm && strcmp(nm, e->index) == 0) found = true;
    }
    bool parsed = doc != NULL;
    yyjson_doc_free(doc);
    buckets_http_result_free(&r);
    if (parsed && !found) {
      buckets_buf_reset(&path);
      buckets_buf_appendf(&path, "/%s", e->index);
      buckets_http_result c;
      if (call(e, "PUT", path.data, NULL, 0, &c, err, errlen) == E_OK) buckets_http_result_free(&c);
    }
  }
  buckets_buf_free(&path);
  return E_OK;
}

static estatus init_es(es *e, char *err, size_t errlen) {
  if (e->initialized) return E_OK;
  estatus st = init_client(e, err, errlen);
  if (st == E_OK) e->initialized = true;
  return st;
}

/* Response.String for errors: "[<code> <text>] <body>". */
static void es_error(const char *what, const buckets_http_result *r, char *err, size_t errlen) {
  const char *text = buckets_http_status_text(r->status);
  snprintf(err, errlen, "%s: [%d %s] %.*s", what, r->status, text ? text : "", (int)BUCKETS_MIN(r->body.len, 400),
           r->body.data ? r->body.data : "");
}

static estatus send_record(es *e, const char *record, size_t n, const char *event_name, const char *key, char *err,
                           size_t errlen) {
  buckets_buf doc = BUCKETS_BUF_INIT, path = BUCKETS_BUF_INIT;
  buckets_buf_append_c(&doc, "{\"Records\":[");
  buckets_buf_append(&doc, record, n);
  buckets_buf_append_c(&doc, "]}\n"); /* json.Encoder */
  buckets_http_result r;
  estatus st;
  if (!e->access) {
    uint8_t hash[BUCKETS_HH256_LEN];
    buckets_hh256(k_magic_key, key, strlen(key), hash);
    char id[64];
    buckets_base64_encode(hash, sizeof(hash), id);
    for (char *p = id; *p; p++) *p = *p == '+' ? '-' : *p == '/' ? '_' : *p; /* base64.URLEncoding */
    buckets_buf_appendf(&path, "/%s/_doc/%s", e->index, id);
    if (strcmp(event_name, "s3:ObjectRemoved:Delete") == 0) { /* removeEntry */
      st = call(e, "HEAD", path.data, NULL, 0, &r, err, errlen);
      bool exists = st == E_OK && r.status <= 299;
      if (st == E_OK) buckets_http_result_free(&r);
      if (exists) {
        st = call(e, "DELETE", path.data, NULL, 0, &r, err, errlen);
        if (st == E_OK) {
          if (r.status > 299) {
            es_error("Delete err", &r, err, errlen);
            st = E_ERR;
          }
          buckets_http_result_free(&r);
        }
      }
    } else { /* updateEntry */
      st = call(e, "PUT", path.data, doc.data, doc.len, &r, err, errlen);
      if (st == E_OK) {
        if (r.status > 299) {
          es_error("Update err", &r, err, errlen);
          st = E_ERR;
        }
        buckets_http_result_free(&r);
      }
    }
  } else { /* addEntry */
    buckets_buf_appendf(&path, "/%s/_doc", e->index);
    st = call(e, "POST", path.data, doc.data, doc.len, &r, err, errlen);
    if (st == E_OK) {
      if (r.status > 299) {
        es_error("Add err", &r, err, errlen);
        st = E_ERR;
      }
      buckets_http_result_free(&r);
    }
  }
  buckets_buf_free(&doc);
  buckets_buf_free(&path);
  return st;
}

static buckets_send_result result(estatus st) {
  return st == E_OK ? BUCKETS_SEND_OK : st == E_CONN ? BUCKETS_SEND_NOT_CONNECTED : BUCKETS_SEND_ERROR;
}

/* Save and SendFromStore alike: init, checkAndInitClient, send. */
static buckets_send_result send_event(void *impl, const char *record, size_t n, const char *event_name, const char *key,
                                      char *err, size_t errlen) {
  es *e = impl;
  pthread_mutex_lock(&e->mu);
  estatus st = init_es(e, err, errlen);
  if (st == E_OK) st = init_client(e, err, errlen);
  if (st == E_OK) st = send_record(e, record, n, event_name, key, err, errlen);
  pthread_mutex_unlock(&e->mu);
  return result(st);
}

/* IsActive: init, then a ping (HEAD /). */
static bool is_active(void *impl, char *err, size_t errlen) {
  es *e = impl;
  pthread_mutex_lock(&e->mu);
  bool up = init_es(e, err, errlen) == E_OK && init_client(e, err, errlen) == E_OK;
  if (up) {
    buckets_http_result r;
    if (call(e, "HEAD", "/", NULL, 0, &r, err, errlen) != E_OK) {
      snprintf(err, errlen, "not connected to target server/service");
      up = false;
    } else {
      up = r.status <= 299;
      buckets_http_result_free(&r);
    }
  }
  pthread_mutex_unlock(&e->mu);
  return up;
}

static void es_free(void *impl) {
  es *e = impl;
  if (!e) return;
  pthread_mutex_destroy(&e->mu);
  free(e->url), free(e->index), free(e->ca_file), free(e->auth);
  free(e);
}

static const buckets_target_ops k_ops = {.type = "elasticsearch", .send = send_event, .free = es_free, .is_active = is_active};
const buckets_target_kind buckets_target_elasticsearch = {"notify_elasticsearch", &k_ops, create};
