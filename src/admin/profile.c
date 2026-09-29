/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* mc admin profile / mc support profile: StartProfilingHandler (start on
 * every node), DownloadProfilingHandler (stop them, zip what they made) and
 * ProfileHandler (both, a duration apart). The profile types are MinIO's;
 * what they hold is this server's (core/prof.h): CPU samples, the heap in
 * use, threads, and empty block/mutex profiles, in pprof's format. */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <yyjson.h>

#include "admin/admin.h"
#include "admin/info.h"
#include "core/prof.h"
#include "core/timefmt.h"
#include "core/zipwrite.h"
#include "crypto/base64.h"
#include "dist/internode.h"
#include "dist/peer.h"
#include "notify/event.h"

typedef struct {
  char type[32];
  const char *ext;
  bool cpu; /* holds the CPU sampler */
  buckets_buf before[2];
  const char *before_names[2];
} profiler;

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static profiler g_prof[16];
static size_t g_nprof;

/* Stops and forgets one profiler (without its data). */
static void prof_drop(profiler *p) {
  if (p->cpu) {
    buckets_buf ignored = BUCKETS_BUF_INIT;
    buckets_prof_cpu_stop(&ignored);
    buckets_buf_free(&ignored);
  }
  buckets_buf_free(&p->before[0]);
  buckets_buf_free(&p->before[1]);
}

static void prof_remove(size_t i) {
  prof_drop(&g_prof[i]);
  memmove(&g_prof[i], &g_prof[i + 1], (g_nprof - i - 1) * sizeof(profiler));
  g_nprof--;
}

/* startProfiler; under g_mu. err gets MinIO's words on failure. */
static bool prof_start(const char *type, char *err, size_t errcap) {
  if (g_nprof >= BUCKETS_ARRAY_LEN(g_prof)) {
    snprintf(err, errcap, "%s", "too many profilers");
    return false;
  }
  profiler p;
  memset(&p, 0, sizeof(p));
  snprintf(p.type, sizeof(p.type), "%s", type);
  p.ext = "pprof";
  if (strcmp(type, "cpu") == 0 || strcmp(type, "cpuio") == 0) {
    if (!buckets_prof_cpu_start(err, errcap)) return false;
    p.cpu = true;
  } else if (strcmp(type, "mem") == 0) {
    buckets_prof_heap(&p.before[0]);
    p.before_names[0] = "before";
  } else if (strcmp(type, "block") == 0) {
  } else if (strcmp(type, "mutex") == 0) {
    buckets_prof_empty("contentions", "count", "delay", "nanoseconds", &p.before[0]);
    p.before_names[0] = "before";
  } else if (strcmp(type, "threads") == 0) {
    buckets_prof_threads(&p.before[0]);
    p.before_names[0] = "before";
  } else if (strcmp(type, "goroutines") == 0) {
    p.ext = "txt";
    buckets_prof_threads_text(&p.before[0]);
    p.before_names[0] = "before";
    buckets_prof_threads_text(&p.before[1]);
    p.before_names[1] = "before,debug=2";
  } else if (strcmp(type, "trace") == 0) {
    p.ext = "trace";
  } else {
    snprintf(err, errcap, "%s", "profiler type unknown");
    return false;
  }
  g_prof[g_nprof++] = p;
  return true;
}

/* getProfileData: stops every profiler; name -> data */
typedef struct {
  char name[96];
  buckets_buf data;
} prof_file;

static size_t prof_collect(prof_file **out) {
  pthread_mutex_lock(&g_mu);
  prof_file *f = buckets_xcalloc(g_nprof * 3 + 1, sizeof(*f));
  size_t n = 0;
  for (size_t i = 0; i < g_nprof; i++) {
    profiler *p = &g_prof[i];
    prof_file *x = &f[n++];
    snprintf(x->name, sizeof(x->name), "%s.%s", p->type, p->ext);
    if (p->cpu) {
      buckets_prof_cpu_stop(&x->data);
      p->cpu = false;
    } else if (strcmp(p->type, "mem") == 0) {
      buckets_prof_heap(&x->data);
    } else if (strcmp(p->type, "block") == 0 || strcmp(p->type, "mutex") == 0) {
      buckets_prof_empty("contentions", "count", "delay", "nanoseconds", &x->data);
    } else if (strcmp(p->type, "threads") == 0) {
      buckets_prof_threads(&x->data);
    } else if (strcmp(p->type, "goroutines") == 0) {
      buckets_prof_threads_text(&x->data);
    }
    for (int k = 0; k < 2; k++) {
      if (!p->before[k].len) continue;
      prof_file *y = &f[n++];
      snprintf(y->name, sizeof(y->name), "%s-%s.%s", p->type, p->before_names[k], p->ext);
      buckets_buf_append(&y->data, p->before[k].data, p->before[k].len);
    }
    prof_drop(p);
  }
  g_nprof = 0;
  pthread_mutex_unlock(&g_mu);
  *out = f;
  return n;
}

static void prof_files_free(prof_file *f, size_t n) {
  for (size_t i = 0; i < n; i++) buckets_buf_free(&f[i].data);
  free(f);
}

/* ---- across the cluster ------------------------------------------------------------------------------ */

static const char *self_name(const buckets_s3_server *s) { return s->cluster ? s->cluster->self : ""; }

/* StartProfiling on every node, then here: StartProfilingResult entries */
static void start_everywhere(buckets_s3_server *s, const char *type, buckets_buf *results) {
  size_t np = 0;
  buckets_http_client *const *pcs = buckets_peer_clients(s->peers, &np);
  if (!np && !(s->cluster && s->cluster->distributed)) {
    /* MinIO's single node reports an empty peer that succeeded */
    buckets_buf_append_c(results, results->len > 1 ? "," : "");
    buckets_buf_append_c(results, "{\"nodeName\":\"\",\"success\":true,\"error\":\"\"}");
  }
  for (size_t i = 0; i < np; i++) {
    char node[300], target[256];
    snprintf(node, sizeof(node), "%s:%d", buckets_http_client_host(pcs[i]), buckets_http_client_port(pcs[i]));
    buckets_buf body = BUCKETS_BUF_INIT;
    buckets_buf t = BUCKETS_BUF_INIT;
    buckets_buf_append_c(&t, BUCKETS_INTERNODE_PREFIX "peer/admin?op=profile-start&type=");
    buckets_url_encode(&t, type, false);
    buckets_buf_append_char(&t, '\0');
    snprintf(target, sizeof(target), "%s", t.data);
    buckets_buf_free(&t);
    int status = 0;
    const char *err = "";
    yyjson_doc *d = NULL;
    if (!buckets_peer_call(s->peers, node, target, &status, &body) || status != 200) {
      err = "peer not reachable";
    } else if ((d = yyjson_read(body.data ? body.data : "", body.len, 0))) {
      const char *e = yyjson_get_str(yyjson_obj_get(yyjson_doc_get_root(d), "error"));
      err = e ? e : "";
    }
    buckets_buf_append_c(results, results->len > 1 ? ",{\"nodeName\":" : "{\"nodeName\":");
    buckets_json_go_string(results, node, strlen(node));
    buckets_buf_appendf(results, ",\"success\":%s,\"error\":", *err ? "false" : "true");
    buckets_json_go_string(results, err, strlen(err));
    buckets_buf_append_char(results, '}');
    yyjson_doc_free(d);
    buckets_buf_free(&body);
  }
  char err[256] = "";
  pthread_mutex_lock(&g_mu);
  bool ok = prof_start(type, err, sizeof(err));
  pthread_mutex_unlock(&g_mu);
  buckets_buf_append_c(results, results->len > 1 ? ",{\"nodeName\":" : "{\"nodeName\":");
  buckets_json_go_string(results, self_name(s), strlen(self_name(s)));
  buckets_buf_appendf(results, ",\"success\":%s,\"error\":", ok ? "true" : "false");
  buckets_json_go_string(results, err, strlen(err));
  buckets_buf_append_char(results, '}');
}

/* The types in a profilerType list ("cpu,mem"). */
static size_t split_types(const char *list, char (*out)[32], size_t cap) {
  size_t n = 0;
  for (const char *p = list; n < cap;) {
    const char *c = strchr(p, ',');
    size_t l = c ? (size_t)(c - p) : strlen(p);
    snprintf(out[n++], 32, "%.*s", (int)(l < 31 ? l : 31), p);
    if (!c) break;
    p = c + 1;
  }
  return n;
}

/* DownloadProfilingData: cluster.info, every peer's profiles, then ours;
 * false when no node had any. */
static bool download_everywhere(buckets_s3_server *s, buckets_buf *zip) {
  buckets_zipw *z = buckets_zipw_new(zip);
  time_t now = time(NULL);
  buckets_buf info = BUCKETS_BUF_INIT;
  buckets_admin_cluster_info_json(s, &info);
  buckets_zipw_add(z, "cluster.info", info.data, info.len, now);
  buckets_buf_free(&info);
  bool found = false;
  size_t np = 0;
  buckets_http_client *const *pcs = buckets_peer_clients(s->peers, &np);
  for (size_t i = 0; i < np; i++) {
    char node[300];
    snprintf(node, sizeof(node), "%s:%d", buckets_http_client_host(pcs[i]), buckets_http_client_port(pcs[i]));
    buckets_buf body = BUCKETS_BUF_INIT;
    int status = 0;
    if (buckets_peer_call(s->peers, node, BUCKETS_INTERNODE_PREFIX "peer/admin?op=profile-stop", &status, &body) &&
        status == 200) {
      yyjson_doc *d = yyjson_read(body.data ? body.data : "", body.len, 0);
      yyjson_val *files = yyjson_obj_get(yyjson_doc_get_root(d), "files");
      size_t k, kmax;
      yyjson_val *key, *val;
      yyjson_obj_foreach(files, k, kmax, key, val) {
        const char *b64 = yyjson_get_str(val);
        size_t bl = b64 ? strlen(b64) : 0;
        uint8_t *raw = buckets_xmalloc(bl + 4);
        long dn = buckets_base64_decode(b64 ? b64 : "", bl, raw);
        if (dn >= 0) {
          char name[512];
          snprintf(name, sizeof(name), "profile-%s-%s", node, yyjson_get_str(key));
          buckets_zipw_add(z, name, raw, (size_t)dn, now);
          found = true;
        }
        free(raw);
      }
      yyjson_doc_free(d);
    }
    buckets_buf_free(&body);
  }
  prof_file *f;
  size_t n = prof_collect(&f);
  for (size_t i = 0; i < n; i++) {
    char name[512];
    snprintf(name, sizeof(name), "profile-%s-%s", self_name(s), f[i].name);
    buckets_zipw_add(z, name, f[i].data.data ? f[i].data.data : "", f[i].data.len, now);
    found = true;
  }
  prof_files_free(f, n);
  buckets_zipw_finish(z);
  return found;
}

static void stop_all_local(void) {
  pthread_mutex_lock(&g_mu);
  while (g_nprof) prof_remove(0);
  pthread_mutex_unlock(&g_mu);
}

void buckets_admin_start_profiling(s3_ctx *c) {
  const char *types = buckets_query_get(&c->q, "profilerType");
  if (!types) { /* the route wants the query (Queries("profilerType", ...)) */
    buckets_admin_unsupported(c);
    return;
  }
  if (!buckets_admin_authorize(c, "admin:Profiling")) return;
  char list[16][32];
  size_t n = split_types(types, list, 16);
  /* the requested types that run already stop first */
  pthread_mutex_lock(&g_mu);
  for (size_t k = 0; k < n; k++)
    for (size_t i = 0; i < g_nprof; i++)
      if (strcmp(g_prof[i].type, list[k]) == 0) {
        prof_remove(i);
        break;
      }
  pthread_mutex_unlock(&g_mu);
  buckets_buf out = BUCKETS_BUF_INIT;
  buckets_buf_append_char(&out, '[');
  for (size_t k = 0; k < n; k++) start_everywhere(c->s, list[k], &out);
  buckets_buf_append_char(&out, ']');
  buckets_buf_reset(&c->resp->body);
  buckets_buf_append(&c->resp->body, out.data, out.len);
  buckets_buf_free(&out);
  c->resp->status = 200;
  buckets_http_resp_header(c->resp, "Content-Type", "application/json");
}

/* The zip, and when nobody profiled, MinIO's error written after it. */
static void send_download(s3_ctx *c) {
  buckets_buf_reset(&c->resp->body);
  bool found = download_everywhere(c->s, &c->resp->body);
  c->resp->status = 200;
  buckets_http_resp_header(c->resp, "Content-Type", "application/zip");
  if (!found) {
    const buckets_s3_error_info *ei = buckets_s3_error_get(BUCKETS_ERR_ADMIN_PROFILER_NOT_ENABLED);
    const char *host = c->s->layer ? c->s->layer->deployment_id_str : "";
    buckets_buf *b = &c->resp->body;
    buckets_buf_append_c(b, "{\"Code\":");
    buckets_json_go_string(b, ei->code, strlen(ei->code));
    buckets_buf_append_c(b, ",\"Message\":");
    buckets_json_go_string(b, ei->message, strlen(ei->message));
    buckets_buf_append_c(b, ",\"Resource\":");
    buckets_json_go_string(b, c->path ? c->path : "", c->path ? strlen(c->path) : 0);
    buckets_buf_append_c(b, ",\"RequestId\":");
    buckets_json_go_string(b, c->request_id, strlen(c->request_id));
    buckets_buf_append_c(b, ",\"HostId\":");
    buckets_json_go_string(b, host, strlen(host));
    buckets_buf_append_char(b, '}');
  }
}

void buckets_admin_download_profiling(s3_ctx *c) {
  if (!buckets_admin_authorize(c, "admin:Profiling")) return;
  send_download(c);
}

void buckets_admin_profile(s3_ctx *c) {
  if (!buckets_admin_authorize(c, "admin:Profiling")) return;
  const char *types = buckets_query_get(&c->q, "profilerType");
  int64_t dur = 60000000000LL;
  const char *ds = buckets_query_get(&c->q, "duration");
  if (ds && *ds && !buckets_go_duration_parse(ds, &dur)) {
    buckets_admin_error(c, BUCKETS_ERR_INVALID_REQUEST);
    return;
  }
  stop_all_local();
  char list[16][32];
  size_t n = split_types(types ? types : "", list, 16);
  buckets_buf ignored = BUCKETS_BUF_INIT;
  for (size_t k = 0; k < n; k++) start_everywhere(c->s, list[k], &ignored);
  buckets_buf_free(&ignored);
  if (dur > 0) {
    struct timespec ts = {dur / 1000000000LL, dur % 1000000000LL};
    nanosleep(&ts, NULL);
  }
  buckets_buf_reset(&c->resp->body);
  if (!download_everywhere(c->s, &c->resp->body)) {
    buckets_admin_error(c, BUCKETS_ERR_ADMIN_PROFILER_NOT_ENABLED);
    return;
  }
  c->resp->status = 200;
  buckets_http_resp_header(c->resp, "Content-Type", "application/zip");
}

/* ---- the peer side ------------------------------------------------------------------------------------- */

bool buckets_admin_profile_peer(buckets_s3_server *s, const char *op, const buckets_query *q,
                                buckets_http_response *resp) {
  (void)s;
  if (strcmp(op, "profile-start") == 0) {
    const char *type = buckets_query_get(q, "type");
    char err[256] = "";
    pthread_mutex_lock(&g_mu);
    for (size_t i = 0; i < g_nprof; i++)
      if (strcmp(g_prof[i].type, type ? type : "") == 0) {
        prof_remove(i);
        break;
      }
    prof_start(type ? type : "", err, sizeof(err));
    pthread_mutex_unlock(&g_mu);
    buckets_buf_append_c(&resp->body, "{\"error\":");
    buckets_json_go_string(&resp->body, err, strlen(err));
    buckets_buf_append_char(&resp->body, '}');
    return true;
  }
  if (strcmp(op, "profile-stop") == 0) {
    prof_file *f;
    size_t n = prof_collect(&f);
    buckets_buf_append_c(&resp->body, "{\"files\":{");
    for (size_t i = 0; i < n; i++) {
      char *b64 = buckets_xmalloc(4 * (f[i].data.len / 3 + 1) + 2);
      buckets_base64_encode((const uint8_t *)(f[i].data.data ? f[i].data.data : ""), f[i].data.len, b64);
      buckets_buf_appendf(&resp->body, "%s\"%s\":\"%s\"", i ? "," : "", f[i].name, b64);
      free(b64);
    }
    buckets_buf_append_c(&resp->body, "}}");
    prof_files_free(f, n);
    return true;
  }
  return false;
}
