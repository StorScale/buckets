/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "lease.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#include "core/buf.h"
#include "core/log.h"

/* metav1.MicroTime: 2006-01-02T15:04:05.000000Z07:00 */
static void micro_now(char out[40]) {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  struct tm tm;
  time_t t = tv.tv_sec;
  gmtime_r(&t, &tm);
  char base[32];
  strftime(base, sizeof(base), "%Y-%m-%dT%H:%M:%S", &tm);
  snprintf(out, 40, "%s.%06dZ", base, (int)tv.tv_usec);
}

static double parse_time(const char *s) {
  if (!s) return 0;
  struct tm tm;
  memset(&tm, 0, sizeof(tm));
  if (sscanf(s, "%d-%d-%dT%d:%d:%d", &tm.tm_year, &tm.tm_mon, &tm.tm_mday, &tm.tm_hour, &tm.tm_min, &tm.tm_sec) != 6) {
    return 0;
  }
  tm.tm_year -= 1900;
  tm.tm_mon -= 1;
  double t = (double)timegm(&tm);
  const char *dot = strchr(s, '.');
  if (dot) t += strtod(dot, NULL);
  return t;
}

static double now_s(void) {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return tv.tv_sec + tv.tv_usec / 1e6;
}

static yyjson_mut_doc *lease_doc(const char *ns, const char *name, const char *holder, int duration_s,
                                 const char *acquire, const char *rv, long long transitions) {
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, root);
  yyjson_mut_obj_add_str(d, root, "apiVersion", "coordination.k8s.io/v1");
  yyjson_mut_obj_add_str(d, root, "kind", "Lease");
  yyjson_mut_val *meta = yyjson_mut_obj_add_obj(d, root, "metadata");
  yyjson_mut_obj_add_strcpy(d, meta, "name", name);
  yyjson_mut_obj_add_strcpy(d, meta, "namespace", ns);
  if (rv) yyjson_mut_obj_add_strcpy(d, meta, "resourceVersion", rv);
  yyjson_mut_val *spec = yyjson_mut_obj_add_obj(d, root, "spec");
  yyjson_mut_obj_add_strcpy(d, spec, "holderIdentity", holder);
  yyjson_mut_obj_add_int(d, spec, "leaseDurationSeconds", duration_s);
  char now[40];
  micro_now(now);
  yyjson_mut_obj_add_strcpy(d, spec, "acquireTime", acquire ? acquire : now);
  yyjson_mut_obj_add_strcpy(d, spec, "renewTime", now);
  yyjson_mut_obj_add_int(d, spec, "leaseTransitions", transitions);
  return d;
}

static int put(kube *k, const char *path, yyjson_mut_doc *d) {
  size_t n;
  char *json = yyjson_mut_write(d, 0, &n);
  int st = kube_request(k, "PUT", path, "application/json", json, n, NULL);
  free(json);
  return st;
}

bool lease_acquire_or_renew(kube *k, const char *ns, const char *name, const char *identity, int duration_s) {
  buckets_buf path = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&path, "/apis/coordination.k8s.io/v1/namespaces/%s/leases/%s", ns, name);
  yyjson_doc *doc;
  int st = kube_get(k, path.data, &doc);
  bool held = false;
  if (st == 404) {
    buckets_buf coll = BUCKETS_BUF_INIT;
    buckets_buf_appendf(&coll, "/apis/coordination.k8s.io/v1/namespaces/%s/leases", ns);
    yyjson_mut_doc *d = lease_doc(ns, name, identity, duration_s, NULL, NULL, 0);
    held = kube_create(k, coll.data, d, NULL) == 201;
    yyjson_mut_doc_free(d);
    buckets_buf_free(&coll);
  } else if (st == 200) {
    yyjson_val *root = yyjson_doc_get_root(doc), *spec = yyjson_obj_get(root, "spec");
    const char *holder = yyjson_get_str(yyjson_obj_get(spec, "holderIdentity"));
    const char *rv = yyjson_get_str(yyjson_obj_get(yyjson_obj_get(root, "metadata"), "resourceVersion"));
    const char *acq = yyjson_get_str(yyjson_obj_get(spec, "acquireTime"));
    long long trans = yyjson_get_sint(yyjson_obj_get(spec, "leaseTransitions"));
    int dur = (int)yyjson_get_int(yyjson_obj_get(spec, "leaseDurationSeconds"));
    double renewed = parse_time(yyjson_get_str(yyjson_obj_get(spec, "renewTime")));
    bool mine = holder && strcmp(holder, identity) == 0;
    bool expired = !holder || !*holder || now_s() > renewed + (dur ? dur : duration_s);
    if (mine || expired) {
      yyjson_mut_doc *d = lease_doc(ns, name, identity, duration_s, mine ? acq : NULL, rv, mine ? trans : trans + 1);
      held = put(k, path.data, d) == 200; /* 409: someone else updated it first */
      yyjson_mut_doc_free(d);
    }
  }
  yyjson_doc_free(doc);
  buckets_buf_free(&path);
  return held;
}

void lease_release(kube *k, const char *ns, const char *name, const char *identity) {
  buckets_buf path = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&path, "/apis/coordination.k8s.io/v1/namespaces/%s/leases/%s", ns, name);
  yyjson_doc *doc;
  if (kube_get(k, path.data, &doc) == 200) {
    yyjson_val *root = yyjson_doc_get_root(doc), *spec = yyjson_obj_get(root, "spec");
    const char *holder = yyjson_get_str(yyjson_obj_get(spec, "holderIdentity"));
    if (holder && strcmp(holder, identity) == 0) {
      const char *rv = yyjson_get_str(yyjson_obj_get(yyjson_obj_get(root, "metadata"), "resourceVersion"));
      yyjson_mut_doc *d = lease_doc(ns, name, "", 1, NULL, rv, yyjson_get_sint(yyjson_obj_get(spec, "leaseTransitions")));
      put(k, path.data, d);
      yyjson_mut_doc_free(d);
    }
  }
  yyjson_doc_free(doc);
  buckets_buf_free(&path);
}
