/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* The realtime metrics (MetricsHandler: mc admin scanner status, mc support
 * top disk/net/rpc...): madmin.RealtimeMetrics records, one per interval,
 * each merging this node's collectLocalMetrics with every peer's as madmin's
 * Merge methods do -- quirks included: the aggregate leaves out memory and
 * CPU (only by_host has them), drive I/O counters and the interface name,
 * and a merged TimedAction's minimum is always 0. */
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <yyjson.h>
#ifdef __linux__
#include <sys/sysmacros.h>
#endif

#include "admin/admin.h"
#include "admin/info.h"
#include "core/timefmt.h"
#include "dist/internode.h"
#include "dist/peer.h"
#include "heal/healer.h"
#include "net/client.h"
#include "s3/batch.h"
#include "scanner/scanner.h"
#include "storage/drivestats.h"
#include "storage/osmetrics.h"
#include "trace/trace.h"

/* madmin.MetricType bits */
enum {
  MT_SCANNER = 1u << 0,
  MT_DISK = 1u << 1,
  MT_OS = 1u << 2,
  MT_BATCH = 1u << 3,
  MT_SITE_RESYNC = 1u << 4,
  MT_NET = 1u << 5,
  MT_MEM = 1u << 6,
  MT_CPU = 1u << 7,
  MT_RPC = 1u << 8,
  MT_ALL = (1u << 10) - 1,
};

#define ZERO_TIME "0001-01-01T00:00:00Z"

typedef struct {
  uint64_t types;
  char *hosts, *disks; /* comma-separated filters, NULL: all */
  char *job_id, *dep_id;
} rt_opts;

static bool in_list(const char *csv, const char *name) {
  if (!csv || !*csv) return true;
  size_t n = strlen(name);
  for (const char *p = csv; *p;) {
    const char *e = strchr(p, ',');
    size_t k = e ? (size_t)(e - p) : strlen(p);
    if (k == n && memcmp(p, name, n) == 0) return true;
    if (!e) break;
    p = e + 1;
  }
  return false;
}

static void now_str(char out[64]) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  buckets_time_rfc3339_nano(ts.tv_sec, ts.tv_nsec, out);
}

/* Go's encoding/json float (strconv 'f' form below 1e21, shortest digits) */
static yyjson_mut_val *go_float(yyjson_mut_doc *d, double v) {
  char s[64];
  if (v == (double)(int64_t)v && v < 1e21 && v > -1e21) {
    snprintf(s, sizeof(s), "%lld", (long long)v);
  } else {
    int prec = 1;
    for (; prec <= 17; prec++) {
      snprintf(s, sizeof(s), "%.*g", prec, v);
      if (strtod(s, NULL) == v) break;
    }
    double a = v < 0 ? -v : v;
    if (strchr(s, 'e') && a >= 1e-6 && a < 1e21) {
      int e10 = 0;
      for (double x = a; x >= 10; x /= 10) e10++;
      for (double x = a; x < 1; x *= 10) e10--;
      int dec = prec - 1 - e10;
      snprintf(s, sizeof(s), "%.*f", dec > 0 ? dec : 0, v);
    }
  }
  return yyjson_mut_rawcpy(d, s);
}

/* ---- Go's field order: optional (omitempty) keys go in their place ---- */

static size_t order_of(const char *const *order, const char *key) {
  for (size_t i = 0; order[i]; i++)
    if (strcmp(order[i], key) == 0) return i;
  return SIZE_MAX;
}

static void set_field(yyjson_mut_doc *d, yyjson_mut_val *obj, const char *const *order, const char *key,
                      yyjson_mut_val *val) {
  yyjson_mut_val *k = yyjson_mut_strcpy(d, key);
  if (yyjson_mut_obj_get(obj, key)) {
    yyjson_mut_obj_replace(obj, k, val);
    return;
  }
  size_t want = order_of(order, key), idx = 0;
  yyjson_mut_obj_iter it = yyjson_mut_obj_iter_with(obj);
  yyjson_mut_val *ek;
  while ((ek = yyjson_mut_obj_iter_next(&it)))
    if (order_of(order, yyjson_mut_get_str(ek)) < want) idx++;
  yyjson_mut_obj_insert(obj, k, val, idx);
}

static const char *const k_metrics_order[] = {"scanner", "disk", "os", "batchJobs", "siteResync", "net",
                                              "mem",     "cpu",  "rpc", "go",       NULL};
static const char *const k_scanner_order[] = {"collected",   "current_cycle", "current_started", "cycle_complete_times",
                                              "ongoing_buckets", "per_bucket_stats", "life_time_ops", "ilm_ops",
                                              "last_minute", "active",        NULL};
static const char *const k_scanner_lm_order[] = {"actions", "ilm", NULL};
static const char *const k_disk_order[] = {"collected",     "n_disks",     "offline", "healing",
                                           "life_time_ops", "last_minute", "iostats", NULL};
static const char *const k_os_order[] = {"collected", "life_time_ops", "last_minute", NULL};
static const char *const k_rpc_order[] = {"collectedAt",      "connected",        "reconnectCount", "disconnected",
                                          "outgoingStreams",  "incomingStreams",  "outgoingBytes",  "incomingBytes",
                                          "outgoingMessages", "incomingMessages", "outQueue",       "lastPongTime",
                                          "lastPingMS",       "maxPingDurMS",     "lastConnectTime", "byDestination",
                                          "byCaller",         NULL};
static const char *const k_iostats[] = {"read_ios",      "read_merges",     "read_sectors",   "read_ticks",
                                        "write_ios",     "write_merges",    "wrte_sectors",   "write_ticks",
                                        "current_ios",   "total_ticks",     "req_ticks",      "discard_ios",
                                        "discard_merges", "discard_secotrs", "discard_ticks", "flush_ios",
                                        "flush_ticks",   NULL};
static const char *const k_netstats[] = {"rx_bytes",   "rx_packets",    "rx_errors",     "rx_dropped", "rx_fifo",
                                         "rx_frame",   "rx_compressed", "rx_multicast",  "tx_bytes",   "tx_packets",
                                         "tx_errors",  "tx_dropped",    "tx_fifo",       "tx_collisions",
                                         "tx_carrier", "tx_compressed", NULL};

/* ---- values: numbers read from peers stay raw text ---- */

static uint64_t num_u(yyjson_mut_val *v) {
  if (!v) return 0;
  if (yyjson_mut_is_raw(v)) return strtoull(yyjson_mut_get_raw(v), NULL, 10);
  if (yyjson_mut_is_uint(v)) return yyjson_mut_get_uint(v);
  if (yyjson_mut_is_sint(v)) return (uint64_t)yyjson_mut_get_sint(v);
  return 0;
}

static double num_f(yyjson_mut_val *v) {
  if (!v) return 0;
  if (yyjson_mut_is_raw(v)) return strtod(yyjson_mut_get_raw(v), NULL);
  if (yyjson_mut_is_real(v)) return yyjson_mut_get_real(v);
  return (double)num_u(v);
}

/* A time.Time's nanoseconds (the zero time sorts first). */
static long double tns(yyjson_mut_val *v) {
  const char *s = v ? yyjson_mut_get_str(v) : NULL;
  long long sec;
  long nsec;
  if (!s || !buckets_time_parse_rfc3339(s, &sec, &nsec)) return -1e30L;
  return (long double)sec * 1e9L + nsec;
}

static bool before(yyjson_mut_val *a, yyjson_mut_val *b) { return tns(a) < tns(b); }

static void set_u(yyjson_mut_doc *d, yyjson_mut_val *obj, const char *key, uint64_t v) {
  yyjson_mut_obj_replace(obj, yyjson_mut_strcpy(d, key), yyjson_mut_uint(d, v));
}

static void copy_key(yyjson_mut_doc *d, yyjson_mut_val *dst, yyjson_mut_val *src, const char *key) {
  yyjson_mut_val *v = yyjson_mut_obj_get(src, key);
  if (v) yyjson_mut_obj_replace(dst, yyjson_mut_strcpy(d, key), yyjson_mut_val_mut_copy(d, v));
}

/* dst[key] (a map, created in its place when src has entries) += src[key] */
static void sum_map(yyjson_mut_doc *d, yyjson_mut_val *dst, const char *const *order, yyjson_mut_val *src,
                    const char *key) {
  yyjson_mut_val *sm = yyjson_mut_obj_get(src, key);
  if (!yyjson_mut_is_obj(sm) || !yyjson_mut_obj_size(sm)) return;
  yyjson_mut_val *dm = yyjson_mut_obj_get(dst, key);
  if (!yyjson_mut_is_obj(dm)) set_field(d, dst, order, key, dm = yyjson_mut_obj(d));
  yyjson_mut_obj_iter it = yyjson_mut_obj_iter_with(sm);
  yyjson_mut_val *k;
  while ((k = yyjson_mut_obj_iter_next(&it))) {
    const char *name = yyjson_mut_get_str(k);
    uint64_t v = num_u(yyjson_mut_obj_iter_get_val(k)) + num_u(yyjson_mut_obj_get(dm, name));
    yyjson_mut_val *nk = yyjson_mut_strcpy(d, name);
    if (!yyjson_mut_obj_replace(dm, nk, yyjson_mut_uint(d, v))) yyjson_mut_obj_add(dm, nk, yyjson_mut_uint(d, v));
  }
}

/* TimedAction.Merge */
static yyjson_mut_val *timed_merge(yyjson_mut_doc *d, yyjson_mut_val *t, yyjson_mut_val *o) {
  uint64_t count = num_u(yyjson_mut_obj_get(t, "count")) + num_u(yyjson_mut_obj_get(o, "count"));
  uint64_t acc = num_u(yyjson_mut_obj_get(t, "acc_time_ns")) + num_u(yyjson_mut_obj_get(o, "acc_time_ns"));
  uint64_t bytes = num_u(yyjson_mut_obj_get(t, "bytes")) + num_u(yyjson_mut_obj_get(o, "bytes"));
  uint64_t mn = num_u(yyjson_mut_obj_get(t, "min_ns")), omin = num_u(yyjson_mut_obj_get(o, "min_ns"));
  uint64_t mx = num_u(yyjson_mut_obj_get(t, "max_ns")), omax = num_u(yyjson_mut_obj_get(o, "max_ns"));
  uint64_t ocount = num_u(yyjson_mut_obj_get(o, "count"));
  if (count == 0) mn = omin;
  if (ocount > 0) mn = mn < omin ? mn : omin;
  mx = mx > omax ? mx : omax;
  yyjson_mut_val *r = yyjson_mut_obj(d);
  yyjson_mut_obj_add_uint(d, r, "count", count);
  yyjson_mut_obj_add_uint(d, r, "acc_time_ns", acc);
  if (mn) yyjson_mut_obj_add_uint(d, r, "min_ns", mn);
  if (mx) yyjson_mut_obj_add_uint(d, r, "max_ns", mx);
  if (bytes) yyjson_mut_obj_add_uint(d, r, "bytes", bytes);
  return r;
}

static void timed_map(yyjson_mut_doc *d, yyjson_mut_val *dst, const char *const *order, yyjson_mut_val *src,
                      const char *key) {
  yyjson_mut_val *sm = yyjson_mut_obj_get(src, key);
  if (!yyjson_mut_is_obj(sm) || !yyjson_mut_obj_size(sm)) return;
  yyjson_mut_val *dm = yyjson_mut_obj_get(dst, key);
  if (!yyjson_mut_is_obj(dm)) set_field(d, dst, order, key, dm = yyjson_mut_obj(d));
  yyjson_mut_obj_iter it = yyjson_mut_obj_iter_with(sm);
  yyjson_mut_val *k;
  while ((k = yyjson_mut_obj_iter_next(&it))) {
    const char *name = yyjson_mut_get_str(k);
    yyjson_mut_val *merged = timed_merge(d, yyjson_mut_obj_get(dm, name), yyjson_mut_obj_iter_get_val(k));
    yyjson_mut_val *nk = yyjson_mut_strcpy(d, name);
    if (!yyjson_mut_obj_replace(dm, nk, merged)) yyjson_mut_obj_add(dm, nk, merged);
  }
}

static void latest(yyjson_mut_doc *d, yyjson_mut_val *dst, yyjson_mut_val *src, const char *key) {
  if (before(yyjson_mut_obj_get(dst, key), yyjson_mut_obj_get(src, key))) copy_key(d, dst, src, key);
}

/* ---- the zero values Merge starts from ---- */

static yyjson_mut_val *zero_of(yyjson_mut_doc *d, const char *type) {
  yyjson_mut_val *o = yyjson_mut_obj(d);
  if (!strcmp(type, "scanner")) {
    yyjson_mut_obj_add_str(d, o, "collected", ZERO_TIME);
    yyjson_mut_obj_add_uint(d, o, "current_cycle", 0);
    yyjson_mut_obj_add_str(d, o, "current_started", ZERO_TIME);
    yyjson_mut_obj_add_null(d, o, "cycle_complete_times");
    yyjson_mut_obj_add_int(d, o, "ongoing_buckets", 0);
    yyjson_mut_obj_add_obj(d, o, "last_minute");
  } else if (!strcmp(type, "disk")) {
    yyjson_mut_obj_add_str(d, o, "collected", ZERO_TIME);
    yyjson_mut_obj_add_int(d, o, "n_disks", 0);
    yyjson_mut_obj_add_obj(d, o, "last_minute");
    yyjson_mut_val *io = yyjson_mut_obj_add_obj(d, o, "iostats");
    for (size_t i = 0; k_iostats[i]; i++) yyjson_mut_obj_add_uint(d, io, k_iostats[i], 0);
  } else if (!strcmp(type, "os")) {
    yyjson_mut_obj_add_str(d, o, "collected", ZERO_TIME);
    yyjson_mut_obj_add_obj(d, o, "last_minute");
  } else if (!strcmp(type, "batchJobs")) {
    yyjson_mut_obj_add_str(d, o, "collected", ZERO_TIME);
    yyjson_mut_obj_add_null(d, o, "Jobs");
  } else if (!strcmp(type, "net")) {
    yyjson_mut_obj_add_str(d, o, "collected", ZERO_TIME);
    yyjson_mut_obj_add_str(d, o, "interfaceName", "");
    yyjson_mut_val *ns = yyjson_mut_obj_add_obj(d, o, "netstats");
    yyjson_mut_obj_add_str(d, ns, "name", "");
    for (size_t i = 0; k_netstats[i]; i++) yyjson_mut_obj_add_uint(d, ns, k_netstats[i], 0);
  } else if (!strcmp(type, "rpc")) {
    for (size_t i = 0; k_rpc_order[i] && strcmp(k_rpc_order[i], "byDestination"); i++) {
      const char *k = k_rpc_order[i];
      if (strstr(k, "Time") || !strcmp(k, "collectedAt")) yyjson_mut_obj_add_str(d, o, k, ZERO_TIME);
      else yyjson_mut_obj_add_uint(d, o, k, 0);
    }
  }
  return o; /* siteResync: replaced wholesale */
}

/* ---- the Merge methods ---- */

static void scanner_merge(yyjson_mut_doc *d, yyjson_mut_val *s, yyjson_mut_val *o) {
  latest(d, s, o, "collected");
  if (num_u(yyjson_mut_obj_get(s, "ongoing_buckets")) < num_u(yyjson_mut_obj_get(o, "ongoing_buckets")))
    copy_key(d, s, o, "ongoing_buckets");
  yyjson_mut_val *opb = yyjson_mut_obj_get(o, "per_bucket_stats");
  if (yyjson_mut_is_obj(opb) && yyjson_mut_obj_size(opb)) {
    yyjson_mut_val *spb = yyjson_mut_obj_get(s, "per_bucket_stats");
    if (!spb) set_field(d, s, k_scanner_order, "per_bucket_stats", spb = yyjson_mut_obj(d));
    yyjson_mut_obj_iter it = yyjson_mut_obj_iter_with(opb);
    yyjson_mut_val *k;
    while ((k = yyjson_mut_obj_iter_next(&it))) {
      yyjson_mut_val *v = yyjson_mut_obj_iter_get_val(k);
      if (!yyjson_mut_arr_size(v) || yyjson_mut_obj_get(spb, yyjson_mut_get_str(k))) continue;
      yyjson_mut_obj_add(spb, yyjson_mut_strcpy(d, yyjson_mut_get_str(k)), yyjson_mut_val_mut_copy(d, v));
    }
  }
  if (num_u(yyjson_mut_obj_get(s, "current_cycle")) < num_u(yyjson_mut_obj_get(o, "current_cycle"))) {
    copy_key(d, s, o, "current_cycle");
    copy_key(d, s, o, "cycle_complete_times");
    copy_key(d, s, o, "current_started");
  }
  if (yyjson_mut_arr_size(yyjson_mut_obj_get(o, "cycle_complete_times")) >
      yyjson_mut_arr_size(yyjson_mut_obj_get(s, "cycle_complete_times")))
    copy_key(d, s, o, "cycle_complete_times");
  sum_map(d, s, k_scanner_order, o, "life_time_ops");
  yyjson_mut_val *slm = yyjson_mut_obj_get(s, "last_minute"), *olm = yyjson_mut_obj_get(o, "last_minute");
  if (olm) timed_map(d, slm, k_scanner_lm_order, olm, "actions");
  sum_map(d, s, k_scanner_order, o, "ilm_ops");
  if (olm) timed_map(d, slm, k_scanner_lm_order, olm, "ilm");
  yyjson_mut_val *oa = yyjson_mut_obj_get(o, "active");
  if (yyjson_mut_arr_size(oa)) {
    yyjson_mut_val *sa = yyjson_mut_obj_get(s, "active");
    if (!sa) set_field(d, s, k_scanner_order, "active", sa = yyjson_mut_arr(d));
    yyjson_mut_arr_iter it = yyjson_mut_arr_iter_with(oa);
    yyjson_mut_val *v;
    while ((v = yyjson_mut_arr_iter_next(&it))) yyjson_mut_arr_append(sa, yyjson_mut_val_mut_copy(d, v));
  }
}

static void disk_merge(yyjson_mut_doc *d, yyjson_mut_val *s, yyjson_mut_val *o) {
  latest(d, s, o, "collected");
  set_u(d, s, "n_disks", num_u(yyjson_mut_obj_get(s, "n_disks")) + num_u(yyjson_mut_obj_get(o, "n_disks")));
  uint64_t off = num_u(yyjson_mut_obj_get(s, "offline")) + num_u(yyjson_mut_obj_get(o, "offline"));
  uint64_t heal = num_u(yyjson_mut_obj_get(s, "healing")) + num_u(yyjson_mut_obj_get(o, "healing"));
  if (off) set_field(d, s, k_disk_order, "offline", yyjson_mut_uint(d, off));
  if (heal) set_field(d, s, k_disk_order, "healing", yyjson_mut_uint(d, heal));
  sum_map(d, s, k_disk_order, o, "life_time_ops");
  yyjson_mut_val *olm = yyjson_mut_obj_get(o, "last_minute");
  static const char *const lm_order[] = {"operations", NULL};
  if (olm) timed_map(d, yyjson_mut_obj_get(s, "last_minute"), lm_order, olm, "operations");
}

static void os_merge(yyjson_mut_doc *d, yyjson_mut_val *s, yyjson_mut_val *o) {
  latest(d, s, o, "collected");
  sum_map(d, s, k_os_order, o, "life_time_ops");
  yyjson_mut_val *olm = yyjson_mut_obj_get(o, "last_minute");
  static const char *const lm_order[] = {"operations", NULL};
  if (olm) timed_map(d, yyjson_mut_obj_get(s, "last_minute"), lm_order, olm, "operations");
}

static void batch_merge(yyjson_mut_doc *d, yyjson_mut_val *s, yyjson_mut_val *o) {
  yyjson_mut_val *oj = yyjson_mut_obj_get(o, "Jobs");
  if (!yyjson_mut_is_obj(oj) || !yyjson_mut_obj_size(oj)) return;
  latest(d, s, o, "collected");
  yyjson_mut_val *sj = yyjson_mut_obj_get(s, "Jobs");
  if (!yyjson_mut_is_obj(sj)) yyjson_mut_obj_replace(s, yyjson_mut_str(d, "Jobs"), sj = yyjson_mut_obj(d));
  yyjson_mut_obj_iter it = yyjson_mut_obj_iter_with(oj);
  yyjson_mut_val *k;
  while ((k = yyjson_mut_obj_iter_next(&it))) {
    yyjson_mut_val *nk = yyjson_mut_strcpy(d, yyjson_mut_get_str(k));
    yyjson_mut_val *v = yyjson_mut_val_mut_copy(d, yyjson_mut_obj_iter_get_val(k));
    if (!yyjson_mut_obj_replace(sj, nk, v)) yyjson_mut_obj_add(sj, nk, v);
  }
}

static void net_merge(yyjson_mut_doc *d, yyjson_mut_val *s, yyjson_mut_val *o) {
  latest(d, s, o, "collected");
  yyjson_mut_val *sn = yyjson_mut_obj_get(s, "netstats"), *on = yyjson_mut_obj_get(o, "netstats");
  for (size_t i = 0; on && k_netstats[i]; i++)
    set_u(d, sn, k_netstats[i], num_u(yyjson_mut_obj_get(sn, k_netstats[i])) + num_u(yyjson_mut_obj_get(on, k_netstats[i])));
}

static void rpc_merge(yyjson_mut_doc *d, yyjson_mut_val *m, yyjson_mut_val *o) {
  latest(d, m, o, "collectedAt");
  latest(d, m, o, "lastConnectTime");
  static const char *const sums[] = {"connected",     "disconnected",     "reconnectCount",   "outgoingStreams",
                                     "incomingStreams", "outgoingBytes",  "incomingBytes",    "outgoingMessages",
                                     "incomingMessages", "outQueue",      NULL};
  for (size_t i = 0; sums[i]; i++)
    set_u(d, m, sums[i], num_u(yyjson_mut_obj_get(m, sums[i])) + num_u(yyjson_mut_obj_get(o, sums[i])));
  if (before(yyjson_mut_obj_get(m, "lastPongTime"), yyjson_mut_obj_get(o, "lastPongTime"))) {
    copy_key(d, m, o, "lastPongTime");
    copy_key(d, m, o, "lastPingMS");
  }
  if (num_f(yyjson_mut_obj_get(m, "maxPingDurMS")) < num_f(yyjson_mut_obj_get(o, "maxPingDurMS")))
    copy_key(d, m, o, "maxPingDurMS");
  static const char *const maps[] = {"byDestination", "byCaller"};
  for (int i = 0; i < 2; i++) {
    yyjson_mut_val *om = yyjson_mut_obj_get(o, maps[i]);
    yyjson_mut_obj_iter it = yyjson_mut_obj_iter_with(om);
    yyjson_mut_val *k;
    while (yyjson_mut_is_obj(om) && (k = yyjson_mut_obj_iter_next(&it))) {
      yyjson_mut_val *mm = yyjson_mut_obj_get(m, maps[i]);
      if (!mm) set_field(d, m, k_rpc_order, maps[i], mm = yyjson_mut_obj(d));
      const char *name = yyjson_mut_get_str(k);
      yyjson_mut_val *ex = yyjson_mut_obj_get(mm, name);
      if (!ex) yyjson_mut_obj_add(mm, yyjson_mut_strcpy(d, name), ex = zero_of(d, "rpc"));
      rpc_merge(d, ex, yyjson_mut_obj_iter_get_val(k));
    }
  }
}

/* Metrics.Merge (no memory, CPU or runtime: madmin leaves them out) */
static void metrics_merge(yyjson_mut_doc *d, yyjson_mut_val *r, yyjson_mut_val *o) {
  static const char *const types[] = {"scanner", "disk", "os", "batchJobs", "siteResync", "net", "rpc"};
  for (size_t i = 0; i < BUCKETS_ARRAY_LEN(types); i++) {
    yyjson_mut_val *ov = yyjson_mut_obj_get(o, types[i]);
    if (!ov || yyjson_mut_is_null(ov)) continue;
    yyjson_mut_val *rv = yyjson_mut_obj_get(r, types[i]);
    if (!rv) set_field(d, r, k_metrics_order, types[i], rv = zero_of(d, types[i]));
    if (!strcmp(types[i], "scanner")) scanner_merge(d, rv, ov);
    else if (!strcmp(types[i], "disk")) disk_merge(d, rv, ov);
    else if (!strcmp(types[i], "os")) os_merge(d, rv, ov);
    else if (!strcmp(types[i], "batchJobs")) batch_merge(d, rv, ov);
    else if (!strcmp(types[i], "siteResync")) {
      if (before(yyjson_mut_obj_get(rv, "collected"), yyjson_mut_obj_get(ov, "collected")))
        yyjson_mut_obj_replace(r, yyjson_mut_str(d, "siteResync"), yyjson_mut_val_mut_copy(d, ov));
    } else if (!strcmp(types[i], "net")) net_merge(d, rv, ov);
    else if (!strcmp(types[i], "rpc")) rpc_merge(d, rv, ov);
  }
}

/* The record being merged (RealtimeMetrics.Merge) */
typedef struct {
  yyjson_mut_doc *d;
  yyjson_mut_val *errors, *hosts, *agg, *by_host, *by_disk;
} rt_rec;

static void rec_init(rt_rec *r) {
  r->d = yyjson_mut_doc_new(NULL);
  r->errors = yyjson_mut_arr(r->d);
  r->hosts = yyjson_mut_arr(r->d);
  r->agg = yyjson_mut_obj(r->d);
  r->by_host = yyjson_mut_obj(r->d);
  r->by_disk = yyjson_mut_obj(r->d);
}

static void copy_entries(yyjson_mut_doc *d, yyjson_mut_val *dst, yyjson_mut_val *src) {
  yyjson_mut_obj_iter it = yyjson_mut_obj_iter_with(src);
  yyjson_mut_val *k;
  while (yyjson_mut_is_obj(src) && (k = yyjson_mut_obj_iter_next(&it))) {
    yyjson_mut_val *nk = yyjson_mut_strcpy(d, yyjson_mut_get_str(k));
    yyjson_mut_val *v = yyjson_mut_val_mut_copy(d, yyjson_mut_obj_iter_get_val(k));
    if (!yyjson_mut_obj_replace(dst, nk, v)) yyjson_mut_obj_add(dst, nk, v);
  }
}

static int cmp_str(const void *a, const void *b) {
  return strcmp(yyjson_mut_get_str(*(yyjson_mut_val *const *)a), yyjson_mut_get_str(*(yyjson_mut_val *const *)b));
}

static void sort_str_arr(yyjson_mut_val *arr) {
  size_t n = yyjson_mut_arr_size(arr);
  if (n < 2) return;
  yyjson_mut_val **v = buckets_xcalloc(n, sizeof(*v));
  for (size_t i = 0; i < n; i++) v[i] = yyjson_mut_arr_get(arr, i);
  qsort(v, n, sizeof(*v), cmp_str);
  yyjson_mut_arr_clear(arr);
  for (size_t i = 0; i < n; i++) yyjson_mut_arr_append(arr, v[i]);
  free(v);
}

static void rec_merge(rt_rec *r, yyjson_mut_val *o) {
  yyjson_mut_doc *d = r->d;
  yyjson_mut_val *oe = yyjson_mut_obj_get(o, "errors"), *v;
  yyjson_mut_arr_iter it = yyjson_mut_arr_iter_with(oe);
  while (yyjson_mut_is_arr(oe) && (v = yyjson_mut_arr_iter_next(&it)))
    yyjson_mut_arr_append(r->errors, yyjson_mut_val_mut_copy(d, v));
  copy_entries(d, r->by_host, yyjson_mut_obj_get(o, "by_host"));
  yyjson_mut_val *oh = yyjson_mut_obj_get(o, "hosts");
  it = yyjson_mut_arr_iter_with(oh);
  while (yyjson_mut_is_arr(oh) && (v = yyjson_mut_arr_iter_next(&it)))
    yyjson_mut_arr_append(r->hosts, yyjson_mut_val_mut_copy(d, v));
  yyjson_mut_val *oa = yyjson_mut_obj_get(o, "aggregated");
  if (oa) metrics_merge(d, r->agg, oa);
  sort_str_arr(r->hosts);
  sort_str_arr(yyjson_mut_obj_get(r->agg, "scanner") ? yyjson_mut_obj_get(yyjson_mut_obj_get(r->agg, "scanner"), "active")
                                                      : NULL);
  copy_entries(d, r->by_disk, yyjson_mut_obj_get(o, "by_disk"));
}

/* Go writes map keys sorted: every map-valued key, recursively */
static bool is_map_key(const char *k) {
  static const char *const maps[] = {"life_time_ops", "ilm_ops", "actions", "ilm",          "operations",
                                     "per_bucket_stats", "by_host", "by_disk", "Jobs",       "byDestination",
                                     "byCaller"};
  for (size_t i = 0; i < BUCKETS_ARRAY_LEN(maps); i++)
    if (!strcmp(k, maps[i])) return true;
  return false;
}

typedef struct {
  yyjson_mut_val *k, *v;
} kvp;

static int cmp_kvp(const void *a, const void *b) {
  return strcmp(yyjson_mut_get_str(((const kvp *)a)->k), yyjson_mut_get_str(((const kvp *)b)->k));
}

static void sort_maps(yyjson_mut_val *v, bool is_map) {
  if (yyjson_mut_is_arr(v)) {
    yyjson_mut_arr_iter it = yyjson_mut_arr_iter_with(v);
    yyjson_mut_val *e;
    while ((e = yyjson_mut_arr_iter_next(&it))) sort_maps(e, false);
    return;
  }
  if (!yyjson_mut_is_obj(v)) return;
  size_t n = yyjson_mut_obj_size(v);
  kvp *p = buckets_xcalloc(n ? n : 1, sizeof(*p));
  yyjson_mut_obj_iter it = yyjson_mut_obj_iter_with(v);
  size_t i = 0;
  yyjson_mut_val *k;
  while ((k = yyjson_mut_obj_iter_next(&it))) p[i].k = k, p[i].v = yyjson_mut_obj_iter_get_val(k), i++;
  for (i = 0; i < n; i++) sort_maps(p[i].v, is_map_key(yyjson_mut_get_str(p[i].k)));
  if (is_map && n > 1) {
    qsort(p, n, sizeof(*p), cmp_kvp);
    yyjson_mut_obj_clear(v);
    for (i = 0; i < n; i++) yyjson_mut_obj_add(v, p[i].k, p[i].v);
  }
  free(p);
}

static void rec_write(rt_rec *r, bool by_host, bool by_disk, bool final, buckets_buf *out) {
  yyjson_mut_doc *d = r->d;
  yyjson_mut_val *root = yyjson_mut_obj(d);
  if (yyjson_mut_arr_size(r->errors)) yyjson_mut_obj_add_val(d, root, "errors", r->errors);
  if (yyjson_mut_arr_size(r->hosts)) yyjson_mut_obj_add_val(d, root, "hosts", r->hosts);
  else yyjson_mut_obj_add_null(d, root, "hosts");
  yyjson_mut_obj_add_val(d, root, "aggregated", r->agg);
  if (by_host && yyjson_mut_obj_size(r->by_host)) yyjson_mut_obj_add_val(d, root, "by_host", r->by_host);
  if (by_disk && yyjson_mut_obj_size(r->by_disk)) yyjson_mut_obj_add_val(d, root, "by_disk", r->by_disk);
  yyjson_mut_obj_add_bool(d, root, "final", final);
  sort_maps(root, false);
  size_t len;
  char *j = yyjson_mut_val_write(root, 0, &len);
  if (j) buckets_buf_append(out, j, len);
  free(j);
  buckets_buf_append_char(out, '\n');
}

/* ---- collectLocalMetrics ---- */

static void add_timed(yyjson_mut_doc *d, yyjson_mut_val *lm, const char *lmkey, const char *name, uint64_t count,
                      uint64_t acc) {
  yyjson_mut_val *ops = yyjson_mut_obj_get(lm, lmkey);
  if (!ops) ops = yyjson_mut_obj_add_obj(d, lm, lmkey);
  yyjson_mut_val *t = yyjson_mut_obj_add_obj(d, ops, name);
  yyjson_mut_obj_add_uint(d, t, "count", count);
  yyjson_mut_obj_add_uint(d, t, "acc_time_ns", acc);
}

/* scannerMetrics.report */
static yyjson_mut_val *local_scanner(yyjson_mut_doc *d, buckets_s3_server *s) {
  buckets_scanner_stats st = {0};
  buckets_scanner *scn = atomic_load(&s->scanner);
  if (scn) buckets_scanner_stats_get(scn, &st);
  char now[64], t[64];
  now_str(now);
  yyjson_mut_val *o = yyjson_mut_obj(d);
  yyjson_mut_obj_add_strcpy(d, o, "collected", now);
  yyjson_mut_obj_add_uint(d, o, "current_cycle", st.have_cycle ? st.current_cycle : 0);
  if (st.have_cycle && st.current_started_ns) {
    buckets_time_rfc3339_nano(st.current_started_ns / 1000000000LL, (long)(st.current_started_ns % 1000000000LL), t);
    yyjson_mut_obj_add_strcpy(d, o, "current_started", t);
  } else {
    yyjson_mut_obj_add_str(d, o, "current_started", ZERO_TIME);
  }
  if (st.have_cycle && st.ncompleted) {
    yyjson_mut_val *a = yyjson_mut_obj_add_arr(d, o, "cycle_complete_times");
    for (size_t i = 0; i < st.ncompleted; i++) {
      buckets_time_rfc3339_nano(st.completed_ns[i] / 1000000000LL, (long)(st.completed_ns[i] % 1000000000LL), t);
      yyjson_mut_arr_add_strcpy(d, a, t);
    }
  } else {
    yyjson_mut_obj_add_null(d, o, "cycle_complete_times");
  }
  yyjson_mut_obj_add_int(d, o, "ongoing_buckets", 0);
  /* our scanner's counts under MinIO's scannerMetric names, sorted */
  struct {
    const char *name;
    uint64_t v;
  } ops[] = {{"HealCheck", st.scanned}, {"SaveUsage", st.usage_saves},    {"ScanBucketDrive", st.bucket_scans_finished},
             {"ScanCycle", st.cycles},  {"ScanFolder", st.folders},      {"ScanObject", st.objects}};
  yyjson_mut_val *lt = NULL;
  for (size_t i = 0; i < BUCKETS_ARRAY_LEN(ops); i++) {
    if (!ops[i].v) continue;
    if (!lt) lt = yyjson_mut_obj_add_obj(d, o, "life_time_ops");
    yyjson_mut_obj_add_uint(d, lt, ops[i].name, ops[i].v);
  }
  yyjson_mut_obj_add_obj(d, o, "last_minute");
  /* getCurrentPaths: pathJoin(node, drive, path) */
  if (st.active[0] && s->layer) {
    const char *drive = NULL;
    for (size_t j = 0; j < s->layer->nall && !drive; j++)
      if (s->layer->all[j] && !s->layer->all[j]->remote) drive = s->layer->all[j]->root;
    buckets_buf p = BUCKETS_BUF_INIT;
    buckets_buf_appendf(&p, "%s/%s/%s", buckets_trace_node(), drive ? drive : "", st.active);
    buckets_buf q = BUCKETS_BUF_INIT;
    for (size_t i = 0; i < p.len; i++)
      if (!(p.data[i] == '/' && q.len && q.data[q.len - 1] == '/')) buckets_buf_append_char(&q, p.data[i]);
    yyjson_mut_val *a = yyjson_mut_obj_add_arr(d, o, "active");
    yyjson_mut_arr_add_strncpy(d, a, q.data, q.len);
    buckets_buf_free(&p);
    buckets_buf_free(&q);
  }
  return o;
}

static yyjson_mut_val *local_os(yyjson_mut_doc *d) {
  buckets_os_stats st;
  buckets_os_stats_get(&st);
  char now[64];
  now_str(now);
  yyjson_mut_val *o = yyjson_mut_obj(d);
  yyjson_mut_obj_add_strcpy(d, o, "collected", now);
  yyjson_mut_val *lt = NULL;
  for (int m = 0; m < BUCKETS_OSM__N; m++) {
    if (!st.total[m]) continue;
    if (!lt) lt = yyjson_mut_obj_add_obj(d, o, "life_time_ops");
    yyjson_mut_obj_add_uint(d, lt, buckets_os_metric_name((buckets_os_metric)m), st.total[m]);
  }
  yyjson_mut_val *lm = yyjson_mut_obj_add_obj(d, o, "last_minute");
  for (int m = 0; m < BUCKETS_OSM__N; m++)
    if (st.count[m]) add_timed(d, lm, "operations", buckets_os_metric_name((buckets_os_metric)m), st.count[m], st.acc_ns[m]);
  return o;
}

/* disk.GetDriveStats: /sys/dev/block/<major>:<minor>/stat */
static void drive_iostats(yyjson_mut_doc *d, yyjson_mut_val *o, const char *path) {
  yyjson_mut_val *io = yyjson_mut_obj_add_obj(d, o, "iostats");
  unsigned long long v[17] = {0};
#ifdef __linux__
  struct stat st;
  if (path && stat(path, &st) == 0) {
    char p[96];
    snprintf(p, sizeof(p), "/sys/dev/block/%u:%u/stat", major(st.st_dev), minor(st.st_dev));
    FILE *f = fopen(p, "r");
    if (f) {
      for (int i = 0; i < 17 && fscanf(f, "%llu", &v[i]) == 1; i++) {
      }
      fclose(f);
    }
  }
#else
  (void)path;
#endif
  for (size_t i = 0; k_iostats[i]; i++) yyjson_mut_obj_add_uint(d, io, k_iostats[i], v[i]);
}

/* collectLocalDisksMetrics, and their aggregate */
static yyjson_mut_val *local_disks(yyjson_mut_doc *d, buckets_s3_server *s, const rt_opts *o, yyjson_mut_val *by_disk) {
  char now[64];
  now_str(now);
  yyjson_mut_val *aggr = zero_of(d, "disk");
  yyjson_mut_obj_replace(aggr, yyjson_mut_str(d, "collected"), yyjson_mut_strcpy(d, now));
  const buckets_cluster_info *ci = s->cluster;
  buckets_objlayer *L = s->layer;
  for (size_t i = 0; ci && L && i < ci->neps; i++) {
    const buckets_info_endpoint *ep = &ci->eps[i];
    if (!ep->local || !in_list(o->disks, ep->endpoint)) continue;
    buckets_drive *drv = NULL;
    for (size_t j = 0; j < L->nall && !drv; j++)
      if (L->all[j] && strcmp(L->all[j]->root, ep->path) == 0) drv = L->all[j];
    struct stat st;
    yyjson_mut_val *dm = yyjson_mut_obj(d);
    if (!drv || stat(ep->path, &st) != 0) {
      yyjson_mut_obj_add_str(d, dm, "collected", ZERO_TIME);
      yyjson_mut_obj_add_int(d, dm, "n_disks", 1);
      yyjson_mut_obj_add_int(d, dm, "offline", 1);
      yyjson_mut_obj_add_obj(d, dm, "last_minute");
      drive_iostats(d, dm, NULL);
    } else {
      yyjson_mut_obj_add_str(d, dm, "collected", ZERO_TIME);
      yyjson_mut_obj_add_int(d, dm, "n_disks", 1);
      char tracker[4096];
      snprintf(tracker, sizeof(tracker), "%s/%s/%s", ep->path, BUCKETS_META_BUCKET, BUCKETS_HEALING_TRACKER);
      struct stat ts;
      if (stat(tracker, &ts) == 0) yyjson_mut_obj_add_int(d, dm, "healing", 1);
      buckets_drive_stats_view sv;
      uint64_t total[BUCKETS_ADMIN_DRIVE_CALLS], count[BUCKETS_ADMIN_DRIVE_CALLS], acc[BUCKETS_ADMIN_DRIVE_CALLS];
      const char *const *names;
      size_t n = buckets_admin_drive_calls(drv, &names, total, count, acc, &sv);
      yyjson_mut_val *lt = NULL;
      for (size_t k = 0; k < n; k++) {
        if (!total[k]) continue;
        if (!lt) lt = yyjson_mut_obj_add_obj(d, dm, "life_time_ops");
        yyjson_mut_obj_add_uint(d, lt, names[k], total[k]);
      }
      yyjson_mut_val *lm = yyjson_mut_obj_add_obj(d, dm, "last_minute");
      for (size_t k = 0; k < n; k++)
        if (count[k]) add_timed(d, lm, "operations", names[k], count[k], acc[k]);
      drive_iostats(d, dm, ep->path);
    }
    yyjson_mut_obj_add(by_disk, yyjson_mut_strcpy(d, ep->endpoint), dm);
    disk_merge(d, aggr, dm);
  }
  return aggr;
}

/* net.GetInterfaceNetStats: /proc/self/net/dev */
static yyjson_mut_val *local_net(yyjson_mut_doc *d, const char *node, yyjson_mut_val *errors) {
  char now[64], iface[64];
  now_str(now);
  buckets_admin_node_interface(node, iface, sizeof(iface));
  yyjson_mut_val *o = zero_of(d, "net");
  yyjson_mut_obj_replace(o, yyjson_mut_str(d, "collected"), yyjson_mut_strcpy(d, now));
  yyjson_mut_obj_replace(o, yyjson_mut_str(d, "interfaceName"), yyjson_mut_strcpy(d, iface));
  char err[256] = "";
#ifdef __linux__
  FILE *f = fopen("/proc/self/net/dev", "r");
  bool found = false;
  if (f) {
    char line[512];
    while (fgets(line, sizeof(line), f)) {
      char *colon = strchr(line, ':');
      if (!colon) continue;
      *colon = '\0';
      char *name = line;
      while (*name == ' ') name++;
      if (strcmp(name, iface) != 0) continue;
      unsigned long long v[16] = {0};
      sscanf(colon + 1, "%llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu", &v[0], &v[1],
             &v[2], &v[3], &v[4], &v[5], &v[6], &v[7], &v[8], &v[9], &v[10], &v[11], &v[12], &v[13], &v[14], &v[15]);
      yyjson_mut_val *ns = yyjson_mut_obj_get(o, "netstats");
      yyjson_mut_obj_replace(ns, yyjson_mut_str(d, "name"), yyjson_mut_strcpy(d, name));
      for (size_t i = 0; k_netstats[i]; i++) set_u(d, ns, k_netstats[i], v[i]);
      found = true;
      break;
    }
    fclose(f);
    if (!found) snprintf(err, sizeof(err), "%s interface not found", iface);
  } else {
    snprintf(err, sizeof(err), "open /proc/self/net/dev: no such file or directory");
  }
#else
  snprintf(err, sizeof(err), "could not read \"/proc\": stat /proc: no such file or directory");
#endif
  if (*err) {
    char msg[512];
    snprintf(msg, sizeof(msg), "%s: %s  (nicstats)", node, err);
    yyjson_mut_arr_add_strcpy(d, errors, msg);
  }
  return o;
}

static yyjson_mut_val *local_cpu(yyjson_mut_doc *d, const char *node, yyjson_mut_val *errors) {
  char now[64];
  now_str(now);
  yyjson_mut_val *o = yyjson_mut_obj(d);
  yyjson_mut_obj_add_strcpy(d, o, "collected", now);
#ifdef __linux__
  /* cpu.Times(false): the first line of /proc/stat, in seconds */
  FILE *f = fopen("/proc/stat", "r");
  unsigned long long v[10] = {0};
  int got = f ? fscanf(f, "cpu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu", &v[0], &v[1], &v[2], &v[3], &v[4],
                       &v[5], &v[6], &v[7], &v[8], &v[9])
              : 0;
  if (f) fclose(f);
  if (got >= 4) {
    double hz = (double)sysconf(_SC_CLK_TCK);
    yyjson_mut_val *t = yyjson_mut_obj_add_obj(d, o, "timesStat");
    yyjson_mut_obj_add_str(d, t, "cpu", "cpu-total");
    static const int idx[] = {0, 2, 3, 1, 4, 5, 6, 7, 8, 9}; /* user system idle nice iowait irq softirq steal guest guestNice */
    static const char *const names[] = {"user", "system", "idle", "nice", "iowait", "irq", "softirq", "steal", "guest",
                                        "guestNice"};
    for (int i = 0; i < 10; i++) yyjson_mut_obj_add_val(d, t, names[i], go_float(d, (double)v[idx[i]] / hz));
  } else {
    yyjson_mut_obj_add_null(d, o, "timesStat");
    char msg[256];
    snprintf(msg, sizeof(msg), "%s: open /proc/stat: no such file or directory (cpuTimes)", node);
    yyjson_mut_arr_add_strcpy(d, errors, msg);
  }
#else
  yyjson_mut_obj_add_null(d, o, "timesStat");
  char msg[256];
  snprintf(msg, sizeof(msg), "%s: not implemented yet (cpuTimes)", node);
  yyjson_mut_arr_add_strcpy(d, errors, msg);
#endif
  double la[3];
  if (getloadavg(la, 3) == 3) {
    yyjson_mut_val *l = yyjson_mut_obj_add_obj(d, o, "loadStat");
    yyjson_mut_obj_add_val(d, l, "load1", go_float(d, la[0]));
    yyjson_mut_obj_add_val(d, l, "load5", go_float(d, la[1]));
    yyjson_mut_obj_add_val(d, l, "load15", go_float(d, la[2]));
  } else {
    yyjson_mut_obj_add_null(d, o, "loadStat");
  }
  long n = sysconf(_SC_NPROCESSORS_ONLN);
  yyjson_mut_obj_add_int(d, o, "cpuCount", n > 0 ? n : 0);
  return o;
}

/* grid.Manager.ConnStats: one connection per peer */
static yyjson_mut_val *local_rpc(yyjson_mut_doc *d, buckets_s3_server *s) {
  yyjson_mut_val *res = zero_of(d, "rpc");
  size_t np = 0;
  buckets_http_client *const *pcs = s->peers ? buckets_peer_clients(s->peers, &np) : NULL;
  uint64_t in_msgs = 0, in_bytes = 0;
  buckets_internode_incoming(&in_msgs, &in_bytes);
  char now[64], t[64];
  now_str(now);
  for (size_t i = 0; i < np; i++) {
    char node[300];
    snprintf(node, sizeof(node), "%s:%d", buckets_http_client_host(pcs[i]), buckets_http_client_port(pcs[i]));
    buckets_http_client_stats cs;
    buckets_http_client_stats_get(pcs[i], &cs);
    bool up = buckets_peer_node_online(s->peers, node);
    yyjson_mut_val *m = yyjson_mut_obj(d);
    yyjson_mut_obj_add_strcpy(d, m, "collectedAt", now);
    yyjson_mut_obj_add_int(d, m, "connected", up);
    yyjson_mut_obj_add_uint(d, m, "reconnectCount", cs.dials > 1 ? cs.dials - 1 : 0);
    yyjson_mut_obj_add_int(d, m, "disconnected", !up);
    yyjson_mut_obj_add_int(d, m, "outgoingStreams", cs.streams > 0 ? cs.streams : 0);
    /* what peers send is not told apart by peer: it goes with the first */
    yyjson_mut_obj_add_int(d, m, "incomingStreams", 0);
    yyjson_mut_obj_add_uint(d, m, "outgoingBytes", cs.sent);
    yyjson_mut_obj_add_uint(d, m, "incomingBytes", cs.received + (i == 0 ? in_bytes : 0));
    yyjson_mut_obj_add_uint(d, m, "outgoingMessages", cs.requests);
    yyjson_mut_obj_add_uint(d, m, "incomingMessages", i == 0 ? in_msgs : 0);
    yyjson_mut_obj_add_int(d, m, "outQueue", 0);
    yyjson_mut_obj_add_str(d, m, "lastPongTime", "1970-01-01T00:00:00Z");
    yyjson_mut_obj_add_uint(d, m, "lastPingMS", 0);
    yyjson_mut_obj_add_uint(d, m, "maxPingDurMS", 0);
    if (cs.last_connect_ns) {
      buckets_time_rfc3339_nano(cs.last_connect_ns / 1000000000LL, (long)(cs.last_connect_ns % 1000000000LL), t);
      yyjson_mut_obj_add_strcpy(d, m, "lastConnectTime", t);
    } else {
      yyjson_mut_obj_add_str(d, m, "lastConnectTime", ZERO_TIME);
    }
    yyjson_mut_val *wrap = yyjson_mut_val_mut_copy(d, m);
    yyjson_mut_val *bd = yyjson_mut_obj_add_obj(d, wrap, "byDestination");
    char remote[320];
    snprintf(remote, sizeof(remote), "%s://%s", s->cluster && s->cluster->secure ? "https" : "http", node);
    yyjson_mut_obj_add(bd, yyjson_mut_strcpy(d, remote), m);
    rpc_merge(d, res, wrap);
  }
  return res;
}

/* collectLocalMetrics, as a RealtimeMetrics value in d */
static yyjson_mut_val *collect_local(yyjson_mut_doc *d, buckets_s3_server *s, const rt_opts *o) {
  yyjson_mut_val *m = yyjson_mut_obj(d);
  if (!o->types) return m;
  const char *node = buckets_trace_node();
  if (o->hosts && *o->hosts && !in_list(o->hosts, node)) return m;
  yyjson_mut_val *errors = yyjson_mut_arr(d), *agg = yyjson_mut_obj(d), *by_disk = NULL;
  if (o->types & MT_DISK) {
    by_disk = yyjson_mut_obj(d);
    yyjson_mut_obj_add_val(d, agg, "disk", local_disks(d, s, o, by_disk));
  }
  if (o->types & MT_SCANNER) set_field(d, agg, k_metrics_order, "scanner", local_scanner(d, s));
  if (o->types & MT_OS) set_field(d, agg, k_metrics_order, "os", local_os(d));
  if (o->types & MT_BATCH) {
    buckets_buf jobs = BUCKETS_BUF_INIT;
    if (s->batch) buckets_batch_metrics_json(s->batch, o->job_id && *o->job_id ? o->job_id : NULL, &jobs);
    yyjson_doc *jd = yyjson_read(jobs.data ? jobs.data : "{}", jobs.data ? jobs.len : 2, YYJSON_READ_NUMBER_AS_RAW);
    char now[64];
    now_str(now);
    yyjson_mut_val *b = yyjson_mut_obj(d);
    yyjson_mut_obj_add_strcpy(d, b, "collected", now);
    yyjson_val *jr = jd ? yyjson_doc_get_root(jd) : NULL;
    yyjson_mut_obj_add_val(d, b, "Jobs", yyjson_is_obj(jr) ? yyjson_val_mut_copy(d, jr) : yyjson_mut_obj(d));
    yyjson_doc_free(jd);
    buckets_buf_free(&jobs);
    set_field(d, agg, k_metrics_order, "batchJobs", b);
  }
  if (o->types & MT_NET) set_field(d, agg, k_metrics_order, "net", local_net(d, node, errors));
  if (o->types & MT_MEM) {
    char now[64];
    now_str(now);
    yyjson_mut_val *mem = yyjson_mut_obj(d);
    yyjson_mut_obj_add_strcpy(d, mem, "collected", now);
    yyjson_mut_obj_add_val(d, mem, "memInfo", buckets_admin_mem_info(d, node));
    set_field(d, agg, k_metrics_order, "mem", mem);
  }
  if (o->types & MT_CPU) set_field(d, agg, k_metrics_order, "cpu", local_cpu(d, node, errors));
  if (o->types & MT_RPC) set_field(d, agg, k_metrics_order, "rpc", local_rpc(d, s));
  if (yyjson_mut_arr_size(errors)) yyjson_mut_obj_add_val(d, m, "errors", errors);
  yyjson_mut_val *hosts = yyjson_mut_obj_add_arr(d, m, "hosts");
  yyjson_mut_arr_add_strcpy(d, hosts, node);
  yyjson_mut_obj_add_val(d, m, "aggregated", agg);
  yyjson_mut_val *bh = yyjson_mut_obj_add_obj(d, m, "by_host");
  yyjson_mut_obj_add(bh, yyjson_mut_strcpy(d, node), yyjson_mut_val_mut_copy(d, agg));
  if (by_disk) yyjson_mut_obj_add_val(d, m, "by_disk", by_disk);
  return m;
}

/* ---- the peers (collectRemoteMetrics) ---- */

typedef struct {
  buckets_s3_server *s;
  const rt_opts *o;
  char node[300];
  buckets_buf body;
  bool ok;
} peer_job;

static void q_append(buckets_buf *t, const char *key, const char *v) {
  if (!v) return;
  buckets_buf_appendf(t, "&%s=", key);
  for (const unsigned char *p = (const unsigned char *)v; *p; p++) {
    if ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') || strchr("-_.~", *p))
      buckets_buf_append_char(t, (char)*p);
    else buckets_buf_appendf(t, "%%%02X", *p);
  }
}

static void *peer_run(void *arg) {
  peer_job *j = arg;
  buckets_buf t = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&t, BUCKETS_INTERNODE_PREFIX "peer/admin?op=rtmetrics&types=%llu", (unsigned long long)j->o->types);
  q_append(&t, "disks", j->o->disks);
  q_append(&t, "by-jobID", j->o->job_id);
  q_append(&t, "by-depID", j->o->dep_id);
  int status = 0;
  j->ok = buckets_peer_call(j->s->peers, j->node, t.data, &status, &j->body) && status == 200;
  buckets_buf_free(&t);
  return NULL;
}

static void collect_remote(rt_rec *r, buckets_s3_server *s, const rt_opts *o) {
  const buckets_cluster_info *ci = s->cluster;
  if (!ci || !ci->distributed || !s->peers) return;
  size_t np = 0;
  buckets_http_client *const *pcs = buckets_peer_clients(s->peers, &np);
  peer_job *jobs = buckets_xcalloc(np ? np : 1, sizeof(*jobs));
  pthread_t *th = buckets_xcalloc(np ? np : 1, sizeof(*th));
  bool *run = buckets_xcalloc(np ? np : 1, sizeof(*run));
  for (size_t i = 0; i < np; i++) {
    jobs[i].s = s, jobs[i].o = o;
    snprintf(jobs[i].node, sizeof(jobs[i].node), "%s:%d", buckets_http_client_host(pcs[i]),
             buckets_http_client_port(pcs[i]));
    if (o->hosts && *o->hosts && !in_list(o->hosts, jobs[i].node)) continue;
    run[i] = pthread_create(&th[i], NULL, peer_run, &jobs[i]) == 0;
  }
  for (size_t i = 0; i < np; i++) {
    if (!run[i]) continue;
    pthread_join(th[i], NULL);
    yyjson_doc *pd = jobs[i].ok ? yyjson_read(jobs[i].body.data ? jobs[i].body.data : "", jobs[i].body.len,
                                              YYJSON_READ_NUMBER_AS_RAW)
                                : NULL;
    yyjson_mut_doc *tmp = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *pm;
    if (pd) {
      pm = yyjson_val_mut_copy(tmp, yyjson_doc_get_root(pd));
    } else {
      /* the RPC error takes the place of the node's metrics */
      pm = yyjson_mut_obj(tmp);
      char msg[512];
      snprintf(msg, sizeof(msg), "%s: %s (rpc)", jobs[i].node,
               *buckets_http_client_dial_error(pcs[i]) ? buckets_http_client_dial_error(pcs[i]) : "peer not reachable");
      yyjson_mut_val *e = yyjson_mut_obj_add_arr(tmp, pm, "errors");
      yyjson_mut_arr_add_strcpy(tmp, e, msg);
    }
    rec_merge(r, pm);
    yyjson_mut_doc_free(tmp);
    yyjson_doc_free(pd);
    buckets_buf_free(&jobs[i].body);
  }
  free(run);
  free(th);
  free(jobs);
}

bool buckets_admin_rtmetrics_peer(buckets_s3_server *s, const char *op, const buckets_query *q,
                                  buckets_http_response *resp) {
  if (strcmp(op, "rtmetrics") != 0) return false;
  rt_opts o = {0};
  const char *tv = buckets_query_get(q, "types");
  o.types = tv ? strtoull(tv, NULL, 10) : 0;
  o.disks = (char *)buckets_query_get(q, "disks");
  o.job_id = (char *)buckets_query_get(q, "by-jobID");
  o.dep_id = (char *)buckets_query_get(q, "by-depID");
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *m = collect_local(d, s, &o);
  size_t len;
  char *j = yyjson_mut_val_write(m, 0, &len);
  if (j) buckets_buf_append(&resp->body, j, len);
  free(j);
  yyjson_mut_doc_free(d);
  resp->status = 200;
  return true;
}

/* ---- the handler ---- */

typedef struct {
  buckets_s3_server *s;
  rt_opts o;
  bool by_host, by_disk;
  int n;
  int64_t interval_ns;
  bool first;
  buckets_buf pending;
  size_t pos;
} mstream;

static void mstream_free(void *ud) {
  mstream *m = ud;
  if (!m) return;
  free(m->o.hosts);
  free(m->o.disks);
  free(m->o.job_id);
  free(m->o.dep_id);
  buckets_buf_free(&m->pending);
  free(m);
}

static void record(mstream *m, buckets_buf *out) {
  rt_rec r;
  rec_init(&r);
  yyjson_mut_doc *ld = yyjson_mut_doc_new(NULL);
  rec_merge(&r, collect_local(ld, m->s, &m->o));
  yyjson_mut_doc_free(ld);
  collect_remote(&r, m->s, &m->o);
  rec_write(&r, m->by_host, m->by_disk, m->n <= 1, out);
  yyjson_mut_doc_free(r.d);
}

static long mstream_read(void *ud, char *buf, size_t cap) {
  mstream *m = ud;
  if (m->pos == m->pending.len) {
    if (m->n <= 0) return 0;
    buckets_buf_reset(&m->pending);
    m->pos = 0;
    if (!m->first) {
      struct timespec ts = {m->interval_ns / 1000000000LL, m->interval_ns % 1000000000LL};
      nanosleep(&ts, NULL);
    }
    m->first = false;
    record(m, &m->pending);
    m->n--;
  }
  size_t k = m->pending.len - m->pos;
  if (k > cap) k = cap;
  memcpy(buf, m->pending.data + m->pos, k);
  m->pos += k;
  return (long)k;
}

static char *dup_opt(s3_ctx *c, const char *key) {
  const char *v = buckets_query_get(&c->q, key);
  return v && *v ? buckets_xstrdup(v) : NULL;
}

void buckets_admin_metrics(s3_ctx *c) {
  if (!buckets_admin_authorize(c, "admin:ServerInfo")) return;
  if (!c->s->layer) {
    buckets_admin_custom_error(c, 503, "XMinioServerNotInitialized",
                               "Server not initialized yet, please try again.");
    return;
  }
  mstream *m = buckets_xcalloc(1, sizeof(*m));
  m->s = c->s;
  m->first = true;
  const char *iv = buckets_query_get(&c->q, "interval");
  int64_t ns = 0;
  if (!iv || !buckets_go_duration_parse(iv, &ns) || ns < 1000000000LL) ns = 1000000000LL;
  m->interval_ns = ns;
  const char *nv = buckets_query_get(&c->q, "n");
  char *end = NULL;
  long n = nv ? strtol(nv, &end, 10) : 0;
  m->n = nv && *nv && end && !*end && n > 0 && n <= INT_MAX ? (int)n : INT_MAX;
  const char *tv = buckets_query_get(&c->q, "types");
  uint64_t types = tv ? strtoull(tv, NULL, 10) : 0;
  m->o.types = types ? types : MT_ALL;
  m->o.hosts = dup_opt(c, "hosts");
  m->o.disks = dup_opt(c, "disks");
  m->o.job_id = dup_opt(c, "by-jobID");
  m->o.dep_id = dup_opt(c, "by-depID");
  const char *bh = buckets_query_get(&c->q, "by-host"), *bd = buckets_query_get(&c->q, "by-disk");
  m->by_host = bh && strcasecmp(bh, "true") == 0;
  m->by_disk = bd && strcasecmp(bd, "true") == 0;
  buckets_http_resp_header(c->resp, "Content-Type", "application/json");
  c->resp->status = 200;
  c->resp->chunked = true;
  c->resp->stream = mstream_read;
  c->resp->stream_ud = m;
  c->resp->stream_free = mstream_free;
}
