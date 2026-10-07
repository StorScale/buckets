/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "scanner/scanner.h"
#include "scanner/compliance.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "core/common.h"
#include "core/log.h"
#include "object/sysconfig.h"
#include "scanner/scantrace.h"
#include "scanner/usage.h"

#define BLOOM_CYCLE_PATH "buckets/.bloomcycle.bin" /* dataUsageBloomNamePath: the next cycle */
#define LIST_PAGE 1000

struct buckets_scanner {
  buckets_objlayer *L;
  buckets_scanner_hooks hooks;
  pthread_t thread;
  pthread_mutex_t mu;
  pthread_cond_t cv;
  bool stop;
  int fixed_interval; /* BUCKETS_SCANNER_INTERVAL, or -1 */
  uint64_t next_cycle;
  unsigned saves;
  buckets_scanner_stats st;
  buckets_scantrace *trace;
  bool tracing; /* the bucket being walked is traced */
  buckets_data_usage *usage; /* the leader's cycle's usage */
  char **tiers;              /* the remote tiers this cycle (tierStats wanted when any) */
  size_t ntiers;
  buckets_compliance_counts *compliance; /* the leader's counts for the bucket being scanned */
};

static int64_t now_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static bool stopping(buckets_scanner *s) {
  pthread_mutex_lock(&s->mu);
  bool stop = s->stop;
  pthread_mutex_unlock(&s->mu);
  return stop;
}

/* Sleeps up to seconds, waking early on stop. Returns false when stopping. */
static bool nap(buckets_scanner *s, int seconds) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  ts.tv_sec += seconds;
  pthread_mutex_lock(&s->mu);
  while (!s->stop && pthread_cond_timedwait(&s->cv, &s->mu, &ts) == 0) {
  }
  bool go = !s->stop;
  pthread_mutex_unlock(&s->mu);
  return go;
}

static bool leads(buckets_objlayer *L, const char *object) {
  for (size_t p = 0; p < L->npools; p++) {
    if (buckets_objlayer_set_is_led_here(L, p, buckets_objlayer_object_set(L, p, object))) return true;
  }
  return false;
}

static void heal_object(buckets_scanner *s, const char *bucket, const char *object) {
  buckets_heal_opts opts = {.remove_dangling = true, .scan_mode = 1, .quiet_clean = true};
  buckets_heal_result r;
  bool healed = buckets_obj_heal(s->L, bucket, object, NULL, &opts, &r) == BUCKETS_OBJ_OK && r.healed;
  if (healed) buckets_log_info("scanner healed %s/%s on %zu drive%s", bucket, object, r.healed, r.healed == 1 ? "" : "s");
  pthread_mutex_lock(&s->mu);
  s->st.scanned++;
  s->st.healed += healed;
  pthread_mutex_unlock(&s->mu);
}

/* A non-leader's bucket: heal what this node leads. */
static void heal_bucket(buckets_scanner *s, const char *bucket) {
  char *marker = NULL;
  for (;;) {
    buckets_obj_listing l;
    if (stopping(s) || buckets_obj_list(s->L, bucket, "", marker, NULL, LIST_PAGE, &l) != BUCKETS_OBJ_OK) break;
    for (size_t i = 0; i < l.nobjects && !stopping(s); i++) {
      pthread_mutex_lock(&s->mu);
      snprintf(s->st.active, sizeof(s->st.active), "%s/%s", bucket, l.objects[i].name);
      pthread_mutex_unlock(&s->mu);
      if (leads(s->L, l.objects[i].name)) heal_object(s, bucket, l.objects[i].name);
    }
    free(marker);
    marker = l.truncated && l.next_marker ? buckets_xstrdup(l.next_marker) : NULL;
    buckets_obj_list_free(&l);
    if (!marker) break;
  }
  free(marker);
}

/* The versions of one key: lifecycle, healing, then usage. */
/* sizeSummary.tiers: every version but delete markers, under its remote tier
 * or storage class, counted only for the tiers configured when the cycle
 * began (and STANDARD and RRS). */
static void tier_usage(buckets_scanner *s, const buckets_object_info *v) {
  if (!s->ntiers || !s->usage || v->delete_marker) return;
  const char *tier = buckets_object_tier(v, NULL, NULL);
  if (!tier) tier = buckets_object_meta(v, "x-amz-storage-class");
  if (!tier || !*tier) tier = "STANDARD";
  bool known = !strcmp(tier, "STANDARD") || !strcmp(tier, "REDUCED_REDUNDANCY");
  for (size_t i = 0; i < s->ntiers && !known; i++) known = !strcmp(s->tiers[i], tier);
  if (!known) return;
  buckets_tier_usage *t = buckets_data_usage_tier(s->usage, tier, true);
  t->size += v->size > 0 ? (uint64_t)v->size : 0;
  t->versions++;
  t->objects += v->is_latest;
}

static void scan_key(buckets_scanner *s, const char *bucket, buckets_object_info *v, size_t n, buckets_bucket_usage *bu) {
  int64_t start = now_ns();
  uint64_t trace_size = 0, trace_versions = 0; /* sizeSummary: stored sizes; versions as MinIO counts them */
  pthread_mutex_lock(&s->mu);
  s->st.objects++;
  s->st.versions += n;
  snprintf(s->st.active, sizeof(s->st.active), "%s/%s", bucket, v[0].name);
  pthread_mutex_unlock(&s->mu);
  bool *removed = buckets_xcalloc(n, sizeof(bool));
  if (s->hooks.object) s->hooks.object(s->hooks.ud, bucket, v, n, removed);
  bool present = false;
  for (size_t i = 0; i < n; i++) present |= !removed[i];
  if (present && leads(s->L, v[0].name)) heal_object(s, bucket, v[0].name);
  if (present) {
    bool versioned = s->hooks.versioned && s->hooks.versioned(s->hooks.ud, bucket, v[0].name);
    uint64_t size = 0, versions = 0, markers = 0;
    for (size_t i = 0; i < n; i++) {
      if (removed[i]) continue;
      if (!v[i].delete_marker) {
        int64_t sz = s->hooks.actual_size ? s->hooks.actual_size(s->hooks.ud, &v[i]) : v[i].size;
        if (sz > 0) size += (uint64_t)sz;
      }
      markers += v[i].delete_marker;
      tier_usage(s, &v[i]);
      if (s->compliance) {
        int64_t csz = s->hooks.actual_size ? s->hooks.actual_size(s->hooks.ud, &v[i]) : v[i].size;
        buckets_compliance_add(s->compliance, &v[i], csz, now_ns() / 1000000000LL);
      }
      /* ToObjectInfo leaves VersionID empty for a null version when the
       * bucket is not versioned; those are not counted as versions. */
      bool has_id = versioned || strcmp(v[i].version_id, "null") != 0;
      versions += has_id;
      if (s->tracing) {
        int64_t stored = v[i].delete_marker ? 0 : v[i].size;
        int64_t actual = v[i].delete_marker ? 0 : s->hooks.actual_size ? s->hooks.actual_size(s->hooks.ud, &v[i]) : v[i].size;
        trace_size += stored > 0 ? (uint64_t)stored : 0;
        trace_versions += has_id && stored == actual;
      }
    }
    buckets_bucket_usage_add_object(bu, size, versions, markers);
    if (s->ntiers && s->usage) { /* every object's summary carries the configured tiers */
      for (size_t i = 0; i < s->ntiers; i++) buckets_data_usage_tier(s->usage, s->tiers[i], true);
      buckets_data_usage_tier(s->usage, "STANDARD", true);
      buckets_data_usage_tier(s->usage, "REDUCED_REDUNDANCY", true);
    }
  }
  if (s->tracing) buckets_scantrace_key(s->trace, v[0].name, start, trace_size, trace_versions);
  free(removed);
}

/* The leader's bucket: every version, grouped by key. */
static bool usage_bucket(buckets_scanner *s, const char *bucket, buckets_bucket_usage *bu) {
  s->tracing = buckets_scantrace_bucket_begin(s->trace, s->L, bucket);
  char *key_marker = NULL, *ver_marker = NULL;
  buckets_object_info *group = NULL;
  size_t ng = 0, cap = 0;
  bool ok = true;
  for (;;) {
    buckets_obj_listing l;
    if (stopping(s)) {
      ok = false;
      break;
    }
    if (buckets_obj_list_versions_all(s->L, bucket, "", key_marker, ver_marker, LIST_PAGE, &l) != BUCKETS_OBJ_OK) {
      ok = false;
      break;
    }
    for (size_t i = 0; i < l.nobjects; i++) {
      if (l.objects[i].free_version) { /* not counted: swept */
        if (s->hooks.free_version) s->hooks.free_version(s->hooks.ud, bucket, &l.objects[i]);
        continue;
      }
      if (ng && strcmp(group[0].name, l.objects[i].name) != 0) {
        scan_key(s, bucket, group, ng, bu);
        for (size_t j = 0; j < ng; j++) buckets_object_info_free(&group[j]);
        ng = 0;
      }
      if (ng == cap) {
        cap = cap ? cap * 2 : 8;
        group = buckets_xrealloc(group, cap * sizeof(*group));
      }
      group[ng++] = l.objects[i]; /* taken over */
      memset(&l.objects[i], 0, sizeof(l.objects[i]));
    }
    free(key_marker);
    free(ver_marker);
    key_marker = l.truncated && l.next_marker ? buckets_xstrdup(l.next_marker) : NULL;
    ver_marker = l.truncated && l.next_version_marker ? buckets_xstrdup(l.next_version_marker) : NULL;
    buckets_obj_list_free(&l);
    if (!key_marker) break;
  }
  if (ok && ng) scan_key(s, bucket, group, ng, bu);
  if (s->tracing) buckets_scantrace_bucket_end(s->trace);
  s->tracing = false;
  for (size_t j = 0; j < ng; j++) buckets_object_info_free(&group[j]);
  free(group);
  free(key_marker);
  free(ver_marker);
  return ok;
}

static void save_usage(buckets_scanner *s, buckets_data_usage *u) {
  buckets_buf j = BUCKETS_BUF_INIT;
  buckets_data_usage_json(u, &j);
  /* storeDataUsageInBackend: a backup every tenth time */
  if (++s->saves % 10 == 0) buckets_sysconfig_write(s->L, BUCKETS_USAGE_PATH ".bkp", j.data, j.len);
  buckets_obj_err err = buckets_sysconfig_write(s->L, BUCKETS_USAGE_PATH, j.data, j.len);
  if (err) buckets_log_warn("scanner: storing data usage: %s", buckets_obj_strerror(err));
  buckets_buf_free(&j);
  pthread_mutex_lock(&s->mu);
  s->st.usage_saves += !err;
  pthread_mutex_unlock(&s->mu);
}

/* The compliance reports' counts, stored apart from MinIO's data usage (scanner/compliance.h). */
static void save_compliance(buckets_scanner *s, const buckets_compliance_bucket *cb, size_t n) {
  buckets_buf j = BUCKETS_BUF_INIT;
  buckets_compliance_json(cb, n, now_ns() / 1000000000LL, &j);
  buckets_obj_err err = buckets_sysconfig_write(s->L, BUCKETS_COMPLIANCE_PATH, j.data, j.len);
  if (err) buckets_log_warn("scanner: storing the compliance counts: %s", buckets_obj_strerror(err));
  buckets_buf_free(&j);
}

static void save_cycle(buckets_scanner *s) {
  uint8_t b[8];
  for (int i = 0; i < 8; i++) b[i] = (uint8_t)(s->next_cycle >> (8 * i));
  buckets_sysconfig_write(s->L, BLOOM_CYCLE_PATH, b, sizeof(b));
}

static void scan_cycle(buckets_scanner *s) {
  int64_t start = now_ns();
  buckets_objlayer *L = s->L;
  bool leader = buckets_objlayer_set_is_led_here(L, 0, 0);
  buckets_bucket_info *bk = NULL;
  size_t nb = 0;
  if (buckets_obj_list_buckets(L, &bk, &nb) != BUCKETS_OBJ_OK) return;
  buckets_data_usage u = {0};
  bool complete = true;
  buckets_compliance_bucket *cb = leader ? buckets_xcalloc(nb + 1, sizeof(*cb)) : NULL;
  if (leader && s->hooks.tier_names) s->ntiers = s->hooks.tier_names(s->hooks.ud, &s->tiers);
  s->usage = leader ? &u : NULL;
  if (leader) {
    pthread_mutex_lock(&s->mu);
    s->st.have_cycle = true;
    s->st.current_cycle = s->next_cycle;
    s->st.current_started_ns = start;
    pthread_mutex_unlock(&s->mu);
  }
  for (size_t b = 0; b < nb && !stopping(s); b++) {
    buckets_obj_heal_bucket(L, bk[b].name);
    buckets_buf meta = BUCKETS_BUF_INIT;
    buckets_buf_appendf(&meta, "buckets/%s/.metadata.bin", bk[b].name);
    if (leads(L, meta.data)) heal_object(s, BUCKETS_META_BUCKET, meta.data);
    buckets_buf_free(&meta);
    pthread_mutex_lock(&s->mu);
    s->st.bucket_scans_started++;
    s->st.folders++;
    pthread_mutex_unlock(&s->mu);
    bool done = true;
    if (leader) {
      cb[b].name = buckets_xstrdup(bk[b].name);
      s->compliance = &cb[b].c;
      done = usage_bucket(s, bk[b].name, buckets_data_usage_add_bucket(&u, bk[b].name));
      s->compliance = NULL;
    }
    else heal_bucket(s, bk[b].name);
    complete &= done;
    pthread_mutex_lock(&s->mu);
    s->st.bucket_scans_finished += done;
    s->st.active[0] = '\0';
    pthread_mutex_unlock(&s->mu);
  }
  complete &= !stopping(s);
  if (leader) {
    buckets_scantrace_cycle(s->next_cycle, start);
    buckets_scantrace_cycle_done(s->trace);
  }
  if (leader && complete) {
    buckets_data_usage_total(&u);
    u.last_update_ns = now_ns();
    save_usage(s, &u);
    save_compliance(s, cb, nb);
    s->next_cycle++;
    pthread_mutex_lock(&s->mu);
    s->st.current_cycle = 0;
    if (s->st.ncompleted == 16) {
      memmove(s->st.completed_ns, s->st.completed_ns + 1, 15 * sizeof(int64_t));
      s->st.ncompleted--;
    }
    s->st.completed_ns[s->st.ncompleted++] = now_ns();
    pthread_mutex_unlock(&s->mu);
    save_cycle(s);
  }
  s->usage = NULL;
  for (size_t i = 0; i < s->ntiers; i++) free(s->tiers[i]);
  free(s->tiers);
  s->tiers = NULL;
  s->ntiers = 0;
  buckets_data_usage_free(&u);
  for (size_t i = 0; cb && i < nb; i++) free(cb[i].name);
  free(cb);
  buckets_bucket_info_free(bk, nb);
  pthread_mutex_lock(&s->mu);
  if (complete) s->st.cycles++;
  s->st.last_activity_ns = now_ns();
  pthread_mutex_unlock(&s->mu);
}

static int cycle_seconds(buckets_scanner *s) {
  if (s->fixed_interval >= 0) return s->fixed_interval;
  int c = s->hooks.cycle_seconds ? s->hooks.cycle_seconds(s->hooks.ud) : 60;
  return c > 0 ? c : 60;
}

static void *run(void *arg) {
  buckets_scanner *s = arg;
  buckets_buf b = BUCKETS_BUF_INIT;
  if (buckets_sysconfig_read(s->L, BLOOM_CYCLE_PATH, &b, NULL) == BUCKETS_OBJ_OK && b.len >= 8) {
    for (int i = 7; i >= 0; i--) s->next_cycle = s->next_cycle << 8 | (uint8_t)b.data[i];
  }
  buckets_buf_free(&b);
  while (nap(s, cycle_seconds(s))) scan_cycle(s);
  return NULL;
}

buckets_scanner *buckets_scanner_start(buckets_objlayer *L, const buckets_scanner_hooks *hooks) {
  const char *iv = getenv("BUCKETS_SCANNER_INTERVAL");
  int fixed = iv ? atoi(iv) : -1;
  if (fixed == 0) return NULL; /* disabled */
  buckets_scanner *s = buckets_xcalloc(1, sizeof(*s));
  s->trace = buckets_scantrace_new();
  s->L = L;
  if (hooks) s->hooks = *hooks;
  s->fixed_interval = fixed;
  pthread_mutex_init(&s->mu, NULL);
  pthread_cond_init(&s->cv, NULL);
  if (pthread_create(&s->thread, NULL, run, s) != 0) buckets_fatal("start scanner thread");
  return s;
}

void buckets_scanner_stop(buckets_scanner *s) {
  if (!s) return;
  pthread_mutex_lock(&s->mu);
  s->stop = true;
  pthread_cond_broadcast(&s->cv);
  pthread_mutex_unlock(&s->mu);
  pthread_join(s->thread, NULL);
  pthread_cond_destroy(&s->cv);
  pthread_mutex_destroy(&s->mu);
  buckets_scantrace_free(s->trace);
  free(s);
}

void buckets_scanner_stats_get(buckets_scanner *s, buckets_scanner_stats *out) {
  memset(out, 0, sizeof(*out));
  if (!s) return;
  pthread_mutex_lock(&s->mu);
  *out = s->st;
  pthread_mutex_unlock(&s->mu);
}
