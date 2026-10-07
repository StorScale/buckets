/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "usage/store.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/common.h"
#include "core/log.h"
#include "object/sysconfig.h"

/* traffic-<server>.json, with the server's name made safe for a file name */
static void traffic_path(const char *day, const char *server, buckets_buf *p) {
  buckets_buf_appendf(p, BUCKETS_USAGE_DIR "%s/traffic-", day);
  for (const char *c = *server ? server : "server"; *c; c++) {
    bool ok = (*c >= 'a' && *c <= 'z') || (*c >= 'A' && *c <= 'Z') || (*c >= '0' && *c <= '9') || *c == '.' ||
              *c == '-';
    buckets_buf_append_char(p, ok ? *c : '_');
  }
  buckets_buf_append_c(p, ".json");
}

buckets_obj_err buckets_usage_store_traffic(buckets_objlayer *L, const char *server,
                                            const buckets_usage_traffic_add *add, size_t n) {
  if (!n) return BUCKETS_OBJ_OK;
  char day[11];
  buckets_usage_today(day);
  buckets_buf p = BUCKETS_BUF_INIT, old = BUCKETS_BUF_INIT, out = BUCKETS_BUF_INIT;
  traffic_path(day, server, &p);
  buckets_sysconfig_read(L, p.data, &old, NULL); /* none yet: a new record */
  buckets_usage_traffic_merge(old.data, old.len, add, n, &out);
  buckets_obj_err err = buckets_sysconfig_write(L, p.data, out.data, out.len);
  buckets_buf_free(&p);
  buckets_buf_free(&old);
  buckets_buf_free(&out);
  return err;
}

void buckets_usage_store_sample(buckets_objlayer *L, const buckets_data_usage *u) {
  char day[11];
  buckets_usage_today(day);
  buckets_usage_sample *s = buckets_xcalloc(u->nbuckets ? u->nbuckets : 1, sizeof(*s));
  for (size_t i = 0; i < u->nbuckets; i++)
    s[i] = (buckets_usage_sample){u->buckets[i].name, u->buckets[i].size};
  buckets_buf p = BUCKETS_BUF_INIT, old = BUCKETS_BUF_INIT, out = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&p, BUCKETS_USAGE_DIR "%s/storage.json", day);
  buckets_sysconfig_read(L, p.data, &old, NULL);
  buckets_usage_storage_merge(old.data, old.len, s, u->nbuckets, &out);
  buckets_obj_err err = buckets_sysconfig_write(L, p.data, out.data, out.len);
  if (err) buckets_log_warn("usage: storing the day's sizes: %s", buckets_obj_strerror(err));
  buckets_buf_free(&p);
  buckets_buf_free(&old);
  buckets_buf_free(&out);
  free(s);
  buckets_usage_store_prune(L);
}

void buckets_usage_store_prune(buckets_objlayer *L) {
  char today[11], keep[11];
  buckets_usage_today(today);
  buckets_usage_keep_from(today, buckets_usage_history_days(), keep);
  char **days = NULL;
  size_t nd = 0;
  if (buckets_sysconfig_list(L, BUCKETS_USAGE_DIR, true, &days, &nd) != BUCKETS_OBJ_OK) return;
  for (size_t i = 0; i < nd; i++) {
    int64_t t;
    if (!buckets_usage_day_parse(days[i], &t) || strcmp(days[i], keep) >= 0) continue;
    buckets_buf prefix = BUCKETS_BUF_INIT;
    buckets_buf_appendf(&prefix, BUCKETS_USAGE_DIR "%s/", days[i]);
    char **files = NULL;
    size_t nf = 0;
    if (buckets_sysconfig_list(L, prefix.data, false, &files, &nf) == BUCKETS_OBJ_OK) {
      for (size_t f = 0; f < nf; f++) {
        buckets_buf p = BUCKETS_BUF_INIT;
        buckets_buf_appendf(&p, "%s%s", prefix.data, files[f]);
        buckets_sysconfig_delete(L, p.data);
        buckets_buf_free(&p);
      }
      buckets_sysconfig_names_free(files, nf);
    }
    buckets_buf_free(&prefix);
  }
  buckets_sysconfig_names_free(days, nd);
}

static bool src_storage(void *ud, const char *day, buckets_buf *out) {
  buckets_buf p = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&p, BUCKETS_USAGE_DIR "%s/storage.json", day);
  bool ok = buckets_sysconfig_read(ud, p.data, out, NULL) == BUCKETS_OBJ_OK;
  buckets_buf_free(&p);
  return ok;
}

static size_t src_traffic(void *ud, const char *day, buckets_buf **out) {
  buckets_buf prefix = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&prefix, BUCKETS_USAGE_DIR "%s/", day);
  char **files = NULL;
  size_t nf = 0, n = 0;
  if (buckets_sysconfig_list(ud, prefix.data, false, &files, &nf) == BUCKETS_OBJ_OK) {
    for (size_t f = 0; f < nf; f++) {
      if (strncmp(files[f], "traffic-", 8) != 0) continue;
      buckets_buf p = BUCKETS_BUF_INIT, b = BUCKETS_BUF_INIT;
      buckets_buf_appendf(&p, "%s%s", prefix.data, files[f]);
      if (buckets_sysconfig_read(ud, p.data, &b, NULL) == BUCKETS_OBJ_OK) {
        *out = buckets_xrealloc(*out, (n + 1) * sizeof(buckets_buf));
        (*out)[n++] = b;
      } else
        buckets_buf_free(&b);
      buckets_buf_free(&p);
    }
    buckets_sysconfig_names_free(files, nf);
  }
  buckets_buf_free(&prefix);
  return n;
}

buckets_usage_source buckets_usage_store_source(buckets_objlayer *L) {
  return (buckets_usage_source){src_storage, src_traffic, L};
}
