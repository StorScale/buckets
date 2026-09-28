/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "storage/format.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <yyjson.h>

#include "core/log.h"
#include "storage/xlmeta.h"

#define FORMAT_PATH "format.json"

typedef struct {
  bool present, valid;
  char id[BUCKETS_UUID_STR_LEN + 1];
  char this_id[BUCKETS_UUID_STR_LEN + 1];
  char format[16];
  char **sets; /* flattened uuids */
  size_t nsets, set_size;
} fmt;

static void fmt_free(fmt *f) {
  for (size_t i = 0; i < f->nsets * f->set_size; i++) free(f->sets[i]);
  free(f->sets);
  memset(f, 0, sizeof(*f));
}

static void read_fmt(buckets_drive *d, fmt *f) {
  memset(f, 0, sizeof(*f));
  buckets_buf raw = BUCKETS_BUF_INIT;
  if (buckets_drive_read_all(d, BUCKETS_META_BUCKET, FORMAT_PATH, &raw) != BUCKETS_DRIVE_OK) {
    buckets_buf_free(&raw);
    return;
  }
  f->present = true;
  yyjson_doc *doc = yyjson_read(raw.data, raw.len, 0);
  buckets_buf_free(&raw);
  if (!doc) return;
  yyjson_val *root = yyjson_doc_get_root(doc), *xl = yyjson_obj_get(root, "xl");
  const char *ver = yyjson_get_str(yyjson_obj_get(root, "version"));
  const char *format = yyjson_get_str(yyjson_obj_get(root, "format"));
  const char *id = yyjson_get_str(yyjson_obj_get(root, "id"));
  const char *this_id = yyjson_get_str(yyjson_obj_get(xl, "this"));
  yyjson_val *sets = yyjson_obj_get(xl, "sets");
  if (ver && strcmp(ver, "1") == 0 && format && id && this_id && strlen(id) == 36 && strlen(this_id) == 36 &&
      yyjson_is_arr(sets) && yyjson_arr_size(sets) > 0 && strlen(format) < sizeof(f->format)) {
    f->nsets = yyjson_arr_size(sets);
    f->set_size = yyjson_arr_size(yyjson_arr_get(sets, 0));
    f->sets = buckets_xcalloc(f->nsets * f->set_size ? f->nsets * f->set_size : 1, sizeof(char *));
    bool ok = f->set_size > 0;
    size_t si, smax;
    yyjson_val *set;
    yyjson_arr_foreach(sets, si, smax, set) {
      if (!yyjson_is_arr(set) || yyjson_arr_size(set) != f->set_size) {
        ok = false;
        break;
      }
      for (size_t j = 0; j < f->set_size; j++) {
        const char *u = yyjson_get_str(yyjson_arr_get(set, j));
        if (!u || strlen(u) != 36) ok = false;
        else f->sets[si * f->set_size + j] = buckets_xstrdup(u);
      }
    }
    if (ok) {
      memcpy(f->id, id, 37);
      memcpy(f->this_id, this_id, 37);
      strcpy(f->format, format);
      f->valid = true;
    }
  }
  yyjson_doc_free(doc);
  if (!f->valid) fmt_free(f), f->present = true;
}

static bool write_fmt(buckets_drive *d, const char *format, const char *id, const char *this_id, char *const *sets,
                      size_t nsets, size_t set_size) {
  yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(doc);
  yyjson_mut_doc_set_root(doc, root);
  yyjson_mut_obj_add_str(doc, root, "version", "1");
  yyjson_mut_obj_add_str(doc, root, "format", format);
  yyjson_mut_obj_add_str(doc, root, "id", id);
  yyjson_mut_val *xl = yyjson_mut_obj_add_obj(doc, root, "xl");
  yyjson_mut_obj_add_str(doc, xl, "version", "3");
  yyjson_mut_obj_add_str(doc, xl, "this", this_id);
  yyjson_mut_val *arr = yyjson_mut_obj_add_arr(doc, xl, "sets");
  for (size_t s = 0; s < nsets; s++) {
    yyjson_mut_val *set = yyjson_mut_arr_add_arr(doc, arr);
    for (size_t j = 0; j < set_size; j++) yyjson_mut_arr_add_str(doc, set, sets[s * set_size + j]);
  }
  yyjson_mut_obj_add_str(doc, xl, "distributionAlgo", "SIPMOD+PARITY");
  size_t len;
  char *json = yyjson_mut_write(doc, 0, &len);
  yyjson_mut_doc_free(doc);
  bool ok = json && buckets_drive_write_all(d, BUCKETS_META_BUCKET, FORMAT_PATH, json, len) == BUCKETS_DRIVE_OK;
  free(json);
  return ok;
}

void buckets_format_result_free(buckets_format_result *r) {
  for (size_t i = 0; r->slots && i < r->nsets * r->set_size; i++) buckets_drive_close(r->slots[i]);
  free(r->slots);
  memset(r, 0, sizeof(*r));
}

static bool same_layout(const fmt *a, const fmt *b) {
  if (strcmp(a->id, b->id) || a->nsets != b->nsets || a->set_size != b->set_size || strcmp(a->format, b->format)) {
    return false;
  }
  for (size_t i = 0; i < a->nsets * a->set_size; i++) {
    if (strcmp(a->sets[i], b->sets[i])) return false;
  }
  return true;
}

bool buckets_format_negotiate(buckets_drive **drives, size_t n, size_t set_size, buckets_format_result *out,
                              char *err, size_t errlen) {
  memset(out, 0, sizeof(*out));
  if (set_size == 0 || n % set_size) {
    snprintf(err, errlen, "%zu drives cannot form sets of %zu", n, set_size);
    return false;
  }
  size_t nsets = n / set_size;
  fmt *f = buckets_xcalloc(n, sizeof(fmt));
  size_t online = 0, unformatted = 0;
  for (size_t i = 0; i < n; i++) {
    if (!drives[i]) continue;
    online++;
    read_fmt(drives[i], &f[i]);
    if (!f[i].present) unformatted++;
  }
  bool ok = true;
  const char *format_name = n == 1 ? "xl-single" : "xl";

  if (online == 0) {
    snprintf(err, errlen, "no drives are online");
    ok = false;
  } else if (unformatted == n) {
    /* Fresh deployment: every drive gets a UUID; sets follow command-line order. */
    char dep[BUCKETS_UUID_STR_LEN + 1];
    buckets_uuid_v4(dep);
    char **ids = buckets_xcalloc(n, sizeof(char *));
    for (size_t i = 0; i < n; i++) {
      ids[i] = buckets_xmalloc(BUCKETS_UUID_STR_LEN + 1);
      buckets_uuid_v4(ids[i]);
    }
    for (size_t i = 0; i < n && ok; i++) {
      if (!write_fmt(drives[i], format_name, dep, ids[i], ids, nsets, set_size)) {
        snprintf(err, errlen, "cannot write format.json to %s", drives[i]->root);
        ok = false;
      } else {
        memcpy(drives[i]->deployment_id, dep, 37);
        memcpy(drives[i]->drive_id, ids[i], 37);
        drives[i]->freshly_formatted = true;
      }
    }
    for (size_t i = 0; i < n; i++) free(ids[i]);
    free(ids);
    if (ok) {
      memcpy(out->deployment_id, dep, 37);
      out->formatted_fresh = n;
      out->nsets = nsets;
      out->set_size = set_size;
      out->slots = buckets_xcalloc(n, sizeof(buckets_drive *));
      for (size_t i = 0; i < n; i++) out->slots[i] = drives[i], drives[i] = NULL;
    }
  } else {
    /* Reference format: the most common valid layout among online drives. */
    size_t best = n, best_votes = 0;
    for (size_t i = 0; i < n; i++) {
      if (!f[i].valid) continue;
      size_t votes = 0;
      for (size_t j = 0; j < n; j++) votes += f[j].valid && same_layout(&f[i], &f[j]);
      if (votes > best_votes) best = i, best_votes = votes;
    }
    size_t quorum = n / 2; /* MinIO needs read quorum of formats: half the drives */
    if (best == n || best_votes < (quorum ? quorum : 1)) {
      snprintf(err, errlen, "no quorum of consistent format.json (%zu of %zu drives agree)", best_votes, n);
      ok = false;
    } else if (f[best].nsets != nsets || f[best].set_size != set_size) {
      snprintf(err, errlen, "drives are formatted as %zu sets of %zu, but the command line gives %zu sets of %zu",
               f[best].nsets, f[best].set_size, nsets, set_size);
      ok = false;
    }
    for (size_t i = 0; ok && i < n; i++) {
      if (f[i].valid && strcmp(f[i].id, f[best].id) != 0) {
        snprintf(err, errlen, "drive %s belongs to another deployment (%s)", drives[i]->root, f[i].id);
        ok = false;
      }
    }
    if (ok) {
      const fmt *ref = &f[best];
      memcpy(out->deployment_id, ref->id, 37);
      out->nsets = nsets;
      out->set_size = set_size;
      out->slots = buckets_xcalloc(n, sizeof(buckets_drive *));
      /* Place formatted drives by their own UUID. */
      for (size_t i = 0; i < n; i++) {
        if (!drives[i] || !f[i].valid) continue;
        for (size_t s = 0; s < n; s++) {
          if (strcmp(ref->sets[s], f[i].this_id) == 0) {
            if (out->slots[s]) {
              buckets_log_warn("drive %s duplicates drive UUID %s; ignoring it", drives[i]->root, f[i].this_id);
              break;
            }
            memcpy(drives[i]->deployment_id, ref->id, 37);
            memcpy(drives[i]->drive_id, f[i].this_id, 37);
            out->slots[s] = drives[i];
            drives[i] = NULL;
            break;
          }
        }
      }
      /* Heal unformatted (replaced) drives into the empty slot at their
       * command-line position, like MinIO's format healing. */
      for (size_t i = 0; i < n; i++) {
        if (!drives[i] || f[i].present || out->slots[i]) continue;
        if (write_fmt(drives[i], ref->format, ref->id, ref->sets[i], ref->sets, nsets, set_size)) {
          memcpy(drives[i]->deployment_id, ref->id, 37);
          memcpy(drives[i]->drive_id, ref->sets[i], 37);
          drives[i]->freshly_formatted = true;
          out->slots[i] = drives[i];
          drives[i] = NULL;
          out->formatted_fresh++;
          buckets_log_info("formatted replacement drive %s as %s", out->slots[i]->root, ref->sets[i]);
        }
      }
    }
  }
  if (ok) buckets_xl_version_id_parse(out->deployment_id, out->deployment_id_bytes);
  for (size_t i = 0; i < n; i++) {
    fmt_free(&f[i]);
    if (drives[i]) {
      if (ok) buckets_log_warn("drive %s is not part of this deployment; leaving it offline", drives[i]->root);
      buckets_drive_close(drives[i]);
      drives[i] = NULL;
    }
  }
  free(f);
  if (!ok) buckets_format_result_free(out);
  return ok;
}
