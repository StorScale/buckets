/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "storage/format.h"

#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <ftw.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <yyjson.h>

#include "core/log.h"
#include "storage/xlmeta.h"

#define FORMAT_PATH "format.json"

typedef struct {
  bool present, valid;
  bool offline; /* could not be read at all (a remote drive that is down) */
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
  buckets_drive_err e = buckets_drive_read_all(d, BUCKETS_META_BUCKET, FORMAT_PATH, &raw);
  if (e != BUCKETS_DRIVE_OK) {
    f->offline = e != BUCKETS_DRIVE_ERR_NOT_FOUND;
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

bool buckets_format_negotiate(buckets_drive **drives, size_t n, size_t set_size, const char *deployment_id,
                              buckets_format_opts *opts, buckets_format_result *out, char *err, size_t errlen) {
  memset(out, 0, sizeof(*out));
  bool may_format = !opts || opts->may_format_fresh;
  if (set_size == 0 || n % set_size) {
    snprintf(err, errlen, "%zu drives cannot form sets of %zu", n, set_size);
    return false;
  }
  size_t nsets = n / set_size;
  fmt *f = buckets_xcalloc(n, sizeof(fmt));
  size_t online = 0, unformatted = 0;
  for (size_t i = 0; i < n; i++) {
    if (!drives[i]) continue;
    read_fmt(drives[i], &f[i]);
    if (f[i].offline) continue;
    online++;
    if (!f[i].present) unformatted++;
  }
  bool ok = true;
  const char *format_name = n == 1 ? "xl-single" : "xl";

  if (online == 0) {
    snprintf(err, errlen, "no drives are online");
    ok = false;
  } else if (unformatted == n && !may_format) {
    snprintf(err, errlen, "waiting for the first server to format the drives");
    ok = false;
  } else if (unformatted == n) {
    /* Fresh deployment: every drive gets a UUID; sets follow command-line order. */
    char dep[BUCKETS_UUID_STR_LEN + 1];
    if (deployment_id) snprintf(dep, sizeof(dep), "%s", deployment_id); /* a new pool joins the deployment */
    else buckets_uuid_v4(dep);
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
      if (unformatted && unformatted + (n - online) == n) {
        snprintf(err, errlen, "waiting for all servers to come online to format the drives (%zu of %zu online)", online,
                 n);
      } else {
        snprintf(err, errlen, "no quorum of consistent format.json (%zu of %zu drives agree, %zu online)", best_votes,
                 n, online);
      }
      ok = false;
    } else if (f[best].nsets != nsets || f[best].set_size != set_size) {
      if (opts) opts->fatal = true;
      snprintf(err, errlen, "drives are formatted as %zu sets of %zu, but the command line gives %zu sets of %zu",
               f[best].nsets, f[best].set_size, nsets, set_size);
      ok = false;
    }
    if (ok && deployment_id && strcmp(f[best].id, deployment_id) != 0) {
      if (opts) opts->fatal = true;
      snprintf(err, errlen, "pool drives belong to deployment %s, not %s", f[best].id, deployment_id);
      ok = false;
    }
    for (size_t i = 0; ok && i < n; i++) {
      if (f[i].valid && strcmp(f[i].id, f[best].id) != 0) {
        if (opts) opts->fatal = true;
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
       * command-line position, like MinIO's format healing. Each node heals
       * only its own drives. */
      for (size_t i = 0; i < n; i++) {
        if (!drives[i] || f[i].present || f[i].offline || drives[i]->remote || out->slots[i]) continue;
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
      /* Remote drives that are down keep their command-line slot, so they
       * rejoin when their node comes back. */
      for (size_t i = 0; i < n; i++) {
        if (!drives[i] || !drives[i]->remote || out->slots[i] || (!f[i].offline && f[i].present)) continue;
        memcpy(drives[i]->deployment_id, ref->id, 37);
        memcpy(drives[i]->drive_id, ref->sets[i], 37);
        out->slots[i] = drives[i];
        drives[i] = NULL;
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

/* ---- a drive replaced while the server runs ------------------------------------------------ */

/* What nftw walks with (one walk at a time). */
static pthread_mutex_t g_walk_mu = PTHREAD_MUTEX_INITIALIZER;
static const char *g_root;
static long long g_cutoff_ms;
static bool g_old;

static bool in_lost_found(const char *path) {
  size_t n = strlen(g_root);
  return strncmp(path + n, "/lost+found", 11) == 0 && (path[n + 11] == '\0' || path[n + 11] == '/');
}

static int find_old(const char *path, const struct stat *st, int type, struct FTW *f) {
  (void)type;
  if (f->level == 0 || in_lost_found(path)) return 0;
#ifdef __APPLE__
  long long mt = (long long)st->st_mtimespec.tv_sec * 1000 + st->st_mtimespec.tv_nsec / 1000000;
#else
  long long mt = (long long)st->st_mtim.tv_sec * 1000 + st->st_mtim.tv_nsec / 1000000;
#endif
  if (mt < g_cutoff_ms) {
    g_old = true;
    return 1; /* stop: there is real data */
  }
  return 0;
}

static int clear(const char *path, const struct stat *st, int type, struct FTW *f) {
  (void)st, (void)type;
  if (f->level == 0 || in_lost_found(path)) return 0;
  remove(path);
  return 0;
}

bool buckets_format_replace(buckets_drive *d, buckets_drive *const *set, size_t n, long long changed_since,
                            char *err, size_t errlen) {
  struct stat st;
  if (stat(d->root, &st) != 0 || !S_ISDIR(st.st_mode)) {
    snprintf(err, errlen, "its directory is missing (the drive is not mounted?)");
    return false;
  }
  static const char *const meta_ok[] = {"tmp", "buckets", "multipart", "config", NULL};
  char meta[4096], sub[4200];
  snprintf(meta, sizeof(meta), "%s/" BUCKETS_META_BUCKET, d->root);
  /* nothing older than the moment it was found emptied (with some slack for clocks and the detection) */
  pthread_mutex_lock(&g_walk_mu);
  g_root = d->root;
  g_cutoff_ms = changed_since ? changed_since - 5000 : 0;
  g_old = false;
  if (changed_since) nftw(d->root, find_old, 32, FTW_PHYS);
  else g_old = true;
  bool old = g_old;
  if (!old) nftw(d->root, clear, 32, FTW_PHYS | FTW_DEPTH); /* what a moment's writes left */
  pthread_mutex_unlock(&g_walk_mu);
  if (old) {
    snprintf(err, errlen, "it holds data from before it lost its format.json, so it is left alone (heal or wipe it by hand)");
    return false;
  }
  /* the deployment's format, from another drive of the set */
  yyjson_doc *ref = NULL;
  for (size_t i = 0; i < n && !ref; i++) {
    if (!set[i] || set[i] == d) continue;
    buckets_buf raw = BUCKETS_BUF_INIT;
    if (buckets_drive_read_all(set[i], BUCKETS_META_BUCKET, FORMAT_PATH, &raw) == BUCKETS_DRIVE_OK) {
      ref = yyjson_read(raw.data, raw.len, 0);
      const char *id = yyjson_get_str(yyjson_obj_get(yyjson_doc_get_root(ref), "id"));
      if (!id || strcmp(id, d->deployment_id) != 0) yyjson_doc_free(ref), ref = NULL;
    }
    buckets_buf_free(&raw);
  }
  if (!ref) {
    snprintf(err, errlen, "no other drive of its set could give the deployment's format");
    return false;
  }
  yyjson_mut_doc *m = yyjson_doc_mut_copy(ref, NULL);
  yyjson_doc_free(ref);
  yyjson_mut_val *xl = yyjson_mut_obj_get(yyjson_mut_doc_get_root(m), "xl");
  yyjson_mut_obj_put(xl, yyjson_mut_str(m, "this"), yyjson_mut_strcpy(m, d->drive_id));
  size_t len;
  char *json = yyjson_mut_write(m, 0, &len);
  yyjson_mut_doc_free(m);
  for (size_t i = 0; meta_ok[i]; i++) { /* the layout a fresh drive gets */
    snprintf(sub, sizeof(sub), "%s/%s", meta, meta_ok[i]);
    mkdir(meta, 0755);
    mkdir(sub, 0755);
  }
  /* written directly: the drive refuses calls until a check finds this format.json */
  char tmp[4300], dst[4300];
  snprintf(tmp, sizeof(tmp), "%s/tmp/.format-%s.json", meta, d->drive_id);
  snprintf(dst, sizeof(dst), "%s/" FORMAT_PATH, meta);
  FILE *f = json ? fopen(tmp, "w") : NULL;
  bool ok = f && fwrite(json, 1, len, f) == len;
  if (f) ok = (fflush(f) == 0 && fsync(fileno(f)) == 0) && ok, fclose(f);
  ok = ok && rename(tmp, dst) == 0;
  if (!ok) unlink(tmp);
  free(json);
  if (!ok) snprintf(err, errlen, "format.json could not be written: %s", strerror(errno));
  else d->freshly_formatted = true;
  return ok;
}
