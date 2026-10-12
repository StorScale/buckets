/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "storage/remote.h"
#include "storage/health.h"

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "core/log.h"
#include "dist/internode.h"
#include "dist/rpcstats.h"
#include "storage/xlmeta.h"

#define OFFLINE_BACKOFF_MS 1000
#define WRITE_BUFFER (4u * 1024 * 1024)
/* How long a peer that refused a call this node added (it runs an older
 * release, as during a rolling upgrade) is sent the older calls instead. */
#define LEGACY_RETRY_MS 60000

struct buckets_remote {
  buckets_http_client *peer;
  char *disk_path;
  _Atomic int64_t offline_until_ms;
  _Atomic bool logged_offline;
  _Atomic int64_t legacy_until_ms; /* see LEGACY_RETRY_MS */
};

static int64_t now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

buckets_drive *buckets_drive_open_remote(buckets_http_client *peer, const char *disk_path, const char *endpoint) {
  buckets_drive *d = buckets_xcalloc(1, sizeof(*d));
  d->root = buckets_xstrdup(endpoint);
  d->remote = buckets_xcalloc(1, sizeof(*d->remote));
  d->remote->peer = peer;
  d->remote->disk_path = buckets_xstrdup(disk_path);
  return d;
}

void buckets_rdrive_free(struct buckets_remote *r) {
  if (!r) return;
  free(r->disk_path);
  free(r);
}

bool buckets_drive_is_online(buckets_drive *d) {
  if (!d) return false;
  if (!d->remote) return buckets_drive_health_state(d) == BUCKETS_DRIVE_HEALTH_OK; /* storage/health.c */
  return atomic_load(&d->remote->offline_until_ms) <= now_ms();
}

/* ---- calls ------------------------------------------------------------------- */

typedef struct {
  buckets_buf q;
} args;

static void arg(args *a, const char *k, const char *v) {
  buckets_buf_appendf(&a->q, "&%s=", k);
  buckets_url_encode(&a->q, v ? v : "", false);
}

static void argi(args *a, const char *k, long long v) { buckets_buf_appendf(&a->q, "&%s=%lld", k, v); }

/* Runs op on the peer. The response body goes to out (if given). With
 * unsupported, a peer that does not know op (400) sets it. */
static buckets_drive_err call_ex(buckets_drive *d, const char *op, args *a, const void *body, size_t blen,
                                 buckets_buf *out, bool *unsupported) {
  struct buckets_remote *r = d->remote;
  buckets_drive_err err = BUCKETS_DRIVE_ERR_OFFLINE;
  if (atomic_load(&r->offline_until_ms) > now_ms()) {
    buckets_buf_free(&a->q);
    return err;
  }
  buckets_buf target = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&target, BUCKETS_INTERNODE_PREFIX "storage/%s?drive=", op);
  buckets_url_encode(&target, r->disk_path, false);
  if (a->q.len) buckets_buf_append(&target, a->q.data, a->q.len);
  buckets_buf_free(&a->q);
  char auth[96];
  buckets_internode_sign("POST", target.data, auth);
  buckets_http_kv h[] = {{BUCKETS_INTERNODE_AUTH, auth}};
  buckets_http_result res;
  int64_t t0 = buckets_rpcstats_now_ns();
  bool sent = buckets_http_client_do(r->peer, "POST", target.data, h, 1, body, blen, &res);
  buckets_rpcstats_add(BUCKETS_RPC_CALLED, "storage", op, buckets_rpcstats_now_ns() - t0);
  if (!sent) {
    atomic_store(&r->offline_until_ms, now_ms() + OFFLINE_BACKOFF_MS);
    if (!atomic_exchange(&r->logged_offline, true)) buckets_log_warn("drive %s is offline", d->root);
    buckets_buf_free(&target);
    return err;
  }
  if (atomic_exchange(&r->logged_offline, false)) buckets_log_info("drive %s is back online", d->root);
  if (res.status == 200) {
    err = BUCKETS_DRIVE_OK;
    if (out) {
      buckets_buf_free(out);
      *out = res.body;
      memset(&res.body, 0, sizeof(res.body));
    }
  } else if (res.status == 400 && unsupported) {
    *unsupported = true;
    atomic_store(&r->legacy_until_ms, now_ms() + LEGACY_RETRY_MS);
    err = BUCKETS_DRIVE_ERR_IO;
  } else {
    size_t n;
    const char *code = buckets_http_result_header(&res, BUCKETS_INTERNODE_ERR, &n);
    err = code ? (buckets_drive_err)atoi(code) : BUCKETS_DRIVE_ERR_IO;
    if (res.status == 403) buckets_log_error("drive %s refused internode authentication; are the root credentials "
                                             "the same on every node?", d->root);
    if (err == BUCKETS_DRIVE_OK) err = BUCKETS_DRIVE_ERR_IO;
  }
  buckets_http_result_free(&res);
  buckets_buf_free(&target);
  return err;
}

static buckets_drive_err call(buckets_drive *d, const char *op, args *a, const void *body, size_t blen,
                              buckets_buf *out) {
  return call_ex(d, op, a, body, blen, out, NULL);
}

/* The peer refused a newer call a moment ago: send it the older ones. */
static bool legacy(buckets_drive *d) { return atomic_load(&d->remote->legacy_until_ms) > now_ms(); }

buckets_drive_err buckets_rdrive_make_vol(buckets_drive *d, const char *name) {
  args a = {BUCKETS_BUF_INIT};
  arg(&a, "vol", name);
  return call(d, "make_vol", &a, NULL, 0, NULL);
}

buckets_drive_err buckets_rdrive_stat_vol(buckets_drive *d, const char *name, time_t *created) {
  args a = {BUCKETS_BUF_INIT};
  arg(&a, "vol", name);
  buckets_buf out = BUCKETS_BUF_INIT;
  buckets_drive_err e = call(d, "stat_vol", &a, NULL, 0, &out);
  if (!e && created) *created = (time_t)strtoll(out.data ? out.data : "0", NULL, 10);
  buckets_buf_free(&out);
  return e;
}

buckets_drive_err buckets_rdrive_delete_vol(buckets_drive *d, const char *name) {
  args a = {BUCKETS_BUF_INIT};
  arg(&a, "vol", name);
  return call(d, "delete_vol", &a, NULL, 0, NULL);
}

/* Lines of "<created>\t<name>". */
buckets_drive_err buckets_rdrive_list_vols(buckets_drive *d, buckets_vol_info **vols, size_t *n) {
  args a = {BUCKETS_BUF_INIT};
  buckets_buf out = BUCKETS_BUF_INIT;
  *vols = NULL;
  *n = 0;
  buckets_drive_err e = call(d, "list_vols", &a, NULL, 0, &out);
  for (char *p = out.data, *nl; !e && p && *p; p = nl + 1) {
    nl = strchr(p, '\n');
    if (!nl) break;
    *nl = '\0';
    char *tab = strchr(p, '\t');
    if (!tab) continue;
    *vols = buckets_xrealloc(*vols, (*n + 1) * sizeof(buckets_vol_info));
    (*vols)[*n].created = (time_t)strtoll(p, NULL, 10);
    (*vols)[*n].name = buckets_xstrdup(tab + 1);
    (*n)++;
  }
  buckets_buf_free(&out);
  return e;
}

buckets_drive_err buckets_rdrive_read_all(buckets_drive *d, const char *vol, const char *path, buckets_buf *out) {
  args a = {BUCKETS_BUF_INIT};
  arg(&a, "vol", vol);
  arg(&a, "path", path);
  buckets_buf got = BUCKETS_BUF_INIT;
  buckets_drive_err e = call(d, "read_all", &a, NULL, 0, &got);
  if (!e && got.len) buckets_buf_append(out, got.data, got.len);
  buckets_buf_free(&got);
  return e;
}

buckets_drive_err buckets_rdrive_write_all(buckets_drive *d, const char *vol, const char *path, const void *data,
                                           size_t n) {
  args a = {BUCKETS_BUF_INIT};
  arg(&a, "vol", vol);
  arg(&a, "path", path);
  return call(d, "write_all", &a, data, n, NULL);
}

buckets_drive_err buckets_rdrive_append(buckets_drive *d, const char *vol, const char *path, int64_t off,
                                        const void *data, size_t n) {
  args a = {BUCKETS_BUF_INIT};
  arg(&a, "vol", vol);
  arg(&a, "path", path);
  argi(&a, "off", off);
  return call(d, "append", &a, data, n, NULL);
}

buckets_drive_err buckets_rdrive_fsync_file(buckets_drive *d, const char *vol, const char *path) {
  args a = {BUCKETS_BUF_INIT};
  arg(&a, "vol", vol);
  arg(&a, "path", path);
  return call(d, "fsync", &a, NULL, 0, NULL);
}

buckets_drive_err buckets_rdrive_read_at(buckets_drive *d, const char *vol, const char *path, int64_t off, void *buf,
                                         size_t n, size_t *got) {
  args a = {BUCKETS_BUF_INIT};
  arg(&a, "vol", vol);
  arg(&a, "path", path);
  argi(&a, "off", off);
  argi(&a, "n", (long long)n);
  buckets_buf out = BUCKETS_BUF_INIT;
  *got = 0;
  buckets_drive_err e = call(d, "read_at", &a, NULL, 0, &out);
  if (!e) {
    *got = BUCKETS_MIN(out.len, n);
    if (*got) memcpy(buf, out.data, *got);
  }
  buckets_buf_free(&out);
  return e;
}

buckets_drive_err buckets_rdrive_rename_data(buckets_drive *d, const char *src_vol, const char *src_dir,
                                             const char *data_dir, const char *dst_vol, const char *dst_path,
                                             const void *xlmeta, size_t xlmeta_len) {
  args a = {BUCKETS_BUF_INIT};
  arg(&a, "src_vol", src_vol);
  arg(&a, "src_dir", src_dir);
  if (data_dir) arg(&a, "data_dir", data_dir);
  arg(&a, "dst_vol", dst_vol);
  arg(&a, "dst_path", dst_path);
  return call(d, "rename_data", &a, xlmeta, xlmeta_len, NULL);
}

/* The version travels as an xl.meta holding just it (and its inline shard). */
buckets_drive_err buckets_rdrive_commit(buckets_drive *d, const buckets_commit_args *c, bool *replaced,
                                        bool *unsupported) {
  *replaced = false;
  if (legacy(d)) {
    *unsupported = true;
    return BUCKETS_DRIVE_ERR_IO;
  }
  args a = {BUCKETS_BUF_INIT};
  arg(&a, "bucket", c->bucket);
  arg(&a, "path", c->path);
  arg(&a, "src_dir", c->src_dir);
  arg(&a, "data_dir", c->data_dir);
  argi(&a, "move", c->move_data);
  argi(&a, "remove_src", c->remove_src);
  argi(&a, "check_bucket", c->check_bucket);
  argi(&a, "inline", c->has_inline);
  if (c->fv_id) {
    char fv[37];
    buckets_xl_version_id_string(c->fv_id, fv);
    arg(&a, "fv", fv);
  }
  buckets_xlmeta x;
  memset(&x, 0, sizeof(x));
  uint8_t *meta = buckets_xmalloc(c->meta_len ? c->meta_len : 1);
  if (c->meta_len) memcpy(meta, c->meta, c->meta_len);
  buckets_xlmeta_put_version(&x, c->hdr, meta, c->meta_len);
  if (c->has_inline) {
    char key[37];
    buckets_xl_version_id_string(c->hdr->version_id, key);
    buckets_xlmeta_inline_put(&x, key, c->inl ? c->inl : "", c->inl_len);
  }
  buckets_buf body = BUCKETS_BUF_INIT, out = BUCKETS_BUF_INIT;
  buckets_xlmeta_serialize(&x, &body);
  buckets_xlmeta_free(&x);
  buckets_drive_err e = call_ex(d, "commit", &a, body.data, body.len, &out, unsupported);
  if (!e) *replaced = out.data && out.data[0] == '1';
  buckets_buf_free(&body);
  buckets_buf_free(&out);
  return e;
}

buckets_drive_err buckets_rdrive_rename_file(buckets_drive *d, const char *src_vol, const char *src, const char *dst_vol,
                                             const char *dst) {
  args a = {BUCKETS_BUF_INIT};
  arg(&a, "src_vol", src_vol);
  arg(&a, "src", src);
  arg(&a, "dst_vol", dst_vol);
  arg(&a, "dst", dst);
  return call(d, "rename_file", &a, NULL, 0, NULL);
}

buckets_drive_err buckets_rdrive_delete(buckets_drive *d, const char *vol, const char *path, bool recursive,
                                        bool prune) {
  args a = {BUCKETS_BUF_INIT};
  arg(&a, "vol", vol);
  arg(&a, "path", path);
  argi(&a, "recursive", recursive);
  argi(&a, "prune", prune);
  return call(d, "delete", &a, NULL, 0, NULL);
}

buckets_drive_err buckets_rdrive_list_dir(buckets_drive *d, const char *vol, const char *dir, buckets_dir_list *out) {
  memset(out, 0, sizeof(*out));
  args a = {BUCKETS_BUF_INIT};
  arg(&a, "vol", vol);
  arg(&a, "dir", dir);
  buckets_buf body = BUCKETS_BUF_INIT;
  buckets_drive_err e = call(d, "list_dir", &a, NULL, 0, &body);
  size_t cap = 0;
  for (char *p = body.data, *nl; !e && p && *p; p = nl + 1) {
    nl = strchr(p, '\n');
    if (!nl) break;
    *nl = '\0';
    if (out->n == cap) {
      cap = cap ? cap * 2 : 32;
      out->names = buckets_xrealloc(out->names, cap * sizeof(char *));
    }
    out->names[out->n++] = buckets_xstrdup(p);
  }
  buckets_buf_free(&body);
  return e;
}

buckets_drive_err buckets_rdrive_disk_info(buckets_drive *d, uint64_t *total, uint64_t *free_bytes) {
  args a = {BUCKETS_BUF_INIT};
  buckets_buf out = BUCKETS_BUF_INIT;
  buckets_drive_err e = call(d, "disk_info", &a, NULL, 0, &out);
  unsigned long long t = 0, f = 0;
  if (!e && (!out.data || sscanf(out.data, "%llu %llu", &t, &f) != 2)) e = BUCKETS_DRIVE_ERR_IO;
  *total = t;
  *free_bytes = f;
  buckets_buf_free(&out);
  return e;
}

buckets_drive_err buckets_rdrive_file_size(buckets_drive *d, const char *vol, const char *path, int64_t *size) {
  args a = {BUCKETS_BUF_INIT};
  arg(&a, "vol", vol);
  arg(&a, "path", path);
  buckets_buf out = BUCKETS_BUF_INIT;
  buckets_drive_err e = call(d, "file_size", &a, NULL, 0, &out);
  if (!e) *size = strtoll(out.data ? out.data : "0", NULL, 10);
  buckets_buf_free(&out);
  return e;
}

int buckets_rdrive_stat(buckets_drive *d, const char *vol, const char *path) {
  args a = {BUCKETS_BUF_INIT};
  arg(&a, "vol", vol);
  arg(&a, "path", path);
  buckets_buf out = BUCKETS_BUF_INIT;
  int r = call(d, "stat", &a, NULL, 0, &out) == BUCKETS_DRIVE_OK && out.data ? atoi(out.data) : 0;
  buckets_buf_free(&out);
  return r;
}

buckets_drive_err buckets_rdrive_stat_info(buckets_drive *d, const char *vol, const char *path, buckets_stat_info **out,
                                           size_t *n) {
  args a = {BUCKETS_BUF_INIT};
  arg(&a, "vol", vol);
  arg(&a, "path", path);
  buckets_buf body = BUCKETS_BUF_INIT;
  buckets_drive_err e = call(d, "stat_info", &a, NULL, 0, &body);
  if (!e && !buckets_stat_info_parse(body.data ? body.data : "[]", body.len, out, n)) e = BUCKETS_DRIVE_ERR_IO;
  buckets_buf_free(&body);
  return e;
}

/* ---- writer: buffered appends --------------------------------------------------------- */

/* The file is created by the first "write" call, which carries the first
 * WRITE_BUFFER bytes, and the last one flushes it to stable storage: a shard
 * of up to WRITE_BUFFER bytes takes one call where create, append and fsync
 * took three. */
struct buckets_rwriter {
  buckets_drive *d;
  char *vol, *path;
  int64_t off;
  bool created;
  buckets_buf buf;
};

buckets_drive_err buckets_rdrive_create_file(buckets_drive *d, const char *vol, const char *path,
                                             buckets_drive_writer **w) {
  if (atomic_load(&d->remote->offline_until_ms) > now_ms()) return BUCKETS_DRIVE_ERR_OFFLINE;
  struct buckets_rwriter *rw = buckets_xcalloc(1, sizeof(*rw));
  rw->d = d;
  rw->vol = buckets_xstrdup(vol);
  rw->path = buckets_xstrdup(path);
  *w = buckets_drive_writer_wrap_remote(rw);
  return BUCKETS_DRIVE_OK;
}

/* Sends the buffer; with sync, also flushes the file to stable storage. */
static buckets_drive_err flush(struct buckets_rwriter *w, bool sync) {
  if (!w->buf.len && !sync && w->created) return BUCKETS_DRIVE_OK;
  buckets_drive_err e = BUCKETS_DRIVE_OK;
  bool unsupported = legacy(w->d);
  if (!unsupported) {
    args a = {BUCKETS_BUF_INIT};
    arg(&a, "vol", w->vol);
    arg(&a, "path", w->path);
    argi(&a, "off", w->off);
    argi(&a, "create", !w->created);
    argi(&a, "sync", sync);
    e = call_ex(w->d, "write", &a, w->buf.data, w->buf.len, NULL, &unsupported);
    if (!unsupported && !e) w->created = true;
  }
  if (unsupported) { /* an older peer */
    e = BUCKETS_DRIVE_OK;
    if (!w->created) {
      args a = {BUCKETS_BUF_INIT};
      arg(&a, "vol", w->vol);
      arg(&a, "path", w->path);
      if (!(e = call(w->d, "create", &a, NULL, 0, NULL))) w->created = true;
    }
    if (!e && w->buf.len) e = buckets_rdrive_append(w->d, w->vol, w->path, w->off, w->buf.data, w->buf.len);
    if (!e && sync) e = buckets_rdrive_fsync_file(w->d, w->vol, w->path);
  }
  if (!e) w->off += (int64_t)w->buf.len;
  buckets_buf_reset(&w->buf);
  return e;
}

static void rwriter_free(struct buckets_rwriter *w) {
  free(w->vol);
  free(w->path);
  buckets_buf_free(&w->buf);
  free(w);
}

buckets_drive_err buckets_rwriter_write(struct buckets_rwriter *w, const void *data, size_t n) {
  buckets_buf_append(&w->buf, data, n);
  return w->buf.len >= WRITE_BUFFER ? flush(w, false) : BUCKETS_DRIVE_OK;
}

buckets_drive_err buckets_rwriter_close(struct buckets_rwriter *w) {
  buckets_drive_err e = flush(w, true);
  rwriter_free(w);
  return e;
}

void buckets_rwriter_abort(struct buckets_rwriter *w) {
  if (w->created) buckets_rdrive_delete(w->d, w->vol, w->path, false, false);
  rwriter_free(w);
}
