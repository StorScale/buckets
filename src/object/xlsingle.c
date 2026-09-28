/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "core/buf.h"
#include "core/log.h"
#include "core/uuid.h"
#include "crypto/hex.h"
#include "crypto/highwayhash.h"
#include "crypto/md5.h"
#include "crypto/sha256.h"
#include "object/internal.h"
#include "object/object.h"

#define XL_META "xl.meta"
#define DIR_SUFFIX "__XLDIR__"
#define BITROT_HASH 32

const char *buckets_obj_strerror(buckets_obj_err e) {
  switch (e) {
    case BUCKETS_OBJ_OK: return "ok";
    case BUCKETS_OBJ_ERR_NO_SUCH_BUCKET: return "no such bucket";
    case BUCKETS_OBJ_ERR_NO_SUCH_KEY: return "no such key";
    case BUCKETS_OBJ_ERR_NO_SUCH_VERSION: return "no such version";
    case BUCKETS_OBJ_ERR_INVALID_NAME: return "invalid object name";
    case BUCKETS_OBJ_ERR_NAME_TOO_LONG: return "object name too long";
    case BUCKETS_OBJ_ERR_NAME_PREFIX_SLASH: return "object name has a leading slash";
    case BUCKETS_OBJ_ERR_EXISTS_AS_DIRECTORY: return "object name conflicts with a directory";
    case BUCKETS_OBJ_ERR_BAD_DIGEST: return "content-md5 mismatch";
    case BUCKETS_OBJ_ERR_SHA256_MISMATCH: return "content-sha256 mismatch";
    case BUCKETS_OBJ_ERR_INCOMPLETE_BODY: return "incomplete body";
    case BUCKETS_OBJ_ERR_READER: return "data source failed";
    case BUCKETS_OBJ_ERR_CORRUPT: return "corrupt data";
    case BUCKETS_OBJ_ERR_IO: return "I/O error";
    case BUCKETS_OBJ_ERR_NO_SUCH_UPLOAD: return "no such upload";
    case BUCKETS_OBJ_ERR_INVALID_PART: return "invalid part";
    case BUCKETS_OBJ_ERR_INVALID_PART_ORDER: return "parts out of order";
    case BUCKETS_OBJ_ERR_PART_TOO_SMALL: return "part too small";
    case BUCKETS_OBJ_ERR_BAD_CHECKSUM: return "checksum mismatch";
  }
  return "unknown";
}

/* ---- small utilities ------------------------------------------------------ */

int64_t buckets_objx_now_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static bool valid_utf8(const unsigned char *s) {
  while (*s) {
    if (*s < 0x80) {
      s++;
      continue;
    }
    int n = (*s & 0xe0) == 0xc0 ? 1 : (*s & 0xf0) == 0xe0 ? 2 : (*s & 0xf8) == 0xf0 ? 3 : -1;
    if (n < 0 || (n == 1 && *s < 0xc2)) return false;
    unsigned cp = *s & (0x3f >> n);
    for (int i = 1; i <= n; i++) {
      if ((s[i] & 0xc0) != 0x80) return false;
      cp = cp << 6 | (s[i] & 0x3f);
    }
    if ((n == 2 && cp < 0x800) || (n == 3 && (cp < 0x10000 || cp > 0x10ffff)) || (cp >= 0xd800 && cp <= 0xdfff)) {
      return false;
    }
    s += n + 1;
  }
  return true;
}

buckets_obj_err buckets_obj_check_name(const char *object) {
  size_t n = strlen(object);
  if (n == 0) return BUCKETS_OBJ_ERR_INVALID_NAME;
  if (n > BUCKETS_MAX_OBJECT_NAME) return BUCKETS_OBJ_ERR_NAME_TOO_LONG;
  if (object[0] == '/') return BUCKETS_OBJ_ERR_NAME_PREFIX_SLASH;
  if (strstr(object, "//") || !valid_utf8((const unsigned char *)object)) return BUCKETS_OBJ_ERR_INVALID_NAME;
  for (const char *p = object; *p;) {
    const char *seg = p;
    while (*p && *p != '/') p++;
    size_t len = (size_t)(p - seg);
    if ((len == 1 && seg[0] == '.') || (len == 2 && seg[0] == '.' && seg[1] == '.')) {
      return BUCKETS_OBJ_ERR_INVALID_NAME;
    }
    if (*p == '/') p++;
  }
  /* A key ending in the directory-object suffix would alias a folder object. */
  if (strstr(object, DIR_SUFFIX)) return BUCKETS_OBJ_ERR_INVALID_NAME;
  return BUCKETS_OBJ_OK;
}

/* <root>/<bucket>/<object>, with trailing-slash keys encoded as name__XLDIR__. */
char *buckets_objx_object_dir(buckets_drive *d, const char *bucket, const char *object) {
  buckets_buf p = BUCKETS_BUF_INIT;
  size_t n = strlen(object);
  if (n && object[n - 1] == '/') {
    buckets_buf_appendf(&p, "%s/%s/%.*s" DIR_SUFFIX, d->root, bucket, (int)(n - 1), object);
  } else {
    buckets_buf_appendf(&p, "%s/%s/%s", d->root, bucket, object);
  }
  return p.data;
}

bool buckets_objx_is_file(const char *path) {
  struct stat st;
  return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

bool buckets_objx_bucket_exists(buckets_drive *d, const char *bucket) {
  return buckets_drive_stat_vol(d, bucket, NULL) == BUCKETS_DRIVE_OK;
}

static int rm_entry(const char *path, const struct stat *st, int flag, struct FTW *ftw) {
  return remove(path) == 0 || errno == ENOENT ? 0 : -1;
}

void buckets_objx_rm_rf(const char *path) { nftw(path, rm_entry, 16, FTW_DEPTH | FTW_PHYS); }

int buckets_objx_mkdir_all(const char *path) {
  char *tmp = buckets_xstrdup(path);
  for (char *s = tmp + 1; *s; s++) {
    if (*s != '/') continue;
    *s = '\0';
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
      free(tmp);
      return -1;
    }
    *s = '/';
  }
  int rc = (mkdir(tmp, 0755) == 0 || errno == EEXIST) ? 0 : -1;
  free(tmp);
  return rc;
}

void buckets_objx_fsync_path(const char *path) {
  int fd = open(path, O_RDONLY);
  if (fd >= 0) {
    fsync(fd);
    close(fd);
  }
}

bool buckets_objx_write_full(int fd, const void *p, size_t n) {
  const char *c = p;
  while (n) {
    ssize_t w = write(fd, c, n);
    if (w < 0 && errno == EINTR) continue;
    if (w < 0) return false;
    c += w;
    n -= (size_t)w;
  }
  return true;
}

static bool read_file(const char *path, buckets_buf *out) {
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) return false;
  char tmp[65536];
  for (;;) {
    ssize_t r = read(fd, tmp, sizeof(tmp));
    if (r < 0 && errno == EINTR) continue;
    if (r < 0) {
      close(fd);
      return false;
    }
    if (r == 0) break;
    buckets_buf_append(out, tmp, (size_t)r);
  }
  close(fd);
  return true;
}

char *buckets_objx_tmp_path(buckets_drive *d) {
  char id[BUCKETS_UUID_STR_LEN + 1];
  buckets_uuid_v4(id);
  buckets_buf p = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&p, "%s/" BUCKETS_META_BUCKET "/tmp/%s", d->root, id);
  return p.data;
}

/* Writes xl.meta via temp file + rename so readers never see a partial file. */
buckets_obj_err buckets_objx_write_xlmeta(buckets_drive *d, const char *dir, const buckets_xlmeta *x) {
  buckets_buf bytes = BUCKETS_BUF_INIT;
  buckets_xlmeta_serialize(x, &bytes);
  char *tmp = buckets_objx_tmp_path(d);
  buckets_obj_err err = BUCKETS_OBJ_OK;
  int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
  if (fd < 0 || !buckets_objx_write_full(fd, bytes.data, bytes.len) || fsync(fd) != 0) err = BUCKETS_OBJ_ERR_IO;
  if (fd >= 0) close(fd);
  if (err == BUCKETS_OBJ_OK) {
    buckets_buf dst = BUCKETS_BUF_INIT;
    buckets_buf_appendf(&dst, "%s/" XL_META, dir);
    if (rename(tmp, dst.data) != 0) err = BUCKETS_OBJ_ERR_IO;
    buckets_buf_free(&dst);
    buckets_objx_fsync_path(dir);
  }
  if (err != BUCKETS_OBJ_OK) unlink(tmp);
  free(tmp);
  buckets_buf_free(&bytes);
  return err;
}

buckets_objx_load_result buckets_objx_load_xlmeta(const char *dir, buckets_xlmeta *x) {
  buckets_buf path = BUCKETS_BUF_INIT, raw = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&path, "%s/" XL_META, dir);
  buckets_objx_load_result res = BUCKETS_OBJX_LOAD_OK;
  if (!read_file(path.data, &raw)) {
    res = errno == ENOENT || errno == ENOTDIR ? BUCKETS_OBJX_LOAD_MISSING : BUCKETS_OBJX_LOAD_ERR;
  } else if (buckets_xlmeta_parse(raw.data, raw.len, x) != BUCKETS_XL_OK) {
    res = BUCKETS_OBJX_LOAD_ERR;
  }
  buckets_buf_free(&path);
  buckets_buf_free(&raw);
  return res;
}

/* ---- object info ---------------------------------------------------------- */

void buckets_object_info_free(buckets_object_info *oi) {
  free(oi->name);
  for (size_t i = 0; i < oi->nmeta; i++) {
    free(oi->meta[i].key);
    free(oi->meta[i].value);
  }
  free(oi->meta);
  free(oi->checksum);
  memset(oi, 0, sizeof(*oi));
}

const char *buckets_object_meta(const buckets_object_info *oi, const char *key) {
  const buckets_xl_kv *kv = buckets_xl_kv_get(oi->meta, oi->nmeta, key);
  return kv ? (const char *)kv->value : NULL;
}

void buckets_objx_fill_info(buckets_object_info *oi, const char *name, const buckets_xl_object *o) {
  memset(oi, 0, sizeof(*oi));
  oi->name = buckets_xstrdup(name);
  buckets_xl_version_id_string(o->version_id, oi->version_id);
  oi->size = o->size;
  oi->mod_time_ns = o->mod_time;
  oi->nparts = o->nparts;
  oi->delete_marker = o->type == BUCKETS_XL_TYPE_DELETE;
  for (size_t i = 0; i < o->nmeta_user; i++) {
    if (strcmp(o->meta_user[i].key, "etag") == 0) {
      snprintf(oi->etag, sizeof(oi->etag), "%s", (const char *)o->meta_user[i].value);
      continue;
    }
    buckets_xl_kv_set(&oi->meta, &oi->nmeta, o->meta_user[i].key, o->meta_user[i].value, o->meta_user[i].value_len);
  }
  const buckets_xl_kv *crc = buckets_xl_kv_get(o->meta_sys, o->nmeta_sys, "x-minio-internal-crc");
  if (crc && crc->value_len) {
    oi->checksum = buckets_xmalloc(crc->value_len);
    memcpy(oi->checksum, crc->value, crc->value_len);
    oi->checksum_len = crc->value_len;
  }
}

/* Picks the requested version (or the latest), decoding it into *o. */
buckets_obj_err buckets_objx_pick_version(const buckets_xlmeta *x, const char *version_id, buckets_xl_object *o) {
  long idx = 0;
  if (version_id && *version_id) {
    uint8_t id[16];
    if (!buckets_xl_version_id_parse(version_id, id)) return BUCKETS_OBJ_ERR_NO_SUCH_VERSION;
    idx = buckets_xlmeta_find(x, id);
    if (idx < 0) return BUCKETS_OBJ_ERR_NO_SUCH_VERSION;
  } else if (x->n == 0) {
    return BUCKETS_OBJ_ERR_NO_SUCH_KEY;
  }
  if (buckets_xl_object_decode(&x->versions[idx], o) != BUCKETS_XL_OK) return BUCKETS_OBJ_ERR_CORRUPT;
  return BUCKETS_OBJ_OK;
}

/* ---- put ------------------------------------------------------------------ */

typedef struct {
  buckets_read_fn rd;
  void *ud;
  int64_t remaining;
  buckets_md5_ctx md5;
  buckets_sha256_ctx sha;
  bool want_sha;
  buckets_cksum_hasher cks;
  bool want_cks;
  buckets_obj_err err;
} source;

/* Reads exactly n bytes (or what remains); flags short reads. */
static size_t source_read(source *s, uint8_t *buf, size_t n) {
  size_t want = (size_t)BUCKETS_MIN((int64_t)n, s->remaining), got = 0;
  while (got < want) {
    long r = s->rd(s->ud, buf + got, want - got);
    if (r < 0) {
      s->err = BUCKETS_OBJ_ERR_READER;
      return got;
    }
    if (r == 0) {
      s->err = BUCKETS_OBJ_ERR_INCOMPLETE_BODY;
      return got;
    }
    got += (size_t)r;
  }
  buckets_md5_update(&s->md5, buf, got);
  if (s->want_sha) buckets_sha256_update(&s->sha, buf, got);
  if (s->want_cks) buckets_cksum_hasher_update(&s->cks, buf, got);
  s->remaining -= (int64_t)got;
  return got;
}

/* Appends one bitrot-framed block: HighwayHash-256(block) || block. */
static void frame_block(buckets_buf *out, const uint8_t *block, size_t n) {
  uint8_t h[BITROT_HASH];
  buckets_hh256(buckets_bitrot_key, block, n, h);
  buckets_buf_append(out, h, BITROT_HASH);
  buckets_buf_append(out, block, n);
}

/* Rejects keys whose parent path is an object, or that shadow a non-empty prefix. */
buckets_obj_err buckets_objx_check_namespace(buckets_drive *d, const char *bucket, const char *object) {
  buckets_buf p = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&p, "%s/%s", d->root, bucket);
  size_t base = p.len;
  buckets_obj_err err = BUCKETS_OBJ_OK;
  for (const char *s = object; (s = strchr(s, '/')) != NULL && s[1]; s++) {
    p.len = base;
    buckets_buf_appendf(&p, "/%.*s/" XL_META, (int)(s - object), object);
    if (buckets_objx_is_file(p.data)) {
      err = BUCKETS_OBJ_ERR_EXISTS_AS_DIRECTORY;
      break;
    }
  }
  if (err == BUCKETS_OBJ_OK) {
    char *dir = buckets_objx_object_dir(d, bucket, object);
    buckets_buf meta = BUCKETS_BUF_INIT;
    buckets_buf_appendf(&meta, "%s/" XL_META, dir);
    struct stat st;
    if (stat(dir, &st) == 0 && !buckets_objx_is_file(meta.data)) {
      if (!S_ISDIR(st.st_mode)) {
        err = BUCKETS_OBJ_ERR_EXISTS_AS_DIRECTORY;
      } else {
        DIR *dh = opendir(dir);
        struct dirent *e;
        while (dh && (e = readdir(dh))) {
          if (strcmp(e->d_name, ".") && strcmp(e->d_name, "..")) {
            err = BUCKETS_OBJ_ERR_EXISTS_AS_DIRECTORY;
            break;
          }
        }
        if (dh) closedir(dh);
      }
    }
    buckets_buf_free(&meta);
    free(dir);
  }
  buckets_buf_free(&p);
  return err;
}

buckets_obj_err buckets_objx_write_data(buckets_drive *d, buckets_read_fn rd, void *rd_ud, int64_t size,
                                       const buckets_put_opts *opts, bool allow_inline, const char *tmp_dir,
                                       const char *data_dir, int part_number, buckets_buf *inline_shard,
                                       uint8_t md5_out[16], buckets_checksum *cksum_out) {
  source src = {.rd = rd, .ud = rd_ud, .remaining = size, .want_sha = opts && opts->want_sha256};
  buckets_md5_init(&src.md5);
  buckets_sha256_init(&src.sha);
  uint32_t ctype = opts ? opts->checksum_type & BUCKETS_CKSUM_BASE_MASK : 0;
  src.want_cks = ctype != 0;
  buckets_cksum_hasher_init(&src.cks, ctype);
  if (cksum_out) memset(cksum_out, 0, sizeof(*cksum_out));
  uint8_t *block = buckets_xmalloc(BUCKETS_BLOCK_SIZE);

  if (allow_inline && size <= BUCKETS_INLINE_THRESHOLD) {
    size_t n = source_read(&src, block, (size_t)size);
    if (!src.err && n > 0) frame_block(inline_shard, block, n);
  } else {
    /* <tmp_dir>/<data-dir>/part.N, renamed into place by the caller. */
    buckets_buf part = BUCKETS_BUF_INIT;
    buckets_buf_appendf(&part, "%s/%s", tmp_dir, data_dir);
    int fd = -1;
    if (buckets_objx_mkdir_all(part.data) == 0) {
      buckets_buf_appendf(&part, "/part.%d", part_number);
      fd = open(part.data, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    }
    if (fd < 0) src.err = BUCKETS_OBJ_ERR_IO;
    buckets_buf chunk = BUCKETS_BUF_INIT;
    while (!src.err && src.remaining > 0) {
      size_t n = source_read(&src, block, BUCKETS_BLOCK_SIZE);
      if (src.err) break;
      buckets_buf_reset(&chunk);
      frame_block(&chunk, block, n);
      if (!buckets_objx_write_full(fd, chunk.data, chunk.len)) src.err = BUCKETS_OBJ_ERR_IO;
    }
    if (!src.err && fd >= 0 && fsync(fd) != 0) src.err = BUCKETS_OBJ_ERR_IO;
    if (fd >= 0) close(fd);
    buckets_buf_free(&chunk);
    buckets_buf_free(&part);
  }
  /* The source must end exactly here. Reading to EOF also lets aws-chunked
   * decoders consume their final chunk and trailers (trailing checksums). */
  if (!src.err) {
    long extra = rd(rd_ud, block, 1);
    if (extra > 0) src.err = BUCKETS_OBJ_ERR_INCOMPLETE_BODY;
    else if (extra < 0) src.err = BUCKETS_OBJ_ERR_READER;
  }
  free(block);

  uint8_t sha[32];
  buckets_md5_final(&src.md5, md5_out);
  buckets_sha256_final(&src.sha, sha);
  if (src.want_cks && cksum_out) {
    cksum_out->type = ctype;
    cksum_out->raw_len = buckets_cksum_hasher_final(&src.cks, cksum_out->raw);
  }
  if (src.err) return src.err;
  if (opts && opts->want_md5 && memcmp(md5_out, opts->want_md5, 16) != 0) return BUCKETS_OBJ_ERR_BAD_DIGEST;
  if (opts && opts->want_sha256 && memcmp(sha, opts->want_sha256, 32) != 0) return BUCKETS_OBJ_ERR_SHA256_MISMATCH;
  return BUCKETS_OBJ_OK;
}

void buckets_objx_init_version(buckets_xl_object *o, const uint8_t data_dir[16], int64_t size) {
  memset(o, 0, sizeof(*o));
  o->type = BUCKETS_XL_TYPE_OBJECT;
  memcpy(o->data_dir, data_dir, 16);
  o->mod_time = buckets_objx_now_ns();
  o->size = size;
  o->ec_m = 1;
  o->ec_n = 0;
  o->ec_block_size = BUCKETS_BLOCK_SIZE;
  o->ec_index = 1;
  o->ec_dist[0] = 1;
  o->ec_dist_n = 1;
}

void buckets_objx_new_data_dir(uint8_t id[16], char str[37]) {
  buckets_random_bytes(id, 16);
  id[6] = (uint8_t)((id[6] & 0x0f) | 0x40);
  id[8] = (uint8_t)((id[8] & 0x3f) | 0x80);
  buckets_xl_version_id_string(id, str);
}

buckets_obj_err buckets_objx_commit(buckets_drive *d, const char *bucket, const char *object, const buckets_xl_object *o,
                                    const buckets_buf *inline_shard, const char *src_data_dir,
                                    buckets_object_info *out) {
  char *dir = buckets_objx_object_dir(d, bucket, object);
  buckets_xlmeta x;
  buckets_objx_load_result lr = buckets_objx_load_xlmeta(dir, &x);
  if (lr != BUCKETS_OBJX_LOAD_OK) {
    if (lr == BUCKETS_OBJX_LOAD_ERR) buckets_log_warn("replacing unreadable xl.meta for %s/%s", bucket, object);
    memset(&x, 0, sizeof(x));
  }

  /* Unversioned bucket: the new object replaces the "null" version. */
  char old_data_dir[37] = "";
  long old = buckets_xlmeta_find(&x, o->version_id);
  if (old >= 0) {
    buckets_xl_object prev;
    if (buckets_xl_object_decode(&x.versions[old], &prev) == BUCKETS_XL_OK) {
      if (prev.type == BUCKETS_XL_TYPE_OBJECT && !buckets_xl_kv_get(prev.meta_sys, prev.nmeta_sys, BUCKETS_XL_META_INLINE)) {
        buckets_xl_version_id_string(prev.data_dir, old_data_dir);
      }
      buckets_xl_object_free(&prev);
    }
  }

  buckets_buf meta = BUCKETS_BUF_INIT;
  buckets_xl_header hdr;
  buckets_xl_object_encode(o, &meta, &hdr);
  buckets_xlmeta_put_version(&x, &hdr, (uint8_t *)meta.data, meta.len);
  char key[37];
  buckets_xl_version_id_string(o->version_id, key);
  if (inline_shard) {
    buckets_xlmeta_inline_put(&x, key, inline_shard->data ? inline_shard->data : "", inline_shard->len);
  } else {
    buckets_xlmeta_inline_remove(&x, key);
  }

  char data_dir[37];
  buckets_xl_version_id_string(o->data_dir, data_dir);
  buckets_obj_err err = BUCKETS_OBJ_OK;
  if (buckets_objx_mkdir_all(dir) != 0) {
    err = BUCKETS_OBJ_ERR_IO;
  } else if (src_data_dir) {
    buckets_buf to = BUCKETS_BUF_INIT;
    buckets_buf_appendf(&to, "%s/%s", dir, data_dir);
    if (rename(src_data_dir, to.data) != 0) err = BUCKETS_OBJ_ERR_IO;
    buckets_buf_free(&to);
  }
  if (!err) err = buckets_objx_write_xlmeta(d, dir, &x);
  if (!err && old_data_dir[0] && strcmp(old_data_dir, data_dir) != 0) {
    buckets_buf stale = BUCKETS_BUF_INIT;
    buckets_buf_appendf(&stale, "%s/%s", dir, old_data_dir);
    buckets_objx_rm_rf(stale.data);
    buckets_buf_free(&stale);
  }
  if (!err && out) buckets_objx_fill_info(out, object, o);
  buckets_xlmeta_free(&x);
  free(dir);
  return err;
}

buckets_obj_err buckets_obj_put(buckets_drive *d, const char *bucket, const char *object, buckets_read_fn rd,
                                void *rd_ud, int64_t size, const buckets_put_opts *opts, buckets_object_info *out) {
  if (!buckets_objx_bucket_exists(d, bucket)) return BUCKETS_OBJ_ERR_NO_SUCH_BUCKET;
  buckets_obj_err err = buckets_obj_check_name(object);
  if (err) return err;
  if ((err = buckets_objx_check_namespace(d, bucket, object)) != BUCKETS_OBJ_OK) return err;
  if (size < 0) return BUCKETS_OBJ_ERR_INCOMPLETE_BODY;

  uint8_t data_dir[16];
  char data_dir_s[37];
  buckets_objx_new_data_dir(data_dir, data_dir_s);
  bool inline_data = size <= BUCKETS_INLINE_THRESHOLD;
  char *tmp_dir = inline_data ? NULL : buckets_objx_tmp_path(d);
  buckets_buf framed = BUCKETS_BUF_INIT;
  uint8_t md5[16];
  buckets_checksum cks;
  err = buckets_objx_write_data(d, rd, rd_ud, size, opts, true, tmp_dir, data_dir_s, 1, &framed, md5, &cks);
  if (!err) {
    /* Built exactly as MinIO's putObject would for a 1-drive set. */
    buckets_xl_object o;
    buckets_objx_init_version(&o, data_dir, size);
    buckets_xl_part_add(&o, 1, size, size, NULL);
    for (size_t i = 0; opts && i < opts->nmeta; i++) {
      buckets_xl_kv_set(&o.meta_user, &o.nmeta_user, opts->meta[i].key, opts->meta[i].value, opts->meta[i].value_len);
    }
    char etag[33];
    buckets_hex_encode(md5, 16, etag);
    buckets_xl_kv_set(&o.meta_user, &o.nmeta_user, "etag", etag, 32);
    if (inline_data) buckets_xl_kv_set(&o.meta_sys, &o.nmeta_sys, BUCKETS_XL_META_INLINE, "true", 4);
    if (opts && opts->pre_commit) err = opts->pre_commit(opts->pre_commit_ud, &cks, &o);

    buckets_buf src = BUCKETS_BUF_INIT;
    if (!inline_data) buckets_buf_appendf(&src, "%s/%s", tmp_dir, data_dir_s);
    if (!err) {
      err = buckets_objx_commit(d, bucket, object, &o, inline_data ? &framed : NULL, inline_data ? NULL : src.data, out);
    }
    buckets_buf_free(&src);
    buckets_xl_object_free(&o);
  }
  if (tmp_dir) {
    buckets_objx_rm_rf(tmp_dir);
    free(tmp_dir);
  }
  buckets_buf_free(&framed);
  return err;
}

/* ---- stat / read ---------------------------------------------------------- */

buckets_obj_err buckets_obj_stat(buckets_drive *d, const char *bucket, const char *object, const char *version_id,
                                 buckets_object_info *out) {
  if (!buckets_objx_bucket_exists(d, bucket)) return BUCKETS_OBJ_ERR_NO_SUCH_BUCKET;
  buckets_obj_err err = buckets_obj_check_name(object);
  if (err) return err;
  char *dir = buckets_objx_object_dir(d, bucket, object);
  buckets_xlmeta x;
  buckets_objx_load_result lr = buckets_objx_load_xlmeta(dir, &x);
  free(dir);
  if (lr == BUCKETS_OBJX_LOAD_MISSING) return version_id && *version_id ? BUCKETS_OBJ_ERR_NO_SUCH_VERSION : BUCKETS_OBJ_ERR_NO_SUCH_KEY;
  if (lr == BUCKETS_OBJX_LOAD_ERR) return BUCKETS_OBJ_ERR_CORRUPT;
  buckets_xl_object o;
  err = buckets_objx_pick_version(&x, version_id, &o);
  if (!err) {
    buckets_objx_fill_info(out, object, &o);
    buckets_xl_object_free(&o);
  }
  buckets_xlmeta_free(&x);
  return err;
}

struct buckets_obj_reader {
  char *dir;
  char data_dir[37];
  buckets_xl_part *parts;
  size_t nparts;
  uint8_t *inline_shard; /* framed inline data, or NULL */
  size_t inline_len;
  size_t part;         /* current part index */
  int64_t part_off;    /* logical offset within current part */
  int64_t remaining;   /* bytes left in the requested range */
  int fd;              /* open part file, or -1 */
  uint8_t *block;      /* verified block cache */
  int64_t block_index; /* block held in cache, or -1 */
  size_t block_len;
};

void buckets_obj_reader_free(buckets_obj_reader *r) {
  if (!r) return;
  if (r->fd >= 0) close(r->fd);
  for (size_t i = 0; i < r->nparts; i++) free(r->parts[i].etag);
  free(r->parts);
  free(r->inline_shard);
  free(r->block);
  free(r->dir);
  free(r);
}

buckets_obj_err buckets_obj_open(buckets_drive *d, const char *bucket, const char *object, const char *version_id,
                                 int64_t offset, int64_t length, buckets_obj_reader **out,
                                 buckets_object_info *info) {
  if (!buckets_objx_bucket_exists(d, bucket)) return BUCKETS_OBJ_ERR_NO_SUCH_BUCKET;
  buckets_obj_err err = buckets_obj_check_name(object);
  if (err) return err;
  char *dir = buckets_objx_object_dir(d, bucket, object);
  buckets_xlmeta x;
  buckets_objx_load_result lr = buckets_objx_load_xlmeta(dir, &x);
  if (lr != BUCKETS_OBJX_LOAD_OK) {
    free(dir);
    if (lr == BUCKETS_OBJX_LOAD_ERR) return BUCKETS_OBJ_ERR_CORRUPT;
    return version_id && *version_id ? BUCKETS_OBJ_ERR_NO_SUCH_VERSION : BUCKETS_OBJ_ERR_NO_SUCH_KEY;
  }
  buckets_xl_object o;
  if ((err = buckets_objx_pick_version(&x, version_id, &o)) != BUCKETS_OBJ_OK) {
    buckets_xlmeta_free(&x);
    free(dir);
    return err;
  }
  if (o.type == BUCKETS_XL_TYPE_DELETE) {
    buckets_xl_object_free(&o);
    buckets_xlmeta_free(&x);
    free(dir);
    return BUCKETS_OBJ_ERR_NO_SUCH_KEY;
  }

  buckets_obj_reader *r = buckets_xcalloc(1, sizeof(*r));
  r->dir = dir;
  r->fd = -1;
  r->block_index = -1;
  buckets_xl_version_id_string(o.data_dir, r->data_dir);
  r->parts = o.parts;
  r->nparts = o.nparts;
  o.parts = NULL;
  o.nparts = 0;
  if (buckets_xl_kv_get(o.meta_sys, o.nmeta_sys, BUCKETS_XL_META_INLINE)) {
    char key[37];
    buckets_xl_version_id_string(o.version_id, key);
    buckets_str shard;
    if (buckets_xlmeta_inline_get(&x, key, &shard)) {
      r->inline_shard = buckets_xmalloc(shard.n ? shard.n : 1);
      memcpy(r->inline_shard, shard.p, shard.n);
      r->inline_len = shard.n;
    } else if (o.size > 0) {
      err = BUCKETS_OBJ_ERR_CORRUPT;
    }
  }
  if (info) buckets_objx_fill_info(info, object, &o);
  buckets_xl_object_free(&o);
  buckets_xlmeta_free(&x);
  if (err) {
    if (info) buckets_object_info_free(info);
    buckets_obj_reader_free(r);
    return err;
  }

  /* Position at `offset`. */
  int64_t off = offset;
  while (r->part < r->nparts && off >= r->parts[r->part].size && r->parts[r->part].size > 0) {
    off -= r->parts[r->part].size;
    r->part++;
  }
  r->part_off = off;
  int64_t total = 0;
  for (size_t i = 0; i < r->nparts; i++) total += r->parts[i].size;
  /* Clamp to the object so an open-ended range ends in EOF, not an error. */
  r->remaining = offset >= total ? 0 : BUCKETS_MIN(length, total - offset);
  r->block = buckets_xmalloc(BUCKETS_BLOCK_SIZE + BITROT_HASH);
  *out = r;
  return BUCKETS_OBJ_OK;
}

/* Loads and verifies block `bi` of the current part into the cache. */
static bool load_block(buckets_obj_reader *r, int64_t bi) {
  int64_t part_size = r->parts[r->part].size;
  int64_t data_off = bi * BUCKETS_BLOCK_SIZE;
  size_t data_len = (size_t)BUCKETS_MIN((int64_t)BUCKETS_BLOCK_SIZE, part_size - data_off);
  size_t frame_len = BITROT_HASH + data_len;
  int64_t frame_off = bi * (BUCKETS_BLOCK_SIZE + BITROT_HASH);
  if (r->inline_shard) {
    if ((size_t)frame_off + frame_len > r->inline_len) return false;
    memcpy(r->block, r->inline_shard + frame_off, frame_len);
  } else {
    if (r->fd < 0) {
      buckets_buf p = BUCKETS_BUF_INIT;
      buckets_buf_appendf(&p, "%s/%s/part.%d", r->dir, r->data_dir, r->parts[r->part].number);
      r->fd = open(p.data, O_RDONLY | O_CLOEXEC);
      buckets_buf_free(&p);
      if (r->fd < 0) return false;
    }
    size_t got = 0;
    while (got < frame_len) {
      ssize_t n = pread(r->fd, r->block + got, frame_len - got, (off_t)(frame_off + (int64_t)got));
      if (n < 0 && errno == EINTR) continue;
      if (n <= 0) return false;
      got += (size_t)n;
    }
  }
  uint8_t h[BITROT_HASH];
  buckets_hh256(buckets_bitrot_key, r->block + BITROT_HASH, data_len, h);
  if (!buckets_ct_equal(h, r->block, BITROT_HASH)) return false;
  r->block_index = bi;
  r->block_len = data_len;
  return true;
}

long buckets_obj_read(buckets_obj_reader *r, void *buf, size_t n) {
  size_t done = 0;
  while (done < n && r->remaining > 0) {
    if (r->part >= r->nparts) return -1; /* range beyond recorded parts: metadata/data mismatch */
    int64_t part_size = r->parts[r->part].size;
    if (r->part_off >= part_size) {
      if (r->fd >= 0) close(r->fd);
      r->fd = -1;
      r->part++;
      r->part_off = 0;
      r->block_index = -1;
      continue;
    }
    int64_t bi = r->part_off / BUCKETS_BLOCK_SIZE;
    if (bi != r->block_index && !load_block(r, bi)) {
      buckets_log_error("bitrot or read failure in %s (part %d, block %lld)", r->dir, r->parts[r->part].number,
                        (long long)bi);
      return -1;
    }
    size_t in_block = (size_t)(r->part_off - bi * BUCKETS_BLOCK_SIZE);
    size_t take = BUCKETS_MIN(r->block_len - in_block, n - done);
    take = (size_t)BUCKETS_MIN((int64_t)take, r->remaining);
    memcpy((uint8_t *)buf + done, r->block + BITROT_HASH + in_block, take);
    done += take;
    r->part_off += (int64_t)take;
    r->remaining -= (int64_t)take;
  }
  return (long)done;
}

/* ---- delete --------------------------------------------------------------- */

/* Removes now-empty directories from dir up to (not including) the bucket. */
static void prune_parents(buckets_drive *d, const char *bucket, const char *dir) {
  buckets_buf stop = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&stop, "%s/%s", d->root, bucket);
  char *p = buckets_xstrdup(dir);
  for (;;) {
    char *slash = strrchr(p, '/');
    if (!slash) break;
    *slash = '\0';
    if (strlen(p) <= stop.len || rmdir(p) != 0) break;
  }
  free(p);
  buckets_buf_free(&stop);
}

buckets_obj_err buckets_obj_delete(buckets_drive *d, const char *bucket, const char *object, const char *version_id) {
  if (!buckets_objx_bucket_exists(d, bucket)) return BUCKETS_OBJ_ERR_NO_SUCH_BUCKET;
  buckets_obj_err err = buckets_obj_check_name(object);
  if (err) return err;
  char *dir = buckets_objx_object_dir(d, bucket, object);
  buckets_xlmeta x;
  buckets_objx_load_result lr = buckets_objx_load_xlmeta(dir, &x);
  if (lr == BUCKETS_OBJX_LOAD_MISSING) {
    free(dir);
    return version_id && *version_id ? BUCKETS_OBJ_ERR_NO_SUCH_VERSION : BUCKETS_OBJ_ERR_NO_SUCH_KEY;
  }
  if (lr == BUCKETS_OBJX_LOAD_ERR) {
    free(dir);
    return BUCKETS_OBJ_ERR_CORRUPT;
  }
  uint8_t id[16] = {0};
  if (version_id && *version_id && !buckets_xl_version_id_parse(version_id, id)) {
    buckets_xlmeta_free(&x);
    free(dir);
    return BUCKETS_OBJ_ERR_NO_SUCH_VERSION;
  }
  long idx = buckets_xlmeta_find(&x, id);
  if (idx < 0) {
    buckets_xlmeta_free(&x);
    free(dir);
    return version_id && *version_id ? BUCKETS_OBJ_ERR_NO_SUCH_VERSION : BUCKETS_OBJ_ERR_NO_SUCH_KEY;
  }
  buckets_xl_object o;
  char data_dir[37] = "";
  bool had_inline = false;
  if (buckets_xl_object_decode(&x.versions[idx], &o) == BUCKETS_XL_OK) {
    had_inline = buckets_xl_kv_get(o.meta_sys, o.nmeta_sys, BUCKETS_XL_META_INLINE) != NULL;
    if (o.type == BUCKETS_XL_TYPE_OBJECT && !had_inline) buckets_xl_version_id_string(o.data_dir, data_dir);
    buckets_xl_object_free(&o);
  }
  buckets_xlmeta_remove_version(&x, id);
  char key[37];
  buckets_xl_version_id_string(id, key);
  buckets_xlmeta_inline_remove(&x, key);

  if (x.n == 0) {
    /* Last version: move the whole object directory aside, then delete it. */
    char *trash = buckets_objx_tmp_path(d);
    if (rename(dir, trash) == 0) {
      buckets_objx_rm_rf(trash);
      prune_parents(d, bucket, dir);
    } else {
      err = BUCKETS_OBJ_ERR_IO;
    }
    free(trash);
  } else {
    err = buckets_objx_write_xlmeta(d, dir, &x);
    if (!err && data_dir[0]) {
      buckets_buf p = BUCKETS_BUF_INIT;
      buckets_buf_appendf(&p, "%s/%s", dir, data_dir);
      buckets_objx_rm_rf(p.data);
      buckets_buf_free(&p);
    }
  }
  buckets_xlmeta_free(&x);
  free(dir);
  return err;
}

/* ---- listing -------------------------------------------------------------- */

/* One directory entry in S3 key order: objects sort by name, prefixes
 * (directories without xl.meta) by name + "/". */
typedef struct {
  char *key;   /* relative to the listed directory; prefixes end in '/' */
  bool is_obj; /* object (possibly a folder object ending in '/') */
} entry;

static int entry_cmp(const void *a, const void *b) { return strcmp(((const entry *)a)->key, ((const entry *)b)->key); }

typedef struct {
  buckets_drive *d;
  const char *bucket;
  const char *prefix;
  const char *marker;
  const char *delim;
  size_t delim_len;
  char *skip_prefix; /* common prefix equal to the marker: already returned */
  int max_keys;
  buckets_obj_listing *out;
  size_t count;
  bool done;
  char *last_prefix;
} list_ctx;

static void emit_prefix(list_ctx *lc, const char *cp, size_t n) {
  if (lc->last_prefix && strlen(lc->last_prefix) == n && memcmp(lc->last_prefix, cp, n) == 0) return;
  if (lc->skip_prefix && strlen(lc->skip_prefix) == n && memcmp(lc->skip_prefix, cp, n) == 0) return;
  if ((int)lc->count == lc->max_keys) {
    lc->out->truncated = true;
    lc->done = true;
    return;
  }
  free(lc->last_prefix);
  lc->last_prefix = buckets_xstrndup(cp, n);
  buckets_obj_listing *o = lc->out;
  o->prefixes = buckets_xrealloc(o->prefixes, (o->nprefixes + 1) * sizeof(char *));
  o->prefixes[o->nprefixes++] = buckets_xstrndup(cp, n);
  lc->count++;
}

static void emit_object(list_ctx *lc, const char *key, const char *dir) {
  if (lc->marker && strcmp(key, lc->marker) <= 0) return;
  if (strncmp(key, lc->prefix, strlen(lc->prefix)) != 0) return;
  if (lc->delim_len) {
    const char *hit = strstr(key + strlen(lc->prefix), lc->delim);
    if (hit) {
      emit_prefix(lc, key, (size_t)(hit - key) + lc->delim_len);
      return;
    }
  }
  if ((int)lc->count == lc->max_keys) {
    lc->out->truncated = true;
    lc->done = true;
    return;
  }
  buckets_xlmeta x;
  if (buckets_objx_load_xlmeta(dir, &x) != BUCKETS_OBJX_LOAD_OK) return;
  buckets_xl_object o;
  if (buckets_objx_pick_version(&x, NULL, &o) == BUCKETS_OBJ_OK) {
    if (o.type == BUCKETS_XL_TYPE_OBJECT) {
      buckets_obj_listing *out = lc->out;
      out->objects = buckets_xrealloc(out->objects, (out->nobjects + 1) * sizeof(buckets_object_info));
      buckets_objx_fill_info(&out->objects[out->nobjects++], key, &o);
      lc->count++;
    }
    buckets_xl_object_free(&o);
  }
  buckets_xlmeta_free(&x);
}

/* Walks <bucket>/<rel> (rel is "" or ends in '/'), emitting keys in order. */
static void walk(list_ctx *lc, const char *rel, const char *name_filter) {
  buckets_buf path = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&path, "%s/%s/%s", lc->d->root, lc->bucket, rel);
  DIR *dh = opendir(path.data);
  if (!dh) {
    buckets_buf_free(&path);
    return;
  }
  entry *ents = NULL;
  size_t n = 0, cap = 0;
  struct dirent *e;
  while ((e = readdir(dh))) {
    const char *nm = e->d_name;
    if (strcmp(nm, ".") == 0 || strcmp(nm, "..") == 0) continue;
    if (*rel == '\0' && strcmp(nm, BUCKETS_META_BUCKET) == 0) continue;
    /* Raw-name filter; emit_object re-checks the decoded key (folder objects). */
    if (name_filter && strncmp(nm, name_filter, strlen(name_filter)) != 0) continue;
    buckets_buf child = BUCKETS_BUF_INIT;
    buckets_buf_appendf(&child, "%s%s", path.data, nm);
    struct stat st;
    bool dir = stat(child.data, &st) == 0 && S_ISDIR(st.st_mode);
    if (!dir) {
      buckets_buf_free(&child);
      continue;
    }
    buckets_buf_append_c(&child, "/" XL_META);
    bool obj = buckets_objx_is_file(child.data);
    buckets_buf_free(&child);
    if (n == cap) {
      cap = cap ? cap * 2 : 32;
      ents = buckets_xrealloc(ents, cap * sizeof(entry));
    }
    size_t nl = strlen(nm), sl = strlen(DIR_SUFFIX);
    if (obj && nl > sl && strcmp(nm + nl - sl, DIR_SUFFIX) == 0) {
      buckets_buf k = BUCKETS_BUF_INIT;
      buckets_buf_appendf(&k, "%.*s/", (int)(nl - sl), nm);
      ents[n++] = (entry){k.data, true};
    } else if (obj) {
      ents[n++] = (entry){buckets_xstrdup(nm), true};
    } else {
      buckets_buf k = BUCKETS_BUF_INIT;
      buckets_buf_appendf(&k, "%s/", nm);
      ents[n++] = (entry){k.data, false};
    }
  }
  closedir(dh);
  if (n) qsort(ents, n, sizeof(entry), entry_cmp);

  for (size_t i = 0; i < n && !lc->done; i++) {
    buckets_buf key = BUCKETS_BUF_INIT;
    buckets_buf_appendf(&key, "%s%s", rel, ents[i].key);
    if (ents[i].is_obj) {
      buckets_buf dir = BUCKETS_BUF_INIT;
      size_t kl = strlen(ents[i].key);
      if (ents[i].key[kl - 1] == '/') {
        buckets_buf_appendf(&dir, "%s%.*s" DIR_SUFFIX, path.data, (int)(kl - 1), ents[i].key);
      } else {
        buckets_buf_appendf(&dir, "%s%s", path.data, ents[i].key);
      }
      emit_object(lc, key.data, dir.data);
      buckets_buf_free(&dir);
    } else {
      /* Skip subtrees that sort entirely at or before the marker. */
      bool before_marker = lc->marker && strcmp(key.data, lc->marker) < 0 &&
                           strncmp(lc->marker, key.data, key.len) != 0;
      size_t pl = strlen(lc->prefix);
      bool matches_prefix = strncmp(key.data, lc->prefix, BUCKETS_MIN(pl, key.len)) == 0;
      if (!before_marker && matches_prefix) {
        if (lc->delim_len == 1 && lc->delim[0] == '/' && key.len > pl) {
          /* With '/' as delimiter a subdirectory is exactly one common prefix. */
          if (!lc->marker || strcmp(key.data, lc->marker) > 0) emit_prefix(lc, key.data, key.len);
        } else {
          walk(lc, key.data, NULL);
        }
      }
    }
    buckets_buf_free(&key);
  }
  for (size_t i = 0; i < n; i++) free(ents[i].key);
  free(ents);
  buckets_buf_free(&path);
}

buckets_obj_err buckets_obj_list(buckets_drive *d, const char *bucket, const char *prefix, const char *marker,
                                 const char *delimiter, int max_keys, buckets_obj_listing *out) {
  memset(out, 0, sizeof(*out));
  if (!buckets_objx_bucket_exists(d, bucket)) return BUCKETS_OBJ_ERR_NO_SUCH_BUCKET;
  if (max_keys <= 0) return BUCKETS_OBJ_OK;
  if (max_keys > BUCKETS_MAX_LIST_KEYS) max_keys = BUCKETS_MAX_LIST_KEYS;
  list_ctx lc = {.d = d,
                 .bucket = bucket,
                 .prefix = prefix ? prefix : "",
                 .marker = marker && *marker ? marker : NULL,
                 .delim = delimiter ? delimiter : "",
                 .delim_len = delimiter ? strlen(delimiter) : 0,
                 .max_keys = max_keys,
                 .out = out};
  /* A marker that is itself a common prefix means everything under it was returned. */
  if (lc.marker && lc.delim_len) {
    size_t pl = strlen(lc.prefix);
    if (strncmp(lc.marker, lc.prefix, pl) == 0) {
      const char *hit = strstr(lc.marker + pl, lc.delim);
      if (hit) lc.skip_prefix = buckets_xstrndup(lc.marker, (size_t)(hit - lc.marker) + lc.delim_len);
    }
  }
  /* Start at the deepest directory the prefix pins down. */
  const char *slash = strrchr(lc.prefix, '/');
  char *base = slash ? buckets_xstrndup(lc.prefix, (size_t)(slash - lc.prefix) + 1) : buckets_xstrdup("");
  const char *filter = slash ? slash + 1 : lc.prefix;
  if (!*base || buckets_obj_check_name(base) == BUCKETS_OBJ_OK) {
    if (*base && !*filter) {
      /* The folder object named by the prefix itself ("photos/") sorts first. */
      buckets_buf fo = BUCKETS_BUF_INIT, meta = BUCKETS_BUF_INIT;
      buckets_buf_appendf(&fo, "%s/%s/%.*s" DIR_SUFFIX, d->root, bucket, (int)strlen(base) - 1, base);
      buckets_buf_appendf(&meta, "%s/" XL_META, fo.data);
      if (buckets_objx_is_file(meta.data)) emit_object(&lc, base, fo.data);
      buckets_buf_free(&fo);
      buckets_buf_free(&meta);
    }
    walk(&lc, base, *filter ? filter : NULL);
  }
  free(base);
  if (out->truncated) {
    /* The last entry returned, whichever kind came last in key order. */
    const char *last_obj = out->nobjects ? out->objects[out->nobjects - 1].name : NULL;
    const char *last_pfx = out->nprefixes ? out->prefixes[out->nprefixes - 1] : NULL;
    const char *last = !last_obj ? last_pfx : !last_pfx ? last_obj : strcmp(last_obj, last_pfx) > 0 ? last_obj : last_pfx;
    out->next_marker = last ? buckets_xstrdup(last) : NULL;
  }
  free(lc.last_prefix);
  free(lc.skip_prefix);
  return BUCKETS_OBJ_OK;
}

void buckets_obj_list_free(buckets_obj_listing *l) {
  for (size_t i = 0; i < l->nobjects; i++) buckets_object_info_free(&l->objects[i]);
  free(l->objects);
  for (size_t i = 0; i < l->nprefixes; i++) free(l->prefixes[i]);
  free(l->prefixes);
  free(l->next_marker);
  memset(l, 0, sizeof(*l));
}

bool buckets_obj_bucket_empty(buckets_drive *d, const char *bucket) {
  buckets_obj_listing l;
  if (buckets_obj_list(d, bucket, "", NULL, NULL, 1, &l) != BUCKETS_OBJ_OK) return true;
  bool empty = l.nobjects == 0;
  buckets_obj_list_free(&l);
  return empty;
}
