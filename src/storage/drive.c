/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "storage/drive.h"
#include "storage/drivestats.h"
#include "storage/osmetrics.h"
#include "core/timefmt.h"
#include "notify/event.h"
#include "trace/trace.h"
#include <stdarg.h>
#include "storage/remote.h"

#include <dirent.h>
#include <ftw.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <time.h>
#include <unistd.h>
#include <yyjson.h>

#include "core/buf.h"
#include "core/log.h"

/* format.json constants, matching MinIO cmd/format-meta.go and format-erasure.go. */
#define FORMAT_META_VERSION "1"
#define FORMAT_BACKEND_SINGLE "xl-single"
#define FORMAT_BACKEND_ERASURE "xl"
#define FORMAT_ERASURE_VERSION "3"
#define FORMAT_DISTRIBUTION_ALGO "SIPMOD+PARITY"

const char *buckets_drive_strerror(buckets_drive_err e) {
  switch (e) {
    case BUCKETS_DRIVE_OK: return "ok";
    case BUCKETS_DRIVE_ERR_EXISTS: return "already exists";
    case BUCKETS_DRIVE_ERR_NOT_FOUND: return "not found";
    case BUCKETS_DRIVE_ERR_NOT_EMPTY: return "not empty";
    case BUCKETS_DRIVE_ERR_CORRUPT: return "format.json is corrupt";
    case BUCKETS_DRIVE_ERR_FOREIGN: return "drive belongs to an unsupported deployment layout";
    case BUCKETS_DRIVE_ERR_IO: return "I/O error";
    case BUCKETS_DRIVE_ERR_OFFLINE: return "drive offline";
  }
  return "unknown";
}

static buckets_drive_err from_errno(int e) {
  switch (e) {
    case EEXIST: return BUCKETS_DRIVE_ERR_EXISTS;
    case ENOENT: return BUCKETS_DRIVE_ERR_NOT_FOUND;
    case ENOTEMPTY: return BUCKETS_DRIVE_ERR_NOT_EMPTY;
    default: return BUCKETS_DRIVE_ERR_IO;
  }
}

static char *path_join(const char *a, const char *b) {
  buckets_buf p = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&p, "%s/%s", a, b);
  return p.data;
}

static int mkdir_p(const char *path) {
  char *tmp = buckets_xstrdup(path);
  for (char *s = tmp + 1; *s; s++) {
    if (*s != '/') continue;
    *s = '\0';
    if (buckets_os_mkdir(tmp, 0755) != 0 && errno != EEXIST) {
      free(tmp);
      return -1;
    }
    *s = '/';
  }
  int rc = (buckets_os_mkdir(tmp, 0755) == 0 || errno == EEXIST) ? 0 : -1;
  free(tmp);
  return rc;
}

/* Data durability for file contents: fdatasync where the platform has it
 * (skips metadata-only flushes, as MinIO's Fdatasync), fsync elsewhere. */
static int data_sync(int fd) { return buckets_os_fdatasync(fd); }

static int fsync_dir(const char *dir) {
  int fd = buckets_os_open(dir, O_RDONLY);
  if (fd < 0) return -1;
  int rc = buckets_os_fsync(fd);
  close(fd);
  return rc;
}

/* Writes data to <dir>/<name> atomically via a temp file + rename + fsync. */
static buckets_drive_err write_atomic(buckets_drive *d, const char *dir, const char *name, const char *data,
                                      size_t n) {
  char tmpname[BUCKETS_UUID_STR_LEN + 1];
  buckets_uuid_v4(tmpname);
  char *tmpdir = path_join(d->root, BUCKETS_META_BUCKET "/tmp");
  char *tmp = path_join(tmpdir, tmpname);
  char *dst = path_join(dir, name);
  buckets_drive_err err = BUCKETS_DRIVE_OK;

  int fd = buckets_os_open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
  if (fd < 0) {
    err = from_errno(errno);
    goto out;
  }
  size_t off = 0;
  while (off < n) {
    ssize_t w = write(fd, data + off, n - off);
    if (w < 0 && errno == EINTR) continue;
    if (w < 0) {
      err = BUCKETS_DRIVE_ERR_IO;
      break;
    }
    off += (size_t)w;
  }
  if (err == BUCKETS_DRIVE_OK && data_sync(fd) != 0) err = BUCKETS_DRIVE_ERR_IO;
  close(fd);
  if (err == BUCKETS_DRIVE_OK && buckets_os_rename(tmp, dst) != 0) err = from_errno(errno);
  if (err == BUCKETS_DRIVE_OK) fsync_dir(dir);
  if (err != BUCKETS_DRIVE_OK) buckets_os_unlink(tmp);
out:
  free(tmpdir);
  free(tmp);
  free(dst);
  return err;
}

static buckets_drive_err write_format(buckets_drive *d) {
  yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(doc);
  yyjson_mut_doc_set_root(doc, root);
  yyjson_mut_obj_add_str(doc, root, "version", FORMAT_META_VERSION);
  yyjson_mut_obj_add_str(doc, root, "format", FORMAT_BACKEND_SINGLE);
  yyjson_mut_obj_add_str(doc, root, "id", d->deployment_id);
  yyjson_mut_val *xl = yyjson_mut_obj_add_obj(doc, root, "xl");
  yyjson_mut_obj_add_str(doc, xl, "version", FORMAT_ERASURE_VERSION);
  yyjson_mut_obj_add_str(doc, xl, "this", d->drive_id);
  yyjson_mut_val *sets = yyjson_mut_obj_add_arr(doc, xl, "sets");
  yyjson_mut_val *set = yyjson_mut_arr_add_arr(doc, sets);
  yyjson_mut_arr_add_str(doc, set, d->drive_id);
  yyjson_mut_obj_add_str(doc, xl, "distributionAlgo", FORMAT_DISTRIBUTION_ALGO);

  size_t len = 0;
  char *json = yyjson_mut_write(doc, 0, &len);
  yyjson_mut_doc_free(doc);
  if (!json) return BUCKETS_DRIVE_ERR_IO;
  char *meta = path_join(d->root, BUCKETS_META_BUCKET);
  buckets_drive_err err = write_atomic(d, meta, "format.json", json, len);
  free(meta);
  free(json);
  return err;
}

static buckets_drive_err read_format(buckets_drive *d, const char *path) {
  yyjson_read_err rerr;
  yyjson_doc *doc = yyjson_read_file(path, 0, NULL, &rerr);
  if (!doc) return BUCKETS_DRIVE_ERR_CORRUPT;
  buckets_drive_err err = BUCKETS_DRIVE_OK;
  yyjson_val *root = yyjson_doc_get_root(doc);
  const char *version = yyjson_get_str(yyjson_obj_get(root, "version"));
  const char *format = yyjson_get_str(yyjson_obj_get(root, "format"));
  const char *id = yyjson_get_str(yyjson_obj_get(root, "id"));
  yyjson_val *xl = yyjson_obj_get(root, "xl");
  const char *this_id = yyjson_get_str(yyjson_obj_get(xl, "this"));
  const char *xl_version = yyjson_get_str(yyjson_obj_get(xl, "version"));
  if (!version || !format || !id || !this_id || !xl_version || strcmp(version, FORMAT_META_VERSION) != 0 ||
      strlen(id) != BUCKETS_UUID_STR_LEN || strlen(this_id) != BUCKETS_UUID_STR_LEN) {
    err = BUCKETS_DRIVE_ERR_CORRUPT;
  } else if (strcmp(format, FORMAT_BACKEND_SINGLE) != 0 || strcmp(xl_version, FORMAT_ERASURE_VERSION) != 0) {
    /* Multi-drive "xl" drives are adopted by the erasure layer, not here. */
    err = BUCKETS_DRIVE_ERR_FOREIGN;
  } else {
    memcpy(d->deployment_id, id, BUCKETS_UUID_STR_LEN + 1);
    memcpy(d->drive_id, this_id, BUCKETS_UUID_STR_LEN + 1);
  }
  yyjson_doc_free(doc);
  return err;
}

static buckets_drive_err drive_prepare(const char *path, buckets_drive **out);

buckets_drive_err buckets_drive_open_raw(const char *path, buckets_drive **out) { return drive_prepare(path, out); }

static buckets_drive_err drive_prepare(const char *path, buckets_drive **out) {
  buckets_drive *d = buckets_xcalloc(1, sizeof(*d));
  d->root = buckets_path_clean(path);
  static const char *const meta_dirs[] = {"tmp", "buckets", "multipart", "config"};
  for (size_t i = 0; i < BUCKETS_ARRAY_LEN(meta_dirs); i++) {
    buckets_buf p = BUCKETS_BUF_INIT;
    buckets_buf_appendf(&p, "%s/" BUCKETS_META_BUCKET "/%s", d->root, meta_dirs[i]);
    int rc = mkdir_p(p.data);
    buckets_buf_free(&p);
    if (rc != 0) {
      buckets_drive_close(d);
      return BUCKETS_DRIVE_ERR_IO;
    }
  }
  *out = d;
  return BUCKETS_DRIVE_OK;
}

buckets_drive_err buckets_drive_open(const char *path, buckets_drive **out) {
  buckets_drive *d = buckets_xcalloc(1, sizeof(*d));
  d->root = buckets_path_clean(path);

  static const char *const meta_dirs[] = {"tmp", "buckets", "multipart", "config"};
  buckets_drive_err err = BUCKETS_DRIVE_OK;
  for (size_t i = 0; i < BUCKETS_ARRAY_LEN(meta_dirs); i++) {
    buckets_buf p = BUCKETS_BUF_INIT;
    buckets_buf_appendf(&p, "%s/" BUCKETS_META_BUCKET "/%s", d->root, meta_dirs[i]);
    int rc = mkdir_p(p.data);
    buckets_buf_free(&p);
    if (rc != 0) {
      buckets_log_error("create %s/%s: %s", d->root, meta_dirs[i], strerror(errno));
      err = BUCKETS_DRIVE_ERR_IO;
      goto fail;
    }
  }

  char *fmt = path_join(d->root, BUCKETS_META_BUCKET "/format.json");
  struct stat st;
  if (buckets_os_stat(fmt, &st) == 0) {
    err = read_format(d, fmt);
  } else if (errno == ENOENT) {
    buckets_uuid_v4(d->deployment_id);
    buckets_uuid_v4(d->drive_id);
    err = write_format(d);
    d->freshly_formatted = err == BUCKETS_DRIVE_OK;
  } else {
    err = BUCKETS_DRIVE_ERR_IO;
  }
  free(fmt);
  if (err != BUCKETS_DRIVE_OK) goto fail;
  *out = d;
  return BUCKETS_DRIVE_OK;

fail:
  buckets_drive_close(d);
  return err;
}

void buckets_drive_close(buckets_drive *d) {
  if (!d) return;
  buckets_drive_stats_free(d);
  buckets_rdrive_free(d->remote);
  free(d->root);
  free(d);
}

static buckets_drive_err drive_make_vol(buckets_drive *d, const char *name) {
  if (d->remote) return buckets_rdrive_make_vol(d, name);
  char *p = path_join(d->root, name);
  buckets_drive_err err = buckets_os_mkdir(p, 0755) == 0 ? BUCKETS_DRIVE_OK : from_errno(errno);
  if (err == BUCKETS_DRIVE_OK) fsync_dir(d->root);
  free(p);
  return err;
}

static buckets_drive_err drive_stat_vol(buckets_drive *d, const char *name, time_t *created) {
  if (d->remote) return buckets_rdrive_stat_vol(d, name, created);
  char *p = path_join(d->root, name);
  struct stat st;
  buckets_drive_err err = BUCKETS_DRIVE_OK;
  if (buckets_os_stat(p, &st) != 0) {
    err = from_errno(errno);
  } else if (!S_ISDIR(st.st_mode)) {
    err = BUCKETS_DRIVE_ERR_NOT_FOUND;
  } else if (created) {
    /* Same as MinIO's StatVol (directory mtime). The authoritative creation
     * time moves to .minio.sys/buckets/<b>/.metadata.bin with bucket metadata. */
    *created = st.st_mtime;
  }
  free(p);
  return err;
}

static buckets_drive_err drive_delete_vol(buckets_drive *d, const char *name) {
  if (d->remote) return buckets_rdrive_delete_vol(d, name);
  char *p = path_join(d->root, name);
  buckets_drive_err err = BUCKETS_DRIVE_OK;
  if (buckets_os_rmdir(p) != 0) {
    /* POSIX allows EEXIST for a non-empty directory. */
    err = errno == EEXIST ? BUCKETS_DRIVE_ERR_NOT_EMPTY : from_errno(errno);
  } else {
    fsync_dir(d->root);
  }
  free(p);
  return err;
}

static int vol_cmp(const void *a, const void *b) {
  return strcmp(((const buckets_vol_info *)a)->name, ((const buckets_vol_info *)b)->name);
}

static buckets_drive_err drive_list_vols(buckets_drive *d, buckets_vol_info **vols, size_t *n) {
  if (d->remote) return buckets_rdrive_list_vols(d, vols, n);
  *vols = NULL;
  *n = 0;
  DIR *dir = buckets_os_opendir(d->root);
  if (!dir) return from_errno(errno);
  struct dirent *ent;
  size_t cap = 0;
  while ((ent = readdir(dir)) != NULL) {
    if (ent->d_name[0] == '.') continue;
    time_t created;
    if (buckets_drive_stat_vol(d, ent->d_name, &created) != BUCKETS_DRIVE_OK) continue;
    if (*n == cap) {
      cap = cap ? cap * 2 : 16;
      *vols = buckets_xrealloc(*vols, cap * sizeof(buckets_vol_info));
    }
    (*vols)[(*n)++] = (buckets_vol_info){buckets_xstrdup(ent->d_name), created};
  }
  closedir(dir);
  if (*n) qsort(*vols, *n, sizeof(buckets_vol_info), vol_cmp);
  return BUCKETS_DRIVE_OK;
}

void buckets_vol_info_free(buckets_vol_info *vols, size_t n) {
  for (size_t i = 0; i < n; i++) free(vols[i].name);
  free(vols);
}

/* ---- StorageAPI ------------------------------------------------------------ */

static char *vpath(buckets_drive *d, const char *vol, const char *path) {
  buckets_buf p = BUCKETS_BUF_INIT;
  if (path && *path) buckets_buf_appendf(&p, "%s/%s/%s", d->root, vol, path);
  else buckets_buf_appendf(&p, "%s/%s", d->root, vol);
  return p.data;
}

char *buckets_drive_tmp_name(void) {
  char id[BUCKETS_UUID_STR_LEN + 1];
  buckets_uuid_v4(id);
  return buckets_xstrdup(id);
}

static void parent_mkdir(const char *path) {
  char *dup = buckets_xstrdup(path);
  char *slash = strrchr(dup, '/');
  if (slash && slash != dup) {
    *slash = '\0';
    mkdir_p(dup);
  }
  free(dup);
}

static buckets_drive_err drive_read_all(buckets_drive *d, const char *vol, const char *path, buckets_buf *out) {
  if (d->remote) return buckets_rdrive_read_all(d, vol, path, out);
  char *p = vpath(d, vol, path);
  int fd = buckets_os_open(p, O_RDONLY | O_CLOEXEC);
  free(p);
  if (fd < 0) return from_errno(errno == ENOTDIR ? ENOENT : errno);
  char tmp[65536];
  buckets_drive_err err = BUCKETS_DRIVE_OK;
  for (;;) {
    ssize_t r = read(fd, tmp, sizeof(tmp));
    if (r < 0 && errno == EINTR) continue;
    if (r < 0) {
      err = errno == EISDIR ? BUCKETS_DRIVE_ERR_NOT_FOUND : BUCKETS_DRIVE_ERR_IO;
      break;
    }
    if (r == 0) break;
    buckets_buf_append(out, tmp, (size_t)r);
  }
  close(fd);
  return err;
}

static buckets_drive_err drive_write_all(buckets_drive *d, const char *vol, const char *path, const void *data,
                                          size_t n) {
  if (d->remote) return buckets_rdrive_write_all(d, vol, path, data, n);
  char *dst = vpath(d, vol, path);
  parent_mkdir(dst);
  char *dir = buckets_xstrdup(dst);
  char *slash = strrchr(dir, '/');
  if (slash) *slash = '\0';
  const char *name = slash ? slash + 1 : dst;
  buckets_drive_err err = write_atomic(d, dir, name, data, n);
  free(dir);
  free(dst);
  return err;
}

#define WRITER_BUFFER (1u << 20)

/* Local writers buffer in user space: shard blocks arrive as a 32-byte hash
 * plus a shard, and two syscalls per block per drive added up. */
struct buckets_drive_writer {
  int fd;
  char *path;
  struct buckets_rwriter *remote;
  uint8_t *buf;
  size_t len;
};

static buckets_drive_err write_fd(int fd, const void *data, size_t n) {
  const char *c = data;
  while (n) {
    ssize_t r = write(fd, c, n);
    if (r < 0 && errno == EINTR) continue;
    if (r < 0) return BUCKETS_DRIVE_ERR_IO;
    c += r;
    n -= (size_t)r;
  }
  return BUCKETS_DRIVE_OK;
}

static buckets_drive_err writer_flush(buckets_drive_writer *w) {
  buckets_drive_err e = w->len ? write_fd(w->fd, w->buf, w->len) : BUCKETS_DRIVE_OK;
  w->len = 0;
  return e;
}

static buckets_drive_err drive_create_file(buckets_drive *d, const char *vol, const char *path,
                                            buckets_drive_writer **w) {
  if (d->remote) return buckets_rdrive_create_file(d, vol, path, w);
  char *p = vpath(d, vol, path);
  parent_mkdir(p);
  int fd = buckets_os_open(p, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
  if (fd < 0) {
    buckets_drive_err e = from_errno(errno);
    free(p);
    return e;
  }
  *w = buckets_xcalloc(1, sizeof(**w));
  (*w)->fd = fd;
  (*w)->path = p;
  return BUCKETS_DRIVE_OK;
}

buckets_drive_writer *buckets_drive_writer_wrap_remote(struct buckets_rwriter *rw) {
  buckets_drive_writer *w = buckets_xcalloc(1, sizeof(*w));
  w->fd = -1;
  w->remote = rw;
  return w;
}

buckets_drive_err buckets_drive_writer_write(buckets_drive_writer *w, const void *data, size_t n) {
  if (w->remote) return buckets_rwriter_write(w->remote, data, n);
  if (w->len + n > WRITER_BUFFER) {
    buckets_drive_err e = writer_flush(w);
    if (e) return e;
  }
  if (n >= WRITER_BUFFER) return write_fd(w->fd, data, n);
  if (!w->buf) w->buf = buckets_xmalloc(WRITER_BUFFER);
  memcpy(w->buf + w->len, data, n);
  w->len += n;
  return BUCKETS_DRIVE_OK;
}

buckets_drive_err buckets_drive_writer_close(buckets_drive_writer *w) {
  if (w->remote) {
    buckets_drive_err e = buckets_rwriter_close(w->remote);
    free(w);
    return e;
  }
  buckets_drive_err err = writer_flush(w);
  if (!err && data_sync(w->fd) != 0) err = BUCKETS_DRIVE_ERR_IO;
  close(w->fd);
  free(w->buf);
  free(w->path);
  free(w);
  return err;
}

void buckets_drive_writer_abort(buckets_drive_writer *w) {
  if (!w) return;
  if (w->remote) {
    buckets_rwriter_abort(w->remote);
    free(w);
    return;
  }
  close(w->fd);
  buckets_os_unlink(w->path);
  free(w->buf);
  free(w->path);
  free(w);
}

static buckets_drive_err drive_append(buckets_drive *d, const char *vol, const char *path, int64_t off,
                                       const void *data, size_t n) {
  if (d->remote) return buckets_rdrive_append(d, vol, path, off, data, n);
  char *p = vpath(d, vol, path);
  int fd = buckets_os_open(p, O_WRONLY | O_CLOEXEC);
  free(p);
  if (fd < 0) return from_errno(errno);
  struct stat st;
  buckets_drive_err err = BUCKETS_DRIVE_OK;
  if (fstat(fd, &st) != 0 || st.st_size != off) {
    err = BUCKETS_DRIVE_ERR_IO;
  } else {
    const char *c = data;
    while (n) {
      ssize_t w = pwrite(fd, c, n, (off_t)off);
      if (w < 0 && errno == EINTR) continue;
      if (w < 0) {
        err = BUCKETS_DRIVE_ERR_IO;
        break;
      }
      c += w;
      n -= (size_t)w;
      off += w;
    }
  }
  close(fd);
  return err;
}

static buckets_drive_err drive_fsync_file(buckets_drive *d, const char *vol, const char *path) {
  if (d->remote) return buckets_rdrive_fsync_file(d, vol, path);
  char *p = vpath(d, vol, path);
  int fd = buckets_os_open(p, O_RDONLY | O_CLOEXEC);
  free(p);
  if (fd < 0) return from_errno(errno);
  buckets_drive_err err = data_sync(fd) == 0 ? BUCKETS_DRIVE_OK : BUCKETS_DRIVE_ERR_IO;
  close(fd);
  return err;
}

struct buckets_drive_file {
  buckets_drive *d;
  int fd;           /* local */
  char *vol, *path; /* remote */
};

static buckets_drive_err drive_open_file(buckets_drive *d, const char *vol, const char *path, buckets_drive_file **f) {
  int fd = -1;
  if (!d->remote) {
    char *p = vpath(d, vol, path);
    fd = buckets_os_open(p, O_RDONLY | O_CLOEXEC);
    free(p);
    if (fd < 0) return from_errno(errno == ENOTDIR ? ENOENT : errno);
  }
  *f = buckets_xcalloc(1, sizeof(**f));
  (*f)->d = d;
  (*f)->fd = fd;
  if (d->remote) {
    (*f)->vol = buckets_xstrdup(vol);
    (*f)->path = buckets_xstrdup(path);
  }
  return BUCKETS_DRIVE_OK;
}

buckets_drive_err buckets_drive_file_read_at(buckets_drive_file *f, int64_t off, void *buf, size_t n, size_t *got) {
  if (f->d->remote) return buckets_rdrive_read_at(f->d, f->vol, f->path, off, buf, n, got);
  *got = 0;
  while (*got < n) {
    ssize_t r = pread(f->fd, (char *)buf + *got, n - *got, (off_t)(off + (int64_t)*got));
    if (r < 0 && errno == EINTR) continue;
    if (r < 0) return BUCKETS_DRIVE_ERR_IO;
    if (r == 0) break;
    *got += (size_t)r;
  }
  return BUCKETS_DRIVE_OK;
}

void buckets_drive_file_close(buckets_drive_file *f) {
  if (!f) return;
  if (f->fd >= 0) close(f->fd);
  free(f->vol);
  free(f->path);
  free(f);
}

static buckets_drive_err drive_read_at(buckets_drive *d, const char *vol, const char *path, int64_t off, void *buf,
                                        size_t n, size_t *got) {
  if (d->remote) return buckets_rdrive_read_at(d, vol, path, off, buf, n, got);
  char *p = vpath(d, vol, path);
  int fd = buckets_os_open(p, O_RDONLY | O_CLOEXEC);
  free(p);
  *got = 0;
  if (fd < 0) return from_errno(errno == ENOTDIR ? ENOENT : errno);
  buckets_drive_err err = BUCKETS_DRIVE_OK;
  while (*got < n) {
    ssize_t r = pread(fd, (char *)buf + *got, n - *got, (off_t)(off + (int64_t)*got));
    if (r < 0 && errno == EINTR) continue;
    if (r < 0) {
      err = BUCKETS_DRIVE_ERR_IO;
      break;
    }
    if (r == 0) break;
    *got += (size_t)r;
  }
  close(fd);
  return err;
}

static buckets_drive_err drive_rename_data(buckets_drive *d, const char *src_vol, const char *src_dir,
                                            const char *data_dir, const char *dst_vol, const char *dst_path,
                                            const void *xlmeta, size_t xlmeta_len) {
  if (d->remote) return buckets_rdrive_rename_data(d, src_vol, src_dir, data_dir, dst_vol, dst_path, xlmeta, xlmeta_len);
  char *dst = vpath(d, dst_vol, dst_path);
  if (mkdir_p(dst) != 0) {
    free(dst);
    return BUCKETS_DRIVE_ERR_IO;
  }
  buckets_drive_err err = BUCKETS_DRIVE_OK;
  if (data_dir) {
    buckets_buf from = BUCKETS_BUF_INIT, to = BUCKETS_BUF_INIT;
    buckets_buf_appendf(&from, "%s/%s/%s/%s", d->root, src_vol, src_dir, data_dir);
    buckets_buf_appendf(&to, "%s/%s", dst, data_dir);
    if (buckets_os_rename(from.data, to.data) != 0) err = from_errno(errno);
    buckets_buf_free(&from);
    buckets_buf_free(&to);
  }
  if (!err) err = write_atomic(d, dst, "xl.meta", xlmeta, xlmeta_len);
  free(dst);
  return err;
}

static int rm_entry(const char *path, const struct stat *st, int flag, struct FTW *ftw) {
  return remove(path) == 0 || errno == ENOENT ? 0 : -1;
}

static buckets_drive_err drive_delete(buckets_drive *d, const char *vol, const char *path, bool recursive,
                                       bool prune) {
  if (d->remote) return buckets_rdrive_delete(d, vol, path, recursive, prune);
  char *p = vpath(d, vol, path);
  buckets_drive_err err = BUCKETS_DRIVE_OK;
  struct stat st;
  if (buckets_os_lstat(p, &st) != 0) {
    err = from_errno(errno);
  } else if (S_ISDIR(st.st_mode) && recursive) {
    /* Move aside first so readers never see a half-deleted tree. */
    char *id = buckets_drive_tmp_name();
    buckets_buf trash = BUCKETS_BUF_INIT;
    buckets_buf_appendf(&trash, "%s/" BUCKETS_META_BUCKET "/tmp/%s", d->root, id);
    free(id);
    if (buckets_os_rename(p, trash.data) != 0) err = from_errno(errno);
    else nftw(trash.data, rm_entry, 16, FTW_DEPTH | FTW_PHYS);
    buckets_buf_free(&trash);
  } else if (remove(p) != 0) {
    err = from_errno(errno);
  }
  if (!err && prune) {
    buckets_buf stop = BUCKETS_BUF_INIT;
    buckets_buf_appendf(&stop, "%s/%s", d->root, vol);
    for (;;) {
      char *slash = strrchr(p, '/');
      if (!slash) break;
      *slash = '\0';
      if (strlen(p) <= stop.len || buckets_os_rmdir(p) != 0) break;
    }
    buckets_buf_free(&stop);
  }
  free(p);
  return err;
}

static buckets_drive_err drive_list_dir(buckets_drive *d, const char *vol, const char *dir, buckets_dir_list *out) {
  if (d->remote) return buckets_rdrive_list_dir(d, vol, dir, out);
  memset(out, 0, sizeof(*out));
  char *p = vpath(d, vol, dir);
  DIR *dh = buckets_os_opendir(p);
  if (!dh) {
    buckets_drive_err e = from_errno(errno == ENOTDIR ? ENOENT : errno);
    free(p);
    return e;
  }
  size_t cap = 0;
  struct dirent *e;
  while ((e = readdir(dh))) {
    if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
    buckets_buf child = BUCKETS_BUF_INIT;
    buckets_buf_appendf(&child, "%s/%s", p, e->d_name);
    struct stat st;
    bool isdir = buckets_os_stat(child.data, &st) == 0 && S_ISDIR(st.st_mode);
    buckets_buf_free(&child);
    if (out->n == cap) {
      cap = cap ? cap * 2 : 32;
      out->names = buckets_xrealloc(out->names, cap * sizeof(char *));
    }
    buckets_buf name = BUCKETS_BUF_INIT;
    buckets_buf_appendf(&name, "%s%s", e->d_name, isdir ? "/" : "");
    out->names[out->n++] = name.data;
  }
  closedir(dh);
  free(p);
  return BUCKETS_DRIVE_OK;
}

void buckets_dir_list_free(buckets_dir_list *l) {
  for (size_t i = 0; i < l->n; i++) free(l->names[i]);
  free(l->names);
  memset(l, 0, sizeof(*l));
}

static buckets_drive_err drive_disk_info(buckets_drive *d, uint64_t *total, uint64_t *free_bytes) {
  if (d->remote) return buckets_rdrive_disk_info(d, total, free_bytes);
  struct statvfs sv;
  if (statvfs(d->root, &sv) != 0) return from_errno(errno);
  *total = (uint64_t)sv.f_blocks * sv.f_frsize;
  *free_bytes = (uint64_t)sv.f_bavail * sv.f_frsize;
  return BUCKETS_DRIVE_OK;
}

static buckets_drive_err drive_file_size(buckets_drive *d, const char *vol, const char *path, int64_t *size) {
  if (d->remote) return buckets_rdrive_file_size(d, vol, path, size);
  char *p = vpath(d, vol, path);
  struct stat st;
  buckets_drive_err err = buckets_os_stat(p, &st) != 0 ? from_errno(errno) : S_ISREG(st.st_mode) ? BUCKETS_DRIVE_OK
                                                                                     : BUCKETS_DRIVE_ERR_NOT_FOUND;
  if (!err) *size = (int64_t)st.st_size;
  free(p);
  return err;
}

int buckets_drive_stat(buckets_drive *d, const char *vol, const char *path) {
  if (d->remote) return buckets_rdrive_stat(d, vol, path);
  char *p = vpath(d, vol, path);
  struct stat st;
  int r = buckets_os_stat(p, &st) != 0 ? 0 : S_ISDIR(st.st_mode) ? 2 : 1;
  free(p);
  return r;
}

static buckets_drive_err drive_rename_file(buckets_drive *d, const char *src_vol, const char *src,
                                            const char *dst_vol, const char *dst) {
  if (d->remote) return buckets_rdrive_rename_file(d, src_vol, src, dst_vol, dst);
  char *from = vpath(d, src_vol, src), *to = vpath(d, dst_vol, dst);
  parent_mkdir(to);
  buckets_drive_err err = buckets_os_rename(from, to) == 0 ? BUCKETS_DRIVE_OK : from_errno(errno);
  free(from);
  free(to);
  return err;
}


/* storageTrace: the drive and the call's paths, joined by spaces */
static void drive_trace(buckets_drive *d, buckets_drive_op op, struct timespec t0, struct timespec t1, buckets_drive_err e,
                        int npaths, ...) {
  buckets_buf path = BUCKETS_BUF_INIT;
  buckets_buf_append_c(&path, d->root);
  va_list ap;
  va_start(ap, npaths);
  for (int i = 0; i < npaths; i++) {
    const char *p = va_arg(ap, const char *);
    if (p && *p) buckets_buf_append_char(&path, ' '), buckets_buf_append_c(&path, p);
  }
  va_end(ap);
  struct timespec w;
  clock_gettime(CLOCK_REALTIME, &w);
  int64_t dur = (t1.tv_sec - t0.tv_sec) * 1000000000LL + (t1.tv_nsec - t0.tv_nsec);
  int64_t start = (int64_t)w.tv_sec * 1000000000LL + w.tv_nsec - dur;
  char when[64], func[64];
  buckets_time_rfc3339_nano(start / 1000000000LL, (long)(start % 1000000000LL), when);
  snprintf(func, sizeof(func), "storage.%s", buckets_drive_op_name(op));
  buckets_buf j = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&j, "{\"type\":%u,\"nodename\":", (unsigned)BUCKETS_TRACE_STORAGE);
  const char *node = buckets_trace_node();
  buckets_json_go_string(&j, node, strlen(node));
  buckets_buf_appendf(&j, ",\"funcname\":\"%s\",\"time\":\"%s\",\"path\":", func, when);
  buckets_json_go_string(&j, path.data, path.len);
  buckets_buf_appendf(&j, ",\"dur\":%lld", (long long)dur);
  if (e) {
    const char *msg = buckets_drive_strerror(e);
    buckets_buf_append_c(&j, ",\"error\":");
    buckets_json_go_string(&j, msg, strlen(msg));
  }
  buckets_buf_append_char(&j, '}');
  buckets_trace_meta m = {.type = BUCKETS_TRACE_STORAGE, .dur_ns = dur};
  buckets_trace_publish(&m, j.data, j.len);
  buckets_buf_free(&j);
  buckets_buf_free(&path);
}

/* ---- the public calls, timed for the drive metrics ---- */

buckets_drive_err buckets_drive_make_vol(buckets_drive *d, const char *name) {
  struct timespec t0, t1;
  buckets_drive_stats_begin(d);
  clock_gettime(CLOCK_MONOTONIC, &t0);
  buckets_drive_err e = drive_make_vol(d, name);
  clock_gettime(CLOCK_MONOTONIC, &t1);
  buckets_drive_stats_end(d, BUCKETS_DOP_MAKE_VOL, (t1.tv_sec - t0.tv_sec) * 1000000000LL + (t1.tv_nsec - t0.tv_nsec), e);
  if (buckets_trace_wanted(BUCKETS_TRACE_STORAGE)) drive_trace(d, BUCKETS_DOP_MAKE_VOL, t0, t1, e, 1, name);
  return e;
}

buckets_drive_err buckets_drive_stat_vol(buckets_drive *d, const char *name, time_t *created) {
  struct timespec t0, t1;
  buckets_drive_stats_begin(d);
  clock_gettime(CLOCK_MONOTONIC, &t0);
  buckets_drive_err e = drive_stat_vol(d, name, created);
  clock_gettime(CLOCK_MONOTONIC, &t1);
  buckets_drive_stats_end(d, BUCKETS_DOP_STAT_VOL, (t1.tv_sec - t0.tv_sec) * 1000000000LL + (t1.tv_nsec - t0.tv_nsec), e);
  if (buckets_trace_wanted(BUCKETS_TRACE_STORAGE)) drive_trace(d, BUCKETS_DOP_STAT_VOL, t0, t1, e, 1, name);
  return e;
}

buckets_drive_err buckets_drive_delete_vol(buckets_drive *d, const char *name) {
  struct timespec t0, t1;
  buckets_drive_stats_begin(d);
  clock_gettime(CLOCK_MONOTONIC, &t0);
  buckets_drive_err e = drive_delete_vol(d, name);
  clock_gettime(CLOCK_MONOTONIC, &t1);
  buckets_drive_stats_end(d, BUCKETS_DOP_DELETE_VOL, (t1.tv_sec - t0.tv_sec) * 1000000000LL + (t1.tv_nsec - t0.tv_nsec), e);
  if (buckets_trace_wanted(BUCKETS_TRACE_STORAGE)) drive_trace(d, BUCKETS_DOP_DELETE_VOL, t0, t1, e, 1, name);
  return e;
}

buckets_drive_err buckets_drive_list_vols(buckets_drive *d, buckets_vol_info **vols, size_t *n) {
  struct timespec t0, t1;
  buckets_drive_stats_begin(d);
  clock_gettime(CLOCK_MONOTONIC, &t0);
  buckets_drive_err e = drive_list_vols(d, vols, n);
  clock_gettime(CLOCK_MONOTONIC, &t1);
  buckets_drive_stats_end(d, BUCKETS_DOP_LIST_VOLS, (t1.tv_sec - t0.tv_sec) * 1000000000LL + (t1.tv_nsec - t0.tv_nsec), e);
  if (buckets_trace_wanted(BUCKETS_TRACE_STORAGE)) drive_trace(d, BUCKETS_DOP_LIST_VOLS, t0, t1, e, 0);
  return e;
}

buckets_drive_err buckets_drive_read_all(buckets_drive *d, const char *vol, const char *path, buckets_buf *out) {
  struct timespec t0, t1;
  buckets_drive_stats_begin(d);
  clock_gettime(CLOCK_MONOTONIC, &t0);
  buckets_drive_err e = drive_read_all(d, vol, path, out);
  clock_gettime(CLOCK_MONOTONIC, &t1);
  buckets_drive_stats_end(d, BUCKETS_DOP_READ_ALL, (t1.tv_sec - t0.tv_sec) * 1000000000LL + (t1.tv_nsec - t0.tv_nsec), e);
  if (buckets_trace_wanted(BUCKETS_TRACE_STORAGE)) drive_trace(d, BUCKETS_DOP_READ_ALL, t0, t1, e, 2, vol, path);
  return e;
}

buckets_drive_err buckets_drive_write_all(buckets_drive *d, const char *vol, const char *path, const void *data,
                                          size_t n) {
  struct timespec t0, t1;
  buckets_drive_stats_begin(d);
  clock_gettime(CLOCK_MONOTONIC, &t0);
  buckets_drive_err e = drive_write_all(d, vol, path, data, n);
  clock_gettime(CLOCK_MONOTONIC, &t1);
  buckets_drive_stats_end(d, BUCKETS_DOP_WRITE_ALL, (t1.tv_sec - t0.tv_sec) * 1000000000LL + (t1.tv_nsec - t0.tv_nsec), e);
  if (buckets_trace_wanted(BUCKETS_TRACE_STORAGE)) drive_trace(d, BUCKETS_DOP_WRITE_ALL, t0, t1, e, 2, vol, path);
  return e;
}

buckets_drive_err buckets_drive_create_file(buckets_drive *d, const char *vol, const char *path,
                                            buckets_drive_writer **w) {
  struct timespec t0, t1;
  buckets_drive_stats_begin(d);
  clock_gettime(CLOCK_MONOTONIC, &t0);
  buckets_drive_err e = drive_create_file(d, vol, path, w);
  clock_gettime(CLOCK_MONOTONIC, &t1);
  buckets_drive_stats_end(d, BUCKETS_DOP_CREATE_FILE, (t1.tv_sec - t0.tv_sec) * 1000000000LL + (t1.tv_nsec - t0.tv_nsec), e);
  if (buckets_trace_wanted(BUCKETS_TRACE_STORAGE)) drive_trace(d, BUCKETS_DOP_CREATE_FILE, t0, t1, e, 2, vol, path);
  return e;
}

buckets_drive_err buckets_drive_append(buckets_drive *d, const char *vol, const char *path, int64_t off,
                                       const void *data, size_t n) {
  struct timespec t0, t1;
  buckets_drive_stats_begin(d);
  clock_gettime(CLOCK_MONOTONIC, &t0);
  buckets_drive_err e = drive_append(d, vol, path, off, data, n);
  clock_gettime(CLOCK_MONOTONIC, &t1);
  buckets_drive_stats_end(d, BUCKETS_DOP_APPEND_FILE, (t1.tv_sec - t0.tv_sec) * 1000000000LL + (t1.tv_nsec - t0.tv_nsec), e);
  if (buckets_trace_wanted(BUCKETS_TRACE_STORAGE)) drive_trace(d, BUCKETS_DOP_APPEND_FILE, t0, t1, e, 2, vol, path);
  return e;
}

buckets_drive_err buckets_drive_fsync_file(buckets_drive *d, const char *vol, const char *path) {
  struct timespec t0, t1;
  buckets_drive_stats_begin(d);
  clock_gettime(CLOCK_MONOTONIC, &t0);
  buckets_drive_err e = drive_fsync_file(d, vol, path);
  clock_gettime(CLOCK_MONOTONIC, &t1);
  buckets_drive_stats_end(d, BUCKETS_DOP_FSYNC_FILE, (t1.tv_sec - t0.tv_sec) * 1000000000LL + (t1.tv_nsec - t0.tv_nsec), e);
  if (buckets_trace_wanted(BUCKETS_TRACE_STORAGE)) drive_trace(d, BUCKETS_DOP_FSYNC_FILE, t0, t1, e, 2, vol, path);
  return e;
}

buckets_drive_err buckets_drive_open_file(buckets_drive *d, const char *vol, const char *path, buckets_drive_file **f) {
  struct timespec t0, t1;
  buckets_drive_stats_begin(d);
  clock_gettime(CLOCK_MONOTONIC, &t0);
  buckets_drive_err e = drive_open_file(d, vol, path, f);
  clock_gettime(CLOCK_MONOTONIC, &t1);
  buckets_drive_stats_end(d, BUCKETS_DOP_OPEN_FILE, (t1.tv_sec - t0.tv_sec) * 1000000000LL + (t1.tv_nsec - t0.tv_nsec), e);
  if (buckets_trace_wanted(BUCKETS_TRACE_STORAGE)) drive_trace(d, BUCKETS_DOP_OPEN_FILE, t0, t1, e, 2, vol, path);
  return e;
}

buckets_drive_err buckets_drive_read_at(buckets_drive *d, const char *vol, const char *path, int64_t off, void *buf,
                                        size_t n, size_t *got) {
  struct timespec t0, t1;
  buckets_drive_stats_begin(d);
  clock_gettime(CLOCK_MONOTONIC, &t0);
  buckets_drive_err e = drive_read_at(d, vol, path, off, buf, n, got);
  clock_gettime(CLOCK_MONOTONIC, &t1);
  buckets_drive_stats_end(d, BUCKETS_DOP_READ_FILE, (t1.tv_sec - t0.tv_sec) * 1000000000LL + (t1.tv_nsec - t0.tv_nsec), e);
  if (buckets_trace_wanted(BUCKETS_TRACE_STORAGE)) drive_trace(d, BUCKETS_DOP_READ_FILE, t0, t1, e, 2, vol, path);
  return e;
}

buckets_drive_err buckets_drive_rename_data(buckets_drive *d, const char *src_vol, const char *src_dir,
                                            const char *data_dir, const char *dst_vol, const char *dst_path,
                                            const void *xlmeta, size_t xlmeta_len) {
  struct timespec t0, t1;
  buckets_drive_stats_begin(d);
  clock_gettime(CLOCK_MONOTONIC, &t0);
  buckets_drive_err e = drive_rename_data(d, src_vol, src_dir, data_dir, dst_vol, dst_path, xlmeta, xlmeta_len);
  clock_gettime(CLOCK_MONOTONIC, &t1);
  buckets_drive_stats_end(d, BUCKETS_DOP_RENAME_DATA, (t1.tv_sec - t0.tv_sec) * 1000000000LL + (t1.tv_nsec - t0.tv_nsec), e);
  if (buckets_trace_wanted(BUCKETS_TRACE_STORAGE)) drive_trace(d, BUCKETS_DOP_RENAME_DATA, t0, t1, e, 5, src_vol, src_dir, data_dir, dst_vol, dst_path);
  return e;
}

buckets_drive_err buckets_drive_delete(buckets_drive *d, const char *vol, const char *path, bool recursive,
                                       bool prune) {
  struct timespec t0, t1;
  buckets_drive_stats_begin(d);
  clock_gettime(CLOCK_MONOTONIC, &t0);
  buckets_drive_err e = drive_delete(d, vol, path, recursive, prune);
  clock_gettime(CLOCK_MONOTONIC, &t1);
  buckets_drive_stats_end(d, BUCKETS_DOP_DELETE, (t1.tv_sec - t0.tv_sec) * 1000000000LL + (t1.tv_nsec - t0.tv_nsec), e);
  if (buckets_trace_wanted(BUCKETS_TRACE_STORAGE)) drive_trace(d, BUCKETS_DOP_DELETE, t0, t1, e, 2, vol, path);
  return e;
}

buckets_drive_err buckets_drive_list_dir(buckets_drive *d, const char *vol, const char *dir, buckets_dir_list *out) {
  struct timespec t0, t1;
  buckets_drive_stats_begin(d);
  clock_gettime(CLOCK_MONOTONIC, &t0);
  buckets_drive_err e = drive_list_dir(d, vol, dir, out);
  clock_gettime(CLOCK_MONOTONIC, &t1);
  buckets_drive_stats_end(d, BUCKETS_DOP_LIST_DIR, (t1.tv_sec - t0.tv_sec) * 1000000000LL + (t1.tv_nsec - t0.tv_nsec), e);
  if (buckets_trace_wanted(BUCKETS_TRACE_STORAGE)) drive_trace(d, BUCKETS_DOP_LIST_DIR, t0, t1, e, 2, vol, dir);
  return e;
}

buckets_drive_err buckets_drive_disk_info(buckets_drive *d, uint64_t *total, uint64_t *free_bytes) {
  struct timespec t0, t1;
  buckets_drive_stats_begin(d);
  clock_gettime(CLOCK_MONOTONIC, &t0);
  buckets_drive_err e = drive_disk_info(d, total, free_bytes);
  clock_gettime(CLOCK_MONOTONIC, &t1);
  buckets_drive_stats_end(d, BUCKETS_DOP_DISK_INFO, (t1.tv_sec - t0.tv_sec) * 1000000000LL + (t1.tv_nsec - t0.tv_nsec), e);
  if (buckets_trace_wanted(BUCKETS_TRACE_STORAGE)) drive_trace(d, BUCKETS_DOP_DISK_INFO, t0, t1, e, 0);
  return e;
}

buckets_drive_err buckets_drive_file_size(buckets_drive *d, const char *vol, const char *path, int64_t *size) {
  struct timespec t0, t1;
  buckets_drive_stats_begin(d);
  clock_gettime(CLOCK_MONOTONIC, &t0);
  buckets_drive_err e = drive_file_size(d, vol, path, size);
  clock_gettime(CLOCK_MONOTONIC, &t1);
  buckets_drive_stats_end(d, BUCKETS_DOP_STAT_FILE, (t1.tv_sec - t0.tv_sec) * 1000000000LL + (t1.tv_nsec - t0.tv_nsec), e);
  if (buckets_trace_wanted(BUCKETS_TRACE_STORAGE)) drive_trace(d, BUCKETS_DOP_STAT_FILE, t0, t1, e, 2, vol, path);
  return e;
}

buckets_drive_err buckets_drive_rename_file(buckets_drive *d, const char *src_vol, const char *src,
                                            const char *dst_vol, const char *dst) {
  struct timespec t0, t1;
  buckets_drive_stats_begin(d);
  clock_gettime(CLOCK_MONOTONIC, &t0);
  buckets_drive_err e = drive_rename_file(d, src_vol, src, dst_vol, dst);
  clock_gettime(CLOCK_MONOTONIC, &t1);
  buckets_drive_stats_end(d, BUCKETS_DOP_RENAME_FILE, (t1.tv_sec - t0.tv_sec) * 1000000000LL + (t1.tv_nsec - t0.tv_nsec), e);
  if (buckets_trace_wanted(BUCKETS_TRACE_STORAGE)) drive_trace(d, BUCKETS_DOP_RENAME_FILE, t0, t1, e, 4, src_vol, src, dst_vol, dst);
  return e;
}

/* ---- StatInfoFile with globbing ------------------------------------------------------------------ */

/* path.Match on one element: '*', '?', and character classes. */
static bool match_elem(const char *p, const char *s) {
  while (*p) {
    if (*p == '*') {
      while (*p == '*') p++;
      if (!*p) return true;
      for (; *s; s++)
        if (match_elem(p, s)) return true;
      return match_elem(p, s);
    }
    if (!*s) return false;
    if (*p == '?') {
      p++, s++;
      continue;
    }
    if (*p == '[') {
      const char *q = p + 1;
      bool neg = *q == '^' || *q == '!';
      if (neg) q++;
      bool hit = false, first = true;
      while (*q && (*q != ']' || first)) {
        first = false;
        char lo = *q == '\\' && q[1] ? *++q : *q, hi = lo;
        q++;
        if (*q == '-' && q[1] && q[1] != ']') {
          q++;
          hi = *q == '\\' && q[1] ? *++q : *q;
          q++;
        }
        if (*s >= lo && *s <= hi) hit = true;
      }
      if (*q != ']') return false; /* malformed: no match */
      if (hit == neg) return false;
      p = q + 1, s++;
      continue;
    }
    if (*p == '\\' && p[1]) p++;
    if (*p != *s) return false;
    p++, s++;
  }
  return !*s;
}

/* The whole relative path, element by element; "**" spans elements. */
static bool match_path(const char *p, const char *s) {
  const char *pe = strchr(p, '/'), *se = strchr(s, '/');
  size_t pl = pe ? (size_t)(pe - p) : strlen(p), sl = se ? (size_t)(se - s) : strlen(s);
  if (pl == 2 && p[0] == '*' && p[1] == '*') {
    if (!pe) return true;                 /* trailing "**": anything below */
    if (match_path(pe + 1, s)) return true; /* zero elements */
    return se ? match_path(p, se + 1) : false;
  }
  char pat[1024], seg[1024];
  if (pl >= sizeof(pat) || sl >= sizeof(seg)) return false;
  memcpy(pat, p, pl), pat[pl] = '\0';
  memcpy(seg, s, sl), seg[sl] = '\0';
  if (!match_elem(pat, seg)) return false;
  if (!pe && !se) return true;
  if (!se && pe && strcmp(pe + 1, "**") == 0) return true; /* "**" also matches nothing */
  if (!pe || !se) return false;
  return match_path(pe + 1, se + 1);
}

static bool has_meta(const char *s) { return strpbrk(s, "*?[\\") != NULL; }

typedef struct {
  buckets_stat_info *v;
  size_t n, cap;
} stat_list;

static void stat_add(stat_list *l, const char *name, const struct stat *st) {
  if (l->n == l->cap) {
    l->cap = l->cap ? 2 * l->cap : 16;
    l->v = buckets_xrealloc(l->v, l->cap * sizeof(*l->v));
  }
  buckets_stat_info *x = &l->v[l->n++];
  x->name = buckets_xstrdup(name);
  x->size = (int64_t)st->st_size;
#ifdef __APPLE__
  x->mtime_ns = (int64_t)st->st_mtimespec.tv_sec * 1000000000LL + st->st_mtimespec.tv_nsec;
#else
  x->mtime_ns = (int64_t)st->st_mtim.tv_sec * 1000000000LL + st->st_mtim.tv_nsec;
#endif
  x->mode = (uint32_t)(st->st_mode & 07777);
  x->dir = S_ISDIR(st->st_mode);
}

/* Every entry under dir (rel: its path relative to the volume) matching pat. */
static void walk_match(const char *volroot, const char *rel, const char *pat, stat_list *l, int depth) {
  if (depth > 64 || l->n > 100000) return;
  buckets_buf path = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&path, "%s%s%s", volroot, *rel ? "/" : "", rel);
  DIR *dh = buckets_os_opendir(path.data);
  buckets_buf_free(&path);
  if (!dh) return;
  struct dirent *de;
  while ((de = readdir(dh))) {
    if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
    buckets_buf child = BUCKETS_BUF_INIT, full = BUCKETS_BUF_INIT;
    buckets_buf_appendf(&child, "%s%s%s", rel, *rel ? "/" : "", de->d_name);
    buckets_buf_appendf(&full, "%s/%s", volroot, child.data);
    struct stat st;
    if (buckets_os_lstat(full.data, &st) == 0) {
      if (match_path(pat, child.data)) stat_add(l, child.data, &st);
      if (S_ISDIR(st.st_mode)) walk_match(volroot, child.data, pat, l, depth + 1);
    }
    buckets_buf_free(&child);
    buckets_buf_free(&full);
  }
  closedir(dh);
}

static int stat_cmp(const void *a, const void *b) {
  return strcmp(((const buckets_stat_info *)a)->name, ((const buckets_stat_info *)b)->name);
}

buckets_drive_err buckets_drive_stat_info(buckets_drive *d, const char *vol, const char *path, buckets_stat_info **out,
                                          size_t *n) {
  *out = NULL;
  *n = 0;
  if (d->remote) return buckets_rdrive_stat_info(d, vol, path, out, n);
  char *volroot = vpath(d, vol, NULL);
  stat_list l = {0};
  if (!has_meta(path)) {
    buckets_buf full = BUCKETS_BUF_INIT;
    buckets_buf_appendf(&full, "%s/%s", volroot, path);
    struct stat st;
    if (buckets_os_lstat(full.data, &st) == 0) {
      /* filepath.Rel of the cleaned path */
      const char *name = path;
      while (*name == '/') name++;
      stat_add(&l, name, &st);
    }
    buckets_buf_free(&full);
  } else {
    /* walk from the literal elements before the first pattern */
    char *pat = buckets_xstrdup(path);
    char *p = pat;
    while (*p == '/') p++;
    buckets_buf start = BUCKETS_BUF_INIT;
    const char *rest = p;
    for (;;) {
      const char *slash = strchr(rest, '/');
      size_t len = slash ? (size_t)(slash - rest) : strlen(rest);
      char elem[1024];
      if (!slash || len >= sizeof(elem)) break;
      memcpy(elem, rest, len), elem[len] = '\0';
      if (has_meta(elem)) break;
      if (start.len) buckets_buf_append_char(&start, '/');
      buckets_buf_append(&start, rest, len);
      rest = slash + 1;
    }
    buckets_buf_append_char(&start, '\0');
    if (*start.data) { /* the directory the walk starts from may match itself */
      buckets_buf full = BUCKETS_BUF_INIT;
      buckets_buf_appendf(&full, "%s/%s", volroot, start.data);
      struct stat st;
      if (buckets_os_lstat(full.data, &st) == 0 && match_path(p, start.data)) stat_add(&l, start.data, &st);
      buckets_buf_free(&full);
    }
    walk_match(volroot, start.data, p, &l, 0);
    buckets_buf_free(&start);
    free(pat);
  }
  free(volroot);
  qsort(l.v, l.n, sizeof(*l.v), stat_cmp);
  *out = l.v;
  *n = l.n;
  return l.n ? BUCKETS_DRIVE_OK : BUCKETS_DRIVE_ERR_NOT_FOUND;
}

void buckets_stat_info_free(buckets_stat_info *s, size_t n) {
  for (size_t i = 0; i < n; i++) free(s[i].name);
  free(s);
}

void buckets_stat_info_json(const buckets_stat_info *s, size_t n, buckets_buf *out) {
  yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *arr = yyjson_mut_arr(doc);
  yyjson_mut_doc_set_root(doc, arr);
  for (size_t i = 0; i < n; i++) {
    yyjson_mut_val *o = yyjson_mut_arr_add_obj(doc, arr);
    yyjson_mut_obj_add_strcpy(doc, o, "name", s[i].name);
    yyjson_mut_obj_add_int(doc, o, "size", s[i].size);
    yyjson_mut_obj_add_int(doc, o, "mtime", s[i].mtime_ns);
    yyjson_mut_obj_add_uint(doc, o, "mode", s[i].mode);
    yyjson_mut_obj_add_bool(doc, o, "dir", s[i].dir);
  }
  size_t len;
  char *json = yyjson_mut_write(doc, 0, &len);
  buckets_buf_append(out, json, len);
  free(json);
  yyjson_mut_doc_free(doc);
}

bool buckets_stat_info_parse(const char *json, size_t len, buckets_stat_info **out, size_t *n) {
  *out = NULL;
  *n = 0;
  yyjson_doc *doc = yyjson_read(json, len, 0);
  yyjson_val *arr = yyjson_doc_get_root(doc);
  if (!yyjson_is_arr(arr)) {
    yyjson_doc_free(doc);
    return false;
  }
  *out = buckets_xcalloc(yyjson_arr_size(arr) + 1, sizeof(**out));
  size_t i, max;
  yyjson_val *o;
  yyjson_arr_foreach(arr, i, max, o) {
    buckets_stat_info *x = &(*out)[(*n)++];
    const char *name = yyjson_get_str(yyjson_obj_get(o, "name"));
    x->name = buckets_xstrdup(name ? name : "");
    x->size = yyjson_get_sint(yyjson_obj_get(o, "size"));
    x->mtime_ns = yyjson_get_sint(yyjson_obj_get(o, "mtime"));
    x->mode = (uint32_t)yyjson_get_uint(yyjson_obj_get(o, "mode"));
    x->dir = yyjson_get_bool(yyjson_obj_get(o, "dir"));
  }
  yyjson_doc_free(doc);
  return true;
}
