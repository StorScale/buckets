/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "storage/drive.h"
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

/* Data durability for file contents: fdatasync where the platform has it
 * (skips metadata-only flushes, as MinIO's Fdatasync), fsync elsewhere. */
static int data_sync(int fd) {
#if defined(__linux__)
  return fdatasync(fd);
#else
  return fsync(fd);
#endif
}

static int fsync_dir(const char *dir) {
  int fd = open(dir, O_RDONLY);
  if (fd < 0) return -1;
  int rc = fsync(fd);
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

  int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
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
  if (err == BUCKETS_DRIVE_OK && rename(tmp, dst) != 0) err = from_errno(errno);
  if (err == BUCKETS_DRIVE_OK) fsync_dir(dir);
  if (err != BUCKETS_DRIVE_OK) unlink(tmp);
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
  d->root = buckets_xstrdup(path);
  size_t rl = strlen(d->root);
  while (rl > 1 && d->root[rl - 1] == '/') d->root[--rl] = '\0';
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
  d->root = buckets_xstrdup(path);
  size_t rl = strlen(d->root);
  while (rl > 1 && d->root[rl - 1] == '/') d->root[--rl] = '\0';

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
  if (stat(fmt, &st) == 0) {
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
  buckets_rdrive_free(d->remote);
  free(d->root);
  free(d);
}

buckets_drive_err buckets_drive_make_vol(buckets_drive *d, const char *name) {
  if (d->remote) return buckets_rdrive_make_vol(d, name);
  char *p = path_join(d->root, name);
  buckets_drive_err err = mkdir(p, 0755) == 0 ? BUCKETS_DRIVE_OK : from_errno(errno);
  if (err == BUCKETS_DRIVE_OK) fsync_dir(d->root);
  free(p);
  return err;
}

buckets_drive_err buckets_drive_stat_vol(buckets_drive *d, const char *name, time_t *created) {
  if (d->remote) return buckets_rdrive_stat_vol(d, name, created);
  char *p = path_join(d->root, name);
  struct stat st;
  buckets_drive_err err = BUCKETS_DRIVE_OK;
  if (stat(p, &st) != 0) {
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

buckets_drive_err buckets_drive_delete_vol(buckets_drive *d, const char *name) {
  if (d->remote) return buckets_rdrive_delete_vol(d, name);
  char *p = path_join(d->root, name);
  buckets_drive_err err = BUCKETS_DRIVE_OK;
  if (rmdir(p) != 0) {
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

buckets_drive_err buckets_drive_list_vols(buckets_drive *d, buckets_vol_info **vols, size_t *n) {
  if (d->remote) return buckets_rdrive_list_vols(d, vols, n);
  *vols = NULL;
  *n = 0;
  DIR *dir = opendir(d->root);
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

buckets_drive_err buckets_drive_read_all(buckets_drive *d, const char *vol, const char *path, buckets_buf *out) {
  if (d->remote) return buckets_rdrive_read_all(d, vol, path, out);
  char *p = vpath(d, vol, path);
  int fd = open(p, O_RDONLY | O_CLOEXEC);
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

buckets_drive_err buckets_drive_write_all(buckets_drive *d, const char *vol, const char *path, const void *data,
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

struct buckets_drive_writer {
  int fd;
  char *path;
  struct buckets_rwriter *remote;
};

buckets_drive_err buckets_drive_create_file(buckets_drive *d, const char *vol, const char *path,
                                            buckets_drive_writer **w) {
  if (d->remote) return buckets_rdrive_create_file(d, vol, path, w);
  char *p = vpath(d, vol, path);
  parent_mkdir(p);
  int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
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
  const char *c = data;
  while (n) {
    ssize_t r = write(w->fd, c, n);
    if (r < 0 && errno == EINTR) continue;
    if (r < 0) return BUCKETS_DRIVE_ERR_IO;
    c += r;
    n -= (size_t)r;
  }
  return BUCKETS_DRIVE_OK;
}

buckets_drive_err buckets_drive_writer_close(buckets_drive_writer *w) {
  if (w->remote) {
    buckets_drive_err e = buckets_rwriter_close(w->remote);
    free(w);
    return e;
  }
  buckets_drive_err err = data_sync(w->fd) == 0 ? BUCKETS_DRIVE_OK : BUCKETS_DRIVE_ERR_IO;
  close(w->fd);
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
  unlink(w->path);
  free(w->path);
  free(w);
}

buckets_drive_err buckets_drive_append(buckets_drive *d, const char *vol, const char *path, int64_t off,
                                       const void *data, size_t n) {
  if (d->remote) return buckets_rdrive_append(d, vol, path, off, data, n);
  char *p = vpath(d, vol, path);
  int fd = open(p, O_WRONLY | O_CLOEXEC);
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

buckets_drive_err buckets_drive_fsync_file(buckets_drive *d, const char *vol, const char *path) {
  if (d->remote) return buckets_rdrive_fsync_file(d, vol, path);
  char *p = vpath(d, vol, path);
  int fd = open(p, O_RDONLY | O_CLOEXEC);
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

buckets_drive_err buckets_drive_open_file(buckets_drive *d, const char *vol, const char *path, buckets_drive_file **f) {
  int fd = -1;
  if (!d->remote) {
    char *p = vpath(d, vol, path);
    fd = open(p, O_RDONLY | O_CLOEXEC);
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

buckets_drive_err buckets_drive_read_at(buckets_drive *d, const char *vol, const char *path, int64_t off, void *buf,
                                        size_t n, size_t *got) {
  if (d->remote) return buckets_rdrive_read_at(d, vol, path, off, buf, n, got);
  char *p = vpath(d, vol, path);
  int fd = open(p, O_RDONLY | O_CLOEXEC);
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

buckets_drive_err buckets_drive_rename_data(buckets_drive *d, const char *src_vol, const char *src_dir,
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
    if (rename(from.data, to.data) != 0) err = from_errno(errno);
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

buckets_drive_err buckets_drive_delete(buckets_drive *d, const char *vol, const char *path, bool recursive,
                                       bool prune) {
  if (d->remote) return buckets_rdrive_delete(d, vol, path, recursive, prune);
  char *p = vpath(d, vol, path);
  buckets_drive_err err = BUCKETS_DRIVE_OK;
  struct stat st;
  if (lstat(p, &st) != 0) {
    err = from_errno(errno);
  } else if (S_ISDIR(st.st_mode) && recursive) {
    /* Move aside first so readers never see a half-deleted tree. */
    char *id = buckets_drive_tmp_name();
    buckets_buf trash = BUCKETS_BUF_INIT;
    buckets_buf_appendf(&trash, "%s/" BUCKETS_META_BUCKET "/tmp/%s", d->root, id);
    free(id);
    if (rename(p, trash.data) != 0) err = from_errno(errno);
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
      if (strlen(p) <= stop.len || rmdir(p) != 0) break;
    }
    buckets_buf_free(&stop);
  }
  free(p);
  return err;
}

buckets_drive_err buckets_drive_list_dir(buckets_drive *d, const char *vol, const char *dir, buckets_dir_list *out) {
  if (d->remote) return buckets_rdrive_list_dir(d, vol, dir, out);
  memset(out, 0, sizeof(*out));
  char *p = vpath(d, vol, dir);
  DIR *dh = opendir(p);
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
    bool isdir = stat(child.data, &st) == 0 && S_ISDIR(st.st_mode);
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

buckets_drive_err buckets_drive_disk_info(buckets_drive *d, uint64_t *total, uint64_t *free_bytes) {
  if (d->remote) return buckets_rdrive_disk_info(d, total, free_bytes);
  struct statvfs sv;
  if (statvfs(d->root, &sv) != 0) return from_errno(errno);
  *total = (uint64_t)sv.f_blocks * sv.f_frsize;
  *free_bytes = (uint64_t)sv.f_bavail * sv.f_frsize;
  return BUCKETS_DRIVE_OK;
}

buckets_drive_err buckets_drive_file_size(buckets_drive *d, const char *vol, const char *path, int64_t *size) {
  if (d->remote) return buckets_rdrive_file_size(d, vol, path, size);
  char *p = vpath(d, vol, path);
  struct stat st;
  buckets_drive_err err = stat(p, &st) != 0 ? from_errno(errno) : S_ISREG(st.st_mode) ? BUCKETS_DRIVE_OK
                                                                                     : BUCKETS_DRIVE_ERR_NOT_FOUND;
  if (!err) *size = (int64_t)st.st_size;
  free(p);
  return err;
}

int buckets_drive_stat(buckets_drive *d, const char *vol, const char *path) {
  if (d->remote) return buckets_rdrive_stat(d, vol, path);
  char *p = vpath(d, vol, path);
  struct stat st;
  int r = stat(p, &st) != 0 ? 0 : S_ISDIR(st.st_mode) ? 2 : 1;
  free(p);
  return r;
}

buckets_drive_err buckets_drive_rename_file(buckets_drive *d, const char *src_vol, const char *src,
                                            const char *dst_vol, const char *dst) {
  if (d->remote) return buckets_rdrive_rename_file(d, src_vol, src, dst_vol, dst);
  char *from = vpath(d, src_vol, src), *to = vpath(d, dst_vol, dst);
  parent_mkdir(to);
  buckets_drive_err err = rename(from, to) == 0 ? BUCKETS_DRIVE_OK : from_errno(errno);
  free(from);
  free(to);
  return err;
}
