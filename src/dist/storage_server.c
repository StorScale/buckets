/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "dist/storage_server.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/query.h"
#include "dist/internode.h"

struct buckets_storage_server {
  buckets_drive **drives;
  size_t n;
};

buckets_storage_server *buckets_storage_server_new(buckets_drive *const *drives, size_t n) {
  buckets_storage_server *s = buckets_xcalloc(1, sizeof(*s));
  s->drives = buckets_xcalloc(n ? n : 1, sizeof(buckets_drive *));
  for (size_t i = 0; i < n; i++) {
    if (drives[i] && !drives[i]->remote) s->drives[s->n++] = drives[i];
  }
  return s;
}

void buckets_storage_server_free(buckets_storage_server *s) {
  if (!s) return;
  free(s->drives);
  free(s);
}

static void fail(buckets_http_response *resp, int status, buckets_drive_err e) {
  resp->status = status;
  buckets_http_resp_headerf(resp, BUCKETS_INTERNODE_ERR, "%d", (int)e);
}

static bool read_body(const buckets_http_request *req, buckets_buf *out) {
  buckets_http_body_cursor c = {req, 0};
  buckets_buf_reserve(out, (size_t)req->body_len);
  char tmp[65536];
  long n;
  while ((n = buckets_http_body_read(&c, tmp, sizeof(tmp))) > 0) buckets_buf_append(out, tmp, (size_t)n);
  return n == 0;
}

void buckets_storage_server_handle(const buckets_http_request *req, buckets_http_response *resp, void *ud) {
  buckets_storage_server *s = ud;
  if (!buckets_internode_verify(req)) {
    fail(resp, 403, BUCKETS_DRIVE_ERR_IO);
    return;
  }
  const size_t pl = strlen(BUCKETS_INTERNODE_PREFIX "storage/");
  char op[32];
  snprintf(op, sizeof(op), "%.*s", (int)(req->path.n > pl ? req->path.n - pl : 0), req->path.p + pl);
  buckets_query q;
  buckets_query_parse(req->query, &q);
  const char *dp = buckets_query_get(&q, "drive");
  buckets_drive *d = NULL;
  for (size_t i = 0; dp && i < s->n && !d; i++) {
    if (strcmp(s->drives[i]->root, dp) == 0) d = s->drives[i];
  }
  if (!d) {
    fail(resp, 404, BUCKETS_DRIVE_ERR_OFFLINE);
    buckets_query_free(&q);
    return;
  }
#define Q(k) (buckets_query_get(&q, k) ? buckets_query_get(&q, k) : "")
#define QI(k) strtoll(Q(k), NULL, 10)
  buckets_drive_err e = BUCKETS_DRIVE_OK;
  buckets_buf body = BUCKETS_BUF_INIT;
  if (strcmp(op, "make_vol") == 0) {
    e = buckets_drive_make_vol(d, Q("vol"));
  } else if (strcmp(op, "stat_vol") == 0) {
    time_t created = 0;
    if (!(e = buckets_drive_stat_vol(d, Q("vol"), &created))) buckets_buf_appendf(&resp->body, "%lld", (long long)created);
  } else if (strcmp(op, "delete_vol") == 0) {
    e = buckets_drive_delete_vol(d, Q("vol"));
  } else if (strcmp(op, "list_vols") == 0) {
    buckets_vol_info *v;
    size_t n;
    if (!(e = buckets_drive_list_vols(d, &v, &n))) {
      for (size_t i = 0; i < n; i++) buckets_buf_appendf(&resp->body, "%lld\t%s\n", (long long)v[i].created, v[i].name);
      buckets_vol_info_free(v, n);
    }
  } else if (strcmp(op, "read_all") == 0) {
    e = buckets_drive_read_all(d, Q("vol"), Q("path"), &resp->body);
  } else if (strcmp(op, "write_all") == 0) {
    e = read_body(req, &body) ? buckets_drive_write_all(d, Q("vol"), Q("path"), body.data ? body.data : "", body.len)
                              : BUCKETS_DRIVE_ERR_IO;
  } else if (strcmp(op, "create") == 0) {
    buckets_drive_writer *w;
    if (!(e = buckets_drive_create_file(d, Q("vol"), Q("path"), &w))) e = buckets_drive_writer_close(w);
  } else if (strcmp(op, "append") == 0) {
    e = read_body(req, &body) ? buckets_drive_append(d, Q("vol"), Q("path"), QI("off"), body.data ? body.data : "",
                                                     body.len)
                              : BUCKETS_DRIVE_ERR_IO;
  } else if (strcmp(op, "fsync") == 0) {
    e = buckets_drive_fsync_file(d, Q("vol"), Q("path"));
  } else if (strcmp(op, "read_at") == 0) {
    long long n = QI("n");
    if (n < 0 || n > 64LL * 1024 * 1024) {
      e = BUCKETS_DRIVE_ERR_IO;
    } else {
      buckets_buf_reserve(&resp->body, (size_t)n);
      size_t got = 0;
      if (!(e = buckets_drive_read_at(d, Q("vol"), Q("path"), QI("off"), resp->body.data, (size_t)n, &got))) {
        resp->body.len = got;
      }
    }
  } else if (strcmp(op, "rename_data") == 0) {
    const char *dd = buckets_query_get(&q, "data_dir");
    e = read_body(req, &body) ? buckets_drive_rename_data(d, Q("src_vol"), Q("src_dir"), dd, Q("dst_vol"),
                                                          Q("dst_path"), body.data ? body.data : "", body.len)
                              : BUCKETS_DRIVE_ERR_IO;
  } else if (strcmp(op, "rename_file") == 0) {
    e = buckets_drive_rename_file(d, Q("src_vol"), Q("src"), Q("dst_vol"), Q("dst"));
  } else if (strcmp(op, "delete") == 0) {
    e = buckets_drive_delete(d, Q("vol"), Q("path"), QI("recursive") != 0, QI("prune") != 0);
  } else if (strcmp(op, "list_dir") == 0) {
    buckets_dir_list l;
    if (!(e = buckets_drive_list_dir(d, Q("vol"), Q("dir"), &l))) {
      for (size_t i = 0; i < l.n; i++) buckets_buf_appendf(&resp->body, "%s\n", l.names[i]);
      buckets_dir_list_free(&l);
    }
  } else if (strcmp(op, "disk_info") == 0) {
    uint64_t t, f;
    if (!(e = buckets_drive_disk_info(d, &t, &f))) {
      buckets_buf_appendf(&resp->body, "%llu %llu", (unsigned long long)t, (unsigned long long)f);
    }
  } else if (strcmp(op, "file_size") == 0) {
    int64_t sz;
    if (!(e = buckets_drive_file_size(d, Q("vol"), Q("path"), &sz))) buckets_buf_appendf(&resp->body, "%lld", (long long)sz);
  } else if (strcmp(op, "stat") == 0) {
    buckets_buf_appendf(&resp->body, "%d", buckets_drive_stat(d, Q("vol"), Q("path")));
  } else {
    resp->status = 400;
  }
#undef Q
#undef QI
  if (e) {
    buckets_buf_reset(&resp->body);
    fail(resp, 500, e);
  }
  buckets_buf_free(&body);
  buckets_query_free(&q);
}
