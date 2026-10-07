/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* The audit log's local copy (src/audit/store.h): matching, segments, querying newest first, retention. */
#include <cmocka.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "audit/store.h"
#include "usage/history.h"

static char *entry(const char *time, const char *api, const char *bucket, const char *object, int status,
                   const char *ak, const char *parent, const char *path) {
  char *s = malloc(1024);
  snprintf(
      s, 1024,
      "{\"version\":\"1\",\"time\":\"%s\",\"api\":{\"name\":\"%s\",\"bucket\":\"%s\",\"object\":\"%s\","
      "\"statusCode\":%d},\"remotehost\":\"10.1.2.3\",\"requestPath\":\"%s\",\"accessKey\":\"%s\"%s%s%s}",
      time, api, bucket, object, status, path, ak, parent ? ",\"parentUser\":\"" : "", parent ? parent : "",
      parent ? "\"" : "");
  return s;
}

static bool matches(const char *json, const buckets_audit_query *q) {
  yyjson_doc *d = yyjson_read(json, strlen(json), 0);
  bool m = buckets_audit_match(yyjson_doc_get_root(d), q);
  yyjson_doc_free(d);
  return m;
}

static void test_match(void **state) {
  (void)state;
  char *put = entry("2026-10-07T10:00:00.5Z", "PutObject", "logs", "app/a.log", 200, "AK1", "alice",
                    "/logs/app/a.log");
  char *del = entry("2026-10-07T10:00:01Z", "DeleteObject", "logs", "app/a.log", 403, "AK1", "alice",
                    "/logs/app/a.log");
  char *adm = entry("2026-10-07T10:00:02Z", "ServerInfo", "", "", 200, "root", NULL, "/minio/admin/v3/info");
  buckets_audit_query q = {0};
  assert_true(matches(put, &q));
  q.user = "alice";
  assert_true(matches(put, &q));
  assert_false(matches(adm, &q));
  q.user = "root"; /* no parent: the access key is the person */
  assert_true(matches(adm, &q));
  /* an OpenID sign-in: the parent is a hash, the token names the person */
  const char *sso =
      "{\"time\":\"2026-10-07T10:00:03Z\",\"api\":{\"name\":\"GetObject\"},\"accessKey\":\"STS1\","
      "\"parentUser\":\"x9Hq\",\"requestClaims\":{\"preferred_username\":\"bob@example.com\","
      "\"upn\":\"bob@corp.example.com\"}}";
  q.user = "bob@example.com";
  assert_true(matches(sso, &q));
  q.user = "bob@corp.example.com";
  assert_true(matches(sso, &q));
  q.user = "x9Hq";
  assert_true(matches(sso, &q));
  q.user = "alice";
  assert_false(matches(sso, &q));
  /* the server's own work: an event, no API name, its keys in "objects" */
  const char *heal =
      "{\"time\":\"2026-10-07T10:00:04Z\",\"event\":\"HealObject\",\"trigger\":\"HealObject\","
      "\"api\":{\"bucket\":\"logs\",\"objects\":[{\"objectName\":\"app/b.log\"}]}}";
  memset(&q, 0, sizeof(q));
  q.kind = "system";
  assert_true(matches(heal, &q));
  assert_false(matches(put, &q));
  q.kind = "read";
  assert_false(matches(heal, &q));
  memset(&q, 0, sizeof(q));
  q.api = "HealObject";
  assert_true(matches(heal, &q));
  memset(&q, 0, sizeof(q));
  q.prefix = "app/";
  assert_true(matches(heal, &q));
  q.prefix = "other/";
  assert_false(matches(heal, &q));
  memset(&q, 0, sizeof(q));
  q.kind = "delete";
  assert_true(matches(del, &q));
  assert_false(matches(put, &q));
  q.kind = "admin";
  assert_true(matches(adm, &q));
  memset(&q, 0, sizeof(q));
  q.status = "denied";
  assert_true(matches(del, &q));
  q.status = "ok";
  assert_true(matches(put, &q));
  memset(&q, 0, sizeof(q));
  q.bucket = "logs", q.prefix = "app/", q.api = "putobject", q.ip = "10.1.";
  assert_true(matches(put, &q));
  q.prefix = "web/";
  assert_false(matches(put, &q));
  /* time: from, to and the cursor */
  memset(&q, 0, sizeof(q));
  int64_t t0 = 1791367200LL * 1000000000LL; /* 2026-10-07T10:00:00Z */
  q.from_ns = t0 + 600000000LL;
  assert_false(matches(put, &q));
  assert_true(matches(del, &q));
  q.from_ns = 0, q.before_ns = t0 + 1000000000LL;
  assert_true(matches(put, &q));
  assert_false(matches(del, &q)); /* at the cursor: not again */
  free(put), free(del), free(adm);
}

static char g_root[256];

static void rm_rf(const char *p) {
  char cmd[600];
  snprintf(cmd, sizeof(cmd), "rm -rf '%s'", p);
  if (system(cmd) != 0) fail();
}

static void test_store(void **state) {
  (void)state;
  snprintf(g_root, sizeof(g_root), "/tmp/buckets-audit-test-%d", (int)getpid());
  rm_rf(g_root);
  buckets_audit_store *s = buckets_audit_store_new(g_root);
  char now_s[40];
  time_t now = time(NULL);
  struct tm tm;
  gmtime_r(&now, &tm);
  strftime(now_s, sizeof(now_s), "%Y-%m-%dT%H:%M:%SZ", &tm);
  for (int i = 0; i < 250; i++) {
    char obj[32];
    snprintf(obj, sizeof(obj), "o%03d", i);
    char *e = entry(now_s, i % 2 ? "GetObject" : "PutObject", "logs", obj, 200, i % 5 ? "AK1" : "AK2",
                    "alice", "/logs/x");
    assert_true(buckets_audit_store_put(s, e, strlen(e)));
    free(e);
  }
  buckets_audit_store_flush(s);
  /* newest first, limited, and the AK2 ones only */
  buckets_audit_query q = {0};
  q.access_key = "AK2", q.limit = 20;
  buckets_buf out = BUCKETS_BUF_INIT;
  int64_t oldest;
  size_t n = buckets_audit_query_dir(g_root, &q, &out, &oldest);
  assert_int_equal(n, 20);
  yyjson_doc *d = yyjson_read(out.data, out.len, 0);
  assert_string_equal(yyjson_get_str(yyjson_obj_get(
                          yyjson_obj_get(yyjson_arr_get(yyjson_doc_get_root(d), 0), "api"), "object")),
                      "o245");
  yyjson_doc_free(d);
  assert_true(oldest > 0);
  buckets_buf_free(&out);
  /* a restart: the open segment is compressed, the next opens beside it, and both are read */
  buckets_audit_store_free(s);
  s = buckets_audit_store_new(g_root);
  char *e = entry(now_s, "DeleteObject", "logs", "late", 204, "AK1", "alice", "/logs/late");
  buckets_audit_store_put(s, e, strlen(e));
  free(e);
  buckets_audit_store_flush(s);
  memset(&q, 0, sizeof(q));
  q.limit = 1000;
  buckets_buf_reset(&out);
  assert_int_equal(buckets_audit_query_dir(g_root, &q, &out, &oldest), 251);
  q.kind = "delete";
  buckets_buf_reset(&out);
  assert_int_equal(buckets_audit_query_dir(g_root, &q, &out, &oldest), 1);
  buckets_buf_free(&out);
  buckets_audit_store_free(s);
  rm_rf(g_root);
}

static void touch(const char *root, const char *day, const char *name, size_t bytes) {
  char p[600];
  snprintf(p, sizeof(p), "%s/%s", root, day);
  mkdir(root, 0700);
  mkdir(p, 0700);
  snprintf(p, sizeof(p), "%s/%s/%s", root, day, name);
  FILE *f = fopen(p, "wb");
  for (size_t i = 0; i < bytes; i++) fputc('x', f);
  fclose(f);
}

static bool exists(const char *root, const char *day, const char *name) {
  char p[600];
  snprintf(p, sizeof(p), "%s/%s/%s", root, day, name);
  return access(p, F_OK) == 0;
}

static void test_retain(void **state) {
  (void)state;
  snprintf(g_root, sizeof(g_root), "/tmp/buckets-audit-retain-%d", (int)getpid());
  rm_rf(g_root);
  int64_t now;
  buckets_usage_day_parse("2026-10-07", &now);
  now += 12 * 3600;
  touch(g_root, "2026-09-01", "10-0000.jsonl.gz", 100); /* older than 30 days */
  touch(g_root, "2026-10-01", "10-0000.jsonl.gz", 100);
  touch(g_root, "2026-10-06", "10-0000.jsonl.gz", 100);
  touch(g_root, "2026-10-07", "12-0000.jsonl", 100);
  touch(g_root, "2026-10-07", "notes.txt", 100); /* not a segment: left alone */
  assert_int_equal(buckets_audit_retain(g_root, 30, 1 << 20, now), 300);
  assert_false(exists(g_root, "2026-09-01", "10-0000.jsonl.gz"));
  /* over the size: the oldest go, never the one being written */
  assert_int_equal(buckets_audit_retain(g_root, 30, 150, now), 100);
  assert_false(exists(g_root, "2026-10-01", "10-0000.jsonl.gz"));
  assert_false(exists(g_root, "2026-10-06", "10-0000.jsonl.gz"));
  assert_true(exists(g_root, "2026-10-07", "12-0000.jsonl"));
  assert_true(exists(g_root, "2026-10-07", "notes.txt"));
  rm_rf(g_root);
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_match),
      cmocka_unit_test(test_store),
      cmocka_unit_test(test_retain),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
