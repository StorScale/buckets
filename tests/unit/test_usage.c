/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* The usage history's records and a period's totals (src/usage/history.h). */
#include <cmocka.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "usage/history.h"

static void test_days(void **state) {
  (void)state;
  char d[11];
  int64_t t;
  assert_true(buckets_usage_day_parse("2026-10-07", &t));
  buckets_usage_day(t, d);
  assert_string_equal(d, "2026-10-07");
  buckets_usage_day(t + 86399, d);
  assert_string_equal(d, "2026-10-07");
  assert_false(buckets_usage_day_parse("2026-02-31", &t));
  assert_false(buckets_usage_day_parse("2026-1-01", &t));
  assert_false(buckets_usage_day_parse("2026-10-07x", &t));
  assert_false(buckets_usage_day_parse(NULL, &t));
  assert_int_equal(buckets_usage_days_in_month("2026-02-10"), 28);
  assert_int_equal(buckets_usage_days_in_month("2028-02-10"), 29);
  assert_int_equal(buckets_usage_days_in_month("2100-02-10"), 28);
  assert_int_equal(buckets_usage_days_in_month("2026-04-30"), 30);
  assert_int_equal(buckets_usage_days_in_month("2026-12-01"), 31);
  /* 13 months kept: the same day last year and the month before it */
  buckets_usage_keep_from("2026-10-07", 396, d);
  assert_string_equal(d, "2025-09-07");
  buckets_usage_keep_from("2026-10-07", 1, d);
  assert_string_equal(d, "2026-10-07");
  unsetenv("BUCKETS_USAGE_HISTORY_DAYS");
  assert_int_equal(buckets_usage_history_days(), 396);
  setenv("BUCKETS_USAGE_HISTORY_DAYS", "30", 1);
  assert_int_equal(buckets_usage_history_days(), 30);
  setenv("BUCKETS_USAGE_HISTORY_DAYS", "0", 1);
  assert_int_equal(buckets_usage_history_days(), 396);
  unsetenv("BUCKETS_USAGE_HISTORY_DAYS");
  setenv("BUCKETS_USAGE_TEST_DAY", "2027-01-01", 1);
  buckets_usage_today(d);
  assert_string_equal(d, "2027-01-01");
  unsetenv("BUCKETS_USAGE_TEST_DAY");
}

static void test_kinds(void **state) {
  (void)state;
  assert_int_equal(buckets_usage_kind_of("getobject"), BUCKETS_USAGE_READ);
  assert_int_equal(buckets_usage_kind_of("headobject"), BUCKETS_USAGE_READ);
  assert_int_equal(buckets_usage_kind_of("listobjectsv2"), BUCKETS_USAGE_READ);
  assert_int_equal(buckets_usage_kind_of("selectobjectcontent"), BUCKETS_USAGE_READ);
  assert_int_equal(buckets_usage_kind_of("putobject"), BUCKETS_USAGE_WRITE);
  assert_int_equal(buckets_usage_kind_of("copyobject"), BUCKETS_USAGE_WRITE);
  assert_int_equal(buckets_usage_kind_of("newmultipartupload"), BUCKETS_USAGE_WRITE);
  assert_int_equal(buckets_usage_kind_of("putobjectpart"), BUCKETS_USAGE_WRITE);
  assert_int_equal(buckets_usage_kind_of("completemultipartupload"), BUCKETS_USAGE_WRITE);
  assert_int_equal(buckets_usage_kind_of("postpolicybucket"), BUCKETS_USAGE_WRITE);
  assert_int_equal(buckets_usage_kind_of("postrestoreobject"), BUCKETS_USAGE_WRITE);
  assert_int_equal(buckets_usage_kind_of("deleteobject"), BUCKETS_USAGE_DELETE);
  assert_int_equal(buckets_usage_kind_of("deletemultipleobjects"), BUCKETS_USAGE_DELETE);
}

static yyjson_doc *parse(buckets_buf *b) { return yyjson_read(b->data, b->len, 0); }
static uint64_t at(yyjson_doc *d, const char *bucket, const char *k) {
  return yyjson_get_uint(
      yyjson_obj_get(yyjson_obj_get(yyjson_obj_get(yyjson_doc_get_root(d), "buckets"), bucket), k));
}

static void test_traffic_merge(void **state) {
  (void)state;
  buckets_buf a = BUCKETS_BUF_INIT, b = BUCKETS_BUF_INIT;
  buckets_usage_traffic_add x[] = {{"one", {10, 20, 3, 2, 1}}, {"two", {1, 0, 0, 1, 0}}};
  buckets_usage_traffic_merge("", 0, x, 2, &a);
  buckets_usage_traffic_add y[] = {{"one", {5, 5, 1, 1, 1}}, {"three", {0, 7, 1, 0, 0}}};
  buckets_usage_traffic_merge(a.data, a.len, y, 2, &b);
  yyjson_doc *d = parse(&b);
  assert_int_equal(at(d, "one", "in"), 15);
  assert_int_equal(at(d, "one", "out"), 25);
  assert_int_equal(at(d, "one", "read"), 4);
  assert_int_equal(at(d, "one", "write"), 3);
  assert_int_equal(at(d, "one", "delete"), 2);
  assert_int_equal(at(d, "two", "write"), 1);
  assert_int_equal(at(d, "three", "out"), 7);
  yyjson_doc_free(d);
  /* a damaged record starts over rather than failing */
  buckets_buf_reset(&b);
  buckets_usage_traffic_merge("{nope", 5, y, 1, &b);
  d = parse(&b);
  assert_int_equal(at(d, "one", "in"), 5);
  yyjson_doc_free(d);
  buckets_buf_free(&a);
  buckets_buf_free(&b);
}

static void test_traffic_hours(void **state) {
  (void)state;
  /* objects deleted and overwritten, in all and per UTC hour (ransomware alerts' usual rates) */
  buckets_buf a = BUCKETS_BUF_INIT, b = BUCKETS_BUF_INIT;
  buckets_usage_traffic_add x[] = {{"logs", {.del = 2, .deleted = 300}, 2}};
  buckets_usage_traffic_merge("", 0, x, 1, &a);
  buckets_usage_traffic_add y[] = {{"logs", {.deleted = 50, .overwritten = 7}, 2}, {"logs", {.deleted = 1}, 23}};
  buckets_usage_traffic_merge(a.data, a.len, y, 2, &b);
  yyjson_doc *d = parse(&b);
  yyjson_val *logs = yyjson_obj_get(yyjson_obj_get(yyjson_doc_get_root(d), "buckets"), "logs");
  assert_int_equal(yyjson_get_uint(yyjson_obj_get(logs, "deleted")), 351);
  assert_int_equal(yyjson_get_uint(yyjson_obj_get(logs, "overwritten")), 7);
  assert_int_equal(yyjson_get_uint(yyjson_obj_get(logs, "delete")), 2);
  yyjson_val *dh = yyjson_obj_get(logs, "dh"), *oh = yyjson_obj_get(logs, "oh");
  assert_int_equal(yyjson_arr_size(dh), 24);
  assert_int_equal(yyjson_get_uint(yyjson_arr_get(dh, 2)), 350);
  assert_int_equal(yyjson_get_uint(yyjson_arr_get(dh, 23)), 1);
  assert_int_equal(yyjson_get_uint(yyjson_arr_get(oh, 2)), 7);
  yyjson_doc_free(d);
  buckets_buf_free(&a);
  buckets_buf_free(&b);
}

static void test_storage_merge(void **state) {
  (void)state;
  buckets_buf a = BUCKETS_BUF_INIT, b = BUCKETS_BUF_INIT, c = BUCKETS_BUF_INIT;
  buckets_usage_sample s1[] = {{"one", 100}}, s2[] = {{"one", 300}}, s3[] = {{"one", 200}, {"two", 9}};
  buckets_usage_storage_merge("", 0, s1, 1, &a);
  buckets_usage_storage_merge(a.data, a.len, s2, 1, &b);
  buckets_usage_storage_merge(b.data, b.len, s3, 2, &c);
  yyjson_doc *d = parse(&c);
  yyjson_val *one = yyjson_obj_get(yyjson_obj_get(yyjson_doc_get_root(d), "buckets"), "one");
  assert_true(yyjson_get_real(yyjson_obj_get(one, "avg")) > 199.99 &&
              yyjson_get_real(yyjson_obj_get(one, "avg")) < 200.01);
  assert_int_equal(at(d, "one", "count"), 3);
  assert_int_equal(at(d, "one", "peak"), 300);
  assert_int_equal(at(d, "one", "last"), 200);
  assert_int_equal(at(d, "two", "count"), 1);
  assert_int_equal(at(d, "two", "last"), 9);
  yyjson_doc_free(d);
  buckets_buf_free(&a);
  buckets_buf_free(&b);
  buckets_buf_free(&c);
}

static void test_teams(void **state) {
  (void)state;
  const char *j =
      "[{\"name\":\"analytics\",\"buckets\":[\"shared\"],\"prefixes\":[\"ana-\"]},"
      "{\"name\":\"anaconda\",\"buckets\":[],\"prefixes\":[\"ana-conda-\"]},"
      "{\"name\":\"web\",\"buckets\":[\"site\",\"shared\"],\"prefixes\":[]}]";
  yyjson_doc *d = yyjson_read(j, strlen(j), 0);
  yyjson_val *t = yyjson_doc_get_root(d);
  bool twice;
  assert_string_equal(buckets_usage_team_of(t, "ana-logs", &twice), "analytics");
  assert_false(twice);
  assert_string_equal(buckets_usage_team_of(t, "ana-conda-env", &twice), "anaconda"); /* the longest prefix */
  assert_string_equal(buckets_usage_team_of(t, "site", &twice), "web");
  assert_string_equal(buckets_usage_team_of(t, "shared", &twice), "analytics"); /* the first by name */
  assert_true(twice);
  assert_null(buckets_usage_team_of(t, "other", &twice));
  assert_null(buckets_usage_team_of(NULL, "other", &twice));
  yyjson_doc_free(d);
}

/* a source of records kept in memory: storage by day, traffic by day and server */
typedef struct {
  const char *day, *json;
} rec;
typedef struct {
  const rec *storage, *traffic;
  size_t ns, nt;
} mem;

static bool mem_storage(void *ud, const char *day, buckets_buf *out) {
  mem *m = ud;
  for (size_t i = 0; i < m->ns; i++)
    if (strcmp(m->storage[i].day, day) == 0) {
      buckets_buf_append_c(out, m->storage[i].json);
      return true;
    }
  return false;
}

static size_t mem_traffic(void *ud, const char *day, buckets_buf **out) {
  mem *m = ud;
  size_t n = 0;
  for (size_t i = 0; i < m->nt; i++)
    if (strcmp(m->traffic[i].day, day) == 0) {
      *out = realloc(*out, (n + 1) * sizeof(buckets_buf));
      (*out)[n] = BUCKETS_BUF_INIT;
      buckets_buf_append_c(&(*out)[n++], m->traffic[i].json);
    }
  return n;
}

static yyjson_val *find(yyjson_val *arr, const char *name) {
  size_t i, max;
  yyjson_val *v;
  yyjson_arr_foreach(arr, i, max, v) {
    yyjson_val *n = yyjson_obj_get(v, "name");
    if (name ? yyjson_equals_str(n, name) : yyjson_is_null(n)) return v;
  }
  return NULL;
}

static double gbm(yyjson_val *o) {
  return yyjson_get_real(yyjson_obj_get(yyjson_obj_get(o, "storage"), "gbMonths"));
}

static void test_report(void **state) {
  (void)state;
  /* 30 GB all of September (30 days): 30 GB-months... */
  static const rec storage[] = {
      {"2026-08-31",
       "{\"buckets\":{\"logs\":{\"avg\":3e10,\"count\":2,\"peak\":30000000000,\"last\":30000000000}}}"},
      /* 2026-09-01..02 have no record: carried forward from 08-31 */
      {"2026-09-03",
       "{\"buckets\":{\"logs\":{\"avg\":3e10,\"count\":4,\"peak\":31000000000,\"last\":30000000000},"
       "\"site\":{\"avg\":1e9,\"count\":4,\"peak\":1000000000,\"last\":2000000000}}}"},
  };
  static const rec traffic[] = {
      {"2026-09-03",
       "{\"buckets\":{\"logs\":{\"in\":100,\"out\":1000,\"read\":10,\"write\":5,\"delete\":1}}}"},
      {"2026-09-03", "{\"buckets\":{\"logs\":{\"in\":50,\"out\":0,\"read\":0,\"write\":3,\"delete\":0}}}"},
      {"2026-09-10",
       "{\"buckets\":{\"site\":{\"in\":0,\"out\":7,\"read\":2,\"write\":0,\"delete\":0},"
       "\"gone\":{\"in\":1,\"out\":1,\"read\":1,\"write\":1,\"delete\":1}}}"},
      {"2026-10-01", "{\"buckets\":{\"logs\":{\"in\":999,\"out\":999,\"read\":9,\"write\":9,\"delete\":9}}}"},
  };
  mem m = {storage, traffic, 2, 4};
  buckets_usage_source src = {mem_storage, mem_traffic, &m};
  const char *tj = "[{\"name\":\"ops\",\"buckets\":[\"logs\"],\"prefixes\":[]}]";
  yyjson_doc *td = yyjson_read(tj, strlen(tj), 0);
  const char *rj = "{\"currency\":\"EUR\",\"storageGbMonth\":0.02}";
  yyjson_doc *rd = yyjson_read(rj, strlen(rj), 0);
  buckets_buf out = BUCKETS_BUF_INIT;
  char err[128];
  assert_true(buckets_usage_report(&src, "2026-09-01", "2026-09-30", yyjson_doc_get_root(td),
                                   yyjson_doc_get_root(rd), &out, err, sizeof(err)));
  yyjson_doc *d = parse(&out);
  yyjson_val *root = yyjson_doc_get_root(d);
  assert_int_equal(yyjson_get_uint(yyjson_obj_get(root, "days")), 30);
  assert_string_equal(yyjson_get_str(yyjson_obj_get(yyjson_obj_get(root, "rates"), "currency")), "EUR");
  assert_int_equal(yyjson_arr_size(yyjson_obj_get(root, "missingDays")), 0);
  yyjson_val *bs = yyjson_obj_get(root, "buckets");
  assert_int_equal(yyjson_arr_size(bs), 3);
  yyjson_val *logs = find(bs, "logs"), *site = find(bs, "site"), *gone = find(bs, "gone");
  assert_true(gbm(logs) > 29.999 && gbm(logs) < 30.001);
  assert_int_equal(yyjson_get_uint(yyjson_obj_get(yyjson_obj_get(logs, "storage"), "peakBytes")),
                   31000000000ULL);
  assert_string_equal(yyjson_get_str(yyjson_obj_get(logs, "team")), "ops");
  assert_int_equal(yyjson_get_uint(yyjson_obj_get(logs, "dataIn")), 150); /* two servers, one day */
  assert_int_equal(yyjson_get_uint(yyjson_obj_get(logs, "dataOut")), 1000);
  assert_int_equal(yyjson_get_uint(yyjson_obj_get(yyjson_obj_get(logs, "requests"), "write")), 8);
  /* site: 1 GB on 09-03, then its last size, 2 GB, carried over 27 days */
  assert_true(gbm(site) > (1.0 + 27 * 2.0) / 30 - 0.001 && gbm(site) < (1.0 + 27 * 2.0) / 30 + 0.001);
  assert_true(yyjson_is_null(yyjson_obj_get(site, "team")));
  yyjson_val *daily = yyjson_obj_get(site, "daily");
  assert_int_equal(yyjson_arr_size(daily), 30);
  assert_int_equal(yyjson_get_uint(yyjson_obj_get(yyjson_arr_get(daily, 0), "bytes")), 0);
  assert_int_equal(yyjson_get_uint(yyjson_obj_get(yyjson_arr_get(daily, 2), "bytes")), 1000000000);
  assert_int_equal(yyjson_get_uint(yyjson_obj_get(yyjson_arr_get(daily, 9), "out")), 7);
  assert_true(gbm(gone) == 0); /* traffic only: a bucket deleted since */
  yyjson_val *teams = yyjson_obj_get(root, "teams");
  assert_int_equal(yyjson_arr_size(teams), 2);
  yyjson_val *ops = find(teams, "ops"), *none = find(teams, NULL);
  assert_non_null(ops);
  assert_non_null(none);
  assert_int_equal(yyjson_arr_size(yyjson_obj_get(none, "buckets")), 2);
  assert_int_equal(yyjson_get_uint(yyjson_obj_get(yyjson_obj_get(none, "requests"), "read")), 3);
  yyjson_doc_free(d);

  /* February, 28 days: the same 30 GB held all month is 30 GB-months too */
  static const rec feb[] = {
      {"2027-02-01",
       "{\"buckets\":{\"logs\":{\"avg\":3e10,\"count\":1,\"peak\":30000000000,\"last\":30000000000}}}"}};
  mem m2 = {feb, NULL, 1, 0};
  buckets_usage_source src2 = {mem_storage, mem_traffic, &m2};
  buckets_buf_reset(&out);
  assert_true(buckets_usage_report(&src2, "2027-02-01", "2027-02-28", NULL, NULL, &out, err, sizeof(err)));
  d = parse(&out);
  logs = find(yyjson_obj_get(yyjson_doc_get_root(d), "buckets"), "logs");
  assert_true(gbm(logs) > 29.999 && gbm(logs) < 30.001);
  assert_true(yyjson_is_null(yyjson_obj_get(yyjson_doc_get_root(d), "rates")));
  yyjson_doc_free(d);

  /* days before any record are missing; half of January then is 15.5/31 of a month */
  buckets_buf_reset(&out);
  assert_true(buckets_usage_report(&src2, "2027-01-30", "2027-02-02", NULL, NULL, &out, err, sizeof(err)));
  d = parse(&out);
  yyjson_val *miss = yyjson_obj_get(yyjson_doc_get_root(d), "missingDays");
  assert_int_equal(yyjson_arr_size(miss), 2);
  assert_string_equal(yyjson_get_str(yyjson_arr_get(miss, 0)), "2027-01-30");
  yyjson_doc_free(d);

  /* bad periods */
  assert_false(buckets_usage_report(&src2, "2027-02-02", "2027-02-01", NULL, NULL, &out, err, sizeof(err)));
  assert_false(buckets_usage_report(&src2, "2026-01-01", "2027-03-01", NULL, NULL, &out, err, sizeof(err)));
  assert_false(buckets_usage_report(&src2, "yesterday", "2027-03-01", NULL, NULL, &out, err, sizeof(err)));
  buckets_buf_free(&out);
  yyjson_doc_free(td);
  yyjson_doc_free(rd);
}

static void test_rates(void **state) {
  (void)state;
  char err[128];
  const char *ok = "{\"currency\":\"USD\",\"storageGbMonth\":0.023,\"outGb\":0.09,\"per10kRead\":0}";
  const char *bad[] = {"[]",
                       "{\"storageGbMonth\":1}",
                       "{\"currency\":\"\"}",
                       "{\"currency\":\"DOLLARSXX\"}",
                       "{\"currency\":\"USD\",\"outGb\":-1}",
                       "{\"currency\":\"USD\",\"inGb\":\"free\"}"};
  yyjson_doc *d = yyjson_read(ok, strlen(ok), 0);
  assert_true(buckets_usage_rates_check(yyjson_doc_get_root(d), err, sizeof(err)));
  yyjson_doc_free(d);
  for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
    d = yyjson_read(bad[i], strlen(bad[i]), 0);
    assert_false(buckets_usage_rates_check(yyjson_doc_get_root(d), err, sizeof(err)));
    yyjson_doc_free(d);
  }
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_days),          cmocka_unit_test(test_kinds),
      cmocka_unit_test(test_traffic_merge), cmocka_unit_test(test_storage_merge), cmocka_unit_test(test_traffic_hours),
      cmocka_unit_test(test_teams),         cmocka_unit_test(test_report),
      cmocka_unit_test(test_rates),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
