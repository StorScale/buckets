/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Ransomware alerts' counting, detection and incidents (src/ransomware/ransomware.h). */
#include <cmocka.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ransomware/ransomware.h"

#define NOW 1800000000LL /* a whole minute */

static yyjson_doc *snap(int window, uint64_t since, int64_t now) {
  buckets_buf b = BUCKETS_BUF_INIT;
  buckets_rw_snapshot("n1:9000", window, since, now, &b);
  yyjson_doc *d = yyjson_read(b.data, b.len, 0);
  buckets_buf_free(&b);
  return d;
}

static void test_counting(void **state) {
  (void)state;
  buckets_rw_reset();
  buckets_rw_note("logs", "AK1", "alice", "access-key", BUCKETS_RW_DELETED, 10,
                  NOW - 600); /* 10 minutes ago */
  buckets_rw_note("logs", "AK1", "alice", "access-key", BUCKETS_RW_DELETED, 7, NOW - 120);
  buckets_rw_note("logs", "AK1", "alice", "access-key", BUCKETS_RW_DESTROYED, 3, NOW - 60);
  buckets_rw_note("logs", "AK2", "bob", "user", BUCKETS_RW_OVERWRITTEN, 5, NOW);
  buckets_rw_note("web", "AK1", "alice", "access-key", BUCKETS_RW_DELETED, 1, NOW);
  buckets_rw_protection("logs", "AK2", "bob", "user", BUCKETS_RW_VERSIONING_SUSPENDED, "Enabled to Suspended",
                        NOW);
  /* the last 5 minutes only */
  yyjson_doc *d = snap(5, 0, NOW);
  yyjson_val *rows = yyjson_obj_get(yyjson_doc_get_root(d), "rows");
  assert_int_equal(yyjson_arr_size(rows), 3);
  size_t i, max;
  yyjson_val *r;
  yyjson_arr_foreach(rows, i, max, r) {
    if (!strcmp(yyjson_get_str(yyjson_obj_get(r, "b")), "logs") &&
        !strcmp(yyjson_get_str(yyjson_obj_get(r, "k")), "AK1")) {
      yyjson_val *n = yyjson_obj_get(r, "n");
      assert_int_equal(yyjson_get_uint(yyjson_arr_get(n, 0)), 7);
      assert_int_equal(yyjson_get_uint(yyjson_arr_get(n, 1)), 3);
    }
  }
  yyjson_val *chs = yyjson_obj_get(yyjson_doc_get_root(d), "changes");
  assert_int_equal(yyjson_arr_size(chs), 1);
  assert_string_equal(yyjson_get_str(yyjson_obj_get(yyjson_arr_get(chs, 0), "change")),
                      "versioning-suspended");
  uint64_t seq = yyjson_get_uint(yyjson_obj_get(yyjson_doc_get_root(d), "seq"));
  yyjson_doc_free(d);
  /* changes already fetched are not sent again */
  d = snap(5, seq, NOW);
  assert_int_equal(yyjson_arr_size(yyjson_obj_get(yyjson_doc_get_root(d), "changes")), 0);
  yyjson_doc_free(d);
  /* totals since start, per bucket */
  buckets_rw_total *t;
  size_t nt = buckets_rw_totals(&t);
  assert_int_equal(nt, 2);
  assert_string_equal(t[0].bucket, "logs");
  assert_int_equal(t[0].n[BUCKETS_RW_DELETED], 17);
  assert_int_equal(t[0].changes[BUCKETS_RW_VERSIONING_SUSPENDED], 1);
  buckets_rw_totals_free(t, nt);
  /* an hour later the old counts are gone */
  d = snap(60, seq, NOW + 3600 + 60);
  assert_int_equal(yyjson_arr_size(yyjson_obj_get(yyjson_doc_get_root(d), "rows")), 0);
  yyjson_doc_free(d);
  buckets_rw_reset();
}

static buckets_rw_row *rows_of(const char *json, size_t *n) {
  buckets_rw_row *rows = NULL;
  *n = 0;
  yyjson_doc *d = yyjson_read(json, strlen(json), 0);
  buckets_rw_rows_add(&rows, n, yyjson_doc_get_root(d));
  yyjson_doc_free(d);
  return rows;
}

static uint64_t usual_tbl(void *ud, const char *bucket, buckets_rw_incident_kind kind) {
  (void)ud;
  if (!strcmp(bucket, "busy")) return kind == BUCKETS_RW_MASS_DELETE ? 500 : 0; /* a nightly clean-up */
  return 0;
}

static void test_detect(void **state) {
  (void)state;
  buckets_rw_rule rule = {1000, 10, 5};
  /* two servers' snapshots of one attack, summed */
  const char *s1 =
      "{\"rows\":[{\"b\":\"logs\",\"k\":\"AK1\",\"u\":\"alice\",\"t\":\"access-key\",\"n\":[600,0,0]},"
      "{\"b\":\"logs\",\"k\":\"AK9\",\"u\":\"carol\",\"t\":\"user\",\"n\":[5,0,0]},"
      "{\"b\":\"busy\",\"k\":\"CRON\",\"u\":\"cron\",\"t\":\"access-key\",\"n\":[3000,0,0]},"
      "{\"b\":\"web\",\"k\":\"AK2\",\"u\":\"bob\",\"t\":\"sts\",\"n\":[0,0,999]}]}";
  const char *s2 =
      "{\"rows\":[{\"b\":\"logs\",\"k\":\"AK1\",\"u\":\"alice\",\"t\":\"access-key\",\"n\":[500,500,0]}]}";
  size_t n;
  buckets_rw_row *rows = rows_of(s1, &n);
  yyjson_doc *d2 = yyjson_read(s2, strlen(s2), 0);
  buckets_rw_rows_add(&rows, &n, yyjson_doc_get_root(d2));
  yyjson_doc_free(d2);
  assert_int_equal(n, 4);
  buckets_rw_burst *b;
  size_t nb = buckets_rw_detect(rows, n, &rule, usual_tbl, NULL, &b);
  /* logs: 1105 deletes, no usual rate: a burst, alice first; busy: 3000 against a usual 500 (x6): not;
   * web: 999 overwrites, under the floor: not */
  assert_int_equal(nb, 1);
  assert_int_equal(b[0].kind, BUCKETS_RW_MASS_DELETE);
  assert_string_equal(b[0].bucket, "logs");
  assert_int_equal(b[0].count, 1105);
  assert_int_equal(b[0].nwho, 2);
  assert_string_equal(b[0].who[0]->access_key, "AK1");
  assert_int_equal(b[0].who_n[0], 1100);
  assert_string_equal(b[0].who[1]->user, "carol");
  free(b);
  /* a lower factor catches the clean-up; an excluded bucket is never reported */
  rule.factor = 5;
  nb = buckets_rw_detect(rows, n, &rule, usual_tbl, NULL, &b);
  assert_int_equal(nb, 2);
  free(b);
  setenv("BUCKETS_RANSOMWARE_EXCLUDE", "scratch, busy", 1);
  nb = buckets_rw_detect(rows, n, &rule, usual_tbl, NULL, &b);
  assert_int_equal(nb, 1);
  free(b);
  unsetenv("BUCKETS_RANSOMWARE_EXCLUDE");
  buckets_rw_rows_free(rows, n);
  /* one credential, a little in each of many buckets: its own burst */
  rule.factor = 10;
  const char *spread =
      "{\"rows\":[{\"b\":\"a\",\"k\":\"AK3\",\"u\":\"eve\",\"t\":\"access-key\",\"n\":[0,0,400]},"
      "{\"b\":\"b\",\"k\":\"AK3\",\"u\":\"eve\",\"t\":\"access-key\",\"n\":[0,0,400]},"
      "{\"b\":\"c\",\"k\":\"AK3\",\"u\":\"eve\",\"t\":\"access-key\",\"n\":[0,0,400]}]}";
  rows = rows_of(spread, &n);
  nb = buckets_rw_detect(rows, n, &rule, usual_tbl, NULL, &b);
  assert_int_equal(nb, 1);
  assert_int_equal(b[0].kind, BUCKETS_RW_MASS_OVERWRITE);
  assert_null(b[0].bucket);
  assert_int_equal(b[0].count, 1200);
  assert_string_equal(b[0].who[0]->user, "eve");
  free(b);
  buckets_rw_rows_free(rows, n);
}

static void test_usual(void **state) {
  (void)state;
  /* a nightly clean-up of 1200 an hour (two servers, 600 each) on 8 of 14 days; one day of 9000 (an attack): the
   * median busiest hour is the clean-up's, and the attack doesn't move it */
  buckets_buf rec[17];
  int day[17];
  size_t n = 0;
  for (int dd = 0; dd < 8; dd++)
    for (int srv = 0; srv < 2; srv++) {
      rec[n] = BUCKETS_BUF_INIT;
      buckets_buf_appendf(&rec[n], "{\"buckets\":{\"busy\":{\"dh\":[0,0,600]}}}");
      day[n++] = dd;
    }
  rec[n] = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&rec[n], "{\"buckets\":{\"busy\":{\"dh\":[9000]}}}");
  day[n++] = 9;
  assert_int_equal(buckets_rw_usual_from_history(rec, day, n, "busy", BUCKETS_RW_MASS_DELETE, 5),
                   100); /* 1200/12 */
  assert_int_equal(buckets_rw_usual_from_history(rec, day, n, "busy", BUCKETS_RW_MASS_OVERWRITE, 5), 0);
  assert_int_equal(buckets_rw_usual_from_history(rec, day, n, "other", BUCKETS_RW_MASS_DELETE, 5), 0);
  /* a new bucket: three days of history is not yet usual */
  assert_int_equal(buckets_rw_usual_from_history(rec, day, 6, "busy", BUCKETS_RW_MASS_DELETE, 5), 0);
  for (size_t i = 0; i < n; i++) buckets_buf_free(&rec[i]);
}

static void test_incidents(void **state) {
  (void)state;
  yyjson_mut_doc *d = buckets_rw_incidents_parse("", 0);
  buckets_rw_row who = {"logs", "AK1", "alice", "access-key", {0}};
  buckets_rw_burst b = {BUCKETS_RW_MASS_DELETE, "logs", 1500, 0, {&who}, {1500}, 1};
  bool opened;
  yyjson_mut_val *x = buckets_rw_incident_record(d, &b, "i-1", NOW, &opened);
  assert_true(opened);
  assert_string_equal(yyjson_mut_get_str(yyjson_mut_obj_get(x, "id")), "i-1");
  /* the same burst a poll later: the same incident, its largest count kept */
  b.count = 2500;
  x = buckets_rw_incident_record(d, &b, "i-2", NOW + 30, &opened);
  assert_false(opened);
  assert_string_equal(yyjson_mut_get_str(yyjson_mut_obj_get(x, "id")), "i-1");
  assert_int_equal(yyjson_mut_get_uint(yyjson_mut_obj_get(yyjson_mut_obj_get(x, "counts"), "deleted")), 2500);
  /* another kind or bucket: its own */
  b.kind = BUCKETS_RW_MASS_OVERWRITE;
  buckets_rw_incident_record(d, &b, "i-3", NOW + 30, &opened);
  assert_true(opened);
  /* quiet for 15 minutes: closed; then a new burst opens a new one */
  buckets_rw_incidents_age(d, NOW + 30 + 900, 900, 90 * 86400);
  assert_null(buckets_rw_incident_open(d, BUCKETS_RW_MASS_DELETE, "logs", NULL));
  b.kind = BUCKETS_RW_MASS_DELETE;
  buckets_rw_incident_record(d, &b, "i-4", NOW + 2000, &opened);
  assert_true(opened);
  /* kept 90 days after closing */
  yyjson_mut_val *arr = yyjson_mut_obj_get(yyjson_mut_doc_get_root(d), "incidents");
  assert_int_equal(yyjson_mut_arr_size(arr), 3);
  buckets_rw_incidents_age(d, NOW + 930 + 90 * 86400 + 1, 900, 90 * 86400);
  assert_int_equal(yyjson_mut_arr_size(arr), 1); /* i-4, closed later, is still kept */
  assert_false(buckets_rw_incident_has_source(d, "n1:9000/1"));
  yyjson_mut_doc_free(d);
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_counting),
      cmocka_unit_test(test_detect),
      cmocka_unit_test(test_usual),
      cmocka_unit_test(test_incidents),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
