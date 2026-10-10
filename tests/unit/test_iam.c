/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cmocka.h>

#include "core/strmap.h"
#include "core/timefmt.h"
#include "crypto/base64.h"
#include "crypto/jwt.h"
#include "iam/iam.h"
#include "object/sysconfig.h"
#include "storage/format.h"

#define ROOT_AK "rootadmin"
#define ROOT_SK "rootsecret123"

/* ---- JWT --------------------------------------------------------------------- */

static void test_jwt_reference(void **state) {
  (void)state;
  /* Produced with Python's hmac module. */
  const char *hs256 =
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhY2Nlc3NLZXkiOiJTVFNLRVkiLCJleHAiOjQxMDI0NDQ4MDAsInBhcmVudCI6ImFsaWNlIn0."
      "bSv4JBxM-w_qsHHtN17auLqJvkqPwufkV5h2iKgRmC4";
  yyjson_doc *c = buckets_jwt_verify(hs256, "topsecret123", 1700000000);
  assert_non_null(c);
  assert_string_equal(yyjson_get_str(yyjson_obj_get(yyjson_doc_get_root(c), "parent")), "alice");
  yyjson_doc_free(c);
  assert_null(buckets_jwt_verify(hs256, "wrongsecret", 1700000000));
  assert_null(buckets_jwt_verify(hs256, "topsecret123", 4102444801LL)); /* expired */

  const char *expired = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJhY2Nlc3NLZXkiOiJYIiwiZXhwIjoxMDAwfQ."
                        "fO14jZ33QdOzKf4M69OxmTl_IHFeWcP31MMzqoT9rfAQ0VJML4OFqoJJQtV-WoN_i4sO-WLDOTTYf7z_JXXFfg";
  c = buckets_jwt_verify(expired, "topsecret123", 999);
  assert_non_null(c);
  yyjson_doc_free(c);
  assert_null(buckets_jwt_verify(expired, "topsecret123", 1000));
}

static void test_jwt_roundtrip(void **state) {
  (void)state;
  buckets_buf tok = BUCKETS_BUF_INIT;
  const char *claims = "{\"accessKey\":\"AK\",\"parent\":\"p\"}";
  buckets_jwt_sign(claims, strlen(claims), "k3y", &tok);
  yyjson_doc *c = buckets_jwt_verify(tok.data, "k3y", time(NULL));
  assert_non_null(c);
  yyjson_doc_free(c);
  /* Tampering with any byte of the signature fails. */
  tok.data[tok.len - 2] ^= 1;
  assert_null(buckets_jwt_verify(tok.data, "k3y", time(NULL)));
  /* No accessKey/sub claim fails. */
  const char *bare = "{\"parent\":\"p\"}";
  buckets_jwt_sign(bare, strlen(bare), "k3y", &tok);
  assert_null(buckets_jwt_verify(tok.data, "k3y", time(NULL)));
  buckets_buf_free(&tok);
  assert_null(buckets_jwt_verify("a.b", "k", 0));
  assert_null(buckets_jwt_verify("a.b.c.d", "k", 0));
}

/* ---- strmap ------------------------------------------------------------------- */

static void test_strmap(void **state) {
  (void)state;
  buckets_strmap m = BUCKETS_STRMAP_INIT;
  char key[32];
  for (intptr_t i = 1; i <= 5000; i++) {
    snprintf(key, sizeof(key), "k%ld", (long)i);
    assert_null(buckets_strmap_put(&m, key, (void *)i));
  }
  for (intptr_t i = 1; i <= 5000; i += 2) {
    snprintf(key, sizeof(key), "k%ld", (long)i);
    assert_ptr_equal(buckets_strmap_del(&m, key), (void *)i);
  }
  assert_int_equal(m.n, 2500);
  for (intptr_t i = 1; i <= 5000; i++) {
    snprintf(key, sizeof(key), "k%ld", (long)i);
    assert_ptr_equal(buckets_strmap_get(&m, key), i % 2 ? NULL : (void *)i);
  }
  size_t it = 0, count = 0;
  while (buckets_strmap_next(&m, &it, NULL, NULL)) count++;
  assert_int_equal(count, 2500);
  assert_ptr_equal(buckets_strmap_put(&m, "k2", (void *)7), (void *)2);
  assert_ptr_equal(buckets_strmap_get(&m, "k2"), (void *)7);
  buckets_strmap_free(&m);
}

static void test_time_rfc3339(void **state) {
  (void)state;
  char out[BUCKETS_TIME_RFC3339_NANO_LEN + 1];
  buckets_time_rfc3339_nano(0, 0, out);
  assert_string_equal(out, "1970-01-01T00:00:00Z");
  buckets_time_rfc3339_nano(-62135596800LL, 0, out);
  assert_string_equal(out, "0001-01-01T00:00:00Z");
  buckets_time_rfc3339_nano(1700000000, 120000000, out);
  assert_string_equal(out, "2023-11-14T22:13:20.12Z");
  long long s;
  long ns;
  assert_true(buckets_time_parse_rfc3339("2023-11-14T22:13:20.12Z", &s, &ns));
  assert_int_equal(s, 1700000000);
  assert_int_equal(ns, 120000000);
  assert_true(buckets_time_parse_rfc3339("0001-01-01T00:00:00Z", &s, &ns));
  assert_int_equal(s, -62135596800LL);
  assert_true(buckets_time_parse_rfc3339("1970-01-01T01:00:00+01:00", &s, &ns));
  assert_int_equal(s, 0);
  assert_true(buckets_time_parse_rfc3339("2024-02-29T00:00:00Z", &s, &ns));
  assert_int_equal(s, 1709164800);
}

/* ---- the store ------------------------------------------------------------------ */

typedef struct {
  char root[256];
  buckets_objlayer *layer;
} fixture;

static int setup(void **state) {
  fixture *f = calloc(1, sizeof(*f));
  snprintf(f->root, sizeof(f->root), "/tmp/buckets-iam-XXXXXX");
  assert_non_null(mkdtemp(f->root));
  buckets_drive *drives[4];
  for (int i = 0; i < 4; i++) {
    char p[300];
    snprintf(p, sizeof(p), "%s/d%d", f->root, i);
    mkdir(p, 0755);
    assert_int_equal(buckets_drive_open_raw(p, &drives[i]), BUCKETS_DRIVE_OK);
  }
  buckets_format_result fr;
  char err[256];
  if (!buckets_format_negotiate(drives, 4, 4, NULL, NULL, &fr, err, sizeof(err))) fail_msg("format: %s", err);
  f->layer = buckets_objlayer_new(&fr, 1, -1);
  buckets_format_result_free(&fr);
  *state = f;
  return 0;
}

static int teardown(void **state) {
  fixture *f = *state;
  buckets_objlayer_free(f->layer);
  char cmd[300];
  snprintf(cmd, sizeof(cmd), "rm -rf '%s'", f->root);
  if (system(cmd) != 0) return 1;
  free(f);
  return 0;
}

static bool allowed(buckets_iam *iam, const char *ak, const char *token, const char *action, const char *bucket,
                    const char *object) {
  buckets_iam_ident *id;
  if (buckets_iam_get_key(iam, ak, &id) != BUCKETS_IAM_KEY_OK) return false;
  bool owner;
  bool ok = buckets_iam_check_token(iam, id, token, &owner) == BUCKETS_IAM_TOKEN_OK;
  const char *user = buckets_iam_condition_user(id);
  const char *const uv[] = {user};
  buckets_cond_value conds[] = {{"username", uv, 1}};
  buckets_policy_args a = {.action = action, .bucket = bucket, .object = object, .conds = conds, .nconds = 1};
  ok = ok && buckets_iam_is_allowed(iam, id, owner, &a);
  buckets_iam_ident_release(id);
  return ok;
}

static void test_users_and_policies(void **state) {
  fixture *f = *state;
  buckets_iam *iam = buckets_iam_new(ROOT_AK, ROOT_SK);
  assert_true(buckets_iam_start(iam, f->layer));

  assert_int_equal(buckets_iam_add_user(iam, "alice", "alicesecret", "enabled"), BUCKETS_IAM_OK);
  assert_int_equal(buckets_iam_add_user(iam, "ab", "alicesecret", "enabled"), BUCKETS_IAM_ERR_INVALID_ACCESS_KEY);
  assert_int_equal(buckets_iam_add_user(iam, "bob", "short", "enabled"), BUCKETS_IAM_ERR_INVALID_SECRET_KEY);
  /* No policy: nothing is allowed; root is allowed everything. */
  assert_false(allowed(iam, "alice", NULL, "s3:GetObject", "photos", "a.jpg"));
  assert_true(allowed(iam, ROOT_AK, NULL, "s3:GetObject", "photos", "a.jpg"));

  const char *pol = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"s3:GetObject\"],"
                    "\"Resource\":[\"arn:aws:s3:::photos/${aws:username}/*\"]}]}";
  char err[256];
  assert_int_equal(buckets_iam_set_policy(iam, "own-photos", pol, strlen(pol), err, sizeof(err)), BUCKETS_IAM_OK);
  const char *attach[] = {"own-photos"};
  char *changed, *effective;
  assert_int_equal(buckets_iam_policy_update(iam, "alice", false, true, attach, 1, &changed, &effective),
                   BUCKETS_IAM_OK);
  assert_string_equal(changed, "own-photos");
  free(changed);
  free(effective);
  assert_int_equal(buckets_iam_policy_update(iam, "alice", false, true, attach, 1, NULL, NULL),
                   BUCKETS_IAM_ERR_NO_POLICY_CHANGE);
  assert_true(allowed(iam, "alice", NULL, "s3:GetObject", "photos", "alice/a.jpg"));
  assert_false(allowed(iam, "alice", NULL, "s3:GetObject", "photos", "bob/a.jpg"));
  assert_false(allowed(iam, "alice", NULL, "s3:PutObject", "photos", "alice/a.jpg"));
  /* A token on a static credential is rejected. */
  assert_false(allowed(iam, "alice", "sometoken", "s3:GetObject", "photos", "alice/a.jpg"));
  assert_int_equal(buckets_iam_delete_policy(iam, "own-photos"), BUCKETS_IAM_ERR_POLICY_IN_USE);

  /* Disabled users fail lookup with a distinct status. */
  assert_int_equal(buckets_iam_set_user_status(iam, "alice", false), BUCKETS_IAM_OK);
  buckets_iam_ident *id;
  assert_int_equal(buckets_iam_get_key(iam, "alice", &id), BUCKETS_IAM_KEY_DISABLED);
  assert_int_equal(buckets_iam_set_user_status(iam, "alice", true), BUCKETS_IAM_OK);

  /* Groups: policies flow to members; a disabled group removes them. */
  assert_int_equal(buckets_iam_add_user(iam, "bob", "bobsecret1", "enabled"), BUCKETS_IAM_OK);
  const char *members[] = {"bob"};
  assert_int_equal(buckets_iam_group_add_members(iam, "devs", members, 1), BUCKETS_IAM_OK);
  const char *rw[] = {"readwrite"};
  assert_int_equal(buckets_iam_policy_update(iam, "devs", true, true, rw, 1, NULL, NULL), BUCKETS_IAM_OK);
  assert_true(allowed(iam, "bob", NULL, "s3:PutObject", "any", "x"));
  assert_int_equal(buckets_iam_group_set_status(iam, "devs", false), BUCKETS_IAM_OK);
  assert_false(allowed(iam, "bob", NULL, "s3:PutObject", "any", "x"));
  assert_int_equal(buckets_iam_group_set_status(iam, "devs", true), BUCKETS_IAM_OK);
  assert_int_equal(buckets_iam_group_remove_members(iam, "devs", NULL, 0), BUCKETS_IAM_ERR_GROUP_NOT_EMPTY);

  /* Everything survives a restart (a second store on the same drives). */
  buckets_iam *iam2 = buckets_iam_new(ROOT_AK, ROOT_SK);
  assert_true(buckets_iam_start(iam2, f->layer));
  assert_true(allowed(iam2, "alice", NULL, "s3:GetObject", "photos", "alice/a.jpg"));
  assert_true(allowed(iam2, "bob", NULL, "s3:PutObject", "any", "x"));
  buckets_iam_user_info ui;
  assert_int_equal(buckets_iam_get_user_info(iam2, "bob", &ui), BUCKETS_IAM_OK);
  assert_int_equal(ui.nmember_of, 1);
  assert_string_equal(ui.member_of[0], "devs");
  assert_true(ui.enabled);
  buckets_iam_user_info_free(&ui, 1);
  buckets_iam_policy_doc pd;
  assert_int_equal(buckets_iam_get_policy(iam2, "own-photos", &pd), BUCKETS_IAM_OK);
  assert_true(buckets_iam_time_is_set(pd.created));
  buckets_iam_policy_doc_free(&pd, 1);

  /* Deleting a user leaves its groups. */
  assert_int_equal(buckets_iam_delete_user(iam2, "bob"), BUCKETS_IAM_OK);
  buckets_iam_group_desc gd;
  assert_int_equal(buckets_iam_group_describe(iam2, "devs", &gd), BUCKETS_IAM_OK);
  assert_int_equal(gd.nmembers, 0);
  assert_string_equal(gd.policy, "readwrite");
  buckets_iam_group_desc_free(&gd);
  assert_int_equal(buckets_iam_group_remove_members(iam2, "devs", NULL, 0), BUCKETS_IAM_OK);
  assert_int_equal(buckets_iam_group_describe(iam2, "devs", &gd), BUCKETS_IAM_ERR_NO_SUCH_GROUP);
  buckets_iam_free(iam2);
  buckets_iam_free(iam);
}

static void test_service_accounts(void **state) {
  fixture *f = *state;
  buckets_iam *iam = buckets_iam_new(ROOT_AK, ROOT_SK);
  assert_true(buckets_iam_start(iam, f->layer));
  assert_int_equal(buckets_iam_add_user(iam, "carol", "carolsecret", "enabled"), BUCKETS_IAM_OK);
  assert_int_equal(buckets_iam_policy_set(iam, "carol", false, BUCKETS_IAM_REG, "readwrite"), BUCKETS_IAM_OK);

  /* Inherited policy. */
  buckets_iam_svc_opts o = {.parent = "carol", .access_key = "carolsvc1", .secret_key = "svcsecret1"};
  buckets_iam_ident *svc;
  char err[256];
  assert_int_equal(buckets_iam_add_svc(iam, &o, &svc, err, sizeof(err)), BUCKETS_IAM_OK);
  assert_true(buckets_iam_ident_is_svc(svc));
  assert_string_equal(buckets_iam_ident_claim(svc, "sa-policy"), "inherited-policy");
  buckets_iam_ident_release(svc);
  assert_true(allowed(iam, "carolsvc1", NULL, "s3:PutObject", "b1b", "k"));
  assert_int_equal(buckets_iam_add_svc(iam, &o, NULL, err, sizeof(err)), BUCKETS_IAM_ERR_SVC_NOT_ALLOWED);

  /* Embedded policy narrows the parent's. */
  const char *ro = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"s3:GetObject\"],"
                   "\"Resource\":[\"arn:aws:s3:::*\"]}]}";
  buckets_iam_svc_opts o2 = {.parent = "carol", .session_policy = ro};
  assert_int_equal(buckets_iam_add_svc(iam, &o2, &svc, err, sizeof(err)), BUCKETS_IAM_OK);
  char ak[64];
  snprintf(ak, sizeof(ak), "%s", svc->access_key);
  assert_int_equal(strlen(ak), 20);
  assert_int_equal(strlen(svc->secret_key), 40);
  buckets_iam_ident_release(svc);
  assert_true(allowed(iam, ak, NULL, "s3:GetObject", "b1b", "k"));
  assert_false(allowed(iam, ak, NULL, "s3:PutObject", "b1b", "k"));

  /* Updating the policy to blank makes it inherit again. */
  buckets_iam_svc_update u = {.set_policy = true, .session_policy = "{}"};
  assert_int_equal(buckets_iam_update_svc(iam, ak, &u, err, sizeof(err)), BUCKETS_IAM_OK);
  assert_true(allowed(iam, ak, NULL, "s3:PutObject", "b1b", "k"));
  buckets_iam_svc_update dis = {.status = "off"};
  assert_int_equal(buckets_iam_update_svc(iam, ak, &dis, err, sizeof(err)), BUCKETS_IAM_OK);
  buckets_iam_ident *id;
  assert_int_equal(buckets_iam_get_key(iam, ak, &id), BUCKETS_IAM_KEY_DISABLED);

  /* Root's service accounts act as root (owner). */
  buckets_iam_svc_opts o3 = {.parent = ROOT_AK, .access_key = "rootsvc1", .secret_key = "rootsvcsecret"};
  assert_int_equal(buckets_iam_add_svc(iam, &o3, NULL, err, sizeof(err)), BUCKETS_IAM_OK);
  assert_true(allowed(iam, "rootsvc1", NULL, "admin:ServerInfo", NULL, NULL));

  /* Reloaded from storage, the tokens still verify. */
  buckets_iam *iam2 = buckets_iam_new(ROOT_AK, ROOT_SK);
  assert_true(buckets_iam_start(iam2, f->layer));
  assert_true(allowed(iam2, "carolsvc1", NULL, "s3:PutObject", "b1b", "k"));
  buckets_iam_ident **list;
  size_t n;
  buckets_iam_list_derived(iam2, "carol", BUCKETS_IAM_SVC, &list, &n);
  assert_int_equal(n, 2);
  for (size_t i = 0; i < n; i++) buckets_iam_ident_release(list[i]);
  free(list);

  /* Deleting the parent removes its service accounts. */
  assert_int_equal(buckets_iam_delete_user(iam2, "carol"), BUCKETS_IAM_OK);
  assert_int_equal(buckets_iam_get_key(iam2, "carolsvc1", &id), BUCKETS_IAM_KEY_UNKNOWN);
  buckets_iam_free(iam2);
  buckets_iam_free(iam);
}

static void test_sts(void **state) {
  fixture *f = *state;
  buckets_iam *iam = buckets_iam_new(ROOT_AK, ROOT_SK);
  assert_true(buckets_iam_start(iam, f->layer));
  assert_int_equal(buckets_iam_add_user(iam, "dave", "davesecret", "enabled"), BUCKETS_IAM_OK);
  assert_int_equal(buckets_iam_policy_set(iam, "dave", false, BUCKETS_IAM_REG, "readonly"), BUCKETS_IAM_OK);
  long long exp = (long long)time(NULL) + 3600;
  char claims[256];
  snprintf(claims, sizeof(claims), "{\"exp\":%lld,\"parent\":\"dave\"}", exp);
  buckets_iam_ident *t;
  assert_int_equal(buckets_iam_set_temp_user(iam, "STSKEY0001", "stssecret01", "dave", NULL, 0,
                                             (buckets_iam_time){exp, 0}, claims, NULL, &t),
                   BUCKETS_IAM_OK);
  char token[2048];
  snprintf(token, sizeof(token), "%s", t->session_token);
  buckets_iam_ident_release(t);
  assert_true(allowed(iam, "STSKEY0001", token, "s3:GetObject", "b1b", "k"));
  assert_false(allowed(iam, "STSKEY0001", token, "s3:PutObject", "b1b", "k"));
  assert_false(allowed(iam, "STSKEY0001", NULL, "s3:GetObject", "b1b", "k")); /* token required */
  assert_false(allowed(iam, "STSKEY0001", "x.y.z", "s3:GetObject", "b1b", "k"));

  /* A session policy narrows further. */
  const char *sp = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"s3:GetObject\"],"
                   "\"Resource\":[\"arn:aws:s3:::only/*\"]}]}";
  char b64[512];
  buckets_base64_encode((const uint8_t *)sp, strlen(sp), b64);
  char claims2[1024];
  snprintf(claims2, sizeof(claims2), "{\"exp\":%lld,\"parent\":\"dave\",\"sessionPolicy\":\"%s\"}", exp, b64);
  assert_int_equal(buckets_iam_set_temp_user(iam, "STSKEY0002", "stssecret02", "dave", NULL, 0,
                                             (buckets_iam_time){exp, 0}, claims2, NULL, &t),
                   BUCKETS_IAM_OK);
  snprintf(token, sizeof(token), "%s", t->session_token);
  buckets_iam_ident_release(t);
  assert_true(allowed(iam, "STSKEY0002", token, "s3:GetObject", "only", "k"));
  assert_false(allowed(iam, "STSKEY0002", token, "s3:GetObject", "other", "k"));

  /* Another server finds it in storage on first use. */
  buckets_iam *iam2 = buckets_iam_new(ROOT_AK, ROOT_SK);
  assert_true(buckets_iam_start(iam2, f->layer));
  assert_true(allowed(iam2, "STSKEY0002", token, "s3:GetObject", "only", "k"));
  buckets_iam_free(iam2);
  buckets_iam_free(iam);
}

static char *policy_claim(void *ud) {
  (void)ud;
  return strdup("policy");
}

/* Roles kept current (iam/idsync.h): a person's temporary credential follows their new roles with the token its
 * client already holds; their access key's claim is re-signed; with no roles left, the temporary credential ends
 * and the key allows nothing. */
static void test_person_policies(void **state) {
  fixture *f = *state;
  buckets_iam *iam = buckets_iam_new(ROOT_AK, ROOT_SK);
  assert_true(buckets_iam_start(iam, f->layer));
  buckets_iam_openid_hooks hooks = {.claim_name = policy_claim};
  buckets_iam_set_openid_hooks(iam, &hooks);
  const char *who = "oidc-ann";
  size_t n = 0;
  assert_int_equal(buckets_iam_set_person_policies(iam, who, "readwrite", &n), BUCKETS_IAM_OK); /* a sign-in */
  long long exp = (long long)time(NULL) + 3600;
  char claims[256];
  snprintf(claims, sizeof(claims), "{\"exp\":%lld,\"parent\":\"%s\",\"policy\":\"readwrite\"}", exp, who);
  buckets_iam_ident *t;
  assert_int_equal(buckets_iam_set_temp_user(iam, "STSANN0001", "stsannsecret", who, NULL, 0,
                                             (buckets_iam_time){exp, 0}, claims, NULL, &t),
                   BUCKETS_IAM_OK);
  char token[2048];
  snprintf(token, sizeof(token), "%s", t->session_token);
  buckets_iam_ident_release(t);
  char err[256];
  buckets_iam_svc_opts o = {.parent = who, .access_key = "ANNKEY0001", .secret_key = "annkeysecret01",
                            .claims_json = "{\"policy\":\"readwrite\"}"};
  assert_int_equal(buckets_iam_add_svc(iam, &o, NULL, err, sizeof(err)), BUCKETS_IAM_OK);
  assert_true(allowed(iam, "STSANN0001", token, "s3:PutObject", "b1b", "k"));
  assert_true(allowed(iam, "ANNKEY0001", NULL, "s3:PutObject", "b1b", "k"));

  /* moved to readonly: one access key re-signed; the session keeps its token and reads, but no longer writes */
  assert_int_equal(buckets_iam_set_person_policies(iam, who, "readonly", &n), BUCKETS_IAM_OK);
  assert_int_equal(n, 1);
  assert_true(allowed(iam, "STSANN0001", token, "s3:GetObject", "b1b", "k"));
  assert_false(allowed(iam, "STSANN0001", token, "s3:PutObject", "b1b", "k"));
  assert_true(allowed(iam, "ANNKEY0001", NULL, "s3:GetObject", "b1b", "k"));
  assert_false(allowed(iam, "ANNKEY0001", NULL, "s3:PutObject", "b1b", "k"));
  buckets_iam_ident *k;
  assert_int_equal(buckets_iam_get_key(iam, "ANNKEY0001", &k), BUCKETS_IAM_KEY_OK);
  assert_string_equal(buckets_iam_ident_claim(k, "policy"), "readonly");
  assert_string_equal(k->secret_key, "annkeysecret01");
  buckets_iam_ident_release(k);
  assert_int_equal(buckets_iam_get_key(iam, "STSANN0001", &k), BUCKETS_IAM_KEY_OK);
  assert_string_equal(k->session_token, token); /* the client's token still matches */
  buckets_iam_ident_release(k);

  /* no roles left: the session ends (its token's claim would give readwrite back), the key allows nothing */
  assert_int_equal(buckets_iam_set_person_policies(iam, who, "", &n), BUCKETS_IAM_OK);
  assert_int_equal(n, 2);
  assert_int_equal(buckets_iam_get_key(iam, "STSANN0001", &k), BUCKETS_IAM_KEY_UNKNOWN);
  assert_false(allowed(iam, "ANNKEY0001", NULL, "s3:GetObject", "b1b", "k"));
  /* a role given back: the key works again */
  assert_int_equal(buckets_iam_set_person_policies(iam, who, "readonly", &n), BUCKETS_IAM_OK);
  assert_true(allowed(iam, "ANNKEY0001", NULL, "s3:GetObject", "b1b", "k"));
  buckets_iam_free(iam);
}

/* Files exactly as MinIO writes them load. */
static void test_minio_format(void **state) {
  fixture *f = *state;
  const char *ident =
      "{\"version\":1,\"credentials\":{\"accessKey\":\"erin\",\"secretKey\":\"erinsecret\",\"expiration\":"
      "\"1970-01-01T00:00:00Z\",\"status\":\"on\"},\"updatedAt\":\"2025-10-20T10:00:00.123456Z\"}";
  const char *mp = "{\"version\":1,\"policy\":\"erin-pol\",\"updatedAt\":\"2025-10-20T10:00:00.2Z\"}";
  /* The bare (pre-12/2021) policy form. */
  const char *pol = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"s3:ListBucket\"],"
                    "\"Resource\":[\"arn:aws:s3:::logs\"]}]}";
  assert_int_equal(buckets_sysconfig_write(f->layer, "config/iam/users/erin/identity.json", ident, strlen(ident)), 0);
  assert_int_equal(buckets_sysconfig_write(f->layer, "config/iam/policydb/users/erin.json", mp, strlen(mp)), 0);
  assert_int_equal(buckets_sysconfig_write(f->layer, "config/iam/policies/erin-pol/policy.json", pol, strlen(pol)), 0);
  buckets_iam *iam = buckets_iam_new(ROOT_AK, ROOT_SK);
  assert_true(buckets_iam_start(iam, f->layer));
  assert_true(allowed(iam, "erin", NULL, "s3:ListBucket", "logs", NULL));
  assert_false(allowed(iam, "erin", NULL, "s3:ListBucket", "other", NULL));
  buckets_iam_policy_doc pd;
  assert_int_equal(buckets_iam_get_policy(iam, "erin-pol", &pd), BUCKETS_IAM_OK);
  assert_true(buckets_iam_time_is_set(pd.created)); /* from the object's mod time */
  buckets_iam_policy_doc_free(&pd, 1);
  buckets_iam_free(iam);
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_jwt_reference),
      cmocka_unit_test_setup_teardown(test_person_policies, setup, teardown),
      cmocka_unit_test(test_jwt_roundtrip),
      cmocka_unit_test(test_strmap),
      cmocka_unit_test(test_time_rfc3339),
      cmocka_unit_test_setup_teardown(test_users_and_policies, setup, teardown),
      cmocka_unit_test_setup_teardown(test_service_accounts, setup, teardown),
      cmocka_unit_test_setup_teardown(test_sts, setup, teardown),
      cmocka_unit_test_setup_teardown(test_minio_format, setup, teardown),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
