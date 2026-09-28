/* SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Vectors are the worked examples from the AWS SigV4 documentation:
 * the generic test suite (get-vanilla) and the S3 "Signature Calculations
 * for the Authorization Header" / "Query String" pages. */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <cmocka.h>
#include <stdio.h>
#include <string.h>

#include "core/timefmt.h"
#include "s3/sigv2.h"
#include "s3/sigv4.h"

#define S3_AK "AKIAIOSFODNN7EXAMPLE"
#define S3_SK "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
#define SUITE_AK "AKIDEXAMPLE"
#define SUITE_SK "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"

static bool lookup(void *ud, buckets_str ak, char secret[BUCKETS_SECRET_MAX]) {
  (void)ud;
  const char *sk = buckets_str_eq_c(ak, S3_AK) ? S3_SK : buckets_str_eq_c(ak, SUITE_AK) ? SUITE_SK : NULL;
  if (!sk) return false;
  snprintf(secret, BUCKETS_SECRET_MAX, "%s", sk);
  return true;
}

static void make_request(buckets_http_request *req, const char *method, const char *target,
                         const char *const *headers /* name, value, ..., NULL */) {
  memset(req, 0, sizeof(*req));
  req->method = buckets_str_c(method);
  req->target = buckets_str_c(target);
  buckets_str_cut(req->target, '?', &req->path, &req->query);
  for (size_t i = 0; headers[i]; i += 2) {
    req->headers[req->nheaders].name = buckets_str_c(headers[i]);
    req->headers[req->nheaders].value = buckets_str_c(headers[i + 1]);
    req->nheaders++;
  }
}

static buckets_sigv4_config config(const char *service, const char *amz_now) {
  time_t now;
  buckets_time_parse_amz(buckets_str_c(amz_now), &now);
  return (buckets_sigv4_config){.region = "us-east-1", .service = service, .now = now, .lookup = lookup};
}

static buckets_s3_error verify_header(const buckets_sigv4_config *cfg, const buckets_http_request *req,
                                      buckets_sigv4_result *res) {
  buckets_query q;
  buckets_query_parse(req->query, &q);
  buckets_s3_error e = buckets_sigv4_verify_header(cfg, req, &q, res);
  buckets_query_free(&q);
  return e;
}

static void test_suite_get_vanilla(void **state) {
  static const char *const h[] = {
      "Host", "example.amazonaws.com", "X-Amz-Date", "20150830T123600Z", "Authorization",
      "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, "
      "SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31",
      NULL};
  buckets_http_request req;
  make_request(&req, "GET", "/", h);
  buckets_sigv4_config cfg = config("service", "20150830T123600Z");
  buckets_sigv4_result res;
  assert_int_equal(verify_header(&cfg, &req, &res), BUCKETS_ERR_NONE);
  assert_string_equal(res.access_key, SUITE_AK);
  assert_string_equal(res.payload_hash, BUCKETS_EMPTY_SHA256);
}

static const char *const k_get_object[] = {
    "Host", "examplebucket.s3.amazonaws.com", "Range", "bytes=0-9", "x-amz-content-sha256",
    BUCKETS_EMPTY_SHA256, "x-amz-date", "20130524T000000Z", "Authorization",
    "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,"
    "SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,"
    "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41",
    NULL};

static void test_s3_get_object(void **state) {
  buckets_http_request req;
  make_request(&req, "GET", "/test.txt", k_get_object);
  buckets_sigv4_config cfg = config("s3", "20130524T000100Z");
  buckets_sigv4_result res;
  assert_int_equal(verify_header(&cfg, &req, &res), BUCKETS_ERR_NONE);
}

static void test_s3_get_bucket_lifecycle(void **state) {
  /* "?lifecycle": a key with no '=' canonicalizes to "lifecycle=". */
  static const char *const h[] = {
      "Host", "examplebucket.s3.amazonaws.com", "x-amz-content-sha256", BUCKETS_EMPTY_SHA256, "x-amz-date",
      "20130524T000000Z", "Authorization",
      "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,"
      "SignedHeaders=host;x-amz-content-sha256;x-amz-date,"
      "Signature=fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543",
      NULL};
  buckets_http_request req;
  make_request(&req, "GET", "/?lifecycle", h);
  buckets_sigv4_config cfg = config("s3", "20130524T000000Z");
  buckets_sigv4_result res;
  assert_int_equal(verify_header(&cfg, &req, &res), BUCKETS_ERR_NONE);
}

static void test_s3_list_objects(void **state) {
  /* Query keys are re-sorted: max-keys before prefix. */
  static const char *const h[] = {
      "Host", "examplebucket.s3.amazonaws.com", "x-amz-content-sha256", BUCKETS_EMPTY_SHA256, "x-amz-date",
      "20130524T000000Z", "Authorization",
      "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,"
      "SignedHeaders=host;x-amz-content-sha256;x-amz-date,"
      "Signature=34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7",
      NULL};
  buckets_http_request req;
  make_request(&req, "GET", "/?max-keys=2&prefix=J", h);
  buckets_sigv4_config cfg = config("s3", "20130524T000000Z");
  buckets_sigv4_result res;
  assert_int_equal(verify_header(&cfg, &req, &res), BUCKETS_ERR_NONE);
}

static void test_s3_presigned(void **state) {
  static const char *const h[] = {"Host", "examplebucket.s3.amazonaws.com", NULL};
  buckets_http_request req;
  make_request(&req, "GET",
               "/test.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256"
               "&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request"
               "&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host"
               "&X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404",
               h);
  buckets_query q;
  buckets_query_parse(req.query, &q);
  assert_int_equal(buckets_auth_classify(&req, &q), BUCKETS_AUTH_SIGV4_PRESIGNED);
  buckets_sigv4_result res;

  buckets_sigv4_config cfg = config("s3", "20130524T010000Z");
  assert_int_equal(buckets_sigv4_verify_presigned(&cfg, &req, &q, &res), BUCKETS_ERR_NONE);
  assert_string_equal(res.payload_hash, BUCKETS_UNSIGNED_PAYLOAD);

  cfg = config("s3", "20130525T000001Z"); /* one second past 86400s */
  assert_int_equal(buckets_sigv4_verify_presigned(&cfg, &req, &q, &res), BUCKETS_ERR_EXPIRED_PRESIGN_REQUEST);

  cfg = config("s3", "20130523T234000Z"); /* 20 minutes before X-Amz-Date */
  assert_int_equal(buckets_sigv4_verify_presigned(&cfg, &req, &q, &res), BUCKETS_ERR_REQUEST_NOT_READY_YET);
  buckets_query_free(&q);
}

static void test_rejections(void **state) {
  buckets_http_request req;
  buckets_sigv4_result res;
  buckets_sigv4_config cfg = config("s3", "20130524T000000Z");

  /* Tampered header value. */
  static const char *tampered[16];
  memcpy(tampered, k_get_object, sizeof(k_get_object));
  tampered[3] = "bytes=0-10";
  make_request(&req, "GET", "/test.txt", tampered);
  assert_int_equal(verify_header(&cfg, &req, &res), BUCKETS_ERR_SIGNATURE_DOES_NOT_MATCH);

  /* Tampered path. */
  make_request(&req, "GET", "/test2.txt", k_get_object);
  assert_int_equal(verify_header(&cfg, &req, &res), BUCKETS_ERR_SIGNATURE_DOES_NOT_MATCH);

  /* Clock skew beyond 15 minutes. */
  make_request(&req, "GET", "/test.txt", k_get_object);
  buckets_sigv4_config late = config("s3", "20130524T001600Z");
  assert_int_equal(verify_header(&late, &req, &res), BUCKETS_ERR_REQUEST_TIME_TOO_SKEWED);

  /* Wrong region is rejected before any crypto. */
  buckets_sigv4_config eu = cfg;
  eu.region = "eu-west-1";
  assert_int_equal(verify_header(&eu, &req, &res), BUCKETS_ERR_AUTHORIZATION_HEADER_MALFORMED);

  /* Unknown access key. */
  static const char *const unknown[] = {
      "Host", "x", "x-amz-date", "20130524T000000Z", "Authorization",
      "AWS4-HMAC-SHA256 Credential=NOBODY/20130524/us-east-1/s3/aws4_request,"
      "SignedHeaders=host;x-amz-date,Signature=00",
      NULL};
  make_request(&req, "GET", "/", unknown);
  assert_int_equal(verify_header(&cfg, &req, &res), BUCKETS_ERR_INVALID_ACCESS_KEY_ID);

  /* host must be signed. */
  static const char *const nohost[] = {
      "Host", "x", "x-amz-date", "20130524T000000Z", "Authorization",
      "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,"
      "SignedHeaders=x-amz-date,Signature=00",
      NULL};
  make_request(&req, "GET", "/", nohost);
  assert_int_equal(verify_header(&cfg, &req, &res), BUCKETS_ERR_UNSIGNED_HEADERS);

  /* Missing fields and wrong service. */
  static const char *const two_fields[] = {
      "Host", "x", "Authorization",
      "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,Signature=00", NULL};
  make_request(&req, "GET", "/", two_fields);
  assert_int_equal(verify_header(&cfg, &req, &res), BUCKETS_ERR_MISSING_FIELDS);
  static const char *const sts[] = {
      "Host", "x", "Authorization",
      "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/sts/aws4_request,"
      "SignedHeaders=host,Signature=00",
      NULL};
  make_request(&req, "GET", "/", sts);
  assert_int_equal(verify_header(&cfg, &req, &res), BUCKETS_ERR_INVALID_SERVICE_S3);
}

static void test_canonical_uri_and_query(void **state) {
  buckets_buf b = BUCKETS_BUF_INIT;
  assert_true(buckets_sigv4_canonical_uri(buckets_str_c("/my%20bucket/a+b/%E2%82%AC~x"), &b));
  assert_string_equal(b.data, "/my%20bucket/a%2Bb/%E2%82%AC~x");
  buckets_buf_reset(&b);
  assert_false(buckets_sigv4_canonical_uri(buckets_str_c("/bad%zz"), &b));

  buckets_query q;
  buckets_buf_reset(&b);
  buckets_query_parse(buckets_str_c("b=2&a=hello+world&a=%2F&X-Amz-Signature=zz&uploads"), &q);
  buckets_sigv4_canonical_query(&q, true, &b);
  /* Stable for duplicate keys (Go url.Values semantics), space as %20. */
  assert_string_equal(b.data, "a=hello%20world&a=%2F&b=2&uploads=");
  buckets_query_free(&q);
  buckets_buf_free(&b);
}

/* AWS "Signing and Authenticating REST Requests" (Signature Version 2) examples. */
static void test_sigv2_examples(void **state) {
  buckets_sigv4_config cfg = config("s3", "20070327T193642Z");
  buckets_sigv4_result res;
  buckets_http_request req;
  static const char *const get[] = {"Host", "johnsmith.s3.amazonaws.com", "Date", "Tue, 27 Mar 2007 19:36:42 +0000",
                                    "Authorization", "AWS AKIAIOSFODNN7EXAMPLE:bWq2s1WEIj+Ydj0vQ697zp+IXMU=", NULL};
  make_request(&req, "GET", "/johnsmith/photos/puppy.jpg", get);
  assert_int_equal(buckets_sigv2_verify_header(&cfg, &req, &res), BUCKETS_ERR_NONE);
  assert_string_equal(res.access_key, S3_AK);

  static const char *const put[] = {"Host", "johnsmith.s3.amazonaws.com", "Date", "Tue, 27 Mar 2007 21:15:45 +0000",
                                    "Content-Type", "image/jpeg", "Content-Length", "94328", "Authorization",
                                    "AWS AKIAIOSFODNN7EXAMPLE:MyyxeRY7whkBe+bq8fHCL/2kKUg=", NULL};
  make_request(&req, "PUT", "/johnsmith/photos/puppy.jpg", put);
  assert_int_equal(buckets_sigv2_verify_header(&cfg, &req, &res), BUCKETS_ERR_NONE);

  /* Tampering with a signed header fails. */
  static const char *const bad[] = {"Host", "johnsmith.s3.amazonaws.com", "Date", "Tue, 27 Mar 2007 21:15:46 +0000",
                                    "Content-Type", "image/jpeg", "Authorization",
                                    "AWS AKIAIOSFODNN7EXAMPLE:MyyxeRY7whkBe+bq8fHCL/2kKUg=", NULL};
  make_request(&req, "PUT", "/johnsmith/photos/puppy.jpg", bad);
  assert_int_equal(buckets_sigv2_verify_header(&cfg, &req, &res), BUCKETS_ERR_SIGNATURE_DOES_NOT_MATCH);

  /* Presigned: signature over Expires instead of Date; expired links fail. */
  char sig[32];
  const char *sts = "GET\n\n\n1175139620\n/johnsmith/photos/puppy.jpg";
  buckets_sigv2_sign(S3_SK, sts, strlen(sts), sig);
  char target[256], enc[64] = "";
  for (size_t i = 0, o = 0; sig[i]; i++) {
    const char *esc = sig[i] == '+' ? "%2B" : sig[i] == '/' ? "%2F" : sig[i] == '=' ? "%3D" : NULL;
    if (esc) {
      memcpy(enc + o, esc, 3);
      o += 3;
    } else {
      enc[o++] = sig[i];
    }
  }
  snprintf(target, sizeof(target), "/johnsmith/photos/puppy.jpg?AWSAccessKeyId=%s&Expires=1175139620&Signature=%s",
           S3_AK, enc);
  static const char *const host_only[] = {"Host", "johnsmith.s3.amazonaws.com", NULL};
  make_request(&req, "GET", target, host_only);
  assert_int_equal(buckets_sigv2_verify_presigned(&cfg, &req, &res), BUCKETS_ERR_NONE);
  buckets_sigv4_config late = config("s3", "20070329T040021Z");
  assert_int_equal(buckets_sigv2_verify_presigned(&late, &req, &res), BUCKETS_ERR_EXPIRED_PRESIGN_REQUEST);
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_suite_get_vanilla),      cmocka_unit_test(test_s3_get_object),
      cmocka_unit_test(test_s3_get_bucket_lifecycle), cmocka_unit_test(test_s3_list_objects),
      cmocka_unit_test(test_s3_presigned),            cmocka_unit_test(test_rejections),
      cmocka_unit_test(test_canonical_uri_and_query), cmocka_unit_test(test_sigv2_examples),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
