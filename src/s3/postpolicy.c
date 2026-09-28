/* Browser-based uploads: POST /bucket with multipart/form-data and a signed
 * policy document. Port of MinIO PostPolicyBucketHandler + postpolicyform.go.
 * SPDX-License-Identifier: AGPL-3.0-or-later */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <yyjson.h>

#include "core/log.h"
#include "core/timefmt.h"
#include "crypto/base64.h"
#include "crypto/hex.h"
#include "crypto/sha256.h"
#include "s3/checksum.h"
#include "s3/internal.h"
#include "s3/sigv2.h"
#include "s3/xml.h"

#define MAX_FIELD 20 * 1024 * 1024 /* MinIO: 2 x 10 MiB form memory */
#define MAX_PARTS 1000

/* ---- multipart/form-data reader -------------------------------------------- */

typedef struct {
  buckets_http_body_cursor cur;
  char delim[128]; /* "\r\n--" + boundary */
  size_t dlen;
  uint8_t buf[64 * 1024];
  size_t pos, len;
  bool eof;
  bool part_done; /* current part's data ended at a delimiter */
  bool final;     /* saw the closing "--boundary--" */
} form_reader;

static void fill(form_reader *f) {
  if (f->pos > 0) {
    memmove(f->buf, f->buf + f->pos, f->len - f->pos);
    f->len -= f->pos;
    f->pos = 0;
  }
  while (!f->eof && f->len < sizeof(f->buf)) {
    long n = buckets_http_body_read(&f->cur, f->buf + f->len, sizeof(f->buf) - f->len);
    if (n <= 0) {
      f->eof = true;
      break;
    }
    f->len += (size_t)n;
  }
}

/* Reads part data up to the next delimiter. Returns bytes, 0 at part end, -1 on error. */
static long part_read(form_reader *f, void *out, size_t n) {
  if (f->part_done) return 0;
  if (f->len - f->pos < f->dlen + 2) fill(f);
  size_t avail = f->len - f->pos;
  uint8_t *p = f->buf + f->pos;
  /* Find the delimiter in what we have. */
  for (size_t i = 0; i + f->dlen <= avail; i++) {
    if (p[i] == '\r' && memcmp(p + i, f->delim, f->dlen) == 0) {
      size_t take = BUCKETS_MIN(i, n);
      memcpy(out, p, take);
      f->pos += take;
      if (take == i) {
        f->pos += f->dlen;
        f->part_done = true;
      }
      return (long)take;
    }
  }
  if (f->eof) return -1; /* data never terminated */
  /* Safe to hand out everything except a possible delimiter prefix at the end. */
  size_t safe = avail > f->dlen ? avail - f->dlen : 0;
  size_t take = BUCKETS_MIN(safe, n);
  if (take == 0) {
    fill(f);
    return part_read(f, out, n);
  }
  memcpy(out, p, take);
  f->pos += take;
  return (long)take;
}

/* After a delimiter: "--" ends the form, CRLF starts another part. */
static bool next_part_start(form_reader *f) {
  if (f->len - f->pos < 2) fill(f);
  if (f->len - f->pos < 2) return false;
  if (memcmp(f->buf + f->pos, "--", 2) == 0) {
    f->final = true;
    return false;
  }
  if (memcmp(f->buf + f->pos, "\r\n", 2) != 0) return false;
  f->pos += 2;
  f->part_done = false;
  return true;
}

static bool read_line(form_reader *f, char *line, size_t cap) {
  size_t n = 0;
  for (;;) {
    if (f->pos == f->len) fill(f);
    if (f->pos == f->len) return false;
    char c = (char)f->buf[f->pos++];
    if (c == '\n') {
      if (n && line[n - 1] == '\r') n--;
      line[n] = '\0';
      return true;
    }
    if (n + 1 >= cap) return false;
    line[n++] = c;
  }
}

/* Parses a Content-Disposition parameter value (quoted or token). */
static char *disp_param(const char *line, const char *key) {
  size_t kl = strlen(key);
  for (const char *p = line; (p = strcasestr(p, key)) != NULL; p += kl) {
    if (p != line && p[-1] != ';' && p[-1] != ' ' && p[-1] != '\t') continue;
    const char *v = p + kl;
    while (*v == ' ') v++;
    if (*v != '=') continue;
    v++;
    while (*v == ' ') v++;
    if (*v == '"') {
      v++;
      const char *e = strchr(v, '"');
      return e ? buckets_xstrndup(v, (size_t)(e - v)) : NULL;
    }
    size_t len = strcspn(v, "; \t");
    return buckets_xstrndup(v, len);
  }
  return NULL;
}

/* ---- form values (http.Header semantics, canonical names) ------------------ */

typedef struct {
  char *name;
  char *value;
} field;

typedef struct {
  field *items;
  size_t n;
} fields;

static void canonical(const char *in, char *out, size_t cap) {
  bool up = true;
  size_t i = 0;
  for (; in[i] && i + 1 < cap; i++) {
    out[i] = up ? (char)toupper((unsigned char)in[i]) : (char)tolower((unsigned char)in[i]);
    up = in[i] == '-';
  }
  out[i] = '\0';
}

static void fields_add(fields *fs, const char *raw_name, const char *value) {
  char name[256];
  canonical(raw_name, name, sizeof(name));
  fs->items = buckets_xrealloc(fs->items, (fs->n + 1) * sizeof(field));
  fs->items[fs->n++] = (field){buckets_xstrdup(name), buckets_xstrdup(value)};
}

static void fields_set(fields *fs, const char *raw_name, const char *value) {
  char name[256];
  canonical(raw_name, name, sizeof(name));
  size_t w = 0;
  for (size_t i = 0; i < fs->n; i++) {
    if (strcmp(fs->items[i].name, name) == 0) {
      free(fs->items[i].name);
      free(fs->items[i].value);
      continue;
    }
    fs->items[w++] = fs->items[i];
  }
  fs->n = w;
  fields_add(fs, name, value);
}

static const char *fields_get(const fields *fs, const char *raw_name) {
  char name[256];
  canonical(raw_name, name, sizeof(name));
  for (size_t i = 0; i < fs->n; i++) {
    if (strcmp(fs->items[i].name, name) == 0) return fs->items[i].value;
  }
  return NULL;
}

static size_t fields_count(const fields *fs, const char *canon_name) {
  size_t c = 0;
  for (size_t i = 0; i < fs->n; i++) c += strcmp(fs->items[i].name, canon_name) == 0;
  return c;
}

static void fields_free(fields *fs) {
  for (size_t i = 0; i < fs->n; i++) {
    free(fs->items[i].name);
    free(fs->items[i].value);
  }
  free(fs->items);
}

/* ---- policy document ------------------------------------------------------- */

typedef struct {
  char op[16]; /* "eq" or "starts-with" */
  char *key;   /* "$name" lower-cased */
  char *value;
} condition;

typedef struct {
  int64_t expiration_ns;
  condition *conds;
  size_t nconds;
  bool range_valid;
  int64_t range_min, range_max;
} post_policy;

static void policy_free(post_policy *p) {
  for (size_t i = 0; i < p->nconds; i++) {
    free(p->conds[i].key);
    free(p->conds[i].value);
  }
  free(p->conds);
}

static void add_cond(post_policy *p, const char *op, const char *key, const char *value) {
  p->conds = buckets_xrealloc(p->conds, (p->nconds + 1) * sizeof(condition));
  condition *c = &p->conds[p->nconds++];
  snprintf(c->op, sizeof(c->op), "%s", op);
  c->key = buckets_xstrdup(key);
  for (char *k = c->key; *k; k++) *k = (char)tolower((unsigned char)*k);
  c->value = buckets_xstrdup(value);
}

/* time.Parse(time.RFC3339Nano, s) */
static bool parse_rfc3339(const char *s, int64_t *ns) {
  int y, mo, d, h, mi, se;
  if (sscanf(s, "%4d-%2d-%2dT%2d:%2d:%2d", &y, &mo, &d, &h, &mi, &se) != 6 || strlen(s) < 20) return false;
  const char *p = s + 19;
  int64_t frac = 0;
  if (*p == '.') {
    int digits = 0;
    for (p++; isdigit((unsigned char)*p); p++, digits++) {
      if (digits < 9) frac = frac * 10 + (*p - '0');
    }
    if (!digits) return false;
    for (; digits < 9; digits++) frac *= 10;
  }
  int offset = 0;
  if (*p == 'Z') {
    p++;
  } else if (*p == '+' || *p == '-') {
    int oh, om;
    if (sscanf(p + 1, "%2d:%2d", &oh, &om) != 2) return false;
    offset = (oh * 60 + om) * 60 * (*p == '-' ? -1 : 1);
    p += 6;
  } else {
    return false;
  }
  if (*p) return false;
  struct tm tm = {.tm_year = y - 1900, .tm_mon = mo - 1, .tm_mday = d, .tm_hour = h, .tm_min = mi, .tm_sec = se};
  *ns = ((int64_t)timegm(&tm) - offset) * 1000000000LL + frac;
  return true;
}

static bool json_int(yyjson_val *v, int64_t *out) {
  if (yyjson_is_num(v)) {
    *out = (int64_t)yyjson_get_num(v);
    return true;
  }
  if (yyjson_is_str(v)) {
    char *end;
    *out = strtoll(yyjson_get_str(v), &end, 10);
    return *yyjson_get_str(v) && !*end;
  }
  return false;
}

/* parsePostPolicyForm */
static bool parse_policy(const char *json, size_t n, post_policy *out) {
  memset(out, 0, sizeof(*out));
  yyjson_doc *doc = yyjson_read(json, n, 0);
  if (!doc) return false;
  yyjson_val *root = yyjson_doc_get_root(doc);
  bool ok = yyjson_is_obj(root);
  const char *expiration = NULL;
  yyjson_val *conds = NULL;
  size_t idx, max;
  yyjson_val *k, *v;
  bool seen_exp = false, seen_cond = false;
  if (ok) {
    yyjson_obj_foreach(root, idx, max, k, v) {
      const char *key = yyjson_get_str(k);
      if (strcmp(key, "expiration") == 0 && !seen_exp) {
        seen_exp = true;
        expiration = yyjson_get_str(v);
        if (!expiration) ok = false;
      } else if (strcmp(key, "conditions") == 0 && !seen_cond) {
        seen_cond = true;
        conds = v;
      } else {
        ok = false; /* duplicate or unknown top-level field */
      }
    }
  }
  if (ok && (!expiration || !parse_rfc3339(expiration, &out->expiration_ns))) ok = false;
  if (ok && conds && !yyjson_is_arr(conds)) ok = false;
  size_t ci, cmax;
  yyjson_val *cond;
  if (ok && conds) {
    yyjson_arr_foreach(conds, ci, cmax, cond) {
      if (!ok) break;
      if (yyjson_is_obj(cond)) {
        size_t oi, omax;
        yyjson_val *ck, *cv;
        yyjson_obj_foreach(cond, oi, omax, ck, cv) {
          if (!yyjson_is_str(cv)) {
            ok = false;
            break;
          }
          char key[512];
          snprintf(key, sizeof(key), "$%s", yyjson_get_str(ck));
          add_cond(out, "eq", key, yyjson_get_str(cv));
        }
      } else if (yyjson_is_arr(cond) && yyjson_arr_size(cond) == 3) {
        yyjson_val *a = yyjson_arr_get(cond, 0), *b = yyjson_arr_get(cond, 1), *c = yyjson_arr_get(cond, 2);
        const char *op = yyjson_get_str(a);
        if (op && (strcasecmp(op, "eq") == 0 || strcasecmp(op, "starts-with") == 0)) {
          if (!yyjson_is_str(b) || !yyjson_is_str(c) || yyjson_get_str(b)[0] != '$') {
            ok = false;
          } else {
            add_cond(out, strcasecmp(op, "eq") == 0 ? "eq" : "starts-with", yyjson_get_str(b), yyjson_get_str(c));
          }
        } else if (op && strcasecmp(op, "content-length-range") == 0) {
          if (!json_int(b, &out->range_min) || !json_int(c, &out->range_max)) ok = false;
          out->range_valid = true;
        } else {
          ok = false;
        }
      } else {
        ok = false;
      }
    }
  }
  yyjson_doc_free(doc);
  if (!ok) policy_free(out);
  return ok;
}

/* checkPostPolicy. Returns true on success; otherwise msg holds MinIO's
 * AccessDenied description. */
static bool check_policy(const fields *fs, const post_policy *p, int64_t now_ns, buckets_buf *msg) {
  static const struct {
    const char *key;
    bool starts_with;
  } known[] = {{"$acl", true},          {"$bucket", false},           {"$cache-control", true},
               {"$content-type", true}, {"$content-disposition", true}, {"$content-encoding", true},
               {"$expires", true},      {"$key", true},               {"$success_action_redirect", true},
               {"$redirect", true},     {"$success_action_status", true}, {"$x-amz-algorithm", false},
               {"$x-amz-credential", false}, {"$x-amz-date", false}};
  static const char *const exempt[] = {"X-Amz-Signature", "File", "Policy", "X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id",
                                       "X-Amz-Server-Side-Encryption-Context", "X-Amz-Server-Side-Encryption-Customer-Algorithm",
                                       "X-Amz-Server-Side-Encryption-Customer-Key",
                                       "X-Amz-Server-Side-Encryption-Customer-Key-Md5"};
  if (p->expiration_ns <= now_ns) {
    buckets_buf_append_c(msg, "Invalid according to Policy: Policy expired");
    return false;
  }

  bool *covered = buckets_xcalloc(fs->n ? fs->n : 1, sizeof(bool));
  bool err = false;
  for (size_t i = 0; i < fs->n; i++) {
    for (size_t e = 0; e < BUCKETS_ARRAY_LEN(exempt); e++) covered[i] |= strcmp(fs->items[i].name, exempt[e]) == 0;
    covered[i] |= strncmp(fs->items[i].name, "X-Ignore-", 9) == 0;
  }
  for (size_t c = 0; c < p->nconds && !err; c++) {
    const condition *cond = &p->conds[c];
    char canon[256];
    canonical(cond->key + 1, canon, sizeof(canon));
    size_t uncovered = 0;
    for (size_t i = 0; i < fs->n; i++) uncovered += !covered[i] && strcmp(fs->items[i].name, canon) == 0;
    if (uncovered >= 2) {
      buckets_buf_appendf(msg, "Invalid according to Policy: Policy Condition failed: [%s, %s, %s]. FormValues have multiple values: [",
                          cond->op, cond->key, cond->value);
      bool first = true;
      for (size_t i = 0; i < fs->n; i++) {
        if (covered[i] || strcmp(fs->items[i].name, canon) != 0) continue;
        buckets_buf_appendf(msg, "%s%s", first ? "" : ", ", fs->items[i].value);
        first = false;
      }
      buckets_buf_append_char(msg, ']');
      err = true;
      break;
    }
    const char *value = fields_get(fs, canon);
    bool matched = true;
    int known_idx = -1;
    for (size_t k = 0; k < BUCKETS_ARRAY_LEN(known); k++) {
      if (strcmp(known[k].key, cond->key) == 0) known_idx = (int)k;
    }
    bool starts = strcmp(cond->op, "starts-with") == 0;
    bool detailed = false;
    if (known_idx >= 0) {
      if (starts && !known[known_idx].starts_with) matched = false;
      else if (starts) matched = strncmp(value ? value : "", cond->value, strlen(cond->value)) == 0;
      else matched = strcmp(value ? value : "", cond->value) == 0;
    } else if (strncmp(cond->key, "$x-amz-", 7) == 0) {
      detailed = true;
      if (starts) matched = strncmp(value ? value : "", cond->value, strlen(cond->value)) == 0;
      else matched = strcmp(value ? value : "", cond->value) == 0;
    }
    if (!matched) {
      if (detailed) {
        buckets_buf_appendf(msg, "Invalid according to Policy: Policy Condition failed: [%s, %s, %s]", cond->op, cond->key,
                            cond->value);
      } else {
        buckets_buf_append_c(msg, "Invalid according to Policy: Policy Condition failed");
      }
      err = true;
    }
    for (size_t i = 0; i < fs->n; i++) covered[i] |= strcmp(fs->items[i].name, canon) == 0;
  }
  if (!err && fields_count(fs, "Signature")) {
    for (size_t i = 0; i < fs->n; i++) {
      if (strcmp(fs->items[i].name, "Signature") == 0 || strcasecmp(fs->items[i].name, "AWSAccessKeyId") == 0) {
        covered[i] = true;
      }
    }
  }
  bool first = true;
  for (size_t i = 0; !err && i < fs->n; i++) {
    if (covered[i]) continue;
    if (first) buckets_buf_append_c(msg, "Each form field that you specify in a form must appear in the list of policy conditions. \"");
    buckets_buf_appendf(msg, "%s%s", first ? "" : ", ", fs->items[i].name);
    first = false;
  }
  if (!first) {
    buckets_buf_append_c(msg, "\" not specified in the policy.");
    err = true;
  }
  free(covered);
  return !err;
}

/* doesPolicySignatureMatch: V2 when a "Signature" field is present, else V4. */
static buckets_s3_error verify_signature(s3_ctx *c, const fields *fs) {
  const char *policy = fields_get(fs, "Policy");
  if (!policy) policy = "";
  const char *v2sig = fields_get(fs, "Signature");
  if (v2sig) {
    const char *ak = fields_get(fs, "AWSAccessKeyId");
    if (!ak || strcmp(ak, c->s->root_user) != 0) return BUCKETS_ERR_INVALID_ACCESS_KEY_ID; /* IAM lookup later */
    const char *secret = c->s->root_password;
    char want[32];
    buckets_sigv2_sign(secret, policy, strlen(policy), want);
    if (strcmp(want, v2sig) != 0) return BUCKETS_ERR_SIGNATURE_DOES_NOT_MATCH;
    snprintf(c->access_key, sizeof(c->access_key), "%s", ak);
    return BUCKETS_ERR_NONE;
  }
  const char *cred = fields_get(fs, "X-Amz-Credential");
  const char *sig = fields_get(fs, "X-Amz-Signature");
  if (!cred) return BUCKETS_ERR_MISSING_FIELDS;
  /* Credential: AKID/DATE/REGION/s3/aws4_request (parsed from the right). */
  char *dup = buckets_xstrdup(cred);
  char *parts[5] = {0};
  for (int i = 4; i >= 1; i--) {
    char *slash = strrchr(dup, '/');
    if (!slash) {
      free(dup);
      return BUCKETS_ERR_CRED_MALFORMED;
    }
    parts[i] = slash + 1;
    *slash = '\0';
  }
  parts[0] = dup;
  buckets_s3_error err = BUCKETS_ERR_NONE;
  const char *region_conf = c->s->region;
  if (strcmp(parts[3], "s3") != 0) err = BUCKETS_ERR_INVALID_SERVICE_S3;
  else if (strcmp(parts[4], "aws4_request") != 0) err = BUCKETS_ERR_INVALID_REQUEST_VERSION;
  else if (*region_conf && strcmp(parts[2], region_conf) != 0) err = BUCKETS_ERR_AUTHORIZATION_HEADER_MALFORMED;
  else if (strlen(parts[1]) != 8) err = BUCKETS_ERR_MALFORMED_CREDENTIAL_DATE;
  const char *secret = NULL;
  if (!err) {
    if (strcmp(parts[0], c->s->root_user) == 0) secret = c->s->root_password;
    else err = BUCKETS_ERR_INVALID_ACCESS_KEY_ID;
  }
  if (!err) {
    uint8_t key[32], mac[32];
    char hex[65];
    buckets_sigv4_signing_key(secret, buckets_str_c(parts[1]), buckets_str_c(parts[2]), "s3", key);
    buckets_hmac_sha256(key, 32, policy, strlen(policy), mac);
    buckets_hex_encode(mac, 32, hex);
    if (!sig || strlen(sig) != 64 || !buckets_ct_equal(hex, sig, 64)) err = BUCKETS_ERR_SIGNATURE_DOES_NOT_MATCH;
    else snprintf(c->access_key, sizeof(c->access_key), "%s", parts[0]);
  }
  free(dup);
  return err;
}

/* ---- handler --------------------------------------------------------------- */

static void post_error(s3_ctx *c, buckets_s3_error e) { buckets_s3_write_error(c, e); }

typedef struct {
  buckets_checksum want;
} post_cks_ctx;

static buckets_obj_err post_cks_check(void *ud, const buckets_checksum *computed, buckets_xl_object *o) {
  post_cks_ctx *pc = ud;
  if (!pc->want.type) return BUCKETS_OBJ_OK;
  if (computed->raw_len != pc->want.raw_len || memcmp(computed->raw, pc->want.raw, computed->raw_len) != 0) {
    return BUCKETS_OBJ_ERR_BAD_CHECKSUM;
  }
  if (o) {
    buckets_buf stored = BUCKETS_BUF_INIT;
    buckets_checksum_append(&pc->want, NULL, 0, &stored);
    buckets_xl_kv_set(&o->meta_sys, &o->nmeta_sys, BUCKETS_CKSUM_META, stored.data, stored.len);
    buckets_buf_free(&stored);
  }
  return BUCKETS_OBJ_OK;
}

void buckets_s3_post_policy(s3_ctx *c) {
  const buckets_http_request *req = c->req;
  if (req->body_len <= 0) {
    post_error(c, BUCKETS_ERR_EMPTY_REQUEST_BODY);
    return;
  }
  buckets_str ct = buckets_http_header_get(req, "Content-Type");
  char *ctype = ct.p ? buckets_str_dup(ct) : buckets_xstrdup("");
  char *boundary = disp_param(ctype, "boundary");
  free(ctype);
  if (!boundary || !*boundary || strlen(boundary) > 70) {
    free(boundary);
    post_error(c, BUCKETS_ERR_MALFORMED_POST_REQUEST);
    return;
  }
  form_reader *f = buckets_xcalloc(1, sizeof(*f));
  f->cur = (buckets_http_body_cursor){req, 0};
  f->dlen = (size_t)snprintf(f->delim, sizeof(f->delim), "\r\n--%s", boundary);
  free(boundary);

  /* The body starts with "--boundary"; treat it as if preceded by CRLF. */
  fill(f);
  if (f->len < f->dlen - 2 || memcmp(f->buf, f->delim + 2, f->dlen - 2) != 0) {
    free(f);
    post_error(c, BUCKETS_ERR_MALFORMED_POST_REQUEST);
    return;
  }
  f->pos = f->dlen - 2;

  fields fs = {0};
  char *file_name = NULL;
  bool have_file = false;
  buckets_s3_error err = BUCKETS_ERR_NONE;
  for (int parts = 0; !err && next_part_start(f); parts++) {
    if (parts >= MAX_PARTS) {
      err = BUCKETS_ERR_MALFORMED_POST_REQUEST;
      break;
    }
    char line[4096], *name = NULL, *fname = NULL;
    while (read_line(f, line, sizeof(line)) && line[0]) {
      if (strncasecmp(line, "content-disposition:", 20) == 0) {
        name = disp_param(line + 20, "name");
        fname = disp_param(line + 20, "filename");
      }
    }
    if (!name || !*name) {
      free(name);
      free(fname);
      char skip[4096];
      while (part_read(f, skip, sizeof(skip)) > 0) {
      }
      continue;
    }
    if (strcmp(name, "file") == 0) {
      file_name = fname ? fname : buckets_xstrdup("");
      fname = NULL;
      have_file = true;
      free(name);
      break; /* the file streams straight into the object layer */
    }
    buckets_buf value = BUCKETS_BUF_INIT;
    char chunk[8192];
    long n;
    while ((n = part_read(f, chunk, sizeof(chunk))) > 0) {
      if (value.len + (size_t)n > MAX_FIELD) {
        n = -1;
        break;
      }
      buckets_buf_append(&value, chunk, (size_t)n);
    }
    if (n < 0) err = BUCKETS_ERR_MALFORMED_POST_REQUEST;
    else fields_add(&fs, name, value.data ? value.data : "");
    buckets_buf_free(&value);
    free(name);
    free(fname);
  }
  if (!err && !have_file) err = BUCKETS_ERR_MALFORMED_POST_REQUEST;
  const char *key = fields_get(&fs, "Key");
  if (!err && !key) err = BUCKETS_ERR_MALFORMED_POST_REQUEST;
  if (!err && file_name && !*file_name) {
    free(file_name);
    file_name = buckets_xstrdup(key);
  }
  post_policy policy = {0};
  bool have_policy = false;
  buckets_buf errmsg = BUCKETS_BUF_INIT;
  if (!err) {
    fields_set(&fs, "Bucket", c->bucket);
    key = fields_get(&fs, "Key");
    if (strstr(key, "${filename}")) {
      buckets_buf k = BUCKETS_BUF_INIT;
      for (const char *p = key; *p;) {
        if (strncmp(p, "${filename}", 11) == 0) {
          buckets_buf_append_c(&k, file_name);
          p += 11;
        } else {
          buckets_buf_append_char(&k, *p++);
        }
      }
      fields_set(&fs, "Key", k.data);
      buckets_buf_free(&k);
    }
    err = verify_signature(c, &fs);
  }
  if (!err) {
    const char *p64 = fields_get(&fs, "Policy");
    size_t pl = p64 ? strlen(p64) : 0;
    uint8_t *pj = buckets_xmalloc(pl + 4);
    long pn = pl ? buckets_base64_decode(p64, pl, pj) : 0;
    if (pn < 0) {
      err = BUCKETS_ERR_MALFORMED_POST_REQUEST;
    } else if (pn > 0) {
      if (!parse_policy((const char *)pj, (size_t)pn, &policy)) {
        err = BUCKETS_ERR_POST_POLICY_CONDITION_INVALID_FORMAT;
      } else {
        have_policy = true;
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        if (!check_policy(&fs, &policy, (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec, &errmsg)) {
          err = BUCKETS_ERR_ACCESS_DENIED;
        }
      }
    }
    free(pj);
  }

  if (!err) {
    /* Metadata from form fields (extractMetadataFromMime). */
    const char *object = fields_get(&fs, "Key");
    while (*object == '/') object++;
    buckets_xl_kv *meta = NULL;
    size_t nmeta = 0;
    static const char *const supported[] = {"content-type", "cache-control", "content-language", "content-encoding",
                                            "content-disposition", "x-amz-storage-class", "X-Amz-Tagging", "expires"};
    for (size_t s = 0; s < BUCKETS_ARRAY_LEN(supported); s++) {
      const char *v = fields_get(&fs, supported[s]);
      if (v) buckets_xl_kv_set(&meta, &nmeta, supported[s], v, strlen(v));
    }
    for (size_t i = 0; i < fs.n; i++) {
      if (strncasecmp(fs.items[i].name, "x-amz-meta-", 11) == 0 || strncasecmp(fs.items[i].name, "x-minio-meta-", 13) == 0) {
        buckets_xl_kv_set(&meta, &nmeta, fs.items[i].name, fs.items[i].value, strlen(fs.items[i].value));
      }
    }
    if (!buckets_xl_kv_get(meta, nmeta, "content-type")) buckets_xl_kv_set(&meta, &nmeta, "content-type", "binary/octet-stream", 19);

    /* The file part's size is unknown up front: stage it first. */
    char *tmpf = NULL;
    int fd = -1;
    int64_t size = 0;
    char chunk[64 * 1024];
    long n;
    snprintf(chunk, sizeof(chunk), "%s/" BUCKETS_META_BUCKET "/tmp/post-XXXXXX", c->s->drive->root);
    tmpf = buckets_xstrdup(chunk);
    fd = mkstemp(tmpf);
    if (fd >= 0) unlink(tmpf);
    while (fd >= 0 && (n = part_read(f, chunk, sizeof(chunk))) > 0) {
      if (write(fd, chunk, (size_t)n) != n) {
        n = -1;
        break;
      }
      size += n;
    }
    if (fd < 0 || n < 0) {
      err = BUCKETS_ERR_MALFORMED_POST_REQUEST;
    } else if (have_policy && policy.range_valid && size < policy.range_min) {
      err = BUCKETS_ERR_ENTITY_TOO_SMALL;
    } else if (have_policy && policy.range_valid && size > policy.range_max) {
      err = BUCKETS_ERR_ENTITY_TOO_LARGE;
    }
    /* x-amz-checksum-* can arrive as form fields (minio-go PostPolicy.SetChecksum). */
    buckets_checksum want = {0};
    if (!err) {
      buckets_http_request form_as_headers = {0};
      for (size_t i = 0; i < fs.n && form_as_headers.nheaders < BUCKETS_HTTP_MAX_HEADERS; i++) {
        form_as_headers.headers[form_as_headers.nheaders++] =
            (buckets_http_header){buckets_str_c(fs.items[i].name), buckets_str_c(fs.items[i].value)};
      }
      if (buckets_checksum_from_request(&form_as_headers, &want) != BUCKETS_ERR_NONE) err = BUCKETS_ERR_INVALID_CHECKSUM;
      else if (want.type & BUCKETS_CKSUM_TRAILING) want.type = 0;
    }
    buckets_object_info oi;
    if (!err) {
      buckets_http_request staged_req = {.body_fd = fd, .body_len = size};
      buckets_http_body_cursor sc = {&staged_req, 0};
      post_cks_ctx pc = {.want = want};
      buckets_put_opts opts = {.meta = meta, .nmeta = nmeta, .checksum_type = want.type & BUCKETS_CKSUM_BASE_MASK,
                               .pre_commit = post_cks_check, .pre_commit_ud = &pc};
      buckets_obj_err oe = buckets_obj_put(c->s->drive, c->bucket, object, (buckets_read_fn)buckets_http_body_read, &sc,
                                           size, &opts, &oi);
      if (oe) err = buckets_s3_obj_error(oe);
    }
    if (fd >= 0) close(fd);
    free(tmpf);
    for (size_t i = 0; i < nmeta; i++) {
      free(meta[i].key);
      free(meta[i].value);
    }
    free(meta);

    if (!err) {
      buckets_http_resp_headerf(c->resp, "ETag", "\"%s\"", oi.etag);
      if (want.type) {
        char enc[64];
        buckets_checksum_encode(&want, enc);
        buckets_http_resp_header(c->resp, buckets_cksum_header(want.type), enc);
        buckets_http_resp_header(c->resp, "X-Amz-Checksum-Type", "FULL_OBJECT");
      }
      buckets_str host = buckets_http_header_get(req, "Host");
      buckets_buf loc = BUCKETS_BUF_INIT;
      buckets_buf_appendf(&loc, "http://" BUCKETS_STR_FMT "/%s/%s", BUCKETS_STR_ARG(host), c->bucket, oi.name);
      buckets_http_resp_header(c->resp, "Location", loc.data);
      const char *redirect = fields_get(&fs, "success_action_redirect");
      const char *status = fields_get(&fs, "success_action_status");
      if (redirect && *redirect) {
        buckets_buf url = BUCKETS_BUF_INIT;
        buckets_buf_append_c(&url, redirect);
        buckets_buf_append_char(&url, strchr(redirect, '?') ? '&' : '?');
        buckets_buf_appendf(&url, "bucket=%s&etag=%%22%s%%22&key=", c->bucket, oi.etag);
        for (const unsigned char *p = (const unsigned char *)oi.name; *p; p++) {
          if (isalnum(*p) || strchr("-_.~", *p)) buckets_buf_append_char(&url, (char)*p);
          else buckets_buf_appendf(&url, "%%%02X", *p);
        }
        buckets_http_resp_header(c->resp, "Location", url.data);
        c->resp->status = 303;
        buckets_buf_free(&url);
      } else if (status && strcmp(status, "201") == 0) {
        buckets_buf *b = &c->resp->body;
        buckets_xml_header(b);
        buckets_xml_open(b, "PostResponse");
        buckets_xml_elem(b, "Bucket", c->bucket);
        buckets_xml_elem(b, "Key", oi.name);
        buckets_buf_appendf(b, "<ETag>&quot;%s&quot;</ETag>", oi.etag);
        buckets_xml_elem(b, "Location", loc.data);
        buckets_xml_close(b, "PostResponse");
        buckets_s3_write_xml(c, 201);
      } else if (status && strcmp(status, "200") == 0) {
        c->resp->status = 200;
      } else {
        c->resp->status = 204;
      }
      buckets_buf_free(&loc);
      buckets_object_info_free(&oi);
    }
  }
  if (err) buckets_s3_write_error_msg(c, err, errmsg.len ? errmsg.data : NULL);
  buckets_buf_free(&errmsg);
  if (have_policy) policy_free(&policy);
  fields_free(&fs);
  free(file_name);
  free(f);
}
