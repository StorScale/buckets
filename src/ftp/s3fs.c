/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "ftp/s3fs.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <yyjson.h>

#include "core/common.h"
#include "core/mime.h"
#include "core/str.h"
#include "core/timefmt.h"
#include "crypto/base64.h"
#include "crypto/crc.h"
#include "crypto/hex.h"
#include "crypto/md5.h"
#include "iam/iam.h"
#include "iam/ldapidp.h"
#include "net/s3client.h"
#include "net/tls.h"
#include "s3/server.h"
#include "s3/xml.h"
#include "siterepl/siterepl.h"

static buckets_s3_server *g_s;
static char g_endpoint[64];
static bool g_secure;
static buckets_tls_client *g_tls;

void buckets_fs_init(buckets_s3_server *s, int port, bool secure) {
  g_s = s;
  snprintf(g_endpoint, sizeof(g_endpoint), "127.0.0.1:%d", port);
  g_secure = secure;
  if (secure && !g_tls) {
    char err[256];
    g_tls = buckets_tls_client_new(NULL, err, sizeof(err));
    if (g_tls) buckets_tls_client_skip_verify(g_tls); /* our own certificate, by IP */
  }
}

void buckets_fs_info_free(buckets_fs_info *fi, size_t n) {
  for (size_t i = 0; fi && i < n; i++) free(fi[i].name);
  free(fi);
}

static void seterr(char *err, size_t cap, const char *msg) { snprintf(err, cap, "%s", msg); }


/* ---- minio-go's argument checks (s3utils) ---- */

static bool valid_utf8(const char *s) {
  const unsigned char *p = (const unsigned char *)s;
  while (*p) {
    int n = *p < 0x80 ? 0 : (*p >> 5) == 6 ? 1 : (*p >> 4) == 14 ? 2 : (*p >> 3) == 30 ? 3 : -1;
    if (n < 0) return false;
    uint32_t cp = n == 0 ? *p : n == 1 ? (*p & 0x1f) : n == 2 ? (*p & 0x0f) : (*p & 0x07);
    p++;
    for (int i = 0; i < n; i++, p++) {
      if ((*p & 0xc0) != 0x80) return false;
      cp = cp << 6 | (*p & 0x3f);
    }
    if ((n == 1 && cp < 0x80) || (n == 2 && cp < 0x800) || (n == 3 && (cp < 0x10000 || cp > 0x10ffff)) ||
        (cp >= 0xd800 && cp <= 0xdfff))
      return false;
  }
  return true;
}

static bool all_space(const char *s) {
  for (; *s; s++)
    if (!strchr(" \t\n\v\f\r", *s)) return false;
  return true;
}

/* checkBucketNameCommon */
static bool check_bucket(const char *b, bool strict, char *err, size_t errlen) {
  size_t n = strlen(b);
  const char *msg = NULL;
  if (all_space(b)) msg = "Bucket name cannot be empty";
  else if (n < 3) msg = "Bucket name cannot be shorter than 3 characters";
  else if (n > 63) msg = "Bucket name cannot be longer than 63 characters";
  else {
    int dots = 0;
    bool ip = true;
    for (const char *p = b; *p && ip; p++) {
      if (*p == '.') dots++;
      else if (*p < '0' || *p > '9') ip = false;
    }
    /* ^(\d+\.){3}\d+$ */
    if (ip && dots == 3 && b[0] != '.' && b[n - 1] != '.' && !strstr(b, "..")) msg = "Bucket name cannot be an ip address";
    else if (strstr(b, "..") || strstr(b, ".-") || strstr(b, "-.")) msg = "Bucket name contains invalid characters";
    else {
      bool ok = true;
      for (size_t i = 0; i < n && ok; i++) {
        char c = b[i];
        bool alnum = strict ? ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'))
                            : ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'));
        bool mid = alnum || c == '.' || c == '-' || (!strict && (c == '_' || c == ':'));
        ok = (i == 0 || i == n - 1) ? alnum : mid;
      }
      if (!ok) msg = "Bucket name contains invalid characters";
    }
  }
  if (msg) seterr(err, errlen, msg);
  return !msg;
}

static bool check_prefix(const char *o, char *err, size_t errlen) {
  if (strlen(o) > 1024) return seterr(err, errlen, "Object name cannot be longer than 1024 characters"), false;
  if (!valid_utf8(o)) return seterr(err, errlen, "Object name with non UTF-8 strings are not supported"), false;
  return true;
}

static bool check_object(const char *o, char *err, size_t errlen) {
  if (all_space(o)) return seterr(err, errlen, "Object name cannot be empty"), false;
  return check_prefix(o, err, errlen);
}

/* ---- paths ---- */

char *buckets_fs_clean(const char *p) {
  /* path.Clean, then pathClean's "." -> "" */
  bool rooted = p[0] == '/';
  size_t n = strlen(p);
  char *out = buckets_xcalloc(n + 2, 1);
  size_t w = 0;
  if (rooted) out[w++] = '/';
  size_t dotdot = w;
  for (size_t r = 0; r < n;) {
    if (p[r] == '/') {
      r++;
    } else if (p[r] == '.' && (r + 1 == n || p[r + 1] == '/')) {
      r++;
    } else if (p[r] == '.' && p[r + 1] == '.' && (r + 2 == n || p[r + 2] == '/')) {
      r += 2;
      if (w > dotdot) {
        w--;
        while (w > dotdot && out[w] != '/') w--;
      } else if (!rooted) {
        if (w > 0) out[w++] = '/';
        out[w++] = '.', out[w++] = '.';
        dotdot = w;
      }
    } else {
      if ((rooted && w != 1) || (!rooted && w != 0)) out[w++] = '/';
      for (; r < n && p[r] != '/'; r++) out[w++] = p[r];
    }
  }
  out[w] = '\0';
  if (w == 0) out[0] = '\0'; /* "." -> "" */
  return out;
}

void buckets_fs_split(const char *path, char **bucket, char **object) {
  if (*path == '/') path++;
  const char *s = strchr(path, '/');
  if (!s) {
    *bucket = buckets_xstrdup(path);
    *object = buckets_xstrdup("");
    return;
  }
  *bucket = buckets_xstrndup(path, (size_t)(s - path));
  *object = buckets_xstrdup(s + 1);
}

/* ---- authentication ---- */

static bool ldap_on(void) { return buckets_iam_ldap_mode(g_s->iam); }

bool buckets_fs_check_password(const char *user, const char *password, char *err, size_t errlen) {
  *err = '\0';
  if (ldap_on()) {
    buckets_iam_ident *sa = buckets_iam_get_ident(g_s->iam, user);
    if (sa && buckets_iam_ident_is_svc(sa)) {
      bool ok = buckets_ct_equal(sa->secret_key, password, strlen(sa->secret_key)) &&
                strlen(sa->secret_key) == strlen(password);
      buckets_iam_ident_release(sa);
      return ok;
    }
    buckets_iam_ident_release(sa);
    buckets_ldapidp *ldap = buckets_s3_ldap(g_s);
    buckets_ldap_dnres dn = {0};
    char **groups = NULL;
    size_t ng = 0;
    bool ok = buckets_ldapidp_bind(ldap, user, password, &dn, &groups, &ng, err, errlen);
    buckets_ldapidp_release(ldap);
    if (!ok) {
      buckets_ldap_dnres_free(&dn);
      return false;
    }
    char *pol = buckets_iam_policy_db_get(g_s->iam, dn.norm_dn, groups, ng);
    bool any = pol && *pol;
    free(pol);
    buckets_ldap_strv_free(groups, ng);
    buckets_ldap_dnres_free(&dn);
    return any;
  }
  buckets_iam_ident *id = NULL;
  if (buckets_iam_get_key(g_s->iam, user, &id) != BUCKETS_IAM_KEY_OK || !id) return false;
  bool ok = strlen(id->secret_key) == strlen(password) && buckets_ct_equal(id->secret_key, password, strlen(password));
  buckets_iam_ident_release(id);
  return ok;
}

/* ---- sessions ---- */

struct buckets_fs {
  buckets_s3c *c;
  char fwd[64];
  char *ak, *sk, *token;
};

/* getMinIOClient for an LDAP user: STS credentials for the session */
static buckets_iam_ident *ldap_sts(const char *user, char *err, size_t errlen) {
  buckets_ldapidp *ldap = buckets_s3_ldap(g_s);
  buckets_ldap_dnres dn = {0};
  char **groups = NULL;
  size_t ng = 0;
  buckets_iam_ident *cred = NULL;
  int r = buckets_ldapidp_lookup_user(ldap, user, &dn, &groups, &ng, err, errlen);
  if (r != 1) {
    if (r == 0 && !*err) seterr(err, errlen, "Authentication failed, check your access credentials");
    goto out;
  }
  char *pol = buckets_iam_policy_db_get(g_s->iam, dn.norm_dn, groups, ng);
  bool any = pol && *pol;
  free(pol);
  if (!any) {
    seterr(err, errlen, "Authentication failed, check your access credentials");
    goto out;
  }
  long long dur = buckets_ldapidp_expiry(ldap, "");
  if (dur < 0) {
    seterr(err, errlen, "invalid token expiry");
    goto out;
  }
  yyjson_mut_doc *claims = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(claims);
  yyjson_mut_doc_set_root(claims, root);
  yyjson_mut_obj_add_int(claims, root, "exp", (long long)time(NULL) + dur);
  yyjson_mut_obj_add_strcpy(claims, root, "ldapUser", dn.norm_dn);
  yyjson_mut_obj_add_strcpy(claims, root, "ldapActualUser", dn.actual_dn);
  yyjson_mut_obj_add_strcpy(claims, root, "ldapUsername", user);
  for (size_t a = 0; a < dn.nattrs; a++) {
    char key[256];
    snprintf(key, sizeof(key), "ldapAttrib_%s", dn.attrs[a].name);
    yyjson_mut_val *arr = yyjson_mut_arr(claims);
    for (size_t v = 0; v < dn.attrs[a].nvalues; v++) yyjson_mut_arr_add_strcpy(claims, arr, dn.attrs[a].values[v]);
    yyjson_mut_obj_add(root, yyjson_mut_strcpy(claims, key), arr);
  }
  char *cj = yyjson_mut_write(claims, 0, NULL);
  yyjson_mut_doc_free(claims);
  char ak[21], sk[41];
  buckets_iam_generate_credentials(ak, sk);
  buckets_iam_err e = buckets_iam_set_temp_user(g_s->iam, ak, sk, dn.norm_dn, (const char *const *)groups, ng,
                                                (buckets_iam_time){(long long)time(NULL) + dur, 0}, cj, NULL, &cred);
  free(cj);
  if (e) {
    seterr(err, errlen, buckets_iam_strerror(e));
    cred = NULL;
  } else {
    buckets_sr_iam_sts(g_s->sr, cred->access_key, NULL);
  }
out:
  buckets_ldap_strv_free(groups, ng);
  buckets_ldap_dnres_free(&dn);
  buckets_ldapidp_release(ldap);
  return cred;
}

static buckets_fs *fs_new(const char *ak, const char *sk, const char *token, const char *remote_ip);

buckets_fs *buckets_fs_open(const char *user, const char *remote_ip, char *err, size_t errlen) {
  buckets_iam_ident *id = NULL;
  bool found = buckets_iam_get_key(g_s->iam, user, &id) == BUCKETS_IAM_KEY_OK && id;
  if (!found && !ldap_on()) {
    seterr(err, errlen, "Specified user does not exist");
    return NULL;
  }
  if (!found) {
    buckets_iam_ident_release(id);
    id = buckets_iam_get_ident(g_s->iam, user);
    if (!(id && buckets_iam_ident_is_svc(id))) {
      buckets_iam_ident_release(id);
      if (!(id = ldap_sts(user, err, errlen))) return NULL;
    }
  } else if (buckets_iam_ident_is_temp(id)) {
    buckets_iam_ident_release(id);
    seterr(err, errlen, "Authentication failed, check your access credentials");
    return NULL;
  }
  buckets_fs *fs = fs_new(id->access_key, id->secret_key, id->session_token, remote_ip);
  buckets_iam_ident_release(id);
  return fs;
}

static buckets_fs *fs_new(const char *ak, const char *sk, const char *token, const char *remote_ip) {
  buckets_fs *fs = buckets_xcalloc(1, sizeof(*fs));
  fs->ak = buckets_xstrdup(ak);
  fs->sk = buckets_xstrdup(sk);
  fs->token = token && *token ? buckets_xstrdup(token) : NULL;
  snprintf(fs->fwd, sizeof(fs->fwd), "%s", remote_ip ? remote_ip : "");
  buckets_s3c_config cfg = {.endpoint = g_endpoint,
                            .secure = g_secure,
                            .access_key = fs->ak,
                            .secret_key = fs->sk,
                            .session_token = fs->token,
                            .region = g_s->region,
                            .tls = g_tls};
  fs->c = buckets_s3c_new(&cfg);
  return fs;
}

buckets_fs *buckets_fs_open_creds(const char *ak, const char *sk, const char *token, const char *remote_ip) {
  return fs_new(ak, sk, token, remote_ip);
}

const char *buckets_fs_access_key(const buckets_fs *fs) { return fs->ak; }

static void out_creds(const buckets_iam_ident *id, bool with_token, char **ak, char **sk, char **token) {
  *ak = buckets_xstrdup(id->access_key);
  *sk = buckets_xstrdup(id->secret_key);
  *token = with_token && id->session_token && *id->session_token ? buckets_xstrdup(id->session_token) : NULL;
}

/* processLDAPAuthentication */
static int ldap_login(const char *user, const buckets_fs_ssh_auth *a, char **ak, char **sk, char **token, char *err,
                      size_t errlen) {
  if (!a->password && !a->key_matches) return seterr(err, errlen, "Authentication failed, check your access credentials"), -1;
  buckets_ldapidp *ldap = buckets_s3_ldap(g_s);
  buckets_ldap_dnres dn = {0};
  char **groups = NULL;
  size_t ng = 0;
  int rc = -1;
  bool found;
  if (a->password) {
    buckets_iam_ident *sa = buckets_iam_get_ident(g_s->iam, user);
    if (sa && buckets_iam_ident_is_svc(sa)) {
      bool ok = strlen(sa->secret_key) == strlen(a->password) &&
                buckets_ct_equal(sa->secret_key, a->password, strlen(a->password));
      if (ok) out_creds(sa, false, ak, sk, token), rc = 0;
      else seterr(err, errlen, "Authentication failed, check your access credentials");
      buckets_iam_ident_release(sa);
      buckets_ldapidp_release(ldap);
      return rc;
    }
    buckets_iam_ident_release(sa);
    found = buckets_ldapidp_bind(ldap, user, a->password, &dn, &groups, &ng, err, errlen);
  } else {
    found = buckets_ldapidp_lookup_user(ldap, user, &dn, &groups, &ng, err, errlen) == 1;
  }
  if (!found) goto out;
  {
    char *pol = buckets_iam_policy_db_get(g_s->iam, dn.norm_dn, groups, ng);
    bool any = pol && *pol;
    free(pol);
    if (!any) {
      seterr(err, errlen, "no policies present on this account");
      goto out;
    }
  }
  yyjson_mut_doc *claims = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(claims);
  yyjson_mut_doc_set_root(claims, root);
  bool have_key = false;
  for (size_t i = 0; i < dn.nattrs; i++) {
    if (dn.attrs[i].nvalues != 1) continue;
    const char *v = dn.attrs[i].values[0];
    if (!strcmp(dn.attrs[i].name, "sshPublicKey") && !a->password) {
      if (!a->key_matches(a->ud, v)) {
        seterr(err, errlen, "Authentication failed, check your access credentials");
        yyjson_mut_doc_free(claims);
        goto out;
      }
      have_key = true;
    }
    char k[256];
    snprintf(k, sizeof(k), "ldapAttrib_%s", dn.attrs[i].name);
    yyjson_mut_obj_add(root, yyjson_mut_strcpy(claims, k), yyjson_mut_strcpy(claims, v));
  }
  if (!a->password && !have_key) {
    seterr(err, errlen, "Authentication failed, check your access credentials");
    yyjson_mut_doc_free(claims);
    goto out;
  }
  long long dur = buckets_ldapidp_expiry(ldap, "");
  if (dur < 0) {
    seterr(err, errlen, "invalid token expiry");
    yyjson_mut_doc_free(claims);
    goto out;
  }
  yyjson_mut_obj_add_int(claims, root, "exp", (long long)time(NULL) + dur);
  yyjson_mut_obj_add_strcpy(claims, root, "ldapUsername", user);
  yyjson_mut_obj_add_strcpy(claims, root, "ldapUser", dn.norm_dn);
  {
    char *cj = yyjson_mut_write(claims, 0, NULL);
    yyjson_mut_doc_free(claims);
    char nak[21], nsk[41];
    buckets_iam_generate_credentials(nak, nsk);
    buckets_iam_ident *cred = NULL;
    buckets_iam_err e = buckets_iam_set_temp_user(g_s->iam, nak, nsk, dn.norm_dn, (const char *const *)groups, ng,
                                                  (buckets_iam_time){(long long)time(NULL) + dur, 0}, cj, NULL, &cred);
    free(cj);
    if (e) {
      seterr(err, errlen, buckets_iam_strerror(e));
      goto out;
    }
    buckets_sr_iam_sts(g_s->sr, cred->access_key, NULL);
    out_creds(cred, true, ak, sk, token);
    buckets_iam_ident_release(cred);
    rc = 0;
  }
out:
  buckets_ldap_strv_free(groups, ng);
  buckets_ldap_dnres_free(&dn);
  buckets_ldapidp_release(ldap);
  return rc;
}

bool buckets_fs_ssh_login(const char *user, const buckets_fs_ssh_auth *a, char **ak, char **sk, char **token,
                          char *err, size_t errlen) {
  *ak = *sk = *token = NULL;
  *err = '\0';
  size_t n = strlen(user);
  char *u = buckets_xstrdup(user);
  bool svc = false;
  if (n > 5 && !strcmp(user + n - 5, "=ldap")) {
    u[n - 5] = '\0';
    bool ok = false;
    if (!ldap_on()) seterr(err, errlen, "ldap authentication is not enabled");
    else ok = ldap_login(u, a, ak, sk, token, err, errlen) == 0;
    free(u);
    return ok;
  }
  if (n > 4 && !strcmp(user + n - 4, "=svc")) {
    u[n - 4] = '\0';
    svc = true;
  }
  if (!svc && ldap_on()) {
    char e2[512];
    if (ldap_login(u, a, ak, sk, token, e2, sizeof(e2)) == 0) {
      free(u);
      return true;
    }
  }
  /* internalAuth */
  buckets_iam_ident *id = NULL;
  bool ok = false;
  if (buckets_iam_get_key(g_s->iam, u, &id) != BUCKETS_IAM_KEY_OK || !id) {
    seterr(err, errlen, "Specified user does not exist");
  } else if (a->cert_trusted && !a->password) {
    if (!a->cert_trusted(a->ud, u)) seterr(err, errlen, "Authentication failed, check your access credentials");
    else ok = true;
  } else if (buckets_iam_ident_is_temp(id) || !a->password || strlen(id->secret_key) != strlen(a->password) ||
             !buckets_ct_equal(id->secret_key, a->password, strlen(a->password))) {
    seterr(err, errlen, "Authentication failed, check your access credentials");
  } else {
    ok = true;
  }
  if (ok) out_creds(id, buckets_iam_ident_is_temp(id), ak, sk, token);
  buckets_iam_ident_release(id);
  free(u);
  return ok;
}

void buckets_fs_close(buckets_fs *fs) {
  if (!fs) return;
  buckets_s3c_free(fs->c);
  free(fs->ak);
  free(fs->sk);
  free(fs->token);
  free(fs);
}

/* forwardForTransport */
static size_t fwd_hdr(buckets_fs *fs, buckets_http_kv *h) {
  if (!fs->fwd[0]) return 0;
  h[0] = (buckets_http_kv){"X-Forwarded-For", fs->fwd};
  return 1;
}

static bool call(buckets_fs *fs, const char *method, const char *bucket, const char *object, const char *query,
                 const buckets_http_kv *extra, size_t nextra, const void *body, size_t blen, buckets_s3c_result *res) {
  buckets_http_kv h[8];
  size_t n = fwd_hdr(fs, h);
  for (size_t i = 0; i < nextra && n < 8; i++) h[n++] = extra[i];
  return buckets_s3c_do(fs->c, method, bucket, object, query, h, n, body, blen, res);
}

static int64_t http_time_ns(const buckets_s3c_result *r) {
  char lm[64];
  buckets_s3c_header_copy(r, "Last-Modified", lm, sizeof(lm));
  time_t t;
  return *lm && buckets_time_parse_http(buckets_str_c(lm), &t) ? (int64_t)t * 1000000000LL : 0;
}

static int64_t iso_ns(const char *s) {
  long long sec;
  long nsec;
  return s && buckets_time_parse_rfc3339(s, &sec, &nsec) ? (int64_t)sec * 1000000000LL + nsec : 0;
}

/* ---- the operations ---- */

bool buckets_fs_stat(buckets_fs *fs, const char *path, buckets_fs_info *out, char *err, size_t errlen) {
  memset(out, 0, sizeof(*out));
  if (strcmp(path, "/") == 0) {
    out->name = buckets_xstrdup("/");
    out->dir = true;
    return true;
  }
  char *bucket, *object;
  buckets_fs_split(path, &bucket, &object);
  bool ok = false;
  buckets_s3c_result r = {0};
  if (!*bucket) {
    seterr(err, errlen, "bucket name cannot be empty");
  } else if (!*object) {
    if (!check_bucket(bucket, false, err, errlen)) {
      /* BucketExists' argument check */
    } else if (call(fs, "HEAD", bucket, NULL, NULL, NULL, 0, NULL, 0, &r)) {
      out->name = buckets_fs_clean(bucket);
      out->dir = ok = true;
    } else {
      seterr(err, errlen, r.status && !strcmp(r.code, "NoSuchBucket") ? "file does not exist" : buckets_s3c_error(&r));
    }
  } else if (!check_bucket(bucket, false, err, errlen) || !check_object(object, err, errlen)) {
    /* StatObject's argument checks */
  } else if (call(fs, "HEAD", bucket, object, NULL, NULL, 0, NULL, 0, &r)) {
    char cl[32];
    buckets_s3c_header_copy(&r, "Content-Length", cl, sizeof(cl));
    out->name = buckets_fs_clean(object);
    out->size = strtoll(cl, NULL, 10);
    out->mtime_ns = http_time_ns(&r);
    out->dir = object[strlen(object) - 1] == '/';
    ok = true;
  } else if (r.status && !strcmp(r.code, "NoSuchKey")) {
    out->name = buckets_fs_clean(object); /* a prefix: a directory */
    out->dir = ok = true;
  } else {
    seterr(err, errlen, buckets_s3c_error(&r));
  }
  buckets_s3c_result_free(&r);
  free(bucket);
  free(object);
  return ok;
}

static char *xml_text(const buckets_xml_doc *d, size_t node, const char *name) {
  size_t c = buckets_xml_child(d, node, name);
  if (!c) return NULL;
  buckets_buf t = BUCKETS_BUF_INIT;
  buckets_xml_unescape(d->nodes[c].text, &t);
  char *s = buckets_xstrndup(t.data ? t.data : "", t.len);
  buckets_buf_free(&t);
  return s;
}

static char *url_dec(const char *s) {
  size_t n = strlen(s);
  char *o = buckets_xcalloc(n + 1, 1);
  long k = buckets_url_decode((buckets_str){s, n}, o, false);
  if (k < 0) {
    free(o);
    return buckets_xstrdup(s);
  }
  o[k] = '\0';
  return o;
}

static void push(buckets_fs_info **v, size_t *n, size_t *cap, char *name, int64_t size, int64_t mtime, bool dir) {
  if (*n == *cap) *v = buckets_xrealloc(*v, (*cap = *cap ? *cap * 2 : 64) * sizeof(**v));
  (*v)[(*n)++] = (buckets_fs_info){name, size, mtime, dir};
}

bool buckets_fs_list(buckets_fs *fs, const char *path, buckets_fs_info **out, size_t *n, char *err, size_t errlen) {
  *out = NULL;
  *n = 0;
  size_t cap = 0;
  char *bucket, *prefix;
  buckets_fs_split(path, &bucket, &prefix);
  bool ok = true;
  if (!*bucket) {
    buckets_s3c_result r = {0};
    if (!call(fs, "GET", NULL, NULL, NULL, NULL, 0, NULL, 0, &r)) {
      seterr(err, errlen, buckets_s3c_error(&r));
      ok = false;
    } else {
      buckets_xml_doc d = {0};
      if (buckets_xml_parse((buckets_str){r.body.data, r.body.len}, &d) && d.count) {
        size_t bs = buckets_xml_child(&d, 0, "Buckets");
        for (size_t b = bs ? d.nodes[bs].first_child : 0; b; b = d.nodes[b].next_sibling) {
          char *name = xml_text(&d, b, "Name"), *cd = xml_text(&d, b, "CreationDate");
          push(out, n, &cap, buckets_fs_clean(name ? name : ""), 0, iso_ns(cd), true);
          free(name);
          free(cd);
        }
      }
      buckets_xml_doc_free(&d);
    }
    buckets_s3c_result_free(&r);
    free(bucket);
    free(prefix);
    return ok;
  }
  if (!check_bucket(bucket, false, err, errlen) || !check_prefix(prefix, err, errlen)) {
    free(bucket);
    free(prefix);
    return false;
  }
  /* retainSlash */
  if (*prefix && prefix[strlen(prefix) - 1] != '/') {
    size_t pl = strlen(prefix) + 2;
    char *p = buckets_xcalloc(pl, 1);
    snprintf(p, pl, "%s/", prefix);
    free(prefix);
    prefix = p;
  }
  char *token = NULL;
  for (;;) {
    buckets_buf q = BUCKETS_BUF_INIT;
    buckets_buf_append_c(&q, "list-type=2&delimiter=%2F&encoding-type=url&fetch-owner=true");
    if (token) buckets_buf_append_c(&q, "&continuation-token="), buckets_url_encode(&q, token, false);
    buckets_buf_append_c(&q, "&prefix="), buckets_url_encode(&q, prefix, false);
    buckets_s3c_result r = {0};
    bool got = call(fs, "GET", bucket, NULL, q.data, NULL, 0, NULL, 0, &r);
    buckets_buf_free(&q);
    free(token);
    token = NULL;
    if (!got) {
      seterr(err, errlen, buckets_s3c_error(&r));
      buckets_s3c_result_free(&r);
      ok = false;
      break;
    }
    buckets_xml_doc d = {0};
    bool more = false;
    if (buckets_xml_parse((buckets_str){r.body.data, r.body.len}, &d) && d.count) {
      size_t plen = strlen(prefix);
      for (size_t c = d.nodes[0].first_child; c; c = d.nodes[c].next_sibling) {
        if (!buckets_str_eq_c(d.nodes[c].name, "Contents")) continue;
        char *k = xml_text(&d, c, "Key"), *sz = xml_text(&d, c, "Size"), *lm = xml_text(&d, c, "LastModified");
        char *key = url_dec(k ? k : "");
        if (strcmp(key, prefix) != 0) {
          push(out, n, &cap, buckets_fs_clean(strncmp(key, prefix, plen) == 0 ? key + plen : key),
               sz ? strtoll(sz, NULL, 10) : 0, iso_ns(lm), key[0] && key[strlen(key) - 1] == '/');
        }
        free(k), free(sz), free(lm), free(key);
      }
      for (size_t c = d.nodes[0].first_child; c; c = d.nodes[c].next_sibling) {
        if (!buckets_str_eq_c(d.nodes[c].name, "CommonPrefixes")) continue;
        char *pp = xml_text(&d, c, "Prefix");
        char *key = url_dec(pp ? pp : "");
        if (strcmp(key, prefix) != 0)
          push(out, n, &cap, buckets_fs_clean(strncmp(key, prefix, plen) == 0 ? key + plen : key), 0, 0, true);
        free(pp), free(key);
      }
      char *trunc = xml_text(&d, 0, "IsTruncated");
      more = trunc && strcmp(trunc, "true") == 0;
      free(trunc);
      if (more) token = xml_text(&d, 0, "NextContinuationToken");
    }
    buckets_xml_doc_free(&d);
    buckets_s3c_result_free(&r);
    if (!more || !token) break;
  }
  free(token);
  free(bucket);
  free(prefix);
  if (!ok) {
    buckets_fs_info_free(*out, *n);
    *out = NULL;
    *n = 0;
  }
  return ok;
}

bool buckets_fs_mkdir(buckets_fs *fs, const char *path, char *err, size_t errlen) {
  char *bucket, *prefix;
  buckets_fs_split(path, &bucket, &prefix);
  bool ok = false;
  buckets_s3c_result r = {0};
  if (!*bucket) {
    seterr(err, errlen, "bucket name cannot be empty");
  } else if (!*prefix) {
    ok = check_bucket(bucket, true, err, errlen) && call(fs, "PUT", bucket, NULL, NULL, NULL, 0, NULL, 0, &r);
    if (!ok && r.status) seterr(err, errlen, buckets_s3c_error(&r));
  } else if (!check_bucket(bucket, false, err, errlen) || !check_object(prefix, err, errlen)) {
    /* PutObject's argument checks */
  } else {
    buckets_buf dir = BUCKETS_BUF_INIT;
    buckets_buf_append_c(&dir, prefix);
    if (dir.data[dir.len - 1] != '/') buckets_buf_append_char(&dir, '/');
    /* minio-go's default type; an empty body carries no checksum */
    buckets_http_kv h[] = {{"Content-Type", "application/octet-stream"}};
    ok = call(fs, "PUT", bucket, dir.data, NULL, h, 1, NULL, 0, &r);
    if (!ok) seterr(err, errlen, buckets_s3c_error(&r));
    buckets_buf_free(&dir);
  }
  buckets_s3c_result_free(&r);
  free(bucket);
  free(prefix);
  return ok;
}

/* RemoveObjects: DeleteObjects in batches of 1000, the first failure */
static bool remove_objects(buckets_fs *fs, const char *bucket, char **keys, size_t n, char *err, size_t errlen) {
  for (size_t at = 0; at < n; at += 1000) {
    buckets_buf x = BUCKETS_BUF_INIT;
    buckets_buf_append_c(&x, "<Delete><Quiet>true</Quiet>");
    for (size_t i = at; i < n && i < at + 1000; i++) {
      buckets_buf_append_c(&x, "<Object><Key>");
      buckets_xml_text(&x, keys[i], strlen(keys[i]));
      buckets_buf_append_c(&x, "</Key></Object>");
    }
    buckets_buf_append_c(&x, "</Delete>");
    uint8_t md[16];
    buckets_md5(x.data, x.len, md);
    char b64[32];
    buckets_base64_encode(md, 16, b64);
    buckets_http_kv h[] = {{"Content-MD5", b64}, {"Content-Type", "application/xml"}};
    buckets_s3c_result r = {0};
    bool ok = call(fs, "POST", bucket, NULL, "delete=", h, 2, x.data, x.len, &r);
    buckets_buf_free(&x);
    if (!ok) {
      seterr(err, errlen, buckets_s3c_error(&r));
      buckets_s3c_result_free(&r);
      return false;
    }
    buckets_xml_doc d = {0};
    bool failed = false;
    if (buckets_xml_parse((buckets_str){r.body.data, r.body.len}, &d) && d.count) {
      size_t e = buckets_xml_child(&d, 0, "Error");
      if (e) {
        char *m = xml_text(&d, e, "Message");
        seterr(err, errlen, m ? m : "");
        free(m);
        failed = true;
      }
    }
    buckets_xml_doc_free(&d);
    buckets_s3c_result_free(&r);
    if (failed) return false;
  }
  return true;
}

bool buckets_fs_rmdir(buckets_fs *fs, const char *path, char *err, size_t errlen) {
  char *bucket, *prefix;
  buckets_fs_split(path, &bucket, &prefix);
  bool ok = false;
  if (!*bucket) {
    seterr(err, errlen, "deleting all buckets not allowed");
  } else if (!check_bucket(bucket, false, err, errlen)) {
    /* RemoveBucket's (or RemoveObjects') argument check */
  } else if (!*prefix) {
    buckets_s3c_result r = {0};
    ok = call(fs, "DELETE", bucket, NULL, NULL, NULL, 0, NULL, 0, &r);
    if (!ok) seterr(err, errlen, buckets_s3c_error(&r));
    buckets_s3c_result_free(&r);
  } else {
    /* every key under the prefix (recursive listing), then removed */
    char **keys = NULL;
    size_t nk = 0, cap = 0;
    char *token = NULL;
    for (;;) {
      buckets_buf q = BUCKETS_BUF_INIT;
      buckets_buf_append_c(&q, "list-type=2&encoding-type=url&fetch-owner=true");
      if (token) buckets_buf_append_c(&q, "&continuation-token="), buckets_url_encode(&q, token, false);
      buckets_buf_append_c(&q, "&prefix="), buckets_url_encode(&q, prefix, false);
      buckets_s3c_result r = {0};
      bool got = call(fs, "GET", bucket, NULL, q.data, NULL, 0, NULL, 0, &r);
      buckets_buf_free(&q);
      free(token);
      token = NULL;
      if (!got) {
        buckets_s3c_result_free(&r);
        break; /* the listing's error ends it quietly, as MinIO's goroutine does */
      }
      buckets_xml_doc d = {0};
      bool more = false;
      if (buckets_xml_parse((buckets_str){r.body.data, r.body.len}, &d) && d.count) {
        for (size_t c = d.nodes[0].first_child; c; c = d.nodes[c].next_sibling) {
          if (!buckets_str_eq_c(d.nodes[c].name, "Contents")) continue;
          char *k = xml_text(&d, c, "Key");
          if (nk == cap) keys = buckets_xrealloc(keys, (cap = cap ? cap * 2 : 256) * sizeof(*keys));
          keys[nk++] = url_dec(k ? k : "");
          free(k);
        }
        char *trunc = xml_text(&d, 0, "IsTruncated");
        more = trunc && !strcmp(trunc, "true");
        free(trunc);
        if (more) token = xml_text(&d, 0, "NextContinuationToken");
      }
      buckets_xml_doc_free(&d);
      buckets_s3c_result_free(&r);
      if (!more || !token) break;
    }
    free(token);
    ok = remove_objects(fs, bucket, keys, nk, err, errlen);
    for (size_t i = 0; i < nk; i++) free(keys[i]);
    free(keys);
  }
  free(bucket);
  free(prefix);
  return ok;
}

bool buckets_fs_delete(buckets_fs *fs, const char *path, char *err, size_t errlen) {
  char *bucket, *object;
  buckets_fs_split(path, &bucket, &object);
  bool ok = false;
  if (!*bucket) {
    seterr(err, errlen, "bucket name cannot be empty");
  } else if (!check_bucket(bucket, false, err, errlen) || !check_object(object, err, errlen)) {
    /* RemoveObject's argument checks */
  } else {
    buckets_s3c_result r = {0};
    ok = call(fs, "DELETE", bucket, object, NULL, NULL, 0, NULL, 0, &r);
    if (!ok) seterr(err, errlen, buckets_s3c_error(&r));
    buckets_s3c_result_free(&r);
  }
  free(bucket);
  free(object);
  return ok;
}

buckets_http_stream *buckets_fs_get(buckets_fs *fs, const char *path, int64_t offset, int64_t *size, char *err,
                                    size_t errlen) {
  char *bucket, *object;
  buckets_fs_split(path, &bucket, &object);
  buckets_http_stream *st = NULL;
  if (!*bucket) {
    seterr(err, errlen, "bucket name cannot be empty");
  } else if (!check_bucket(bucket, false, err, errlen) || !check_object(object, err, errlen)) {
    /* GetObject's argument checks */
  } else {
    buckets_http_kv h[3];
    size_t n = fwd_hdr(fs, h);
    char range[48];
    if (offset > 0) {
      snprintf(range, sizeof(range), "bytes=%lld-", (long long)offset);
      h[n++] = (buckets_http_kv){"Range", range};
    }
    buckets_s3c_result r = {0};
    st = buckets_s3c_open(fs->c, "GET", bucket, object, NULL, h, n, &r);
    if (!st) {
      seterr(err, errlen, buckets_s3c_error(&r));
    } else {
      char cl[32], cr[96];
      buckets_s3c_header_copy(&r, "Content-Length", cl, sizeof(cl));
      buckets_s3c_header_copy(&r, "Content-Range", cr, sizeof(cr));
      const char *slash = strrchr(cr, '/');
      int64_t total = slash ? strtoll(slash + 1, NULL, 10) : strtoll(cl, NULL, 10);
      *size = total - offset;
    }
    buckets_s3c_result_free(&r);
  }
  free(bucket);
  free(object);
  return st;
}

/* ---- PutFile: minio-go's multipart upload of unknown length ---- */

#define PART_SIZE 553648128LL /* OptimalPartInfo(-1): 5 TiB / 10000, rounded up to 16 MiB */
#define SPOOL_MEM (8 << 20)

typedef struct {
  buckets_buf mem;
  FILE *f;
  int64_t len, pos;
} spool;

static void spool_reset(spool *s) {
  buckets_buf_reset(&s->mem);
  if (s->f) fclose(s->f);
  s->f = NULL;
  s->len = s->pos = 0;
}

static bool spool_add(spool *s, const void *p, size_t n) {
  if (!s->f && s->mem.len + n <= SPOOL_MEM) {
    buckets_buf_append(&s->mem, p, n);
  } else {
    if (!s->f) {
      if (!(s->f = tmpfile())) return false;
      if (s->mem.len && fwrite(s->mem.data, 1, s->mem.len, s->f) != s->mem.len) return false;
      buckets_buf_reset(&s->mem);
    }
    if (fwrite(p, 1, n, s->f) != n) return false;
  }
  s->len += (int64_t)n;
  return true;
}

static long spool_read(void *ud, void *buf, size_t n) {
  spool *s = ud;
  if (s->pos >= s->len) return 0;
  size_t k = (size_t)BUCKETS_MIN((int64_t)n, s->len - s->pos);
  if (!s->f) {
    memcpy(buf, s->mem.data + s->pos, k);
  } else {
    if (s->pos == 0) fflush(s->f), fseeko(s->f, 0, SEEK_SET);
    k = fread(buf, 1, k, s->f);
    if (k == 0) return -1;
  }
  s->pos += (int64_t)k;
  return (long)k;
}

static void crc_b64(uint32_t crc, char out[16]) {
  uint8_t b[4] = {(uint8_t)(crc >> 24), (uint8_t)(crc >> 16), (uint8_t)(crc >> 8), (uint8_t)crc};
  buckets_base64_encode(b, 4, out);
}

bool buckets_fs_put(buckets_fs *fs, const char *path, long (*rd)(void *ud, void *buf, size_t n), void *ud, int64_t *n,
                    char *err, size_t errlen) {
  *n = 0;
  char *bucket, *object;
  buckets_fs_split(path, &bucket, &object);
  if (!*bucket || !check_bucket(bucket, false, err, errlen) || !check_object(object, err, errlen)) {
    if (!*bucket) seterr(err, errlen, "bucket name cannot be empty");
    free(bucket);
    free(object);
    return false;
  }
  const char *dot = strrchr(object, '.'), *sl = strrchr(object, '/');
  const char *ctype = buckets_mimedb_type(dot && (!sl || dot > sl) ? dot : "");
  buckets_http_kv ch[] = {{"Content-Type", ctype}, {"X-Amz-Checksum-Algorithm", "CRC32C"},
                          {"X-Amz-Checksum-Type", "FULL_OBJECT"}};
  buckets_s3c_result r = {0};
  bool ok = false;
  char *upload = NULL;
  buckets_buf complete = BUCKETS_BUF_INIT;
  spool sp = {BUCKETS_BUF_INIT, NULL, 0, 0};
  uint32_t full = 0;
  if (!call(fs, "POST", bucket, object, "uploads=", ch, 3, NULL, 0, &r)) {
    seterr(err, errlen, buckets_s3c_error(&r));
    goto out;
  }
  {
    buckets_xml_doc d = {0};
    if (buckets_xml_parse((buckets_str){r.body.data, r.body.len}, &d) && d.count) upload = xml_text(&d, 0, "UploadId");
    buckets_xml_doc_free(&d);
  }
  buckets_s3c_result_free(&r);
  if (!upload) {
    seterr(err, errlen, "missing upload ID");
    goto out;
  }
  buckets_buf_append_c(&complete, "<CompleteMultipartUpload>");
  bool eof = false;
  for (int part = 1; !eof; part++) {
    spool_reset(&sp);
    uint32_t pcrc = 0;
    char buf[65536];
    while (sp.len < PART_SIZE) {
      long k = rd(ud, buf, (size_t)BUCKETS_MIN((int64_t)sizeof(buf), PART_SIZE - sp.len));
      if (k < 0) {
        seterr(err, errlen, "unexpected EOF");
        goto abort;
      }
      if (k == 0) {
        eof = true;
        break;
      }
      if (!spool_add(&sp, buf, (size_t)k)) {
        seterr(err, errlen, strerror(errno));
        goto abort;
      }
      pcrc = buckets_crc32c(pcrc, buf, (size_t)k);
      full = buckets_crc32c(full, buf, (size_t)k);
    }
    if (eof && sp.len == 0 && part > 1) break;
    char pb64[16], q[512];
    crc_b64(pcrc, pb64);
    snprintf(q, sizeof(q), "partNumber=%d&uploadId=%s", part, upload);
    buckets_http_kv ph[2];
    size_t np = fwd_hdr(fs, ph);
    ph[np++] = (buckets_http_kv){"x-amz-checksum-crc32c", pb64};
    sp.pos = 0;
    if (!buckets_s3c_do_stream(fs->c, "PUT", bucket, object, q, ph, np, spool_read, &sp, sp.len, &r)) {
      seterr(err, errlen, buckets_s3c_error(&r));
      buckets_s3c_result_free(&r);
      goto abort;
    }
    char etag[128];
    buckets_s3c_header_copy(&r, "ETag", etag, sizeof(etag));
    buckets_s3c_result_free(&r);
    buckets_buf_appendf(&complete, "<Part><PartNumber>%d</PartNumber><ETag>", part);
    buckets_xml_text(&complete, etag, strlen(etag));
    buckets_buf_appendf(&complete, "</ETag><ChecksumCRC32C>%s</ChecksumCRC32C></Part>", pb64);
    *n += sp.len;
  }
  buckets_buf_append_c(&complete, "</CompleteMultipartUpload>");
  {
    char fb64[16], q[512];
    crc_b64(full, fb64);
    snprintf(q, sizeof(q), "uploadId=%s", upload);
    buckets_http_kv h[] = {{"x-amz-checksum-crc32c", fb64}, {"x-amz-checksum-type", "FULL_OBJECT"}};
    if (!call(fs, "POST", bucket, object, q, h, 2, complete.data, complete.len, &r)) {
      seterr(err, errlen, buckets_s3c_error(&r));
      buckets_s3c_result_free(&r);
      goto abort;
    }
    buckets_s3c_result_free(&r);
  }
  ok = true;
  goto out;
abort : {
  char q[512];
  snprintf(q, sizeof(q), "uploadId=%s", upload);
  call(fs, "DELETE", bucket, object, q, NULL, 0, NULL, 0, &r);
  buckets_s3c_result_free(&r);
}
out:
  spool_reset(&sp);
  buckets_buf_free(&sp.mem);
  buckets_buf_free(&complete);
  free(upload);
  free(bucket);
  free(object);
  return ok;
}
