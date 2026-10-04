/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* The cluster's KES server, and trials of new key store settings for the
 * console's "Test" step. */
#include "kms.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "core/buf.h"
#include "core/log.h"
#include "crypto/base64.h"
#include "crypto/hex.h"
#include "crypto/sha256.h"
#include "kms/kesutil.h"
#include "kms/kms.h"

/* how long a trial KES may take to become ready */
#define TRIAL_TIMEOUT_S 120

typedef yyjson_mut_doc mdoc;
typedef yyjson_mut_val mval;

static yyjson_val *at(yyjson_val *o, const char *path) {
  char key[128];
  while (o && *path) {
    const char *dot = strchr(path, '.');
    size_t n = dot ? (size_t)(dot - path) : strlen(path);
    snprintf(key, sizeof(key), "%.*s", (int)n, path);
    o = yyjson_obj_get(o, key);
    path = dot ? dot + 1 : path + n;
  }
  return o;
}
static const char *get_str(yyjson_val *o, const char *path) { return yyjson_get_str(at(o, path)); }

/* ---- Secrets ------------------------------------------------------------------- */

static char *secret_path(const bc_spec *s, const char *name) {
  buckets_buf p = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&p, "/api/v1/namespaces/%s/secrets/%s", s->ns, name);
  return p.data;
}

/* data[key] of a Secret, decoded; NULL if absent */
static char *secret_value(yyjson_val *secret, const char *key) {
  const char *b64 = yyjson_get_str(yyjson_obj_get(yyjson_obj_get(secret, "data"), key)); /* keys have dots */
  if (!b64) return NULL;
  size_t n = strlen(b64);
  char *out = buckets_xmalloc(n * 3 / 4 + 4);
  long k = buckets_base64_decode(b64, n, (uint8_t *)out);
  if (k < 0) {
    free(out);
    return NULL;
  }
  out[k] = '\0';
  return out;
}

/* Reads a Secret, creating it with make() when it does not exist. */
static bool ensure_secret(op_ctx *o, const bc_spec *s, const char *name, yyjson_mut_doc *(*make)(const bc_spec *, void *),
                          void *ud, yyjson_doc **out, char *err, size_t errlen) {
  char *path = secret_path(s, name);
  int st = kube_get(o->k, path, out);
  if (st == 404) {
    yyjson_doc_free(*out);
    *out = NULL;
    yyjson_mut_doc *d = make(s, ud);
    buckets_buf coll = BUCKETS_BUF_INIT;
    buckets_buf_appendf(&coll, "/api/v1/namespaces/%s/secrets", s->ns);
    yyjson_doc *resp = NULL;
    st = d ? kube_create(o->k, coll.data, d, &resp) : 0;
    if (st == 201) buckets_log_info("%s/%s: created Secret %s", s->ns, s->name, name);
    else if (st != 409) buckets_log_warn("%s/%s: creating Secret %s: %d %s", s->ns, s->name, name, st, kube_error_message(resp));
    yyjson_doc_free(resp);
    yyjson_mut_doc_free(d);
    buckets_buf_free(&coll);
    if (st == 201 || st == 409) st = kube_get(o->k, path, out);
  }
  free(path);
  if (st != 200) {
    snprintf(err, errlen, "Secret %s cannot be read or created (%d)", name, st);
    return false;
  }
  return true;
}

static yyjson_mut_doc *make_empty(const bc_spec *s, void *name) { return bc_kms_empty_secret(s, name); }

static yyjson_mut_doc *make_tls(const bc_spec *s, void *ud) {
  (void)ud;
  char live[128], trial[128], n[8][300];
  bc_kes_name(s, false, live, sizeof(live));
  bc_kes_name(s, true, trial, sizeof(trial));
  const char *names[2] = {live, trial};
  for (int i = 0; i < 2; i++) {
    snprintf(n[4 * i], sizeof(n[0]), "%s", names[i]);
    snprintf(n[4 * i + 1], sizeof(n[0]), "%s.%s", names[i], s->ns);
    snprintf(n[4 * i + 2], sizeof(n[0]), "%s.%s.svc", names[i], s->ns);
    snprintf(n[4 * i + 3], sizeof(n[0]), "%s.%s.svc.%s", names[i], s->ns, s->cluster_domain);
  }
  const char *dns[8];
  for (int i = 0; i < 8; i++) dns[i] = n[i];
  buckets_buf cert = BUCKETS_BUF_INIT, key = BUCKETS_BUF_INIT;
  char err[128];
  yyjson_mut_doc *d = NULL; /* NULL: reported as not created */
  if (buckets_kes_server_cert(dns, 8, 3650, &cert, &key, err, sizeof(err))) d = bc_kes_tls_secret(s, cert.data, key.data);
  buckets_buf_free(&cert);
  if (key.data) memset(key.data, 0, key.len);
  buckets_buf_free(&key);
  return d;
}

static yyjson_mut_doc *make_identity(const bc_spec *s, void *ud) {
  (void)ud;
  char admin[64], client[64];
  buckets_kes_api_key_new(admin);
  buckets_kes_api_key_new(client);
  yyjson_mut_doc *d = bc_kes_identity_secret(s, admin, client);
  memset(admin, 0, sizeof(admin));
  memset(client, 0, sizeof(client));
  return d;
}

/* What KES runs with: its certificate, and the admin and bucketsd API keys. */
typedef struct {
  char *cert, *admin, *client;
  char admin_id[65], client_id[65];
} kes_creds;

static void creds_free(kes_creds *c) {
  free(c->cert);
  if (c->admin) memset(c->admin, 0, strlen(c->admin)), free(c->admin);
  if (c->client) memset(c->client, 0, strlen(c->client)), free(c->client);
}

static bool ensure_creds(op_ctx *o, const bc_spec *s, kes_creds *c, char *err, size_t errlen) {
  memset(c, 0, sizeof(*c));
  char name[128];
  yyjson_doc *doc = NULL;
  bool ok = true;
  /* the console fills these in; it may only update Secrets that exist */
  bc_kms_settings_secret_name(s, name, sizeof(name));
  ok = ensure_secret(o, s, name, make_empty, name, &doc, err, errlen);
  yyjson_doc_free(doc), doc = NULL;
  bc_kms_candidate_secret_name(s, name, sizeof(name));
  ok = ok && ensure_secret(o, s, name, make_empty, name, &doc, err, errlen);
  yyjson_doc_free(doc), doc = NULL;
  bc_kes_tls_secret_name(s, name, sizeof(name));
  ok = ok && ensure_secret(o, s, name, make_tls, NULL, &doc, err, errlen);
  if (ok) c->cert = secret_value(yyjson_doc_get_root(doc), "tls.crt");
  yyjson_doc_free(doc), doc = NULL;
  bc_kes_identity_secret_name(s, name, sizeof(name));
  ok = ok && ensure_secret(o, s, name, make_identity, NULL, &doc, err, errlen);
  if (ok) {
    c->admin = secret_value(yyjson_doc_get_root(doc), "admin");
    c->client = secret_value(yyjson_doc_get_root(doc), "client");
  }
  yyjson_doc_free(doc);
  if (ok && (!c->cert || !c->admin || !c->client || !buckets_kes_identity(c->admin, c->admin_id) ||
             !buckets_kes_identity(c->client, c->client_id))) {
    char tn[160], in[160];
    bc_kes_tls_secret_name(s, tn, sizeof(tn));
    bc_kes_identity_secret_name(s, in, sizeof(in));
    snprintf(err, errlen, "the KES Secrets %s and %s are incomplete: delete them to have them made again", tn, in);
    ok = false;
  }
  if (!ok) creds_free(c);
  return ok;
}

/* A Secret's JSON document data[key], parsed; NULL if absent or not JSON. */
static yyjson_doc *secret_json(op_ctx *o, const bc_spec *s, const char *name, const char *key) {
  char *path = secret_path(s, name);
  yyjson_doc *sec = NULL;
  int st = kube_get(o->k, path, &sec);
  free(path);
  char *v = st == 200 ? secret_value(yyjson_doc_get_root(sec), key) : NULL;
  yyjson_doc_free(sec);
  if (!v) return NULL;
  yyjson_doc *d = yyjson_read(v, strlen(v), 0);
  memset(v, 0, strlen(v));
  free(v);
  return d;
}

bool op_secret_ensure_empty(op_ctx *o, const bc_spec *s, const char *name, char *err, size_t errlen) {
  yyjson_doc *doc = NULL;
  bool ok = ensure_secret(o, s, name, make_empty, (void *)name, &doc, err, errlen);
  yyjson_doc_free(doc);
  return ok;
}

char *op_secret_text(op_ctx *o, const bc_spec *s, const char *name, const char *key) {
  char *path = secret_path(s, name);
  yyjson_doc *sec = NULL;
  int st = kube_get(o->k, path, &sec);
  free(path);
  char *v = st == 200 ? secret_value(yyjson_doc_get_root(sec), key) : NULL;
  yyjson_doc_free(sec);
  return v;
}

yyjson_doc *op_secret_json(op_ctx *o, const bc_spec *s, const char *name, const char *key) {
  return secret_json(o, s, name, key);
}

/* ---- KES servers ------------------------------------------------------------- */

static bool apply_all(op_ctx *o, const bc_spec *s, bc_object *objs, size_t n, long long *ready, char *err,
                      size_t errlen) {
  *ready = 0;
  for (size_t i = 0; i < n; i++) {
    yyjson_doc *resp = NULL;
    int code = kube_apply(o->k, objs[i].path, objs[i].doc, &resp);
    if (code / 100 != 2) {
      snprintf(err, errlen, "applying %s failed (%d): %s", objs[i].path, code, kube_error_message(resp));
      buckets_log_warn("%s/%s: %s", s->ns, s->name, err);
      yyjson_doc_free(resp);
      return false;
    }
    const char *kind = get_str(yyjson_doc_get_root(resp), "kind");
    if (kind && strcmp(kind, "Deployment") == 0) *ready = yyjson_get_sint(at(yyjson_doc_get_root(resp), "status.readyReplicas"));
    yyjson_doc_free(resp);
  }
  return true;
}

static void delete_kes(op_ctx *o, const bc_spec *s, bool trial) {
  char **paths;
  size_t n = bc_kes_paths(s, trial, &paths);
  for (size_t i = 0; i < n; i++) {
    kube_delete(o->k, paths[i]);
    free(paths[i]);
  }
  free(paths);
}

/* A client for a KES server, as its admin. */
static buckets_kms *kes_client(const bc_spec *s, bool trial, const char *key_name, const kes_creds *c, char *err,
                               size_t errlen) {
  char tmpl[] = "/tmp/buckets-operator-kes-XXXXXX";
  int fd = mkstemp(tmpl);
  if (fd < 0) {
    snprintf(err, errlen, "cannot write KES's CA certificate to /tmp");
    return NULL;
  }
  size_t n = strlen(c->cert);
  bool wrote = write(fd, c->cert, n) == (ssize_t)n;
  close(fd);
  char ep[512];
  bc_kes_endpoint(s, trial, ep, sizeof(ep));
  buckets_kms *k = wrote ? buckets_kms_kes_new(ep, key_name, c->admin, tmpl, err, errlen) : NULL;
  if (!wrote) snprintf(err, errlen, "cannot write KES's CA certificate to /tmp");
  unlink(tmpl);
  return k;
}

/* The reason in a KES server's log: the "Error: ..." it exited with (the last
 * thing it prints: to the end), or the message of its last ERROR line. */
void op_kes_log_reason(const char *text, char *out, size_t cap) {
  buckets_buf r = BUCKETS_BUF_INIT;
  const char *p = text;
  while (p && *p) {
    const char *eol = strchr(p, '\n');
    size_t n = eol ? (size_t)(eol - p) : strlen(p);
    const char *m;
    if (n > 7 && strncmp(p, "Error: ", 7) == 0) {
      buckets_buf_reset(&r);
      buckets_buf_append(&r, p + 7, n - 7);
      /* Vault's errors go on over several lines, blank ones between */
      for (const char *q = eol ? eol + 1 : NULL; q && *q;) {
        const char *e2 = strchr(q, '\n');
        size_t n2 = e2 ? (size_t)(e2 - q) : strlen(q);
        buckets_buf_append_char(&r, ' ');
        buckets_buf_append(&r, q, n2);
        q = e2 ? e2 + 1 : NULL;
      }
      break;
    } else if ((m = strstr(p, "\"level\":\"ERROR\"")) && m < p + n && (m = strstr(m, "\"msg\":\"")) && m < p + n) {
      /* buckets-kes: {"level":"ERROR","time":...,"msg":"..."} */
      buckets_buf_reset(&r);
      for (const char *c = m + 7; c < p + n && *c != '"'; c++) {
        if (*c == '\\' && c + 1 < p + n) {
          c++;
          buckets_buf_append_char(&r, *c == 'n' || *c == 't' ? ' ' : *c);
        } else {
          buckets_buf_append_char(&r, *c);
        }
      }
    } else if ((m = strstr(p, "level=ERROR msg=\"")) && m < p + n) {
      buckets_buf_reset(&r);
      for (const char *c = m + 17; c < p + n && *c != '"'; c++) {
        if (*c == '\\' && c + 1 < p + n) {
          c++;
          buckets_buf_append_char(&r, *c == 'n' || *c == 't' ? ' ' : *c);
        } else {
          buckets_buf_append_char(&r, *c);
        }
      }
    }
    p = eol ? eol + 1 : NULL;
  }
  /* one line, single spaces */
  size_t w = 0;
  for (size_t i = 0; i < r.len && w + 1 < cap; i++) {
    char ch = r.data[i] == '\t' || r.data[i] == '\n' ? ' ' : r.data[i];
    if (ch == ' ' && (w == 0 || out[w - 1] == ' ')) continue;
    out[w++] = ch;
  }
  while (w && out[w - 1] == ' ') w--;
  out[w] = '\0';
  buckets_buf_free(&r);
}

typedef struct {
  char pod[128];
  bool ready, failed;
  int restarts;
  char why[600];
} pod_state;

/* The state of a KES server's (first) pod, and why it fails if it does. */
static void kes_pod(op_ctx *o, const bc_spec *s, bool trial, pod_state *ps) {
  memset(ps, 0, sizeof(*ps));
  char kes[128];
  bc_kes_name(s, trial, kes, sizeof(kes));
  buckets_buf path = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&path, "/api/v1/namespaces/%s/pods?labelSelector=buckets.io%%2Fkes%%3D%s", s->ns, kes);
  yyjson_doc *doc = NULL;
  int st = kube_get(o->k, path.data, &doc);
  buckets_buf_free(&path);
  yyjson_val *pod = st == 200 ? yyjson_arr_get_first(yyjson_obj_get(yyjson_doc_get_root(doc), "items")) : NULL;
  if (!pod) {
    yyjson_doc_free(doc);
    return;
  }
  snprintf(ps->pod, sizeof(ps->pod), "%s", get_str(pod, "metadata.name") ? get_str(pod, "metadata.name") : "");
  yyjson_val *cs = yyjson_arr_get_first(at(pod, "status.containerStatuses"));
  ps->ready = yyjson_get_bool(yyjson_obj_get(cs, "ready"));
  ps->restarts = (int)yyjson_get_sint(yyjson_obj_get(cs, "restartCount"));
  const char *reason = get_str(cs, "state.waiting.reason"), *wmsg = get_str(cs, "state.waiting.message");
  bool terminated = at(cs, "state.terminated") != NULL;
  if (reason && (strcmp(reason, "ErrImagePull") == 0 || strcmp(reason, "ImagePullBackOff") == 0 ||
                 strcmp(reason, "InvalidImageName") == 0)) {
    ps->failed = true;
    snprintf(ps->why, sizeof(ps->why), "The KES image %s cannot be pulled%s%s", s->kes.image, wmsg ? ": " : ".",
             wmsg ? wmsg : "");
  } else if (reason && strcmp(reason, "CreateContainerConfigError") == 0) {
    ps->failed = true;
    snprintf(ps->why, sizeof(ps->why), "KES cannot start: %s", wmsg ? wmsg : reason);
  } else if (ps->restarts > 0 || terminated) {
    ps->failed = true;
    buckets_buf p2 = BUCKETS_BUF_INIT, logs = BUCKETS_BUF_INIT;
    buckets_buf_appendf(&p2, "/api/v1/namespaces/%s/pods/%s/log?container=kes&tailLines=40%s", s->ns, ps->pod,
                        terminated ? "" : "&previous=true");
    kube_get_text(o->k, p2.data, &logs);
    char r[500] = "";
    if (logs.len) op_kes_log_reason(logs.data, r, sizeof(r));
    snprintf(ps->why, sizeof(ps->why), "KES stopped: %s", *r ? r : "see its log");
    buckets_buf_free(&p2);
    buckets_buf_free(&logs);
  }
  yyjson_doc_free(doc);
}

/* The reason a running KES gave for failing a request, from its log. */
static void kes_log_reason(op_ctx *o, const bc_spec *s, const char *pod, char *out, size_t cap) {
  *out = '\0';
  if (!*pod) return;
  buckets_buf p = BUCKETS_BUF_INIT, logs = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&p, "/api/v1/namespaces/%s/pods/%s/log?container=kes&tailLines=20", s->ns, pod);
  if (kube_get_text(o->k, p.data, &logs) == 200 && logs.len) op_kes_log_reason(logs.data, out, cap);
  buckets_buf_free(&p);
  buckets_buf_free(&logs);
}

static const char *kms_errtext(buckets_kms_err e) {
  switch (e) {
  case BUCKETS_KMS_ERR_KEY_NOT_FOUND: return "the key does not exist";
  case BUCKETS_KMS_ERR_KEY_EXISTS: return "the key exists already";
  case BUCKETS_KMS_ERR_PERMISSION: return "KES refused the request";
  case BUCKETS_KMS_ERR_UNAVAILABLE: return "KES cannot be reached";
  case BUCKETS_KMS_ERR_DECRYPT: return "decrypting failed";
  default: return "the key store failed the request";
  }
}

/* Makes sure a KES server has a key, creating it when allowed. "" when it is
 * there (created says whether it was made now), else why not. */
static void ensure_key(buckets_kms *k, const char *name, bool create, bool *created, buckets_kms_err *e) {
  uint8_t pt[32];
  buckets_buf ct = BUCKETS_BUF_INIT;
  char kid[256];
  *created = false;
  *e = buckets_kms_generate(k, name, "{}", pt, &ct, kid, sizeof(kid));
  if (*e == BUCKETS_KMS_ERR_KEY_NOT_FOUND && create) {
    *e = buckets_kms_create_key(k, name);
    if (*e == BUCKETS_KMS_ERR_KEY_EXISTS) *e = BUCKETS_KMS_OK;
    *created = *e == BUCKETS_KMS_OK;
  }
  buckets_buf_free(&ct);
}

/* ---- status helpers ------------------------------------------------------------- */

static void step(mdoc *d, mval *steps, const char *name, const char *status, const char *message) {
  mval *st = yyjson_mut_arr_add_obj(d, steps);
  yyjson_mut_obj_add_strcpy(d, st, "name", name);
  yyjson_mut_obj_add_strcpy(d, st, "status", status);
  if (message && *message) yyjson_mut_obj_add_strcpy(d, st, "message", message);
}

static void sha_hex(const char *s, char out[17]) {
  uint8_t h[32];
  buckets_sha256(s, strlen(s), h);
  buckets_hex_encode(h, 8, out);
  out[16] = '\0';
}

/* ---- trials --------------------------------------------------------------------- */

/* Runs the checks against a ready trial server; false when one fails. */
static bool trial_checks(op_ctx *o, const bc_spec *s, yyjson_val *cand, const kes_creds *c, const char *pod, mdoc *d,
                         mval *steps, char *msg, size_t cap) {
  const char *key = get_str(cand, "keyName");
  if (!key || !*key) key = BC_KES_DEFAULT_KEY;
  bool create = yyjson_get_bool(yyjson_obj_get(cand, "createKey"));
  char err[300], why[500], line[700];
  buckets_kms *k = kes_client(s, true, key, c, err, sizeof(err));
  if (!k) {
    step(d, steps, "Reach the key store", "failed", err);
    snprintf(msg, cap, "%s", err);
    return false;
  }
  bool ok = false, created;
  buckets_kms_err e;
  ensure_key(k, key, create, &created, &e);
  char title[300];
  snprintf(title, sizeof(title), "Default key %s", key);
  if (e == BUCKETS_KMS_ERR_KEY_NOT_FOUND) {
    step(d, steps, "Reach the key store", "ok", NULL);
    snprintf(line, sizeof(line), "Key %s is not in this key store. Choose an existing key, or let Buckets create it.", key);
    step(d, steps, title, "failed", line);
    snprintf(msg, cap, "%s", line);
    goto out;
  }
  if (e) {
    kes_log_reason(o, s, pod, why, sizeof(why));
    snprintf(line, sizeof(line), "%s", *why ? why : kms_errtext(e));
    step(d, steps, "Reach the key store", "failed", line);
    snprintf(msg, cap, "%s", line);
    goto out;
  }
  step(d, steps, "Reach the key store", "ok", NULL);
  step(d, steps, title, "ok", created ? "created" : "exists");
  /* a data key, as for an object, and back */
  uint8_t pt[32], back[32];
  buckets_buf ct = BUCKETS_BUF_INIT;
  char kid[256];
  e = buckets_kms_generate(k, key, "{\"buckets\":\"test\"}", pt, &ct, kid, sizeof(kid));
  if (!e) e = buckets_kms_decrypt(k, key, (const uint8_t *)ct.data, ct.len, "{\"buckets\":\"test\"}", back);
  if (!e && memcmp(pt, back, 32) != 0) e = BUCKETS_KMS_ERR_DECRYPT;
  buckets_buf_free(&ct);
  if (e) {
    kes_log_reason(o, s, pod, why, sizeof(why));
    snprintf(line, sizeof(line), "%s", *why ? why : kms_errtext(e));
    step(d, steps, "Encrypt and decrypt with it", "failed", line);
    snprintf(msg, cap, "%s", line);
    goto out;
  }
  step(d, steps, "Encrypt and decrypt with it", "ok", NULL);
  /* the keys the cluster uses now must be there too */
  buckets_buf missing = BUCKETS_BUF_INIT;
  size_t i, max, nreq = 0;
  yyjson_val *rk;
  yyjson_arr_foreach(yyjson_obj_get(cand, "requiredKeys"), i, max, rk) {
    const char *name = yyjson_get_str(rk);
    if (!name || !*name || strcmp(name, key) == 0) continue;
    nreq++;
    bool cr;
    ensure_key(k, name, false, &cr, &e);
    if (e) buckets_buf_appendf(&missing, "%s%s", missing.len ? ", " : "", name);
  }
  if (missing.len) {
    snprintf(line, sizeof(line),
             "This key store lacks keys the cluster uses now: %s. Objects encrypted with them could not be read. Copy "
             "the keys into it first, or keep the current key store.",
             missing.data);
    step(d, steps, "Keys in use", "failed", line);
    snprintf(msg, cap, "%s", line);
    buckets_buf_free(&missing);
    goto out;
  }
  if (nreq) step(d, steps, "Keys in use", "ok", NULL);
  buckets_buf_free(&missing);
  snprintf(msg, cap, "Every check passed.");
  ok = true;
out:
  buckets_kms_free(k);
  return ok;
}

/* The trial the console asked for: started, followed, finished. Writes status.kms.test. */
static void reconcile_trial(op_ctx *o, yyjson_val *bc, const bc_spec *s, const kes_creds *c, mdoc *d, mval *kms) {
  yyjson_val *prev = at(bc, "status.kms.test");
  const char *want = yyjson_get_str(yyjson_obj_get(at(bc, "metadata.annotations"), BC_KMS_TEST_ANNOTATION));
  const char *prev_id = get_str(prev, "id"), *prev_phase = get_str(prev, "phase");
  time_t now = time(NULL);
  if (want && *want && (!prev_id || strcmp(prev_id, want) != 0)) {
    /* a new trial */
    mval *t = yyjson_mut_obj_add_obj(d, kms, "test");
    yyjson_mut_obj_add_strcpy(d, t, "id", want);
    yyjson_mut_obj_add_int(d, t, "startedAt", (int64_t)now);
    mval *steps = yyjson_mut_obj_add_arr(d, t, "steps");
    char cn[128], err[400];
    bc_kms_candidate_secret_name(s, cn, sizeof(cn));
    yyjson_doc *cand = secret_json(o, s, cn, "candidate.json");
    yyjson_val *cr = yyjson_doc_get_root(cand);
    char *config = NULL, *ca = NULL;
    if (!cr) snprintf(err, sizeof(err), "There are no settings to test in Secret %s.", cn);
    else config = bc_kes_config(s, yyjson_obj_get(cr, "settings"), c->admin_id, c->client_id, &ca, err, sizeof(err));
    if (config) {
      char hash[17];
      sha_hex(config, hash);
      yyjson_mut_obj_add_strcpy(d, t, "configHash", hash);
    }
    if (!config) {
      step(d, steps, "Check the settings", "failed", err);
      yyjson_mut_obj_add_str(d, t, "phase", "Failed");
      yyjson_mut_obj_add_strcpy(d, t, "message", err);
      yyjson_mut_obj_add_int(d, t, "finishedAt", (int64_t)now);
    } else {
      step(d, steps, "Check the settings", "ok", NULL);
      delete_kes(o, s, true); /* a trial before this one */
      bc_object *objs;
      size_t n = bc_kes_objects(s, true, config, ca, &objs);
      long long ready;
      if (apply_all(o, s, objs, n, &ready, err, sizeof(err))) {
        step(d, steps, "Start KES with these settings", "running", NULL);
        yyjson_mut_obj_add_str(d, t, "phase", "Running");
        yyjson_mut_obj_add_str(d, t, "message", "Starting KES with these settings");
        buckets_log_info("%s/%s: trying new KMS settings (%s)", s->ns, s->name, want);
      } else {
        step(d, steps, "Start KES with these settings", "failed", err);
        yyjson_mut_obj_add_str(d, t, "phase", "Failed");
        yyjson_mut_obj_add_strcpy(d, t, "message", err);
        yyjson_mut_obj_add_int(d, t, "finishedAt", (int64_t)now);
      }
      bc_objects_free(objs, n);
    }
    free(config);
    free(ca);
    yyjson_doc_free(cand);
    return;
  }
  if (!prev) return;
  if (!prev_phase || strcmp(prev_phase, "Running") != 0) { /* finished: kept as reported */
    yyjson_mut_obj_add_val(d, kms, "test", yyjson_val_mut_copy(d, prev));
    return;
  }
  /* running: ready, failed, or still starting */
  mval *t = yyjson_mut_obj_add_obj(d, kms, "test");
  yyjson_mut_obj_add_strcpy(d, t, "id", prev_id ? prev_id : "");
  int64_t started = yyjson_get_sint(yyjson_obj_get(prev, "startedAt"));
  yyjson_mut_obj_add_int(d, t, "startedAt", started);
  if (get_str(prev, "configHash")) yyjson_mut_obj_add_strcpy(d, t, "configHash", get_str(prev, "configHash"));
  mval *steps = yyjson_mut_obj_add_arr(d, t, "steps");
  step(d, steps, "Check the settings", "ok", NULL);
  pod_state ps;
  kes_pod(o, s, true, &ps);
  char msg[800] = "";
  bool passed = false;
  if (ps.ready) {
    step(d, steps, "Start KES with these settings", "ok", NULL);
    char cn[128];
    bc_kms_candidate_secret_name(s, cn, sizeof(cn));
    yyjson_doc *cand = secret_json(o, s, cn, "candidate.json");
    passed = trial_checks(o, s, yyjson_doc_get_root(cand), c, ps.pod, d, steps, msg, sizeof(msg));
    yyjson_doc_free(cand);
  } else if (ps.failed) {
    step(d, steps, "Start KES with these settings", "failed", ps.why);
    snprintf(msg, sizeof(msg), "%s", ps.why);
  } else if (now - started > TRIAL_TIMEOUT_S) {
    char why[500];
    kes_log_reason(o, s, ps.pod, why, sizeof(why));
    snprintf(msg, sizeof(msg), "KES did not become ready within %d seconds%s%s", TRIAL_TIMEOUT_S, *why ? ": " : ".", why);
    step(d, steps, "Start KES with these settings", "failed", msg);
  } else {
    step(d, steps, "Start KES with these settings", "running", NULL);
    yyjson_mut_obj_add_str(d, t, "phase", "Running");
    yyjson_mut_obj_add_str(d, t, "message", "Starting KES with these settings");
    return;
  }
  yyjson_mut_obj_add_str(d, t, "phase", passed ? "Passed" : "Failed");
  yyjson_mut_obj_add_strcpy(d, t, "message", msg);
  yyjson_mut_obj_add_int(d, t, "finishedAt", (int64_t)time(NULL));
  buckets_log_info("%s/%s: KMS settings trial %s %s: %s", s->ns, s->name, prev_id ? prev_id : "", passed ? "passed" : "failed",
                   msg);
  delete_kes(o, s, true);
}

/* ---- the live server -------------------------------------------------------------- */

void op_kms_reconcile(op_ctx *o, yyjson_val *bc, bc_spec *s, yyjson_mut_doc *d, yyjson_mut_val *kms) {
  yyjson_val *prev = at(bc, "status.kms");
  bool was_deployed = yyjson_get_bool(yyjson_obj_get(prev, "deployed"));
  bool activated = yyjson_get_bool(yyjson_obj_get(prev, "activated"));
  s->kes.active = false;
  if (!s->console.enabled && !s->kes.enabled) {
    if (was_deployed) delete_kes(o, s, false);
    yyjson_mut_obj_add_str(d, kms, "phase", "Off");
    return;
  }
  kes_creds c;
  char err[500];
  if (!ensure_creds(o, s, &c, err, sizeof(err))) {
    yyjson_mut_obj_add_str(d, kms, "phase", "Error");
    yyjson_mut_obj_add_strcpy(d, kms, "message", err);
    if (prev && yyjson_obj_get(prev, "test")) yyjson_mut_obj_add_val(d, kms, "test", yyjson_val_mut_copy(d, yyjson_obj_get(prev, "test")));
    s->kes.active = s->kes.enabled && activated;
    if (s->kes.active) yyjson_mut_obj_add_bool(d, kms, "activated", true);
    return;
  }
  reconcile_trial(o, bc, s, &c, d, kms);

  if (!s->kes.enabled) {
    if (was_deployed) delete_kes(o, s, false);
    yyjson_mut_obj_add_str(d, kms, "phase", "Off");
    yyjson_mut_obj_add_str(d, kms, "message", "No KMS: set one up in the console (Encryption).");
    creds_free(&c);
    return;
  }
  yyjson_mut_obj_add_strcpy(d, kms, "keyName", s->kes.key_name);
  yyjson_mut_obj_add_int(d, kms, "replicas", s->kes.replicas);
  char sn[128];
  bc_kms_settings_secret_name(s, sn, sizeof(sn));
  yyjson_doc *settings = secret_json(o, s, sn, "settings.json");
  yyjson_val *sv = yyjson_doc_get_root(settings);
  char *ca = NULL, *config = sv ? bc_kes_config(s, sv, c.admin_id, c.client_id, &ca, err, sizeof(err)) : NULL;
  if (sv) {
    char desc[300];
    buckets_kes_settings_describe(sv, desc, sizeof(desc));
    yyjson_mut_obj_add_strcpy(d, kms, "backend", desc);
  }
  if (!config) {
    yyjson_mut_obj_add_str(d, kms, "phase", sv ? "Error" : "NotConfigured");
    if (sv) yyjson_mut_obj_add_strcpy(d, kms, "message", err);
    else {
      char m[300];
      snprintf(m, sizeof(m), "No key store settings yet: set them in the console (Encryption) or in Secret %s.", sn);
      yyjson_mut_obj_add_strcpy(d, kms, "message", m);
    }
    s->kes.active = activated; /* settings broken after the fact: bucketsd keeps what it had */
    if (activated) yyjson_mut_obj_add_bool(d, kms, "activated", true);
    yyjson_doc_free(settings);
    creds_free(&c);
    return;
  }
  bc_object *objs;
  size_t n = bc_kes_objects(s, false, config, ca, &objs);
  long long ready = 0;
  bool applied = apply_all(o, s, objs, n, &ready, err, sizeof(err));
  bc_objects_free(objs, n);
  free(config);
  free(ca);
  yyjson_doc_free(settings);
  yyjson_mut_obj_add_bool(d, kms, "deployed", true);
  yyjson_mut_obj_add_int(d, kms, "readyReplicas", ready);
  char ep[512];
  bc_kes_endpoint(s, false, ep, sizeof(ep));
  yyjson_mut_obj_add_strcpy(d, kms, "endpoint", ep);
  /* the default key, made once per key name (a trial normally made it already) */
  const char *key_ready = get_str(prev, "keyReady");
  bool have_key = key_ready && strcmp(key_ready, s->kes.key_name) == 0;
  char why[500] = "";
  if (applied && !have_key && ready > 0) {
    buckets_kms *k = kes_client(s, false, s->kes.key_name, &c, err, sizeof(err));
    if (k) {
      bool created;
      buckets_kms_err e;
      ensure_key(k, s->kes.key_name, s->kes.create_key, &created, &e);
      have_key = e == BUCKETS_KMS_OK;
      if (created) buckets_log_info("%s/%s: created KMS key %s", s->ns, s->name, s->kes.key_name);
      if (e == BUCKETS_KMS_ERR_KEY_NOT_FOUND) {
        /* an adopted key store must already hold it: another key would hide that it is the wrong place */
        snprintf(why, sizeof(why), "it is not in the key store, and spec.kms.kes.createKey is false: check that the "
                                   "settings in Secret %s-kms point where the keys are", s->name);
      } else if (!have_key) {
        pod_state ps;
        kes_pod(o, s, false, &ps);
        kes_log_reason(o, s, ps.pod, why, sizeof(why));
        if (!*why) snprintf(why, sizeof(why), "%s", kms_errtext(e));
      }
      buckets_kms_free(k);
    } else {
      snprintf(why, sizeof(why), "%s", err);
    }
  }
  if (have_key) yyjson_mut_obj_add_strcpy(d, kms, "keyReady", s->kes.key_name);
  activated = activated || have_key;
  s->kes.active = activated;
  if (activated) yyjson_mut_obj_add_bool(d, kms, "activated", true);
  const char *phase;
  char msg[700];
  if (!applied) {
    phase = "Error";
    snprintf(msg, sizeof(msg), "%s", err);
  } else if (ready >= s->kes.replicas && have_key) {
    phase = "Ready";
    snprintf(msg, sizeof(msg), "%lld of %d KES servers ready", ready, s->kes.replicas);
  } else if (*why) {
    phase = "Error";
    snprintf(msg, sizeof(msg), "The default key %s: %s", s->kes.key_name, why);
  } else if (ready == 0) {
    pod_state ps;
    kes_pod(o, s, false, &ps);
    phase = activated ? "Degraded" : "Starting";
    snprintf(msg, sizeof(msg), "%s", ps.failed ? ps.why : "KES is starting");
  } else {
    phase = activated ? "Degraded" : "Starting";
    snprintf(msg, sizeof(msg), "%lld of %d KES servers ready", ready, s->kes.replicas);
  }
  yyjson_mut_obj_add_str(d, kms, "phase", phase);
  yyjson_mut_obj_add_strcpy(d, kms, "message", msg);
  creds_free(&c);
}
