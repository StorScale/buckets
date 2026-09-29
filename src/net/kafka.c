/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "net/kafka.h"

#include <libdeflate.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "core/buf.h"
#include "core/common.h"
#include "core/log.h"
#include "crypto/base64.h"
#include "crypto/crc.h"
#include "net/conn.h"

#define CLIENT_ID "buckets"
#define TIMEOUT_MS 5000         /* Net.Dial/Read/WriteTimeout */
#define METADATA_REFRESH_S 900  /* Metadata.RefreshFrequency */
#define RETRY_MAX 2             /* Producer.Retry.Max */
#define MAX_BROKERS 64
#define MAX_TOPICS 256

enum { API_PRODUCE = 0, API_METADATA = 3, API_SASL_HANDSHAKE = 17, API_API_VERSIONS = 18, API_SASL_AUTHENTICATE = 36 };

typedef struct {
  int32_t id;
  char host[256];
  int port;
  buckets_conn *conn;
} broker;

typedef struct {
  char *name;
  int32_t npart;
  int32_t *leaders; /* per partition */
} topic;

struct buckets_kafka {
  char **seeds;
  size_t nseeds;
  int ver[4];
  bool tls, skip_verify, sasl;
  char *ca_dir, *cert, *key, *user, *pass, *mech, *compression;
  int level, timeout_ms, backoff_ms;
  broker brokers[MAX_BROKERS];
  size_t nbrokers;
  broker seed; /* the connection metadata is asked through */
  topic topics[MAX_TOPICS];
  size_t ntopics;
  int32_t corr;
  time_t last_refresh;
  bool warned_codec;
};

/* ---- versions ------------------------------------------------------------------------ */

bool buckets_kafka_parse_version(const char *s, int v[4], char *err, size_t errlen) {
  int n[4] = {0}, k = 0;
  const char *p = s;
  if (strlen(s) < 5) goto bad;
  while (*p && k < 4) {
    if (*p < '0' || *p > '9') goto bad;
    n[k++] = (int)strtol(p, (char **)&p, 10);
    if (*p == '.') p++;
    else if (*p) goto bad;
  }
  if (*p || (n[0] == 0 && k != 4) || (n[0] > 0 && k != 3)) goto bad;
  if (n[0] > 0) v[0] = n[0], v[1] = n[1], v[2] = n[2], v[3] = 0;
  else memcpy(v, n, sizeof(n));
  return true;
bad:
  snprintf(err, errlen, "invalid version `%s`", s);
  return false;
}

static bool at_least(const buckets_kafka *k, int a, int b, int c, int d) {
  int w[4] = {a, b, c, d};
  for (int i = 0; i < 4; i++) {
    if (k->ver[i] != w[i]) return k->ver[i] > w[i];
  }
  return true;
}

static int metadata_version(const buckets_kafka *k) {
  if (at_least(k, 2, 8, 0, 0)) return 10;
  if (at_least(k, 2, 4, 0, 0)) return 9;
  if (at_least(k, 2, 1, 0, 0)) return 7;
  if (at_least(k, 2, 0, 0, 0)) return 6;
  if (at_least(k, 1, 0, 0, 0)) return 5;
  return 4;
}

static int produce_version(const buckets_kafka *k) {
  if (at_least(k, 2, 1, 0, 0)) return 7;
  if (at_least(k, 2, 0, 0, 0)) return 6;
  if (at_least(k, 1, 0, 0, 0)) return 5;
  return 3;
}

/* ---- encoding -------------------------------------------------------------------------- */

static void e8(buckets_buf *b, uint8_t v) { buckets_buf_append(b, &v, 1); }
static void e16(buckets_buf *b, uint16_t v) {
  uint8_t x[2] = {(uint8_t)(v >> 8), (uint8_t)v};
  buckets_buf_append(b, x, 2);
}
static void e32(buckets_buf *b, uint32_t v) {
  uint8_t x[4] = {(uint8_t)(v >> 24), (uint8_t)(v >> 16), (uint8_t)(v >> 8), (uint8_t)v};
  buckets_buf_append(b, x, 4);
}
static void e64(buckets_buf *b, uint64_t v) {
  e32(b, (uint32_t)(v >> 32));
  e32(b, (uint32_t)v);
}
static void estr(buckets_buf *b, const char *s) {
  size_t n = strlen(s);
  e16(b, (uint16_t)n);
  buckets_buf_append(b, s, n);
}
static void euvar(buckets_buf *b, uint64_t v) {
  while (v >= 0x80) {
    e8(b, (uint8_t)(v | 0x80));
    v >>= 7;
  }
  e8(b, (uint8_t)v);
}
static void evar(buckets_buf *b, int64_t v) { euvar(b, ((uint64_t)v << 1) ^ (uint64_t)(v >> 63)); } /* zigzag */
static void ecstr(buckets_buf *b, const char *s) { /* compact string */
  size_t n = strlen(s);
  euvar(b, n + 1);
  buckets_buf_append(b, s, n);
}

typedef struct {
  const uint8_t *p;
  size_t n;
  bool bad;
} dec;

static const uint8_t *take(dec *d, size_t n) {
  if (d->bad || d->n < n) {
    d->bad = true;
    return NULL;
  }
  const uint8_t *p = d->p;
  d->p += n, d->n -= n;
  return p;
}
static int8_t d8(dec *d) {
  const uint8_t *p = take(d, 1);
  return p ? (int8_t)p[0] : 0;
}
static int16_t d16(dec *d) {
  const uint8_t *p = take(d, 2);
  return p ? (int16_t)(p[0] << 8 | p[1]) : 0;
}
static int32_t d32(dec *d) {
  const uint8_t *p = take(d, 4);
  return p ? (int32_t)((uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3]) : 0;
}
static int64_t d64(dec *d) {
  int64_t hi = (uint32_t)d32(d), lo = (uint32_t)d32(d);
  return (int64_t)((uint64_t)hi << 32 | (uint64_t)lo);
}
static uint64_t duvar(dec *d) {
  uint64_t v = 0;
  for (int s = 0; s < 64; s += 7) {
    int8_t b = d8(d);
    v |= (uint64_t)(b & 0x7f) << s;
    if (!(b & 0x80) || d->bad) break;
  }
  return v;
}
/* A string (int16 length, or compact); NULL for null. Malloc'd. */
static char *dstr(dec *d, bool compact) {
  int64_t n = compact ? (int64_t)duvar(d) - 1 : d16(d);
  if (n < 0) return NULL;
  const uint8_t *p = take(d, (size_t)n);
  return p ? buckets_xstrndup((const char *)p, (size_t)n) : NULL;
}
static int32_t darr(dec *d, bool compact) { return compact ? (int32_t)duvar(d) - 1 : d32(d); }
static void dtags(dec *d) { /* tagged fields: skipped */
  uint64_t n = duvar(d);
  for (uint64_t i = 0; i < n && !d->bad; i++) {
    duvar(d);
    take(d, (size_t)duvar(d));
  }
}

/* ---- connections ------------------------------------------------------------------------- */

static void bdrop(broker *b) {
  buckets_conn_close(b->conn);
  b->conn = NULL;
}

/* One request/response; flexible requests use header v2 (response header
 * v1, except ApiVersions' which stays v0). */
static bool roundtrip(buckets_kafka *k, broker *b, int16_t api, int16_t ver, bool flexible, const buckets_buf *body,
                      buckets_buf *resp) {
  buckets_buf m = BUCKETS_BUF_INIT;
  e32(&m, 0);
  e16(&m, (uint16_t)api);
  e16(&m, (uint16_t)ver);
  int32_t corr = k->corr++;
  e32(&m, (uint32_t)corr);
  estr(&m, CLIENT_ID);
  if (flexible) e8(&m, 0); /* no tagged fields */
  buckets_buf_append(&m, body->data, body->len);
  uint32_t len = (uint32_t)(m.len - 4);
  uint8_t *p = (uint8_t *)m.data;
  p[0] = (uint8_t)(len >> 24), p[1] = (uint8_t)(len >> 16), p[2] = (uint8_t)(len >> 8), p[3] = (uint8_t)len;
  bool ok = buckets_conn_write(b->conn, m.data, m.len);
  buckets_buf_free(&m);
  uint8_t h[4];
  if (!ok || !buckets_conn_read_full(b->conn, h, 4)) {
    bdrop(b);
    return false;
  }
  uint32_t n = (uint32_t)h[0] << 24 | (uint32_t)h[1] << 16 | (uint32_t)h[2] << 8 | h[3];
  if (n < 4 || n > (64u << 20)) {
    bdrop(b);
    return false;
  }
  buckets_buf_reset(resp);
  buckets_buf_reserve(resp, n);
  if (!buckets_conn_read_full(b->conn, resp->data, n)) {
    bdrop(b);
    return false;
  }
  resp->len = n;
  dec d = {(const uint8_t *)resp->data, n, false};
  if (d32(&d) != corr) {
    bdrop(b);
    return false;
  }
  size_t skip = 4;
  if (flexible && api != API_API_VERSIONS) {
    dtags(&d);
    skip = (size_t)(d.p - (const uint8_t *)resp->data);
  }
  memmove(resp->data, resp->data + skip, n - skip);
  resp->len = n - skip;
  return true;
}

/* ---- SASL -------------------------------------------------------------------------------- */

static const char *kerror(int code) {
  switch (code) {
  case 3: return "kafka server: Request was for a topic or partition that does not exist on this broker";
  case 5: return "kafka server: In the middle of a leadership election, there is currently no leader for this partition and hence it is unavailable for writes";
  case 6: return "kafka server: Tried to send a message to a replica that is not the leader for some partition. Your metadata is out of date";
  case 7: return "kafka server: Request exceeded the user-specified time limit in the request";
  case 10: return "kafka server: Message was too large, server rejected it to avoid allocation error";
  case 17: return "kafka server: The request attempted to perform an operation on an invalid topic";
  case 29: return "kafka server: The client is not authorized to access this topic";
  case 33: return "kafka server: The broker does not support the requested SASL mechanism";
  case 34: return "kafka server: Request is not valid given the current SASL state";
  case 58: return "kafka server: SASL Authentication failed";
  default: return NULL;
  }
}

static void kerr(int code, char *err, size_t errlen) {
  const char *s = kerror(code);
  if (s) snprintf(err, errlen, "%s", s);
  else snprintf(err, errlen, "kafka server: Unexpected (unknown?) server error (code %d)", code);
}

/* SaslAuthenticate: one exchange of auth bytes. */
static bool sasl_authenticate(buckets_kafka *k, broker *b, const void *out, size_t n, buckets_buf *in, char *err,
                              size_t errlen) {
  int16_t ver = at_least(k, 2, 2, 0, 0) ? 1 : 0;
  buckets_buf body = BUCKETS_BUF_INIT, resp = BUCKETS_BUF_INIT;
  e32(&body, (uint32_t)n);
  buckets_buf_append(&body, out, n);
  bool ok = roundtrip(k, b, API_SASL_AUTHENTICATE, ver, false, &body, &resp);
  if (!ok) snprintf(err, errlen, "EOF");
  if (ok) {
    dec d = {(const uint8_t *)resp.data, resp.len, false};
    int16_t code = d16(&d);
    char *msg = dstr(&d, false);
    int32_t al = d32(&d);
    const uint8_t *ab = al > 0 ? take(&d, (size_t)al) : NULL;
    if (code) {
      if (msg && *msg) snprintf(err, errlen, "%s: %s", kerror(code) ? kerror(code) : "kafka server: error", msg);
      else kerr(code, err, errlen);
      ok = false;
    } else {
      buckets_buf_reset(in);
      if (ab) buckets_buf_append(in, ab, (size_t)al);
    }
    free(msg);
  }
  buckets_buf_free(&body);
  buckets_buf_free(&resp);
  return ok;
}

static bool scram(buckets_kafka *k, broker *b, const EVP_MD *md, char *err, size_t errlen) {
  size_t hl = (size_t)EVP_MD_get_size(md);
  uint8_t raw[24];
  RAND_bytes(raw, sizeof(raw));
  char nonce[40];
  buckets_base64_encode(raw, sizeof(raw), nonce);
  buckets_buf bare = BUCKETS_BUF_INIT, in = BUCKETS_BUF_INIT, first = BUCKETS_BUF_INIT, fin = BUCKETS_BUF_INIT;
  buckets_buf_append_c(&bare, "n=");
  for (const char *c = k->user; *c; c++) {
    if (*c == '=') buckets_buf_append_c(&bare, "=3D");
    else if (*c == ',') buckets_buf_append_c(&bare, "=2C");
    else buckets_buf_append(&bare, c, 1);
  }
  buckets_buf_appendf(&bare, ",r=%s", nonce);
  buckets_buf_appendf(&first, "n,,%s", bare.data);
  bool ok = sasl_authenticate(k, b, first.data, first.len, &in, err, errlen);
  if (ok) {
    char sf[1024];
    snprintf(sf, sizeof(sf), "%.*s", (int)in.len, in.data ? in.data : "");
    char *r = strstr(sf, "r="), *s = strstr(sf, ",s="), *i = strstr(sf, ",i=");
    if (!r || !s || !i || strncmp(r + 2, nonce, strlen(nonce)) != 0) {
      snprintf(err, errlen, "kafka: invalid SCRAM server message");
      ok = false;
    } else {
      char snonce[256], salt64[256];
      snprintf(snonce, sizeof(snonce), "%.*s", (int)(s - r - 2), r + 2);
      snprintf(salt64, sizeof(salt64), "%.*s", (int)(i - s - 3), s + 3);
      uint8_t salt[192], salted[64], ckey[64], stored[64], csig[64], proof[64], skey[64], ssig[64];
      long sl = buckets_base64_decode(salt64, strlen(salt64), salt);
      unsigned int ol;
      PKCS5_PBKDF2_HMAC(k->pass, (int)strlen(k->pass), salt, (int)(sl > 0 ? sl : 0), atoi(i + 3), md, (int)hl, salted);
      HMAC(md, salted, (int)hl, (const uint8_t *)"Client Key", 10, ckey, &ol);
      EVP_Digest(ckey, hl, stored, &ol, md, NULL);
      buckets_buf auth = BUCKETS_BUF_INIT;
      buckets_buf_appendf(&auth, "%s,%s,c=biws,r=%s", bare.data, sf, snonce);
      HMAC(md, stored, (int)hl, (const uint8_t *)auth.data, auth.len, csig, &ol);
      for (size_t j = 0; j < hl; j++) proof[j] = ckey[j] ^ csig[j];
      char proof64[100];
      buckets_base64_encode(proof, hl, proof64);
      buckets_buf_appendf(&fin, "c=biws,r=%s,p=%s", snonce, proof64);
      ok = sasl_authenticate(k, b, fin.data, fin.len, &in, err, errlen);
      if (ok) {
        HMAC(md, salted, (int)hl, (const uint8_t *)"Server Key", 10, skey, &ol);
        HMAC(md, skey, (int)hl, (const uint8_t *)auth.data, auth.len, ssig, &ol);
        char ssig64[100], want[110];
        buckets_base64_encode(ssig, hl, ssig64);
        snprintf(want, sizeof(want), "v=%s", ssig64);
        if (in.len < strlen(want) || strncmp(in.data, want, strlen(want)) != 0) {
          snprintf(err, errlen, "kafka: invalid SCRAM server signature");
          ok = false;
        }
      }
      buckets_buf_free(&auth);
    }
  }
  buckets_buf_free(&bare), buckets_buf_free(&in), buckets_buf_free(&first), buckets_buf_free(&fin);
  return ok;
}

static bool sasl(buckets_kafka *k, broker *b, char *err, size_t errlen) {
  const char *mech = !strcasecmp(k->mech, "sha512") ? "SCRAM-SHA-512" : !strcasecmp(k->mech, "sha256") ? "SCRAM-SHA-256" : "PLAIN";
  buckets_buf body = BUCKETS_BUF_INIT, resp = BUCKETS_BUF_INIT;
  estr(&body, mech);
  bool ok = roundtrip(k, b, API_SASL_HANDSHAKE, 1, false, &body, &resp);
  if (!ok) snprintf(err, errlen, "EOF");
  else {
    dec d = {(const uint8_t *)resp.data, resp.len, false};
    int16_t code = d16(&d);
    if (code) {
      kerr(code, err, errlen);
      ok = false;
    }
  }
  buckets_buf_free(&body);
  buckets_buf_free(&resp);
  if (!ok) return false;
  if (!strcmp(mech, "PLAIN")) {
    buckets_buf tok = BUCKETS_BUF_INIT, in = BUCKETS_BUF_INIT;
    e8(&tok, 0);
    buckets_buf_append_c(&tok, k->user);
    e8(&tok, 0);
    buckets_buf_append_c(&tok, k->pass);
    ok = sasl_authenticate(k, b, tok.data, tok.len, &in, err, errlen);
    buckets_buf_free(&tok);
    buckets_buf_free(&in);
    return ok;
  }
  return scram(k, b, !strcmp(mech, "SCRAM-SHA-512") ? EVP_sha512() : EVP_sha256(), err, errlen);
}

/* Broker.Open: dial, TLS, SASL, ApiVersions (2.4 and later). */
static bool bopen(buckets_kafka *k, broker *b, char *err, size_t errlen) {
  if (b->conn && !buckets_conn_broken(b->conn)) return true;
  bdrop(b);
  b->conn = buckets_conn_dial(b->host, b->port, NULL, k->timeout_ms, err, errlen);
  if (!b->conn) return false;
  if (k->tls) {
    buckets_tls_client *tc = buckets_tls_client_new(k->ca_dir, err, errlen);
    if (tc && k->skip_verify) buckets_tls_client_skip_verify(tc);
    if (tc && *k->cert && *k->key) buckets_tls_client_use_cert(tc, k->cert, k->key, err, errlen);
    bool ok = tc && buckets_conn_start_tls(b->conn, tc, b->host);
    buckets_tls_client_free(tc);
    if (!ok) {
      snprintf(err, errlen, "tls: failed to verify certificate");
      bdrop(b);
      return false;
    }
  }
  if (k->sasl && !sasl(k, b, err, errlen)) {
    bdrop(b);
    return false;
  }
  if (at_least(k, 2, 4, 0, 0) && b != &k->seed) { /* ApiVersions v3 (not on the seed connection, as in sarama) */
    buckets_buf body = BUCKETS_BUF_INIT, resp = BUCKETS_BUF_INIT;
    ecstr(&body, "buckets");
    ecstr(&body, BUCKETS_VERSION);
    e8(&body, 0);
    bool ok = roundtrip(k, b, API_API_VERSIONS, 3, true, &body, &resp);
    buckets_buf_free(&body);
    buckets_buf_free(&resp);
    if (!ok) {
      snprintf(err, errlen, "EOF");
      return false;
    }
  }
  return true;
}

/* ---- metadata ------------------------------------------------------------------------------ */

static topic *find_topic(buckets_kafka *k, const char *name) {
  for (size_t i = 0; i < k->ntopics; i++)
    if (!strcmp(k->topics[i].name, name)) return &k->topics[i];
  return NULL;
}

/* A Metadata request (all topics when topic is NULL) and its brokers and
 * topics taken in. */
static bool metadata(buckets_kafka *k, broker *b, const char *topic_name, char *err, size_t errlen) {
  int v = metadata_version(k);
  bool flex = v >= 9;
  buckets_buf body = BUCKETS_BUF_INIT, resp = BUCKETS_BUF_INIT;
  if (!topic_name) {
    if (flex) euvar(&body, 0); /* null compact array */
    else e32(&body, 0xffffffff);
  } else if (flex) {
    euvar(&body, 2);
    if (v >= 10) {
      uint8_t zero[16] = {0};
      buckets_buf_append(&body, zero, 16);
    }
    ecstr(&body, topic_name);
    e8(&body, 0);
  } else {
    e32(&body, 1);
    estr(&body, topic_name);
  }
  e8(&body, topic_name ? 1 : 0); /* allow_auto_topic_creation: not on full refreshes */
  if (v >= 8) e8(&body, 0), e8(&body, 0);
  if (flex) e8(&body, 0);
  bool ok = roundtrip(k, b, API_METADATA, (int16_t)v, flex, &body, &resp);
  buckets_buf_free(&body);
  if (!ok) {
    snprintf(err, errlen, "EOF");
    buckets_buf_free(&resp);
    return false;
  }
  dec d = {(const uint8_t *)resp.data, resp.len, false};
  d32(&d); /* throttle */
  int32_t nb = darr(&d, flex);
  broker nbk[MAX_BROKERS];
  size_t nn = 0;
  for (int32_t i = 0; i < nb && !d.bad; i++) {
    int32_t id = d32(&d);
    char *host = dstr(&d, flex);
    int32_t port = d32(&d);
    free(dstr(&d, flex)); /* rack */
    if (flex) dtags(&d);
    if (nn < MAX_BROKERS && host) {
      nbk[nn] = (broker){.id = id, .port = port};
      snprintf(nbk[nn].host, sizeof(nbk[nn].host), "%s", host);
      nn++;
    }
    free(host);
  }
  free(dstr(&d, flex)); /* cluster id */
  d32(&d);              /* controller */
  int32_t nt = darr(&d, flex);
  for (int32_t i = 0; i < nt && !d.bad; i++) {
    int16_t terr = d16(&d);
    char *name = dstr(&d, flex);
    if (v >= 10) take(&d, 16);
    d8(&d); /* internal */
    int32_t np = darr(&d, flex);
    int32_t *leaders = np > 0 ? buckets_xcalloc((size_t)np, sizeof(int32_t)) : NULL;
    for (int32_t j = 0; j < np && !d.bad; j++) {
      d16(&d);
      int32_t idx = d32(&d), leader = d32(&d);
      if (v >= 7) d32(&d);
      for (int arr = 0; arr < (v >= 5 ? 3 : 2); arr++) {
        int32_t c = darr(&d, flex);
        for (int32_t q = 0; q < c && !d.bad; q++) d32(&d);
      }
      if (flex) dtags(&d);
      if (idx >= 0 && idx < np) leaders[idx] = leader;
    }
    if (v >= 8) d32(&d);
    if (flex) dtags(&d);
    if (name && !terr && np > 0) {
      topic *t = find_topic(k, name);
      if (!t && k->ntopics < MAX_TOPICS) t = &k->topics[k->ntopics++], t->name = buckets_xstrdup(name), t->leaders = NULL;
      if (t) {
        free(t->leaders);
        t->leaders = leaders, t->npart = np;
        leaders = NULL;
      }
    }
    free(leaders);
    free(name);
  }
  buckets_buf_free(&resp);
  if (d.bad) {
    snprintf(err, errlen, "kafka: insufficient data to decode packet, more bytes expected");
    return false;
  }
  /* registerBroker: keep open connections to brokers still listed */
  for (size_t i = 0; i < nn; i++) {
    for (size_t j = 0; j < k->nbrokers; j++) {
      if (k->brokers[j].id == nbk[i].id && !strcmp(k->brokers[j].host, nbk[i].host) && k->brokers[j].port == nbk[i].port) {
        nbk[i].conn = k->brokers[j].conn;
        k->brokers[j].conn = NULL;
      }
    }
  }
  for (size_t j = 0; j < k->nbrokers; j++) bdrop(&k->brokers[j]);
  memcpy(k->brokers, nbk, nn * sizeof(broker));
  k->nbrokers = nn;
  k->last_refresh = time(NULL);
  return true;
}

/* Metadata through the seed connection, else any known broker. */
static bool refresh(buckets_kafka *k, const char *topic_name, char *err, size_t errlen) {
  if (bopen(k, &k->seed, err, errlen) && metadata(k, &k->seed, topic_name, err, errlen)) return true;
  for (size_t s = 0; s < k->nseeds; s++) {
    char host[256];
    const char *colon = strrchr(k->seeds[s], ':');
    snprintf(host, sizeof(host), "%.*s", colon ? (int)(colon - k->seeds[s]) : (int)strlen(k->seeds[s]), k->seeds[s]);
    if (host[0] == '[') memmove(host, host + 1, strlen(host)), host[strlen(host) - 1] = '\0';
    bdrop(&k->seed);
    k->seed = (broker){.id = -1, .port = colon ? atoi(colon + 1) : 9092};
    snprintf(k->seed.host, sizeof(k->seed.host), "%s", host);
    char e[256];
    if (bopen(k, &k->seed, e, sizeof(e)) && metadata(k, &k->seed, topic_name, e, sizeof(e))) return true;
    snprintf(err, errlen, "%s", e);
  }
  char last[300];
  snprintf(last, sizeof(last), "%s", err);
  snprintf(err, errlen, "kafka: client has run out of available brokers to talk to: %s", last);
  return false;
}

/* ---- produce ------------------------------------------------------------------------------ */

static void fnv1a(const char *p, size_t n, uint32_t *h) {
  *h = 2166136261u;
  for (size_t i = 0; i < n; i++) *h = (*h ^ (uint8_t)p[i]) * 16777619u;
}

/* A snappy block (raw format), greedy with a 4-byte hash. */
static void snappy_encode(const uint8_t *src, size_t n, buckets_buf *out) {
  buckets_buf_reset(out);
  euvar(out, n);
  uint32_t table[1 << 14];
  memset(table, 0xff, sizeof(table));
  size_t lit = 0, i = 0;
#define EMIT_LITERAL(from, len)                                                                \
  do {                                                                                         \
    size_t l_ = (len);                                                                         \
    if (l_) {                                                                                  \
      if (l_ <= 60) e8(out, (uint8_t)((l_ - 1) << 2));                                         \
      else if (l_ <= 256) e8(out, 60 << 2), e8(out, (uint8_t)(l_ - 1));                        \
      else if (l_ <= 65536) e8(out, 61 << 2), e8(out, (uint8_t)(l_ - 1)), e8(out, (uint8_t)((l_ - 1) >> 8)); \
      else e8(out, 62 << 2), e8(out, (uint8_t)(l_ - 1)), e8(out, (uint8_t)((l_ - 1) >> 8)), e8(out, (uint8_t)((l_ - 1) >> 16)); \
      buckets_buf_append(out, src + (from), l_);                                               \
    }                                                                                          \
  } while (0)
  while (i + 4 <= n) {
    uint32_t v;
    memcpy(&v, src + i, 4);
    uint32_t h = (v * 0x1e35a7bdu) >> 18;
    uint32_t cand = table[h];
    table[h] = (uint32_t)i;
    if (cand != 0xffffffffu && i - cand <= 65535 && !memcmp(src + cand, src + i, 4)) {
      size_t len = 4;
      while (i + len < n && src[cand + len] == src[i + len]) len++;
      EMIT_LITERAL(lit, i - lit);
      size_t off = i - cand, left = len;
      while (left > 0) { /* copies with 2-byte offsets, at most 64 bytes each */
        size_t c = left > 64 ? 64 : left;
        if (left > 64 && left - 64 < 4) c = 60;
        e8(out, (uint8_t)(((c - 1) << 2) | 2));
        e8(out, (uint8_t)off);
        e8(out, (uint8_t)(off >> 8));
        left -= c;
      }
      i += len;
      lit = i;
    } else {
      i++;
    }
  }
  EMIT_LITERAL(lit, n - lit);
#undef EMIT_LITERAL
}

/* A record batch (magic 2) of msgs, as sarama's produceSet builds it. */
static void record_batch(buckets_kafka *k, const buckets_kafka_msg *msgs, size_t n, buckets_buf *out) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  int64_t now_ms = (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
  buckets_buf recs = BUCKETS_BUF_INIT;
  for (size_t i = 0; i < n; i++) {
    buckets_buf r = BUCKETS_BUF_INIT;
    e8(&r, 0);          /* attributes */
    evar(&r, 0);        /* timestamp delta */
    evar(&r, (int64_t)i); /* offset delta */
    if (!msgs[i].key) evar(&r, -1); /* a null key */
    else {
      evar(&r, (int64_t)msgs[i].klen);
      buckets_buf_append(&r, msgs[i].key, msgs[i].klen);
    }
    evar(&r, (int64_t)msgs[i].vlen);
    buckets_buf_append(&r, msgs[i].value, msgs[i].vlen);
    evar(&r, 0); /* headers */
    evar(&recs, (int64_t)r.len);
    buckets_buf_append(&recs, r.data, r.len);
    buckets_buf_free(&r);
  }
  int codec = 0;
  const char *c = k->compression;
  buckets_buf packed = BUCKETS_BUF_INIT;
  if (!strcasecmp(c, "gzip")) {
    int level = k->level < 0 ? 6 : k->level > 9 ? 9 : k->level; /* gzip.NewWriterLevel */
    struct libdeflate_compressor *z = libdeflate_alloc_compressor(level);
    size_t bound = libdeflate_gzip_compress_bound(z, recs.len);
    buckets_buf_reserve(&packed, bound);
    packed.len = libdeflate_gzip_compress(z, recs.data, recs.len, packed.data, bound);
    libdeflate_free_compressor(z);
    if (packed.len) codec = 1;
  } else if (!strcasecmp(c, "snappy")) {
    snappy_encode((const uint8_t *)recs.data, recs.len, &packed);
    codec = 2;
  } else if ((!strcasecmp(c, "lz4") || !strcasecmp(c, "zstd")) && !k->warned_codec) {
    buckets_log_warn("kafka: %s compression is not supported; sending uncompressed", c);
    k->warned_codec = true;
  }
  buckets_buf b = BUCKETS_BUF_INIT;
  e64(&b, 0);          /* first offset */
  e32(&b, 0);          /* length, below */
  e32(&b, 0);          /* partition leader epoch */
  e8(&b, 2);           /* magic */
  e32(&b, 0);          /* crc, below */
  size_t crc_from = b.len;
  e16(&b, (uint16_t)codec);
  e32(&b, (uint32_t)(n - 1)); /* last offset delta */
  e64(&b, (uint64_t)now_ms);  /* first timestamp */
  e64(&b, (uint64_t)now_ms);  /* max timestamp */
  e64(&b, (uint64_t)-1);      /* producer id */
  e16(&b, (uint16_t)-1);      /* producer epoch */
  e32(&b, 0);                 /* first sequence */
  e32(&b, (uint32_t)n);
  if (codec) buckets_buf_append(&b, packed.data, packed.len);
  else buckets_buf_append(&b, recs.data, recs.len);
  uint8_t *p = (uint8_t *)b.data;
  uint32_t len = (uint32_t)(b.len - 12), crc = buckets_crc32c(0, p + crc_from, b.len - crc_from);
  p[8] = (uint8_t)(len >> 24), p[9] = (uint8_t)(len >> 16), p[10] = (uint8_t)(len >> 8), p[11] = (uint8_t)len;
  p[17] = (uint8_t)(crc >> 24), p[18] = (uint8_t)(crc >> 16), p[19] = (uint8_t)(crc >> 8), p[20] = (uint8_t)crc;
  buckets_buf_reset(out);
  buckets_buf_append(out, b.data, b.len);
  buckets_buf_free(&b);
  buckets_buf_free(&recs);
  buckets_buf_free(&packed);
}

static broker *leader_broker(buckets_kafka *k, int32_t id) {
  for (size_t i = 0; i < k->nbrokers; i++)
    if (k->brokers[i].id == id) return &k->brokers[i];
  return NULL;
}

static bool retriable(int code) { return code == 3 || code == 5 || code == 6 || code == 7 || code == 19 || code == 20; }

int buckets_kafka_send(buckets_kafka *k, const char *topic_name, const buckets_kafka_msg *msgs, size_t n, char *err,
                       size_t errlen) {
  if (!n) return 0;
  for (int attempt = 0; attempt <= RETRY_MAX; attempt++) {
    if (attempt) {
      struct timespec w = {k->backoff_ms / 1000, (long)(k->backoff_ms % 1000) * 1000000L}; /* Producer.Retry.Backoff */
      nanosleep(&w, NULL);
      if (!refresh(k, topic_name, err, errlen)) return 1;
    }
    topic *t = find_topic(k, topic_name);
    if (!t && !refresh(k, topic_name, err, errlen)) return 1;
    t = find_topic(k, topic_name);
    if (!t) {
      kerr(3, err, errlen);
      continue;
    }
    /* every message goes to its key's partition; each partition in one request */
    int32_t *chosen = buckets_xcalloc(n, sizeof(int32_t));
    int result = 0;
    bool retry = false;
    for (int32_t part = 0; part < t->npart && !retry; part++) {
      buckets_kafka_msg *sel = buckets_xcalloc(n, sizeof(*sel));
      size_t ns = 0;
      for (size_t i = 0; i < n; i++) {
        int32_t p;
        if (!msgs[i].key) { /* the random partitioner, fixed per call */
          if (!chosen[i]) {
            uint32_t r;
            RAND_bytes((uint8_t *)&r, sizeof(r));
            chosen[i] = 1 + (int32_t)(r % (uint32_t)t->npart);
          }
          p = chosen[i] - 1;
        } else {
          uint32_t h;
          fnv1a(msgs[i].key, msgs[i].klen, &h);
          p = (int32_t)h % t->npart;
          if (p < 0) p = -p;
        }
        if (p == part) sel[ns++] = msgs[i];
      }
      if (!ns) {
        free(sel);
        continue;
      }
      broker *b = leader_broker(k, t->leaders[part]);
      if (!b || !bopen(k, b, err, errlen)) {
        free(sel);
        if (!b) kerr(5, err, errlen);
        retry = true;
        result = 1;
        break;
      }
      buckets_buf batch = BUCKETS_BUF_INIT, body = BUCKETS_BUF_INIT, resp = BUCKETS_BUF_INIT;
      record_batch(k, sel, ns, &batch);
      free(sel);
      e16(&body, 0xffff); /* transactional id: null */
      e16(&body, 1);      /* acks */
      e32(&body, (uint32_t)k->timeout_ms);
      e32(&body, 1);
      estr(&body, topic_name);
      e32(&body, 1);
      e32(&body, (uint32_t)part);
      e32(&body, (uint32_t)batch.len);
      buckets_buf_append(&body, batch.data, batch.len);
      bool ok = roundtrip(k, b, API_PRODUCE, (int16_t)produce_version(k), false, &body, &resp);
      if (!ok) {
        snprintf(err, errlen, "EOF");
        retry = true;
        result = 1;
      } else {
        dec d = {(const uint8_t *)resp.data, resp.len, false};
        int32_t ntp = d32(&d);
        for (int32_t i = 0; i < ntp && !d.bad; i++) {
          free(dstr(&d, false));
          int32_t npp = d32(&d);
          for (int32_t j = 0; j < npp && !d.bad; j++) {
            d32(&d);
            int16_t code = d16(&d);
            d64(&d);
            d64(&d);                                   /* log append time */
            if (produce_version(k) >= 5) d64(&d);       /* log start offset */
            if (code) {
              kerr(code, err, errlen);
              result = 2;
              if (retriable(code)) retry = true;
            }
          }
        }
      }
      buckets_buf_free(&batch), buckets_buf_free(&body), buckets_buf_free(&resp);
      if (result && !retry) break;
    }
    free(chosen);
    if (!retry) return result;
    if (attempt == RETRY_MAX) return result ? result : 2;
  }
  return 2;
}

/* ---- lifecycle ------------------------------------------------------------------------------ */

buckets_kafka *buckets_kafka_new(const buckets_kafka_cfg *cfg) {
  buckets_kafka *k = buckets_xcalloc(1, sizeof(*k));
  k->seeds = buckets_xcalloc(cfg->nbrokers ? cfg->nbrokers : 1, sizeof(char *));
  for (size_t i = 0; i < cfg->nbrokers; i++) k->seeds[i] = buckets_xstrdup(cfg->brokers[i]);
  k->nseeds = cfg->nbrokers;
  char err[128];
  if (!cfg->version || !*cfg->version || !buckets_kafka_parse_version(cfg->version, k->ver, err, sizeof(err)))
    k->ver[0] = 2, k->ver[1] = 1, k->ver[2] = 0, k->ver[3] = 0;
  k->tls = cfg->tls, k->skip_verify = cfg->tls_skip_verify, k->sasl = cfg->sasl;
  k->ca_dir = cfg->ca_dir ? buckets_xstrdup(cfg->ca_dir) : NULL;
  k->cert = buckets_xstrdup(cfg->client_cert ? cfg->client_cert : "");
  k->key = buckets_xstrdup(cfg->client_key ? cfg->client_key : "");
  k->user = buckets_xstrdup(cfg->sasl_user ? cfg->sasl_user : "");
  k->pass = buckets_xstrdup(cfg->sasl_pass ? cfg->sasl_pass : "");
  k->mech = buckets_xstrdup(cfg->sasl_mechanism ? cfg->sasl_mechanism : "");
  k->compression = buckets_xstrdup(cfg->compression ? cfg->compression : "");
  k->level = cfg->compression_level;
  k->timeout_ms = cfg->timeout_ms > 0 ? cfg->timeout_ms : TIMEOUT_MS;
  k->backoff_ms = cfg->retry_backoff_ms > 0 ? cfg->retry_backoff_ms : 1000;
  k->seed.id = -1;
  return k;
}

void buckets_kafka_free(buckets_kafka *k) {
  if (!k) return;
  bdrop(&k->seed);
  for (size_t i = 0; i < k->nbrokers; i++) bdrop(&k->brokers[i]);
  for (size_t i = 0; i < k->ntopics; i++) free(k->topics[i].name), free(k->topics[i].leaders);
  for (size_t i = 0; i < k->nseeds; i++) free(k->seeds[i]);
  free(k->seeds);
  free(k->ca_dir), free(k->cert), free(k->key), free(k->user), free(k->pass), free(k->mech), free(k->compression);
  free(k);
}

bool buckets_kafka_connect(buckets_kafka *k, char *err, size_t errlen) {
  k->seed.conn = NULL;
  k->seed.host[0] = '\0'; /* start from the first seed */
  return refresh(k, NULL, err, errlen);
}

bool buckets_kafka_has_brokers(buckets_kafka *k) { return k->nbrokers > 0; }

void buckets_kafka_tick(buckets_kafka *k) {
  if (k->nbrokers && time(NULL) - k->last_refresh >= METADATA_REFRESH_S) {
    char err[256];
    refresh(k, NULL, err, sizeof(err));
  }
}
