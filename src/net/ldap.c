/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "net/ldap.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

/* ---- BER ------------------------------------------------------------------------------------ */

static void ber_len(buckets_buf *b, size_t n) {
  if (n < 128) {
    buckets_buf_append_char(b, (char)n);
    return;
  }
  uint8_t tmp[8];
  int k = 0;
  while (n) {
    tmp[k++] = (uint8_t)(n & 0xff);
    n >>= 8;
  }
  buckets_buf_append_char(b, (char)(0x80 | k));
  while (k) buckets_buf_append_char(b, (char)tmp[--k]);
}

static void ber_tlv(buckets_buf *b, uint8_t tag, const void *v, size_t n) {
  buckets_buf_append_char(b, (char)tag);
  ber_len(b, n);
  if (n) buckets_buf_append(b, v, n);
}

static void ber_str(buckets_buf *b, uint8_t tag, const char *s) { ber_tlv(b, tag, s, strlen(s)); }

static void ber_int(buckets_buf *b, uint8_t tag, long v) {
  uint8_t tmp[9];
  int k = 0;
  do {
    tmp[k++] = (uint8_t)(v & 0xff);
    v >>= 8;
  } while ((v != 0 && v != -1) || (k && ((tmp[k - 1] & 0x80) != 0) != (v < 0)));
  uint8_t out[9];
  for (int i = 0; i < k; i++) out[i] = tmp[k - 1 - i];
  ber_tlv(b, tag, out, (size_t)k);
}

/* Wraps inner as the contents of a constructed tag. */
static void ber_wrap(buckets_buf *b, uint8_t tag, const buckets_buf *inner) {
  ber_tlv(b, tag, inner->data ? inner->data : "", inner->len);
}

typedef struct {
  const uint8_t *p;
  size_t n;
} ber;

static bool ber_next(ber *c, uint8_t *tag, ber *val) {
  if (c->n < 2) return false;
  *tag = c->p[0];
  size_t len = c->p[1], hdr = 2;
  if (len & 0x80) {
    size_t k = len & 0x7f;
    if (k == 0 || k > 4 || c->n < 2 + k) return false;
    len = 0;
    for (size_t i = 0; i < k; i++) len = (len << 8) | c->p[2 + i];
    hdr += k;
  }
  if (c->n - hdr < len) return false;
  val->p = c->p + hdr;
  val->n = len;
  c->p += hdr + len;
  c->n -= hdr + len;
  return true;
}

static long ber_get_int(const ber *v) {
  long x = v->n && (v->p[0] & 0x80) ? -1 : 0;
  for (size_t i = 0; i < v->n && i < 8; i++) x = (x << 8) | v->p[i];
  return x;
}

static char *ber_get_str(const ber *v) { return buckets_xstrndup((const char *)v->p, v->n); }

/* ---- filters (RFC 4515, go-ldap's CompileFilter) ---------------------------------------------- */

static int hexval(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

/* A filter value with \xx escapes decoded. */
static bool unescape_value(const char *p, size_t n, buckets_buf *out) {
  buckets_buf_reset(out);
  for (size_t i = 0; i < n; i++) {
    if (p[i] != '\\') {
      buckets_buf_append_char(out, p[i]);
      continue;
    }
    if (i + 2 >= n) return false;
    int h = hexval(p[i + 1]), l = hexval(p[i + 2]);
    if (h < 0 || l < 0) return false;
    buckets_buf_append_char(out, (char)(h * 16 + l));
    i += 2;
  }
  return true;
}

static bool compile(const char **pp, buckets_buf *out, char *err, size_t errlen);

static bool compile_list(const char **pp, uint8_t tag, buckets_buf *out, char *err, size_t errlen) {
  buckets_buf inner = BUCKETS_BUF_INIT;
  bool ok = true;
  while (ok && **pp == '(') ok = compile(pp, &inner, err, errlen);
  if (ok) ber_wrap(out, tag, &inner);
  buckets_buf_free(&inner);
  return ok;
}

static bool compile_item(const char *s, size_t n, buckets_buf *out, char *err, size_t errlen) {
  /* attr op value */
  size_t i = 0;
  while (i < n && s[i] != '=' && s[i] != '~' && s[i] != '>' && s[i] != '<' && s[i] != ':') i++;
  if (i == 0 || i >= n) {
    snprintf(err, errlen, "invalid filter item: %.*s", (int)n, s);
    return false;
  }
  if (s[i] == ':') {
    snprintf(err, errlen, "extensible match filters are not supported");
    return false;
  }
  char *attr = buckets_xstrndup(s, i);
  uint8_t tag;
  size_t vstart;
  if (s[i] == '=') {
    tag = 0xA3;
    vstart = i + 1;
  } else if (i + 1 < n && s[i + 1] == '=') {
    tag = s[i] == '~' ? 0xA8 : s[i] == '>' ? 0xA5 : 0xA6;
    vstart = i + 2;
  } else {
    free(attr);
    snprintf(err, errlen, "invalid filter operator in %.*s", (int)n, s);
    return false;
  }
  const char *v = s + vstart;
  size_t vn = n - vstart;
  buckets_buf val = BUCKETS_BUF_INIT, inner = BUCKETS_BUF_INIT;
  bool ok = true;
  bool has_star = false;
  for (size_t k = 0; k < vn; k++) {
    if (v[k] == '\\') k += 2;
    else if (v[k] == '*') has_star = true;
  }
  if (tag == 0xA3 && vn == 1 && v[0] == '*') {
    ber_str(out, 0x87, attr); /* present */
  } else if (tag == 0xA3 && has_star) {
    /* substrings: initial [0], any [1], final [2] */
    buckets_buf subs = BUCKETS_BUF_INIT;
    size_t start = 0, part = 0;
    for (size_t k = 0; k <= vn && ok; k++) {
      if (k < vn && v[k] == '\\') {
        k += 2;
        continue;
      }
      if (k < vn && v[k] != '*') continue;
      bool last = k == vn;
      if (k > start) {
        ok = unescape_value(v + start, k - start, &val);
        uint8_t st = part == 0 ? 0x80 : last ? 0x82 : 0x81;
        if (ok) ber_tlv(&subs, st, val.data, val.len);
      }
      part++;
      start = k + 1;
    }
    ber_str(&inner, 0x04, attr);
    ber_wrap(&inner, 0x30, &subs);
    ber_wrap(out, 0xA4, &inner);
    buckets_buf_free(&subs);
  } else {
    ok = unescape_value(v, vn, &val);
    if (ok) {
      ber_str(&inner, 0x04, attr);
      ber_tlv(&inner, 0x04, val.data ? val.data : "", val.len);
      ber_wrap(out, tag, &inner);
    }
  }
  if (!ok) snprintf(err, errlen, "invalid escape in filter value");
  buckets_buf_free(&val);
  buckets_buf_free(&inner);
  free(attr);
  return ok;
}

static bool compile(const char **pp, buckets_buf *out, char *err, size_t errlen) {
  const char *p = *pp;
  if (*p != '(') {
    snprintf(err, errlen, "filter does not start with an '('");
    return false;
  }
  p++;
  bool ok;
  if (*p == '&' || *p == '|') {
    uint8_t tag = *p == '&' ? 0xA0 : 0xA1;
    p++;
    ok = compile_list(&p, tag, out, err, errlen);
  } else if (*p == '!') {
    p++;
    buckets_buf inner = BUCKETS_BUF_INIT;
    ok = compile(&p, &inner, err, errlen);
    if (ok) ber_wrap(out, 0xA2, &inner);
    buckets_buf_free(&inner);
  } else {
    /* An item runs to the matching ')' (escaped parens are \28 / \29). */
    const char *e = p;
    while (*e && *e != ')') {
      if (*e == '(') {
        snprintf(err, errlen, "unexpected '(' in filter");
        return false;
      }
      e++;
    }
    ok = *e == ')' && compile_item(p, (size_t)(e - p), out, err, errlen);
    if (!*e) snprintf(err, errlen, "unexpected end of filter");
    p = e;
  }
  if (ok && *p != ')') {
    snprintf(err, errlen, "unexpected end of filter");
    ok = false;
  }
  if (ok) p++;
  *pp = p;
  return ok;
}

bool buckets_ldap_compile_filter(const char *filter, buckets_buf *out, char *err, size_t errlen) {
  const char *p = filter;
  buckets_buf_reset(out);
  if (!compile(&p, out, err, errlen)) return false;
  if (*p) {
    snprintf(err, errlen, "finished compiling filter with extra at end: %s", p);
    return false;
  }
  return true;
}

char *buckets_ldap_escape_filter(const char *s) {
  static const char hx[] = "0123456789abcdef";
  buckets_buf b = BUCKETS_BUF_INIT;
  buckets_buf_append_c(&b, "");
  for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
    if (*p > 0x7f || *p == '(' || *p == ')' || *p == '\\' || *p == '*') {
      char e[3] = {'\\', hx[*p >> 4], hx[*p & 0xf]};
      buckets_buf_append(&b, e, 3);
    } else {
      buckets_buf_append_char(&b, (char)*p);
    }
  }
  return buckets_buf_detach(&b);
}

/* ---- DNs (go-ldap's ParseDN / DN.String) ------------------------------------------------------ */

/* stripLeadingAndTrailingSpaces + decodeString */
static bool decode_str(const char *s, size_t n, buckets_buf *out) {
  size_t a = 0, z = n;
  while (a < z && s[a] == ' ') a++;
  while (z > a && s[z - 1] == ' ') z--;
  if (z > a && s[z - 1] == '\\' && z < n) z++; /* keep an escaped trailing space */
  buckets_buf_reset(out);
  buckets_buf_append_c(out, "");
  for (size_t i = a; i < z; i++) {
    if (s[i] != '\\') {
      buckets_buf_append_char(out, s[i]);
      continue;
    }
    if (i + 1 >= z) return false;
    if (strchr(" \"#+,;<=>\\", s[i + 1])) {
      buckets_buf_append_char(out, s[i + 1]);
      i++;
      continue;
    }
    if (i + 2 >= z) return false;
    int h = hexval(s[i + 1]), l = hexval(s[i + 2]);
    if (h < 0 || l < 0) return false;
    buckets_buf_append_char(out, (char)(h * 16 + l));
    i += 2;
  }
  return true;
}

/* encodeString */
static void encode_str(buckets_buf *b, const char *v, size_t n, bool is_value) {
  static const char hx[] = "0123456789abcdef";
  for (size_t i = 0; i < n; i++) {
    unsigned char c = (unsigned char)v[i];
    if ((i == 0 && (c == ' ' || c == '#')) || (i == n - 1 && c == ' ') || strchr("\"+,;<>\\", c) ||
        (!is_value && c == '=')) {
      if (c) {
        buckets_buf_append_char(b, '\\');
        buckets_buf_append_char(b, (char)c);
        continue;
      }
    }
    if (c < ' ' || c > '~') {
      char e[3] = {'\\', hx[c >> 4], hx[c & 0xf]};
      buckets_buf_append(b, e, 3);
      continue;
    }
    buckets_buf_append_char(b, (char)c);
  }
}

static int cmp_str(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }

/* Parses dn into normalized RDN strings. Returns the count, or -1. */
static long parse_dn(const char *dn, char ***rdns) {
  *rdns = NULL;
  size_t len = strlen(dn);
  bool blank = true;
  for (size_t i = 0; i < len; i++) blank &= isspace((unsigned char)dn[i]) != 0;
  if (blank) return 0;
  size_t nr = 0;
  char **attrs = NULL; /* attributes of the current RDN, as "type=value" */
  size_t na = 0;
  buckets_buf type = BUCKETS_BUF_INIT, val = BUCKETS_BUF_INIT;
  bool have_type = false, escaping = false, ok = true;
  size_t start = 0;
  for (size_t i = 0; i <= len && ok; i++) {
    char c = i < len ? dn[i] : '\0';
    if (i < len) {
      if (escaping) {
        escaping = false;
        continue;
      }
      if (c == '\\') {
        escaping = true;
        continue;
      }
      if (c == '=' && !have_type) {
        ok = decode_str(dn + start, i - start, &type);
        have_type = ok && type.len > 0;
        if (ok && !have_type) have_type = false;
        start = i + 1;
        continue;
      }
      if (c != ',' && c != '+' && c != ';') continue;
    }
    /* end of an attribute (at a separator, or the end of the string) */
    if (!have_type) {
      ok = false;
      break;
    }
    const char *vs = dn + start;
    size_t vn = i - start;
    if (vn && vs[0] == '#') {
      /* hex-encoded BER value */
      buckets_buf raw = BUCKETS_BUF_INIT;
      if ((vn - 1) % 2) ok = false;
      for (size_t k = 1; k + 1 < vn && ok; k += 2) {
        int h = hexval(vs[k]), l = hexval(vs[k + 1]);
        if (h < 0 || l < 0) ok = false;
        else buckets_buf_append_char(&raw, (char)(h * 16 + l));
      }
      ber cur = {(const uint8_t *)raw.data, raw.len}, v;
      uint8_t tag;
      buckets_buf_reset(&val);
      if (ok && ber_next(&cur, &tag, &v)) buckets_buf_append(&val, v.p, v.n);
      else ok = false;
      buckets_buf_free(&raw);
    } else {
      ok = decode_str(vs, vn, &val);
    }
    if (!ok) break;
    buckets_buf a = BUCKETS_BUF_INIT;
    for (size_t k = 0; k < type.len; k++) type.data[k] = (char)tolower((unsigned char)type.data[k]);
    encode_str(&a, type.data, type.len, false);
    buckets_buf_append_char(&a, '=');
    encode_str(&a, val.data ? val.data : "", val.len, true);
    attrs = buckets_xrealloc(attrs, (na + 1) * sizeof(char *));
    attrs[na++] = buckets_buf_detach(&a);
    have_type = false;
    buckets_buf_reset(&type);
    start = i + 1;
    if (c != '+') { /* the RDN is complete */
      qsort(attrs, na, sizeof(char *), cmp_str);
      buckets_buf r = BUCKETS_BUF_INIT;
      for (size_t k = 0; k < na; k++) {
        if (k) buckets_buf_append_char(&r, '+');
        buckets_buf_append_c(&r, attrs[k]);
        free(attrs[k]);
      }
      free(attrs);
      attrs = NULL;
      na = 0;
      *rdns = buckets_xrealloc(*rdns, (nr + 1) * sizeof(char *));
      (*rdns)[nr++] = buckets_buf_detach(&r);
    }
  }
  for (size_t k = 0; k < na; k++) free(attrs[k]);
  free(attrs);
  buckets_buf_free(&type);
  buckets_buf_free(&val);
  if (!ok) {
    for (size_t k = 0; k < nr; k++) free((*rdns)[k]);
    free(*rdns);
    *rdns = NULL;
    return -1;
  }
  return (long)nr;
}

static void rdns_free(char **r, long n) {
  for (long i = 0; i < n; i++) free(r[i]);
  free(r);
}

char *buckets_ldap_normalize_dn(const char *dn) {
  char **r;
  long n = parse_dn(dn, &r);
  if (n < 0) return NULL;
  buckets_buf b = BUCKETS_BUF_INIT;
  buckets_buf_append_c(&b, "");
  for (long i = 0; i < n; i++) {
    if (i) buckets_buf_append_char(&b, ',');
    buckets_buf_append_c(&b, r[i]);
  }
  rdns_free(r, n);
  return buckets_buf_detach(&b);
}

bool buckets_ldap_dn_ancestor_of(const char *ancestor, const char *descendant) {
  char **a, **d;
  long na = parse_dn(ancestor, &a), nd = parse_dn(descendant, &d);
  bool ok = na >= 0 && nd >= 0 && na < nd;
  for (long i = 0; ok && i < na; i++) ok = strcmp(a[i], d[nd - na + i]) == 0;
  rdns_free(a, na < 0 ? 0 : na);
  rdns_free(d, nd < 0 ? 0 : nd);
  return ok;
}

char *buckets_ldap_decode_dn(const char *dn) {
  buckets_buf b = BUCKETS_BUF_INIT;
  if (!decode_str(dn, strlen(dn), &b)) {
    buckets_buf_free(&b);
    return NULL;
  }
  return buckets_buf_detach(&b);
}

/* ---- the connection ----------------------------------------------------------------------------- */

struct buckets_ldap {
  int fd;
  buckets_tls_conn *tls;
  int next_id;
  int code;
  buckets_buf in; /* received, not yet parsed */
};

int buckets_ldap_result_code(const buckets_ldap *l) { return l->code; }

static bool io_send(buckets_ldap *l, const void *p, size_t n) {
  const char *c = p;
  while (n) {
    long w = l->tls ? buckets_tls_send(l->tls, c, n) : (long)send(l->fd, c, n, 0);
    if (w <= 0) {
      if (!l->tls && w < 0 && errno == EINTR) continue;
      return false;
    }
    c += w;
    n -= (size_t)w;
  }
  return true;
}

static bool io_fill(buckets_ldap *l) {
  char tmp[16384];
  long r = l->tls ? buckets_tls_recv(l->tls, tmp, sizeof(tmp)) : (long)recv(l->fd, tmp, sizeof(tmp), 0);
  if (r <= 0) return false;
  buckets_buf_append(&l->in, tmp, (size_t)r);
  return true;
}

/* One whole LDAPMessage (the SEQUENCE contents) into msg. */
static bool read_message(buckets_ldap *l, buckets_buf *msg) {
  for (;;) {
    ber cur = {(const uint8_t *)l->in.data, l->in.len}, v;
    uint8_t tag;
    if (l->in.len >= 2 && ber_next(&cur, &tag, &v)) {
      size_t consumed = (size_t)(cur.p - (const uint8_t *)l->in.data);
      buckets_buf_reset(msg);
      buckets_buf_append(msg, v.p, v.n);
      buckets_buf_consume(&l->in, consumed);
      return tag == 0x30;
    }
    if (!io_fill(l)) return false;
  }
}

static bool send_op(buckets_ldap *l, int id, const buckets_buf *op) {
  buckets_buf body = BUCKETS_BUF_INIT, msg = BUCKETS_BUF_INIT;
  ber_int(&body, 0x02, id);
  buckets_buf_append(&body, op->data, op->len);
  ber_wrap(&msg, 0x30, &body);
  bool ok = io_send(l, msg.data, msg.len);
  buckets_buf_free(&body);
  buckets_buf_free(&msg);
  return ok;
}

/* Reads LDAPResult fields from a response op's contents. */
static void read_result(buckets_ldap *l, ber *op, char *err, size_t errlen) {
  uint8_t tag;
  ber code, mdn, diag;
  l->code = -1;
  if (ber_next(op, &tag, &code) && tag == 0x0A) l->code = (int)ber_get_int(&code);
  if (ber_next(op, &tag, &mdn) && ber_next(op, &tag, &diag) && l->code != 0) {
    snprintf(err, errlen, "LDAP Result Code %d: %.*s", l->code, (int)diag.n, (const char *)diag.p);
  } else if (l->code != 0) {
    snprintf(err, errlen, "LDAP Result Code %d", l->code);
  }
}

/* Waits for the response op to request id; returns its tag and contents. */
static bool await(buckets_ldap *l, int id, uint8_t *tag, buckets_buf *msg, ber *op, char *err, size_t errlen) {
  for (;;) {
    if (!read_message(l, msg)) {
      snprintf(err, errlen, "LDAP: connection closed");
      l->code = -1;
      return false;
    }
    ber cur = {(const uint8_t *)msg->data, msg->len}, idv;
    uint8_t t;
    if (!ber_next(&cur, &t, &idv) || t != 0x02 || !ber_next(&cur, tag, op)) {
      snprintf(err, errlen, "LDAP: malformed message");
      l->code = -1;
      return false;
    }
    if (ber_get_int(&idv) == id) return true;
  }
}

static int dial(const char *host, int port, int timeout_ms, char *err, size_t errlen) {
  char ps[16];
  snprintf(ps, sizeof(ps), "%d", port);
  struct addrinfo hints = {.ai_socktype = SOCK_STREAM}, *res;
  if (getaddrinfo(host, ps, &hints, &res) != 0) {
    snprintf(err, errlen, "LDAP: cannot resolve %s", host);
    return -1;
  }
  int fd = -1;
  for (struct addrinfo *a = res; a && fd < 0; a = a->ai_next) {
    fd = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
    if (fd < 0) continue;
    int fl = fcntl(fd, F_GETFL);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    int rc = connect(fd, a->ai_addr, a->ai_addrlen);
    if (rc < 0 && errno == EINPROGRESS) {
      struct pollfd pfd = {fd, POLLOUT, 0};
      int e = 0;
      socklen_t el = sizeof(e);
      rc = poll(&pfd, 1, timeout_ms) == 1 && getsockopt(fd, SOL_SOCKET, SO_ERROR, &e, &el) == 0 && e == 0 ? 0 : -1;
    }
    fcntl(fd, F_SETFL, fl);
    if (rc != 0) {
      close(fd);
      fd = -1;
    }
  }
  freeaddrinfo(res);
  if (fd < 0) {
    snprintf(err, errlen, "LDAP Result Code 200 \"Network Error\": dial tcp %s:%d: connection refused", host, port);
    return -1;
  }
  struct timeval tv = {timeout_ms / 1000, (timeout_ms % 1000) * 1000};
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#ifdef SO_NOSIGPIPE
  int one = 1;
  setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
  return fd;
}

buckets_ldap *buckets_ldap_connect(const char *host, int port, buckets_ldap_mode mode, buckets_tls_client *tls,
                                   int timeout_ms, char *err, size_t errlen) {
  int fd = dial(host, port, timeout_ms, err, errlen);
  if (fd < 0) return NULL;
  buckets_ldap *l = buckets_xcalloc(1, sizeof(*l));
  l->fd = fd;
  l->next_id = 1;
  if (mode == BUCKETS_LDAP_LDAPS) {
    if (!(l->tls = buckets_tls_connect(tls, fd, host))) {
      snprintf(err, errlen, "LDAP: TLS handshake with %s:%d failed", host, port);
      buckets_ldap_close(l);
      return NULL;
    }
  } else if (mode == BUCKETS_LDAP_STARTTLS) {
    buckets_buf inner = BUCKETS_BUF_INIT, op = BUCKETS_BUF_INIT, msg = BUCKETS_BUF_INIT;
    ber_str(&inner, 0x80, "1.3.6.1.4.1.1466.20037");
    ber_wrap(&op, 0x77, &inner);
    int id = l->next_id++;
    bool ok = send_op(l, id, &op);
    uint8_t tag;
    ber resp;
    if (ok) ok = await(l, id, &tag, &msg, &resp, err, errlen);
    if (ok) {
      read_result(l, &resp, err, errlen);
      ok = tag == 0x78 && l->code == 0;
    }
    buckets_buf_free(&inner);
    buckets_buf_free(&op);
    buckets_buf_free(&msg);
    if (ok && !(l->tls = buckets_tls_connect(tls, fd, host))) {
      snprintf(err, errlen, "LDAP: StartTLS handshake with %s:%d failed", host, port);
      ok = false;
    }
    if (!ok) {
      buckets_ldap_close(l);
      return NULL;
    }
  }
  return l;
}

void buckets_ldap_close(buckets_ldap *l) {
  if (!l) return;
  if (l->fd >= 0) {
    buckets_buf op = BUCKETS_BUF_INIT;
    ber_tlv(&op, 0x42, NULL, 0); /* UnbindRequest */
    send_op(l, l->next_id++, &op);
    buckets_buf_free(&op);
  }
  buckets_tls_conn_free(l->tls);
  if (l->fd >= 0) close(l->fd);
  buckets_buf_free(&l->in);
  free(l);
}

bool buckets_ldap_bind(buckets_ldap *l, const char *dn, const char *password, char *err, size_t errlen) {
  buckets_buf inner = BUCKETS_BUF_INIT, op = BUCKETS_BUF_INIT, msg = BUCKETS_BUF_INIT;
  ber_int(&inner, 0x02, 3);
  ber_str(&inner, 0x04, dn ? dn : "");
  ber_str(&inner, 0x80, password ? password : "");
  ber_wrap(&op, 0x60, &inner);
  int id = l->next_id++;
  bool ok = send_op(l, id, &op);
  if (!ok) snprintf(err, errlen, "LDAP: send failed");
  uint8_t tag;
  ber resp;
  if (ok) ok = await(l, id, &tag, &msg, &resp, err, errlen);
  if (ok) {
    read_result(l, &resp, err, errlen);
    ok = tag == 0x61 && l->code == 0;
  }
  buckets_buf_free(&inner);
  buckets_buf_free(&op);
  buckets_buf_free(&msg);
  return ok;
}

void buckets_ldap_entries_free(buckets_ldap_entry *e, size_t n) {
  for (size_t i = 0; i < n; i++) {
    free(e[i].dn);
    for (size_t a = 0; a < e[i].nattrs; a++) {
      free(e[i].attrs[a].name);
      for (size_t v = 0; v < e[i].attrs[a].nvalues; v++) free(e[i].attrs[a].values[v]);
      free(e[i].attrs[a].values);
    }
    free(e[i].attrs);
  }
  free(e);
}

bool buckets_ldap_search(buckets_ldap *l, const char *base, buckets_ldap_scope scope, const char *filter,
                         const char *const *attrs, buckets_ldap_entry **out, size_t *n, char *err, size_t errlen) {
  *out = NULL;
  *n = 0;
  buckets_buf f = BUCKETS_BUF_INIT;
  if (!buckets_ldap_compile_filter(filter, &f, err, errlen)) {
    buckets_buf_free(&f);
    l->code = -1;
    return false;
  }
  buckets_buf inner = BUCKETS_BUF_INIT, al = BUCKETS_BUF_INIT, op = BUCKETS_BUF_INIT, msg = BUCKETS_BUF_INIT;
  ber_str(&inner, 0x04, base);
  ber_int(&inner, 0x0A, scope);
  ber_int(&inner, 0x0A, 0); /* neverDerefAliases */
  ber_int(&inner, 0x02, 0); /* sizeLimit */
  ber_int(&inner, 0x02, 0); /* timeLimit */
  ber_tlv(&inner, 0x01, "\0", 1); /* typesOnly FALSE */
  buckets_buf_append(&inner, f.data, f.len);
  if (!attrs) ber_str(&al, 0x04, "1.1");
  for (size_t i = 0; attrs && attrs[i]; i++) ber_str(&al, 0x04, attrs[i]);
  ber_wrap(&inner, 0x30, &al);
  ber_wrap(&op, 0x63, &inner);
  int id = l->next_id++;
  bool ok = send_op(l, id, &op);
  if (!ok) snprintf(err, errlen, "LDAP: send failed");
  size_t cap = 0;
  while (ok) {
    uint8_t tag;
    ber resp;
    if (!(ok = await(l, id, &tag, &msg, &resp, err, errlen))) break;
    if (tag == 0x65) { /* SearchResultDone */
      read_result(l, &resp, err, errlen);
      ok = l->code == 0;
      break;
    }
    if (tag != 0x64) continue; /* references and the like */
    uint8_t t;
    ber dnv, attrl;
    if (!ber_next(&resp, &t, &dnv) || !ber_next(&resp, &t, &attrl)) continue;
    if (*n == cap) {
      cap = cap ? cap * 2 : 8;
      *out = buckets_xrealloc(*out, cap * sizeof(buckets_ldap_entry));
    }
    buckets_ldap_entry *e = &(*out)[(*n)++];
    memset(e, 0, sizeof(*e));
    e->dn = ber_get_str(&dnv);
    ber pa;
    while (ber_next(&attrl, &t, &pa)) {
      ber typ, vals, v;
      if (!ber_next(&pa, &t, &typ) || !ber_next(&pa, &t, &vals)) continue;
      e->attrs = buckets_xrealloc(e->attrs, (e->nattrs + 1) * sizeof(buckets_ldap_attr));
      buckets_ldap_attr *a = &e->attrs[e->nattrs++];
      memset(a, 0, sizeof(*a));
      a->name = ber_get_str(&typ);
      while (ber_next(&vals, &t, &v)) {
        a->values = buckets_xrealloc(a->values, (a->nvalues + 1) * sizeof(char *));
        a->values[a->nvalues++] = ber_get_str(&v);
      }
    }
  }
  buckets_buf_free(&f);
  buckets_buf_free(&inner);
  buckets_buf_free(&al);
  buckets_buf_free(&op);
  buckets_buf_free(&msg);
  if (!ok) {
    buckets_ldap_entries_free(*out, *n);
    *out = NULL;
    *n = 0;
  }
  return ok;
}
