/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "iam/ldapidp.h"

#include <arpa/nameser.h>
#include <ctype.h>
#include <netinet/in.h>
#include <resolv.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/buf.h"
#include "core/common.h"

#define LDAP_TIMEOUT_MS 30000
#define DEFAULT_EXPIRY (60LL * 60)
#define MIN_EXPIRY (15LL * 60)
#define MAX_EXPIRY (365LL * 24 * 60 * 60)

typedef struct {
  char *original, *server_dn; /* server_dn: normalized, as the server returned it */
} base_dn;

struct buckets_ldapidp {
  _Atomic int refs;
  bool enabled;
  char *server_addr, *srv_record_name;
  bool insecure, starttls;
  buckets_tls_client *tls;
  char *lookup_dn, *lookup_pw;
  char *user_filter, *group_filter;
  base_dn *user_bases, *group_bases;
  size_t nuser_bases, ngroup_bases;
  char **user_attrs;
  size_t nuser_attrs;
};

void buckets_ldap_strv_free(char **v, size_t n) {
  for (size_t i = 0; i < n; i++) free(v[i]);
  free(v);
}

static void strv_push(char ***v, size_t *n, char *s) {
  *v = buckets_xrealloc(*v, (*n + 1) * sizeof(char *));
  (*v)[(*n)++] = s;
}

void buckets_ldap_dnres_free(buckets_ldap_dnres *r) {
  if (!r) return;
  free(r->norm_dn);
  free(r->actual_dn);
  for (size_t a = 0; a < r->nattrs; a++) {
    free(r->attrs[a].name);
    buckets_ldap_strv_free(r->attrs[a].values, r->attrs[a].nvalues);
  }
  free(r->attrs);
  memset(r, 0, sizeof(*r));
}

static void bases_free(base_dn *b, size_t n) {
  for (size_t i = 0; i < n; i++) {
    free(b[i].original);
    free(b[i].server_dn);
  }
  free(b);
}

buckets_ldapidp *buckets_ldapidp_ref(buckets_ldapidp *p) {
  if (p) atomic_fetch_add(&p->refs, 1);
  return p;
}

void buckets_ldapidp_release(buckets_ldapidp *p) {
  if (!p || atomic_fetch_sub(&p->refs, 1) != 1) return;
  free(p->server_addr);
  free(p->srv_record_name);
  buckets_tls_client_free(p->tls);
  free(p->lookup_dn);
  free(p->lookup_pw);
  free(p->user_filter);
  free(p->group_filter);
  bases_free(p->user_bases, p->nuser_bases);
  bases_free(p->group_bases, p->ngroup_bases);
  buckets_ldap_strv_free(p->user_attrs, p->nuser_attrs);
  free(p);
}

bool buckets_ldapidp_enabled(const buckets_ldapidp *p) { return p && p->enabled; }

/* ---- helpers --------------------------------------------------------------------------------- */

static void seterr(char *err, size_t errlen, const char *fmt, ...) BUCKETS_PRINTF(3, 4);
static void seterr(char *err, size_t errlen, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(err, errlen, fmt, ap);
  va_end(ap);
}

/* strings.ReplaceAll */
static char *replace_all(const char *s, const char *what, const char *with) {
  buckets_buf b = BUCKETS_BUF_INIT;
  buckets_buf_append_c(&b, "");
  size_t wl = strlen(what);
  for (const char *p = s; *p;) {
    if (strncmp(p, what, wl) == 0) {
      buckets_buf_append_c(&b, with);
      p += wl;
    } else {
      buckets_buf_append_char(&b, *p++);
    }
  }
  return buckets_buf_detach(&b);
}

/* splitAndTrim */
static size_t split_trim(const char *s, char sep, char ***out) {
  *out = NULL;
  size_t n = 0;
  for (const char *p = s ? s : ""; *p || p == s;) {
    const char *e = strchr(p, sep);
    size_t len = e ? (size_t)(e - p) : strlen(p);
    size_t a = 0, z = len;
    while (a < z && isspace((unsigned char)p[a])) a++;
    while (z > a && isspace((unsigned char)p[z - 1])) z--;
    if (z > a) strv_push(out, &n, buckets_xstrndup(p + a, z - a));
    if (!e) break;
    p = e + 1;
  }
  return n;
}

static bool is_code(const buckets_ldap *l, int code) { return l && buckets_ldap_result_code(l) == code; }

/* ---- connecting -------------------------------------------------------------------------------- */

static buckets_ldap *connect_addr(const buckets_ldapidp *p, const char *host, int port, char *err, size_t errlen) {
  buckets_ldap_mode mode = p->insecure ? BUCKETS_LDAP_PLAIN : p->starttls ? BUCKETS_LDAP_STARTTLS : BUCKETS_LDAP_LDAPS;
  return buckets_ldap_connect(host, port, mode, p->tls, LDAP_TIMEOUT_MS, err, errlen);
}

/* net.SplitHostPort, defaulting the port to 636. */
static bool split_host_port(const char *addr, char *host, size_t hcap, int *port, char *err, size_t errlen) {
  const char *colon;
  if (addr[0] == '[') {
    const char *rb = strchr(addr, ']');
    if (!rb) {
      seterr(err, errlen, "address %s: missing ']' in address", addr);
      return false;
    }
    snprintf(host, hcap, "%.*s", (int)(rb - addr - 1), addr + 1);
    colon = rb[1] == ':' ? rb + 1 : NULL;
    if (!colon && rb[1]) {
      seterr(err, errlen, "address %s: unexpected characters after ']'", addr);
      return false;
    }
  } else {
    colon = strrchr(addr, ':');
    if (colon && strchr(addr, ':') != colon) {
      seterr(err, errlen, "address %s: too many colons in address", addr);
      return false;
    }
    snprintf(host, hcap, "%.*s", (int)(colon ? (size_t)(colon - addr) : strlen(addr)), addr);
  }
  *port = 636;
  if (colon) {
    char *end;
    long v = strtol(colon + 1, &end, 10);
    if (!colon[1] || *end || v <= 0 || v > 65535) {
      seterr(err, errlen, "address %s: invalid port", addr);
      return false;
    }
    *port = (int)v;
  }
  return true;
}

static buckets_ldap *ldap_connect(const buckets_ldapidp *p, char *err, size_t errlen) {
  if (!p || !p->enabled) {
    seterr(err, errlen, "LDAP is not configured");
    return NULL;
  }
  const char *srv = p->srv_record_name ? p->srv_record_name : "";
  if (!*srv) {
    char host[512];
    int port;
    if (!split_host_port(p->server_addr, host, sizeof(host), &port, err, errlen)) return NULL;
    return connect_addr(p, host, port, err, errlen);
  }
  char qname[600];
  if (strcmp(srv, "on") == 0) snprintf(qname, sizeof(qname), "%s", p->server_addr);
  else if (strcmp(srv, "ldap") == 0 || strcmp(srv, "ldaps") == 0)
    snprintf(qname, sizeof(qname), "_%s._tcp.%s", srv, p->server_addr);
  else {
    seterr(err, errlen, "Invalid SRV Record Name parameter");
    return NULL;
  }
  unsigned char ans[4096];
  int len = res_query(qname, ns_c_in, ns_t_srv, ans, sizeof(ans));
  ns_msg msg;
  if (len < 0 || ns_initparse(ans, len, &msg) < 0) {
    seterr(err, errlen, "DNS SRV Record lookup error: lookup %s: no such host", qname);
    return NULL;
  }
  buckets_buf errs = BUCKETS_BUF_INIT;
  buckets_ldap *l = NULL;
  for (int i = 0; i < ns_msg_count(msg, ns_s_an) && !l; i++) {
    ns_rr rr;
    if (ns_parserr(&msg, ns_s_an, i, &rr) < 0 || ns_rr_type(rr) != ns_t_srv || ns_rr_rdlen(rr) < 7) continue;
    const unsigned char *rd = ns_rr_rdata(rr);
    int port = (rd[4] << 8) | rd[5];
    char target[NS_MAXDNAME];
    if (dn_expand(ns_msg_base(msg), ns_msg_end(msg), rd + 6, target, sizeof(target)) < 0) continue;
    char e[512];
    l = connect_addr(p, target, port, e, sizeof(e));
    if (!l) buckets_buf_appendf(&errs, "%sConnect err to %s.:%d - %s", errs.len ? "; " : "", target, port, e);
  }
  if (!l) seterr(err, errlen, "Could not connect to any LDAP server: %s", errs.data ? errs.data : "");
  buckets_buf_free(&errs);
  return l;
}

/* LookupBind */
static bool lookup_bind(const buckets_ldapidp *p, buckets_ldap *l, char *err, size_t errlen) {
  char e[512];
  if (buckets_ldap_bind(l, p->lookup_dn, p->lookup_pw, e, sizeof(e))) return true;
  if (is_code(l, 49)) seterr(err, errlen, "LDAP Lookup Bind user invalid credentials error: %s", e);
  else seterr(err, errlen, "LDAP client: %s", e);
  return false;
}

static buckets_ldap *connect_bound(const buckets_ldapidp *p, char *err, size_t errlen) {
  buckets_ldap *l = ldap_connect(p, err, errlen);
  if (l && !lookup_bind(p, l, err, errlen)) {
    buckets_ldap_close(l);
    return NULL;
  }
  return l;
}

/* Moves an entry into a search result, normalizing its DN. */
static bool take_entry(buckets_ldap_entry *e, buckets_ldap_dnres *out, char *err, size_t errlen) {
  char *norm = buckets_ldap_normalize_dn(e->dn);
  if (!norm) {
    seterr(err, errlen, "DN (%s) parse failure", e->dn);
    return false;
  }
  memset(out, 0, sizeof(*out));
  out->norm_dn = norm;
  out->actual_dn = e->dn;
  out->attrs = e->attrs;
  out->nattrs = e->nattrs;
  e->dn = NULL;
  e->attrs = NULL;
  e->nattrs = 0;
  return true;
}

/* LookupDN: 1 found, 0 no such object, -1 error. */
static int lookup_dn(buckets_ldap *l, const char *dn, char *const *attrs, size_t nattrs, buckets_ldap_dnres *out,
                     char *err, size_t errlen) {
  const char **al = NULL;
  if (nattrs) {
    al = buckets_xcalloc(nattrs + 1, sizeof(char *));
    for (size_t i = 0; i < nattrs; i++) al[i] = attrs[i];
  }
  buckets_ldap_entry *es;
  size_t n;
  char e[512];
  bool ok = buckets_ldap_search(l, dn, BUCKETS_LDAP_SCOPE_BASE, "(objectClass=*)", al, &es, &n, e, sizeof(e));
  free(al);
  if (!ok) {
    if (is_code(l, 32)) return 0;
    seterr(err, errlen, "LDAP client: %s", e);
    return -1;
  }
  int r = 1;
  if (n != 1) {
    seterr(err, errlen, "Multiple DNs found for %s - this should not happen for a base object search", dn);
    r = -1;
  } else if (!take_entry(&es[0], out, err, errlen)) {
    r = -1;
  }
  buckets_ldap_entries_free(es, n);
  return r;
}

/* LookupUsername: 1 found, 0 not found ("User DN not found for: ..."), -1 error. */
static int lookup_username(const buckets_ldapidp *p, buckets_ldap *l, const char *username, buckets_ldap_dnres *out,
                           char *err, size_t errlen) {
  char *esc = buckets_ldap_escape_filter(username);
  char *filter = replace_all(p->user_filter, "%s", esc);
  free(esc);
  const char **al = NULL;
  if (p->nuser_attrs) {
    al = buckets_xcalloc(p->nuser_attrs + 1, sizeof(char *));
    for (size_t i = 0; i < p->nuser_attrs; i++) al[i] = p->user_attrs[i];
  }
  buckets_ldap_dnres found = {0};
  size_t nfound = 0;
  int r = 1;
  for (size_t b = 0; b < p->nuser_bases && r > 0; b++) {
    buckets_ldap_entry *es;
    size_t n;
    char e[512];
    if (!buckets_ldap_search(l, p->user_bases[b].server_dn, BUCKETS_LDAP_SCOPE_SUB, filter, al, &es, &n, e,
                             sizeof(e))) {
      if (is_code(l, 32))
        seterr(err, errlen, "Base DN (%s) for user DN search does not exist: %s", p->user_bases[b].server_dn, e);
      else seterr(err, errlen, "%s", e);
      r = -1;
      break;
    }
    for (size_t i = 0; i < n && r > 0; i++) {
      if (nfound++ == 0) {
        if (!take_entry(&es[i], &found, err, errlen)) r = -1;
      } else {
        /* only the count matters beyond the first; still check the DN parses */
        char *norm = buckets_ldap_normalize_dn(es[i].dn);
        if (!norm) {
          seterr(err, errlen, "DN (%s) parse failure", es[i].dn);
          r = -1;
        }
        free(norm);
      }
    }
    buckets_ldap_entries_free(es, n);
  }
  free(al);
  free(filter);
  if (r > 0 && nfound == 0) {
    seterr(err, errlen, "User DN not found for: %s", username);
    r = 0;
  } else if (r > 0 && nfound != 1) {
    seterr(err, errlen, "Multiple DNs for %s found - please fix the search filter", username);
    r = -1;
  }
  if (r > 0) *out = found;
  else buckets_ldap_dnres_free(&found);
  return r;
}

/* SearchForUserGroups */
static bool search_groups(const buckets_ldapidp *p, buckets_ldap *l, const char *username, const char *bind_dn,
                          char ***groups, size_t *ngroups, char *err, size_t errlen) {
  *groups = NULL;
  *ngroups = 0;
  if (!p->group_filter || !*p->group_filter) return true;
  char *eu = buckets_ldap_escape_filter(username), *ed = buckets_ldap_escape_filter(bind_dn);
  char *f1 = replace_all(p->group_filter, "%s", eu);
  char *filter = replace_all(f1, "%d", ed);
  free(eu);
  free(ed);
  free(f1);
  bool ok = true;
  for (size_t b = 0; b < p->ngroup_bases && ok; b++) {
    buckets_ldap_entry *es;
    size_t n;
    char e[512];
    if (!buckets_ldap_search(l, p->group_bases[b].server_dn, BUCKETS_LDAP_SCOPE_SUB, filter, NULL, &es, &n, e,
                             sizeof(e))) {
      if (is_code(l, 32))
        seterr(err, errlen, "Error finding groups of %s: Base DN (%s) for group search does not exist: %s", bind_dn,
               p->group_bases[b].server_dn, e);
      else seterr(err, errlen, "Error finding groups of %s: LDAP client: %s", bind_dn, e);
      ok = false;
      break;
    }
    for (size_t i = 0; i < n && ok; i++) {
      char *norm = buckets_ldap_normalize_dn(es[i].dn);
      if (!norm) {
        seterr(err, errlen, "Error finding groups of %s: DN (%s) parse failure", bind_dn, es[i].dn);
        ok = false;
      } else {
        strv_push(groups, ngroups, norm);
      }
    }
    buckets_ldap_entries_free(es, n);
  }
  free(filter);
  if (!ok) {
    buckets_ldap_strv_free(*groups, *ngroups);
    *groups = NULL;
    *ngroups = 0;
  }
  return ok;
}

static bool under_bases(const base_dn *b, size_t n, const char *dn) {
  for (size_t i = 0; i < n; i++)
    if (buckets_ldap_dn_ancestor_of(b[i].server_dn, dn)) return true;
  return false;
}

/* GetValidatedDNUnderBaseDN: 1 found, 0 not found, -1 error. */
static int validated_under(buckets_ldap *l, const char *dn, const base_dn *b, size_t nb, char *const *attrs,
                           size_t nattrs, buckets_ldap_dnres *out, bool *under, char *err, size_t errlen) {
  *under = false;
  if (!nb) {
    seterr(err, errlen, "no Base DNs given");
    return -1;
  }
  char e[512];
  int r = lookup_dn(l, dn, attrs, nattrs, out, e, sizeof(e));
  if (r < 0) {
    seterr(err, errlen, "Error looking up DN %s: %s", dn, e);
    return -1;
  }
  if (r == 0) return 0;
  *under = under_bases(b, nb, out->norm_dn);
  return 1;
}

/* ---- the operations ------------------------------------------------------------------------------ */

static bool parses_as_dn(const char *s) {
  char *n = buckets_ldap_normalize_dn(s);
  free(n);
  return n != NULL;
}

bool buckets_ldapidp_bind(buckets_ldapidp *p, const char *username, const char *password, buckets_ldap_dnres *out,
                          char ***groups, size_t *ngroups, char *err, size_t errlen) {
  memset(out, 0, sizeof(*out));
  *groups = NULL;
  *ngroups = 0;
  buckets_ldap *l = connect_bound(p, err, errlen);
  if (!l) return false;
  char e[512];
  bool ok = lookup_username(p, l, username, out, e, sizeof(e)) > 0;
  if (!ok) seterr(err, errlen, "Unable to find user DN: %s", e);
  if (ok && !buckets_ldap_bind(l, out->actual_dn, password, e, sizeof(e))) {
    seterr(err, errlen, "LDAP auth failed for DN %s: %s", out->actual_dn, e);
    ok = false;
  }
  ok = ok && lookup_bind(p, l, err, errlen) && search_groups(p, l, username, out->actual_dn, groups, ngroups, err, errlen);
  buckets_ldap_close(l);
  if (!ok) buckets_ldap_dnres_free(out);
  return ok;
}

int buckets_ldapidp_lookup_user(buckets_ldapidp *p, const char *username, buckets_ldap_dnres *out, char ***groups,
                                size_t *ngroups, char *err, size_t errlen) {
  memset(out, 0, sizeof(*out));
  *groups = NULL;
  *ngroups = 0;
  buckets_ldap *l = connect_bound(p, err, errlen);
  if (!l) return -1;
  char e[512];
  int r = lookup_username(p, l, username, out, e, sizeof(e));
  if (r <= 0) seterr(err, errlen, "Unable to find user DN: %s", e);
  if (r > 0 && !search_groups(p, l, username, out->actual_dn, groups, ngroups, err, errlen)) {
    buckets_ldap_dnres_free(out);
    r = -1;
  }
  buckets_ldap_close(l);
  return r;
}

bool buckets_ldapidp_parses_as_dn(const char *s) { return parses_as_dn(s); }

int buckets_ldapidp_validated_user(buckets_ldapidp *p, const char *username, buckets_ldap_dnres *out, char *err,
                                   size_t errlen) {
  memset(out, 0, sizeof(*out));
  buckets_ldap *l = connect_bound(p, err, errlen);
  if (!l) return -1;
  int r;
  if (!parses_as_dn(username)) {
    char e[512];
    r = lookup_username(p, l, username, out, e, sizeof(e));
    if (r < 0) seterr(err, errlen, "Unable to find user DN: %s", e);
  } else {
    bool under;
    r = validated_under(l, username, p->user_bases, p->nuser_bases, p->user_attrs, p->nuser_attrs, out, &under, err,
                        errlen);
    if (r > 0 && !under) {
      buckets_ldap_dnres_free(out);
      r = 0;
    }
  }
  buckets_ldap_close(l);
  return r;
}

int buckets_ldapidp_validated_group(buckets_ldapidp *p, const char *dn, buckets_ldap_dnres *out, bool *under_base,
                                    char *err, size_t errlen) {
  memset(out, 0, sizeof(*out));
  *under_base = false;
  buckets_ldap *l = connect_bound(p, err, errlen);
  if (!l) return -1;
  int r = validated_under(l, dn, p->group_bases, p->ngroup_bases, NULL, 0, out, under_base, err, errlen);
  buckets_ldap_close(l);
  return r;
}

int buckets_ldapidp_validated_user_groups(buckets_ldapidp *p, const char *username, buckets_ldap_dnres *out,
                                          char ***groups, size_t *ngroups, char *err, size_t errlen) {
  memset(out, 0, sizeof(*out));
  *groups = NULL;
  *ngroups = 0;
  buckets_ldap *l = connect_bound(p, err, errlen);
  if (!l) return -1;
  int r;
  const char *short_name = "";
  if (!parses_as_dn(username)) {
    char e[512];
    r = lookup_username(p, l, username, out, e, sizeof(e));
    if (r < 0) seterr(err, errlen, "Unable to find user DN: %s", e);
    short_name = username;
  } else {
    bool under;
    r = validated_under(l, username, p->user_bases, p->nuser_bases, p->user_attrs, p->nuser_attrs, out, &under, err,
                        errlen);
    if (r >= 0 && !under) {
      seterr(err, errlen, "Unable to find user DN: <nil>");
      buckets_ldap_dnres_free(out);
      r = -1;
    }
  }
  if (r > 0 && !search_groups(p, l, short_name, out->actual_dn, groups, ngroups, err, errlen)) {
    buckets_ldap_dnres_free(out);
    r = -1;
  }
  buckets_ldap_close(l);
  return r;
}

bool buckets_ldapidp_is_user_dn(const buckets_ldapidp *p, const char *dn) {
  return p && parses_as_dn(dn) && under_bases(p->user_bases, p->nuser_bases, dn);
}

bool buckets_ldapidp_is_group_dn(const buckets_ldapidp *p, const char *dn) {
  return p && parses_as_dn(dn) && under_bases(p->group_bases, p->ngroup_bases, dn);
}

long long buckets_ldapidp_expiry(const buckets_ldapidp *p, const char *dsecs) {
  (void)p;
  if (!dsecs || !*dsecs) return DEFAULT_EXPIRY;
  char *end;
  long long d = strtoll(dsecs, &end, 10);
  if (*end || d < MIN_EXPIRY || d > MAX_EXPIRY) return -1;
  return d;
}

char *buckets_ldapidp_quick_normalize(const char *dn) {
  char *n = buckets_ldap_normalize_dn(dn);
  return n ? n : buckets_xstrdup(dn);
}

char *buckets_ldapidp_decode(const char *dn) {
  char *d = buckets_ldap_decode_dn(dn);
  return d ? d : buckets_xstrdup(dn);
}

bool buckets_ldapidp_non_eligible(buckets_ldapidp *p, char *const *dns, size_t n, char ***out, size_t *nout,
                                  char *err, size_t errlen) {
  *out = NULL;
  *nout = 0;
  buckets_ldap *l = connect_bound(p, err, errlen);
  if (!l) return false;
  char *filter = replace_all(p->user_filter, "%s", "*");
  bool ok = true;
  for (size_t i = 0; i < n && ok; i++) {
    buckets_ldap_entry *es;
    size_t ne;
    char e[512];
    bool gone;
    if (!buckets_ldap_search(l, dns[i], BUCKETS_LDAP_SCOPE_BASE, filter, NULL, &es, &ne, e, sizeof(e))) {
      if (!is_code(l, 32)) {
        seterr(err, errlen, "%s", e);
        ok = false;
        break;
      }
      gone = true;
    } else {
      gone = ne == 0;
      buckets_ldap_entries_free(es, ne);
    }
    if (gone) {
      char *norm = buckets_ldap_normalize_dn(dns[i]);
      if (!norm) {
        seterr(err, errlen, "DN (%s) parse failure", dns[i]);
        ok = false;
      } else {
        strv_push(out, nout, norm);
      }
    }
  }
  free(filter);
  buckets_ldap_close(l);
  if (!ok) {
    buckets_ldap_strv_free(*out, *nout);
    *out = NULL;
    *nout = 0;
  }
  return ok;
}

bool buckets_ldapidp_user_groups(buckets_ldapidp *p, const char *username, const char *dn, char ***groups,
                                 size_t *ngroups, char *err, size_t errlen) {
  *groups = NULL;
  *ngroups = 0;
  buckets_ldap *l = connect_bound(p, err, errlen);
  if (!l) return false;
  bool ok = search_groups(p, l, username ? username : "", dn, groups, ngroups, err, errlen);
  buckets_ldap_close(l);
  return ok;
}

/* ---- Lookup + Validate ------------------------------------------------------------------------------ */

static bool valid_attr(const char *a) {
  if (!isalpha((unsigned char)a[0])) return false;
  for (const char *c = a; *c; c++)
    if (!isalnum((unsigned char)*c) && *c != '-') return false;
  return true;
}

/* validateAndParseBaseDNList */
static bool parse_bases(buckets_ldap *l, const char *list, base_dn **out, size_t *nout, char *err, size_t errlen) {
  char **dns;
  size_t n = split_trim(list, ';', &dns);
  bool ok = true;
  for (size_t i = 0; i < n && ok; i++) {
    buckets_ldap_dnres r;
    char e[512];
    int f = lookup_dn(l, dns[i], NULL, 0, &r, e, sizeof(e));
    if (f < 0) {
      seterr(err, errlen, "Base DN `%s` lookup failed: %s", dns[i], e);
      ok = false;
    } else if (f == 0) {
      seterr(err, errlen, "Base DN `%s` not found in the LDAP server", dns[i]);
      ok = false;
    } else {
      *out = buckets_xrealloc(*out, (*nout + 1) * sizeof(base_dn));
      (*out)[(*nout)++] = (base_dn){buckets_xstrdup(dns[i]), buckets_xstrdup(r.norm_dn)};
      buckets_ldap_dnres_free(&r);
    }
  }
  buckets_ldap_strv_free(dns, n);
  return ok;
}

/* checkForDNOverlaps: false (err set) on an overlap. */
static bool check_overlaps(const base_dn *b, size_t n, const char *what, char *err, size_t errlen) {
  for (size_t i = 0; i < n; i++) {
    for (size_t j = i + 1; j < n; j++) {
      const char *anc = NULL, *desc = NULL;
      if (buckets_ldap_dn_ancestor_of(b[i].server_dn, b[j].server_dn)) anc = b[i].original, desc = b[j].original;
      else if (buckets_ldap_dn_ancestor_of(b[j].server_dn, b[i].server_dn)) anc = b[j].original, desc = b[i].original;
      if (anc) {
        seterr(err, errlen, "%s Search Parameters Misconfigured: %s Search Base DN `%s` is an ancestor of `%s`",
               what, what, anc, desc);
        return false;
      }
    }
  }
  return true;
}

/* compileFilter: with dummy values for %s and %d. */
static bool filter_compiles(const char *f, char *e, size_t elen) {
  char *s1 = replace_all(f, "%s", "a");
  char *s2 = replace_all(s1, "%d", "uid=a,dc=min,dc=io");
  buckets_buf b = BUCKETS_BUF_INIT;
  bool ok = buckets_ldap_compile_filter(s2, &b, e, elen);
  buckets_buf_free(&b);
  free(s1);
  free(s2);
  return ok;
}

#define FAIL(...)                       \
  do {                                  \
    seterr(err, errlen, __VA_ARGS__);   \
    goto fail;                          \
  } while (0)

static const char *const k_conn_err = "LDAP Server Connection Error";
static const char *const k_param_err = "LDAP Server Connection Parameters Misconfigured";
static const char *const k_bind_err = "LDAP Lookup Bind Error";
static const char *const k_user_err = "User Search Parameters Misconfigured";
static const char *const k_group_err = "Group Search Parameters Misconfigured";

/* Config.Validate on p (enabled). */
static bool validate(buckets_ldapidp *p, char *err, size_t errlen, const char *user_bases, const char *group_bases,
                     const char *attrs) {
  buckets_ldap *l = NULL;
  char e[768];
  if (!p->server_addr || !*p->server_addr) FAIL("%s: Address is empty", k_param_err);
  if (p->srv_record_name && *p->srv_record_name && strcmp(p->srv_record_name, "ldap") != 0 &&
      strcmp(p->srv_record_name, "ldaps") != 0 && strcmp(p->srv_record_name, "on") != 0)
    FAIL("%s: SRV Record Name is invalid", k_param_err);
  if (!(l = ldap_connect(p, e, sizeof(e)))) FAIL("%s: Could not connect to LDAP server: %s", k_conn_err, e);
  if (!p->lookup_dn || !*p->lookup_dn) FAIL("%s: Lookup Bind UserDN not specified", k_bind_err);
  if (!lookup_bind(p, l, e, sizeof(e))) FAIL("%s: Error connecting as LDAP Lookup Bind user: %s", k_bind_err, e);
  if (!parse_bases(l, user_bases, &p->user_bases, &p->nuser_bases, e, sizeof(e)))
    FAIL("%s: UserDN search base DN failed to validate/parse: %s", k_user_err, e);
  if (!p->nuser_bases) FAIL("%s: UserDN search base is empty", k_user_err);
  if (!check_overlaps(p->user_bases, p->nuser_bases, "User", err, errlen)) goto fail;
  p->nuser_attrs = split_trim(attrs, ',', &p->user_attrs);
  for (size_t i = 0; i < p->nuser_attrs; i++)
    if (!valid_attr(p->user_attrs[i]))
      FAIL("%s: UserDN attributes `%s` are invalid: Attribute name `%s` is invalid", k_user_err, attrs,
           p->user_attrs[i]);
  if (!*p->user_filter) FAIL("%s: UserDN search filter is empty", k_user_err);
  if (strstr(p->user_filter, "%d")) FAIL("%s: User DN search filter contains `%%d`", k_user_err);
  if (!strstr(p->user_filter, "%s")) FAIL("%s: User DN search filter does not contain `%%s`", k_user_err);
  if (!filter_compiles(p->user_filter, e, sizeof(e)))
    FAIL("%s: User DN search filter `%s` failed to compile: %s", k_user_err, p->user_filter, e);
  if (*group_bases || *p->group_filter) {
    if (!parse_bases(l, group_bases, &p->group_bases, &p->ngroup_bases, e, sizeof(e)))
      FAIL("%s: Group Search Base DN failed to parse: %s", k_group_err, e);
    if (!p->ngroup_bases) FAIL("%s: Group Search Base DN is required.", k_group_err);
    if (!check_overlaps(p->group_bases, p->ngroup_bases, "Group", err, errlen)) goto fail;
    if (!*p->group_filter) FAIL("%s: Group Search Filter is required.", k_group_err);
    if (!strstr(p->group_filter, "%d") && !strstr(p->group_filter, "%s"))
      FAIL("%s: GroupSearchFilter must contain at least one of \"%%s\" or \"%%d\"", k_group_err);
    if (!filter_compiles(p->group_filter, e, sizeof(e)))
      FAIL("%s: Group DN search filter `%s` failed to compile: %s", k_group_err, p->group_filter, e);
  }
  buckets_ldap_close(l);
  return true;
fail:
  buckets_ldap_close(l);
  return false;
}

static char *get(const buckets_config *cfg, const char *key) {
  char *v = buckets_config_get(cfg, "identity_ldap", NULL, key);
  return v ? v : buckets_xstrdup("");
}

buckets_ldapidp *buckets_ldapidp_build(const buckets_config *cfg, const char *ca, char *err, size_t errlen) {
  buckets_ldapidp *p = buckets_xcalloc(1, sizeof(*p));
  atomic_init(&p->refs, 1);
  p->server_addr = get(cfg, "server_addr");
  if (!*p->server_addr) return p;
  char *user_bases = NULL, *group_bases = NULL, *attrs = NULL, *v = NULL;
  p->srv_record_name = get(cfg, "srv_record_name");
  v = get(cfg, "enable");
  bool explicit = *v;
  if (explicit) {
    int b = buckets_config_parse_bool(v);
    if (b < 0) FAIL("ParseBool: parsing \"%s\": invalid syntax", v);
    p->enabled = b;
  }
  free(v);
  v = NULL;
  const char *const bools[] = {"server_insecure", "server_starttls", "tls_skip_verify"};
  bool vals[3] = {false, false, false};
  for (int i = 0; i < 3; i++) {
    v = get(cfg, bools[i]);
    if (*v) {
      int b = buckets_config_parse_bool(v);
      if (b < 0) FAIL("ParseBool: parsing \"%s\": invalid syntax", v);
      vals[i] = b;
    }
    free(v);
    v = NULL;
  }
  p->insecure = vals[0];
  p->starttls = vals[1];
  p->lookup_dn = get(cfg, "lookup_bind_dn");
  p->lookup_pw = get(cfg, "lookup_bind_password");
  p->user_filter = get(cfg, "user_dn_search_filter");
  user_bases = get(cfg, "user_dn_search_base_dn");
  attrs = get(cfg, "user_dn_attributes");
  p->group_filter = get(cfg, "group_search_filter");
  group_bases = get(cfg, "group_search_base_dn");
  if (!explicit) p->enabled = true;
  if (p->enabled) {
    if (!p->insecure) {
      if (!(p->tls = buckets_tls_client_new(ca, err, errlen))) goto fail;
      if (vals[2]) buckets_tls_client_skip_verify(p->tls);
    }
    if (!validate(p, err, errlen, user_bases, group_bases, attrs)) goto fail;
  }
  free(user_bases);
  free(group_bases);
  free(attrs);
  return p;
fail:
  free(v);
  free(user_bases);
  free(group_bases);
  free(attrs);
  buckets_ldapidp_release(p);
  return NULL;
}
