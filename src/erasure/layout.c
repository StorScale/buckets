/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "erasure/layout.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/buf.h"
#include "crypto/crc.h"
#include "crypto/siphash.h"

static const size_t k_set_sizes[] = {2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

/* ---- ellipses ------------------------------------------------------------- */

bool buckets_ell_has(const char *arg) {
  return strstr(arg, "...") || (strchr(arg, '{') && strchr(arg, '}'));
}

static bool range_char(char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z'); }

/* parseEllipsesRange: "{N...M}" in decimal, else hex; zero padding if either
 * bound starts with 0 (and the start is longer than one digit). */
static bool parse_range(const char *body, size_t n, char ***seq, size_t *nseq) {
  const char *dots = NULL;
  for (size_t i = 0; i + 3 <= n; i++) {
    if (memcmp(body + i, "...", 3) == 0) {
      if (dots) return false;
      dots = body + i;
    }
  }
  if (!dots) return false;
  char a[32], b[32];
  size_t al = (size_t)(dots - body), bl = n - al - 3;
  if (al == 0 || bl == 0 || al >= sizeof(a) || bl >= sizeof(b)) return false;
  memcpy(a, body, al);
  a[al] = 0;
  memcpy(b, dots + 3, bl);
  b[bl] = 0;
  bool hex = false;
  char *end;
  unsigned long long start = strtoull(a, &end, 10);
  if (*end) {
    start = strtoull(a, &end, 16);
    if (*end) return false;
    hex = true;
  }
  unsigned long long stop = strtoull(b, &end, 10);
  if (*end) {
    stop = strtoull(b, &end, 16);
    if (*end) return false;
    hex = true;
  }
  if (start > stop || stop - start > 100000) return false;
  bool pad = (a[0] == '0' && al > 1) || b[0] == '0';
  *nseq = (size_t)(stop - start + 1);
  *seq = buckets_xcalloc(*nseq, sizeof(char *));
  for (unsigned long long i = start; i <= stop; i++) {
    char tmp[64];
    if (pad) snprintf(tmp, sizeof(tmp), hex ? "%0*llx" : "%0*llu", (int)bl, i);
    else snprintf(tmp, sizeof(tmp), hex ? "%llx" : "%llu", i);
    (*seq)[i - start] = buckets_xstrdup(tmp);
  }
  return true;
}

/* Rightmost "{[0-9a-z]*...[0-9a-z]*}" in s[0..n): the greedy regex's pick. */
static bool find_last_group(const char *s, size_t n, size_t *open, size_t *close) {
  for (size_t c = n; c-- > 0;) {
    if (s[c] != '}') continue;
    for (size_t o = c; o-- > 0;) {
      if (s[o] == '{') {
        bool ok = true;
        for (size_t k = o + 1; k < c && ok; k++) ok = range_char(s[k]) || s[k] == '.';
        if (ok && c - o - 1 >= 3) {
          const char *d = strstr(s + o, "...");
          if (d && (size_t)(d - s) < c) {
            *open = o;
            *close = c;
            return true;
          }
        }
        break;
      }
      if (!range_char(s[o]) && s[o] != '.') break;
    }
  }
  return false;
}

void buckets_ell_arg_free(buckets_ell_arg *a) {
  for (size_t i = 0; i < a->n; i++) {
    free(a->p[i].prefix);
    free(a->p[i].suffix);
    for (size_t j = 0; j < a->p[i].nseq; j++) free(a->p[i].seq[j]);
    free(a->p[i].seq);
  }
  free(a->p);
  memset(a, 0, sizeof(*a));
}

bool buckets_ell_parse(const char *arg, buckets_ell_arg *out) {
  memset(out, 0, sizeof(*out));
  size_t n = strlen(arg), o, c;
  if (!find_last_group(arg, n, &o, &c)) return false;
  size_t tail_start = c + 1, tail_end = n;
  for (;;) {
    out->p = buckets_xrealloc(out->p, (out->n + 1) * sizeof(buckets_ell_pattern));
    buckets_ell_pattern *p = &out->p[out->n++];
    memset(p, 0, sizeof(*p));
    if (!parse_range(arg + o + 1, c - o - 1, &p->seq, &p->nseq)) {
      buckets_ell_arg_free(out);
      return false;
    }
    p->suffix = buckets_xstrndup(arg + tail_start, tail_end - tail_start);
    size_t no, nc;
    if (o > 0 && find_last_group(arg, o, &no, &nc)) {
      tail_start = nc + 1;
      tail_end = o;
      o = no;
      c = nc;
      continue;
    }
    p->prefix = buckets_xstrndup(arg, o);
    break;
  }
  for (size_t i = 0; i < out->n; i++) {
    const char *pre = out->p[i].prefix ? out->p[i].prefix : "";
    if (strpbrk(pre, "{}") || strpbrk(out->p[i].suffix, "{}")) {
      buckets_ell_arg_free(out);
      return false;
    }
  }
  return true;
}

char **buckets_ell_expand(const buckets_ell_arg *a, size_t *n) {
  size_t total = 1;
  for (size_t i = 0; i < a->n; i++) total *= a->p[i].nseq;
  char **out = buckets_xcalloc(total ? total : 1, sizeof(char *));
  /* argExpander: the last pattern (leftmost in the string) varies fastest. */
  size_t *idx = buckets_xcalloc(a->n ? a->n : 1, sizeof(size_t));
  for (size_t k = 0; k < total; k++) {
    size_t rem = k;
    for (size_t j = a->n; j-- > 0;) {
      idx[j] = rem % a->p[j].nseq;
      rem /= a->p[j].nseq;
    }
    buckets_buf s = BUCKETS_BUF_INIT;
    for (size_t j = a->n; j-- > 0;) {
      const buckets_ell_pattern *p = &a->p[j];
      buckets_buf_appendf(&s, "%s%s%s", p->prefix ? p->prefix : "", p->seq[idx[j]], p->suffix);
    }
    out[k] = s.data;
  }
  free(idx);
  *n = total;
  return out;
}

/* ---- set sizing (getSetIndexes) ------------------------------------------- */

static size_t gcd(size_t x, size_t y) {
  while (y) {
    size_t t = x % y;
    x = y;
    y = t;
  }
  return x;
}

size_t buckets_layout_set_size(const size_t *total_sizes, size_t n, size_t set_drive_count,
                               const buckets_ell_arg *patterns, size_t npatterns, char *err, size_t errlen) {
  if (n == 0) {
    snprintf(err, errlen, "no drives");
    return 0;
  }
  for (size_t i = 0; i < n; i++) {
    if (total_sizes[i] < 2 || total_sizes[i] < set_drive_count) {
      snprintf(err, errlen, "Incorrect number of endpoints provided");
      return 0;
    }
  }
  size_t common = total_sizes[0];
  for (size_t i = 1; i < n; i++) common = gcd(common, total_sizes[i]);
  size_t counts[16], ncounts = 0;
  for (size_t i = 0; i < BUCKETS_ARRAY_LEN(k_set_sizes); i++) {
    if (common % k_set_sizes[i] == 0) counts[ncounts++] = k_set_sizes[i];
  }
  if (!ncounts) {
    snprintf(err, errlen, "number of drives %zu is not divisible by any supported erasure set size", common);
    return 0;
  }
  size_t set_size = 0;
  if (set_drive_count) {
    for (size_t i = 0; i < ncounts; i++) {
      if (counts[i] == set_drive_count) set_size = set_drive_count;
    }
    if (!set_size) {
      snprintf(err, errlen, "Invalid set drive count %zu for %zu drives", set_drive_count, common);
      return 0;
    }
  } else {
    /* possibleSetCountsWithSymmetry: the last pattern examined decides. */
    size_t sym[16], nsym = 0;
    for (size_t i = 0; i < ncounts; i++) {
      bool symmetry = false;
      for (size_t a = 0; a < npatterns; a++) {
        for (size_t p = 0; p < patterns[a].n; p++) {
          size_t len = patterns[a].p[p].nseq;
          symmetry = len > counts[i] ? len % counts[i] == 0 : counts[i] % len == 0;
        }
      }
      if (symmetry || npatterns == 0) sym[nsym++] = counts[i];
    }
    if (!nsym) {
      snprintf(err, errlen, "No symmetric distribution detected: %zu drives cannot be spread symmetrically", common);
      return 0;
    }
    /* commonSetDriveCount */
    if (common < sym[nsym - 1]) {
      set_size = common;
    } else {
      size_t prev = common / sym[0];
      for (size_t i = 0; i < nsym; i++) {
        if (common % sym[i] == 0 && common / sym[i] <= prev) {
          prev = common / sym[i];
          set_size = sym[i];
        }
      }
    }
  }
  if (set_size < 2 || set_size > 16) {
    snprintf(err, errlen, "number of drives %zu is not divisible by any supported erasure set size", common);
    return 0;
  }
  return set_size;
}

void buckets_layout_free(buckets_pool_layout *l) {
  for (size_t i = 0; i < l->ndrives; i++) free(l->drives[i]);
  free(l->drives);
  memset(l, 0, sizeof(*l));
}

bool buckets_layout_pool(char *const *args, size_t nargs, size_t set_drive_count, buckets_pool_layout *out,
                         char *err, size_t errlen) {
  memset(out, 0, sizeof(*out));
  if (nargs == 1 && !buckets_ell_has(args[0])) { /* single drive: xl-single */
    out->drives = buckets_xcalloc(1, sizeof(char *));
    out->drives[0] = buckets_xstrdup(args[0]);
    out->ndrives = out->set_size = 1;
    return true;
  }
  bool ellipses = true;
  for (size_t i = 0; i < nargs; i++) ellipses &= buckets_ell_has(args[i]);
  buckets_ell_arg pat = {0};
  size_t total;
  if (ellipses) {
    if (nargs != 1) {
      snprintf(err, errlen, "one ellipsis argument per pool");
      return false;
    }
    if (!buckets_ell_parse(args[0], &pat)) {
      snprintf(err, errlen, "Invalid ellipsis format in (%s)", args[0]);
      return false;
    }
    out->drives = buckets_ell_expand(&pat, &total);
  } else {
    total = nargs;
    out->drives = buckets_xcalloc(nargs, sizeof(char *));
    for (size_t i = 0; i < nargs; i++) out->drives[i] = buckets_xstrdup(args[i]);
  }
  out->ndrives = total;
  out->set_size = buckets_layout_set_size(&total, 1, set_drive_count, ellipses ? &pat : NULL, ellipses ? 1 : 0, err, errlen);
  buckets_ell_arg_free(&pat);
  for (size_t i = 0; out->set_size && i < total; i++) {
    for (size_t j = i + 1; j < total; j++) {
      if (strcmp(out->drives[i], out->drives[j]) == 0) {
        snprintf(err, errlen, "duplicate drive %s", out->drives[i]);
        out->set_size = 0;
      }
    }
  }
  if (!out->set_size) {
    buckets_layout_free(out);
    return false;
  }
  return true;
}

/* ---- placement ----------------------------------------------------------- */

int buckets_default_parity(int d) {
  switch (d) {
    case 1: return 0;
    case 2: case 3: return 1;
    case 4: case 5: return 2;
    case 6: case 7: return 3;
    default: return 4;
  }
}

size_t buckets_set_index(const char *object, size_t nsets, const uint8_t id[16]) {
  uint64_t k0 = 0, k1 = 0;
  for (int i = 7; i >= 0; i--) k0 = k0 << 8 | id[i];
  for (int i = 15; i >= 8; i--) k1 = k1 << 8 | id[i];
  return (size_t)(buckets_siphash24(k0, k1, object, strlen(object)) % nsets);
}

void buckets_hash_order(const char *key, int n, int *out) {
  uint32_t crc = buckets_crc32_ieee(0, key, strlen(key));
  int start = (int)(crc % (uint32_t)n);
  for (int i = 1; i <= n; i++) out[i - 1] = 1 + ((start + i) % n);
}
