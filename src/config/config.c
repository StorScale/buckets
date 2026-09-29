/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* A port of MinIO's internal/config (config.go, help.go): parsing,
 * validation, environment resolution and formatting of sub-system configs. */
#include "config/config.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <yyjson.h>

extern char **environ;

typedef struct {
  const char *key, *def, *type, *help;
  bool hidden_if_empty, optional, sensitive, secret;
} cfg_key_def;

typedef struct {
  const char *name, *help;
  bool multiple_targets, dynamic, single_target, documented;
  const cfg_key_def *keys;
  size_t nkeys;
} cfg_subsys_def;

#include "config/config_tables.inc"

#define DEF BUCKETS_CONFIG_DEFAULT_TARGET

/* ---- key/value lists ------------------------------------------------------------------ */

typedef struct {
  char *key, *value;
} kv;

typedef struct {
  kv *v;
  size_t n;
} kvs;

static void kvs_free(kvs *k) {
  for (size_t i = 0; i < k->n; i++) {
    free(k->v[i].key);
    free(k->v[i].value);
  }
  free(k->v);
  memset(k, 0, sizeof(*k));
}

static const char *kvs_lookup(const kvs *k, const char *key) {
  for (size_t i = 0; i < k->n; i++) {
    if (strcmp(k->v[i].key, key) == 0) return k->v[i].value;
  }
  return NULL;
}

static void kvs_set(kvs *k, const char *key, const char *value) {
  for (size_t i = 0; i < k->n; i++) {
    if (strcmp(k->v[i].key, key) == 0) {
      free(k->v[i].value);
      k->v[i].value = buckets_xstrdup(value);
      return;
    }
  }
  k->v = buckets_xrealloc(k->v, (k->n + 1) * sizeof(kv));
  k->v[k->n].key = buckets_xstrdup(key);
  k->v[k->n].value = buckets_xstrdup(value);
  k->n++;
}

static void kvs_delete(kvs *k, const char *key) {
  for (size_t i = 0; i < k->n; i++) {
    if (strcmp(k->v[i].key, key) != 0) continue;
    free(k->v[i].key);
    free(k->v[i].value);
    memmove(&k->v[i], &k->v[i + 1], (k->n - i - 1) * sizeof(kv));
    k->n--;
    return;
  }
}

static kvs kvs_clone(const kvs *k) {
  kvs o = {0};
  for (size_t i = 0; i < k->n; i++) kvs_set(&o, k->v[i].key, k->v[i].value);
  return o;
}

static kvs kvs_defaults(const cfg_subsys_def *d) {
  kvs o = {0};
  for (size_t i = 0; i < d->nkeys; i++) kvs_set(&o, d->keys[i].key, d->keys[i].def);
  return o;
}

static bool has_space(const char *s) {
  for (; *s; s++) {
    if (isspace((unsigned char)*s)) return true;
  }
  return false;
}

/* KV.String */
static void kv_write(buckets_buf *b, const char *key, const char *value) {
  bool q = has_space(value);
  buckets_buf_appendf(b, q ? "%s=\"%s\"" : "%s=%s", key, value);
}

/* ---- the registry ----------------------------------------------------------------------- */

static const cfg_subsys_def *subsys_def(const char *name) {
  for (size_t i = 0; i < K_SUBSYSTEMS_N; i++) {
    if (strcmp(k_subsystems[i].name, name) == 0) return &k_subsystems[i];
  }
  return NULL;
}

static const cfg_key_def *key_def(const cfg_subsys_def *d, const char *key) {
  for (size_t i = 0; i < d->nkeys; i++) {
    if (strcmp(d->keys[i].key, key) == 0) return &d->keys[i];
  }
  return NULL;
}

/* A key has a help entry (HelpSubSysMap) unless it is the implicit "enable". */
static bool key_has_help(const cfg_key_def *k) { return *k->type || *k->help; }

bool buckets_config_is_dynamic(const char *subsys) {
  const cfg_subsys_def *d = subsys_def(subsys);
  return d && d->dynamic;
}

bool buckets_config_known(const char *subsys) { return subsys_def(subsys) != NULL; }

/* ---- the config ---------------------------------------------------------------------------- */

typedef struct {
  char *name;
  kvs k;
} target;

typedef struct {
  const cfg_subsys_def *def;
  target *t;
  size_t n;
} subsys;

struct buckets_config {
  subsys s[K_SUBSYSTEMS_N];
};

static subsys *find(buckets_config *c, const char *name) {
  for (size_t i = 0; i < K_SUBSYSTEMS_N; i++) {
    if (strcmp(c->s[i].def->name, name) == 0) return &c->s[i];
  }
  return NULL;
}

static const subsys *cfind(const buckets_config *c, const char *name) { return find((buckets_config *)c, name); }

static target *tfind(const subsys *s, const char *name) {
  for (size_t i = 0; i < s->n; i++) {
    if (strcmp(s->t[i].name, name) == 0) return &s->t[i];
  }
  return NULL;
}

static target *tadd(subsys *s, const char *name) {
  target *t = tfind(s, name);
  if (t) return t;
  s->t = buckets_xrealloc(s->t, (s->n + 1) * sizeof(target));
  t = &s->t[s->n++];
  t->name = buckets_xstrdup(name);
  memset(&t->k, 0, sizeof(t->k));
  return t;
}

static void tdel(subsys *s, const char *name) {
  for (size_t i = 0; i < s->n; i++) {
    if (strcmp(s->t[i].name, name) != 0) continue;
    free(s->t[i].name);
    kvs_free(&s->t[i].k);
    memmove(&s->t[i], &s->t[i + 1], (s->n - i - 1) * sizeof(target));
    s->n--;
    return;
  }
}

buckets_config *buckets_config_new(void) {
  buckets_config *c = buckets_xcalloc(1, sizeof(*c));
  for (size_t i = 0; i < K_SUBSYSTEMS_N; i++) {
    c->s[i].def = &k_subsystems[i];
    tadd(&c->s[i], DEF)->k = kvs_defaults(&k_subsystems[i]);
  }
  return c;
}

void buckets_config_free(buckets_config *c) {
  if (!c) return;
  for (size_t i = 0; i < K_SUBSYSTEMS_N; i++) {
    for (size_t j = 0; j < c->s[i].n; j++) {
      free(c->s[i].t[j].name);
      kvs_free(&c->s[i].t[j].k);
    }
    free(c->s[i].t);
  }
  free(c);
}

buckets_config *buckets_config_clone(const buckets_config *c) {
  buckets_config *o = buckets_xcalloc(1, sizeof(*o));
  for (size_t i = 0; i < K_SUBSYSTEMS_N; i++) {
    o->s[i].def = c->s[i].def;
    for (size_t j = 0; j < c->s[i].n; j++) tadd(&o->s[i], c->s[i].t[j].name)->k = kvs_clone(&c->s[i].t[j].k);
  }
  return o;
}

/* ---- JSON (config.json) ------------------------------------------------------------------------ */

buckets_config *buckets_config_from_json(const char *json, size_t len, char *err, size_t errlen) {
  yyjson_doc *d = yyjson_read(json, len, 0);
  if (!d || !yyjson_is_obj(yyjson_doc_get_root(d))) {
    yyjson_doc_free(d);
    snprintf(err, errlen, "config.json is not a JSON object");
    return NULL;
  }
  /* Config.Merge: every known sub-system from New(), each stored target on
   * top of the defaults; crawler became scanner; api lost two keys. */
  buckets_config *c = buckets_config_new();
  size_t i, max;
  yyjson_val *k, *v;
  yyjson_obj_foreach(yyjson_doc_get_root(d), i, max, k, v) {
    const char *name = yyjson_get_str(k);
    if (strcmp(name, "crawler") == 0) name = "scanner";
    subsys *s = find(c, name);
    if (!s || !yyjson_is_obj(v)) continue;
    size_t j, jmax;
    yyjson_val *tk, *tv;
    yyjson_obj_foreach(v, j, jmax, tk, tv) {
      kvs merged = kvs_defaults(s->def);
      size_t e, emax;
      yyjson_val *ent;
      kvs stored = {0};
      yyjson_arr_foreach(tv, e, emax, ent) {
        const char *key = yyjson_get_str(yyjson_obj_get(ent, "key"));
        const char *val = yyjson_get_str(yyjson_obj_get(ent, "value"));
        if (key) kvs_set(&stored, key, val ? val : "");
      }
      /* ckvs = stored, with defaults added for missing keys (defaults order last). */
      kvs out = kvs_clone(&stored);
      for (size_t x = 0; x < merged.n; x++) {
        if (!kvs_lookup(&stored, merged.v[x].key)) kvs_set(&out, merged.v[x].key, merged.v[x].value);
      }
      if (strcmp(s->def->name, "api") == 0) {
        kvs_delete(&out, "replication_workers");
        kvs_delete(&out, "replication_failed_workers");
      }
      target *t = tadd(s, yyjson_get_str(tk));
      kvs_free(&t->k);
      t->k = out;
      kvs_free(&stored);
      kvs_free(&merged);
    }
  }
  yyjson_doc_free(d);
  return c;
}

char *buckets_config_to_json(const buckets_config *c) {
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, root);
  for (size_t i = 0; i < K_SUBSYSTEMS_N; i++) {
    const subsys *s = &c->s[i];
    yyjson_mut_val *so = yyjson_mut_obj(d);
    for (size_t j = 0; j < s->n; j++) {
      yyjson_mut_val *arr = yyjson_mut_arr(d);
      for (size_t x = 0; x < s->t[j].k.n; x++) {
        yyjson_mut_val *e = yyjson_mut_arr_add_obj(d, arr);
        yyjson_mut_obj_add_strcpy(d, e, "key", s->t[j].k.v[x].key);
        yyjson_mut_obj_add_strcpy(d, e, "value", s->t[j].k.v[x].value);
      }
      yyjson_mut_obj_add(so, yyjson_mut_strcpy(d, s->t[j].name), arr);
    }
    yyjson_mut_obj_add(root, yyjson_mut_strcpy(d, s->def->name), so);
  }
  char *json = yyjson_mut_write(d, 0, NULL);
  yyjson_mut_doc_free(d);
  return json;
}

/* ---- the environment ------------------------------------------------------------------------------- */

const char *buckets_config_getenv(const char *minio_name) {
  if (strncmp(minio_name, "MINIO_", 6) == 0) {
    char alt[512];
    snprintf(alt, sizeof(alt), "BUCKETS_%s", minio_name + 6);
    const char *v = getenv(alt);
    if (v && *v) return v;
  }
  const char *v = getenv(minio_name);
  return v && *v ? v : NULL;
}

/* getEnvVarName */
static void env_name(const char *subsys, const char *tgt, const char *param, char *out, size_t cap) {
  size_t n = (size_t)snprintf(out, cap, "MINIO_%s_%s", subsys, param);
  if (strcmp(tgt, DEF) != 0) snprintf(out + n, cap - n, "_%s", tgt);
  for (size_t i = 0; i < n && out[i]; i++) out[i] = (char)toupper((unsigned char)out[i]);
}

/* Environment variable names with this prefix, as MINIO_ names (BUCKETS_
 * ones are reported under their MINIO_ spelling). */
static size_t env_list(const char *prefix, char ***out) {
  size_t n = 0, cap = 0;
  *out = NULL;
  for (char **e = environ; e && *e; e++) {
    const char *name = *e;
    char buf[512];
    if (strncmp(name, "BUCKETS_", 8) == 0) {
      snprintf(buf, sizeof(buf), "MINIO_%s", name + 8);
      name = buf;
    }
    const char *eq = strchr(name, '=');
    if (!eq || strncmp(name, prefix, strlen(prefix)) != 0) continue;
    char *nm = buckets_xstrndup(name, (size_t)(eq - name));
    bool dup = false;
    for (size_t i = 0; i < n && !dup; i++) dup = strcmp((*out)[i], nm) == 0;
    if (dup || !eq[1]) {
      free(nm);
      continue;
    }
    if (n == cap) {
      cap = cap ? cap * 2 : 16;
      *out = buckets_xrealloc(*out, cap * sizeof(char *));
    }
    (*out)[n++] = nm;
  }
  return n;
}

static void strv_free(char **v, size_t n) {
  for (size_t i = 0; i < n; i++) free(v[i]);
  free(v);
}

static int cmp_str(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }

/* GetAvailableTargets */
size_t buckets_config_targets(const buckets_config *c, const char *name, char ***out) {
  *out = NULL;
  const subsys *s = cfind(c, name);
  if (!s) return 0;
  char **v = buckets_xcalloc(1, sizeof(char *));
  size_t n = 0;
  v[n++] = buckets_xstrdup(DEF);
  if (s->def->single_target) {
    *out = v;
    return n;
  }
  char **seen = NULL;
  size_t ns = 0;
  for (size_t i = 0; i < s->n; i++) {
    if (strcmp(s->t[i].name, DEF) == 0) continue;
    seen = buckets_xrealloc(seen, (ns + 1) * sizeof(char *));
    seen[ns++] = buckets_xstrdup(s->t[i].name);
  }
  /* Env targets: MINIO_<SUBSYS>_<KEY>_<TARGET>, with the longest matching key. */
  char **envs;
  size_t ne = env_list("MINIO_", &envs);
  for (size_t e = 0; e < ne; e++) {
    const char *best = NULL;
    size_t best_len = 0;
    for (size_t k = 0; k < s->def->nkeys; k++) {
      char pfx[512];
      env_name(name, DEF, s->def->keys[k].key, pfx, sizeof(pfx));
      strcat(pfx, "_");
      size_t pl = strlen(pfx);
      if (strlen(envs[e]) > pl && strncmp(envs[e], pfx, pl) == 0 && pl > best_len) {
        best = envs[e] + pl;
        best_len = pl;
      }
    }
    if (!best) continue;
    bool dup = false;
    for (size_t i = 0; i < ns && !dup; i++) dup = strcmp(seen[i], best) == 0;
    if (!dup) {
      seen = buckets_xrealloc(seen, (ns + 1) * sizeof(char *));
      seen[ns++] = buckets_xstrdup(best);
    }
  }
  strv_free(envs, ne);
  if (ns) qsort(seen, ns, sizeof(char *), cmp_str);
  v = buckets_xrealloc(v, (ns + 1) * sizeof(char *));
  for (size_t i = 0; i < ns; i++) v[n++] = seen[i];
  free(seen);
  *out = v;
  return n;
}

char *buckets_config_get(const buckets_config *c, const char *name, const char *tgt, const char *key) {
  const subsys *s = cfind(c, name);
  if (!s) return NULL;
  const cfg_key_def *k = key_def(s->def, key);
  if (!k && strcmp(key, "comment") != 0) return NULL;
  if (!tgt || !*tgt) tgt = DEF;
  char en[512];
  env_name(name, tgt, key, en, sizeof(en));
  const char *v = buckets_config_getenv(en);
  if (v) return buckets_xstrdup(v);
  const target *t = tfind(s, tgt);
  if (t && (v = kvs_lookup(&t->k, key))) return buckets_xstrdup(v);
  return buckets_xstrdup(k ? k->def : "");
}

/* ---- set / delete ------------------------------------------------------------------------------------ */

static bool fail(char *err, size_t errlen, const char *fmt, ...) BUCKETS_PRINTF(3, 4);
static bool fail(char *err, size_t errlen, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(err, errlen, fmt, ap);
  va_end(ap);
  return false;
}

/* GetSubSys: (sub-system, rest of the line, target). */
static bool get_subsys(const char *line, char *sub, size_t subcap, char *tgt, size_t tgtcap, const char **rest,
                       char *err, size_t errlen) {
  snprintf(tgt, tgtcap, DEF);
  *rest = NULL;
  if (!*line) return fail(err, errlen, "input arguments cannot be empty");
  const char *sp = strchr(line, ' ');
  size_t first = sp ? (size_t)(sp - line) : strlen(line);
  if (sp) *rest = sp + 1;
  const char *colon = memchr(line, ':', first);
  size_t sl = colon ? (size_t)(colon - line) : first;
  snprintf(sub, subcap, "%.*s", (int)sl, line);
  const cfg_subsys_def *d = subsys_def(sub);
  if (!d) {
    snprintf(err, errlen, "unknown sub-system %s", line);
    return false;
  }
  if (colon && d->single_target) return fail(err, errlen, "sub-system '%s' only supports single target", sub);
  if (colon) snprintf(tgt, tgtcap, "%.*s", (int)(first - sl - 1), colon + 1);
  return true;
}

bool buckets_config_subsys_of(const char *line, char *sub, size_t cap, char *err, size_t errlen) {
  char tgt[256];
  const char *rest;
  return get_subsys(line, sub, cap, tgt, sizeof(tgt), &rest, err, errlen);
}

static char *trim_dup(const char *p, size_t n) {
  while (n && isspace((unsigned char)*p)) {
    p++;
    n--;
  }
  while (n && isspace((unsigned char)p[n - 1])) n--;
  return buckets_xstrndup(p, n);
}

/* madmin.SanitizeValue: trim, then one layer of double, then single quotes. */
static char *sanitize(const char *v) {
  char *t = trim_dup(v, strlen(v));
  size_t n = strlen(t);
  char *p = t;
  if (n && *p == '"') {
    p++;
    n--;
  }
  if (n && p[n - 1] == '"') n--;
  if (n && *p == '\'') {
    p++;
    n--;
  }
  if (n && p[n - 1] == '\'') n--;
  char *out = buckets_xstrndup(p, n);
  free(t);
  return out;
}

static int cmp_size(const void *a, const void *b) {
  size_t x = *(const size_t *)a, y = *(const size_t *)b;
  return x < y ? -1 : x > y;
}

/* kvFields: split "k1=v1 k2=v 2" at each known "key=" (first occurrence). */
static size_t kv_fields(const char *input, const cfg_subsys_def *d, char ***out) {
  size_t *idx = buckets_xcalloc(d->nkeys + 1, sizeof(size_t));
  size_t n = 0;
  for (size_t i = 0; i <= d->nkeys; i++) {
    const char *key = i < d->nkeys ? d->keys[i].key : "comment";
    if (i < d->nkeys && strcmp(key, "comment") == 0) continue;
    char pat[256];
    snprintf(pat, sizeof(pat), "%s=", key);
    const char *hit = strstr(input, pat);
    if (hit) idx[n++] = (size_t)(hit - input);
  }
  qsort(idx, n, sizeof(size_t), cmp_size);
  *out = buckets_xcalloc(n ? n : 1, sizeof(char *));
  for (size_t i = 0; i < n; i++) {
    size_t end = i + 1 < n ? idx[i + 1] : strlen(input);
    (*out)[i] = trim_dup(input + idx[i], end - idx[i]);
  }
  free(idx);
  return n;
}

/* SetKVS */
static bool set_kvs(buckets_config *c, const char *line, bool *dynamic, char *err, size_t errlen) {
  char name[128], tgt[256];
  const char *rest;
  if (!get_subsys(line, name, sizeof(name), tgt, sizeof(tgt), &rest, err, errlen)) return false;
  if (!rest) return fail(err, errlen, "sub-system '%s' must have key", name);
  subsys *s = find(c, name);
  const cfg_subsys_def *d = s->def;
  *dynamic = d->dynamic;
  char **fields;
  size_t nf = kv_fields(rest, d, &fields);
  if (!nf) {
    free(fields);
    return fail(err, errlen, "sub-system '%s' cannot have empty keys", name);
  }
  kvs in = {0};
  char *prev = NULL;
  bool ok = true;
  for (size_t i = 0; i < nf && ok; i++) {
    char *eq = strchr(fields[i], '=');
    if (!eq && prev) {
      char *v = sanitize(fields[i]);
      buckets_buf joined = BUCKETS_BUF_INIT;
      buckets_buf_appendf(&joined, "%s %s", kvs_lookup(&in, prev), v);
      kvs_set(&in, prev, joined.data);
      buckets_buf_free(&joined);
      free(v);
      continue;
    }
    if (!eq) {
      ok = fail(err, errlen, "key '%s', cannot have empty value", fields[i]);
      break;
    }
    *eq = '\0';
    char *v = sanitize(eq + 1);
    kvs_set(&in, fields[i], v);
    free(prev);
    prev = buckets_xstrdup(fields[i]);
    free(v);
  }
  free(prev);
  strv_free(fields, nf);
  if (!ok) {
    kvs_free(&in);
    return false;
  }
  bool enable_required = key_def(d, "enable") != NULL;
  if (!kvs_lookup(&in, "enable") && enable_required) kvs_set(&in, "enable", "on");
  target *existing = tfind(s, tgt);
  kvs cur;
  if (!existing) {
    cur = kvs_defaults(d);
  } else {
    cur = kvs_clone(&existing->k);
    for (size_t i = 0; i < d->nkeys; i++) {
      if (!kvs_lookup(&cur, d->keys[i].key)) kvs_set(&cur, d->keys[i].key, d->keys[i].def);
    }
  }
  for (size_t i = 0; i < in.n; i++) {
    if (strcmp(in.v[i].key, "comment") != 0) kvs_set(&cur, in.v[i].key, in.v[i].value);
  }
  const char *comment = kvs_lookup(&in, "comment");
  if (comment) kvs_set(&cur, "comment", comment);
  kvs_free(&in);
  /* Required keys of an enabled target must be set. */
  bool enabled = !enable_required || (kvs_lookup(&cur, "enable") && strcmp(kvs_lookup(&cur, "enable"), "on") == 0);
  for (size_t i = 0; i < d->nkeys && enabled; i++) {
    const cfg_key_def *k = &d->keys[i];
    if (!key_has_help(k) || k->optional) continue;
    const char *v = kvs_lookup(&cur, k->key);
    if (!v || !*v) {
      kvs_free(&cur);
      return fail(err, errlen, "'%s' is not optional for '%s' sub-system, please check '%s' documentation", k->key,
                  name, name);
    }
  }
  target *t = tadd(s, tgt);
  kvs_free(&t->k);
  t->k = cur;
  return true;
}

/* Iterates non-empty, non-comment lines. */
typedef bool (*line_fn)(buckets_config *c, const char *line, void *ud, char *err, size_t errlen);

static bool each_line(buckets_config *c, const char *text, line_fn fn, void *ud, char *err, size_t errlen) {
  const char *p = text;
  while (*p) {
    const char *nl = strchr(p, '\n');
    size_t n = nl ? (size_t)(nl - p) : strlen(p);
    if (n && p[n - 1] == '\r') n--;
    char *line = buckets_xstrndup(p, n);
    bool ok = !*line || line[0] == '#' || fn(c, line, ud, err, errlen);
    free(line);
    if (!ok) return false;
    p = nl ? nl + 1 : p + strlen(p);
  }
  return true;
}

static bool set_line(buckets_config *c, const char *line, void *ud, char *err, size_t errlen) {
  bool dyn;
  if (!set_kvs(c, line, &dyn, err, errlen)) return false;
  bool *all = ud;
  *all = *all && dyn;
  return true;
}

bool buckets_config_set_text(buckets_config *c, const char *text, bool *dynamic_only, char *err, size_t errlen) {
  bool dyn = true;
  bool ok = each_line(c, text, set_line, &dyn, err, errlen);
  if (dynamic_only) *dynamic_only = ok && dyn;
  return ok;
}

/* DelKVS */
static bool del_line(buckets_config *c, const char *line, void *ud, char *err, size_t errlen) {
  (void)ud;
  char name[128], tgt[256];
  const char *rest;
  if (!get_subsys(line, name, sizeof(name), tgt, sizeof(tgt), &rest, err, errlen)) {
    /* Unknown sub-systems given alone are simply dropped. */
    return !subsys_def(name) && !strchr(line, ' ');
  }
  subsys *s = find(c, name);
  target *t = tfind(s, tgt);
  if (!t) {
    snprintf(err, errlen, "sub-system %s:%s already deleted or does not exist", name, tgt);
    return false;
  }
  if (!rest) {
    tdel(s, tgt);
    return true;
  }
  kvs cur = kvs_clone(&t->k);
  const char *p = rest;
  while (*p) {
    while (*p && isspace((unsigned char)*p)) p++;
    if (!*p) break;
    const char *e = p;
    while (*e && !isspace((unsigned char)*e)) e++;
    char *key = buckets_xstrndup(p, (size_t)(e - p));
    if (!kvs_lookup(&cur, key)) {
      snprintf(err, errlen, "key %s doesn't exist", key);
      free(key);
      kvs_free(&cur);
      return false;
    }
    const cfg_key_def *k = key_def(s->def, key);
    if (k) kvs_set(&cur, key, k->def);
    else kvs_delete(&cur, key);
    free(key);
    p = e;
  }
  kvs_free(&t->k);
  t->k = cur;
  return true;
}

bool buckets_config_del_text(buckets_config *c, const char *text, char *err, size_t errlen) {
  return each_line(c, text, del_line, NULL, err, errlen);
}

bool buckets_config_check_valid_keys(const buckets_config *c, const char *name, char *err, size_t errlen) {
  const subsys *s = cfind(c, name);
  if (!s) return fail(err, errlen, "Subsystem %s does not exist", name);
  const cfg_subsys_def *d = s->def;
  /* Unknown MINIO_<SUBSYS>... variables. */
  char prefix[128];
  snprintf(prefix, sizeof(prefix), "MINIO_%s", name);
  for (char *p = prefix; *p; p++) *p = (char)toupper((unsigned char)*p);
  char **envs;
  size_t ne = env_list(prefix, &envs);
  buckets_buf unknown = BUCKETS_BUF_INIT;
  for (size_t e = 0; e < ne; e++) {
    bool valid = false;
    for (size_t k = 0; k <= d->nkeys && !valid; k++) {
      const char *key = k < d->nkeys ? d->keys[k].key : "comment";
      char en[512];
      env_name(name, DEF, key, en, sizeof(en));
      valid = strcmp(envs[e], en) == 0;
      if (!valid && !d->single_target) {
        strcat(en, "_");
        valid = strlen(envs[e]) > strlen(en) && strncmp(envs[e], en, strlen(en)) == 0;
      }
    }
    if (!valid) buckets_buf_appendf(&unknown, "%s%s", unknown.len ? ", " : "", envs[e]);
  }
  strv_free(envs, ne);
  if (unknown.len) {
    snprintf(err, errlen, "The following environment variables are unknown: %s", unknown.data);
    buckets_buf_free(&unknown);
    return false;
  }
  for (size_t t = 0; t < s->n; t++) {
    buckets_buf bad = BUCKETS_BUF_INIT;
    for (size_t i = 0; i < s->t[t].k.n; i++) {
      const char *key = s->t[t].k.v[i].key;
      if (key_def(d, key) || strcmp(key, "comment") == 0) continue;
      kv_write(&bad, key, s->t[t].k.v[i].value);
      buckets_buf_append_c(&bad, " ");
    }
    if (bad.len) {
      snprintf(err, errlen,
               "found invalid keys (%s) for '%s:%s' sub-system, use 'mc admin config reset myminio %s:%s' to fix "
               "invalid keys",
               bad.data, name, s->t[t].name, name, s->t[t].name);
      buckets_buf_free(&bad);
      return false;
    }
    buckets_buf_free(&bad);
  }
  return true;
}

bool buckets_config_check_notify_keys(const buckets_config *c, const char *name, char *err, size_t errlen) {
  const subsys *s = cfind(c, name);
  if (!s) return true;
  for (size_t t = 0; t < s->n; t++) {
    const char *en = kvs_lookup(&s->t[t].k, "enable");
    if (!en || strcmp(en, "on") != 0) continue; /* only targets explicitly on */
    buckets_buf bad = BUCKETS_BUF_INIT;
    for (size_t i = 0; i < s->t[t].k.n; i++) {
      const char *key = s->t[t].k.v[i].key;
      if (key_def(s->def, key) || strcmp(key, "comment") == 0) continue;
      if (bad.len) buckets_buf_append_c(&bad, " ");
      kv_write(&bad, key, s->t[t].k.v[i].value);
    }
    if (bad.len) {
      char st[300];
      if (strcmp(s->t[t].name, DEF) == 0) snprintf(st, sizeof(st), "%s", name);
      else snprintf(st, sizeof(st), "%s:%s", name, s->t[t].name);
      snprintf(err, errlen,
               "found invalid keys (%s) for '%s' sub-system, use 'mc admin config reset myminio %s' to fix invalid keys",
               bad.data, st, st);
      buckets_buf_free(&bad);
      return false;
    }
    buckets_buf_free(&bad);
  }
  return true;
}

char *buckets_config_getenv_only(const char *name, const char *tgt, const char *key) {
  char en[512];
  env_name(name, tgt && *tgt ? tgt : DEF, key, en, sizeof(en));
  const char *v = buckets_config_getenv(en);
  return buckets_xstrdup(v ? v : "");
}

/* ---- output ------------------------------------------------------------------------------------------ */

/* SubsysInfo.WriteTo for one target. */
static void write_target(const subsys *s, const char *tgt, bool redact, bool off, buckets_buf *out) {
  const cfg_subsys_def *d = s->def;
  /* Environment overrides first, as comments. */
  for (size_t i = 0; i <= d->nkeys; i++) {
    const char *key = i < d->nkeys ? d->keys[i].key : "comment";
    char en[512];
    env_name(d->name, tgt, key, en, sizeof(en));
    const char *v = buckets_config_getenv(en);
    if (!v) continue;
    if (i < d->nkeys && d->keys[i].secret && redact) continue;
    buckets_buf_appendf(out, "# %s=%s\n", en, v);
  }
  if (off) buckets_buf_append_c(out, "# ");
  buckets_buf_append_c(out, d->name);
  if (strcmp(tgt, DEF) != 0) buckets_buf_appendf(out, ":%s", tgt);
  buckets_buf_append_c(out, " ");
  const target *t = tfind(s, tgt);
  for (size_t i = 0; t && i < t->k.n; i++) {
    const char *key = t->k.v[i].key, *val = t->k.v[i].value;
    const cfg_key_def *k = key_def(d, key);
    if (!k && strcmp(key, "comment") != 0) continue;
    if (k && k->secret && redact && *val) continue;
    if (k && k->hidden_if_empty && !*val) continue;
    if (strcmp(key, "enable") == 0 && strcmp(val, "on") == 0) continue;
    kv_write(out, key, val);
    buckets_buf_append_c(out, " ");
  }
  buckets_buf_append_c(out, "\n");
}

bool buckets_config_get_text(const buckets_config *c, const char *name, const char *tgt, bool redact,
                             buckets_buf *out, char *err, size_t errlen) {
  const subsys *s = cfind(c, name);
  if (!s) return fail(err, errlen, "unknown subsystem: %s", name);
  char **targets;
  size_t nt = buckets_config_targets(c, name, &targets);
  bool ok = true;
  if (tgt) {
    bool found = false;
    for (size_t i = 0; i < nt && !found; i++) found = strcmp(targets[i], tgt) == 0;
    if (!found) ok = fail(err, errlen, "there is no target `%s` for subsystem `%s`", tgt, name);
    else write_target(s, tgt, redact, false, out);
  } else {
    for (size_t i = 0; i < nt; i++) write_target(s, targets[i], redact, false, out);
  }
  strv_free(targets, nt);
  return ok;
}

/* Whether a target is on, for the export (each sub-system's Enabled()). */
static bool target_enabled(const subsys *s, const char *tgt) {
  const target *t = tfind(s, tgt);
  const char *en = t ? kvs_lookup(&t->k, "enable") : NULL;
  const char *n = s->def->name;
#define V(key) (t && kvs_lookup(&t->k, key) && *kvs_lookup(&t->k, key))
  if (strcmp(n, "etcd") == 0) return V("endpoints");
  if (strcmp(n, "storage_class") == 0) return V("standard") || V("rrs");
  if (strcmp(n, "policy_plugin") == 0 || strcmp(n, "identity_plugin") == 0) return V("url");
  if (strcmp(n, "identity_openid") == 0) return (!en || strcmp(en, "off") != 0) && (V("config_url") || V("client_id"));
  if (strcmp(n, "identity_ldap") == 0) return V("server_addr");
  if (strcmp(n, "identity_tls") == 0) return en && strcmp(en, "on") == 0;
#undef V
  return !en || strcmp(en, "off") != 0;
}

void buckets_config_export(const buckets_config *c, buckets_buf *out) {
  for (size_t i = 0; i < K_SUBSYSTEMS_N; i++) {
    const subsys *s = &c->s[i];
    if (!s->def->documented) continue;
    char **targets;
    size_t nt = buckets_config_targets(c, s->def->name, &targets);
    for (size_t j = 0; j < nt; j++) write_target(s, targets[j], false, !target_enabled(s, targets[j]), out);
    strv_free(targets, nt);
  }
}

static void upper(const char *in, char *out, size_t cap) {
  size_t n = 0;
  for (; in[n] && n + 1 < cap; n++) out[n] = (char)toupper((unsigned char)in[n]);
  out[n] = '\0';
}

char *buckets_config_help_json(const char *name, const char *key, bool env_only, char *err, size_t errlen) {
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, root);
  if (!name || !*name) {
    yyjson_mut_obj_add_str(d, root, "subSys", "");
    yyjson_mut_obj_add_str(d, root, "description", "");
    yyjson_mut_obj_add_bool(d, root, "multipleTargets", false);
    yyjson_mut_val *kh = yyjson_mut_obj_add_arr(d, root, "keysHelp");
    for (size_t i = 0; i < K_SUBSYSTEMS_N; i++) {
      if (!k_subsystems[i].documented) continue;
      yyjson_mut_val *h = yyjson_mut_arr_add_obj(d, kh);
      yyjson_mut_obj_add_str(d, h, "key", k_subsystems[i].name);
      yyjson_mut_obj_add_str(d, h, "type", "");
      yyjson_mut_obj_add_str(d, h, "description", k_subsystems[i].help);
      yyjson_mut_obj_add_bool(d, h, "optional", false);
      yyjson_mut_obj_add_bool(d, h, "multipleTargets", k_subsystems[i].multiple_targets);
    }
  } else {
    char sub[128];
    snprintf(sub, sizeof(sub), "%s", name);
    char *colon = strchr(sub, ':');
    if (colon) *colon = '\0';
    const cfg_subsys_def *s = subsys_def(sub);
    if (!s || !s->documented) {
      snprintf(err, errlen, "unknown sub-system %s", sub);
      yyjson_mut_doc_free(d);
      return NULL;
    }
    const cfg_key_def *only = NULL;
    if (key && *key) {
      only = key_def(s, key);
      if (!only || !key_has_help(only)) {
        snprintf(err, errlen, "unknown key %s for sub-system %s", key, sub);
        yyjson_mut_doc_free(d);
        return NULL;
      }
    }
    yyjson_mut_obj_add_strcpy(d, root, "subSys", sub);
    yyjson_mut_obj_add_str(d, root, "description", s->help);
    yyjson_mut_obj_add_bool(d, root, "multipleTargets", s->multiple_targets);
    yyjson_mut_val *kh = yyjson_mut_obj_add_arr(d, root, "keysHelp");
    char us[128], uk[256];
    upper(sub, us, sizeof(us));
    if (s->multiple_targets) {
      yyjson_mut_val *h = yyjson_mut_arr_add_obj(d, kh);
      char k[256];
      snprintf(k, sizeof(k), env_only ? "MINIO_%s_ENABLE" : "enable", us);
      yyjson_mut_obj_add_strcpy(d, h, "key", k);
      char desc[256];
      snprintf(desc, sizeof(desc), "enable %s target, default is 'off'", sub);
      yyjson_mut_obj_add_strcpy(d, h, "type", "on|off");
      yyjson_mut_obj_add_strcpy(d, h, "description", desc);
      yyjson_mut_obj_add_bool(d, h, "optional", false);
      yyjson_mut_obj_add_bool(d, h, "multipleTargets", false);
    }
    for (size_t i = 0; i < s->nkeys; i++) {
      const cfg_key_def *k = &s->keys[i];
      if (!key_has_help(k) || (only && k != only)) continue;
      yyjson_mut_val *h = yyjson_mut_arr_add_obj(d, kh);
      char kname[300];
      upper(k->key, uk, sizeof(uk));
      snprintf(kname, sizeof(kname), env_only ? "MINIO_%s_%s" : "%s%s", env_only ? us : "", env_only ? uk : k->key);
      yyjson_mut_obj_add_strcpy(d, h, "key", kname);
      yyjson_mut_obj_add_str(d, h, "type", k->type);
      yyjson_mut_obj_add_str(d, h, "description", k->help);
      yyjson_mut_obj_add_bool(d, h, "optional", k->optional);
      yyjson_mut_obj_add_bool(d, h, "multipleTargets", false);
    }
  }
  char *json = yyjson_mut_write(d, 0, NULL);
  yyjson_mut_doc_free(d);
  return json;
}

/* ---- validation -------------------------------------------------------------------------------------- */

typedef struct {
  const char *subsys;
  buckets_config_validator fn;
} validator_ent;
static validator_ent g_validators[16];
static size_t g_nvalidators;

void buckets_config_register_validator(const char *subsys, buckets_config_validator fn) {
  for (size_t i = 0; i < g_nvalidators; i++) {
    if (strcmp(g_validators[i].subsys, subsys) == 0) {
      g_validators[i].fn = fn;
      return;
    }
  }
  if (g_nvalidators < BUCKETS_ARRAY_LEN(g_validators)) g_validators[g_nvalidators++] = (validator_ent){subsys, fn};
}

bool buckets_config_validate(const buckets_config *c, const char *subsys, char *err, size_t errlen) {
  bool all = !subsys || !*subsys;
  for (size_t i = 0; i < K_SUBSYSTEMS_N; i++) {
    const char *n = k_subsystems[i].name;
    if (!all && strcmp(n, subsys) != 0) continue;
    /* notification targets check their own keys (checkValidNotificationKeysForSubSys) */
    if (strncmp(n, "notify_", 7) == 0) continue;
    if (!buckets_config_check_valid_keys(c, n, err, errlen)) return false;
  }
  for (size_t i = 0; i < g_nvalidators; i++) {
    if (!all && strcmp(g_validators[i].subsys, subsys) != 0) continue;
    if (!g_validators[i].fn(c, err, errlen)) return false;
  }
  return true;
}

int buckets_config_parse_bool(const char *s) {
  static const char *const on[] = {"1", "t", "T", "TRUE", "true", "True", "on", "ON", "On", "enabled"};
  static const char *const off[] = {"0", "f", "F", "FALSE", "false", "False", "off", "OFF", "Off", "disabled"};
  for (size_t i = 0; s && i < BUCKETS_ARRAY_LEN(on); i++) {
    if (strcmp(s, on[i]) == 0) return 1;
    if (strcmp(s, off[i]) == 0) return 0;
  }
  return -1;
}

size_t buckets_config_resolved(const buckets_config *c, const char *name, const char *tgt, bool redact,
                               buckets_config_kvsrc **out) {
  *out = NULL;
  const subsys *s = cfind(c, name);
  if (!s) return 0;
  if (!tgt || !*tgt) tgt = DEF;
  const target *t = tfind(s, tgt);
  const cfg_subsys_def *d = s->def;
  buckets_config_kvsrc *v = buckets_xcalloc(d->nkeys + 2, sizeof(*v));
  size_t n = 0;
  for (size_t i = 0; i <= d->nkeys; i++) {
    bool comment = i == d->nkeys;
    const char *key = comment ? "comment" : d->keys[i].key;
    if (!comment && strcmp(key, "comment") == 0) continue;
    const char *def = comment ? "" : d->keys[i].def;
    char en[512];
    env_name(name, tgt, key, en, sizeof(en));
    const char *val = buckets_config_getenv(en);
    buckets_config_src src = BUCKETS_CFG_SRC_ENV;
    if (!val || !*val) {
      val = t ? kvs_lookup(&t->k, key) : NULL;
      src = BUCKETS_CFG_SRC_CFG;
    }
    if (!val) {
      val = def;
      src = BUCKETS_CFG_SRC_DEF;
    }
    if (strcmp(val, def) == 0) src = BUCKETS_CFG_SRC_DEF;
    if (comment && src == BUCKETS_CFG_SRC_DEF) continue;
    if (!comment && redact && d->keys[i].secret) continue;
    v[n++] = (buckets_config_kvsrc){buckets_xstrdup(key), buckets_xstrdup(val), src};
  }
  *out = v;
  return n;
}

void buckets_config_kvsrc_free(buckets_config_kvsrc *v, size_t n) {
  for (size_t i = 0; i < n; i++) {
    free(v[i].key);
    free(v[i].value);
  }
  free(v);
}
