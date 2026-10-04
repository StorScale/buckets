/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "iam/teams.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/common.h"

const char *const buckets_team_levels[] = {"ro", "rw", "admin", NULL};

#define SID_PREFIX "buckets-team:v1:"
#define ARN "arn:aws:s3:::"

BUCKETS_PRINTF(3, 4) static bool fail(char *err, size_t errlen, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(err, errlen, fmt, ap);
  va_end(ap);
  return false;
}

static int level_index(const char *level) {
  for (int i = 0; buckets_team_levels[i]; i++)
    if (strcmp(level, buckets_team_levels[i]) == 0) return i;
  return -1;
}

/* ---- what each level may do ------------------------------------------------------------- */

/* On the buckets themselves; each level adds to the one before. */
static const char *const k_bucket_actions[][20] = {
    {"s3:GetBucketLocation", "s3:ListBucket", "s3:ListBucketVersions", "s3:ListBucketMultipartUploads",
     "s3:GetBucketVersioning", NULL},
    {NULL},
    {"s3:PutBucketVersioning", "s3:GetLifecycleConfiguration", "s3:PutLifecycleConfiguration", "s3:GetBucketTagging",
     "s3:PutBucketTagging", "s3:GetEncryptionConfiguration", "s3:PutEncryptionConfiguration",
     "s3:GetBucketNotification", "s3:PutBucketNotification", "s3:GetBucketObjectLockConfiguration",
     "s3:PutBucketObjectLockConfiguration", "s3:GetReplicationConfiguration", "s3:PutReplicationConfiguration",
     "s3:GetBucketCors", "s3:PutBucketCors", "s3:DeleteBucketCors", "s3:GetBucketPolicy", NULL},
};

/* On their objects. */
static const char *const k_object_actions[][12] = {
    {"s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectTagging", "s3:GetObjectVersionTagging",
     "s3:GetObjectRetention", "s3:GetObjectLegalHold", "s3:GetObjectAttributes", "s3:GetObjectVersionAttributes", NULL},
    {"s3:PutObject", "s3:DeleteObject", "s3:DeleteObjectVersion", "s3:PutObjectTagging", "s3:PutObjectVersionTagging",
     "s3:DeleteObjectTagging", "s3:DeleteObjectVersionTagging", "s3:AbortMultipartUpload",
     "s3:ListMultipartUploadParts", NULL},
    {"s3:PutObjectRetention", "s3:PutObjectLegalHold", NULL},
};

/* Creating and deleting buckets, under the team's prefixes only (admin). */
static const char *const k_create_actions[] = {"s3:CreateBucket", "s3:DeleteBucket", NULL};

/* ---- checks ------------------------------------------------------------------------------ */

static bool name_char(char c) { return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'); }

static bool valid_bucket(const char *b) {
  size_t n = strlen(b);
  if (n < 3 || n > 63 || !name_char(b[0]) || !name_char(b[n - 1])) return false;
  for (size_t i = 0; i < n; i++) {
    if (!name_char(b[i]) && b[i] != '-' && b[i] != '.') return false;
    if (b[i] == '.' && (b[i + 1] == '.' || b[i + 1] == '-' || (i && b[i - 1] == '-'))) return false;
  }
  return true;
}

static bool valid_prefix(const char *p) {
  size_t n = strlen(p);
  if (n < 2 || n > 62 || !name_char(p[0])) return false;
  for (size_t i = 0; i < n; i++)
    if (!name_char(p[i]) && p[i] != '-' && p[i] != '.') return false;
  return true;
}

static bool check_names(yyjson_val *arr, bool prefixes, size_t *count, char *err, size_t errlen) {
  *count = 0;
  if (!arr) return true;
  if (!yyjson_is_arr(arr)) return fail(err, errlen, "%s must be a list", prefixes ? "Prefixes" : "Buckets");
  size_t i, max;
  yyjson_val *v;
  yyjson_arr_foreach(arr, i, max, v) {
    const char *s = yyjson_get_str(v);
    if (!s) return fail(err, errlen, "%s must be names", prefixes ? "Prefixes" : "Buckets");
    if (prefixes ? !valid_prefix(s) : !valid_bucket(s))
      return prefixes ? fail(err, errlen,
                             "\"%s\" is not a bucket-name prefix: 2 to 62 lower-case letters, digits, dots and "
                             "hyphens, starting with a letter or digit",
                             s)
                      : fail(err, errlen,
                             "\"%s\" is not a bucket name: 3 to 63 lower-case letters, digits, dots and hyphens, "
                             "starting and ending with a letter or digit",
                             s);
    for (size_t j = 0; j < i; j++)
      if (strcmp(yyjson_get_str(yyjson_arr_get(arr, j)), s) == 0)
        return fail(err, errlen, "\"%s\" is listed twice", s);
    (*count)++;
  }
  return true;
}

bool buckets_team_check(yyjson_val *team, char *err, size_t errlen) {
  if (!yyjson_is_obj(team)) return fail(err, errlen, "%s", "A team must be an object");
  const char *name = yyjson_get_str(yyjson_obj_get(team, "name"));
  if (!name || !*name) return fail(err, errlen, "%s", "Give the team a name");
  size_t n = strlen(name);
  bool ok = n <= BUCKETS_TEAM_NAME_MAX && name_char(name[0]) && name[n - 1] != '-';
  for (size_t i = 0; ok && i < n; i++) ok = name_char(name[i]) || name[i] == '-';
  if (!ok)
    return fail(err, errlen,
                "\"%s\" is not a team name: up to 40 lower-case letters, digits and hyphens, starting with a letter or "
                "digit and not ending with a hyphen",
                name);
  size_t nb, np;
  if (!check_names(yyjson_obj_get(team, "buckets"), false, &nb, err, errlen)) return false;
  if (!check_names(yyjson_obj_get(team, "prefixes"), true, &np, err, errlen)) return false;
  if (!nb && !np) return fail(err, errlen, "%s", "Give the team at least one bucket or prefix");
  yyjson_val *levels = yyjson_obj_get(team, "levels");
  if (!yyjson_is_arr(levels) || !yyjson_arr_size(levels))
    return fail(err, errlen, "%s", "Choose at least one access level: ro, rw or admin");
  size_t i, max;
  yyjson_val *v;
  yyjson_arr_foreach(levels, i, max, v) {
    const char *l = yyjson_get_str(v);
    if (!l || level_index(l) < 0) return fail(err, errlen, "\"%s\" is not an access level: ro, rw or admin", l ? l : "");
  }
  return true;
}

/* ---- policies ---------------------------------------------------------------------------- */

void buckets_team_policy_name(const char *name, const char *level, char *out, size_t cap) {
  snprintf(out, cap, "team-%s-%s", name, level);
}

static void add_strs(yyjson_mut_doc *d, yyjson_mut_val *arr, const char *const *s) {
  for (; *s; s++) yyjson_mut_arr_add_str(d, arr, *s);
}

/* The team's ARNs: each bucket, then each prefix as a wildcard; suffix "/" + "*" for their objects. */
static void add_arns(yyjson_mut_doc *d, yyjson_mut_val *arr, yyjson_val *team, bool buckets, bool prefixes, const char *suffix) {
  const char *keys[2] = {buckets ? "buckets" : NULL, prefixes ? "prefixes" : NULL};
  for (int k = 0; k < 2; k++) {
    if (!keys[k]) continue;
    size_t i, max;
    yyjson_val *v;
    yyjson_arr_foreach(yyjson_obj_get(team, keys[k]), i, max, v) {
      char arn[160];
      snprintf(arn, sizeof(arn), ARN "%s%s%s", yyjson_get_str(v), k ? "*" : "", suffix);
      yyjson_mut_arr_add_strcpy(d, arr, arn);
    }
  }
}

static yyjson_mut_val *statement(yyjson_mut_doc *d, yyjson_mut_val *stmts, const char *name, const char *level,
                                 const char *part) {
  yyjson_mut_val *s = yyjson_mut_arr_add_obj(d, stmts);
  char sid[128];
  snprintf(sid, sizeof(sid), SID_PREFIX "%s:%s%s%s", name, level, part ? ":" : "", part ? part : "");
  yyjson_mut_obj_add_strcpy(d, s, "Sid", sid);
  yyjson_mut_obj_add_str(d, s, "Effect", "Allow");
  return s;
}

static yyjson_mut_val *team_policy_doc(yyjson_mut_doc *d, yyjson_val *team, const char *level) {
  const char *name = yyjson_get_str(yyjson_obj_get(team, "name"));
  int li = level_index(level);
  yyjson_mut_val *root = yyjson_mut_obj(d);
  yyjson_mut_obj_add_str(d, root, "Version", "2012-10-17");
  yyjson_mut_val *stmts = yyjson_mut_obj_add_arr(d, root, "Statement");

  yyjson_mut_val *s = statement(d, stmts, name, level, NULL);
  yyjson_mut_val *a = yyjson_mut_obj_add_arr(d, s, "Action");
  for (int i = 0; i <= li; i++) add_strs(d, a, k_bucket_actions[i]);
  add_arns(d, yyjson_mut_obj_add_arr(d, s, "Resource"), team, true, true, "");

  s = statement(d, stmts, name, level, "objects");
  a = yyjson_mut_obj_add_arr(d, s, "Action");
  for (int i = 0; i <= li; i++) add_strs(d, a, k_object_actions[i]);
  add_arns(d, yyjson_mut_obj_add_arr(d, s, "Resource"), team, true, true, "/*");

  if (li >= 2 && yyjson_arr_size(yyjson_obj_get(team, "prefixes"))) {
    s = statement(d, stmts, name, level, "create");
    add_strs(d, yyjson_mut_obj_add_arr(d, s, "Action"), k_create_actions);
    add_arns(d, yyjson_mut_obj_add_arr(d, s, "Resource"), team, false, true, "");
  }
  return root;
}

void buckets_team_policy(yyjson_val *team, const char *level, buckets_buf *out) {
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_doc_set_root(d, team_policy_doc(d, team, level));
  size_t n;
  char *json = yyjson_mut_write(d, 0, &n);
  buckets_buf_append(out, json, n);
  free(json);
  yyjson_mut_doc_free(d);
}

/* ---- reading teams back ------------------------------------------------------------------- */

/* A string or an array of strings, as a set: every member of a in b, and the same count of distinct ones. */
static bool str_in(yyjson_val *v, const char *s) {
  if (yyjson_is_str(v)) return strcmp(yyjson_get_str(v), s) == 0;
  size_t i, max;
  yyjson_val *x;
  yyjson_arr_foreach(v, i, max, x) if (yyjson_is_str(x) && strcmp(yyjson_get_str(x), s) == 0) return true;
  return false;
}

static bool subset(yyjson_val *a, yyjson_val *b) {
  if (yyjson_is_str(a)) return str_in(b, yyjson_get_str(a));
  if (!yyjson_is_arr(a)) return false;
  size_t i, max;
  yyjson_val *x;
  yyjson_arr_foreach(a, i, max, x) if (!yyjson_is_str(x) || !str_in(b, yyjson_get_str(x))) return false;
  return true;
}

static bool same_set(yyjson_val *a, yyjson_val *b) { return subset(a, b) && subset(b, a); }

/* The same policy as far as enforcement goes: statements in order, each with the same Sid, Effect, and Action and
 * Resource sets, and nothing else. */
static bool same_policy(yyjson_val *got, yyjson_val *want) {
  const char *gv = yyjson_get_str(yyjson_obj_get(got, "Version")), *wv = yyjson_get_str(yyjson_obj_get(want, "Version"));
  if (!gv || strcmp(gv, wv) != 0) return false;
  yyjson_val *gs = yyjson_obj_get(got, "Statement"), *ws = yyjson_obj_get(want, "Statement");
  if (!yyjson_is_arr(gs) || yyjson_arr_size(gs) != yyjson_arr_size(ws)) return false;
  for (size_t i = 0; i < yyjson_arr_size(ws); i++) {
    yyjson_val *g = yyjson_arr_get(gs, i), *w = yyjson_arr_get(ws, i);
    if (!yyjson_is_obj(g) || yyjson_obj_size(g) != yyjson_obj_size(w)) return false;
    const char *keys[] = {"Sid", "Effect"};
    for (int k = 0; k < 2; k++) {
      const char *a = yyjson_get_str(yyjson_obj_get(g, keys[k]));
      if (!a || strcmp(a, yyjson_get_str(yyjson_obj_get(w, keys[k]))) != 0) return false;
    }
    if (!same_set(yyjson_obj_get(g, "Action"), yyjson_obj_get(w, "Action"))) return false;
    if (!same_set(yyjson_obj_get(g, "Resource"), yyjson_obj_get(w, "Resource"))) return false;
  }
  return true;
}

/* The team and level a policy is marked with, when its name agrees. */
static bool team_marker(const char *policy_name, yyjson_val *doc, char *team, size_t cap, int *level) {
  yyjson_val *first = yyjson_arr_get_first(yyjson_obj_get(doc, "Statement"));
  const char *sid = yyjson_get_str(yyjson_obj_get(first, "Sid"));
  if (!sid || strncmp(sid, SID_PREFIX, strlen(SID_PREFIX)) != 0) return false;
  sid += strlen(SID_PREFIX);
  const char *colon = strchr(sid, ':');
  if (!colon || (size_t)(colon - sid) >= cap || strchr(colon + 1, ':')) return false;
  snprintf(team, cap, "%.*s", (int)(colon - sid), sid);
  *level = level_index(colon + 1);
  if (*level < 0) return false;
  char want[128];
  buckets_team_policy_name(team, colon + 1, want, sizeof(want));
  return strcmp(want, policy_name) == 0;
}

/* A team (immutable) with the buckets and prefixes of a level's policy, from its first statement's resources. */
static yyjson_doc *team_from_policy(const char *name, const char *level, yyjson_val *doc) {
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *t = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, t);
  yyjson_mut_obj_add_strcpy(d, t, "name", name);
  yyjson_mut_val *b = yyjson_mut_obj_add_arr(d, t, "buckets"), *p = yyjson_mut_obj_add_arr(d, t, "prefixes");
  yyjson_val *res = yyjson_obj_get(yyjson_arr_get_first(yyjson_obj_get(doc, "Statement")), "Resource");
  size_t i, max;
  yyjson_val *r;
  yyjson_arr_foreach(res, i, max, r) {
    const char *s = yyjson_get_str(r);
    if (!s || strncmp(s, ARN, strlen(ARN)) != 0) continue;
    s += strlen(ARN);
    size_t n = strlen(s);
    if (n && s[n - 1] == '*') yyjson_mut_arr_add_strncpy(d, p, s, n - 1);
    else yyjson_mut_arr_add_strcpy(d, b, s);
  }
  yyjson_mut_arr_add_strcpy(d, yyjson_mut_obj_add_arr(d, t, "levels"), level);
  yyjson_doc *out = yyjson_mut_doc_imut_copy(d, NULL);
  yyjson_mut_doc_free(d);
  return out;
}

/* Whether a level's stored policy is what the Teams page would write for the team it reads as. */
static bool policy_is_generated(const char *name, const char *level, yyjson_val *doc, yyjson_doc **team_out) {
  yyjson_doc *t = team_from_policy(name, level, doc);
  char err[256];
  bool ok = buckets_team_check(yyjson_doc_get_root(t), err, sizeof(err));
  if (ok) {
    yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *want = team_policy_doc(d, yyjson_doc_get_root(t), level);
    yyjson_doc *w = yyjson_mut_val_imut_copy(want, NULL);
    ok = same_policy(doc, yyjson_doc_get_root(w));
    yyjson_doc_free(w);
    yyjson_mut_doc_free(d);
  }
  *team_out = t;
  return ok;
}

typedef struct {
  char name[BUCKETS_TEAM_NAME_MAX + 1];
  yyjson_val *docs[3];
} found_team;

static int found_cmp(const void *a, const void *b) { return strcmp(((const found_team *)a)->name, ((const found_team *)b)->name); }

yyjson_mut_val *buckets_teams_from_policies(yyjson_mut_doc *d, yyjson_val *policies) {
  yyjson_mut_val *out = yyjson_mut_arr(d);
  size_t cap = yyjson_obj_size(policies), n = 0;
  found_team *ts = calloc(cap ? cap : 1, sizeof(*ts));
  size_t i, max;
  yyjson_val *k, *v;
  yyjson_obj_foreach(policies, i, max, k, v) {
    char team[BUCKETS_TEAM_NAME_MAX + 1];
    int level;
    if (!team_marker(yyjson_get_str(k), v, team, sizeof(team), &level)) continue;
    size_t j = 0;
    while (j < n && strcmp(ts[j].name, team) != 0) j++;
    if (j == n) snprintf(ts[n++].name, sizeof(ts[0].name), "%s", team);
    ts[j].docs[level] = v;
  }
  qsort(ts, n, sizeof(*ts), found_cmp);
  for (size_t j = 0; j < n; j++) {
    yyjson_mut_val *t = yyjson_mut_arr_add_obj(d, out);
    yyjson_mut_val *levels = yyjson_mut_arr(d), *edited = yyjson_mut_arr(d);
    yyjson_doc *from = NULL;
    bool from_generated = false;
    for (int l = 0; l < 3; l++) {
      if (!ts[j].docs[l]) continue;
      yyjson_mut_arr_add_str(d, levels, buckets_team_levels[l]);
      yyjson_doc *read;
      bool gen = policy_is_generated(ts[j].name, buckets_team_levels[l], ts[j].docs[l], &read);
      if (!gen) yyjson_mut_arr_add_str(d, edited, buckets_team_levels[l]);
      if (!from || (gen && !from_generated)) {
        yyjson_doc_free(from);
        from = read, from_generated = gen;
      } else {
        yyjson_doc_free(read);
      }
    }
    yyjson_val *fr = yyjson_doc_get_root(from);
    yyjson_mut_obj_add_strcpy(d, t, "name", ts[j].name);
    yyjson_mut_obj_add_val(d, t, "buckets", yyjson_val_mut_copy(d, yyjson_obj_get(fr, "buckets")));
    yyjson_mut_obj_add_val(d, t, "prefixes", yyjson_val_mut_copy(d, yyjson_obj_get(fr, "prefixes")));
    yyjson_mut_obj_add_val(d, t, "levels", levels);
    yyjson_mut_obj_add_val(d, t, "edited", edited);
    yyjson_doc_free(from);
  }
  free(ts);
  return out;
}

bool buckets_team_overlaps(yyjson_val *team, yyjson_val *teams, char *err, size_t errlen) {
  const char *name = yyjson_get_str(yyjson_obj_get(team, "name"));
  size_t i, max, a, amax, b, bmax;
  yyjson_val *o, *p, *q;
  yyjson_arr_foreach(teams, i, max, o) {
    const char *other = yyjson_get_str(yyjson_obj_get(o, "name"));
    if (!other || strcmp(other, name) == 0) continue;
    yyjson_arr_foreach(yyjson_obj_get(team, "prefixes"), a, amax, p) {
      const char *mine = yyjson_get_str(p);
      yyjson_arr_foreach(yyjson_obj_get(o, "prefixes"), b, bmax, q) {
        const char *theirs = yyjson_get_str(q);
        if (!theirs) continue;
        size_t lm = strlen(mine), lt = strlen(theirs);
        if (strncmp(mine, theirs, lm < lt ? lm : lt) == 0) {
          snprintf(err, errlen, "The prefix \"%s\" overlaps team %s's prefix \"%s\": a bucket could belong to both",
                   mine, other, theirs);
          return true;
        }
      }
    }
  }
  return false;
}
