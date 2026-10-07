/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "bucket/notification.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/common.h"
#include "iam/policy.h"
#include "s3/xml.h"

static const char *const k_names[] = {
    [BUCKETS_EV_OBJECT_ACCESSED_GET] = "s3:ObjectAccessed:Get",
    [BUCKETS_EV_OBJECT_ACCESSED_GET_RETENTION] = "s3:ObjectAccessed:GetRetention",
    [BUCKETS_EV_OBJECT_ACCESSED_GET_LEGAL_HOLD] = "s3:ObjectAccessed:GetLegalHold",
    [BUCKETS_EV_OBJECT_ACCESSED_HEAD] = "s3:ObjectAccessed:Head",
    [BUCKETS_EV_OBJECT_ACCESSED_ATTRIBUTES] = "s3:ObjectAccessed:Attributes",
    [BUCKETS_EV_OBJECT_CREATED_COMPLETE_MULTIPART_UPLOAD] = "s3:ObjectCreated:CompleteMultipartUpload",
    [BUCKETS_EV_OBJECT_CREATED_COPY] = "s3:ObjectCreated:Copy",
    [BUCKETS_EV_OBJECT_CREATED_POST] = "s3:ObjectCreated:Post",
    [BUCKETS_EV_OBJECT_CREATED_PUT] = "s3:ObjectCreated:Put",
    [BUCKETS_EV_OBJECT_CREATED_PUT_RETENTION] = "s3:ObjectCreated:PutRetention",
    [BUCKETS_EV_OBJECT_CREATED_PUT_LEGAL_HOLD] = "s3:ObjectCreated:PutLegalHold",
    [BUCKETS_EV_OBJECT_CREATED_PUT_TAGGING] = "s3:ObjectCreated:PutTagging",
    [BUCKETS_EV_OBJECT_CREATED_DELETE_TAGGING] = "s3:ObjectCreated:DeleteTagging",
    [BUCKETS_EV_OBJECT_REMOVED_DELETE] = "s3:ObjectRemoved:Delete",
    [BUCKETS_EV_OBJECT_REMOVED_DELETE_MARKER_CREATED] = "s3:ObjectRemoved:DeleteMarkerCreated",
    [BUCKETS_EV_OBJECT_REMOVED_DELETE_ALL_VERSIONS] = "s3:ObjectRemoved:DeleteAllVersions",
    [BUCKETS_EV_OBJECT_REMOVED_NOOP] = "s3:ObjectRemoved:NoOP",
    [BUCKETS_EV_BUCKET_CREATED] = "s3:BucketCreated:*",
    [BUCKETS_EV_BUCKET_REMOVED] = "s3:BucketRemoved:*",
    [BUCKETS_EV_OBJECT_REPLICATION_FAILED] = "s3:Replication:OperationFailedReplication",
    [BUCKETS_EV_OBJECT_REPLICATION_COMPLETE] = "s3:Replication:OperationCompletedReplication",
    [BUCKETS_EV_OBJECT_REPLICATION_MISSED_THRESHOLD] = "s3:Replication:OperationMissedThreshold",
    [BUCKETS_EV_OBJECT_REPLICATION_REPLICATED_AFTER_THRESHOLD] = "s3:Replication:OperationReplicatedAfterThreshold",
    [BUCKETS_EV_OBJECT_REPLICATION_NOT_TRACKED] = "s3:Replication:OperationNotTracked",
    [BUCKETS_EV_OBJECT_RESTORE_POST] = "s3:ObjectRestore:Post",
    [BUCKETS_EV_OBJECT_RESTORE_COMPLETED] = "s3:ObjectRestore:Completed",
    [BUCKETS_EV_OBJECT_TRANSITION_FAILED] = "s3:ObjectTransition:Failed",
    [BUCKETS_EV_OBJECT_TRANSITION_COMPLETE] = "s3:ObjectTransition:Complete",
    [BUCKETS_EV_OBJECT_MANY_VERSIONS] = "s3:Scanner:ManyVersions",
    [BUCKETS_EV_OBJECT_LARGE_VERSIONS] = "s3:Scanner:LargeVersions",
    [BUCKETS_EV_PREFIX_MANY_FOLDERS] = "s3:Scanner:BigPrefix",
    [BUCKETS_EV_ILM_DEL_MARKER_EXPIRATION_DELETE] = "s3:LifecycleDelMarkerExpiration:Delete",
    [BUCKETS_EV_BUCKETS_MASS_DELETE] = "s3:Buckets:MassDelete",
    [BUCKETS_EV_BUCKETS_MASS_OVERWRITE] = "s3:Buckets:MassOverwrite",
    [BUCKETS_EV_BUCKETS_PROTECTION_REMOVED] = "s3:Buckets:ProtectionRemoved",
    [BUCKETS_EV_OBJECT_ACCESSED_ALL] = "s3:ObjectAccessed:*",
    [BUCKETS_EV_OBJECT_CREATED_ALL] = "s3:ObjectCreated:*",
    [BUCKETS_EV_OBJECT_REMOVED_ALL] = "s3:ObjectRemoved:*",
    [BUCKETS_EV_OBJECT_REPLICATION_ALL] = "s3:Replication:*",
    [BUCKETS_EV_OBJECT_RESTORE_ALL] = "s3:ObjectRestore:*",
    [BUCKETS_EV_OBJECT_TRANSITION_ALL] = "s3:ObjectTransition:*",
    [BUCKETS_EV_BUCKETS_ALL] = "s3:Buckets:*",
};

const char *buckets_event_name_str(buckets_event_name n) {
  return (size_t)n < BUCKETS_ARRAY_LEN(k_names) && k_names[n] ? k_names[n] : "";
}

buckets_event_name buckets_event_name_parse(const char *s) {
  for (size_t i = 1; i < BUCKETS_ARRAY_LEN(k_names); i++)
    if (k_names[i] && strcmp(k_names[i], s) == 0) return (buckets_event_name)i;
  return BUCKETS_EV_NONE; /* "s3:Scanner:*" and Everything have no name to parse */
}

#define BIT(n) (1ULL << ((n) - 1))
_Static_assert(BUCKETS_EV__SINGLE_END <= 64, "event masks are 64 bits");

uint64_t buckets_event_name_mask(buckets_event_name n) {
  if (n > BUCKETS_EV_NONE && n < BUCKETS_EV__SINGLE_END) return BIT(n);
  switch (n) {
  case BUCKETS_EV_OBJECT_ACCESSED_ALL:
    return BIT(BUCKETS_EV_OBJECT_ACCESSED_GET) | BIT(BUCKETS_EV_OBJECT_ACCESSED_HEAD) |
           BIT(BUCKETS_EV_OBJECT_ACCESSED_GET_RETENTION) | BIT(BUCKETS_EV_OBJECT_ACCESSED_GET_LEGAL_HOLD) |
           BIT(BUCKETS_EV_OBJECT_ACCESSED_ATTRIBUTES);
  case BUCKETS_EV_OBJECT_CREATED_ALL:
    return BIT(BUCKETS_EV_OBJECT_CREATED_COMPLETE_MULTIPART_UPLOAD) | BIT(BUCKETS_EV_OBJECT_CREATED_COPY) |
           BIT(BUCKETS_EV_OBJECT_CREATED_POST) | BIT(BUCKETS_EV_OBJECT_CREATED_PUT) |
           BIT(BUCKETS_EV_OBJECT_CREATED_PUT_RETENTION) | BIT(BUCKETS_EV_OBJECT_CREATED_PUT_LEGAL_HOLD) |
           BIT(BUCKETS_EV_OBJECT_CREATED_PUT_TAGGING) | BIT(BUCKETS_EV_OBJECT_CREATED_DELETE_TAGGING);
  case BUCKETS_EV_OBJECT_REMOVED_ALL:
    return BIT(BUCKETS_EV_OBJECT_REMOVED_DELETE) | BIT(BUCKETS_EV_OBJECT_REMOVED_DELETE_MARKER_CREATED) |
           BIT(BUCKETS_EV_OBJECT_REMOVED_NOOP) | BIT(BUCKETS_EV_OBJECT_REMOVED_DELETE_ALL_VERSIONS);
  case BUCKETS_EV_OBJECT_REPLICATION_ALL:
    return BIT(BUCKETS_EV_OBJECT_REPLICATION_FAILED) | BIT(BUCKETS_EV_OBJECT_REPLICATION_COMPLETE) |
           BIT(BUCKETS_EV_OBJECT_REPLICATION_NOT_TRACKED) | BIT(BUCKETS_EV_OBJECT_REPLICATION_MISSED_THRESHOLD) |
           BIT(BUCKETS_EV_OBJECT_REPLICATION_REPLICATED_AFTER_THRESHOLD);
  case BUCKETS_EV_OBJECT_RESTORE_ALL:
    return BIT(BUCKETS_EV_OBJECT_RESTORE_POST) | BIT(BUCKETS_EV_OBJECT_RESTORE_COMPLETED);
  case BUCKETS_EV_OBJECT_TRANSITION_ALL:
    return BIT(BUCKETS_EV_OBJECT_TRANSITION_FAILED) | BIT(BUCKETS_EV_OBJECT_TRANSITION_COMPLETE);
  case BUCKETS_EV_BUCKETS_ALL:
    return BIT(BUCKETS_EV_BUCKETS_MASS_DELETE) | BIT(BUCKETS_EV_BUCKETS_MASS_OVERWRITE) |
           BIT(BUCKETS_EV_BUCKETS_PROTECTION_REMOVED);
  case BUCKETS_EV_OBJECT_SCANNER_ALL:
    return BIT(BUCKETS_EV_OBJECT_MANY_VERSIONS) | BIT(BUCKETS_EV_OBJECT_LARGE_VERSIONS) |
           BIT(BUCKETS_EV_PREFIX_MANY_FOLDERS);
  case BUCKETS_EV_EVERYTHING: return BIT(BUCKETS_EV__SINGLE_END) - 1;
  default: return 0;
  }
}


/* ---- parsing ------------------------------------------------------------------ */

typedef struct {
  const buckets_xml_doc *d;
  buckets_s3_error err;
  char *msg;
  size_t cap;
  bool malformed; /* a non-event error: MalformedXML */
} pctx;

#define NAME_IS(d, n, s) buckets_str_eq_c((d)->nodes[n].name, s)

static bool fail(pctx *x, buckets_s3_error e, const char *fmt, const char *arg) {
  x->err = e;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
  snprintf(x->msg, x->cap, fmt, arg ? arg : "");
#pragma GCC diagnostic pop
  return false;
}

static bool text_of(pctx *x, size_t node, char *out, size_t cap) {
  buckets_buf b = BUCKETS_BUF_INIT;
  bool ok = buckets_xml_unescape(x->d->nodes[node].text, &b);
  if (ok) snprintf(out, cap, "%s", b.data ? b.data : "");
  buckets_buf_free(&b);
  if (!ok) fail(x, BUCKETS_ERR_MALFORMED_XML, "malformed text%s", NULL);
  return ok;
}

/* parseARN */
static bool parse_arn(const char *s, buckets_target_id *t, char *region, size_t rcap) {
  if (strncmp(s, "arn:minio:sqs:", 14) != 0) return false;
  const char *tok[7];
  size_t len[7], n = 0;
  const char *p = s;
  while (n < 7) {
    const char *c = strchr(p, ':');
    tok[n] = p;
    len[n] = c ? (size_t)(c - p) : strlen(p);
    n++;
    if (!c) break;
    p = c + 1;
  }
  if (n != 6 || !len[4] || !len[5] || len[4] >= sizeof(t->id) || len[5] >= sizeof(t->type) || len[3] >= rcap) return false;
  snprintf(region, rcap, "%.*s", (int)len[3], tok[3]);
  snprintf(t->id, sizeof(t->id), "%.*s", (int)len[4], tok[4]);
  snprintf(t->type, sizeof(t->type), "%.*s", (int)len[5], tok[5]);
  return true;
}

/* S3Key: FilterRule elements, then the one-prefix/one-suffix check. */
static bool parse_s3key(pctx *x, size_t node, buckets_notify_queue *q) {
  const buckets_xml_doc *d = x->d;
  q->nrules = 0;
  bool seen_prefix = false, seen_suffix = false;
  for (size_t c = d->nodes[node].first_child; c; c = d->nodes[c].next_sibling) {
    if (!NAME_IS(d, c, "FilterRule")) continue;
    char name[64] = "", value[1100] = "";
    for (size_t k = d->nodes[c].first_child; k; k = d->nodes[k].next_sibling) {
      if (NAME_IS(d, k, "Name") && !text_of(x, k, name, sizeof(name))) return false;
      if (NAME_IS(d, k, "Value") && !text_of(x, k, value, sizeof(value))) return false;
    }
    bool prefix = strcmp(name, "prefix") == 0;
    if (!prefix && strcmp(name, "suffix") != 0) return fail(x, BUCKETS_ERR_FILTER_NAME_INVALID, "invalid filter name '%s'", name);
    /* (MinIO validates the value it has not stored yet: any value passes.) */
    if (prefix ? seen_prefix : seen_suffix) {
      return prefix ? fail(x, BUCKETS_ERR_FILTER_NAME_PREFIX, "more than one prefix in filter rule%s", NULL)
                    : fail(x, BUCKETS_ERR_FILTER_NAME_SUFFIX, "more than one suffix in filter rule%s", NULL);
    }
    if (prefix) seen_prefix = true;
    else seen_suffix = true;
    snprintf(q->rules[q->nrules].name, sizeof(q->rules[0].name), "%s", name);
    snprintf(q->rules[q->nrules].value, sizeof(q->rules[0].value), "%s", value);
    q->nrules++;
  }
  return true;
}

static bool parse_queue(pctx *x, size_t node, buckets_notify_queue *q) {
  const buckets_xml_doc *d = x->d;
  memset(q, 0, sizeof(*q));
  for (size_t c = d->nodes[node].first_child; c; c = d->nodes[c].next_sibling) {
    if (NAME_IS(d, c, "Id")) {
      if (!text_of(x, c, q->id, sizeof(q->id))) return false;
    } else if (NAME_IS(d, c, "Filter")) {
      q->nrules = 0;
      for (size_t k = d->nodes[c].first_child; k; k = d->nodes[k].next_sibling)
        if (NAME_IS(d, k, "S3Key") && !parse_s3key(x, k, q)) return false;
    } else if (NAME_IS(d, c, "Event")) {
      char name[128];
      if (!text_of(x, c, name, sizeof(name))) return false;
      buckets_event_name ev = buckets_event_name_parse(name);
      if (!ev) return fail(x, BUCKETS_ERR_EVENT_NOTIFICATION, "invalid event name '%s'", name);
      q->events = buckets_xrealloc(q->events, (q->nevents + 1) * sizeof(*q->events));
      q->events[q->nevents++] = ev;
    } else if (NAME_IS(d, c, "Queue")) {
      char arn[512];
      if (!text_of(x, c, arn, sizeof(arn))) return false;
      if (!parse_arn(arn, &q->target, q->region, sizeof(q->region)))
        return fail(x, BUCKETS_ERR_ARN_NOTIFICATION, "invalid ARN '%s'", arn);
    }
  }
  if (!q->nevents) {
    x->malformed = true;
    return fail(x, BUCKETS_ERR_MALFORMED_XML, "missing event name(s)%s", NULL);
  }
  for (size_t i = 0; i < q->nevents; i++)
    for (size_t j = 0; j < i; j++)
      if (q->events[i] == q->events[j])
        return fail(x, BUCKETS_ERR_OVERLAPPING_CONFIGS, "duplicate event name '%s' found", buckets_event_name_str(q->events[i]));
  return true;
}

static bool queue_equal(const buckets_notify_queue *a, const buckets_notify_queue *b) {
  if (strcmp(a->id, b->id) || a->nrules != b->nrules || a->nevents != b->nevents || strcmp(a->target.id, b->target.id) ||
      strcmp(a->target.type, b->target.type) || strcmp(a->region, b->region))
    return false;
  for (size_t i = 0; i < a->nrules; i++)
    if (strcmp(a->rules[i].name, b->rules[i].name) || strcmp(a->rules[i].value, b->rules[i].value)) return false;
  for (size_t i = 0; i < a->nevents; i++)
    if (a->events[i] != b->events[i]) return false;
  return true;
}

static bool decode(pctx *x, const char *xml, size_t n, buckets_notify_config *out) {
  memset(out, 0, sizeof(*out));
  buckets_xml_doc d = {0};
  if (!buckets_xml_parse((buckets_str){xml, n}, &d) || !d.count) {
    if (d.nodes) buckets_xml_doc_free(&d);
    x->malformed = true;
    return fail(x, BUCKETS_ERR_MALFORMED_XML, "malformed XML%s", NULL);
  }
  x->d = &d;
  bool ok = true, unsupported = false;
  if (!buckets_str_eq_c(d.nodes[0].name, "NotificationConfiguration")) {
    x->malformed = true;
    ok = fail(x, BUCKETS_ERR_MALFORMED_XML, "expected element type <NotificationConfiguration>%s", NULL);
  }
  buckets_xml_root_xmlns((buckets_str){xml, n}, out->xmlns, sizeof(out->xmlns));
  for (size_t c = d.nodes[0].first_child; ok && c; c = d.nodes[c].next_sibling) {
    if (NAME_IS(&d, c, "QueueConfiguration")) {
      out->queues = buckets_xrealloc(out->queues, (out->nqueues + 1) * sizeof(*out->queues));
      ok = parse_queue(x, c, &out->queues[out->nqueues]);
      out->nqueues++;
    } else if (NAME_IS(&d, c, "CloudFunctionConfiguration") || NAME_IS(&d, c, "TopicConfiguration")) {
      unsupported = true;
    }
  }
  /* duplicate queue configurations (ignoring a region only the later one has) */
  for (size_t i = 0; ok && i + 1 < out->nqueues; i++) {
    for (size_t j = i + 1; ok && j < out->nqueues; j++) {
      buckets_notify_queue q2 = out->queues[j];
      if (*q2.region && !*out->queues[i].region) q2.region[0] = '\0';
      if (queue_equal(&out->queues[i], &q2))
        ok = fail(x, BUCKETS_ERR_OVERLAPPING_FILTER_NOTIFICATION, "duplicate queue configuration%s", NULL);
    }
  }
  if (ok && unsupported) ok = fail(x, BUCKETS_ERR_UNSUPPORTED_NOTIFICATION, "topic or cloud function configuration is not supported%s", NULL);
  buckets_xml_doc_free(&d);
  if (!ok) buckets_notify_config_free(out);
  return ok;
}

bool buckets_notify_config_parse(const char *xml, size_t n, const char *region, buckets_target_exists_fn exists,
                                 void *ud, buckets_notify_config *out, buckets_s3_error *err, char *msg, size_t cap) {
  char dummy[8];
  pctx x = {.msg = msg ? msg : dummy, .cap = msg ? cap : sizeof(dummy)};
  if (!decode(&x, xml, n, out)) {
    *err = x.err;
    return false;
  }
  /* Validate */
  for (size_t i = 0; i < out->nqueues; i++) {
    buckets_notify_queue *q = &out->queues[i];
    char arn[512];
    snprintf(arn, sizeof(arn), "arn:minio:sqs:%s:%s:%s", q->region, q->target.id, q->target.type);
    if (*q->region && region && *region && strcmp(q->region, region) != 0) {
      fail(&x, BUCKETS_ERR_REGION_NOTIFICATION, "unknown region '%s'", q->region);
    } else if (!exists || !exists(ud, &q->target)) {
      fail(&x, BUCKETS_ERR_ARN_NOTIFICATION, "ARN '%s' not found", arn);
    } else {
      continue;
    }
    *err = x.err;
    buckets_notify_config_free(out);
    return false;
  }
  /* SetRegion, and a default namespace */
  for (size_t i = 0; i < out->nqueues; i++) snprintf(out->queues[i].region, sizeof(out->queues[i].region), "%s", region ? region : "");
  if (!*out->xmlns) snprintf(out->xmlns, sizeof(out->xmlns), "%s", BUCKETS_S3_XMLNS);
  return true;
}

bool buckets_notify_config_load(const char *xml, size_t n, buckets_notify_config *out) {
  char msg[8];
  pctx x = {.msg = msg, .cap = sizeof(msg)};
  return decode(&x, xml, n, out);
}

void buckets_notify_config_free(buckets_notify_config *c) {
  for (size_t i = 0; i < c->nqueues; i++) free(c->queues[i].events);
  free(c->queues);
  memset(c, 0, sizeof(*c));
}

void buckets_notify_config_prune(buckets_notify_config *c, buckets_target_exists_fn exists, void *ud) {
  size_t k = 0;
  for (size_t i = 0; i < c->nqueues; i++) {
    if (exists && exists(ud, &c->queues[i].target)) c->queues[k++] = c->queues[i];
    else free(c->queues[i].events);
  }
  c->nqueues = k;
}

void buckets_notify_config_xml(const buckets_notify_config *c, const char *region, buckets_buf *out) {
  if (*c->xmlns) buckets_buf_appendf(out, "<NotificationConfiguration xmlns=\"%s\">", c->xmlns);
  else buckets_buf_append_c(out, "<NotificationConfiguration>");
  for (size_t i = 0; i < c->nqueues; i++) {
    const buckets_notify_queue *q = &c->queues[i];
    buckets_xml_open(out, "QueueConfiguration");
    buckets_xml_elem(out, "Id", q->id);
    if (q->nrules) {
      buckets_buf_append_c(out, "<Filter><S3Key>");
      for (size_t r = 0; r < q->nrules; r++) {
        buckets_xml_open(out, "FilterRule");
        buckets_xml_elem(out, "Name", q->rules[r].name);
        buckets_xml_elem(out, "Value", q->rules[r].value);
        buckets_xml_close(out, "FilterRule");
      }
      buckets_buf_append_c(out, "</S3Key></Filter>");
    }
    for (size_t e = 0; e < q->nevents; e++) buckets_xml_elem(out, "Event", buckets_event_name_str(q->events[e]));
    char arn[512];
    snprintf(arn, sizeof(arn), "arn:minio:sqs:%s:%s:%s", region ? region : q->region, q->target.id, q->target.type);
    buckets_xml_elem(out, "Queue", arn);
    buckets_xml_close(out, "QueueConfiguration");
  }
  buckets_buf_append_c(out, "</NotificationConfiguration>");
}

/* NewPattern */
static void pattern_of(const buckets_notify_queue *q, char *out, size_t cap) {
  const char *prefix = "", *suffix = "";
  for (size_t r = 0; r < q->nrules; r++) {
    if (strcmp(q->rules[r].name, "prefix") == 0) prefix = q->rules[r].value;
    else suffix = q->rules[r].value;
  }
  buckets_buf p = BUCKETS_BUF_INIT;
  if (*prefix) {
    buckets_buf_append_c(&p, prefix);
    if (prefix[strlen(prefix) - 1] != '*') buckets_buf_append_char(&p, '*');
  }
  if (*suffix) {
    if (*suffix != '*') buckets_buf_append_char(&p, '*');
    buckets_buf_append_c(&p, suffix);
  }
  /* strings.ReplaceAll(pattern, "**", "*") */
  size_t k = 0;
  for (size_t i = 0; i < p.len; i++) {
    if (p.data[i] == '*' && i + 1 < p.len && p.data[i + 1] == '*') {
      out[k < cap - 1 ? k++ : k] = '*';
      i++;
      continue;
    }
    if (k < cap - 1) out[k++] = p.data[i];
  }
  out[k] = '\0';
  if (!k) snprintf(out, cap, "*"); /* NewRulesMap: no pattern matches all */
  buckets_buf_free(&p);
}

size_t buckets_notify_config_match(const buckets_notify_config *c, buckets_event_name ev, const char *key,
                                   buckets_target_id *out, size_t cap) {
  uint64_t bit = buckets_event_name_mask(ev);
  size_t n = 0;
  for (size_t i = 0; i < c->nqueues; i++) {
    const buckets_notify_queue *q = &c->queues[i];
    uint64_t mask = 0;
    for (size_t e = 0; e < q->nevents; e++) mask |= buckets_event_name_mask(q->events[e]);
    if (!(mask & bit)) continue;
    char pat[2200];
    pattern_of(q, pat, sizeof(pat));
    if (!buckets_wildcard_match_simple(pat, key)) continue;
    bool dup = false;
    for (size_t k = 0; k < n && !dup; k++)
      dup = !strcmp(out[k].id, q->target.id) && !strcmp(out[k].type, q->target.type);
    if (!dup && n < cap) out[n++] = q->target;
  }
  return n;
}
