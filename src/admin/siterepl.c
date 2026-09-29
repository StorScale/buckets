/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* The site replication admin API (MinIO's admin-handlers-site-replication.go):
 * /minio/admin/v3/site-replication/... */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "admin/admin.h"
#include "crypto/madmin.h"
#include "siterepl/siterepl.h"

static void reply(s3_ctx *c, const buckets_buf *b) {
  buckets_buf_reset(&c->resp->body);
  if (b->len) buckets_buf_append(&c->resp->body, b->data, b->len);
  buckets_http_resp_header(c->resp, "Content-Type", "application/json");
  c->resp->status = 200;
}

static void fail(s3_ctx *c, const buckets_sr_err *e) {
  buckets_admin_error_msg(c, (buckets_s3_error)e->code, e->message);
}

/* parseJSONBody: the body, decrypted with the requester's secret when asked. */
static bool body(s3_ctx *c, bool encrypted, buckets_buf *out) {
  buckets_s3_error de = buckets_s3_read_doc(c);
  if (de) {
    buckets_admin_error(c, de);
    return false;
  }
  if (!encrypted) {
    buckets_buf_append(out, c->doc.data ? c->doc.data : "", c->doc.len);
    return true;
  }
  if (!buckets_madmin_decrypt(c->ident->secret_key, c->doc.data ? c->doc.data : "", c->doc.len, out)) {
    buckets_admin_error_msg(c, BUCKETS_ERR_SITE_REPLICATION_INVALID_REQUEST, "unable to decrypt the request");
    return false;
  }
  return true;
}

static bool qtrue(s3_ctx *c, const char *k) {
  const char *v = buckets_query_get(&c->q, k);
  return v && strcmp(v, "true") == 0;
}

static const char *qget(s3_ctx *c, const char *k) {
  const char *v = buckets_query_get(&c->q, k);
  return v ? v : "";
}

void buckets_admin_sr_add(s3_ctx *c) {
  if (!buckets_admin_authorize(c, "admin:SiteReplicationAdd")) return;
  buckets_buf b = BUCKETS_BUF_INIT, out = BUCKETS_BUF_INIT;
  if (!body(c, true, &b)) return;
  buckets_sr_err e;
  if (buckets_sr_add(c->s->sr, c->ident->access_key, b.data ? b.data : "", b.len, qtrue(c, "replicateILMExpiry"), &out, &e))
    reply(c, &out);
  else
    fail(c, &e);
  buckets_buf_free(&b);
  buckets_buf_free(&out);
}

void buckets_admin_sr_peer_join(s3_ctx *c) {
  if (!buckets_admin_authorize(c, "admin:SiteReplicationAdd")) return;
  buckets_buf b = BUCKETS_BUF_INIT;
  if (!body(c, true, &b)) return;
  buckets_sr_err e;
  if (buckets_sr_peer_join(c->s->sr, b.data ? b.data : "", b.len, &e)) c->resp->status = 200;
  else fail(c, &e);
  buckets_buf_free(&b);
}

void buckets_admin_sr_peer_bucket_ops(s3_ctx *c) {
  if (!buckets_admin_authorize(c, "admin:SiteReplicationOperation")) return;
  buckets_sr_err e;
  if (buckets_sr_peer_bucket_op(c->s->sr, qget(c, "bucket"), qget(c, "operation"), qget(c, "createdAt"),
                                qtrue(c, "lockEnabled"), qtrue(c, "versioningEnabled"), qtrue(c, "forceCreate"), &e))
    c->resp->status = 200;
  else
    fail(c, &e);
}

void buckets_admin_sr_peer_iam_item(s3_ctx *c) {
  if (!buckets_admin_authorize(c, "admin:SiteReplicationOperation")) return;
  buckets_buf b = BUCKETS_BUF_INIT;
  if (!body(c, false, &b)) return;
  buckets_sr_err e;
  if (buckets_sr_peer_iam_item(c->s->sr, b.data ? b.data : "", b.len, &e)) c->resp->status = 200;
  else fail(c, &e);
  buckets_buf_free(&b);
}

void buckets_admin_sr_peer_bucket_meta(s3_ctx *c) {
  if (!buckets_admin_authorize(c, "admin:SiteReplicationOperation")) return;
  buckets_buf b = BUCKETS_BUF_INIT;
  if (!body(c, false, &b)) return;
  buckets_sr_err e;
  if (buckets_sr_peer_bucket_meta(c->s->sr, b.data ? b.data : "", b.len, &e)) c->resp->status = 200;
  else fail(c, &e);
  buckets_buf_free(&b);
}

void buckets_admin_sr_info(s3_ctx *c) {
  if (!buckets_admin_authorize(c, "admin:SiteReplicationInfo")) return;
  buckets_buf out = BUCKETS_BUF_INIT;
  buckets_sr_info_json(c->s->sr, &out);
  reply(c, &out);
  buckets_buf_free(&out);
}

void buckets_admin_sr_peer_idp_settings(s3_ctx *c) {
  if (!buckets_admin_authorize(c, "admin:SiteReplicationAdd")) return;
  buckets_buf out = BUCKETS_BUF_INIT;
  buckets_sr_idp_settings_json(c->s->sr, &out);
  reply(c, &out);
  buckets_buf_free(&out);
}

/* getSRStatusOptions */
static void status_opts(s3_ctx *c, buckets_sr_status_opts *o) {
  memset(o, 0, sizeof(*o));
  o->buckets = qtrue(c, "buckets");
  o->policies = qtrue(c, "policies");
  o->groups = qtrue(c, "groups");
  o->users = qtrue(c, "users");
  o->ilm_expiry_rules = qtrue(c, "ilm-expiry-rules");
  o->peer_state = qtrue(c, "peer-state");
  o->show_deleted = qtrue(c, "showDeleted");
  o->metrics = qtrue(c, "metrics");
  const char *en = qget(c, "entity");
  o->entity = strcmp(en, "bucket") == 0            ? 1
              : strcmp(en, "policy") == 0          ? 2
              : strcmp(en, "user") == 0            ? 3
              : strcmp(en, "group") == 0           ? 4
              : strcmp(en, "ilm-expiry-rule") == 0 ? 5
                                                   : 0;
  o->entity_value = qget(c, "entityvalue");
}

void buckets_admin_sr_status(s3_ctx *c) {
  if (!buckets_admin_authorize(c, "admin:SiteReplicationInfo")) return;
  buckets_sr_status_opts o;
  status_opts(c, &o);
  if (!o.buckets && !o.policies && !o.groups && !o.users && !o.ilm_expiry_rules && !o.peer_state &&
      !o.show_deleted && !o.metrics && !o.entity && !*o.entity_value) {
    o.buckets = o.users = o.policies = o.groups = o.ilm_expiry_rules = true;
  }
  buckets_buf out = BUCKETS_BUF_INIT;
  buckets_sr_err e;
  if (buckets_sr_status_json(c->s->sr, &o, &out, &e)) reply(c, &out);
  else fail(c, &e);
  buckets_buf_free(&out);
}

void buckets_admin_sr_metainfo(s3_ctx *c) {
  if (!buckets_admin_authorize(c, "admin:SiteReplicationInfo")) return;
  buckets_sr_status_opts o;
  status_opts(c, &o);
  buckets_buf out = BUCKETS_BUF_INIT;
  buckets_sr_err e;
  if (buckets_sr_metainfo_json(c->s->sr, &o, &out, &e)) reply(c, &out);
  else fail(c, &e);
  buckets_buf_free(&out);
}

void buckets_admin_sr_edit(s3_ctx *c) {
  if (!buckets_admin_authorize(c, "admin:SiteReplicationAdd")) return;
  buckets_buf b = BUCKETS_BUF_INIT, out = BUCKETS_BUF_INIT;
  if (!body(c, true, &b)) return;
  buckets_sr_err e;
  if (buckets_sr_edit(c->s->sr, b.data ? b.data : "", b.len, qtrue(c, "disableILMExpiryReplication"),
                      qtrue(c, "enableILMExpiryReplication"), &out, &e))
    reply(c, &out);
  else
    fail(c, &e);
  buckets_buf_free(&b);
  buckets_buf_free(&out);
}

void buckets_admin_sr_peer_edit(s3_ctx *c) {
  if (!buckets_admin_authorize(c, "admin:SiteReplicationAdd")) return;
  buckets_buf b = BUCKETS_BUF_INIT;
  if (!body(c, false, &b)) return;
  buckets_sr_err e;
  if (buckets_sr_peer_edit(c->s->sr, b.data ? b.data : "", b.len, &e)) c->resp->status = 200;
  else fail(c, &e);
  buckets_buf_free(&b);
}

void buckets_admin_sr_state_edit(s3_ctx *c) {
  if (!buckets_admin_authorize(c, "admin:SiteReplicationOperation")) return;
  buckets_buf b = BUCKETS_BUF_INIT;
  if (!body(c, false, &b)) return;
  buckets_sr_err e;
  if (buckets_sr_state_edit(c->s->sr, b.data ? b.data : "", b.len, &e)) c->resp->status = 200;
  else fail(c, &e);
  buckets_buf_free(&b);
}

void buckets_admin_sr_remove(s3_ctx *c) {
  if (!buckets_admin_authorize(c, "admin:SiteReplicationRemove")) return;
  buckets_buf b = BUCKETS_BUF_INIT, out = BUCKETS_BUF_INIT;
  if (!body(c, false, &b)) return;
  buckets_sr_err e;
  if (buckets_sr_remove(c->s->sr, b.data ? b.data : "", b.len, &out, &e)) reply(c, &out);
  else fail(c, &e);
  buckets_buf_free(&b);
  buckets_buf_free(&out);
}

void buckets_admin_sr_peer_remove(s3_ctx *c) {
  if (!buckets_admin_authorize(c, "admin:SiteReplicationRemove")) return;
  buckets_buf b = BUCKETS_BUF_INIT;
  if (!body(c, false, &b)) return;
  buckets_sr_err e;
  if (buckets_sr_peer_remove(c->s->sr, b.data ? b.data : "", b.len, &e)) c->resp->status = 200;
  else fail(c, &e);
  buckets_buf_free(&b);
}

void buckets_admin_sr_resync_op(s3_ctx *c) {
  if (!buckets_admin_authorize(c, "admin:SiteReplicationResync")) return;
  buckets_buf b = BUCKETS_BUF_INIT, out = BUCKETS_BUF_INIT;
  if (!body(c, false, &b)) return;
  buckets_sr_err e;
  if (buckets_sr_resync_op(c->s->sr, b.data ? b.data : "", b.len, qget(c, "operation"), &out, &e)) reply(c, &out);
  else fail(c, &e);
  buckets_buf_free(&b);
  buckets_buf_free(&out);
}
