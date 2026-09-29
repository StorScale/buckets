/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Object and bucket tagging (MinIO's {Get,Put,Delete}{Object,Bucket}TaggingHandler).
 * Object tags live in the version's metadata under X-Amz-Tagging, in the query
 * form; bucket tags are the bucket metadata's TaggingConfigXML. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bucket/metasys.h"
#include "bucket/tags.h"
#include "s3/internal.h"
#include "s3/xml.h"

#define TAGGING_META "X-Amz-Tagging"

void buckets_s3_write_tags_error(s3_ctx *c, const void *tags_error) {
  const buckets_tags_error *e = tags_error;
  char msg[256];
  buckets_tags_err_message(e, msg, sizeof(msg));
  if (e->code == BUCKETS_TAGS_MALFORMED_XML && strcmp(e->detail, "XML syntax error") != 0) {
    /* toAPIError of io.EOF or an xml.UnmarshalError: an internal error */
    char full[400];
    snprintf(full, sizeof(full), "%s: cause(%s)", buckets_s3_error_get(BUCKETS_ERR_INTERNAL_ERROR)->message, msg);
    buckets_s3_write_error_msg(c, BUCKETS_ERR_INTERNAL_ERROR, full);
    return;
  }
  if (e->code == BUCKETS_TAGS_MALFORMED_XML) {
    char full[400];
    snprintf(full, sizeof(full), "%s (%s)", buckets_s3_error_get(BUCKETS_ERR_MALFORMED_XML)->message, msg);
    buckets_s3_write_error_msg(c, BUCKETS_ERR_MALFORMED_XML, full);
    return;
  }
  buckets_s3_write_custom_error(c, 400, buckets_tags_err_code(e), msg);
}

bool buckets_s3_check_tagging_header(s3_ctx *c) {
  buckets_str h = buckets_http_header_get(c->req, "X-Amz-Tagging");
  if (!h.p || !h.n) return true;
  char *s = buckets_str_dup(h);
  buckets_tags t;
  buckets_tags_error e;
  bool ok = buckets_tags_parse_query(s, true, &t, &e);
  free(s);
  if (!ok) {
    buckets_s3_write_tags_error(c, &e);
    return false;
  }
  buckets_tags_free(&t);
  return true;
}

int buckets_s3_tag_count(const char *user_tags) {
  if (!user_tags || !*user_tags) return 0;
  buckets_tags t;
  buckets_tags_error e;
  if (!buckets_tags_parse_query(user_tags, true, &t, &e)) return 0;
  int n = (int)t.n;
  buckets_tags_free(&t);
  return n;
}

/* The object version (not a delete marker) the request addresses. */
static bool stat_version(s3_ctx *c, buckets_object_info *oi) {
  const char *version = buckets_query_get(&c->q, "versionId");
  buckets_obj_err err = buckets_obj_stat(c->s->layer, c->bucket, c->object, version, oi);
  if (!err && oi->delete_marker) {
    buckets_object_info_free(oi);
    err = version && *version ? BUCKETS_OBJ_ERR_METHOD_NOT_ALLOWED : BUCKETS_OBJ_ERR_NO_SUCH_KEY;
  }
  if (err) {
    buckets_s3_write_error(c, buckets_s3_obj_error(err));
    return false;
  }
  return true;
}

void buckets_s3_get_object_tagging(s3_ctx *c) {
  buckets_object_info oi;
  if (!stat_version(c, &oi)) return;
  const char *ut = buckets_object_meta(&oi, TAGGING_META);
  if (ut && *ut) c->audit_tagging = buckets_xstrdup(ut); /* into X-Amz-Tagging, as MinIO */
  buckets_tags t = {0};
  buckets_tags_error e;
  if (ut && *ut && !buckets_tags_parse_query(ut, true, &t, &e)) {
    buckets_object_info_free(&oi);
    buckets_s3_write_tags_error(c, &e);
    return;
  }
  const char *version = buckets_query_get(&c->q, "versionId");
  if (version && *version && strcmp(version, "null") != 0)
    buckets_http_resp_header(c->resp, "x-amz-version-id", version);
  buckets_buf *b = &c->resp->body;
  buckets_xml_header(b);
  buckets_tags_xml(&t, b);
  buckets_tags_free(&t);
  buckets_object_info_free(&oi);
  buckets_s3_write_xml(c, 200);
}

typedef struct {
  const char *tags; /* the new X-Amz-Tagging value ("" removes them) */
  char *old;        /* the tags it replaces */
} tag_edit;

static buckets_obj_err edit_tags(void *ud, const buckets_object_info *cur, buckets_xl_kv **user, size_t *nuser,
                                 buckets_xl_kv **sys, size_t *nsys) {
  (void)sys, (void)nsys;
  tag_edit *e = ud;
  const char *old = cur ? buckets_object_meta(cur, TAGGING_META) : NULL;
  free(e->old);
  e->old = old && *old ? buckets_xstrdup(old) : NULL;
  buckets_xl_kv_set(user, nuser, TAGGING_META, e->tags, strlen(e->tags));
  return BUCKETS_OBJ_OK;
}

static void set_object_tags(s3_ctx *c, const char *tags, int status) {
  const char *version = buckets_query_get(&c->q, "versionId");
  tag_edit e = {.tags = tags};
  buckets_object_info oi;
  buckets_obj_err err = buckets_obj_update_meta(c->s->layer, c->bucket, c->object, version, edit_tags, &e, &oi);
  /* MinIO sets the request's X-Amz-Tagging: the new tags on a put, the old ones on a delete */
  if (!c->audit_tagging) {
    if (*tags || status == 200) c->audit_tagging = buckets_xstrdup(tags);
    else if (e.old) c->audit_tagging = buckets_xstrdup(e.old);
  }
  free(e.old);
  if (err) {
    buckets_s3_write_error(c, buckets_s3_obj_error(err));
    return;
  }
  buckets_s3_version_header(c, oi.version_id);
  c->resp->status = status;
  buckets_s3_send_event(c, *tags ? BUCKETS_EV_OBJECT_CREATED_PUT_TAGGING : BUCKETS_EV_OBJECT_CREATED_DELETE_TAGGING, c->bucket,
                        c->object, &oi, NULL);
  buckets_object_info_free(&oi);
}

void buckets_s3_put_object_tagging(s3_ctx *c) {
  buckets_s3_error derr = buckets_s3_read_doc(c);
  if (derr) {
    buckets_s3_write_error(c, derr);
    return;
  }
  buckets_tags t;
  buckets_tags_error e;
  if (!buckets_tags_parse_xml(c->doc.data ? c->doc.data : "", c->doc.len, true, &t, &e)) {
    buckets_s3_write_tags_error(c, &e);
    return;
  }
  buckets_buf s = BUCKETS_BUF_INIT;
  buckets_tags_string(&t, &s);
  buckets_tags_free(&t);
  set_object_tags(c, s.data ? s.data : "", 200);
  buckets_buf_free(&s);
}

void buckets_s3_delete_object_tagging(s3_ctx *c) { set_object_tags(c, "", 204); }

/* ---- bucket tagging ------------------------------------------------------- */

void buckets_s3_get_bucket_tagging(s3_ctx *c) {
  buckets_bucket_state *st = buckets_metasys_get(c->s->meta, c->bucket);
  const buckets_buf *cfg = &st->meta.config[BUCKETS_BCFG_TAGGING];
  buckets_tags t;
  buckets_tags_error e;
  if (!cfg->len || !buckets_tags_parse_xml(cfg->data, cfg->len, false, &t, &e)) {
    buckets_bucket_state_release(st);
    buckets_s3_write_error(c, BUCKETS_ERR_BUCKET_TAGGING_NOT_FOUND);
    return;
  }
  buckets_bucket_state_release(st);
  buckets_tags_xml(&t, &c->resp->body);
  buckets_tags_free(&t);
  buckets_s3_write_xml(c, 200);
}

void buckets_s3_put_bucket_tagging(s3_ctx *c) {
  buckets_s3_error derr = buckets_s3_read_doc(c);
  if (derr) {
    buckets_s3_write_error(c, derr);
    return;
  }
  buckets_tags t;
  buckets_tags_error e;
  if (!buckets_tags_parse_xml(c->doc.data ? c->doc.data : "", c->doc.len, false, &t, &e)) {
    char msg[256];
    buckets_tags_err_message(&e, msg, sizeof(msg));
    buckets_s3_write_error_msg(c, BUCKETS_ERR_MALFORMED_XML, msg);
    return;
  }
  /* Stored as xml.Marshal(tags) writes it. */
  buckets_buf x = BUCKETS_BUF_INIT;
  buckets_tags_xml(&t, &x);
  buckets_tags_free(&t);
  bool ok = buckets_metasys_update(c->s->meta, c->bucket, BUCKETS_BCFG_TAGGING, x.data, x.len);
  buckets_buf_free(&x);
  if (!ok) {
    buckets_s3_write_error(c, BUCKETS_ERR_INTERNAL_ERROR);
    return;
  }
  c->resp->status = 200;
}

void buckets_s3_delete_bucket_tagging(s3_ctx *c) {
  if (!buckets_metasys_update(c->s->meta, c->bucket, BUCKETS_BCFG_TAGGING, NULL, 0)) {
    buckets_s3_write_error(c, BUCKETS_ERR_INTERNAL_ERROR);
    return;
  }
  c->resp->status = 204;
}
