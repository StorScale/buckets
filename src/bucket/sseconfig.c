/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "bucket/sseconfig.h"

#include <stdio.h>
#include <string.h>

#include "core/common.h"
#include "s3/xml.h"

#define ARN_PREFIX "arn:aws:kms:"

static bool text_of(const buckets_xml_doc *d, size_t node, char *out, size_t cap) {
  buckets_buf b = BUCKETS_BUF_INIT;
  bool ok = buckets_xml_unescape(d->nodes[node].text, &b);
  snprintf(out, cap, "%s", b.data ? b.data : "");
  buckets_buf_free(&b);
  return ok;
}

bool buckets_sse_config_parse(const char *xml, size_t len, buckets_sse_config *out, char *err, size_t errlen) {
  memset(out, 0, sizeof(*out));
  buckets_xml_doc d = {0};
  if (!memchr(xml, '<', len)) {
    snprintf(err, errlen, "EOF");
    return false;
  }
  if (!buckets_xml_parse((buckets_str){xml, len}, &d)) {
    if (d.nodes) buckets_xml_doc_free(&d);
    snprintf(err, errlen, "XML syntax error");
    return false;
  }
  if (!buckets_str_eq_c(d.nodes[0].name, "ServerSideEncryptionConfiguration")) {
    snprintf(err, errlen, "expected element type <ServerSideEncryptionConfiguration> but have <%.*s>",
             (int)BUCKETS_MIN(d.nodes[0].name.n, 64), d.nodes[0].name.p);
    buckets_xml_doc_free(&d);
    return false;
  }
  buckets_xml_root_xmlns((buckets_str){xml, len}, out->xmlns, sizeof(out->xmlns));
  size_t rules = 0;
  bool ok = true;
  for (size_t r = d.nodes[0].first_child; r && ok; r = d.nodes[r].next_sibling) {
    if (!buckets_str_eq_c(d.nodes[r].name, "Rule")) continue;
    rules++;
    size_t a = buckets_xml_child(&d, r, "ApplyServerSideEncryptionByDefault");
    char alg[64] = "", key[256] = "";
    for (size_t f = a ? d.nodes[a].first_child : 0; f && ok; f = d.nodes[f].next_sibling) {
      if (buckets_str_eq_c(d.nodes[f].name, "SSEAlgorithm")) {
        ok = text_of(&d, f, alg, sizeof(alg));
        if (ok && strcmp(alg, "AES256") != 0 && strcmp(alg, "aws:kms") != 0) {
          snprintf(err, errlen, "Unknown SSE algorithm");
          ok = false;
        }
      } else if (buckets_str_eq_c(d.nodes[f].name, "KMSMasterKeyID")) {
        ok = text_of(&d, f, key, sizeof(key));
      }
    }
    snprintf(out->algorithm, sizeof(out->algorithm), "%s", alg); /* the last rule wins (a single one is allowed) */
    snprintf(out->key_id, sizeof(out->key_id), "%s", key);
  }
  buckets_xml_doc_free(&d);
  if (!ok) return false;
  if (rules != 1) {
    snprintf(err, errlen, "only one server-side encryption rule is allowed at a time");
    return false;
  }
  if (strcmp(out->algorithm, "AES256") == 0 && out->key_id[0]) {
    snprintf(err, errlen, "MasterKeyID is allowed with aws:kms only");
    return false;
  }
  if (strcmp(out->algorithm, "aws:kms") == 0) {
    size_t kl = strlen(out->key_id);
    if (!kl) {
      snprintf(err, errlen, "MasterKeyID is missing with aws:kms");
      return false;
    }
    if (out->key_id[0] == ' ' || out->key_id[kl - 1] == ' ') {
      snprintf(err, errlen, "MasterKeyID contains unsupported characters");
      return false;
    }
  }
  if (!out->xmlns[0]) snprintf(out->xmlns, sizeof(out->xmlns), "%s", BUCKETS_S3_XMLNS);
  return true;
}

void buckets_sse_config_xml(const buckets_sse_config *c, buckets_buf *out) {
  if (c->xmlns[0]) buckets_xml_open_ns(out, "ServerSideEncryptionConfiguration", c->xmlns);
  else buckets_xml_open(out, "ServerSideEncryptionConfiguration");
  buckets_xml_open(out, "Rule");
  buckets_xml_open(out, "ApplyServerSideEncryptionByDefault");
  if (c->algorithm[0]) buckets_xml_elem(out, "SSEAlgorithm", c->algorithm);
  if (c->key_id[0]) buckets_xml_elem(out, "KMSMasterKeyID", c->key_id);
  buckets_xml_close(out, "ApplyServerSideEncryptionByDefault");
  buckets_xml_close(out, "Rule");
  buckets_xml_close(out, "ServerSideEncryptionConfiguration");
}

const char *buckets_sse_config_key(const buckets_sse_config *c) {
  return strncmp(c->key_id, ARN_PREFIX, strlen(ARN_PREFIX)) == 0 ? c->key_id + strlen(ARN_PREFIX) : c->key_id;
}
