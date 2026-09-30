/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Veeam's Smart Object Storage API (veeam-sos-api.go): two virtual objects in
 * every bucket that tell Veeam Backup what the storage offers and how much of
 * it is left, and a storage-class override for Veeam clients. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bucket/metasys.h"
#include "bucket/quota.h"
#include "crypto/md5.h"
#include "s3/internal.h"

#define SOS_PREFIX ".system-d26a9498-cb7c-4a87-a44a-8ae204f5ba6c/"
#define VEEAM_AGENT "APN/1.0 Veeam/1.0"

bool buckets_s3_is_veeam_object(const char *object) {
  return strcmp(object, SOS_PREFIX "system.xml") == 0 || strcmp(object, SOS_PREFIX "capacity.xml") == 0;
}

static bool veeam_client(s3_ctx *c) {
  buckets_str ua = buckets_http_header_get(c->req, "User-Agent");
  size_t n = strlen(VEEAM_AGENT);
  for (size_t i = 0; ua.p && i + n <= ua.n; i++)
    if (memcmp(ua.p + i, VEEAM_AGENT, n) == 0) return true;
  return false;
}

/* filterStorageClass: Veeam 14 and later only know the standard classes. */
const char *buckets_s3_filter_storage_class(s3_ctx *c, const char *sc) {
  const char *force = getenv("_MINIO_VEEAM_FORCE_SC");
  if (force && *force && sc && strcmp(sc, "STANDARD") != 0 && strcmp(sc, "REDUCED_REDUNDANCY") != 0 && veeam_client(c))
    return force;
  return sc;
}

bool buckets_s3_veeam_object(s3_ctx *c, const char *bucket, const char *object, buckets_buf *out, char etag[33]) {
  if (strcmp(object, SOS_PREFIX "system.xml") == 0) {
    /* the quotes are Veeam's: xml.Marshal escapes them */
    buckets_buf_append_c(out, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                              "<SystemInfo><ProtocolVersion>&#34;1.0&#34;</ProtocolVersion>"
                              "<ModelName>&#34;Buckets " BUCKETS_VERSION "&#34;</ModelName>"
                              "<ProtocolCapabilities><CapacityInfo>true</CapacityInfo>"
                              "<UploadSessions>false</UploadSessions><IAMSTS>false</IAMSTS></ProtocolCapabilities>"
                              "<SystemRecommendations><KbBlockSize>4096</KbBlockSize></SystemRecommendations>"
                              "</SystemInfo>");
  } else if (strcmp(object, SOS_PREFIX "capacity.xml") == 0) {
    int64_t used = c->s->bucket_usage ? (int64_t)c->s->bucket_usage(c->s->bucket_usage_ud, bucket) : 0;
    int64_t capacity = 0;
    if (c->s->meta) {
      buckets_bucket_state *st = buckets_metasys_get(c->s->meta, bucket);
      if (st->has_quota) capacity = (int64_t)buckets_quota_hard_limit(&st->quota);
      buckets_bucket_state_release(st);
    }
    for (size_t p = 0; !capacity && c->s->layer && p < c->s->layer->npools; p++) {
      uint64_t ut, uf, rt, rf;
      buckets_objlayer_pool_space(c->s->layer, p, &ut, &uf, &rt, &rf);
      capacity += (int64_t)ut;
    }
    char x[256];
    snprintf(x, sizeof(x),
             "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<CapacityInfo><Capacity>%lld</Capacity>"
             "<Available>%lld</Available><Used>%lld</Used></CapacityInfo>",
             (long long)capacity, (long long)(capacity - used), (long long)used);
    buckets_buf_append_c(out, x);
  } else {
    return false;
  }
  uint8_t md[BUCKETS_MD5_LEN];
  buckets_md5(out->data, out->len, md);
  for (int i = 0; i < BUCKETS_MD5_LEN; i++) snprintf(etag + 2 * i, 3, "%02x", md[i]);
  return true;
}
