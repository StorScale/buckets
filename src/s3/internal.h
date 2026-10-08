/* Shared state for S3 request handlers (not part of the public API).
 * SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_S3_INTERNAL_H
#define BUCKETS_S3_INTERNAL_H

#include "bucket/notification.h"
#include "core/auditctx.h"
#include "core/query.h"
#include "iam/iam.h"
#include "net/http.h"
#include "object/object.h"
#include "s3/errors.h"
#include "s3/server.h"
#include "s3/sigv4.h"

/* Same canonical owner MinIO reports (globalMinioDefaultOwnerID). */
#define BUCKETS_S3_OWNER_ID "02d6176db174dc93cb1b899f7c6078f08654445fe8cf1b6ce98d8855f66bdbf4"
#define BUCKETS_S3_OWNER_NAME "buckets"
/* MinIO's globalMaxObjectSize. */
#define BUCKETS_S3_MAX_OBJECT_SIZE (5LL * 1024 * 1024 * 1024 * 1024)
/* Largest request document (XML) read into memory. */
#define BUCKETS_S3_MAX_DOC_SIZE (4 * 1024 * 1024)

typedef struct s3_conds s3_conds;

typedef struct {
  buckets_s3_server *s;
  const buckets_http_request *req;
  buckets_http_response *resp;
  buckets_query q;
  char request_id[33];
  char *path;   /* decoded request path */
  char *bucket; /* decoded, NULL at service level */
  char *object; /* decoded, NULL at bucket level */
  /* Bucket and key reported in error documents from here on, when set (MinIO's
   * checkRequestAuthType rewrites them, e.g. to a copy source). Owned. */
  char *err_bucket, *err_object;
  const char *err_message; /* the next error document's message instead of the code's (static text) */
  char access_key[256];
  buckets_auth_type auth;
  buckets_sigv4_result sig; /* valid for SigV4-authenticated requests */
  buckets_buf doc;          /* request document, when read via buckets_s3_read_doc */
  buckets_iam_ident *ident; /* the authenticated credential; NULL = anonymous */
  bool owner;               /* root, or root-derived without a session policy */
  s3_conds *conds;          /* policy condition values, built on first use */
  buckets_iam_key_status key_status; /* from the signature's key lookup */
  const char *op_name; /* admin/STS handler name for trace ("ServerInfo"), when not an S3 API */
  /* audit (only while audit targets exist) */
  bool audited;
  buckets_audit_tags tags;       /* the object layer's operations */
  buckets_buf audit_objects;     /* DeleteObjects: the objects, as JSON array elements */
  char *audit_tagging;           /* the object's tags, as MinIO sets them into the request's X-Amz-Tagging (audit, trace) */
} s3_ctx;

/* ---- STS (sts.c) ---- */
/* POST / with a form body and no query: MinIO's STS route. */
bool buckets_sts_matches(const s3_ctx *c);
void buckets_sts_handle(s3_ctx *c);

/* ---- authorization (auth.c) ---- */
/* IAMSys.IsAllowed with this request's condition values (anonymous
 * requests: the bucket policy). */
bool buckets_s3_allowed(s3_ctx *c, const char *action, const char *bucket, const char *object, bool deny_only);
/* authorizeRequest: also DeleteObjectVersion (deny-only) for versioned
 * deletes, and ListBucket standing in for ListBucketVersions. */
buckets_s3_error buckets_s3_authorize(s3_ctx *c, const char *action, const char *bucket, const char *object,
                                      const char *version_id);
/* Whether the bucket policy alone allows action to an anonymous caller. */
bool buckets_s3_bucket_policy_allows(s3_ctx *c, const char *action, const char *bucket, const char *object);
/* buckets_s3_authorize, writing the error response when denied. */
bool buckets_s3_require(s3_ctx *c, const char *action, const char *bucket, const char *object, const char *version_id);
/* Sets one condition value (e.g. object-lock keys for retention checks). */
void buckets_s3_cond_override(s3_ctx *c, const char *key, const char *value);
void buckets_s3_conds_free(s3_conds *cs);

/* handlers.GetSourceIP: X-Forwarded-For, X-Real-Ip, Forwarded, else the peer. */
void buckets_s3_source_ip(const buckets_http_request *req, char *out, size_t cap);

/* ---- event notifications (notification.c) ---- */
void buckets_s3_get_notification(s3_ctx *c);
void buckets_s3_put_notification(s3_ctx *c);
void buckets_s3_listen_notification(s3_ctx *c);
/* sendEvent for an object (oi may be NULL: removals, bucket events). */
/* The request's credential, for reports and alerts: its access key ("" when anonymous), the person behind it, and
 * "root", "user", "access-key", "sts" or "anonymous". */
void buckets_s3_credential(const s3_ctx *c, const char **access_key, const char **user, const char **type);
/* Whether audit entries are built: for the local copy (audit/store.h) or an audit target. */
bool buckets_s3_audit_wanted(buckets_s3_server *s);
/* A protection change on c->bucket for ransomware alerts (ransomware/ransomware.h: buckets_rw_change), by the
 * request's credential; detail in words. */
void buckets_s3_protection_removed(s3_ctx *c, int change, const char *detail);
void buckets_s3_send_event(s3_ctx *c, int event_name, const char *bucket, const char *object, const buckets_object_info *oi,
                           const char *version_id);
/* As MinIO's handlers that send the event before writing the response
 * (PutObject, a no-op delete): no content-length element. */
void buckets_s3_send_event_early(s3_ctx *c, int event_name, const char *bucket, const char *object,
                                 const buckets_object_info *oi, const char *version_id);
/* An event without a request (lifecycle expiry): no request parameters,
 * this node as the source host. */
/* The index (metrics/stats.h) of the MinIO API route the request takes, or
 * -1 when it takes none (admin, STS, health, unroutable). */
/* Serves /minio/v2/metrics/... and /minio/metrics/v3... (authenticating as
 * MinIO's AuthMiddleware); false when the request is not one of them. */
bool buckets_s3_metrics_handle(s3_ctx *c);
/* The request's audit entry to the audit targets, when there are any:
 * api is its route (metrics/stats.h), with its time to first byte, time to
 * response and body bytes sent. */
void buckets_s3_audit(s3_ctx *c, int api, int64_t ttfb_ns, int64_t ttr_ns, uint64_t tx);
/* buckets_audit_internal_fn, ud the server */
void buckets_s3_audit_internal(void *ud, const char *event, const char *api_name, const char *bucket, const char *object,
                               const char *version_id, const char *error, const char *const *keys,
                               const char *const *values, size_t ntags);
/* The request's trace record to trace subscribers, when there are any:
 * start and end (unix ns), time to first byte and body bytes sent. */
void buckets_s3_trace_http(s3_ctx *c, int api, int64_t start_ns, int64_t end_ns, int64_t ttfb_ns, uint64_t tx);
int buckets_s3_api_index(const s3_ctx *c);
/* A ransomware alerts incident's event (s3:Buckets:*) to the bucket's targets: no object, its details as the
 * record's metadata, the credential as principal. */
struct buckets_event_kv;
void buckets_s3_send_incident_event(buckets_s3_server *s, int event_name, const char *bucket, const char *principal,
                                    const struct buckets_event_kv *details, size_t ndetails);
void buckets_s3_send_internal_event(buckets_s3_server *s, int event_name, const char *bucket, const char *object,
                                    const buckets_object_info *oi, const char *version_id, const char *user_agent);

/* The bucket's versioning as it applies to object (PrefixEnabled / PrefixSuspended). */
void buckets_s3_versioning(s3_ctx *c, const char *object, bool *enabled, bool *suspended);
/* x-amz-version-id for a version other than "null" (setPutObjHeaders). */
void buckets_s3_version_header(s3_ctx *c, const char *version_id);
/* An error with a code outside the generated table (APIError literals). */
/* NotImplemented for MinIO's rejected APIs: no bucket or key in the document. */
void buckets_s3_write_rejected(s3_ctx *c);
void buckets_s3_write_custom_error(s3_ctx *c, int status, const char *code, const char *message);
void buckets_s3_write_error(s3_ctx *c, buckets_s3_error e);
void buckets_s3_write_error_msg(s3_ctx *c, buckets_s3_error e, const char *message);
void buckets_s3_write_xml(s3_ctx *c, int status);
buckets_s3_error buckets_s3_obj_error(buckets_obj_err e);
/* Reads a (small) request body into c->doc and checks its payload hash and
 * Content-MD5. Object uploads verify inside the object layer instead. */
buckets_s3_error buckets_s3_read_doc(s3_ctx *c);
/* SCIM 2.0 (s3/scimhandlers.c): the endpoint under /minio/scim/v2/, and whether it is on. */
void buckets_scim_handle(s3_ctx *c);
bool buckets_scim_enabled(void);
const char *buckets_scim_op_name(int i);
const char *buckets_scim_result_name(int i);
/* validateLengthAndChecksum + read: Content-MD5 or x-amz-checksum-* required and verified. */
buckets_s3_error buckets_s3_read_checked_doc(s3_ctx *c);

/* enforceBucketQuotaHard: false (with the error written) when writing size
 * more bytes to bucket would exceed its hard quota. */
bool buckets_s3_enforce_quota(s3_ctx *c, const char *bucket, int64_t size);

/* ---- replication (replhandlers.c) ---- */
/* What a write carries for incoming replication (putOpts / delOpts). */
typedef struct {
  bool request;      /* X-Minio-Source-Replication-Request */
  bool replica;      /* X-Amz-Replication-Status: REPLICA */
  bool has_vid;      /* PUT ?versionId= */
  char version_id[37];
  int64_t mtime_ns;  /* X-Minio-Source-Mtime, 0 when absent */
  char etag[256];    /* X-Minio-Source-Etag */
  bool delete_marker; /* X-Minio-Source-Deletemarker: true */
} buckets_s3_repl_in;
struct buckets_repl_dsc_s;
bool buckets_s3_repl_request(s3_ctx *c);
bool buckets_s3_repl_replica(s3_ctx *c);
/* Parses and authorizes (s3:ReplicateObject / ReplicateDelete for replicas);
 * writes the error and returns false on failure. */
bool buckets_s3_repl_in_parse(s3_ctx *c, const char *object, bool put, buckets_s3_repl_in *ri);
/* A replica's metadata: its REPLICA status and when it arrived. */
void buckets_s3_repl_in_meta(s3_ctx *c, const buckets_s3_repl_in *ri, buckets_xl_kv **meta, size_t *n);
/* mustReplicate for a new version: marks it pending (into meta) and fills dsc. */
void buckets_s3_repl_out_meta(s3_ctx *c, const char *object, buckets_xl_kv **meta, size_t *n, bool request,
                              struct buckets_repl_dsc_s *dsc);
/* In a metadata edit of c->object's version: mustReplicate(Metadata) on
 * the edited metadata; marks the version pending (into sys). tags: the
 * tags the decision sees (NULL: those in user). */
void buckets_s3_repl_meta_edit(s3_ctx *c, buckets_xl_kv **user, size_t *nuser, buckets_xl_kv **sys, size_t *nsys,
                               const char *tags, struct buckets_repl_dsc_s *dsc);
bool buckets_s3_is_local_endpoint(buckets_s3_server *s, const char *endpoint);
void buckets_s3_put_bucket_replication(s3_ctx *c);
void buckets_s3_get_bucket_replication(s3_ctx *c);
void buckets_s3_delete_bucket_replication(s3_ctx *c);
void buckets_s3_reset_bucket_replication_start(s3_ctx *c);
void buckets_s3_reset_bucket_replication_status(s3_ctx *c);
void buckets_s3_get_bucket_replication_metrics(s3_ctx *c, bool v2);
void buckets_s3_validate_replication_creds(s3_ctx *c);

/* ---- lifecycle (lifecycle.c) ---- */
void buckets_s3_put_bucket_lifecycle(s3_ctx *c);
void buckets_s3_get_bucket_lifecycle(s3_ctx *c);
void buckets_s3_delete_bucket_lifecycle(s3_ctx *c);
/* x-amz-expiration (or x-minio-transition) for an object, from the bucket's lifecycle. */
void buckets_s3_expiration_header(s3_ctx *c, const buckets_object_info *oi);
/* enqueueTransitionImmediate: a just-written version whose transition is already due. */
void buckets_s3_transition_immediate(s3_ctx *c, const buckets_object_info *oi);
/* ObjectInfo.StorageClass: a transitioned version's tier, else the stored class or STANDARD. */
const char *buckets_s3_storage_class(const buckets_object_info *oi);
/* Veeam SOS (veeam.c): the virtual system.xml and capacity.xml objects. */
bool buckets_s3_is_veeam_object(const char *object);
/* The object's body and its ETag; false for any other name. */
bool buckets_s3_veeam_object(s3_ctx *c, const char *bucket, const char *object, buckets_buf *out, char etag[33]);
/* filterStorageClass: _MINIO_VEEAM_FORCE_SC for Veeam clients. */
const char *buckets_s3_filter_storage_class(s3_ctx *c, const char *sc);

/* ---- tagging (tagging.c) ---- */
/* Writes the S3 error for a tags parse error (buckets_tags_error). */
void buckets_s3_write_tags_error(s3_ctx *c, const void *tags_error);
/* Validates X-Amz-Tagging when present; writes the error and returns false. */
bool buckets_s3_check_tagging_header(s3_ctx *c);
/* Number of tags in a stored X-Amz-Tagging value (0 when unparsable). */
int buckets_s3_tag_count(const char *user_tags);
void buckets_s3_get_object_tagging(s3_ctx *c);
void buckets_s3_put_object_tagging(s3_ctx *c);
void buckets_s3_delete_object_tagging(s3_ctx *c);
void buckets_s3_get_bucket_tagging(s3_ctx *c);
void buckets_s3_put_bucket_tagging(s3_ctx *c);
void buckets_s3_delete_bucket_tagging(s3_ctx *c);

/* ---- object lock (objectlock.c) ---- */
/* checkPutObjectLockAllowed: the retention and legal hold a write gets (from
 * its headers or the bucket's default retention), added to meta. */
buckets_s3_error buckets_s3_lock_put_meta(s3_ctx *c, const char *object, buckets_xl_kv **meta, size_t *nmeta);
/* enforceRetentionBypassForDelete for removing a version by ID. */
buckets_s3_error buckets_s3_lock_check_delete(s3_ctx *c, const char *object, const char *version_id);
/* FilterObjectLockMetadata: drops lock metadata the caller may not read. */
void buckets_s3_lock_filter_meta(s3_ctx *c, buckets_object_info *oi);
void buckets_s3_put_object_retention(s3_ctx *c);
void buckets_s3_get_object_retention(s3_ctx *c);
void buckets_s3_put_object_legal_hold(s3_ctx *c);
void buckets_s3_get_object_legal_hold(s3_ctx *c);
void buckets_s3_put_bucket_object_lock(s3_ctx *c);
void buckets_s3_get_bucket_object_lock(s3_ctx *c);

/* Object-level handlers (s3/objects.c). */
void buckets_s3_route_object(s3_ctx *c);
void buckets_s3_list_objects(s3_ctx *c, bool v2);
void buckets_s3_list_object_versions(s3_ctx *c);
void buckets_s3_delete_objects(s3_ctx *c);
void buckets_s3_list_uploads(s3_ctx *c);
void buckets_s3_write_private_acl(s3_ctx *c);
/* GetObject through an object lambda (?lambdaArn=). */
void buckets_s3_get_object_lambda(s3_ctx *c);
void buckets_s3_put_acl(s3_ctx *c);
void buckets_s3_post_policy(s3_ctx *c);
/* The signature verifiers' key lookup (ud: the s3_ctx): root, IAM users,
 * service accounts and STS. On success c->ident holds the credential. */
bool buckets_s3_lookup_secret(void *ud, buckets_str access_key, char secret[BUCKETS_SECRET_MAX]);
/* After signature verification: maps lookup failures (disabled key, IAM
 * not loaded) and validates the session token (checkClaimsFromToken). */
buckets_s3_error buckets_s3_check_credential(s3_ctx *c, buckets_s3_error verify_err, const char *form_token);

#endif
