/* Shared state for S3 request handlers (not part of the public API).
 * SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_S3_INTERNAL_H
#define BUCKETS_S3_INTERNAL_H

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
  char access_key[256];
  buckets_auth_type auth;
  buckets_sigv4_result sig; /* valid for SigV4-authenticated requests */
  buckets_buf doc;          /* request document, when read via buckets_s3_read_doc */
  buckets_iam_ident *ident; /* the authenticated credential; NULL = anonymous */
  bool owner;               /* root, or root-derived without a session policy */
  s3_conds *conds;          /* policy condition values, built on first use */
  buckets_iam_key_status key_status; /* from the signature's key lookup */
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
/* buckets_s3_authorize, writing the error response when denied. */
bool buckets_s3_require(s3_ctx *c, const char *action, const char *bucket, const char *object, const char *version_id);
/* Sets one condition value (e.g. object-lock keys for retention checks). */
void buckets_s3_cond_override(s3_ctx *c, const char *key, const char *value);
void buckets_s3_conds_free(s3_conds *cs);

void buckets_s3_write_error(s3_ctx *c, buckets_s3_error e);
void buckets_s3_write_error_msg(s3_ctx *c, buckets_s3_error e, const char *message);
void buckets_s3_write_xml(s3_ctx *c, int status);
buckets_s3_error buckets_s3_obj_error(buckets_obj_err e);
/* Reads a (small) request body into c->doc and checks its payload hash and
 * Content-MD5. Object uploads verify inside the object layer instead. */
buckets_s3_error buckets_s3_read_doc(s3_ctx *c);

/* Object-level handlers (s3/objects.c). */
void buckets_s3_route_object(s3_ctx *c);
void buckets_s3_list_objects(s3_ctx *c, bool v2);
void buckets_s3_delete_objects(s3_ctx *c);
void buckets_s3_list_uploads(s3_ctx *c);
void buckets_s3_write_private_acl(s3_ctx *c);
void buckets_s3_put_acl(s3_ctx *c);
void buckets_s3_post_policy(s3_ctx *c);
/* The signature verifiers' key lookup (ud: the s3_ctx): root, IAM users,
 * service accounts and STS. On success c->ident holds the credential. */
bool buckets_s3_lookup_secret(void *ud, buckets_str access_key, char secret[BUCKETS_SECRET_MAX]);
/* After signature verification: maps lookup failures (disabled key, IAM
 * not loaded) and validates the session token (checkClaimsFromToken). */
buckets_s3_error buckets_s3_check_credential(s3_ctx *c, buckets_s3_error verify_err, const char *form_token);

#endif
