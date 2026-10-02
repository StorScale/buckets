/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_K8S_KUBE_H
#define BUCKETS_K8S_KUBE_H

#include <yyjson.h>

#include "core/buf.h"

/* A small Kubernetes REST client over bucketsd's HTTP/TLS client, for the
 * operator and the console. Objects are written with server-side apply, so
 * reconciling is a matter of sending the desired state.
 *
 * Configuration: in a pod, the service account (KUBERNETES_SERVICE_HOST and
 * /var/run/secrets/kubernetes.io/serviceaccount). Outside one:
 * BUCKETS_KUBE_API (https://host:port), BUCKETS_KUBE_TOKEN or
 * BUCKETS_KUBE_TOKEN_FILE, and BUCKETS_KUBE_CA (a CA bundle file). */
typedef struct kube kube;

kube *kube_from_env(char *err, size_t errlen);
void kube_free(kube *k);

/* Returns the HTTP status, 0 on a transport failure. *out gets the parsed
 * JSON response when out is non-NULL (NULL if there was none). */
int kube_request(kube *k, const char *method, const char *path, const char *content_type, const char *body,
                 size_t body_len, yyjson_doc **out);
int kube_get(kube *k, const char *path, yyjson_doc **out);
/* A plain-text GET (pod logs) into out. */
int kube_get_text(kube *k, const char *path, buckets_buf *out);
/* Server-side apply of an object (path is the object's own URL). */
int kube_apply(kube *k, const char *path, yyjson_mut_doc *obj, yyjson_doc **out);
/* JSON merge patch (RFC 7386) of an object. */
int kube_merge_patch(kube *k, const char *path, yyjson_mut_doc *patch, yyjson_doc **out);
/* Replaces an object (PUT): metadata.resourceVersion makes it conditional. */
int kube_update(kube *k, const char *path, yyjson_mut_doc *obj, yyjson_doc **out);
/* Server-side apply's field manager ("buckets-operator" by default). */
void kube_set_field_manager(kube *k, const char *name);
int kube_create(kube *k, const char *collection_path, yyjson_mut_doc *obj, yyjson_doc **out);
int kube_delete(kube *k, const char *path);
/* A message from a failed response (Status.message), for logs. */
const char *kube_error_message(yyjson_doc *doc);

#endif
