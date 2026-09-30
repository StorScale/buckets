/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_CORE_MIME_H
#define BUCKETS_CORE_MIME_H

#include <stddef.h>

/* Go's mime.TypeByExtension over its built-in table ("" when unknown), and
 * net/http's DetectContentType (the WHATWG sniffing algorithm) over the
 * first 512 bytes of a body. */
const char *buckets_mime_by_ext(const char *name);
const char *buckets_mime_sniff(const void *data, size_t n);
/* minio/pkg mimedb.TypeByExtension: the type of an extension (".txt" or
 * "txt"), "application/octet-stream" when unknown. */
const char *buckets_mimedb_type(const char *ext);

#endif
