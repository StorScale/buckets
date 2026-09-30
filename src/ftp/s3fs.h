/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_FTP_S3FS_H
#define BUCKETS_FTP_S3FS_H

/* The file system FTP and SFTP users see (MinIO's ftp-server-driver.go and
 * sftp-server-driver.go): buckets are the top-level directories, "/" in
 * keys separates directories. Every operation is an S3 request to this
 * server over loopback, signed with the user's own credentials, as MinIO
 * does with minio-go -- so policies, events, audit and quotas apply as for
 * any S3 client. Errors are Go's words for them (minio-go's messages). */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "core/buf.h"
#include "net/client.h"

struct buckets_s3_server;

typedef struct {
  char *name; /* the entry's name (the last path element, cleaned) */
  int64_t size;
  int64_t mtime_ns; /* 0: unknown (listed as 1980-01-01, FileZilla's floor) */
  bool dir;
} buckets_fs_info;

void buckets_fs_info_free(buckets_fs_info *fi, size_t n);

/* Loopback to this server's S3 API: host:port, TLS when secure. */
void buckets_fs_init(struct buckets_s3_server *s, int port, bool secure);

/* CheckPasswd: an IAM user (or root, or with LDAP a service account or an
 * LDAP bind whose user or groups have policies). false with err "" for a
 * wrong password; err set for a failure checking it. */
bool buckets_fs_check_password(const char *user, const char *password, char *err, size_t errlen);
/* The public key authentication of SFTP: a user whose ssh-public-keys
 * (IAM) or LDAP sshPublicKey attribute holds key (the wire form). */
bool buckets_fs_check_pubkey(const char *user, const uint8_t *key, size_t keylen, char *err, size_t errlen);

typedef struct buckets_fs buckets_fs;
/* The session of a logged-in user (getMinIOClient). NULL with err set:
 * "Specified user does not exist", "Authentication failed, ..." */
buckets_fs *buckets_fs_open(const char *user, const char *remote_ip, char *err, size_t errlen);
void buckets_fs_close(buckets_fs *fs);

/* The operations, returning false with err in Go's words. */
bool buckets_fs_stat(buckets_fs *fs, const char *path, buckets_fs_info *out, char *err, size_t errlen);
/* The entries of a directory (the buckets, for "/"), in minio-go's order:
 * per page of 1000, files then subdirectories. */
bool buckets_fs_list(buckets_fs *fs, const char *path, buckets_fs_info **out, size_t *n, char *err, size_t errlen);
bool buckets_fs_mkdir(buckets_fs *fs, const char *path, char *err, size_t errlen);
bool buckets_fs_rmdir(buckets_fs *fs, const char *path, char *err, size_t errlen);
bool buckets_fs_delete(buckets_fs *fs, const char *path, char *err, size_t errlen);

/* GetFile from offset: *size gets what is left to read. */
buckets_http_stream *buckets_fs_get(buckets_fs *fs, const char *path, int64_t offset, int64_t *size, char *err,
                                    size_t errlen);
/* PutFile of unknown length (minio-go's putObjectMultipartStreamNoLength:
 * parts of 528 MiB with CRC32C, a full-object checksum). *n gets the bytes
 * written. */
bool buckets_fs_put(buckets_fs *fs, const char *path, long (*rd)(void *ud, void *buf, size_t n), void *ud, int64_t *n,
                    char *err, size_t errlen);

/* path2BucketObject: "/b/k/x" -> "b", "k/x" (strings to free). */
void buckets_fs_split(const char *path, char **bucket, char **object);
/* path.Clean */
char *buckets_fs_clean(const char *path);

#endif
