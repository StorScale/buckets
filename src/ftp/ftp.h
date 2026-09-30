/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_FTP_FTP_H
#define BUCKETS_FTP_FTP_H

/* The FTP server (--ftp, MinIO's ftp-server.go on goftp.io/server): the
 * buckets as directories, over plain FTP or explicit FTPS (AUTH TLS), with
 * passive and active data connections. Replies are goftp's, word for word. */

#include <stdbool.h>
#include <stddef.h>

typedef struct {
  int port;        /* 8021 when not given */
  char *public_ip; /* the address's host: the passive mode address */
  char *port_range;
  char *key, *cert;
  bool force_tls;
} buckets_ftp_opts;

/* The --ftp key=value arguments; false with err as MinIO's fatal message. */
bool buckets_ftp_parse(char *const *args, size_t n, buckets_ftp_opts *o, char *err, size_t errlen);
/* Starts serving (a thread per session). s3_tls/certs_dir: the S3 API's
 * certificate, used when --ftp gives none. */
bool buckets_ftp_start(buckets_ftp_opts *o, bool s3_tls, const char *certs_dir, char *err, size_t errlen);

#endif
