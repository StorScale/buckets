/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_FTP_SFTP_H
#define BUCKETS_FTP_SFTP_H

/* The SFTP server (--sftp, MinIO's sftp-server.go on x/crypto/ssh and
 * pkg/sftp's RequestServer), over libssh: the buckets as directories,
 * password and public key logins (IAM users, service accounts, LDAP with its
 * sshPublicKey attribute, certificates of a trusted user CA). */

#include <stdbool.h>
#include <stddef.h>

typedef struct {
  int port;        /* 8022 when not given */
  char *public_ip; /* the address's host */
  char *key_file;  /* ssh-private-key: the host key (mandatory) */
  char *pub_key_algos, *kex_algos, *cipher_algos, *mac_algos; /* libssh lists; NULL: MinIO's defaults */
  char *ca_file;   /* trusted-user-ca-key */
  bool no_password;
} buckets_sftp_opts;

/* The --sftp key=value arguments; false with err as MinIO's fatal message. */
bool buckets_sftp_parse(char *const *args, size_t n, buckets_sftp_opts *o, char *err, size_t errlen);
bool buckets_sftp_start(buckets_sftp_opts *o, char *err, size_t errlen);

#endif
