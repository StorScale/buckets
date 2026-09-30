/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_FTP_SSHCERT_H
#define BUCKETS_FTP_SSHCERT_H

/* OpenSSH user certificates (PROTOCOL.certkeys), checked as x/crypto/ssh's
 * CertChecker.Authenticate does for MinIO's trusted-user-ca-key: signed by
 * the CA (signature verified), a user certificate, valid now, naming the user
 * among its principals, with no critical option but source-address. */

#include <libssh/libssh.h>
#include <stdbool.h>

bool buckets_sshcert_trusted(ssh_key key, ssh_key ca, const char *user, const char *remote_ip);

#endif
