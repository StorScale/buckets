#!/usr/bin/env python3
"""Generate docs/parity.md: every API handler MinIO registers, and Buckets' status.

The route list is extracted from a MinIO checkout so nothing is forgotten; the
status of each handler is maintained in STATUS below and updated as features land.

usage: scripts/gen-parity.py ~/minio RELEASE.2025-10-15T17-29-55Z
"""
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DONE, PARTIAL = "done", "partial"

# handler -> (status, note). Anything absent is "todo".
STATUS = {
    # S3 (single drive; SSE, versioning, object lock, tagging arrive in later phases)
    "ListBucketsHandler": (DONE, ""),
    "PutBucketHandler": (DONE, ""),
    "HeadBucketHandler": (DONE, ""),
    "DeleteBucketHandler": (PARTIAL, "no x-minio-force-delete"),
    "GetBucketLocationHandler": (DONE, ""),
    "GetBucketVersioningHandler": (DONE, ""),
    "ListObjectsV1Handler": (DONE, ""),
    "ListObjectsV2Handler": (DONE, ""),
    "ListObjectsV2MHandler": (DONE, "metadata=true extension"),
    "PutObjectHandler": (PARTIAL, "no SSE/compression yet"),
    "GetObjectHandler": (PARTIAL, "no SSE/compression/zip-extract yet"),
    "HeadObjectHandler": (PARTIAL, "no SSE/compression yet"),
    "DeleteObjectHandler": (DONE, ""),
    "DeleteMultipleObjectsHandler": (DONE, ""),
    "CopyObjectHandler": (PARTIAL, "no SSE yet"),
    "CopyObjectPartHandler": (DONE, ""),
    "NewMultipartUploadHandler": (DONE, ""),
    "PutObjectPartHandler": (DONE, ""),
    "CompleteMultipartUploadHandler": (DONE, ""),
    "AbortMultipartUploadHandler": (DONE, ""),
    "ListObjectPartsHandler": (DONE, ""),
    "ListMultipartUploadsHandler": (DONE, "per-object listing, like MinIO"),
    "GetObjectAttributesHandler": (DONE, ""),
    "PostPolicyBucketHandler": (PARTIAL, "no SSE form fields yet"),
    "GetBucketACLHandler": (DONE, "canned private, as MinIO"),
    "PutBucketACLHandler": (DONE, "canned private, as MinIO"),
    "GetObjectACLHandler": (DONE, "canned private, as MinIO"),
    "PutObjectACLHandler": (DONE, "canned private, as MinIO"),
    "GetBucketPolicyHandler": (DONE, ""),
    "PutBucketPolicyHandler": (DONE, ""),
    "DeleteBucketPolicyHandler": (DONE, ""),
    # admin: IAM, config, service (Phase 4)
    "AddUser": (DONE, ""),
    "RemoveUser": (DONE, ""),
    "ListUsers": (DONE, ""),
    "GetUserInfo": (DONE, ""),
    "SetUserStatus": (DONE, ""),
    "UpdateGroupMembers": (DONE, ""),
    "GetGroup": (DONE, ""),
    "ListGroups": (DONE, ""),
    "SetGroupStatus": (DONE, ""),
    "ListCannedPolicies": (DONE, ""),
    "InfoCannedPolicy": (DONE, ""),
    "AddCannedPolicy": (DONE, ""),
    "RemoveCannedPolicy": (DONE, ""),
    "SetPolicyForUserOrGroup": (DONE, ""),
    "AttachDetachPolicyBuiltin": (DONE, ""),
    "ListPolicyMappingEntities": (DONE, ""),
    "AddServiceAccount": (DONE, ""),
    "UpdateServiceAccount": (DONE, ""),
    "InfoServiceAccount": (DONE, ""),
    "ListServiceAccounts": (DONE, ""),
    "DeleteServiceAccount": (DONE, ""),
    "ListAccessKeysBulk": (DONE, ""),
    "InfoAccessKey": (DONE, ""),
    "TemporaryAccountInfo": (DONE, ""),
    "RevokeTokens": (DONE, ""),
    "AccountInfoHandler": (PARTIAL, "usage and bucket feature details wait for the scanner and bucket metadata"),
    "ExportIAM": (DONE, ""),
    "ImportIAM": (DONE, ""),
    "ImportIAMV2": (DONE, ""),
    "AddServiceAccountLDAP": (DONE, ""),
    "AttachDetachPolicyLDAP": (DONE, ""),
    "ListAccessKeysLDAP": (DONE, ""),
    "ListAccessKeysLDAPBulk": (DONE, ""),
    "ListLDAPPolicyMappingEntities": (DONE, ""),
    "ListAccessKeysOpenIDBulk": (DONE, ""),
    "AddIdentityProviderCfg": (DONE, ""),
    "UpdateIdentityProviderCfg": (DONE, ""),
    "ListIdentityProviderCfg": (DONE, ""),
    "GetIdentityProviderCfg": (DONE, ""),
    "DeleteIdentityProviderCfg": (DONE, ""),
    "GetConfigKVHandler": (DONE, ""),
    "SetConfigKVHandler": (DONE, ""),
    "DelConfigKVHandler": (DONE, ""),
    "HelpConfigKVHandler": (DONE, ""),
    "ListConfigHistoryKVHandler": (DONE, ""),
    "ClearConfigHistoryKVHandler": (DONE, ""),
    "RestoreConfigHistoryKVHandler": (DONE, ""),
    "GetConfigHandler": (DONE, ""),
    "SetConfigHandler": (DONE, ""),
    "ServerInfoHandler": (PARTIAL, "usage figures wait for the scanner"),
    "ServiceHandler": (DONE, ""),
    "ServiceV2Handler": (DONE, ""),
    # STS
    "AssumeRole": (DONE, ""),
    "AssumeRoleWithSSO": (DONE, "WebIdentity and ClientGrants from a form body"),
    "AssumeRoleWithWebIdentity": (DONE, ""),
    "AssumeRoleWithClientGrants": (DONE, ""),
    "AssumeRoleWithLDAPIdentity": (DONE, ""),
    "AssumeRoleWithCertificate": (DONE, ""),
    "AssumeRoleWithCustomToken": (DONE, ""),
    # health
    "LivenessCheckHandler": (DONE, ""),
    "ReadinessCheckHandler": (DONE, ""),
    "ClusterCheckHandler": (DONE, "per-set write quorum"),
    "ClusterReadCheckHandler": (DONE, "per-set read quorum"),
    "PutBucketVersioningHandler": (DONE, ""),
    "ListObjectVersionsHandler": (DONE, ""),
    "ListObjectVersionsMHandler": (DONE, "metadata=true extension"),
    "GetBucketObjectLockConfigHandler": (DONE, ""),
    "PutBucketObjectLockConfigHandler": (DONE, ""),
    "GetObjectRetentionHandler": (DONE, ""),
    "PutObjectRetentionHandler": (DONE, ""),
    "GetObjectLegalHoldHandler": (DONE, ""),
    "PutObjectLegalHoldHandler": (DONE, ""),
    "GetObjectTaggingHandler": (DONE, ""),
    "PutObjectTaggingHandler": (DONE, ""),
    "DeleteObjectTaggingHandler": (DONE, ""),
    "GetBucketTaggingHandler": (DONE, ""),
    "PutBucketTaggingHandler": (DONE, ""),
    "DeleteBucketTaggingHandler": (DONE, ""),
    "GetBucketCorsHandler": (DONE, "dummy, as MinIO; CORS is the global api cors_allow_origin"),
    "PutBucketCorsHandler": (DONE, "dummy, as MinIO"),
    "DeleteBucketCorsHandler": (DONE, "dummy, as MinIO"),
    "GetBucketWebsiteHandler": (DONE, "dummy, as MinIO"),
    "DeleteBucketWebsiteHandler": (DONE, "dummy, as MinIO"),
    "GetBucketAccelerateHandler": (DONE, "dummy, as MinIO"),
    "GetBucketRequestPaymentHandler": (DONE, "dummy, as MinIO"),
    "GetBucketLoggingHandler": (DONE, "dummy, as MinIO"),
    "GetBucketPolicyStatusHandler": (DONE, ""),
    "GetBucketQuotaConfigHandler": (DONE, ""),
    "PutBucketQuotaConfigHandler": (PARTIAL, "enforced on object size alone until the scanner reports bucket usage"),
}

SOURCES = [
    ("S3 API", "cmd/api-router.go", r"api\.([A-Za-z0-9]+Handler)"),
    ("Admin API (madmin / mc admin)", "cmd/admin-router.go", r"adminAPI\.([A-Za-z0-9]+)"),
    ("STS", "cmd/sts-handlers.go", r"sts\.(AssumeRole[A-Za-z]*)\)"),
    ("KMS API", "cmd/kms-router.go", r"kmsAPI\.([A-Za-z0-9]+)"),
    ("Metrics", "cmd/metrics-router.go", r"(metricsHandler|metricsServerHandler|metricsNodeHandler|"
     r"metricsBucketHandler|metricsResourceHandler)\b"),
    ("Health", "cmd/healthcheck-router.go", r"([A-Za-z]+CheckHandler)"),
]

ICON = {DONE: "✅", PARTIAL: "🟡", "todo": "⬜"}


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    minio, ref = sys.argv[1], sys.argv[2]
    out = [
        "# Feature parity with MinIO",
        "",
        f"Generated by `scripts/gen-parity.py` from MinIO `{ref}`. Every handler MinIO",
        "registers is listed; statuses live in the script's `STATUS` table.",
        "",
        "✅ done · 🟡 partial · ⬜ not started",
        "",
    ]
    totals = {DONE: 0, PARTIAL: 0, "todo": 0}
    sections = []
    for title, path, pattern in SOURCES:
        src = subprocess.check_output(["git", "-C", minio, "show", f"{ref}:{path}"], text=True)
        names = sorted(set(re.findall(pattern, src)))
        rows = []
        for n in names:
            status, note = STATUS.get(n, ("todo", ""))
            totals[status] += 1
            rows.append(f"| {ICON[status]} | `{n}` | {note} |")
        done = sum(1 for n in names if STATUS.get(n, ("todo",))[0] == DONE)
        sections += [f"## {title} ({done}/{len(names)})", "", f"Source: `{path}`", "",
                     "| | Handler | Notes |", "|---|---|---|"] + rows + [""]
    total = sum(totals.values())
    out += [f"**Overall:** {totals[DONE]} done, {totals[PARTIAL]} partial, {totals['todo']} not started "
            f"({total} handlers).", ""]
    out += sections
    out += [
        "## Beyond the routers",
        "",
        "Subsystems with no single handler, tracked by phase in `docs/architecture.md`:",
        "erasure coding + bitrot, xl.meta v2, pools, distributed locking and healing (done), scanner usage/ILM, healing, scanner,",
        "ILM/tiering, bucket + site replication, notifications (10 targets), audit,",
        "SSE-S3/KMS/C, compression, S3 Select, SFTP/FTP, batch jobs, decommission/rebalance,",
        "operator, console (IAM with LDAP, OpenID, plugins and OPA is done).",
        "",
    ]
    with open(os.path.join(ROOT, "docs/parity.md"), "w") as f:
        f.write("\n".join(out))
    print(f"docs/parity.md: {totals[DONE]} done, {totals[PARTIAL]} partial, {total} total")


if __name__ == "__main__":
    main()
