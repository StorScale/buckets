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

DONE, PARTIAL, DROPPED = "done", "partial", "dropped"

# handler -> (status, note). Anything absent is "todo".
STATUS = {
    # S3 (single drive; SSE, versioning, object lock, tagging arrive in later phases)
    "ListBucketsHandler": (DONE, ""),
    "PutBucketHandler": (DONE, ""),
    "HeadBucketHandler": (DONE, ""),
    "DeleteBucketHandler": (DONE, ""),
    "GetBucketLocationHandler": (DONE, ""),
    "GetBucketVersioningHandler": (DONE, ""),
    "ListObjectsV1Handler": (DONE, ""),
    "ListObjectsV2Handler": (DONE, ""),
    "ListObjectsV2MHandler": (DONE, "metadata=true extension"),
    "PutObjectHandler": (DONE, ""),
    "GetObjectHandler": (DONE, "files inside zip archives with x-minio-extract, as MinIO"),
    "HeadObjectHandler": (DONE, ""),
    "DeleteObjectHandler": (DONE, ""),
    "DeleteMultipleObjectsHandler": (DONE, ""),
    "CopyObjectHandler": (DONE, ""),
    "CopyObjectPartHandler": (DONE, ""),
    "NewMultipartUploadHandler": (DONE, ""),
    "PutObjectPartHandler": (DONE, ""),
    "CompleteMultipartUploadHandler": (DONE, ""),
    "AbortMultipartUploadHandler": (DONE, ""),
    "ListObjectPartsHandler": (DONE, ""),
    "ListMultipartUploadsHandler": (DONE, "per-object listing, like MinIO"),
    "GetObjectAttributesHandler": (DONE, ""),
    "PostPolicyBucketHandler": (DONE, ""),
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
    "ServerInfoHandler": (DONE, "no gc_stats (Go's); per-set usage is reported for single-set deployments"),
    "ServiceHandler": (DONE, ""),
    "HealHandler": (DONE, ""),
    "BackgroundHealStatusHandler": (DONE, ""),
    "StorageInfoHandler": (DONE, ""),
    "TopLocksHandler": (DONE, ""),
    "ForceUnlockHandler": (DONE, ""),
    "ExportBucketMetadataHandler": (DONE, ""),
    "ImportBucketMetadataHandler": (DONE, ""),
    "InspectDataHandler": (DONE, ""),
    "ObjectSpeedTestHandler": (DONE, "PUTs and GETs through the object layer rather than a loopback S3 client"),
    "NetperfHandler": (DONE, ""),
    "HealthInfoHandler": (DONE, "Linux data from /proc and /sys; elsewhere MinIO's own errors"),
    "StartProfilingHandler": (DONE, "pprof CPU samples (SIGPROF), heap in use, threads; block/mutex empty; trace empty"),
    "DownloadProfilingHandler": (DONE, ""),
    "ProfileHandler": (DONE, ""),
    "SitePerfHandler": (DONE, ""),
    "ClientDevNull": (DONE, ""),
    "ClientDevNullExtraTime": (DONE, ""),
    "SiteReplicationDevNull": (DONE, "unsigned requests are served only while site replication is on"),
    "SiteReplicationNetPerf": (DONE, "unsigned requests are served only while site replication is on"),
    "DriveSpeedtestHandler": (DONE, "dperf's O_DIRECT test on Linux, \"not implemented\" elsewhere, as dperf"),
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
    "PutBucketQuotaConfigHandler": (DONE, ""),
    "DataUsageInfoHandler": (DONE, ""),
    "PutBucketLifecycleHandler": (DONE, "expiry; transitions with tiering"),
    "GetBucketLifecycleHandler": (DONE, ""),
    "DeleteBucketLifecycleHandler": (DONE, ""),
    "PutBucketEncryptionHandler": (DONE, ""),
    "GetBucketEncryptionHandler": (DONE, ""),
    "DeleteBucketEncryptionHandler": (DONE, ""),
    "KMSStatusHandler": (DONE, "builtin KMS"),
    "KMSKeyStatusHandler": (DONE, "builtin KMS"),
    "KMSCreateKeyHandler": (DONE, "builtin KMS"),
    "KMSMetricsHandler": (DONE, "builtin KMS"),
    "KMSAPIsHandler": (DONE, "builtin KMS"),
    "KMSVersionHandler": (DONE, "builtin KMS"),
    "KMSListKeysHandler": (DONE, "builtin KMS"),
    # Phase 7: notifications, trace, logs, metrics
    "GetBucketNotificationHandler": (DONE, ""),
    "PutBucketNotificationHandler": (DONE, ""),
    "ListenNotificationHandler": (DONE, ""),
    "TraceHandler": (DONE, ""),
    "ConsoleLogHandler": (DONE, ""),
    "metricsHandler": (DONE, "v2 cluster"),
    "metricsNodeHandler": (DONE, "v2 node"),
    "metricsBucketHandler": (DONE, "v2 bucket"),
    "metricsResourceHandler": (DONE, "v2 resource"),
    "metricsServerHandler": (DONE, "v3"),
    # Phase 8: replication, tiering, batch jobs, pools
    "PutBucketReplicationConfigHandler": (DONE, ""),
    "GetBucketReplicationConfigHandler": (DONE, ""),
    "DeleteBucketReplicationConfigHandler": (DONE, ""),
    "GetBucketReplicationMetricsHandler": (DONE, ""),
    "GetBucketReplicationMetricsV2Handler": (DONE, ""),
    "ResetBucketReplicationStartHandler": (DONE, ""),
    "ResetBucketReplicationStatusHandler": (DONE, ""),
    "ValidateBucketReplicationCredsHandler": (DONE, ""),
    "SetRemoteTargetHandler": (DONE, ""),
    "ListRemoteTargetsHandler": (DONE, ""),
    "RemoveRemoteTargetHandler": (DONE, ""),
    "ReplicationDiffHandler": (DONE, ""),
    "ReplicationMRFHandler": (DONE, ""),
    "MetricsHandler": (PARTIAL, "batch jobs; the scanner, disk, OS, net, memory, CPU, RPC and runtime types are not reported yet"),
    "ListBucketUsers": (DONE, ""),
    "ListBucketPolicies": (DONE, ""),
    "AddTierHandler": (DONE, ""),
    "ListTierHandler": (DONE, ""),
    "EditTierHandler": (DONE, ""),
    "RemoveTierHandler": (DONE, ""),
    "VerifyTierHandler": (DONE, ""),
    "TierStatsHandler": (DONE, ""),
    "StartBatchJob": (DONE, ""),
    "ListBatchJobs": (DONE, ""),
    "BatchJobStatus": (DONE, ""),
    "DescribeBatchJob": (DONE, ""),
    "CancelBatchJob": (DONE, ""),
    "ListPools": (DONE, ""),
    "StatusPool": (DONE, ""),
    "StartDecommission": (DONE, ""),
    "CancelDecommission": (DONE, ""),
    "RebalanceStart": (DONE, ""),
    "RebalanceStatus": (DONE, ""),
    "RebalanceStop": (DONE, ""),
    "SiteReplicationAdd": (DONE, ""),
    "SiteReplicationRemove": (DONE, ""),
    "SiteReplicationInfo": (DONE, ""),
    "SiteReplicationMetaInfo": (DONE, ""),
    "SiteReplicationStatus": (DONE, ""),
    "SiteReplicationEdit": (DONE, ""),
    "SiteReplicationResyncOp": (DONE, ""),
    "SRPeerJoin": (DONE, ""),
    "SRPeerBucketOps": (DONE, ""),
    "SRPeerReplicateIAMItem": (DONE, ""),
    "SRPeerReplicateBucketItem": (DONE, ""),
    "SRPeerGetIDPSettings": (DONE, ""),
    "SRPeerEdit": (DONE, ""),
    "SRPeerRemove": (DONE, ""),
    "SRStateEdit": (DONE, ""),
    "PutObjectExtractHandler": (DONE, "snowball tar archives: plain, gzip, bzip2, zstd, lz4, s2"),
    "PostRestoreObjectHandler": (DONE, "restores from any tier; SELECT restores answer as MinIO's (an output path, nothing written)"),
    # Phase 9
    "GetObjectLambdaHandler": (DONE, "lambda_webhook targets; client certificates not yet"),
    "SelectObjectContentHandler": (DONE, "CSV, JSON and Parquet (MINIO_API_SELECT_PARQUET); every input compression"),
    # dropped on purpose (docs/architecture.md): Kubernetes rolls images
    "ServerUpdateHandler": (DROPPED, "self-update; the operator rolls images"),
    "ServerUpdateV2Handler": (DROPPED, "self-update; the operator rolls images"),
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

ICON = {DONE: "✅", PARTIAL: "🟡", DROPPED: "➖", "todo": "⬜"}


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
        "✅ done · 🟡 partial · ⬜ not started · ➖ dropped on purpose",
        "",
    ]
    totals = {DONE: 0, PARTIAL: 0, DROPPED: 0, "todo": 0}
    sections = []
    for title, path, pattern in SOURCES:
        src = subprocess.check_output(["git", "-C", minio, "show", f"{ref}:{path}"], text=True)
        names = sorted(set(re.findall(pattern, src)))
        rows = []
        for n in names:
            status, note = STATUS.get(n, ("todo", ""))
            totals[status] += 1
            rows.append(f"| {ICON[status]} | `{n}` | {note} |")
        done = sum(1 for n in names if STATUS.get(n, ("todo",))[0] in (DONE, DROPPED))
        sections += [f"## {title} ({done}/{len(names)})", "", f"Source: `{path}`", "",
                     "| | Handler | Notes |", "|---|---|---|"] + rows + [""]
    total = sum(totals.values())
    out += [f"**Overall:** {totals[DONE]} done, {totals[PARTIAL]} partial, {totals['todo']} not started, "
            f"{totals[DROPPED]} dropped ({total} handlers).", ""]
    out += sections
    # "Beyond the routers" onwards is written by hand; keep it.
    path = os.path.join(ROOT, "docs/parity.md")
    with open(path) as f:
        old = f.read()
    k = old.find("## Beyond the routers")
    out += [old[k:].rstrip("\n"), ""] if k >= 0 else []
    with open(path, "w") as f:
        f.write("\n".join(out))
    print(f"docs/parity.md: {totals[DONE]} done, {totals[PARTIAL]} partial, {total} total")


if __name__ == "__main__":
    main()
