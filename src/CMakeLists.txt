# libbuckets: everything except main(), so tests and fuzzers link the same code.
# The commit metrics report (minio_software_commit_info), as MinIO's CommitID.
execute_process(COMMAND git rev-parse HEAD WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
                OUTPUT_VARIABLE BUCKETS_COMMIT OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
if(NOT BUCKETS_COMMIT)
  set(BUCKETS_COMMIT "DEVELOPMENT.GOGET")
endif()

add_library(buckets STATIC
  core/common.c
  core/str.c
  core/buf.c
  core/zipwrite.c
  core/prof.c
  core/log.c
  core/timefmt.c
  core/yaml.c
  core/wpool.c
  batch/job.c
  core/zip.c
  core/query.c
  core/uuid.c
  core/loop.c
  core/mime.c
  core/msgpack.c
  core/pool.c
  crypto/sha256.c
  crypto/fips.c
  crypto/md5.c
  crypto/hex.c
  crypto/base64.c
  crypto/highwayhash.c
  crypto/xxhash.c
  crypto/crc.c
  crypto/sha1.c
  crypto/cksum.c
  crypto/siphash.c
  crypto/madmin.c
  crypto/aead.c
  crypto/dare.c
  crypto/estream.c
  crypto/objkey.c
  kms/kms.c
  kms/kesutil.c
  kes/key.c
  kes/store.c
  kes/vault.c
  kes/aws.c
  kes/azure.c
  kes/gcp.c
  kes/server.c
  k8s/kube.c
  kms/cfgcrypt.c
  compress/s2.c
  compress/stream.c
  select/value.c
  select/json.c
  select/sql.c
  select/eval.c
  select/csv.c
  select/parquet.c
  select/select.c
  notify/event.c
  notify/target.c
  notify/targets.c
  notify/webhook.c
  notify/redis.c
  notify/nsq.c
  notify/nats.c
  notify/mqtt.c
  notify/elasticsearch.c
  notify/postgres.c
  notify/mysql.c
  notify/amqp.c
  notify/kafka.c
  notify/nkeys.c
  notify/xnet.c
  notify/notifier.c
  metrics/expo.c
  metrics/stats.c
  metrics/sys.c
  s3/metrics.c
  s3/audit.c
  s3/tracehttp.c
  trace/trace.c
  logger/httptarget.c
  logger/kafkatarget.c
  logger/logger.c
  logger/console.c
  core/auditctx.c
  s3/apiname.c
  console/console.c
  console/kmsconfig.c
  console/idpconfig.c
  console/teams.c
  console/access.c
  net/http.c
  net/tls.c
  net/client.c
  net/conn.c
  net/kafka.c
  net/fetch.c
  net/s3client.c
  net/ldap.c
  s3/errors.c
  s3/errors_gen.c
  s3/xml.c
  s3/zipindex.c
  s3/lambda.c
  s3/veeam.c
  s3/replicate.c
  s3/replstats.c
  s3/tiering.c
  s3/batch.c
  s3/datamove.c
  s3/replhandlers.c
  s3/sigv4.c
  s3/sign.c
  s3/sigv2.c
  s3/bucketname.c
  s3/server.c
  s3/objects.c
  s3/chunked.c
  s3/checksum.c
  s3/postpolicy.c
  storage/drive.c
  storage/drivestats.c
  storage/osmetrics.c
  storage/xlmeta.c
  storage/format.c
  storage/remote.c
  storage/health.c
  dist/internode.c
  dist/storage_server.c
  dist/dsync.c
  dist/peer.c
  dist/peerstream.c
  dist/endpoint.c
  object/erasure.c
  object/nslock.c
  object/pools.c
  bucket/replication.c
  bucket/targets.c
  bucket/metadata.c
  bucket/metasys.c
  bucket/versioning.c
  bucket/tags.c
  bucket/quota.c
  bucket/lifecycle.c
  bucket/notification.c
  bucket/sseconfig.c
  bucket/objectlock.c
  erasure/rs.c
  erasure/layout.c
  heal/healer.c
  scanner/scanner.c
  scanner/scantrace.c
  scanner/usage.c
  scanner/compliance.c
  usage/history.c
  usage/store.c
  ransomware/ransomware.c
  s3/ransomguard.c
  iam/policy.c
  iam/iam.c
  iam/openid.c
  iam/idpsettings.c
  iam/teams.c
  iam/access.c
  iam/ldapidp.c
  iam/idsync.c
  iam/plugins.c
  crypto/jwt.c
  crypto/jwk.c
  core/strmap.c
  object/sysconfig.c
  s3/auth.c
  s3/sts.c
  s3/objectlock.c
  s3/tagging.c
  s3/lifecycle.c
  s3/sse.c
  s3/compress.c
  s3/notification.c
  admin/admin.c
  admin/bucketmeta.c
  admin/heal.c
  admin/health.c
  admin/info.c
  admin/inspect.c
  admin/jobstream.c
  admin/perf.c
  admin/profile.c
  admin/locks.c
  admin/netperf.c
  admin/rtmetrics.c
  ftp/s3fs.c
  ftp/ftp.c
  ftp/sftp.c
  ftp/sshcert.c
  admin/config.c
  admin/iamxfer.c
  admin/bucket.c
  admin/compliance.c
  admin/usage.c
  admin/incidents.c
  admin/replicate.c
  admin/siterepl.c
  admin/tier.c
  admin/batch.c
  admin/pools.c
  siterepl/siterepl.c
  siterepl/srstatus.c
  tier/tier.c
  tier/warm.c
  tier/azure.c
  tier/gcs.c
  admin/kms.c
  config/config.c
  config/sys.c
)
target_include_directories(buckets PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
# timegm, gmtime_r, arc4random_buf, strncasecmp live outside strict C17.
target_compile_definitions(buckets PUBLIC _GNU_SOURCE _DARWIN_C_SOURCE
  BUCKETS_VERSION="${PROJECT_VERSION}"
  BUCKETS_COMMIT="${BUCKETS_COMMIT}")
find_package(Threads REQUIRED)
find_library(RESOLV_LIB resolv)
if(RESOLV_LIB)
  target_link_libraries(buckets PUBLIC ${RESOLV_LIB})
endif()
target_link_libraries(buckets PUBLIC llhttp::llhttp yyjson libdeflate::libdeflate_static buckets_libyaml
  buckets_zlib buckets_bzip2 buckets_zstd buckets_lz4 buckets_libssh OpenSSL::SSL OpenSSL::Crypto Threads::Threads)
find_library(MATH_LIB m) # glibc keeps libm apart (macOS has it in libSystem)
if(MATH_LIB)
  target_link_libraries(buckets PUBLIC ${MATH_LIB})
endif()
buckets_warnings(buckets)

add_executable(bucketsd cmd/bucketsd/main.c)
target_link_libraries(bucketsd PRIVATE buckets)
buckets_warnings(bucketsd)
install(TARGETS bucketsd RUNTIME DESTINATION bin)

add_executable(consoled cmd/consoled/main.c)
target_link_libraries(consoled PRIVATE buckets)

add_executable(buckets-kes cmd/buckets-kes/main.c)
target_link_libraries(buckets-kes PRIVATE buckets)
buckets_warnings(consoled)
install(TARGETS consoled RUNTIME DESTINATION bin)
