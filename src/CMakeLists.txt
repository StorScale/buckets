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
  core/log.c
  core/timefmt.c
  core/zip.c
  core/query.c
  core/uuid.c
  core/loop.c
  core/msgpack.c
  core/pool.c
  crypto/sha256.c
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
  crypto/objkey.c
  kms/kms.c
  compress/s2.c
  notify/event.c
  notify/target.c
  notify/targets.c
  notify/webhook.c
  notify/notifier.c
  metrics/expo.c
  metrics/stats.c
  metrics/sys.c
  s3/metrics.c
  s3/audit.c
  s3/tracehttp.c
  trace/trace.c
  logger/httptarget.c
  logger/logger.c
  logger/console.c
  core/auditctx.c
  s3/apiname.c
  console/console.c
  net/http.c
  net/tls.c
  net/client.c
  net/fetch.c
  net/ldap.c
  s3/errors.c
  s3/errors_gen.c
  s3/xml.c
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
  storage/xlmeta.c
  storage/format.c
  storage/remote.c
  dist/internode.c
  dist/storage_server.c
  dist/dsync.c
  dist/peer.c
  dist/endpoint.c
  object/erasure.c
  object/nslock.c
  object/pools.c
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
  scanner/usage.c
  iam/policy.c
  iam/iam.c
  iam/openid.c
  iam/ldapidp.c
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
  admin/info.c
  admin/config.c
  admin/iamxfer.c
  admin/bucket.c
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
target_link_libraries(buckets PUBLIC llhttp::llhttp yyjson libdeflate::libdeflate_static OpenSSL::SSL OpenSSL::Crypto Threads::Threads)
buckets_warnings(buckets)

add_executable(bucketsd cmd/bucketsd/main.c)
target_link_libraries(bucketsd PRIVATE buckets)
buckets_warnings(bucketsd)
install(TARGETS bucketsd RUNTIME DESTINATION bin)

add_executable(consoled cmd/consoled/main.c)
target_link_libraries(consoled PRIVATE buckets)
buckets_warnings(consoled)
install(TARGETS consoled RUNTIME DESTINATION bin)
