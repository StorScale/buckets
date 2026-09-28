# libbuckets: everything except main(), so tests and fuzzers link the same code.
add_library(buckets STATIC
  core/common.c
  core/str.c
  core/buf.c
  core/log.c
  core/timefmt.c
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
  net/http.c
  net/tls.c
  net/client.c
  s3/errors.c
  s3/errors_gen.c
  s3/xml.c
  s3/sigv4.c
  s3/sigv2.c
  s3/bucketname.c
  s3/server.c
  s3/objects.c
  s3/chunked.c
  s3/checksum.c
  s3/postpolicy.c
  storage/drive.c
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
  erasure/rs.c
  erasure/layout.c
  heal/healer.c
  iam/policy.c
  iam/iam.c
  crypto/jwt.c
  core/strmap.c
  object/sysconfig.c
  s3/auth.c
  s3/sts.c
  admin/admin.c
)
target_include_directories(buckets PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
# timegm, gmtime_r, arc4random_buf, strncasecmp live outside strict C17.
target_compile_definitions(buckets PUBLIC _GNU_SOURCE _DARWIN_C_SOURCE
  BUCKETS_VERSION="${PROJECT_VERSION}")
find_package(Threads REQUIRED)
target_link_libraries(buckets PUBLIC llhttp::llhttp yyjson OpenSSL::SSL OpenSSL::Crypto Threads::Threads)
buckets_warnings(buckets)

add_executable(bucketsd cmd/bucketsd/main.c)
target_link_libraries(bucketsd PRIVATE buckets)
buckets_warnings(bucketsd)
install(TARGETS bucketsd RUNTIME DESTINATION bin)
