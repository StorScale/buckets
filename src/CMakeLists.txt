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
  crypto/sha256.c
  crypto/md5.c
  crypto/hex.c
  crypto/base64.c
  crypto/highwayhash.c
  crypto/xxhash.c
  crypto/crc.c
  crypto/sha1.c
  crypto/cksum.c
  net/http.c
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
  object/xlsingle.c
  object/multipart.c
  bucket/metadata.c
  erasure/rs.c
)
target_include_directories(buckets PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
# timegm, gmtime_r, arc4random_buf, strncasecmp live outside strict C17.
target_compile_definitions(buckets PUBLIC _GNU_SOURCE _DARWIN_C_SOURCE
  BUCKETS_VERSION="${PROJECT_VERSION}")
target_link_libraries(buckets PUBLIC llhttp::llhttp yyjson)
buckets_warnings(buckets)

add_executable(bucketsd cmd/bucketsd/main.c)
target_link_libraries(bucketsd PRIVATE buckets)
buckets_warnings(bucketsd)
install(TARGETS bucketsd RUNTIME DESTINATION bin)
