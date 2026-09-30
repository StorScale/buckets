# Third-party dependencies, pinned. Everything is fetched and built from source so
# a bare toolchain (cc + cmake) is enough to build buckets.
include(FetchContent)
set(FETCHCONTENT_QUIET ON)

# llhttp: HTTP/1.1 request parser (the release/* tags ship generated C sources).
FetchContent_Declare(llhttp
  URL https://github.com/nodejs/llhttp/archive/refs/tags/release/v9.4.3.tar.gz
  DOWNLOAD_EXTRACT_TIMESTAMP ON)
set(LLHTTP_BUILD_SHARED_LIBS OFF CACHE INTERNAL "")
set(LLHTTP_BUILD_STATIC_LIBS ON CACHE INTERNAL "")
set(BUILD_SHARED_LIBS OFF CACHE INTERNAL "")
FetchContent_MakeAvailable(llhttp)

# yyjson: JSON read/write (format.json, admin API, IAM documents).
FetchContent_Declare(yyjson
  URL https://github.com/ibireme/yyjson/archive/refs/tags/0.13.0.tar.gz
  DOWNLOAD_EXTRACT_TIMESTAMP ON)
set(YYJSON_BUILD_TESTS OFF CACHE INTERNAL "")
FetchContent_MakeAvailable(yyjson)

# libdeflate: raw DEFLATE, zlib and gzip (zip archives, compression, S3 Select input).
FetchContent_Declare(libdeflate
  URL https://github.com/ebiggers/libdeflate/archive/refs/tags/v1.24.tar.gz
  DOWNLOAD_EXTRACT_TIMESTAMP ON)
set(LIBDEFLATE_BUILD_SHARED_LIB OFF CACHE INTERNAL "")
set(LIBDEFLATE_BUILD_STATIC_LIB ON CACHE INTERNAL "")
set(LIBDEFLATE_BUILD_GZIP OFF CACHE INTERNAL "")
set(LIBDEFLATE_BUILD_TESTS OFF CACHE INTERNAL "")
FetchContent_MakeAvailable(libdeflate)

if(BUCKETS_BUILD_TESTS)
  # cmocka: unit test framework.
  FetchContent_Declare(cmocka
    GIT_REPOSITORY https://git.cryptomilk.org/projects/cmocka.git
    GIT_TAG cmocka-2.0.2
    GIT_SHALLOW ON)
  set(WITH_STATIC_LIB ON CACHE INTERNAL "")
  set(WITH_EXAMPLES OFF CACHE INTERNAL "")
  set(UNIT_TESTING OFF CACHE INTERNAL "")
  set(PICKY_DEVELOPER OFF CACHE INTERNAL "")
  FetchContent_MakeAvailable(cmocka)
endif()

# libyaml: YAML parsing (batch job definitions). Its own CMakeLists predates
# CMake 3.5, so only the sources are fetched and built here.
FetchContent_Declare(libyaml
  URL https://github.com/yaml/libyaml/archive/refs/tags/0.2.5.tar.gz
  DOWNLOAD_EXTRACT_TIMESTAMP ON
  SOURCE_SUBDIR no-cmake)
FetchContent_MakeAvailable(libyaml)
file(GLOB BUCKETS_LIBYAML_SOURCES ${libyaml_SOURCE_DIR}/src/*.c)
add_library(buckets_libyaml STATIC ${BUCKETS_LIBYAML_SOURCES})
target_include_directories(buckets_libyaml SYSTEM PUBLIC ${libyaml_SOURCE_DIR}/include)
target_include_directories(buckets_libyaml PRIVATE ${libyaml_SOURCE_DIR}/src)
target_compile_definitions(buckets_libyaml PUBLIC YAML_DECLARE_STATIC
  PRIVATE _GNU_SOURCE YAML_VERSION_MAJOR=0 YAML_VERSION_MINOR=2 YAML_VERSION_PATCH=5 YAML_VERSION_STRING="0.2.5")
set_target_properties(buckets_libyaml PROPERTIES POSITION_INDEPENDENT_CODE ON C_CLANG_TIDY "")
target_compile_options(buckets_libyaml PRIVATE -w)

# Streaming decompressors (S3 Select input, snowball archives): zlib for gzip,
# bzip2, zstd and LZ4 frames. Only their library sources are built.
macro(buckets_fetch_sources name url)
  FetchContent_Declare(${name} URL ${url} DOWNLOAD_EXTRACT_TIMESTAMP ON SOURCE_SUBDIR no-cmake)
  FetchContent_MakeAvailable(${name})
endmacro()
macro(buckets_static_lib target)
  add_library(${target} STATIC ${ARGN})
  set_target_properties(${target} PROPERTIES POSITION_INDEPENDENT_CODE ON C_CLANG_TIDY "")
  target_compile_options(${target} PRIVATE -w)
endmacro()

buckets_fetch_sources(zlib https://github.com/madler/zlib/releases/download/v1.3.1/zlib-1.3.1.tar.gz)
set(_s adler32.c compress.c crc32.c deflate.c infback.c inffast.c inflate.c inftrees.c trees.c uncompr.c zutil.c)
list(TRANSFORM _s PREPEND ${zlib_SOURCE_DIR}/)
buckets_static_lib(buckets_zlib ${_s})
target_include_directories(buckets_zlib SYSTEM PUBLIC ${zlib_SOURCE_DIR})
target_compile_definitions(buckets_zlib PRIVATE HAVE_UNISTD_H)

buckets_fetch_sources(bzip2 https://sourceware.org/pub/bzip2/bzip2-1.0.8.tar.gz)
set(_s blocksort.c huffman.c crctable.c randtable.c compress.c decompress.c bzlib.c)
list(TRANSFORM _s PREPEND ${bzip2_SOURCE_DIR}/)
buckets_static_lib(buckets_bzip2 ${_s})
target_include_directories(buckets_bzip2 SYSTEM PUBLIC ${bzip2_SOURCE_DIR})
target_compile_definitions(buckets_bzip2 PRIVATE BZ_NO_STDIO)

buckets_fetch_sources(zstd https://github.com/facebook/zstd/releases/download/v1.5.7/zstd-1.5.7.tar.gz)
file(GLOB _s ${zstd_SOURCE_DIR}/lib/common/*.c ${zstd_SOURCE_DIR}/lib/compress/*.c ${zstd_SOURCE_DIR}/lib/decompress/*.c)
buckets_static_lib(buckets_zstd ${_s})
target_include_directories(buckets_zstd SYSTEM PUBLIC ${zstd_SOURCE_DIR}/lib)
target_compile_definitions(buckets_zstd PRIVATE ZSTD_DISABLE_ASM ZSTD_MULTITHREAD=0)

buckets_fetch_sources(lz4 https://github.com/lz4/lz4/releases/download/v1.10.0/lz4-1.10.0.tar.gz)
set(_s lz4.c lz4frame.c lz4hc.c xxhash.c)
list(TRANSFORM _s PREPEND ${lz4_SOURCE_DIR}/lib/)
buckets_static_lib(buckets_lz4 ${_s})
target_include_directories(buckets_lz4 SYSTEM PUBLIC ${lz4_SOURCE_DIR}/lib)
target_compile_definitions(buckets_lz4 PRIVATE XXH_NAMESPACE=LZ4_)

