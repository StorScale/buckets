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
  PRIVATE YAML_VERSION_MAJOR=0 YAML_VERSION_MINOR=2 YAML_VERSION_PATCH=5 YAML_VERSION_STRING="0.2.5")
set_target_properties(buckets_libyaml PROPERTIES POSITION_INDEPENDENT_CODE ON C_CLANG_TIDY "")
target_compile_options(buckets_libyaml PRIVATE -w)
