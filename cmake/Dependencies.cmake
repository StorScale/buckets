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
