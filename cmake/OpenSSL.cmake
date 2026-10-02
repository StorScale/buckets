# OpenSSL 3 (TLS for S3 and internode traffic). The system's is used when it
# is new enough -- production images install it. Otherwise a pinned release is
# built once from source into BUCKETS_DEPS_PREFIX, shared by every build dir.
# 3.2 is the floor: madmin's encrypted admin payloads use its Argon2id KDF.
set(BUCKETS_OPENSSL_MIN 3.2)
set(BUCKETS_OPENSSL_VERSION 3.5.4)
set(BUCKETS_OPENSSL_SHA256 967311f84955316969bdb1d8d4b983718ef42338639c621ec4c34fddef355e99)
set(BUCKETS_DEPS_PREFIX "${CMAKE_SOURCE_DIR}/.deps" CACHE PATH "Where source-built dependencies are installed")

find_package(OpenSSL ${BUCKETS_OPENSSL_MIN} QUIET)
if(NOT OPENSSL_FOUND)
  if(OPENSSL_VERSION)
    message(STATUS "buckets: system OpenSSL ${OPENSSL_VERSION} is older than ${BUCKETS_OPENSSL_MIN}")
  endif()
  # FindOpenSSL caches what it found even when the version is refused; clear
  # it so the lookup below finds the pinned build, not the old library again.
  foreach(_v OPENSSL_INCLUDE_DIR OPENSSL_SSL_LIBRARY OPENSSL_CRYPTO_LIBRARY OPENSSL_SSL_LIBRARY_DEBUG
      OPENSSL_SSL_LIBRARY_RELEASE OPENSSL_CRYPTO_LIBRARY_DEBUG OPENSSL_CRYPTO_LIBRARY_RELEASE)
    unset(${_v} CACHE)
    unset(${_v})
  endforeach()
  set(_ossl_prefix "${BUCKETS_DEPS_PREFIX}/openssl-${BUCKETS_OPENSSL_VERSION}")
  if(NOT EXISTS "${_ossl_prefix}/lib/libssl.a")
    message(STATUS "buckets: building OpenSSL ${BUCKETS_OPENSSL_VERSION} into ${_ossl_prefix} (one time)")
    set(_src "${BUCKETS_DEPS_PREFIX}/src")
    set(_tar "${_src}/openssl-${BUCKETS_OPENSSL_VERSION}.tar.gz")
    file(DOWNLOAD
      "https://github.com/openssl/openssl/releases/download/openssl-${BUCKETS_OPENSSL_VERSION}/openssl-${BUCKETS_OPENSSL_VERSION}.tar.gz"
      "${_tar}" EXPECTED_HASH SHA256=${BUCKETS_OPENSSL_SHA256} TLS_VERIFY ON)
    file(ARCHIVE_EXTRACT INPUT "${_tar}" DESTINATION "${_src}")
    set(_dir "${_src}/openssl-${BUCKETS_OPENSSL_VERSION}")
    cmake_host_system_information(RESULT _ncpu QUERY NUMBER_OF_LOGICAL_CORES)
    foreach(_step
        "perl;Configure;--prefix=${_ossl_prefix};--libdir=lib;no-shared;no-tests;no-docs;no-apps"
        "make;-j${_ncpu};build_libs"
        "make;install_dev")
      execute_process(COMMAND ${_step} WORKING_DIRECTORY "${_dir}" RESULT_VARIABLE _rc
        OUTPUT_FILE "${_src}/openssl-build.log" ERROR_FILE "${_src}/openssl-build.log")
      if(NOT _rc EQUAL 0)
        message(FATAL_ERROR "building OpenSSL failed at '${_step}'; see ${_src}/openssl-build.log")
      endif()
    endforeach()
  endif()
  set(OPENSSL_ROOT_DIR "${_ossl_prefix}")
  set(OPENSSL_USE_STATIC_LIBS TRUE)
  find_package(OpenSSL ${BUCKETS_OPENSSL_MIN} REQUIRED)
endif()
message(STATUS "buckets: OpenSSL ${OPENSSL_VERSION} (${OPENSSL_SSL_LIBRARY})")
