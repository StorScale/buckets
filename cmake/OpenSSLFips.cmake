# OpenSSL's FIPS provider, for FIPS mode (docs/fips.md), built once into BUCKETS_DEPS_PREFIX/fips-<version> by
# scripts/build-fips-provider.sh (which sets the version) when BUCKETS_FIPS_PROVIDER is on. The unit test of FIPS
# mode uses it when it is there.
option(BUCKETS_FIPS_PROVIDER "Build OpenSSL's FIPS provider (for FIPS mode and its tests)" OFF)
execute_process(COMMAND "${CMAKE_SOURCE_DIR}/scripts/build-fips-provider.sh" --version
  OUTPUT_VARIABLE BUCKETS_FIPS_PROVIDER_VERSION OUTPUT_STRIP_TRAILING_WHITESPACE)
set(BUCKETS_FIPS_DIR "${BUCKETS_DEPS_PREFIX}/fips-${BUCKETS_FIPS_PROVIDER_VERSION}")
if(BUCKETS_FIPS_PROVIDER AND NOT EXISTS "${BUCKETS_FIPS_DIR}/lib/ossl-modules/fips.so")
  message(STATUS "buckets: building the OpenSSL ${BUCKETS_FIPS_PROVIDER_VERSION} FIPS provider into ${BUCKETS_FIPS_DIR} (one time)")
  file(MAKE_DIRECTORY "${BUCKETS_DEPS_PREFIX}/src/fips-build")
  execute_process(COMMAND ${CMAKE_COMMAND} -E env "FIPS_BUILD_DIR=${BUCKETS_DEPS_PREFIX}/src/fips-build"
    "${CMAKE_SOURCE_DIR}/scripts/build-fips-provider.sh" "${BUCKETS_FIPS_DIR}" RESULT_VARIABLE _rc)
  if(NOT _rc EQUAL 0)
    message(FATAL_ERROR "building the FIPS provider failed")
  endif()
endif()
if(EXISTS "${BUCKETS_FIPS_DIR}/lib/ossl-modules/fips.so")
  message(STATUS "buckets: OpenSSL FIPS provider ${BUCKETS_FIPS_PROVIDER_VERSION} in ${BUCKETS_FIPS_DIR}")
endif()
