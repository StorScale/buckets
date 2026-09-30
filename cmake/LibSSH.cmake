# libssh (the SSH server behind --sftp: key exchange, authentication, the sftp
# subsystem). Built once from a pinned release into BUCKETS_DEPS_PREFIX, as a
# static library against our OpenSSL; its CMake project cannot be added to
# ours (target names collide with cmocka's).
set(BUCKETS_LIBSSH_VERSION 0.11.1)
set(BUCKETS_LIBSSH_SHA256 14b7dcc72e91e08151c58b981a7b570ab2663f630e7d2837645d5a9c612c1b79)
set(_ssh_prefix "${BUCKETS_DEPS_PREFIX}/libssh-${BUCKETS_LIBSSH_VERSION}")
if(NOT EXISTS "${_ssh_prefix}/lib/libssh.a")
  message(STATUS "buckets: building libssh ${BUCKETS_LIBSSH_VERSION} into ${_ssh_prefix} (one time)")
  set(_src "${BUCKETS_DEPS_PREFIX}/src")
  set(_tar "${_src}/libssh-${BUCKETS_LIBSSH_VERSION}.tar.xz")
  file(DOWNLOAD "https://www.libssh.org/files/0.11/libssh-${BUCKETS_LIBSSH_VERSION}.tar.xz" "${_tar}"
    EXPECTED_HASH SHA256=${BUCKETS_LIBSSH_SHA256} TLS_VERIFY ON)
  file(ARCHIVE_EXTRACT INPUT "${_tar}" DESTINATION "${_src}")
  get_filename_component(_ossl_root "${OPENSSL_INCLUDE_DIR}" DIRECTORY)
  set(_bld "${_src}/libssh-${BUCKETS_LIBSSH_VERSION}-build")
  file(MAKE_DIRECTORY "${_bld}")
  execute_process(COMMAND ${CMAKE_COMMAND} "${_src}/libssh-${BUCKETS_LIBSSH_VERSION}"
      -G "${CMAKE_GENERATOR}" -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=${_ssh_prefix}
      -DCMAKE_INSTALL_LIBDIR=lib -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER} -DCMAKE_POSITION_INDEPENDENT_CODE=ON
      -DCMAKE_OSX_ARCHITECTURES=${CMAKE_OSX_ARCHITECTURES} -DOPENSSL_ROOT_DIR=${_ossl_root} -DOPENSSL_USE_STATIC_LIBS=ON
      -DBUILD_SHARED_LIBS=OFF -DWITH_SERVER=ON -DWITH_SFTP=ON -DWITH_EXAMPLES=OFF
      -DWITH_ZLIB=OFF -DWITH_GSSAPI=OFF -DWITH_PCAP=OFF -DWITH_NACL=OFF -DWITH_GCRYPT=OFF -DWITH_MBEDTLS=OFF
      -DWITH_DSA=OFF -DWITH_FIDO2=OFF -DUNIT_TESTING=OFF -DCLIENT_TESTING=OFF -DSERVER_TESTING=OFF
      -DWITH_SYMBOL_VERSIONING=OFF -DWITH_PKCS11_URI=OFF
    WORKING_DIRECTORY "${_bld}" RESULT_VARIABLE _rc OUTPUT_FILE "${_src}/libssh-build.log"
    ERROR_FILE "${_src}/libssh-build.log")
  if(_rc EQUAL 0)
    execute_process(COMMAND ${CMAKE_COMMAND} --build . --target install WORKING_DIRECTORY "${_bld}"
      RESULT_VARIABLE _rc OUTPUT_FILE "${_src}/libssh-build.log" ERROR_FILE "${_src}/libssh-build.log")
  endif()
  if(NOT _rc EQUAL 0 OR NOT EXISTS "${_ssh_prefix}/lib/libssh.a")
    message(FATAL_ERROR "building libssh failed; see ${_src}/libssh-build.log")
  endif()
endif()
add_library(buckets_libssh STATIC IMPORTED GLOBAL)
set_target_properties(buckets_libssh PROPERTIES
  IMPORTED_LOCATION "${_ssh_prefix}/lib/libssh.a"
  INTERFACE_INCLUDE_DIRECTORIES "${_ssh_prefix}/include"
  INTERFACE_COMPILE_DEFINITIONS LIBSSH_STATIC=1
  INTERFACE_LINK_LIBRARIES "OpenSSL::Crypto")
message(STATUS "buckets: libssh ${BUCKETS_LIBSSH_VERSION} (${_ssh_prefix}/lib/libssh.a)")
