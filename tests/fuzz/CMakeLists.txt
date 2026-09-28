# Fuzz targets. With a libFuzzer-capable clang (Linux) they are real fuzzers;
# elsewhere (Apple clang ships no libFuzzer runtime) they link a small driver
# that replays corpus files, so the harnesses still compile and run in CI.
include(CheckCSourceCompiles)
set(CMAKE_REQUIRED_FLAGS "-fsanitize=fuzzer")
check_c_source_compiles("
#include <stddef.h>
#include <stdint.h>
int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) { return 0; }" BUCKETS_HAVE_LIBFUZZER)
unset(CMAKE_REQUIRED_FLAGS)

function(buckets_fuzz_target name)
  if(BUCKETS_HAVE_LIBFUZZER)
    add_executable(${name} ${name}.c)
    target_compile_options(${name} PRIVATE -fsanitize=fuzzer,address,undefined)
    target_link_options(${name} PRIVATE -fsanitize=fuzzer,address,undefined)
  else()
    add_executable(${name} ${name}.c standalone_driver.c)
  endif()
  target_link_libraries(${name} PRIVATE buckets)
  if(BUCKETS_BUILD_TESTS AND EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/corpus/${name})
    add_test(NAME ${name}_corpus COMMAND ${name} ${CMAKE_CURRENT_SOURCE_DIR}/corpus/${name})
  endif()
endfunction()

buckets_fuzz_target(fuzz_sigv4)
buckets_fuzz_target(fuzz_xml)
buckets_fuzz_target(fuzz_s2)
