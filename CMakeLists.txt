cmake_minimum_required(VERSION 3.20)

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" BUCKETS_VERSION LIMIT_COUNT 1)
project(buckets VERSION ${BUCKETS_VERSION} LANGUAGES C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Build type" FORCE)
endif()

option(BUCKETS_BUILD_TESTS "Build unit tests" ON)
option(BUCKETS_BUILD_FUZZ "Build fuzz targets" ON)
set(BUCKETS_SANITIZE "" CACHE STRING "Sanitizers to enable, e.g. address,undefined or thread")

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(Warnings)
include(Sanitizers)
include(Dependencies)
include(OpenSSL)

add_subdirectory(src)

if(BUCKETS_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests/unit)
endif()

if(BUCKETS_BUILD_FUZZ)
  add_subdirectory(tests/fuzz)
endif()
