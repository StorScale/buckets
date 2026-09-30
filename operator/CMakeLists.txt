# buckets-operator: the Kubernetes operator, linked against libbuckets for
# HTTP/TLS, JSON and logging.
add_library(buckets_operator STATIC
  src/kube.c
  src/manifests.c
  src/reconcile.c
  src/lease.c
  src/s3client.c
  src/iam.c
)
target_include_directories(buckets_operator PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(buckets_operator PUBLIC buckets)
buckets_warnings(buckets_operator)

add_executable(buckets-operator src/main.c)
target_link_libraries(buckets-operator PRIVATE buckets_operator)
buckets_warnings(buckets-operator)

if(BUCKETS_BUILD_TESTS)
  add_executable(test_manifests tests/test_manifests.c)
  target_link_libraries(test_manifests PRIVATE buckets_operator cmocka::cmocka)
  add_test(NAME test_manifests COMMAND test_manifests)
  # The Helm chart ships its own copy of the CRDs (Helm's crds/ directory).
  file(GLOB crds RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}/deploy/crds ${CMAKE_CURRENT_SOURCE_DIR}/deploy/crds/*.yaml)
  foreach(crd ${crds})
    add_test(NAME helm_crd_${crd} COMMAND ${CMAKE_COMMAND} -E compare_files ${CMAKE_CURRENT_SOURCE_DIR}/deploy/crds/${crd}
                                          ${CMAKE_CURRENT_SOURCE_DIR}/helm/buckets-operator/crds/${crd})
  endforeach()
endif()
