# -DBUCKETS_SANITIZE=address,undefined  or  -DBUCKETS_SANITIZE=thread
if(BUCKETS_SANITIZE)
  message(STATUS "buckets: sanitizers enabled: ${BUCKETS_SANITIZE}")
  add_compile_options(-fsanitize=${BUCKETS_SANITIZE} -fno-omit-frame-pointer -fno-sanitize-recover=all)
  add_link_options(-fsanitize=${BUCKETS_SANITIZE})
endif()
