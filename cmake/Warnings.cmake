# Strict warnings for first-party code. Applied per target via buckets_warnings().
function(buckets_warnings target)
  target_compile_options(${target} PRIVATE
    -Wall -Wextra -Wpedantic
    -Wshadow -Wcast-align -Wpointer-arith -Wstrict-prototypes
    -Wmissing-prototypes -Wformat=2 -Wundef -Wvla
    -Wno-unused-parameter
    -Werror=implicit-function-declaration -Werror=return-type)
endfunction()
