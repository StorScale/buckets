# libFuzzer builds of the fuzz targets (Apple clang has no libFuzzer).
#   docker build -f tests/fuzz/Dockerfile -t buckets/fuzz .
FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends clang llvm libclang-rt-dev cmake ninja-build git ca-certificates libssl-dev perl python3 \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN rm -rf build* .deps \
 && CC=clang cmake -S . -B /build -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo -DBUCKETS_BUILD_TESTS=OFF -DBUCKETS_BUILD_FUZZ=ON -DBUCKETS_FUZZ_INSTRUMENT=ON \
 && ninja -C /build $(sed -n 's/^buckets_fuzz_target(\(.*\))$/\1/p' tests/fuzz/CMakeLists.txt)
