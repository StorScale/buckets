#!/usr/bin/env bash
# Fuzz soak: every target under libFuzzer (ASan + UBSan) in a Linux container,
# in parallel, for SECONDS each (default 3600). Grown corpora and any crash
# inputs land in OUT (default $TMPDIR/buckets-fuzz); the script fails if any
# target crashed. JOBS: parallel jobs per target (default 1).
#   tests/fuzz/soak.sh [target...]
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
SECONDS_EACH=${SECONDS:-3600}
JOBS=${JOBS:-1}
OUT=${OUT:-${TMPDIR:-/tmp}/buckets-fuzz}
TARGETS=("$@")
[[ ${#TARGETS[@]} -gt 0 ]] || TARGETS=($(sed -n 's/^buckets_fuzz_target(\(.*\))$/\1/p' "$ROOT/tests/fuzz/CMakeLists.txt"))
docker build -q -f "$ROOT/tests/fuzz/Dockerfile" -t buckets/fuzz "$ROOT" >/dev/null
mkdir -p "$OUT"
for t in "${TARGETS[@]}"; do
  docker rm -f "buckets-fuzz-$t" >/dev/null 2>&1 || true
  # no bind mounts (a VM-backed docker may not share this path): copy out after
  docker run -d --name "buckets-fuzz-$t" buckets/fuzz sh -c "
    mkdir -p /out/corpus /out/crashes; cp /src/tests/fuzz/corpus/$t/* /out/corpus/ 2>/dev/null
    [ -d /seed ] && cp /seed/* /out/corpus/ 2>/dev/null
    cd /out && /build/tests/fuzz/$t -max_total_time=$SECONDS_EACH -jobs=$JOBS -workers=$JOBS -rss_limit_mb=4096 \
      -timeout=30 -artifact_prefix=/out/crashes/ -print_final_stats=1 /out/corpus > /out/log 2>&1
    echo \$? > /out/rc" >/dev/null
  # a previous soak's corpus seeds this one
  if [[ -d "$OUT/$t/corpus" ]]; then docker cp "$OUT/$t/corpus" "buckets-fuzz-$t:/seed" 2>/dev/null || true; fi
done
for t in "${TARGETS[@]}"; do
  docker wait "buckets-fuzz-$t" >/dev/null
  rm -rf "$OUT/$t.new" && docker cp "buckets-fuzz-$t:/out" "$OUT/$t.new" && rm -rf "$OUT/$t" && mv "$OUT/$t.new" "$OUT/$t"
  docker rm "buckets-fuzz-$t" >/dev/null
done
fail=0
for t in "${TARGETS[@]}"; do
  rc=$(cat "$OUT/$t/rc" 2>/dev/null || echo "?")
  n=$(ls "$OUT/$t/crashes" | wc -l | tr -d ' ')
  execs=$( (grep -ho 'stat::number_of_executed_units: *[0-9]*' "$OUT/$t"/log "$OUT/$t"/fuzz-*.log 2>/dev/null || true) | awk '{s+=$2} END {print s+0}')
  printf '%-14s rc=%-3s runs=%-12s corpus=%-6s crashes=%s\n' "$t" "$rc" "$execs" "$(ls "$OUT/$t/corpus" | wc -l | tr -d ' ')" "$n"
  [[ $rc == 0 && $n == 0 ]] || fail=1
done
exit $fail
