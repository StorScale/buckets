#!/usr/bin/env bash
# Healing on a 4-drive (EC 2+2) set. Each case damages one drive, lets the
# healer repair it, then hides two other drives so reads can only succeed if
# the repaired drive really holds its shards again.
#   tests/integration/heal.sh [bucketsd]
set -euo pipefail
BIN=${1:-build/src/bucketsd}
PORT=${PORT:-19720}
AK=healuser
SK=healsecret1234
WORK=$(mktemp -d "${TMPDIR:-/tmp}/buckets-heal-XXXXXX")
EP="http://127.0.0.1:$PORT"
S3=(--aws-sigv4 "aws:amz:us-east-1:s3" --user "$AK:$SK")
D="$WORK/drives"
B=healbucket
PID=
cleanup() {
  [[ -n "$PID" ]] && kill "$PID" 2>/dev/null && wait "$PID" 2>/dev/null || true
  [[ -n "${KEEP:-}" ]] && echo "kept $WORK" || rm -rf "$WORK"
}
trap cleanup EXIT

md5of() { (md5sum 2>/dev/null || md5 -r) | cut -d' ' -f1; }
start() {
  BUCKETS_ROOT_USER=$AK BUCKETS_ROOT_PASSWORD=$SK "$BIN" server --address "127.0.0.1:$PORT" "$D/d{1...4}" \
    2>>"$WORK/log" &
  PID=$!
  for _ in $(seq 50); do curl -sf "$EP/minio/health/live" >/dev/null && return; sleep 0.1; done
  echo "server did not start"; cat "$WORK/log"; exit 1
}
stop() { kill "$PID"; wait "$PID" 2>/dev/null || true; PID=; }
pass=0
fail=0
expect() { # name got want
  if [[ "$2" == "$3" ]]; then pass=$((pass + 1)); printf '  ok    %s\n' "$1"
  else fail=$((fail + 1)); printf '  FAIL  %s: got %q want %q\n' "$1" "$2" "$3"; fi
}
status() { curl -s -o /dev/null -w '%{http_code}' "${S3[@]}" "$@"; }
get_md5() { curl -s "${S3[@]}" "$EP/$B/$1" | md5of; }
# Waits (up to 10 s) for a shell condition to hold.
until_true() { for _ in $(seq 100); do eval "$1" && return 0; sleep 0.1; done; return 1; }
# Reads $1 with drives $2 and $3 hidden (their copy of the object moved away).
read_without() {
  mv "$D/d$2/$B/$1" "$WORK/h$2"; mv "$D/d$3/$B/$1" "$WORK/h$3"
  get_md5 "$1"
  mv "$WORK/h$2" "$D/d$2/$B/$1"; mv "$WORK/h$3" "$D/d$3/$B/$1"
}

head -c 3500000 /dev/urandom >"$WORK/big"
head -c 900 /dev/urandom >"$WORK/small"
BIG=$(md5of <"$WORK/big")
SMALL=$(md5of <"$WORK/small")

start
status -X PUT "$EP/$B" >/dev/null
for o in rot.bin gone.bin; do status -T "$WORK/big" "$EP/$B/$o" >/dev/null; done
status -T "$WORK/small" "$EP/$B/tiny.bin" >/dev/null

# The drive holding the first data shard (EcIndex 1), which every read uses.
first_shard() { for i in 1 2 3 4; do LC_ALL=C grep -q $'EcIndex\x01' "$D/d$i/$B/$1/xl.meta" && echo "$i" && return; done; }
others() { for i in 1 2 3 4; do [[ $i != "$1" ]] && printf '%s ' "$i"; done; }

echo "== bitrot is repaired after a read finds it"
r=$(first_shard rot.bin)
read -r o1 o2 _ <<<"$(others "$r")"
part=$(ls "$D"/d$r/$B/rot.bin/*/part.1)
before=$(md5of <"$part")
printf 'XXXXXXXXXXXXXXXX' | dd of="$part" bs=1 seek=100 conv=notrunc 2>/dev/null
expect "read through bitrot" "$(get_md5 rot.bin)" "$BIG"
until_true '[[ -f "$part" && $(md5of <"$part") == "$before" ]]' || true
expect "rotten shard rewritten" "$(md5of <"$part")" "$before"
expect "read without two other drives" "$(read_without rot.bin "$o1" "$o2")" "$BIG"

echo "== a drive missing the object gets it back"
rm -rf "$D/d2/$B/gone.bin"
expect "read with d2 missing it" "$(get_md5 gone.bin)" "$BIG"
until_true '[[ -f "$D/d2/$B/gone.bin/xl.meta" ]]' || true
expect "read from d2+d4 only" "$(read_without gone.bin 1 3)" "$BIG"

echo "== an unreadable object is never mistaken for dangling"
status -T "$WORK/big" "$EP/$B/keep.bin" >/dev/null
r=$(first_shard keep.bin)
read -r o1 o2 _ <<<"$(others "$r")"
part=$(ls "$D"/d$r/$B/keep.bin/*/part.1)
printf 'XXXXXXXXXXXXXXXX' | dd of="$part" bs=1 seek=100 conv=notrunc 2>/dev/null
mv "$D/d$o1/$B/keep.bin" "$WORK/k1"; mv "$D/d$o2/$B/keep.bin" "$WORK/k2"
expect "read fails with two drives hidden and one rotten" "$(status "$EP/$B/keep.bin")" 503
sleep 2 # let the healer try (and fail) to heal it
mv "$WORK/k1" "$D/d$o1/$B/keep.bin"; mv "$WORK/k2" "$D/d$o2/$B/keep.bin"
expect "object still there once the drives return" "$(get_md5 keep.bin)" "$BIG"

echo "== an inline object's lost xl.meta"
rm -f "$D/d3/$B/tiny.bin/xl.meta"
expect "read with d3 missing it" "$(get_md5 tiny.bin)" "$SMALL"
until_true '[[ -f "$D/d3/$B/tiny.bin/xl.meta" ]]' || true
expect "read from d3+d4 only" "$(read_without tiny.bin 1 2)" "$SMALL"
stop

echo "== a replaced drive is filled in the background"
for i in $(seq 1 30); do printf 'object %d\n' "$i" >"$WORK/o$i"; done
start
for i in $(seq 1 30); do status -T "$WORK/o$i" "$EP/$B/many/o$i" >/dev/null; done
stop
# A dangling object: its metadata survives on one drive only.
status -X PUT "$EP/$B" >/dev/null 2>&1 || true
rm -rf "$D/d4" && mkdir -p "$D/d4"
start
status -T "$WORK/small" "$EP/$B/lonely.bin" >/dev/null
stop
rm -rf "$D/d1/$B/lonely.bin" "$D/d2/$B/lonely.bin"
rm -rf "$D/d4" && mkdir -p "$D/d4"
start
until_true '[[ ! -f "$D/d4/.minio.sys/buckets-healing.json" && -d "$D/d4/$B/many/o30" ]]' || true
expect "healing tracker cleared" "$([[ -f "$D/d4/.minio.sys/buckets-healing.json" ]] && echo present || echo gone)" gone
expect "bucket metadata healed" "$([[ -f "$D/d4/.minio.sys/buckets/$B/.metadata.bin/xl.meta" ]] && echo yes)" yes
ok=0
for i in $(seq 1 30); do
  [[ "$(read_without "many/o$i" 1 2)" == "$(md5of <"$WORK/o$i")" ]] && ok=$((ok + 1))
done
expect "30 small objects readable from d3+d4" "$ok" 30
expect "big object readable from d3+d4" "$(read_without rot.bin 1 2)" "$BIG"
expect "dangling object purged" "$([[ -e "$D/d3/$B/lonely.bin" ]] && echo present || echo gone)" gone
stop

if grep -q 'Sanitizer\|runtime error' "$WORK/log"; then
  fail=$((fail + 1)); echo "  FAIL  sanitizer report:"; grep -A20 'Sanitizer\|runtime error' "$WORK/log" | head -40
fi
echo "heal: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
