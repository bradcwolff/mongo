#!/bin/bash
# Long libFuzzer hunt against the already-built sanitizer binaries.
# Does not rebuild. Crash/oom/timeout inputs land in artifacts/crashers/.
set -u
cd /workspace

SHA=$(git rev-parse HEAD)
SYM="${ASAN_SYMBOLIZER_PATH:-$HOME/.cache/bazel/_bazel_ubuntu/eab0d61a99b6696edb3d2aff87b585e8/external/mongo_toolchain_v4/stow/llvm-v4/bin/llvm-symbolizer}"
export ASAN_SYMBOLIZER_PATH="$SYM"
export UBSAN_SYMBOLIZER_PATH="$SYM"
export ASAN_OPTIONS="halt_on_error=1:detect_leaks=0:allocator_may_return_null=1:symbolize=1:malloc_context_size=30"
export UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1:symbolize=1"
export PATH="$HOME/.local/bin:$PATH"

mkdir -p artifacts/corpus/op_msg artifacts/corpus/sasl artifacts/corpus/protocol \
  artifacts/crashers/op_msg artifacts/crashers/sasl artifacts/crashers/protocol \
  artifacts/logs artifacts/meta

seed_dir() {
  local dest=$1
  shift
  find "$dest" -type f -print -quit | grep -q . && return 0
  local src
  for src in "$@"; do
    if [ -d "$src" ]; then
      cp -a "$src"/. "$dest"/
    fi
  done
}

seed_dir artifacts/corpus/sasl \
  src/mongo/db/auth/sasl_handshake_corpus \
  fuzz-artifacts/corpus/sasl
seed_dir artifacts/corpus/op_msg fuzz-artifacts/corpus/op_msg
seed_dir artifacts/corpus/protocol fuzz-artifacts/corpus/protocol
# Named seeds win if a previous corpus snapshot had the exp-less token.
cp -a src/mongo/db/auth/sasl_handshake_corpus/oidc_jwt artifacts/corpus/sasl/oidc_jwt
cp -a src/mongo/db/auth/sasl_handshake_corpus/oidc_step2 artifacts/corpus/sasl/oidc_step2

printf '%s\n' "$SHA" > artifacts/meta/harness-commit.txt
date -u +%Y-%m-%dT%H:%M:%SZ > artifacts/meta/started-utc.txt

# Free the idle Bazel server (~2GiB) before the parallel fuzzers start.
bazel shutdown >> artifacts/logs/driver.log 2>&1 || true

run_one() {
  local name=$1 bin=$2 seconds=$3 workers=$4 rss=$5 maxlen=$6 tmo=$7
  local log="/workspace/artifacts/logs/${name}.log"
  local prefix="/workspace/artifacts/crashers/${name}/"
  local corpus="/workspace/artifacts/corpus/${name}"
  local binpath="/workspace/${bin}"
  local work="/workspace/artifacts/logs/work-${name}"
  mkdir -p "$work"
  # -jobs writes fuzz-<job>.log in the cwd. Keep those per target.
  local argv="${binpath} -jobs=${workers} -workers=${workers} -max_total_time=${seconds} -print_final_stats=1 -rss_limit_mb=${rss} -max_len=${maxlen} -timeout=${tmo} -detect_leaks=0 -artifact_prefix=${prefix} ${corpus}"
  {
    echo "SHA ${SHA}"
    echo "ARGV ${argv}"
    echo "START $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "NOTE in-binary SASL self-test JWT still lacks exp; corpus oidc_jwt and oidc_step2 include exp=1893456000. Binary was not rebuilt."
    echo "NOTE workers are long-lived. -fork was not used: each fork child restarts the server, and op_msg wall throughput fell to about 10 exec/s."
  } > "$log"
  cp "$log" "/workspace/artifacts/meta/${name}.argv"
  local deadline=$(( $(date +%s) + seconds ))
  cd "$work"
  while [ "$(date +%s)" -lt $((deadline - 20)) ]; do
    local left=$(( deadline - $(date +%s) ))
    set +e
    "$binpath" \
      -jobs="${workers}" \
      -workers="${workers}" \
      -max_total_time="${left}" \
      -print_final_stats=1 \
      -rss_limit_mb="${rss}" \
      -max_len="${maxlen}" \
      -timeout="${tmo}" \
      -detect_leaks=0 \
      -artifact_prefix="${prefix}" \
      "${corpus}" >> "$log" 2>&1
    local rc=$?
    set -e
    local stamp
    stamp=$(date -u +%Y%m%dT%H%M%SZ)
    echo "EXIT ${rc} ${stamp} left_at_start=${left}" >> "$log"
    local f
    for f in fuzz-*.log; do
      [ -e "$f" ] || continue
      cp "$f" "${prefix}worker-log-${stamp}-${f}"
    done
    if [ "$rc" -eq 0 ]; then
      break
    fi
    echo "RESTART rc=${rc}" >> "$log"
    sleep 2
  done
  echo "END $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$log"
  echo "${name} done" >> /workspace/artifacts/logs/driver.log
}

# Drop the lower-ceiling fuzzer if the box is about to OOM. op_msg and sasl keep running.
monitor_mem() {
  while true; do
    local avail
    avail=$(awk '/MemAvailable/{print $2}' /proc/meminfo)
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) avail_kb=${avail}" >> artifacts/logs/mem.log
    ps -eo rss=,args= | awk '/fuzzer/ && !/awk/ {print}' >> artifacts/logs/mem.log
    if [ "${avail}" -lt 900000 ] && pgrep -f 'rpc/protocol_fuzzer' >/dev/null 2>&1; then
      echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) stopping protocol_fuzzer avail_kb=${avail}" >> artifacts/logs/mem.log
      pkill -TERM -f 'rpc/protocol_fuzzer' || true
    fi
    sleep 60
  done
}

echo "DRIVER_START $(date -u +%Y-%m-%dT%H:%M:%SZ) sha=${SHA}" >> artifacts/logs/driver.log
monitor_mem &
mon=$!

run_one op_msg bazel-bin/src/mongo/db/op_msg_fuzzer 14400 2 5120 8192 60 &
p_op=$!
run_one sasl bazel-bin/src/mongo/db/auth/sasl_handshake_fuzzer 14400 1 3072 4096 30 &
p_sasl=$!
run_one protocol bazel-bin/src/mongo/rpc/protocol_fuzzer 3600 1 1536 8192 30 &
p_proto=$!
wait "$p_op" "$p_sasl" "$p_proto"
kill "$mon" 2>/dev/null || true
date -u +%Y-%m-%dT%H:%M:%SZ > artifacts/meta/ended-utc.txt
echo "ALL_DONE $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> artifacts/logs/driver.log
