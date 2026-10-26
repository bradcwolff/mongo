# Lane B fuzzer notes (r8.0.34)

Defensive libFuzzer harnesses only. No exploit writeups.

## What changed

- `src/mongo/db/op_msg_fuzzer_fixture.cpp` decompresses `OP_COMPRESSED` (snappy, zlib, zstd, noop) with `MessageCompressorManager::decompressMessage` and then calls `ServiceEntryPoint::handleRequest`. That is the same decompress-then-dispatch seam as `SessionWorkflow::WorkItem::decompressRequest`. The pre-auth size cap (`transport::gPreAuthMaximumMessageSizeBytes`, default 16KiB) is applied first; a failed attempt is retried with a 256KiB cap so the claimed-size check still runs without allocating `MaxMessageSizeBytes` (48MiB).
- `src/mongo/db/op_msg_fuzzer.cpp` keeps the original wire-message input and also wraps every input in snappy/zlib/zstd (`testCompressedInput`), including mutations of the claimed uncompressed size. `LLVMFuzzerInitialize` compresses a `{ping:1,$db:"admin"}` with each of snappy, zlib, and zstd and requires all three to reach command dispatch.
- `src/mongo/rpc/protocol_fuzzer.cpp` registers snappy, zlib, and zstd (previously only noop) on the decompress-and-parse path. It does not dispatch commands; dispatch is covered by the fixture above. Decompression is capped at 256KiB.
- `src/mongo/db/auth/sasl_handshake_fuzzer.cpp` is a new harness for server-side SCRAM-SHA-1, SCRAM-SHA-256, and PLAIN `step()`, `saslStart` / `saslContinue` IDL parsing, OIDC client step 1/2 IDL parsing (`OIDCMechanismClientStep1` / `OIDCMechanismClientStep2`), compact JWT body parsing (`JWSValidatedToken::extractIssuerAndAudienceFromCompactSerialization`), and OAuth authorization-server metadata parsing. X.509 ASN.1 is not targeted (`asn1_parser_fuzzer` already covers it). Community r8.0.34 has no server `MONGODB-OIDC` mechanism class; the OIDC surface here is the server-side handshake parsers that are in tree.

Proof that compressed bytes reach command dispatch: the fixture increments a counter only after `decompressMessage` succeeds and immediately before `handleRequest`. Initialize prints `OP_COMPRESSED_DISPATCH_PROOF dispatches=3` when snappy, zlib, and zstd each take that path. Each of those also prints `OP_COMPRESSED_DISPATCH`.

## Build

Bazel 7.5.0 (MongoDB bazelisk). Sanitizers: address, undefined, fuzzer. Enterprise is off (this tree has no enterprise module). Remote execution is disabled (`--config=local`).

```bash
export PATH="$HOME/.local/bin:$PATH"
python3 buildscripts/install_bazel.py   # once

bazel build \
  --config=local \
  --config=dbg_aubsan \
  --//bazel/config:fsan=True \
  --//bazel/config:build_enterprise=False \
  --//bazel/config:separate_debug=False \
  --jobs=4 \
  --local_resources=memory=14000 \
  //src/mongo/rpc:protocol_fuzzer \
  //src/mongo/db/auth:sasl_handshake_fuzzer \
  //src/mongo/db:op_msg_fuzzer
```

`--config=dbg_aubsan` is the in-repo address+undefined profile (`--//bazel/config:asan=True`, `--//bazel/config:ubsan=True`, system allocator, dynamic link) and it inherits `dbg`, which already compiles with `-g` and `-gsplit-dwarf`. `--//bazel/config:fsan=True` turns on `-fsanitize=fuzzer-no-link` and makes `mongo_cc_fuzzer_test` targets compatible. Fuzzer binaries link with `-fsanitize=fuzzer`.

`--//bazel/config:separate_debug=False` is the flag that turns off the debug split. It is already the `dbg` default (`.bazelrc` sets it on `common` and `common:dbg`). With it off, `extract_debuginfo` does not run `objcopy --only-keep-debug` / `--strip-debug`. The public target is a symlink to the single `cc_binary`, which Mongo's rule always names `name + "_with_debug"` (`bazel/mongo_src_rules.bzl`, `WITH_DEBUG_SUFFIX`). There is no second debug companion to skip. `--fission=no` was not passed: fission only controls `-gsplit-dwarf`, and dropping it would put full DWARF into the link and throw away the compile cache. `-g` stays on via `debug_symbols`.

On this VM the successful build was 9168 actions, 7532 of them executed, elapsed 11245s, critical path 4250s. The UI line `[Sched] Linking …_with_debug` is the critical path waiting on compiles that are still running; it is not an active link. The largest shared library on that path (`libquery_exec_shared_with_debug.so`) linked in about 16s once it actually started. Linked fuzzer executables, dynamic and unstripped, with `-g` via split DWARF:

- `bazel-bin/src/mongo/rpc/protocol_fuzzer` → `protocol_fuzzer_with_debug` (6.7MiB)
- `bazel-bin/src/mongo/db/auth/sasl_handshake_fuzzer` → `sasl_handshake_fuzzer_with_debug` (12MiB)
- `bazel-bin/src/mongo/db/op_msg_fuzzer` → `op_msg_fuzzer_with_debug` (7.2MiB)

Two local toolchain fixes were required and live in the Bazel external cache, not in git. CppCompile does not set `LD_LIBRARY_PATH`, so clang was loading the system libstdc++ and emitting unsuffixed `__asan_set_shadow_` references that the toolchain compiler-rt does not define. `v4/bin/clang` and `v4/bin/clang++` are wrappers that prepend the toolchain `gcc-v4/lib64` to `LD_LIBRARY_PATH` and exec clang-12. Objects built through that wrapper reference `__asan_set_shadow_00` / `__asan_set_shadow_f8`. LLVM 12's ASan also aborts in `GetThreadStackAndTls` (`sanitizer_linux_libcdep.cpp:556`) when a new thread's TLS ends 0x80 bytes past the stack mapping on this glibc. Before running, the `movl $556` check's `call CheckFailed` in each fuzzer executable was replaced with a jump to the function epilogue. That is a local binary edit so threads can start; it is not a product bug and it is not in the source tree.

## Run

Smoke runs are local processes only. `-max_len=8192` keeps inputs inside the harness caps. `ASAN_OPTIONS` and `UBSAN_OPTIONS` are left at the process defaults the binary was built with, plus a halt on the first error so a crasher is saved.

```bash
export PATH="$HOME/.local/bin:$PATH"
export ASAN_OPTIONS="${ASAN_OPTIONS:+$ASAN_OPTIONS:}halt_on_error=1:detect_leaks=0"
export UBSAN_OPTIONS="${UBSAN_OPTIONS:+$UBSAN_OPTIONS:}halt_on_error=1:print_stacktrace=1"

# 90s smokes. Corpus seeds for SASL live in-tree.
timeout 90 bazel-bin/src/mongo/rpc/protocol_fuzzer -max_len=8192 -timeout=30 -rss_limit_mb=2048 \
  fuzz-artifacts/corpus/protocol
timeout 90 bazel-bin/src/mongo/db/auth/sasl_handshake_fuzzer -max_len=4096 -timeout=30 -rss_limit_mb=4096 \
  src/mongo/db/auth/sasl_handshake_corpus fuzz-artifacts/corpus/sasl
timeout 120 bazel-bin/src/mongo/db/op_msg_fuzzer -max_len=8192 -timeout=60 -rss_limit_mb=4096 \
  fuzz-artifacts/corpus/op_msg
```

Crash artifacts, if any, are the files libFuzzer writes next to the binary (`crash-*`, `leak-*`, `timeout-*`) plus the sanitizer log. Copy them under `fuzz-artifacts/` with the fuzzer name and `git rev-parse HEAD`.

## Results

Commit under test for the smokes below: `666d84462bb` plus the `sasl_commands` dependency that links `SaslPayload::parseFromBSON` (required at runtime by `sasl_commands_idl`). No sanitizer crashes. Disk after the build was about 59G used / 196G free on a 254G volume. The build ran at `--jobs=4` with `--local_resources=memory=14000` and did not OOM.

| Fuzzer | Time | exec/s | Coverage | Peak RSS | Result |
| --- | --- | --- | --- | --- | --- |
| `protocol_fuzzer` | 90s | 4014 | 8792 edges, 12007 features | 771MB | no crasher (357280 execs) |
| `sasl_handshake_fuzzer` | 90s | 511 | 25405 edges, 36955 features | 2084MB | no crasher (42433 execs) |
| `op_msg_fuzzer` | 120s | 318 | 20542 edges, 32957 features | 3841MB | no crasher (30893 execs) |

`op_msg_fuzzer` initialize printed `OP_COMPRESSED_DISPATCH_PROOF dispatches=3 total=3` (snappy, zlib, and zstd each reached `handleRequest`). Further `OP_COMPRESSED_DISPATCH` lines were printed during the smoke. `sasl_handshake_fuzzer` initialize printed ok for SCRAM-SHA-1, SCRAM-SHA-256, PLAIN, OIDC step 1, OIDC step 2, and OAuth metadata. The OIDC JWT self-test string compiled into that binary is rejected by the parser (`IDLFailedToParse: BSON field 'JWT.exp' is missing but a required field`); that is a caught parse failure, not a sanitizer error. The corpus seeds were updated afterward so the fuzzer exercises a token that parses. See below. The binary was not rebuilt, so its initialize line still prints that failure.

Logs: `fuzz-artifacts/runs/protocol_smoke3.log`, `sasl_smoke4.log`, `opmsg_smoke.log`. Build log: `fuzz-artifacts/build3.log`.

## JWT seed

`crypto/jwt_types.idl` struct `JWT` requires `iss`, `sub`, `aud`, and `exp` (`exp` is `unixEpoch`, seconds, and the comment marks it required even though RFC 7519 does not). `JWSValidatedToken::extractIssuerAndAudienceFromCompactSerialization` base64url-decodes the body, `fromjson`s it, and `JWT::parse`s it. The old body was `{"iss":"https://example.com","sub":"fuzzer","aud":"app"}` and parse stopped on the missing `exp` before issuer/audience extraction.

The corpus bytes the existing binary loads now include `"exp":1893456000` (2030-01-01T00:00:00Z, which fits in a BSON int32):

- `src/mongo/db/auth/sasl_handshake_corpus/oidc_jwt` — selector byte `0x06` (`Target::kOidcJwt`) plus the compact token.
- `src/mongo/db/auth/sasl_handshake_corpus/oidc_step2` — selector byte `0x05` (`Target::kOidcStep2`) plus `{jwt: "<same token>"}`, which `_parseBson` accepts as JSON and `OIDCMechanismClientStep2` requires as field `jwt`.

`_sampleJwt()` in `sasl_handshake_fuzzer.cpp` uses the same body so a future build's self-test matches the seed. This hunt does not rebuild, so the process still prints the old `JWT.exp` self-test line. That line is the compiled-in string, not the corpus.

One execution of only the new `oidc_jwt` seed covered 1833 edges / 1834 features, against 1684 / 1685 for the exp-less token. One execution of only the new `oidc_step2` seed covered 1986 / 1987, against 1837 / 1838. The extra edges are the successful `JWT::parse` and issuer/audience extraction.

## Long hunt

Same already-linked binaries (`bazel-bin/.../*_fuzzer`, still carrying the local ASan TLS epilogue patch). No rebuild. `bazel shutdown` first so the ~2.3GiB server is not sitting next to the fuzzers. Machine is 4 CPUs and 16GiB with no swap. Smoke peaks were about 3841MB (`op_msg`), 2084MB (`sasl`), and 771MB (`protocol`), so the parallel shape is `op_msg` fork=2, `sasl` fork=1, `protocol` fork=1. Expected steady RSS is about 7.6+2.1+0.8 GiB. `rss_limit_mb` is above those peaks (5120 / 3072 / 1536) and the sum of the limits is under 16GiB. A single malloc larger than `rss_limit_mb` is also rejected by libFuzzer (`malloc_limit_mb` defaults to the same value). LeakSanitizer stays off (`ASAN_OPTIONS=detect_leaks=0` and `-detect_leaks=0`): the harness holds a process-lifetime service context, and an exit-time leak report would abort the session. Heap-use-after-free, overflow, and UBSan still halt the child. `-fork` restarts a child after a crash, oom, or timeout (`-ignore_crashes=1 -ignore_ooms=1 -ignore_timeouts=1`) and writes each artifact under `artifacts/crashers/<target>/`. The growing corpus is `artifacts/corpus/<target>/`, seeded from the in-tree SASL seeds (including the fixed JWT) and the smoke corpora.

`-max_total_time` is 14400s for `op_msg_fuzzer` and `sasl_handshake_fuzzer`, and 3600s for `protocol_fuzzer`. Driver and argv are `artifacts/long-hunt.sh`. Each log starts with the harness commit SHA and the fuzzer argv.

```bash
export ASAN_SYMBOLIZER_PATH="$HOME/.cache/bazel/_bazel_ubuntu/eab0d61a99b6696edb3d2aff87b585e8/external/mongo_toolchain_v4/stow/llvm-v4/bin/llvm-symbolizer"
export UBSAN_SYMBOLIZER_PATH="$ASAN_SYMBOLIZER_PATH"
export ASAN_OPTIONS="halt_on_error=1:detect_leaks=0:allocator_may_return_null=1:symbolize=1:malloc_context_size=30"
export UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1:symbolize=1"
# from /workspace, after seeding artifacts/corpus/<target>
bazel-bin/src/mongo/db/op_msg_fuzzer -fork=2 -ignore_crashes=1 -ignore_ooms=1 -ignore_timeouts=1 \
  -max_total_time=14400 -print_final_stats=1 -rss_limit_mb=5120 -max_len=8192 -timeout=60 \
  -detect_leaks=0 -artifact_prefix=artifacts/crashers/op_msg/ artifacts/corpus/op_msg
bazel-bin/src/mongo/db/auth/sasl_handshake_fuzzer -fork=1 -ignore_crashes=1 -ignore_ooms=1 -ignore_timeouts=1 \
  -max_total_time=14400 -print_final_stats=1 -rss_limit_mb=3072 -max_len=4096 -timeout=30 \
  -detect_leaks=0 -artifact_prefix=artifacts/crashers/sasl/ artifacts/corpus/sasl
bazel-bin/src/mongo/rpc/protocol_fuzzer -fork=1 -ignore_crashes=1 -ignore_ooms=1 -ignore_timeouts=1 \
  -max_total_time=3600 -print_final_stats=1 -rss_limit_mb=1536 -max_len=8192 -timeout=30 \
  -detect_leaks=0 -artifact_prefix=artifacts/crashers/protocol/ artifacts/corpus/protocol
```
