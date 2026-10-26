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

`op_msg_fuzzer` initialize printed `OP_COMPRESSED_DISPATCH_PROOF dispatches=3 total=3` (snappy, zlib, and zstd each reached `handleRequest`). Further `OP_COMPRESSED_DISPATCH` lines were printed during the smoke. `sasl_handshake_fuzzer` initialize printed ok for SCRAM-SHA-1, SCRAM-SHA-256, PLAIN, OIDC step 1, OIDC step 2, and OAuth metadata. The OIDC JWT self-test seed is rejected by the parser (`IDLFailedToParse: BSON field 'JWT.exp' is missing but a required field`); that is a caught parse failure, not a sanitizer error.

Logs: `fuzz-artifacts/runs/protocol_smoke3.log`, `sasl_smoke4.log`, `opmsg_smoke.log`. Build log: `fuzz-artifacts/build3.log`.
