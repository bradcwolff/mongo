# Lane B fuzzer notes (r8.0.34)

Defensive libFuzzer harnesses only. No exploit writeups.

## What changed

- `src/mongo/db/op_msg_fuzzer_fixture.cpp` decompresses `OP_COMPRESSED` (snappy, zlib, zstd, noop) with `MessageCompressorManager::decompressMessage` and then calls `ServiceEntryPoint::handleRequest`. That is the same decompress-then-dispatch seam as `SessionWorkflow::WorkItem::decompressRequest`. The pre-auth size cap (`transport::gPreAuthMaximumMessageSizeBytes`, default 16KiB) is applied first; a failed attempt is retried with a 256KiB cap so the claimed-size check still runs without allocating `MaxMessageSizeBytes` (48MiB).
- `src/mongo/db/op_msg_fuzzer.cpp` keeps the original wire-message input and also wraps every input in snappy/zlib/zstd (`testCompressedInput`), including mutations of the claimed uncompressed size. `LLVMFuzzerInitialize` compresses a `{ping:1,$db:"admin"}` with each of snappy, zlib, and zstd and requires all three to reach command dispatch.
- `src/mongo/rpc/protocol_fuzzer.cpp` registers snappy, zlib, and zstd (previously only noop) on the decompress-and-parse path. It does not dispatch commands; dispatch is covered by the fixture above. Decompression is capped at 256KiB.
- `src/mongo/db/auth/sasl_handshake_fuzzer.cpp` is a new harness for server-side SCRAM-SHA-1, SCRAM-SHA-256, and PLAIN `step()`, `saslStart` / `saslContinue` IDL parsing, OIDC client step 1/2 IDL parsing (`OIDCMechanismClientStep1` / `OIDCMechanismClientStep2`), compact JWT body parsing (`JWSValidatedToken::extractIssuerAndAudienceFromCompactSerialization`), and OAuth authorization-server metadata parsing. X.509 ASN.1 is not targeted (`asn1_parser_fuzzer` already covers it). Community r8.0.34 has no server `MONGODB-OIDC` mechanism class; the OIDC surface here is the server-side handshake parsers that are in tree.

Proof that compressed bytes reach command dispatch: the fixture increments a counter only after `decompressMessage` succeeds and immediately before `handleRequest`. Initialize prints `OP_COMPRESSED_DISPATCH_PROOF dispatches=3` when snappy, zlib, and zstd each take that path. Each of those also prints `OP_COMPRESSED_DISPATCH`.

## Build

Bazel 7.5.0 (MongoDB bazelisk). Sanitizers: address, undefined, fuzzer. Enterprise is off (this tree has no enterprise module). Remote execution is disabled.

```bash
export PATH="$HOME/.local/bin:$PATH"
python3 buildscripts/install_bazel.py   # once

bazel build \
  --config=local \
  --config=dbg_aubsan \
  --//bazel/config:fsan=True \
  --//bazel/config:build_enterprise=False \
  --jobs=2 \
  //src/mongo/rpc:protocol_fuzzer \
  //src/mongo/db/auth:sasl_handshake_fuzzer \
  //src/mongo/db:op_msg_fuzzer
```

`--config=dbg_aubsan` is the in-repo address+undefined profile (`--//bazel/config:asan=True`, `--//bazel/config:ubsan=True`, system allocator, dynamic link). `--//bazel/config:fsan=True` turns on `-fsanitize=fuzzer-no-link` for the build and makes `mongo_cc_fuzzer_test` targets compatible. Fuzzer binaries link with `-fsanitize=fuzzer`.

Binaries (after a successful build):

- `bazel-bin/src/mongo/rpc/protocol_fuzzer`
- `bazel-bin/src/mongo/db/auth/sasl_handshake_fuzzer`
- `bazel-bin/src/mongo/db/op_msg_fuzzer`

## Run

Smoke runs are local processes only. `-max_len=8192` keeps inputs inside the harness caps. `ASAN_OPTIONS` and `UBSAN_OPTIONS` are left at the process defaults the binary was built with, plus a halt on the first error so a crasher is saved.

```bash
export PATH="$HOME/.local/bin:$PATH"
export ASAN_OPTIONS="${ASAN_OPTIONS:+$ASAN_OPTIONS:}halt_on_error=1:detect_leaks=0"
export UBSAN_OPTIONS="${UBSAN_OPTIONS:+$UBSAN_OPTIONS:}halt_on_error=1:print_stacktrace=1"

# 90s smokes. Corpus seeds for SASL live in-tree.
timeout 90 bazel-bin/src/mongo/rpc/protocol_fuzzer -max_len=8192 -timeout=30 -rss_limit_mb=2048 \
  fuzz-artifacts/corpus/protocol
timeout 90 bazel-bin/src/mongo/db/auth/sasl_handshake_fuzzer -max_len=4096 -timeout=30 -rss_limit_mb=2048 \
  src/mongo/db/auth/sasl_handshake_corpus fuzz-artifacts/corpus/sasl
timeout 120 bazel-bin/src/mongo/db/op_msg_fuzzer -max_len=8192 -timeout=60 -rss_limit_mb=4096 \
  fuzz-artifacts/corpus/op_msg
```

Crash artifacts, if any, are the files libFuzzer writes next to the binary (`crash-*`, `leak-*`, `timeout-*`) plus the sanitizer log. Copy them under `fuzz-artifacts/` with the fuzzer name and `git rev-parse HEAD`.

## Results

Filled in after the sanitizer build and smokes on this VM.
