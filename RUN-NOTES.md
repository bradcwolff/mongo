# Aggregation execution fuzzer (Lane C)

Defensive libFuzzer harness for the MongoDB 8.0.34 aggregation pipeline and expression execution engine. It builds grammar-valid `aggregate` commands and dispatches them through the existing `OpMsgFuzzerFixture` service entry point. It does not fuzz raw BSON, BSONColumn, or OP_MSG bytes.

Base commit: `r8.0.34` (`a1cb58fa746233febef0da3e8034533ed4320c22`).

## What runs

`src/mongo/db/agg_exec_fuzzer.cpp` turns fuzzer bytes into a pipeline (stage choice, nested expressions, constants) and calls `OpMsgFuzzerFixture::runCommand()`.

That method builds an OP_MSG and calls `ServiceEntryPoint::handleRequest` on the same `ServiceContext` the `op_msg_fuzzer` target uses (WiredTiger, catalog, sharding state, replication coordinator mock). `prepareForAggregationExecutionFuzzing()` grants the in-memory client internal authorization and allows writes so seeding and execution are not rejected before the engine runs. The original byte-oriented `testOneInput` path is unchanged.

`prepareForAggregationExecutionFuzzing()` also installs `IndexBuildsCoordinatorMongod` (so `createIndexes` can build the seed `2dsphere` index) and `QuerySettingsManager` (aggregate looks up query settings before execution). The fuzzer links `//src/mongo/db/commands:standalone` and `//src/mongo/db/pipeline/process_interface:mongod_process_interface_factory` with `-Wl,--no-as-needed`, and takes the address of `mongo::runAggregate`, so `aggregate` / `insert` / `createIndexes` and `MongoProcessInterface::create` are registered.

Startup then:

1. Best-effort `setParameter` of `internalQueryFrameworkControl=trySbeEngine`. `featureFlagSbeFull` is startup-only on this tag and returns `IllegalOperation` (code 20) at runtime; that failure is logged and is not fatal. `trySbeEngine` is what lets eligible `$group` / `$lookup` stages take the SBE path.
2. Inserts seed collections `fuzzdb.docs`, `fuzzdb.other`, and `fuzzdb.graph` (mixed scalars, arrays, subdocuments, dates, a parent chain, and a `2dsphere` `loc`), then `createIndexes` (`a_1` and `loc_2dsphere`) on each.
3. Requires these probes to return `ok: 1` before fuzzing: nested `$expr` + `$group`, equality `$lookup`, `$lookup` with a nested `$expr` subpipeline, `$graphLookup`, `$setWindowFields`.
4. Best-effort lowers sort / `$group` / SBE hash-agg spill thresholds so later inputs exercise spill code.

Each fuzz input is one `aggregate` command (`maxTimeMS` 2000, batch size at least 1) against `docs`, `other`, `graph`, or a collectionless `$documents` pipeline. Stages include `$match`/`$expr`, `$project`/`$addFields`, `$group`, `$lookup` (equality and pipeline, including one nested lookup), `$graphLookup` (maxDepth 0–3), `$setWindowFields` (sum/avg/rank/shift/expMovingAvg/percentile/derivative), `$bucket`/`$bucketAuto`, `$facet`, `$redact`, `$unionWith`, `$fill`, `$densify`, `$unwind`, `$geoNear`, and array expressions (`$map`, `$filter`, `$reduce`, `$sortArray`). Command errors are returned as statuses. Address-sanitizer faults are not caught.

`AGG_FUZZ_LOG=1` prints each command before execution.

Corpus seeds: `src/mongo/db/fuzz_corpus/agg_exec_fuzzer/`.

## Build

This tree maps the historical `--sanitize=fuzzer,address` selection onto Bazel flags. Fuzzer targets are incompatible unless `--//bazel/config:fsan=True`. Address and fuzzer sanitizers also require the system allocator, Clang, and `opt=on` or `opt=debug`.

```bash
python3 buildscripts/install_bazel.py
export PATH="$HOME/.local/bin:$PATH"

bazel build \
  --config=local \
  --//bazel/config:compiler_type=clang \
  --//bazel/config:opt=debug \
  --//bazel/config:allocator=system \
  --//bazel/config:linkstatic=False \
  --//bazel/config:build_enterprise=False \
  --//bazel/config:asan=True \
  --//bazel/config:fsan=True \
  --jobs=2 \
  //src/mongo/db:agg_exec_fuzzer
```

Put `--jobs=2` after `--config=local`. That config sets `--jobs=auto`, and the later flag wins. `--//bazel/config:build_enterprise=False` is required on this community tree: the default is enterprise on, and the Bazel wrapper does not keep a `--build_enterprise=False` it appends itself. Dynamic linking (`linkstatic=False`) keeps the ASAN link inside a small VM. If the link is killed, rerun with `--jobs=1` and record RSS and free disk.

The binary is `bazel-bin/src/mongo/db/agg_exec_fuzzer` (the real ELF is `agg_exec_fuzzer_with_debug` under the Bazel execroot). This clang emits `__asan_set_shadow_(addr, size)` and mold does not rewrite it to `__asan_set_shadow_00`. The harness defines and exports that symbol.

## Run

LibFuzzer writes new coverage inputs into the first corpus directory. Copy the seeds so the in-tree files stay the original 16.

```bash
mkdir -p artifacts /tmp/agg_exec_corpus
cp -a src/mongo/db/fuzz_corpus/agg_exec_fuzzer/. /tmp/agg_exec_corpus/
ASAN_OPTIONS=abort_on_error=1:halt_on_error=1:detect_leaks=0:allocator_may_return_null=1 \
  ./bazel-bin/src/mongo/db/agg_exec_fuzzer \
  /tmp/agg_exec_corpus \
  -artifact_prefix=artifacts/agg_exec_ \
  -max_total_time=90 \
  -timeout=30 \
  -rss_limit_mb=0 \
  -print_final_stats=1
```

`detect_leaks=0` avoids treating the long-lived fixture's process-lifetime allocations as a finding. `rss_limit_mb=0` disables libFuzzer's default 2GiB RSS cap. `allocator_may_return_null=1` lets the server's own OOM paths return instead of aborting inside the sanitizer. `-timeout=30` is the per-input cap used for the ASAN smoke below; individual pipelines in that run stayed under one second.

Replay one input and print the command:

```bash
AGG_FUZZ_LOG=1 ASAN_OPTIONS=abort_on_error=1:halt_on_error=1:detect_leaks=0 \
  ./bazel-bin/src/mongo/db/agg_exec_fuzzer artifacts/agg_exec_<crash-file>
```

Crash inputs and sanitizer stacks, if any, are kept under `artifacts/`. This harness does not turn a crash into an exploit, a reachability proof, or a bounty write-up.

## This run

Branch `cursor/agg-exec-fuzzer-72a8`, base tag `r8.0.34` (`a1cb58fa746233febef0da3e8034533ed4320c22`), PR base `v8.0.34` (same commit; there is no remote `r8.0.34` branch).

Harness and smoke revision: `19215cd4349c58008a7b5cd64aafa942e9504d20`.

Sanitizer build of `//src/mongo/db:agg_exec_fuzzer` completed (`--//bazel/config:asan=True --//bazel/config:fsan=True`, `opt=debug`, system allocator, dynamic link, `build_enterprise=False`, `--jobs=2`). Binary: `bazel-bin/src/mongo/db/agg_exec_fuzzer`.

One-input smoke (`-runs=1` on `seed_00`) exited 0. Setup log:

- `trySbeEngine`: ok
- `featureFlagSbeFull`: IllegalOperation, not changeable at runtime (expected, not fatal)
- inserts of `docs`, `other`, `graph`: ok
- indexes on those collections: ok
- probes `$expr`+`$group`, equality `$lookup`, pipeline `$lookup`, `$graphLookup`, `$setWindowFields`: ok
- sort / group / SBE hash-agg spill parameters: ok
- printed `agg_exec_fuzzer ready`

Bounded smoke, same binary, `-max_total_time=90 -timeout=30 -print_final_stats=1` against the 16 seeds:

- `Done 50837 runs in 91 second(s)`
- `stat::average_exec_per_sec: 558`
- coverage `5448` after the seeds, `13213` at the end; `16538` features
- `stat::peak_rss_mb: 1712`
- `stat::slowest_unit_time_sec: 0`
- process exit 0
- libFuzzer RSS line during the run stayed at 1712Mb; `ps` RSS was about 1.65 GiB
- disk on `/` at the end of the run: 46G used, 209G free. The link was not OOM-killed

No AddressSanitizer report and no libFuzzer crash, timeout, or OOM artifact. `artifacts/` has `agg_exec_smoke90.txt` with that stat block. Earlier empty-input artifacts (`crash-da39a3ee…`) were harness setup failures (a glibc/ASAN TLS check, then missing service wiring) and were deleted. They are not aggregation defects.

Local environment fixes that are not in the commit, and that a fresh VM needs before this binary will run:

- Empty Bazel stubs under `src/mongo/db/modules/enterprise/` so analysis can load unconditional enterprise labels. They are gitexcluded. Pass `--//bazel/config:build_enterprise=False`.
- Headers from `libssl-dev`, `libcurl4-openssl-dev`, `zlib1g-dev`, and `liblzma-dev` (libmongocrypt includes `openssl/crypto.h`).
- The mold link feature puts the toolchain `gcc-v4/lib64` on `LD_LIBRARY_PATH`. That tree's `libstdc++.so.6` is older than `GLIBCXX_3.4.30`, which system `libicuuc.so.74` needs, so `clang++` fails to start. Point both the external and execroot `libstdc++.so.6` symlinks at `/usr/lib/x86_64-linux-gnu/libstdc++.so.6`. Leave `libstdc++.so` aimed at the toolchain SONAME.
- LLVM 12 ASAN's `GetThreadStackAndTls` CHECKs `tls_end <= stack_end`. glibc 2.39 TLS extends `0x80` bytes past the pthread stack, so every new thread aborts before `main` reaches the grammar. After each link, the executable's unique `ja` into that check (`77 31 48 29 f2`, file offset `0x1b00e3` on this link) is overwritten with two nops. Reapply after every relink; the offset moves. Do not patch `libclang_rt.asan-x86_64.a` or Bazel will relink the world. The output ELF is mode `0555`; `chmod u+w` before writing. This nop is not a product patch.
