# Aggregation execution fuzzer (Lane C)

Defensive libFuzzer harness for the MongoDB 8.0.34 aggregation pipeline and expression execution engine. It builds grammar-valid `aggregate` commands and dispatches them through the existing `OpMsgFuzzerFixture` service entry point. It does not fuzz raw BSON, BSONColumn, or OP_MSG bytes.

Base commit: `r8.0.34` (`a1cb58fa746233febef0da3e8034533ed4320c22`).

## What runs

`src/mongo/db/agg_exec_fuzzer.cpp` turns fuzzer bytes into a pipeline (stage choice, nested expressions, constants) and calls `OpMsgFuzzerFixture::runCommand()`.

That method builds an OP_MSG and calls `ServiceEntryPoint::handleRequest` on the same `ServiceContext` the `op_msg_fuzzer` target uses (WiredTiger, catalog, sharding state, replication coordinator mock). `prepareForAggregationExecutionFuzzing()` grants the in-memory client internal authorization and allows writes so seeding and execution are not rejected before the engine runs. The original byte-oriented `testOneInput` path is unchanged.

Startup then:

1. Best-effort `setParameter` of `internalQueryFrameworkControl=trySbeEngine` and `featureFlagSbeFull=true` so eligible stages, including `$group` and `$lookup`, can take the SBE path.
2. Inserts seed collections `fuzzdb.docs`, `fuzzdb.other`, and `fuzzdb.graph` (mixed scalars, arrays, subdocuments, dates, a parent chain, and a `2dsphere` `loc`).
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
  --//bazel/config:compiler_type=clang \
  --//bazel/config:opt=debug \
  --//bazel/config:allocator=system \
  --//bazel/config:linkstatic=False \
  --//bazel/config:asan=True \
  --//bazel/config:fsan=True \
  --jobs=2 \
  //src/mongo/db:agg_exec_fuzzer
```

`--jobs=2` and dynamic linking are there to keep the ASAN link inside a small VM. If the link is killed, rerun with `--jobs=1` and record RSS and free disk.

The binary is `bazel-bin/src/mongo/db/agg_exec_fuzzer`.

## Run

```bash
mkdir -p artifacts
ASAN_OPTIONS=abort_on_error=1:halt_on_error=1:detect_leaks=0 \
  ./bazel-bin/src/mongo/db/agg_exec_fuzzer \
  src/mongo/db/fuzz_corpus/agg_exec_fuzzer \
  -artifact_prefix=artifacts/agg_exec_ \
  -max_total_time=90 \
  -timeout=15 \
  -rss_limit_mb=0 \
  -print_final_stats=1
```

`detect_leaks=0` avoids treating the long-lived fixture's process-lifetime allocations as a finding. `rss_limit_mb=0` disables libFuzzer's default 2GiB RSS cap, which an ASAN mongod-sized process exceeds during startup.

Replay one input and print the command:

```bash
AGG_FUZZ_LOG=1 ASAN_OPTIONS=abort_on_error=1:halt_on_error=1:detect_leaks=0 \
  ./bazel-bin/src/mongo/db/agg_exec_fuzzer artifacts/agg_exec_<crash-file>
```

Crash inputs and sanitizer stacks, if any, are kept under `artifacts/`. This harness does not turn a crash into an exploit, a reachability proof, or a bounty write-up.

## This run

Build and smoke results are filled in after the sanitizer binary is produced.
