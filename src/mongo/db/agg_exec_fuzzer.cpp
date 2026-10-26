/**
 *    Copyright (C) 2026-present MongoDB, Inc.
 *
 *    This program is free software: you can redistribute it and/or modify
 *    it under the terms of the Server Side Public License, version 1,
 *    as published by MongoDB, Inc.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    Server Side Public License for more details.
 *
 *    You should have received a copy of the Server Side Public License
 *    along with this program. If not, see
 *    <http://www.mongodb.com/licensing/server-side-public-license>.
 *
 *    As a special exception, the copyright holders give permission to link the
 *    code of portions of this program with the OpenSSL library under certain
 *    conditions as described in each individual source file and distribute
 *    linked combinations including the program with the OpenSSL library. You
 *    must comply with the Server Side Public License in all respects for
 *    all of the code used other than as permitted herein. If you modify file(s)
 *    with this exception, you may extend this exception to your version of the
 *    file(s), but you are not obligated to do so. If you do not wish to do so,
 *    delete this exception statement from your version. If you delete this
 *    exception statement from all source files in the program, then also delete
 *    it in the license file.
 */

/**
 * Structure-aware aggregation execution fuzzer.
 *
 * LibFuzzer bytes are consumed as a pipeline grammar (stage choice, expression
 * shape, constants). Each input becomes one grammar-valid `aggregate` command
 * and is dispatched through OpMsgFuzzerFixture::runCommand(), which calls the
 * mongod ServiceEntryPoint on the op_msg fuzzer ServiceContext. That is the
 * pipeline and expression execution engine, including $lookup / $graphLookup,
 * $setWindowFields, nested $expr, and SBE when the server selects it.
 *
 * This harness does not mutate raw OP_MSG, BSON, or BSONColumn bytes.
 */

#include <cstdlib>
#include <iostream>
#include <string>

#include <boost/log/core/core.hpp>

#include "mongo/bson/bsonobjbuilder.h"
#include "mongo/bson/json.h"
#include "mongo/db/commands/run_aggregate.h"
#include "mongo/db/op_msg_fuzzer_fixture.h"
#include "mongo/util/time_support.h"

// ODR-use a symbol from //src/mongo/db/commands:standalone so the linker keeps
// that shared library. Its static initializers register aggregate/insert/createIndexes.
static const auto kKeepStandaloneCommands = &mongo::runAggregate;

// This toolchain's clang emits calls to __asan_set_shadow_(addr, size) to clear
// an inline stack-shadow region on function exit (the same (addr, size) shape as
// __asan_set_shadow_00). compiler-rt only defines the suffixed setters, and mold
// does not rewrite the unsuffixed symbol, so shared objects import it and the
// executable has to provide it. -rdynamic exports this definition to those DSOs.
extern "C" void __asan_set_shadow_00(unsigned long addr, unsigned long size);
extern "C" void __asan_set_shadow_(unsigned long addr, unsigned long size) {
    __asan_set_shadow_00(addr, size);
}

namespace mongo {
namespace {

template <typename T, size_t N>
constexpr size_t nOf(const T (&)[N]) {
    return N;
}

class Bytes {
public:
    Bytes(const uint8_t* data, size_t size) : _data(data), _size(size) {}

    uint8_t next() {
        if (_i >= _size) {
            return 0;
        }
        return _data[_i++];
    }

    size_t mod(size_t n) {
        if (n == 0) {
            return 0;
        }
        return static_cast<size_t>(next()) % n;
    }

    bool bit() {
        return (next() & 1) != 0;
    }

    // Inclusive range [-10, 10].
    int smallInt() {
        return static_cast<int>(next() % 21) - 10;
    }

private:
    const uint8_t* _data;
    size_t _size;
    size_t _i = 0;
};

constexpr StringData kNumPaths[] = {
    "$a"_sd, "$b"_sd, "$_id"_sd, "$sub.x"_sd, "$w"_sd, "$v"_sd, "$parent"_sd, "$$la"_sd};
constexpr StringData kStrPaths[] = {"$s"_sd, "$sub.y"_sd, "$name"_sd, "$$lb"_sd};
constexpr StringData kArrPaths[] = {"$arr"_sd, "$sub.z"_sd};
constexpr StringData kStrLits[] = {""_sd, "a"_sd, "bb"_sd, "xyz"_sd, "n0"_sd, "y"_sd, "ff"_sd};
constexpr StringData kCmp[] = {"$eq"_sd, "$ne"_sd, "$gt"_sd, "$gte"_sd, "$lt"_sd, "$lte"_sd};
constexpr StringData kFields[] = {
    "a"_sd, "b"_sd, "s"_sd, "flag"_sd, "d"_sd, "parent"_sd, "n"_sd, "sub.x"_sd};

void appendBoolExpr(Bytes& in, BSONObjBuilder& bob, StringData name, int depth);
void appendNumExpr(Bytes& in, BSONObjBuilder& bob, StringData name, int depth);
void appendStrExpr(Bytes& in, BSONObjBuilder& bob, StringData name, int depth);
void appendValueExpr(Bytes& in, BSONObjBuilder& bob, StringData name, int depth);

void appendBoolExprElt(Bytes& in, BSONArrayBuilder& arr, int depth) {
    BSONObjBuilder wrapped;
    appendBoolExpr(in, wrapped, "e"_sd, depth);
    auto owned = wrapped.obj();
    arr.append(owned["e"]);
}

void appendNumExprElt(Bytes& in, BSONArrayBuilder& arr, int depth) {
    BSONObjBuilder wrapped;
    appendNumExpr(in, wrapped, "e"_sd, depth);
    auto owned = wrapped.obj();
    arr.append(owned["e"]);
}

void appendStrExprElt(Bytes& in, BSONArrayBuilder& arr, int depth) {
    BSONObjBuilder wrapped;
    appendStrExpr(in, wrapped, "e"_sd, depth);
    auto owned = wrapped.obj();
    arr.append(owned["e"]);
}

void appendValueExprElt(Bytes& in, BSONArrayBuilder& arr, int depth) {
    BSONObjBuilder wrapped;
    appendValueExpr(in, wrapped, "e"_sd, depth);
    auto owned = wrapped.obj();
    arr.append(owned["e"]);
}

void appendBoolExpr(Bytes& in, BSONObjBuilder& bob, StringData name, int depth) {
    const int shape = depth <= 0 ? 0 : static_cast<int>(in.mod(5));
    switch (shape) {
        case 0: {
            BSONObjBuilder expr(bob.subobjStart(name));
            BSONArrayBuilder args(expr.subarrayStart(kCmp[in.mod(nOf(kCmp))]));
            args.append(kNumPaths[in.mod(nOf(kNumPaths))]);
            args.append(in.smallInt());
            break;
        }
        case 1: {
            BSONObjBuilder expr(bob.subobjStart(name));
            BSONArrayBuilder args(expr.subarrayStart(kCmp[in.mod(nOf(kCmp))]));
            args.append(kStrPaths[in.mod(nOf(kStrPaths))]);
            args.append(kStrLits[in.mod(nOf(kStrLits))]);
            break;
        }
        case 2: {
            BSONObjBuilder expr(bob.subobjStart(name));
            BSONArrayBuilder args(expr.subarrayStart("$and"_sd));
            appendBoolExprElt(in, args, depth - 1);
            appendBoolExprElt(in, args, depth - 1);
            break;
        }
        case 3: {
            BSONObjBuilder expr(bob.subobjStart(name));
            BSONArrayBuilder args(expr.subarrayStart("$or"_sd));
            appendBoolExprElt(in, args, depth - 1);
            appendBoolExprElt(in, args, depth - 1);
            if (in.bit()) {
                appendBoolExprElt(in, args, depth - 1);
            }
            break;
        }
        default: {
            BSONObjBuilder expr(bob.subobjStart(name));
            BSONArrayBuilder args(expr.subarrayStart("$not"_sd));
            appendBoolExprElt(in, args, depth - 1);
            break;
        }
    }
}

void appendNumExpr(Bytes& in, BSONObjBuilder& bob, StringData name, int depth) {
    const int shape = depth <= 0 ? static_cast<int>(in.mod(3)) : static_cast<int>(in.mod(10));
    switch (shape) {
        case 0:
            bob.append(name, kNumPaths[in.mod(nOf(kNumPaths))]);
            break;
        case 1:
            bob.append(name, in.smallInt());
            break;
        case 2:
            bob.append(name, in.bit() ? 1.5 : 0.0);
            break;
        case 3: {
            BSONObjBuilder expr(bob.subobjStart(name));
            BSONArrayBuilder args(expr.subarrayStart("$add"_sd));
            appendNumExprElt(in, args, depth - 1);
            appendNumExprElt(in, args, depth - 1);
            break;
        }
        case 4: {
            BSONObjBuilder expr(bob.subobjStart(name));
            BSONArrayBuilder args(expr.subarrayStart(in.bit() ? "$subtract"_sd : "$multiply"_sd));
            appendNumExprElt(in, args, depth - 1);
            appendNumExprElt(in, args, depth - 1);
            break;
        }
        case 5: {
            BSONObjBuilder expr(bob.subobjStart(name));
            BSONArrayBuilder args(expr.subarrayStart("$mod"_sd));
            appendNumExprElt(in, args, depth - 1);
            args.append(1 + static_cast<int>(in.mod(5)));
            break;
        }
        case 6: {
            BSONObjBuilder expr(bob.subobjStart(name));
            BSONArrayBuilder args(expr.subarrayStart("$abs"_sd));
            appendNumExprElt(in, args, depth - 1);
            break;
        }
        case 7: {
            BSONObjBuilder expr(bob.subobjStart(name));
            BSONArrayBuilder args(expr.subarrayStart("$size"_sd));
            args.append(kArrPaths[in.mod(nOf(kArrPaths))]);
            break;
        }
        case 8: {
            BSONObjBuilder expr(bob.subobjStart(name));
            BSONArrayBuilder args(expr.subarrayStart("$year"_sd));
            args.append("$d"_sd);
            break;
        }
        default: {
            BSONObjBuilder expr(bob.subobjStart(name));
            BSONArrayBuilder args(expr.subarrayStart("$ifNull"_sd));
            appendNumExprElt(in, args, depth - 1);
            args.append(0);
            break;
        }
    }
}

void appendStrExpr(Bytes& in, BSONObjBuilder& bob, StringData name, int depth) {
    const int shape = depth <= 0 ? static_cast<int>(in.mod(2)) : static_cast<int>(in.mod(7));
    switch (shape) {
        case 0:
            bob.append(name, kStrPaths[in.mod(nOf(kStrPaths))]);
            break;
        case 1:
            bob.append(name, kStrLits[in.mod(nOf(kStrLits))]);
            break;
        case 2: {
            BSONObjBuilder expr(bob.subobjStart(name));
            BSONArrayBuilder args(expr.subarrayStart("$toLower"_sd));
            appendStrExprElt(in, args, depth - 1);
            break;
        }
        case 3: {
            BSONObjBuilder expr(bob.subobjStart(name));
            BSONArrayBuilder args(expr.subarrayStart("$concat"_sd));
            appendStrExprElt(in, args, depth - 1);
            appendStrExprElt(in, args, depth - 1);
            break;
        }
        case 4: {
            BSONObjBuilder expr(bob.subobjStart(name));
            BSONArrayBuilder args(expr.subarrayStart("$substrBytes"_sd));
            appendStrExprElt(in, args, depth - 1);
            args.append(0);
            args.append(1 + static_cast<int>(in.mod(4)));
            break;
        }
        case 5: {
            BSONObjBuilder expr(bob.subobjStart(name));
            BSONObjBuilder dts(expr.subobjStart("$dateToString"_sd));
            dts.append("date"_sd, "$d"_sd);
            dts.append("format"_sd, "%Y-%m-%d"_sd);
            break;
        }
        default: {
            BSONObjBuilder expr(bob.subobjStart(name));
            BSONArrayBuilder args(expr.subarrayStart("$toString"_sd));
            appendNumExprElt(in, args, depth - 1);
            break;
        }
    }
}

void appendValueExpr(Bytes& in, BSONObjBuilder& bob, StringData name, int depth) {
    const int shape = depth <= 0 ? static_cast<int>(in.mod(3)) : static_cast<int>(in.mod(12));
    switch (shape) {
        case 0:
            appendNumExpr(in, bob, name, depth);
            break;
        case 1:
            appendStrExpr(in, bob, name, depth);
            break;
        case 2:
            appendBoolExpr(in, bob, name, depth);
            break;
        case 3: {
            BSONObjBuilder expr(bob.subobjStart(name));
            BSONObjBuilder m(expr.subobjStart("$map"_sd));
            m.append("input"_sd, "$arr"_sd);
            m.append("as"_sd, "item"_sd);
            BSONObjBuilder inExpr(m.subobjStart("in"_sd));
            BSONArrayBuilder add(inExpr.subarrayStart("$add"_sd));
            add.append("$$item"_sd);
            add.append(in.smallInt());
            break;
        }
        case 4: {
            BSONObjBuilder expr(bob.subobjStart(name));
            BSONObjBuilder f(expr.subobjStart("$filter"_sd));
            f.append("input"_sd, "$arr"_sd);
            f.append("as"_sd, "item"_sd);
            BSONObjBuilder cond(f.subobjStart("cond"_sd));
            BSONArrayBuilder cmp(cond.subarrayStart(in.bit() ? "$gte"_sd : "$ne"_sd));
            cmp.append("$$item"_sd);
            cmp.append(in.smallInt());
            break;
        }
        case 5: {
            BSONObjBuilder expr(bob.subobjStart(name));
            BSONObjBuilder red(expr.subobjStart("$reduce"_sd));
            red.append("input"_sd, kArrPaths[in.mod(nOf(kArrPaths))]);
            red.append("initialValue"_sd, in.smallInt());
            BSONObjBuilder inExpr(red.subobjStart("in"_sd));
            BSONArrayBuilder op(inExpr.subarrayStart(in.bit() ? "$add"_sd : "$multiply"_sd));
            op.append("$$value"_sd);
            op.append("$$this"_sd);
            break;
        }
        case 6: {
            BSONObjBuilder expr(bob.subobjStart(name));
            BSONArrayBuilder args(expr.subarrayStart("$arrayElemAt"_sd));
            args.append(kArrPaths[in.mod(nOf(kArrPaths))]);
            args.append(static_cast<int>(in.mod(3)));
            break;
        }
        case 7: {
            BSONObjBuilder expr(bob.subobjStart(name));
            BSONArrayBuilder args(expr.subarrayStart("$slice"_sd));
            args.append("$arr"_sd);
            args.append(1 + static_cast<int>(in.mod(3)));
            break;
        }
        case 8: {
            BSONObjBuilder expr(bob.subobjStart(name));
            BSONObjBuilder sort(expr.subobjStart("$sortArray"_sd));
            sort.append("input"_sd, "$arr"_sd);
            sort.append("sortBy"_sd, in.bit() ? 1 : -1);
            break;
        }
        case 9: {
            BSONObjBuilder expr(bob.subobjStart(name));
            BSONObjBuilder gf(expr.subobjStart("$getField"_sd));
            gf.append("field"_sd, in.bit() ? "x"_sd : "y"_sd);
            gf.append("input"_sd, "$sub"_sd);
            break;
        }
        case 10: {
            BSONObjBuilder expr(bob.subobjStart(name));
            BSONObjBuilder sf(expr.subobjStart("$setField"_sd));
            sf.append("field"_sd, "x"_sd);
            sf.append("input"_sd, "$sub"_sd);
            appendNumExpr(in, sf, "value"_sd, depth - 1);
            break;
        }
        default: {
            BSONObjBuilder expr(bob.subobjStart(name));
            BSONArrayBuilder args(expr.subarrayStart("$cond"_sd));
            appendBoolExprElt(in, args, depth - 1);
            appendNumExprElt(in, args, depth - 1);
            appendNumExprElt(in, args, depth - 1);
            break;
        }
    }
}

void appendWindowBounds(BSONArrayBuilder& bounds, size_t which) {
    switch (which % 5) {
        case 0:
            bounds.append("unbounded"_sd);
            bounds.append("unbounded"_sd);
            break;
        case 1:
            bounds.append("unbounded"_sd);
            bounds.append("current"_sd);
            break;
        case 2:
            bounds.append("current"_sd);
            bounds.append("current"_sd);
            break;
        case 3:
            bounds.append("current"_sd);
            bounds.append("unbounded"_sd);
            break;
        default:
            bounds.append(-1);
            bounds.append(1);
            break;
    }
}

void appendAccumulator(BSONObjBuilder& parent, StringData field, StringData op, StringData input) {
    BSONObjBuilder acc(parent.subobjStart(field));
    acc.append(op, input);
}

enum StageKind : int {
    kMatch = 0,
    kMatchNested,
    kProject,
    kAddFields,
    kGroup,
    kSort,
    kLimitSkip,
    kUnwind,
    kLookupEq,
    kLookupPipeline,
    kGraphLookup,
    kWindow,
    kBucket,
    kBucketAuto,
    kFacet,
    kReplaceWith,
    kRedact,
    kUnionWith,
    kFill,
    kDensify,
    kSample,
    kSortByCount,
    kCount,
    kUnset,
    kGeoNear,
};

int pickKind(Bytes& in) {
    constexpr int kBiased[] = {kMatch,      kMatchNested,    kMatchNested, kGroup,     kGroup,
                               kLookupEq,   kLookupEq,       kLookupPipeline, kLookupPipeline,
                               kGraphLookup, kGraphLookup,   kWindow,      kWindow,    kWindow,
                               kProject,    kAddFields,      kSort,        kUnwind,    kFacet,
                               kRedact,     kUnionWith,      kFill,        kDensify,   kBucket,
                               kBucketAuto, kSample,         kSortByCount, kCount,     kUnset,
                               kGeoNear,    kReplaceWith,    kLimitSkip};
    return kBiased[in.mod(nOf(kBiased))];
}

void appendSimpleStage(Bytes& in, BSONArrayBuilder& pipeline) {
    BSONObjBuilder stage(pipeline.subobjStart());
    switch (in.mod(4)) {
        case 0: {
            BSONObjBuilder match(stage.subobjStart("$match"_sd));
            appendBoolExpr(in, match, "$expr"_sd, 2);
            break;
        }
        case 1: {
            BSONObjBuilder proj(stage.subobjStart("$project"_sd));
            proj.append("_id"_sd, 1);
            proj.append("a"_sd, 1);
            appendValueExpr(in, proj, "c0"_sd, 1);
            break;
        }
        case 2: {
            BSONObjBuilder group(stage.subobjStart("$group"_sd));
            group.append("_id"_sd, "$flag"_sd);
            appendAccumulator(group, "sumA"_sd, "$sum"_sd, "$a"_sd);
            break;
        }
        default:
            stage.append("$limit"_sd, 1 + static_cast<int>(in.mod(5)));
            break;
    }
}

void appendStage(Bytes& in, BSONArrayBuilder& pipeline, bool allowGeo, bool isLast) {
    BSONObjBuilder stage(pipeline.subobjStart());
    int kind = pickKind(in);
    if (kind == kGeoNear && !allowGeo) {
        kind = kMatchNested;
    }
    if ((kind == kCount || kind == kSortByCount || kind == kFacet) && !isLast) {
        kind = kAddFields;
    }

    switch (kind) {
        case kMatch: {
            BSONObjBuilder match(stage.subobjStart("$match"_sd));
            constexpr StringData kPredFields[] = {"a"_sd, "b"_sd, "w"_sd, "v"_sd};
            auto field = kPredFields[in.mod(nOf(kPredFields))];
            {
                BSONObjBuilder pred(match.subobjStart(field));
                pred.append(kCmp[in.mod(nOf(kCmp))], in.smallInt());
            }
            if (in.bit()) {
                appendBoolExpr(in, match, "$expr"_sd, 2);
            }
            break;
        }
        case kMatchNested: {
            // Boolean expression nested through $and / $or / $not / $size.
            BSONObjBuilder match(stage.subobjStart("$match"_sd));
            BSONObjBuilder expr(match.subobjStart("$expr"_sd));
            BSONArrayBuilder land(expr.subarrayStart("$and"_sd));
            appendBoolExprElt(in, land, 2);
            {
                BSONObjBuilder orObj;
                {
                    BSONArrayBuilder ors(orObj.subarrayStart("$or"_sd));
                    appendBoolExprElt(in, ors, 1);
                    appendBoolExprElt(in, ors, 2);
                }
                land.append(orObj.obj());
            }
            break;
        }
        case kProject: {
            BSONObjBuilder proj(stage.subobjStart("$project"_sd));
            proj.append("_id"_sd, in.bit() ? 1 : 0);
            proj.append("a"_sd, 1);
            proj.append("s"_sd, 1);
            appendValueExpr(in, proj, "c0"_sd, 2);
            if (in.bit()) {
                appendValueExpr(in, proj, "c1"_sd, 2);
            }
            break;
        }
        case kAddFields: {
            BSONObjBuilder add(stage.subobjStart("$addFields"_sd));
            appendValueExpr(in, add, "c0"_sd, 2);
            appendNumExpr(in, add, "c1"_sd, 2);
            if (in.bit()) {
                appendStrExpr(in, add, "c2"_sd, 1);
            }
            break;
        }
        case kGroup: {
            BSONObjBuilder group(stage.subobjStart("$group"_sd));
            switch (in.mod(4)) {
                case 0:
                    group.appendNull("_id"_sd);
                    break;
                case 1:
                    group.append("_id"_sd, "$flag"_sd);
                    break;
                case 2:
                    group.append("_id"_sd, "$s"_sd);
                    break;
                default:
                    appendValueExpr(in, group, "_id"_sd, 1);
                    break;
            }
            appendAccumulator(group, "sumA"_sd, "$sum"_sd, in.bit() ? "$a"_sd : "$b"_sd);
            if (in.bit()) {
                appendAccumulator(group, "avgB"_sd, "$avg"_sd, "$b"_sd);
            }
            if (in.bit()) {
                appendAccumulator(group, "minA"_sd, "$min"_sd, "$a"_sd);
            }
            if (in.bit()) {
                appendAccumulator(group, "maxA"_sd, "$max"_sd, "$a"_sd);
            }
            if (in.bit()) {
                appendAccumulator(group, "pushed"_sd, "$push"_sd, "$s"_sd);
            }
            break;
        }
        case kSort: {
            BSONObjBuilder sort(stage.subobjStart("$sort"_sd));
            auto first = kFields[in.mod(nOf(kFields))];
            sort.append(first, in.bit() ? 1 : -1);
            auto second = kFields[in.mod(nOf(kFields))];
            if (second != first) {
                sort.append(second, 1);
            }
            break;
        }
        case kLimitSkip: {
            if (in.bit()) {
                stage.append("$limit"_sd, 1 + static_cast<int>(in.mod(8)));
            } else {
                stage.append("$skip"_sd, static_cast<int>(in.mod(3)));
            }
            break;
        }
        case kUnwind: {
            if (in.bit()) {
                stage.append("$unwind"_sd, in.bit() ? "$arr"_sd : "$sub.z"_sd);
            } else {
                BSONObjBuilder uw(stage.subobjStart("$unwind"_sd));
                uw.append("path"_sd, in.bit() ? "$arr"_sd : "$sub.z"_sd);
                uw.append("preserveNullAndEmptyArrays"_sd, in.bit());
                if (in.bit()) {
                    uw.append("includeArrayIndex"_sd, "idx"_sd);
                }
            }
            break;
        }
        case kLookupEq: {
            BSONObjBuilder look(stage.subobjStart("$lookup"_sd));
            constexpr StringData kFrom[] = {"other"_sd, "docs"_sd, "graph"_sd};
            look.append("from"_sd, kFrom[in.mod(nOf(kFrom))]);
            constexpr StringData kJoin[] = {"a"_sd, "s"_sd, "_id"_sd};
            look.append("localField"_sd, kJoin[in.mod(nOf(kJoin))]);
            look.append("foreignField"_sd, kJoin[in.mod(nOf(kJoin))]);
            look.append("as"_sd, "joined"_sd);
            break;
        }
        case kLookupPipeline: {
            BSONObjBuilder look(stage.subobjStart("$lookup"_sd));
            constexpr StringData kFrom[] = {"other"_sd, "graph"_sd, "docs"_sd};
            look.append("from"_sd, kFrom[in.mod(nOf(kFrom))]);
            look.append("as"_sd, "joined"_sd);
            {
                BSONObjBuilder vars(look.subobjStart("let"_sd));
                vars.append("la"_sd, "$a"_sd);
                vars.append("ls"_sd, "$s"_sd);
            }
            BSONArrayBuilder sub(look.subarrayStart("pipeline"_sd));
            {
                BSONObjBuilder st(sub.subobjStart());
                BSONObjBuilder match(st.subobjStart("$match"_sd));
                BSONObjBuilder expr(match.subobjStart("$expr"_sd));
                BSONArrayBuilder land(expr.subarrayStart("$and"_sd));
                {
                    BSONObjBuilder eqObj;
                    {
                        const bool numeric = in.bit();
                        BSONArrayBuilder args(eqObj.subarrayStart("$eq"_sd));
                        args.append(numeric ? "$a"_sd : "$s"_sd);
                        args.append(numeric ? "$$la"_sd : "$$ls"_sd);
                    }
                    land.append(eqObj.obj());
                }
                {
                    BSONObjBuilder cmpObj;
                    {
                        BSONArrayBuilder args(cmpObj.subarrayStart("$gte"_sd));
                        BSONObj lenObj = [] {
                            BSONObjBuilder lenBuilder;
                            {
                                BSONArrayBuilder lenArgs(
                                    lenBuilder.subarrayStart("$strLenBytes"_sd));
                                lenArgs.append("$s"_sd);
                            }
                            return lenBuilder.obj();
                        }();
                        args.append(lenObj);
                        args.append(0);
                    }
                    land.append(cmpObj.obj());
                }
            }
            {
                BSONObjBuilder st(sub.subobjStart());
                BSONObjBuilder proj(st.subobjStart("$project"_sd));
                proj.append("_id"_sd, 0);
                proj.append("a"_sd, 1);
                proj.append("s"_sd, 1);
                BSONObjBuilder nested(proj.subobjStart("nested"_sd));
                BSONArrayBuilder add(nested.subarrayStart("$add"_sd));
                add.append("$a"_sd);
                add.append("$$la"_sd);
            }
            {
                BSONObjBuilder st(sub.subobjStart());
                st.append("$limit"_sd, 1 + static_cast<int>(in.mod(4)));
            }
            if (in.bit()) {
                BSONObjBuilder st(sub.subobjStart());
                BSONObjBuilder inner(st.subobjStart("$lookup"_sd));
                inner.append("from"_sd, "docs"_sd);
                inner.append("localField"_sd, "a"_sd);
                inner.append("foreignField"_sd, "a"_sd);
                inner.append("as"_sd, "innerJoined"_sd);
            }
            break;
        }
        case kGraphLookup: {
            BSONObjBuilder g(stage.subobjStart("$graphLookup"_sd));
            g.append("from"_sd, "graph"_sd);
            constexpr StringData kStart[] = {"$parent"_sd, "$a"_sd, "$_id"_sd};
            g.append("startWith"_sd, kStart[in.mod(nOf(kStart))]);
            g.append("connectFromField"_sd, "parent"_sd);
            g.append("connectToField"_sd, "_id"_sd);
            g.append("as"_sd, "chain"_sd);
            g.append("maxDepth"_sd, static_cast<int>(in.mod(4)));
            if (in.bit()) {
                g.append("depthField"_sd, "depth"_sd);
            }
            if (in.bit()) {
                BSONObjBuilder restr(g.subobjStart("restrictSearchWithMatch"_sd));
                appendBoolExpr(in, restr, "$expr"_sd, 1);
            }
            break;
        }
        case kWindow: {
            BSONObjBuilder win(stage.subobjStart("$setWindowFields"_sd));
            constexpr StringData kPart[] = {"$flag"_sd, "$s"_sd, "$a"_sd};
            if (in.mod(4) != 0) {
                win.append("partitionBy"_sd, kPart[in.mod(nOf(kPart))]);
            }
            const bool dateSort = in.bit();
            {
                BSONObjBuilder sortBy(win.subobjStart("sortBy"_sd));
                sortBy.append(dateSort ? "d"_sd : "a"_sd, 1);
            }
            BSONObjBuilder output(win.subobjStart("output"_sd));
            const int preset = static_cast<int>(in.mod(5));
            if (preset == 0 || preset == 3) {
                BSONObjBuilder field(output.subobjStart("winSum"_sd));
                field.append("$sum"_sd, "$a"_sd);
                BSONObjBuilder window(field.subobjStart("window"_sd));
                BSONArrayBuilder bounds(window.subarrayStart("documents"_sd));
                appendWindowBounds(bounds, in.mod(5));
            }
            if (preset == 0 || preset == 2) {
                BSONObjBuilder field(output.subobjStart("winAvg"_sd));
                field.append("$avg"_sd, "$b"_sd);
                BSONObjBuilder window(field.subobjStart("window"_sd));
                BSONArrayBuilder bounds(window.subarrayStart("documents"_sd));
                appendWindowBounds(bounds, in.mod(5));
            }
            if (preset == 1) {
                {
                    BSONObjBuilder rank(output.subobjStart("rnk"_sd));
                    BSONObjBuilder spec(rank.subobjStart("$rank"_sd));
                    (void)spec;
                }
                {
                    BSONObjBuilder dense(output.subobjStart("dense"_sd));
                    BSONObjBuilder spec(dense.subobjStart("$denseRank"_sd));
                    (void)spec;
                }
                {
                    BSONObjBuilder docn(output.subobjStart("docn"_sd));
                    BSONObjBuilder spec(docn.subobjStart("$documentNumber"_sd));
                    (void)spec;
                }
            }
            if (preset == 2) {
                {
                    BSONObjBuilder field(output.subobjStart("shifted"_sd));
                    BSONObjBuilder shift(field.subobjStart("$shift"_sd));
                    shift.append("output"_sd, "$a"_sd);
                    int by = static_cast<int>(in.mod(5)) - 2;
                    if (by == 0) {
                        by = 1;
                    }
                    shift.append("by"_sd, by);
                    shift.appendNull("default"_sd);
                }
                {
                    BSONObjBuilder emaField(output.subobjStart("ema"_sd));
                    BSONObjBuilder ema(emaField.subobjStart("$expMovingAvg"_sd));
                    ema.append("input"_sd, "$b"_sd);
                    ema.append("N"_sd, 1 + static_cast<int>(in.mod(4)));
                }
            }
            if (preset == 3) {
                BSONObjBuilder field(output.subobjStart("pct"_sd));
                {
                    BSONObjBuilder pct(field.subobjStart("$percentile"_sd));
                    pct.append("input"_sd, "$a"_sd);
                    {
                        BSONArrayBuilder ps(pct.subarrayStart("p"_sd));
                        ps.append(0.5);
                        ps.append(0.9);
                    }
                    pct.append("method"_sd, "approximate"_sd);
                }
                BSONObjBuilder window(field.subobjStart("window"_sd));
                BSONArrayBuilder bounds(window.subarrayStart("documents"_sd));
                bounds.append("unbounded"_sd);
                bounds.append("unbounded"_sd);
            }
            if (preset == 4 && dateSort) {
                BSONObjBuilder field(output.subobjStart("deriv"_sd));
                BSONObjBuilder deriv(field.subobjStart("$derivative"_sd));
                deriv.append("input"_sd, "$a"_sd);
                deriv.append("unit"_sd, "millisecond"_sd);
            } else if (preset == 4) {
                BSONObjBuilder field(output.subobjStart("winMin"_sd));
                field.append("$min"_sd, "$a"_sd);
                BSONObjBuilder window(field.subobjStart("window"_sd));
                BSONArrayBuilder bounds(window.subarrayStart("documents"_sd));
                appendWindowBounds(bounds, 0);
            }
            break;
        }
        case kBucket: {
            BSONObjBuilder bucket(stage.subobjStart("$bucket"_sd));
            bucket.append("groupBy"_sd, "$a"_sd);
            {
                BSONArrayBuilder bounds(bucket.subarrayStart("boundaries"_sd));
                bounds.append(-100);
                bounds.append(0);
                bounds.append(4);
                bounds.append(8);
                bounds.append(1000);
            }
            bucket.append("default"_sd, "other"_sd);
            BSONObjBuilder output(bucket.subobjStart("output"_sd));
            appendAccumulator(output, "n"_sd, "$sum"_sd, "$a"_sd);
            break;
        }
        case kBucketAuto: {
            BSONObjBuilder bucket(stage.subobjStart("$bucketAuto"_sd));
            bucket.append("groupBy"_sd, "$b"_sd);
            bucket.append("buckets"_sd, 1 + static_cast<int>(in.mod(4)));
            BSONObjBuilder output(bucket.subobjStart("output"_sd));
            appendAccumulator(output, "n"_sd, "$sum"_sd, "$a"_sd);
            break;
        }
        case kFacet: {
            BSONObjBuilder facet(stage.subobjStart("$facet"_sd));
            {
                BSONArrayBuilder p(facet.subarrayStart("byFlag"_sd));
                appendSimpleStage(in, p);
                appendSimpleStage(in, p);
            }
            {
                BSONArrayBuilder p(facet.subarrayStart("top"_sd));
                appendSimpleStage(in, p);
            }
            break;
        }
        case kReplaceWith: {
            if (in.bit()) {
                stage.append("$replaceWith"_sd, "$sub"_sd);
            } else {
                BSONObjBuilder doc(stage.subobjStart("$replaceWith"_sd));
                doc.append("a"_sd, "$a"_sd);
                appendNumExpr(in, doc, "b"_sd, 1);
                doc.append("s"_sd, "$s"_sd);
            }
            break;
        }
        case kRedact: {
            BSONObjBuilder red(stage.subobjStart("$redact"_sd));
            BSONArrayBuilder cond(red.subarrayStart("$cond"_sd));
            appendBoolExprElt(in, cond, 1);
            cond.append(in.bit() ? "$$KEEP"_sd : "$$DESCEND"_sd);
            cond.append(in.bit() ? "$$PRUNE"_sd : "$$KEEP"_sd);
            break;
        }
        case kUnionWith: {
            BSONObjBuilder u(stage.subobjStart("$unionWith"_sd));
            constexpr StringData kColl[] = {"other"_sd, "graph"_sd, "docs"_sd};
            u.append("coll"_sd, kColl[in.mod(nOf(kColl))]);
            BSONArrayBuilder p(u.subarrayStart("pipeline"_sd));
            appendSimpleStage(in, p);
            if (in.bit()) {
                appendSimpleStage(in, p);
            }
            break;
        }
        case kFill: {
            BSONObjBuilder fill(stage.subobjStart("$fill"_sd));
            {
                BSONObjBuilder sortBy(fill.subobjStart("sortBy"_sd));
                sortBy.append("a"_sd, 1);
            }
            BSONObjBuilder output(fill.subobjStart("output"_sd));
            const bool linear = in.bit();
            BSONObjBuilder spec(output.subobjStart(linear ? "b"_sd : "n"_sd));
            spec.append("method"_sd, linear ? "linear"_sd : "locf"_sd);
            break;
        }
        case kDensify: {
            BSONObjBuilder d(stage.subobjStart("$densify"_sd));
            d.append("field"_sd, "a"_sd);
            if (in.bit()) {
                d.append("partitionBy"_sd, "$flag"_sd);
            }
            BSONObjBuilder range(d.subobjStart("range"_sd));
            range.append("step"_sd, 1 + static_cast<int>(in.mod(3)));
            if (in.bit()) {
                range.append("bounds"_sd, "full"_sd);
            } else {
                BSONArrayBuilder bounds(range.subarrayStart("bounds"_sd));
                bounds.append(0);
                bounds.append(20);
            }
            break;
        }
        case kSample: {
            BSONObjBuilder sample(stage.subobjStart("$sample"_sd));
            sample.append("size"_sd, 1 + static_cast<int>(in.mod(4)));
            break;
        }
        case kSortByCount: {
            if (in.bit()) {
                stage.append("$sortByCount"_sd, "$flag"_sd);
            } else {
                BSONObjBuilder expr(stage.subobjStart("$sortByCount"_sd));
                BSONArrayBuilder lower(expr.subarrayStart("$toLower"_sd));
                lower.append("$s"_sd);
            }
            break;
        }
        case kCount:
            stage.append("$count"_sd, "n"_sd);
            break;
        case kUnset:
            stage.append("$unset"_sd, in.bit() ? "mixed"_sd : "n"_sd);
            break;
        case kGeoNear: {
            BSONObjBuilder g(stage.subobjStart("$geoNear"_sd));
            {
                BSONObjBuilder near(g.subobjStart("near"_sd));
                near.append("type"_sd, "Point"_sd);
                BSONArrayBuilder coords(near.subarrayStart("coordinates"_sd));
                coords.append(static_cast<double>(in.smallInt()));
                coords.append(static_cast<double>(in.smallInt()));
            }
            g.append("distanceField"_sd, "dist"_sd);
            g.append("spherical"_sd, true);
            break;
        }
        default:
            stage.append("$limit"_sd, 1);
            break;
    }
}

void appendDocumentsStage(Bytes& in, BSONArrayBuilder& pipeline) {
    BSONObjBuilder stage(pipeline.subobjStart());
    BSONArrayBuilder docs(stage.subarrayStart("$documents"_sd));
    const int n = 1 + static_cast<int>(in.mod(3));
    for (int i = 0; i < n; ++i) {
        BSONObjBuilder doc(docs.subobjStart());
        doc.append("_id"_sd, i);
        doc.append("a"_sd, i);
        doc.append("b"_sd, static_cast<double>(i) + 0.5);
        doc.append("s"_sd, kStrLits[in.mod(nOf(kStrLits))]);
        doc.append("flag"_sd, (i % 2) == 0);
        doc.append("w"_sd, i);
        doc.append("v"_sd, i * 3);
        doc.append("name"_sd, "n"_sd);
        if (i == 0) {
            doc.appendNull("parent"_sd);
            doc.appendNull("n"_sd);
        } else {
            doc.append("parent"_sd, i - 1);
            doc.append("n"_sd, i);
        }
        doc.appendDate("d"_sd,
                       Date_t::fromMillisSinceEpoch(1'577'836'800'000LL +
                                                    static_cast<long long>(i) * 86'400'000LL));
        {
            BSONArrayBuilder arr(doc.subarrayStart("arr"_sd));
            arr.append(i);
            arr.append(i + 1);
            arr.append(i % 3);
        }
        {
            BSONObjBuilder sub(doc.subobjStart("sub"_sd));
            sub.append("x"_sd, i);
            sub.append("y"_sd, "y"_sd);
            BSONArrayBuilder z(sub.subarrayStart("z"_sd));
            z.append(i);
            z.append(0);
        }
        doc.append("mixed"_sd, (i % 2) == 0 ? "s"_sd : "t"_sd);
    }
}

BSONObj buildAggregateCommand(const uint8_t* data, size_t size) {
    Bytes in(data, size);
    const uint8_t flags = in.next();
    const bool collectionless = (flags & 0x1) != 0;
    const int collPick = static_cast<int>((flags >> 1) & 0x3);
    const bool allowDisk = (flags & 0x10) != 0;
    const int nStages = 1 + static_cast<int>(in.next() % 6);

    BSONObjBuilder cmd;
    cmd.append("$db"_sd, "fuzzdb"_sd);
    if (collectionless) {
        cmd.append("aggregate"_sd, 1);
    } else {
        constexpr StringData kColl[] = {"docs"_sd, "other"_sd, "graph"_sd, "docs"_sd};
        cmd.append("aggregate"_sd, kColl[collPick]);
    }
    cmd.append("allowDiskUse"_sd, allowDisk);
    cmd.append("maxTimeMS"_sd, 2000);
    {
        BSONObjBuilder letb(cmd.subobjStart("let"_sd));
        letb.append("la"_sd, in.smallInt());
        letb.append("lb"_sd, kStrLits[in.mod(nOf(kStrLits))]);
    }
    {
        BSONObjBuilder cursor(cmd.subobjStart("cursor"_sd));
        cursor.append("batchSize"_sd, 1 + static_cast<int>(flags & 0x1f));
    }
    {
        BSONArrayBuilder pipeline(cmd.subarrayStart("pipeline"_sd));
        if (collectionless) {
            appendDocumentsStage(in, pipeline);
        }
        for (int i = 0; i < nStages; ++i) {
            const bool first = !collectionless && i == 0;
            appendStage(in, pipeline, first, i + 1 == nStages);
        }
    }
    return cmd.obj();
}

void appendCoreFields(BSONObjBuilder& doc, int i, int aValue) {
    doc.append("a"_sd, aValue);
    doc.append("b"_sd, static_cast<double>(aValue) + 0.5);
    doc.append("s"_sd, kStrLits[static_cast<size_t>(i) % nOf(kStrLits)]);
    doc.append("flag"_sd, (i % 2) == 0);
    doc.append("w"_sd, i);
    doc.append("v"_sd, i * 10);
    doc.append("name"_sd, "n"_sd);
    if (i % 3 == 0) {
        doc.appendNull("n"_sd);
    } else {
        doc.append("n"_sd, i);
    }
    doc.appendDate("d"_sd,
                   Date_t::fromMillisSinceEpoch(1'577'836'800'000LL +
                                                static_cast<long long>(i) * 86'400'000LL));
    {
        BSONArrayBuilder arr(doc.subarrayStart("arr"_sd));
        arr.append(i);
        arr.append(i + 1);
        arr.append(i % 3);
    }
    {
        BSONObjBuilder sub(doc.subobjStart("sub"_sd));
        sub.append("x"_sd, i);
        sub.append("y"_sd, "y"_sd);
        BSONArrayBuilder z(sub.subarrayStart("z"_sd));
        z.append(i);
        z.append(0);
    }
    {
        BSONObjBuilder loc(doc.subobjStart("loc"_sd));
        loc.append("type"_sd, "Point"_sd);
        BSONArrayBuilder coords(loc.subarrayStart("coordinates"_sd));
        coords.append(static_cast<double>(i % 20));
        coords.append(static_cast<double>(i % 10));
    }
    if (i % 2 == 0) {
        doc.append("mixed"_sd, i);
    } else {
        doc.append("mixed"_sd, "s"_sd);
    }
}

BSONObj makeInsert(StringData coll, int count, bool duplicateA) {
    BSONObjBuilder cmd;
    cmd.append("insert"_sd, coll);
    cmd.append("$db"_sd, "fuzzdb"_sd);
    cmd.append("ordered"_sd, true);
    {
        BSONArrayBuilder docs(cmd.subarrayStart("documents"_sd));
        for (int i = 0; i < count; ++i) {
            BSONObjBuilder doc(docs.subobjStart());
            doc.append("_id"_sd, i);
            appendCoreFields(doc, i, duplicateA ? (i % 8) : i);
            if (i == 0) {
                doc.appendNull("parent"_sd);
            } else {
                doc.append("parent"_sd, i - 1);
            }
        }
    }
    return cmd.obj();
}

void requireOk(const Status& status, StringData what) {
    if (status.isOK()) {
        std::cerr << "agg_exec_fuzzer setup " << what << ": ok" << std::endl;
        return;
    }
    std::cerr << "agg_exec_fuzzer setup failed at " << what << ": " << status.toString()
              << std::endl;
    std::abort();
}

void logStatus(StringData what, const Status& status) {
    std::cerr << "agg_exec_fuzzer setup " << what << ": "
              << (status.isOK() ? "ok" : status.toString()) << std::endl;
}

BSONObj setParameterCmd(StringData name, int value) {
    BSONObjBuilder cmd;
    cmd.append("setParameter"_sd, 1);
    cmd.append(name, value);
    cmd.append("$db"_sd, "admin"_sd);
    return cmd.obj();
}

BSONObj setParameterCmd(StringData name, bool value) {
    BSONObjBuilder cmd;
    cmd.append("setParameter"_sd, 1);
    cmd.append(name, value);
    cmd.append("$db"_sd, "admin"_sd);
    return cmd.obj();
}

BSONObj setParameterCmd(StringData name, StringData value) {
    BSONObjBuilder cmd;
    cmd.append("setParameter"_sd, 1);
    cmd.append(name, value);
    cmd.append("$db"_sd, "admin"_sd);
    return cmd.obj();
}

class AggExecFuzzerHarness {
public:
    AggExecFuzzerHarness() {
        (void)kKeepStandaloneCommands;
        _fixture.prepareForAggregationExecutionFuzzing();
        logStatus("trySbeEngine",
                  _fixture
                      .runCommand(setParameterCmd("internalQueryFrameworkControl"_sd,
                                                  "trySbeEngine"_sd))
                      .getStatus());
        logStatus(
            "featureFlagSbeFull",
            _fixture.runCommand(setParameterCmd("featureFlagSbeFull"_sd, true)).getStatus());

        seedCollection("docs"_sd, 12, false);
        seedCollection("other"_sd, 16, true);
        seedCollection("graph"_sd, 12, false);
        logStatus("index docs", _fixture.runCommand(indexCmd("docs"_sd)).getStatus());
        logStatus("index other", _fixture.runCommand(indexCmd("other"_sd)).getStatus());
        logStatus("index graph", _fixture.runCommand(indexCmd("graph"_sd)).getStatus());

        requireOk(runJson(R"({
            "aggregate": "docs",
            "pipeline": [
                {"$match": {"$expr": {"$and": [
                    {"$gte": ["$a", 0]},
                    {"$or": [
                        {"$eq": ["$flag", true]},
                        {"$lt": [{"$size": "$arr"}, {"$add": ["$a", 1]}]}
                    ]}
                ]}}},
                {"$group": {"_id": "$flag", "s": {"$sum": "$a"}, "avg": {"$avg": "$b"}}}
            ],
            "cursor": {"batchSize": 10},
            "$db": "fuzzdb"
        })"),
                  "probe $expr+$group");
        requireOk(runJson(R"({
            "aggregate": "docs",
            "pipeline": [
                {"$lookup": {
                    "from": "other",
                    "localField": "a",
                    "foreignField": "a",
                    "as": "joined"
                }}
            ],
            "cursor": {"batchSize": 4},
            "$db": "fuzzdb"
        })"),
                  "probe $lookup");
        requireOk(runJson(R"({
            "aggregate": "docs",
            "pipeline": [
                {"$lookup": {
                    "from": "other",
                    "let": {"la": "$a"},
                    "pipeline": [
                        {"$match": {"$expr": {"$and": [
                            {"$eq": ["$a", "$$la"]},
                            {"$gte": [{"$strLenBytes": "$s"}, 0]}
                        ]}}},
                        {"$limit": 3}
                    ],
                    "as": "joined"
                }}
            ],
            "cursor": {"batchSize": 4},
            "$db": "fuzzdb"
        })"),
                  "probe $lookup pipeline");
        requireOk(runJson(R"({
            "aggregate": "docs",
            "pipeline": [
                {"$graphLookup": {
                    "from": "graph",
                    "startWith": "$parent",
                    "connectFromField": "parent",
                    "connectToField": "_id",
                    "as": "chain",
                    "maxDepth": 3,
                    "depthField": "depth"
                }}
            ],
            "cursor": {"batchSize": 4},
            "$db": "fuzzdb"
        })"),
                  "probe $graphLookup");
        requireOk(runJson(R"({
            "aggregate": "docs",
            "pipeline": [
                {"$setWindowFields": {
                    "partitionBy": "$flag",
                    "sortBy": {"a": 1},
                    "output": {
                        "winSum": {
                            "$sum": "$a",
                            "window": {"documents": ["unbounded", "current"]}
                        },
                        "rnk": {"$rank": {}},
                        "shifted": {"$shift": {"output": "$b", "by": 1, "default": null}}
                    }
                }}
            ],
            "cursor": {"batchSize": 4},
            "$db": "fuzzdb"
        })"),
                  "probe $setWindowFields");

        logStatus("sort spill limit",
                  _fixture
                      .runCommand(
                          setParameterCmd("internalQueryMaxBlockingSortMemoryUsageBytes"_sd, 1))
                      .getStatus());
        logStatus("group spill limit",
                  _fixture
                      .runCommand(setParameterCmd("internalDocumentSourceGroupMaxMemoryBytes"_sd, 1))
                      .getStatus());
        logStatus(
            "sbe hash agg spill limit",
            _fixture
                .runCommand(setParameterCmd(
                    "internalQuerySlotBasedExecutionHashAggApproxMemoryUseInBytesBeforeSpill"_sd,
                    1))
                .getStatus());
        logStatus("sbe hash agg force spill",
                  _fixture
                      .runCommand(setParameterCmd(
                          "internalQuerySlotBasedExecutionHashAggForceIncreasedSpilling"_sd, true))
                      .getStatus());
        std::cerr << "agg_exec_fuzzer ready" << std::endl;
    }

    int testOne(const uint8_t* data, size_t size) {
        auto cmd = buildAggregateCommand(data, size);
        if (const char* log = std::getenv("AGG_FUZZ_LOG")) {
            if (log[0] != '\0' && log[0] != '0') {
                std::cerr << "agg_exec_fuzzer cmd " << cmd.toString() << std::endl;
            }
        }
        (void)_fixture.runCommand(std::move(cmd));
        return 0;
    }

private:
    Status runJson(StringData json) {
        return _fixture.runCommand(fromjson(json)).getStatus();
    }

    void seedCollection(StringData coll, int count, bool duplicateA) {
        auto sw = _fixture.runCommand(makeInsert(coll, count, duplicateA));
        const std::string what = std::string("insert ") + coll.toString();
        requireOk(sw.getStatus(), what);
        const int n = sw.getValue()["n"].numberInt();
        if (n != count) {
            std::cerr << "agg_exec_fuzzer insert " << coll << " wrote " << n << " expected "
                      << count << " reply " << sw.getValue().toString() << std::endl;
            std::abort();
        }
    }

    static BSONObj indexCmd(StringData coll) {
        BSONObjBuilder cmd;
        cmd.append("createIndexes"_sd, coll);
        cmd.append("$db"_sd, "fuzzdb"_sd);
        {
            BSONArrayBuilder indexes(cmd.subarrayStart("indexes"_sd));
            {
                BSONObjBuilder idx(indexes.subobjStart());
                {
                    BSONObjBuilder key(idx.subobjStart("key"_sd));
                    key.append("a"_sd, 1);
                }
                idx.append("name"_sd, "a_1"_sd);
            }
            {
                BSONObjBuilder idx(indexes.subobjStart());
                {
                    BSONObjBuilder key(idx.subobjStart("key"_sd));
                    key.append("loc"_sd, "2dsphere"_sd);
                }
                idx.append("name"_sd, "loc_2dsphere"_sd);
            }
        }
        return cmd.obj();
    }

    OpMsgFuzzerFixture _fixture;
};

}  // namespace

int aggExecFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Function-local static so the fixture destructor runs at process exit and can
    // shut down the index-build thread pool before the global ServiceContext.
    static AggExecFuzzerHarness* harness = nullptr;
    if (!harness) {
        auto core = boost::log::core::get();
        core->set_logging_enabled(false);
        static AggExecFuzzerHarness instance;
        harness = &instance;
    }
    return harness->testOne(data, size);
}

}  // namespace mongo

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    return mongo::aggExecFuzzerTestOneInput(data, size);
}
