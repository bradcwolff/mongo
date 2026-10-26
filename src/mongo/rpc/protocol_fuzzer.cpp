/**
 *    Copyright (C) 2019-present MongoDB, Inc.
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

#include "mongo/base/data_range_cursor.h"
#include "mongo/bson/bson_validate.h"
#include "mongo/db/dbmessage.h"
#include "mongo/db/ops/write_ops.h"
#include "mongo/rpc/factory.h"
#include "mongo/rpc/message.h"
#include "mongo/transport/message_compressor_manager.h"
#include "mongo/transport/message_compressor_noop.h"
#include "mongo/transport/message_compressor_registry.h"
#include "mongo/transport/message_compressor_snappy.h"
#include "mongo/transport/message_compressor_zlib.h"
#include "mongo/transport/message_compressor_zstd.h"
#include "mongo/util/shared_buffer.h"

#include <memory>
#include <string>
#include <vector>

namespace mongo {
namespace {
// Bound decompression so a hostile uncompressed-size field cannot force a 48MB allocation on
// every input. Full command dispatch of the decompressed message lives in OpMsgFuzzerFixture.
constexpr size_t kFuzzerDecompressCap = 256 * 1024;
}  // namespace

struct CompressionInfrastructure {
    CompressionInfrastructure() : manager(&registry) {
        std::vector<std::string> names = {"noop", "snappy", "zlib", "zstd"};
        registry.setSupportedCompressors(std::move(names));
        registry.registerImplementation(std::make_unique<NoopMessageCompressor>());
        registry.registerImplementation(std::make_unique<SnappyMessageCompressor>());
        registry.registerImplementation(std::make_unique<ZlibMessageCompressor>());
        registry.registerImplementation(std::make_unique<ZstdMessageCompressor>());
        uassertStatusOK(registry.finalizeSupportedCompressors());
    }

    MessageCompressorRegistry registry;
    MessageCompressorManager manager;
};

void doFuzzing(ConstDataRangeCursor fuzzedData) try {
    if (fuzzedData.length() < sizeof(MSGHEADER::Layout)) {
        return;
    }

    // Make sure that we do BSON validation on all incoming messages
    serverGlobalParams.objcheck = true;

    auto sb = SharedBuffer::allocate(fuzzedData.length());
    memcpy(sb.get(), fuzzedData.data(), fuzzedData.length());
    Message msg(std::move(sb));
    if (static_cast<size_t>(msg.size()) != fuzzedData.length()) {
        return;
    }

    if (msg.operation() == dbCompressed) {
        static CompressionInfrastructure compression = {};
        msg = uassertStatusOK(
            compression.manager.decompressMessage(msg, nullptr, kFuzzerDecompressCap));
    }


    switch (msg.operation()) {
        case dbMsg: {
            auto request = OpMsgRequest::parseOwned(msg);
            validateBSON(request.body).ignore();
            for (const auto& docSeq : request.sequences) {
                for (const auto& doc : docSeq.objs) {
                    validateBSON(doc).ignore();
                }
            }
        } break;
        case dbInsert: {
            auto op = InsertOp::parseLegacy(msg);
        } break;
        case dbQuery: {
            DbMessage dbMsgObj(msg);
            QueryMessage q(dbMsgObj);
        } break;
        // These message types don't have parsers because they are no longer supported.
        case dbGetMore:
        case dbKillCursors:
        case dbDelete:
        case dbUpdate:
            break;
        default:
            invariant(!isSupportedRequestNetworkOp(msg.operation()));
            break;
    }
} catch (const DBException&) {
    // Ignore all errors from our assert macros
}

}  // namespace mongo

extern "C" int LLVMFuzzerTestOneInput(const char* Data, size_t Size) {
    mongo::doFuzzing(mongo::ConstDataRangeCursor(Data, Size));
    return 0;
}
