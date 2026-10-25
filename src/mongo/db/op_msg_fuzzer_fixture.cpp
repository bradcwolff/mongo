/**
 *    Copyright (C) 2020-present MongoDB, Inc.
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

#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

#include <boost/smart_ptr/intrusive_ptr.hpp>

#include "mongo/base/initializer.h"
#include "mongo/base/status.h"
#include "mongo/base/string_data.h"
#include "mongo/db/auth/authorization_manager.h"
#include "mongo/db/catalog/collection.h"
#include "mongo/db/catalog/collection_impl.h"
#include "mongo/db/catalog/database_holder.h"
#include "mongo/db/catalog/database_holder_impl.h"
#include "mongo/db/concurrency/d_concurrency.h"
#include "mongo/db/concurrency/lock_manager_defs.h"
#include "mongo/db/op_msg_fuzzer_fixture.h"
#include "mongo/db/op_observer/op_observer.h"
#include "mongo/db/op_observer/op_observer_registry.h"
#include "mongo/db/repl/repl_settings.h"
#include "mongo/db/repl/replication_coordinator.h"
#include "mongo/db/repl/replication_coordinator_mock.h"
#include "mongo/db/s/collection_sharding_state.h"
#include "mongo/db/s/collection_sharding_state_factory_shard.h"
#include "mongo/db/server_options.h"
#include "mongo/db/service_entry_point_mongod.h"
#include "mongo/db/session_manager_mongod.h"
#include "mongo/db/storage/control/storage_control.h"
#include "mongo/db/storage/recovery_unit_noop.h"
#include "mongo/db/storage/storage_engine.h"
#include "mongo/db/storage/storage_engine_init.h"
#include "mongo/db/storage/storage_options.h"
#include "mongo/db/vector_clock_mutable.h"
#include "mongo/bson/json.h"
#include "mongo/rpc/message.h"
#include "mongo/rpc/op_msg.h"
#include "mongo/s/sharding_state.h"
#include "mongo/transport/message_compressor_manager.h"
#include "mongo/transport/message_compressor_noop.h"
#include "mongo/transport/message_compressor_registry.h"
#include "mongo/transport/message_compressor_snappy.h"
#include "mongo/transport/message_compressor_zlib.h"
#include "mongo/transport/message_compressor_zstd.h"
#include "mongo/transport/service_entry_point.h"
#include "mongo/transport/transport_options_gen.h"
#include "mongo/util/assert_util.h"
#include "mongo/util/future.h"
#include "mongo/util/periodic_runner_factory.h"
#include "mongo/util/shared_buffer.h"
#include "mongo/util/version/releases.h"

namespace mongo {

namespace {
constexpr auto kTempDirStem = "op_msg_fuzzer_fixture"_sd;

// Production pre-auth ingress rejects larger bodies. A second, still-bounded cap lets the
// fuzzer reach the "claimed size exceeds the pre-auth limit" check and the success path for
// messages that would be legal after authentication, without allocating MaxMessageSizeBytes.
constexpr size_t kRaisedDecompressCap = 256 * 1024;

size_t preAuthDecompressCap() {
    const auto configured = transport::gPreAuthMaximumMessageSizeBytes.loadRelaxed();
    if (configured <= 0) {
        return 16 * 1024;
    }
    return static_cast<size_t>(configured);
}
}  // namespace

struct OpMsgFuzzerFixture::CompressionState {
    CompressionState() : manager(&registry) {
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
    uint64_t dispatches = 0;
};

// This must be called before creating any new threads that may access `AuthorizationManager` to
// avoid a data-race.
void OpMsgFuzzerFixture::_setAuthorizationManager() {
    auto localExternalState = std::make_unique<AuthzManagerExternalStateMock>();
    _externalState = localExternalState.get();

    auto localAuthzManager = std::make_unique<AuthorizationManagerImpl>(
        _serviceContext->getService(), std::move(localExternalState));
    _authzManager = localAuthzManager.get();
    _externalState->setAuthorizationManager(_authzManager);
    _authzManager->setAuthEnabled(true);

    AuthorizationManager::set(_serviceContext->getService(), std::move(localAuthzManager));
}

OpMsgFuzzerFixture::OpMsgFuzzerFixture(bool skipGlobalInitializers)
    : _dir(kTempDirStem.toString()) {
    _compression = std::make_unique<CompressionState>();

    if (!skipGlobalInitializers) {
        auto ret = runGlobalInitializers(std::vector<std::string>{});
        invariant(ret.isOK());
    }

    setGlobalServiceContext(ServiceContext::make());
    _session = _transportLayer.createSession();

    _serviceContext = getGlobalServiceContext();
    _setAuthorizationManager();
    _serviceContext->getService()->setServiceEntryPoint(
        std::make_unique<ServiceEntryPointMongod>());

    auto observerRegistry = std::make_unique<OpObserverRegistry>();
    _serviceContext->setOpObserver(std::move(observerRegistry));

    _serviceContext->setPeriodicRunner(makePeriodicRunner(_serviceContext));

    _clientStrand = ClientStrand::make(_serviceContext->getService()->makeClient("test", _session));
    auto clientGuard = _clientStrand->bind();

    storageGlobalParams.dbpath = _dir.path();
    storageGlobalParams.engine = "wiredTiger";
    storageGlobalParams.engineSetByUser = true;
    storageGlobalParams.repair = false;
    serverGlobalParams.enableMajorityReadConcern = false;
    // (Generic FCV reference): Initialize FCV.
    serverGlobalParams.mutableFCV.setVersion(multiversion::GenericFCV::kLatest);

    {
        auto initializeStorageEngineOpCtx =
            _serviceContext->makeOperationContext(clientGuard.get());
        shard_role_details::setRecoveryUnit(initializeStorageEngineOpCtx.get(),
                                            std::make_unique<RecoveryUnitNoop>(),
                                            WriteUnitOfWork::RecoveryUnitState::kNotInUnitOfWork);

        initializeStorageEngine(initializeStorageEngineOpCtx.get(),
                                StorageEngineInitFlags::kAllowNoLockFile |
                                    StorageEngineInitFlags::kSkipMetadataFile);
        StorageControl::startStorageControls(_serviceContext, true /*forTestOnly*/);
    }

    ShardingState::create(_serviceContext);
    CollectionShardingStateFactory::set(
        _serviceContext, std::make_unique<CollectionShardingStateFactoryShard>(_serviceContext));
    DatabaseHolder::set(_serviceContext, std::make_unique<DatabaseHolderImpl>());
    Collection::Factory::set(_serviceContext, std::make_unique<CollectionImpl::FactoryImpl>());

    // Setup the repl coordinator in standalone mode so we don't need an oplog etc.
    repl::ReplicationCoordinator::set(
        _serviceContext,
        std::make_unique<repl::ReplicationCoordinatorMock>(_serviceContext, repl::ReplSettings()));

    _serviceContext->getStorageEngine()->notifyStorageStartupRecoveryComplete();
}

OpMsgFuzzerFixture::~OpMsgFuzzerFixture() {
    CollectionShardingStateFactory::clear(_serviceContext);

    {
        auto clientGuard = _clientStrand->bind();
        auto opCtx = _serviceContext->makeOperationContext(clientGuard.get());
        Lock::GlobalLock glk(opCtx.get(), MODE_X);
        auto databaseHolder = DatabaseHolder::get(opCtx.get());
        databaseHolder->closeAll(opCtx.get());
    }

    shutdownGlobalStorageEngineCleanly(_serviceContext, true /* memLeakAllowed */);
}

int OpMsgFuzzerFixture::_dispatchWireMessage(Message msg) {
    auto clientGuard = _clientStrand->bind();
    auto opCtx = _serviceContext->makeOperationContext(clientGuard.get());
    VectorClockMutable::get(_serviceContext)->tickClusterTimeTo(kInMemoryLogicalTime);

    try {
        if (msg.operation() == dbCompressed) {
            MessageCompressorId compressorId = 0;
            // Same entry point as SessionWorkflow::WorkItem::decompressRequest: pre-auth cap
            // first (this fixture's client is not authenticated), then a raised cap so a
            // claimed-size mismatch is still evaluated inside decompressMessage.
            auto sw = _compression->manager.decompressMessage(msg, &compressorId, preAuthDecompressCap());
            if (!sw.isOK()) {
                sw = _compression->manager.decompressMessage(
                    msg, &compressorId, kRaisedDecompressCap);
            }
            if (!sw.isOK()) {
                return 0;
            }
            msg = std::move(sw.getValue());
            ++_compression->dispatches;
            if (_compression->dispatches <= 16 || (_compression->dispatches % 10000) == 0) {
                std::cerr << "OP_COMPRESSED_DISPATCH compressorId=" << static_cast<int>(compressorId)
                          << " opcode=" << static_cast<int32_t>(msg.operation())
                          << " count=" << _compression->dispatches << "\n";
            }
        }

        _serviceContext->getService()
            ->getServiceEntryPoint()
            ->handleRequest(opCtx.get(), msg)
            .get();
    } catch (const AssertionException&) {
        // Invalid inputs are expected from the fuzzer.
    }

    return 0;
}

int OpMsgFuzzerFixture::testOneInput(const char* Data, size_t Size) {
    if (Size < sizeof(MSGHEADER::Value)) {
        return 0;
    }

    int new_size = Size + sizeof(int);
    auto sb = SharedBuffer::allocate(new_size);
    memcpy(sb.get(), &new_size, sizeof(int));
    memcpy(sb.get() + sizeof(int), Data, Size);
    return _dispatchWireMessage(Message(std::move(sb)));
}

int OpMsgFuzzerFixture::testCompressedInput(const char* Data, size_t Size) {
    if (Size < sizeof(MSGHEADER::Value) || !_compression) {
        return 0;
    }

    int new_size = Size + sizeof(int);
    auto innerBuf = SharedBuffer::allocate(new_size);
    memcpy(innerBuf.get(), &new_size, sizeof(int));
    memcpy(innerBuf.get() + sizeof(int), Data, Size);
    Message inner(std::move(innerBuf));

    const MessageCompressorId ids[] = {
        static_cast<MessageCompressorId>(MessageCompressor::kSnappy),
        static_cast<MessageCompressorId>(MessageCompressor::kZlib),
        static_cast<MessageCompressorId>(MessageCompressor::kZstd),
    };
    const auto selector = static_cast<uint8_t>(Data[0]);
    const MessageCompressorId compressorId = ids[selector % 3];
    auto swCompressed = _compression->manager.compressMessage(inner, &compressorId);
    if (!swCompressed.isOK()) {
        return 0;
    }

    Message compressed = std::move(swCompressed.getValue());
    if (compressed.operation() != dbCompressed || compressed.size() <= 0) {
        return 0;
    }

    const int len = compressed.size();
    const int sizeFieldOffset =
        static_cast<int>(MsgData::MsgDataHeaderSize + sizeof(int32_t));  // skip original opcode
    if (len < sizeFieldOffset + static_cast<int>(sizeof(int32_t))) {
        return 0;
    }

    auto mutated = SharedBuffer::allocate(len);
    memcpy(mutated.get(), compressed.buf(), len);
    auto* claimedSize = reinterpret_cast<int32_t*>(mutated.get() + sizeFieldOffset);
    const int32_t actualSize = *claimedSize;
    switch ((selector >> 4) & 0x7) {
        case 0:
            break;
        case 1:
            *claimedSize = actualSize - 1;
            break;
        case 2:
            *claimedSize = actualSize + 1;
            break;
        case 3:
            *claimedSize = 0;
            break;
        case 4:
            *claimedSize = -1;
            break;
        default: {
            int32_t fromInput = actualSize;
            if (Size >= 1 + sizeof(int32_t)) {
                memcpy(&fromInput, Data + 1, sizeof(fromInput));
            }
            *claimedSize = fromInput;
            break;
        }
    }

    return _dispatchWireMessage(Message(std::move(mutated)));
}

bool OpMsgFuzzerFixture::selfTestCompressedDispatch() {
    OpMsgBuilder builder;
    builder.setBody(fromjson(R"({ping: 1, $db: "admin"})"));
    Message ping = builder.finishWithoutSizeChecking();
    if (ping.size() <= static_cast<int>(sizeof(int))) {
        return false;
    }

    const uint64_t before = compressedDispatches();
    const MessageCompressorId ids[] = {
        static_cast<MessageCompressorId>(MessageCompressor::kSnappy),
        static_cast<MessageCompressorId>(MessageCompressor::kZlib),
        static_cast<MessageCompressorId>(MessageCompressor::kZstd),
    };
    for (MessageCompressorId id : ids) {
        auto sw = _compression->manager.compressMessage(ping, &id);
        if (!sw.isOK() || sw.getValue().operation() != dbCompressed) {
            std::cerr << "OP_COMPRESSED_SELFTEST compress failed id=" << static_cast<int>(id)
                      << "\n";
            return false;
        }
        Message compressed = std::move(sw.getValue());
        const int len = compressed.size();
        if (len <= static_cast<int>(sizeof(int))) {
            return false;
        }
        // testOneInput prepends the length word; pass the bytes that follow it.
        testOneInput(compressed.buf() + sizeof(int), static_cast<size_t>(len - sizeof(int)));
    }

    const uint64_t delta = compressedDispatches() - before;
    std::cerr << "OP_COMPRESSED_DISPATCH_PROOF dispatches=" << delta
              << " total=" << compressedDispatches() << "\n";
    return delta == 3;
}

uint64_t OpMsgFuzzerFixture::compressedDispatches() const {
    return _compression ? _compression->dispatches : 0;
}

}  // namespace mongo
