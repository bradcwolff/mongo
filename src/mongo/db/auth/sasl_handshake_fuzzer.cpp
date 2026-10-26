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
 *    all of the code used other than as permitted herein. If you do not wish to
 *    do so, delete this exception statement from your version. If you delete this
 *    exception statement from all source files in the program, then also delete
 *    it in the license file.
 */

#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "mongo/base/initializer.h"
#include "mongo/base/status.h"
#include "mongo/base/string_data.h"
#include "mongo/bson/bson_validate.h"
#include "mongo/bson/bsonobj.h"
#include "mongo/bson/json.h"
#include "mongo/crypto/jws_validated_token.h"
#include "mongo/crypto/mechanism_scram.h"
#include "mongo/crypto/sha1_block.h"
#include "mongo/crypto/sha256_block.h"
#include "mongo/db/auth/authorization_manager.h"
#include "mongo/db/auth/authorization_manager_impl.h"
#include "mongo/db/auth/authz_manager_external_state_mock.h"
#include "mongo/db/auth/oauth_authorization_server_metadata_gen.h"
#include "mongo/db/auth/oidc_protocol_gen.h"
#include "mongo/db/auth/sasl_command_constants.h"
#include "mongo/db/auth/sasl_commands_gen.h"
#include "mongo/db/auth/sasl_mechanism_registry.h"
#include "mongo/db/auth/sasl_options.h"
#include "mongo/db/auth/sasl_plain_server_conversation.h"
#include "mongo/db/auth/sasl_scram_server_conversation.h"
#include "mongo/db/auth/user.h"
#include "mongo/db/service_context.h"
#include "mongo/util/database_name_util.h"
#include "mongo/idl/idl_parser.h"
#include "mongo/util/base64.h"
#include "mongo/util/password_digest.h"

namespace mongo {
namespace {

constexpr StringData kFuzzerUser = "fuzzer"_sd;
constexpr StringData kFuzzerDb = "test"_sd;
constexpr StringData kFuzzerPassword = "fuzzer"_sd;

enum class Target : uint8_t {
    kScramSha1 = 0,
    kScramSha256 = 1,
    kPlain = 2,
    kSaslStart = 3,
    kOidcStep1 = 4,
    kOidcStep2 = 5,
    kOidcJwt = 6,
    kOauthMetadata = 7,
    kSaslContinue = 8,
    kCount = 9,
};

class SaslHandshakeFuzzer {
public:
    SaslHandshakeFuzzer() {
        auto initStatus = runGlobalInitializers(std::vector<std::string>{});
        invariant(initStatus.isOK());

        saslGlobalParams.authenticationMechanisms = {
            "SCRAM-SHA-1", "SCRAM-SHA-256", "PLAIN", "MONGODB-X509"};
        saslGlobalParams.authFailedDelay.store(0);

        auto serviceContextHolder = ServiceContext::make();
        _serviceContext = serviceContextHolder.get();
        setGlobalServiceContext(std::move(serviceContextHolder));

        if (!internalSecurity.getUser()) {
            UserRequest systemLocal(UserName("__system"_sd, "local"_sd), boost::none);
            internalSecurity.setUser(std::make_shared<UserHandle>(User(systemLocal)));
        }

        _client = _serviceContext->getService()->makeClient("sasl-handshake-fuzzer");
        _opCtx = _serviceContext->makeOperationContext(_client.get());

        auto externalState = std::make_unique<AuthzManagerExternalStateMock>();
        _externalState = externalState.get();
        auto authzManager = std::make_unique<AuthorizationManagerImpl>(_serviceContext->getService(),
                                                                       std::move(externalState));
        _authzManager = authzManager.get();
        AuthorizationManager::set(_serviceContext->getService(), std::move(authzManager));

        uassertStatusOK(_externalState->insertUserDocument(
            _opCtx.get(), _userDocument(), BSONObj()));
    }

    void selfTest() {
        const std::string clientFirst = "n,,n=fuzzer,r=rOprNGfwEbeR";
        _report("scram-sha-1", _step(std::make_unique<SaslSCRAMSHA1ServerMechanism>(kFuzzerDb.toString()),
                                     clientFirst));
        _report("scram-sha-256",
                _step(std::make_unique<SaslSCRAMSHA256ServerMechanism>(kFuzzerDb.toString()),
                      clientFirst));

        std::string plain = std::string("fuzzer") + '\0' + "fuzzer" + '\0' + "fuzzer";
        _report("plain",
                _step(std::make_unique<SASLPlainServerMechanism>(kFuzzerDb.toString()), plain));

        try {
            auto step1 = auth::OIDCMechanismClientStep1::parse(
                IDLParserContext("oidc-selftest"), fromjson(R"({n: "fuzzer"})"));
            std::cerr << "SASL_HANDSHAKE_SELFTEST oidc-step1="
                      << (step1.getPrincipalName() ? "ok" : "missing-principal") << "\n";
        } catch (const DBException& ex) {
            std::cerr << "SASL_HANDSHAKE_SELFTEST oidc-step1=FAIL " << ex.toStatus() << "\n";
        }

        const std::string token = _sampleJwt();
        auto jwtStatus =
            crypto::JWSValidatedToken::extractIssuerAndAudienceFromCompactSerialization(token);
        std::cerr << "SASL_HANDSHAKE_SELFTEST oidc-jwt="
                  << (jwtStatus.isOK() ? "ok" : jwtStatus.getStatus().toString()) << "\n";

        try {
            auth::OIDCMechanismClientStep2::parse(IDLParserContext("oidc-selftest-step2"),
                                                  BSON("jwt" << token));
            std::cerr << "SASL_HANDSHAKE_SELFTEST oidc-step2=ok\n";
        } catch (const DBException& ex) {
            std::cerr << "SASL_HANDSHAKE_SELFTEST oidc-step2=FAIL " << ex.toStatus() << "\n";
        }

        try {
            OAuthAuthorizationServerMetadata::parse(
                IDLParserContext("oauth-selftest"),
                fromjson(R"({issuer: "https://example.com", jwks_uri: "https://example.com/jwks"})"));
            std::cerr << "SASL_HANDSHAKE_SELFTEST oauth-metadata=ok\n";
        } catch (const DBException& ex) {
            std::cerr << "SASL_HANDSHAKE_SELFTEST oauth-metadata=FAIL " << ex.toStatus() << "\n";
        }
    }

    void testOneInput(const char* data, size_t size) {
        if (size < 2 || data == nullptr) {
            return;
        }
        const auto target = static_cast<Target>(static_cast<uint8_t>(data[0]) %
                                                 static_cast<uint8_t>(Target::kCount));
        const char* payload = data + 1;
        const size_t payloadSize = size - 1;

        try {
            switch (target) {
                case Target::kScramSha1:
                    _fuzzScram<SaslSCRAMSHA1ServerMechanism>(payload, payloadSize, data[0]);
                    break;
                case Target::kScramSha256:
                    _fuzzScram<SaslSCRAMSHA256ServerMechanism>(payload, payloadSize, data[0]);
                    break;
                case Target::kPlain:
                    (void)_step(std::make_unique<SASLPlainServerMechanism>(kFuzzerDb.toString()),
                                std::string(payload, payloadSize));
                    break;
                case Target::kSaslStart:
                    _fuzzSaslStart(payload, payloadSize);
                    break;
                case Target::kOidcStep1:
                    _fuzzOidcStep1(payload, payloadSize);
                    break;
                case Target::kOidcStep2:
                    _fuzzOidcStep2(payload, payloadSize);
                    break;
                case Target::kOidcJwt:
                    (void)crypto::JWSValidatedToken::extractIssuerAndAudienceFromCompactSerialization(
                        StringData(payload, payloadSize));
                    break;
                case Target::kOauthMetadata:
                    _fuzzOauthMetadata(payload, payloadSize);
                    break;
                case Target::kSaslContinue:
                    _fuzzSaslContinue(payload, payloadSize);
                    break;
                case Target::kCount:
                    break;
            }
        } catch (const DBException&) {
            // Malformed handshake messages are the input domain.
        }
    }

private:
    static BSONObj _userDocument() {
        const auto digested = createPasswordDigest(kFuzzerUser, kFuzzerPassword);
        const auto sha1Cred = scram::Secrets<SHA1Block>::generateCredentials(digested, 4096);
        const auto sha256Cred = scram::Secrets<SHA256Block>::generateCredentials(
            kFuzzerPassword.toString(), 4096);
        return BSON("_id" << "test.fuzzer" << AuthorizationManager::USER_NAME_FIELD_NAME
                          << kFuzzerUser << AuthorizationManager::USER_DB_FIELD_NAME << kFuzzerDb
                          << "credentials"
                          << BSON("SCRAM-SHA-1" << sha1Cred << "SCRAM-SHA-256" << sha256Cred)
                          << "roles" << BSONArray());
    }

    static std::string _sampleJwt() {
        const auto header = base64url::encode(R"({"alg":"none","kid":"k"})"_sd);
        // exp is required (jwt_types.idl JWT.exp, unixEpoch seconds). 1893456000 is
        // 2030-01-01 and fits in an int32 so fromjson stores a numeric BSON date field.
        const auto body = base64url::encode(
            R"({"iss":"https://example.com","sub":"fuzzer","aud":"app","exp":1893456000})"_sd);
        return header + "." + body + ".c2ln";
    }

    static void _report(StringData name, const Status& status) {
        std::cerr << "SASL_HANDSHAKE_SELFTEST " << name << "="
                  << (status.isOK() ? "ok" : status.toString()) << "\n";
    }

    Status _step(std::unique_ptr<ServerMechanismBase> mechanism, StringData payload) {
        auto result = mechanism->step(_opCtx.get(), payload);
        return result.getStatus();
    }

    template <typename Mechanism>
    void _fuzzScram(const char* data, size_t size, char selector) {
        auto mechanism = std::make_unique<Mechanism>(kFuzzerDb.toString());
        if ((static_cast<uint8_t>(selector) & 0x80) != 0) {
            (void)mechanism->setOptions(BSON(saslCommandOptionSkipEmptyExchange << true));
        } else if ((static_cast<uint8_t>(selector) & 0x40) != 0) {
            (void)mechanism->setOptions(BSON(saslCommandOptionSkipEmptyExchange << "nope"));
        }

        StringData step1(data, size);
        StringData step2;
        if (size >= sizeof(uint16_t)) {
            uint16_t claimed = 0;
            memcpy(&claimed, data, sizeof(claimed));
            const size_t header = sizeof(claimed);
            if (claimed > 0 && header + static_cast<size_t>(claimed) < size) {
                step1 = StringData(data + header, claimed);
                step2 = StringData(data + header + claimed, size - header - claimed);
            }
        }

        auto first = mechanism->step(_opCtx.get(), step1);
        if (!first.isOK()) {
            return;
        }
        // Second step parses client-final-message (channel binding, nonce, proof).
        const auto secondPayload = step2.empty() ? step1 : step2;
        (void)mechanism->step(_opCtx.get(), secondPayload);
    }

    boost::optional<BSONObj> _parseBson(const char* data, size_t size) {
        if (size == 0) {
            return boost::none;
        }
        if (data[0] == '{' || data[0] == ' ' || data[0] == '\n' || data[0] == '\t') {
            try {
                return fromjson(std::string(data, size));
            } catch (const DBException&) {
                return boost::none;
            }
        }
        if (!validateBSON(data, size).isOK()) {
            return boost::none;
        }
        return BSONObj(data);
    }

    void _fuzzSaslStart(const char* data, size_t size) {
        auto obj = _parseBson(data, size);
        if (!obj) {
            return;
        }
        auto request = auth::SaslStartCommand::parse(IDLParserContext("sasl-fuzzer-start"), *obj);
        auto swMech = SASLServerMechanismRegistry::get(_serviceContext->getService())
                          .getServerMechanism(request.getMechanism(),
                                              DatabaseNameUtil::serialize(
                                                  request.getDbName(),
                                                  request.getSerializationContext()));
        if (!swMech.isOK()) {
            return;
        }
        auto mechanism = std::move(swMech.getValue());
        if (request.getOptions()) {
            uassertStatusOK(mechanism->setOptions(*request.getOptions()));
        }
        (void)mechanism->step(_opCtx.get(), request.getPayload().get());
    }

    void _fuzzSaslContinue(const char* data, size_t size) {
        auto obj = _parseBson(data, size);
        if (!obj) {
            return;
        }
        auth::SaslContinueCommand::parse(IDLParserContext("sasl-fuzzer-continue"), *obj);
    }

    void _fuzzOidcStep1(const char* data, size_t size) {
        auto obj = _parseBson(data, size);
        if (!obj) {
            return;
        }
        auth::OIDCMechanismClientStep1::parse(IDLParserContext("sasl-fuzzer-oidc-1"), *obj);
    }

    void _fuzzOidcStep2(const char* data, size_t size) {
        auto obj = _parseBson(data, size);
        if (!obj) {
            return;
        }
        auto parsed =
            auth::OIDCMechanismClientStep2::parse(IDLParserContext("sasl-fuzzer-oidc-2"), *obj);
        (void)crypto::JWSValidatedToken::extractIssuerAndAudienceFromCompactSerialization(
            parsed.getJWT());
    }

    void _fuzzOauthMetadata(const char* data, size_t size) {
        auto obj = _parseBson(data, size);
        if (!obj) {
            return;
        }
        OAuthAuthorizationServerMetadata::parse(IDLParserContext("sasl-fuzzer-oauth"), *obj);
    }

    ServiceContext* _serviceContext = nullptr;
    ServiceContext::UniqueClient _client;
    ServiceContext::UniqueOperationContext _opCtx;
    AuthzManagerExternalStateMock* _externalState = nullptr;
    AuthorizationManagerImpl* _authzManager = nullptr;
};

SaslHandshakeFuzzer& fuzzer() {
    static SaslHandshakeFuzzer instance;
    return instance;
}

void saslHandshakeFuzzerSelfTest() {
    fuzzer().selfTest();
}

void saslHandshakeFuzzerOneInput(const char* data, size_t size) {
    fuzzer().testOneInput(data, size);
}

}  // namespace

void runSaslHandshakeFuzzerSelfTest() {
    saslHandshakeFuzzerSelfTest();
}

void runSaslHandshakeFuzzerOneInput(const char* data, size_t size) {
    saslHandshakeFuzzerOneInput(data, size);
}

}  // namespace mongo

extern "C" int LLVMFuzzerInitialize(int* /*argc*/, char*** /*argv*/) {
    mongo::runSaslHandshakeFuzzerSelfTest();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    mongo::runSaslHandshakeFuzzerOneInput(reinterpret_cast<const char*>(data), size);
    return 0;
}
