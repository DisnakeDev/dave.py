#include <dave/common.h>
#include <dave/decryptor.h>
#include <dave/encryptor.h>
#include <dave/mls/parameters.h>
#include <dave/mls/session.h>
#include <dave/version.h>
#include <dave_interfaces.h>
#include <mls/crypto.h>
#include <nanobind/nanobind.h>
#include <nanobind/stl/chrono.h>
#include <nanobind/stl/function.h>
#include <nanobind/stl/map.h>
#include <nanobind/stl/optional.h>
#include <nanobind/stl/set.h>
#include <nanobind/stl/shared_ptr.h>
#include <nanobind/stl/string.h>
#include <nanobind/stl/unique_ptr.h>
#include <nanobind/stl/variant.h>
#include <nanobind/stl/vector.h>

#include <iostream>

#include "logging.hpp"
#include "utils.hpp"

namespace nb = nanobind;
namespace dave = discord::dave;

// used instead of std::variant for hard-/soft-rejecting messages
enum RejectType : uint8_t {
    Failed,  // dave::failed_t
    Ignored  // dave::ignored_t
};

template <class T>
std::variant<RejectType, T> unwrapRejection(
    std::variant<dave::failed_t, dave::ignored_t, T>&& variant
) {
    if (std::holds_alternative<dave::failed_t>(variant))
        return RejectType::Failed;
    else if (std::holds_alternative<dave::ignored_t>(variant))
        return RejectType::Ignored;
    return std::get<T>(std::move(variant));
}

class SignatureKeyPair {
private:
    SignatureKeyPair(std::shared_ptr<mlspp::SignaturePrivateKey> privateKey)
        : privateKey(privateKey) {}

public:
    std::shared_ptr<mlspp::SignaturePrivateKey> privateKey;

    static SignatureKeyPair generate(dave::ProtocolVersion version) {
        auto suite = dave::mls::CiphersuiteForProtocolVersion(version);
        return {std::make_shared<mlspp::SignaturePrivateKey>(
            mlspp::SignaturePrivateKey::generate(suite)
        )};
    }

    static SignatureKeyPair load(dave::ProtocolVersion version, const std::string& str) {
        auto suite = dave::mls::CiphersuiteForProtocolVersion(version);
        return {std::make_shared<mlspp::SignaturePrivateKey>(
            mlspp::SignaturePrivateKey::from_jwk(suite, str)
        )};
    }

    std::string dump(dave::ProtocolVersion version) {
        auto suite = dave::mls::CiphersuiteForProtocolVersion(version);
        return privateKey->to_jwk(suite);
    }
};

class SessionWrapper {
private:
    std::unique_ptr<dave::mls::Session> _session;

public:
    SessionWrapper(dave::mls::MLSFailureCallback callback) {
        // context and authSessionId are only used for persistent keys, which we don't implement
        // (it builds with the null/placeholder implementation, so the key store would
        // never return anything anyway)
        _session = std::make_unique<dave::mls::Session>("", "", callback);
    }

    void Init(
        dave::ProtocolVersion version,
        uint64_t groupId,
        std::string const& selfUserId,
        std::shared_ptr<SignatureKeyPair>& transientKey
    ) {
        auto key = transientKey != nullptr ? transientKey->privateKey : nullptr;
        _session->Init(version, groupId, selfUserId, key);
    }

    void Reset() { _session->Reset(); }

    void SetProtocolVersion(dave::ProtocolVersion version) {
        _session->SetProtocolVersion(version);
    }

    dave::ProtocolVersion GetProtocolVersion() { return _session->GetProtocolVersion(); }

    void SetExternalSender(nb::bytes marshalledExternalSender) {
        return _session->SetExternalSender(nb::bytes_to_vector(marshalledExternalSender));
    }

    std::optional<nb::bytes> ProcessProposals(
        nb::bytes proposals, std::set<std::string> const& recognizedUserIDs
    ) {
        auto res = _session->ProcessProposals(nb::bytes_to_vector(proposals), recognizedUserIDs);
        if (res) return nb::vector_to_bytes(*res);
        return std::nullopt;
    }

    std::variant<RejectType, dave::RosterMap> ProcessCommit(nb::bytes commit) {
        return unwrapRejection(_session->ProcessCommit(nb::bytes_to_vector(commit)));
    }

    std::optional<dave::RosterMap> ProcessWelcome(
        nb::bytes welcome, std::set<std::string> const& recognizedUserIDs
    ) {
        return _session->ProcessWelcome(nb::bytes_to_vector(welcome), recognizedUserIDs);
    }

    nb::bytes GetMarshalledKeyPackage() {
        return nb::vector_to_bytes(_session->GetMarshalledKeyPackage());
    }

    nb::bytes GetLastEpochAuthenticator() {
        return nb::vector_to_bytes(_session->GetLastEpochAuthenticator());
    }

    std::unique_ptr<dave::IKeyRatchet> GetKeyRatchet(std::string const& userId) const noexcept {
        return _session->GetKeyRatchet(userId);
    }

    nb::object GetPairwiseFingerprint(uint16_t version, std::string const& userId) {
        auto fut = nb::module_::import_("asyncio").attr("Future")();
        _session->GetPairwiseFingerprint(
            version, userId, [fut = gil_object_wrapper(fut)](std::vector<uint8_t> const& result) {
                nb::gil_scoped_acquire acquire;
                auto call_soon_threadsafe = fut->attr("get_loop")().attr("call_soon_threadsafe");
                call_soon_threadsafe(
                    fut->attr("set_result"), nb::vector_to_bytes(std::move(result))
                );
            }
        );
        return fut;
    }
};

class EncryptorWrapper {
private:
    std::unique_ptr<dave::Encryptor> _encryptor;

public:
    EncryptorWrapper() { _encryptor = std::make_unique<dave::Encryptor>(); }

    void SetKeyRatchet(std::unique_ptr<dave::IKeyRatchet> keyRatchet) {
        return _encryptor->SetKeyRatchet(std::move(keyRatchet));
    }

    void SetPassthroughMode(bool passthroughMode) {
        _encryptor->SetPassthroughMode(passthroughMode);
    }

    bool HasKeyRatchet() { return _encryptor->HasKeyRatchet(); }

    bool IsPassthroughMode() { return _encryptor->IsPassthroughMode(); }

    void AssignSsrcToCodec(uint32_t ssrc, dave::Codec codecType) {
        _encryptor->AssignSsrcToCodec(ssrc, codecType);
    }

    dave::Codec CodecForSsrc(uint32_t ssrc) { return _encryptor->CodecForSsrc(ssrc); }

    std::optional<nb::bytes> Encrypt(dave::MediaType mediaType, uint32_t ssrc, nb::bytes frame) {
        auto frameView =
            dave::MakeArrayView(reinterpret_cast<const uint8_t*>(frame.data()), frame.size());

        auto requiredSize = _encryptor->GetMaxCiphertextByteSize(mediaType, frameView.size());
        std::vector<uint8_t> outFrame(requiredSize);
        auto outFrameView = dave::MakeArrayView(outFrame);

        size_t bytesWritten = 0;
        auto result = _encryptor->Encrypt(mediaType, ssrc, frameView, outFrameView, &bytesWritten);

        if (result != dave::Encryptor::ResultCode::Success) {
            DISCORD_LOG(LS_ERROR) << "encryption failed: " << result;
            return std::nullopt;
        }
        return nb::bytes(outFrame.data(), bytesWritten);
    }

    dave::EncryptorStats GetStats(dave::MediaType mediaType) {
        return _encryptor->GetStats(mediaType);
    }

    void SetProtocolVersionChangedCallback(
        dave::Encryptor::ProtocolVersionChangedCallback callback
    ) {
        _encryptor->SetProtocolVersionChangedCallback(callback);
    }

    dave::ProtocolVersion GetProtocolVersion() { return _encryptor->GetProtocolVersion(); }
};

class DecryptorWrapper {
private:
    std::unique_ptr<dave::Decryptor> _decryptor;

public:
    DecryptorWrapper() { _decryptor = std::make_unique<dave::Decryptor>(); }

    void TransitionToKeyRatchet(
        std::unique_ptr<dave::IKeyRatchet> keyRatchet, dave::Decryptor::Duration transitionExpiry
    ) {
        _decryptor->TransitionToKeyRatchet(std::move(keyRatchet), transitionExpiry);
    }

    void TransitionToPassthroughMode(
        bool passthroughMode, dave::Decryptor::Duration transitionExpiry
    ) {
        _decryptor->TransitionToPassthroughMode(passthroughMode, transitionExpiry);
    }

    std::optional<nb::bytes> Decrypt(dave::MediaType mediaType, nb::bytes frame) {
        auto frameView =
            dave::MakeArrayView(reinterpret_cast<const uint8_t*>(frame.data()), frame.size());

        auto requiredSize = _decryptor->GetMaxPlaintextByteSize(mediaType, frameView.size());
        std::vector<uint8_t> outFrame(requiredSize);
        auto outFrameView = dave::MakeArrayView(outFrame);

        size_t bytesWritten = 0;
        auto result = _decryptor->Decrypt(mediaType, frameView, outFrameView, &bytesWritten);

        if (result != dave::Decryptor::ResultCode::Success) {
            DISCORD_LOG(LS_ERROR) << "decryption failed: " << result;
            return std::nullopt;
        }
        return nb::bytes(outFrame.data(), bytesWritten);
    }

    dave::DecryptorStats GetStats(dave::MediaType mediaType) {
        return _decryptor->GetStats(mediaType);
    }
};

NB_MODULE(_dave_impl, m) {
    init_logging();

    m.doc() = "Python bindings to the C++ impl of Discord's DAVE protocol";

    m.attr("k_init_transition_id") = dave::kInitTransitionId;
    m.attr("k_disabled_version") = dave::kDisabledVersion;

    nb::enum_<RejectType>(m, "RejectType", nb::is_arithmetic(), "")
        .value("failed", RejectType::Failed, "")
        .value("ignored", RejectType::Ignored, "");

    nb::enum_<dave::MediaType>(m, "MediaType", nb::is_arithmetic(), "")
        .value("audio", dave::MediaType::Audio, "")
        .value("video", dave::MediaType::Video, "");

    nb::enum_<dave::Codec>(m, "Codec", nb::is_arithmetic(), "")
        .value("unknown", dave::Codec::Unknown, "")
        .value("opus", dave::Codec::Opus, "")
        .value("vp8", dave::Codec::VP8, "")
        .value("vp9", dave::Codec::VP9, "")
        .value("h264", dave::Codec::H264, "")
        .value("h265", dave::Codec::H265, "")
        .value("av1", dave::Codec::AV1, "");

    m.def("get_max_supported_protocol_version", dave::MaxSupportedProtocolVersion);

    nb::class_<SignatureKeyPair>(m, "SignatureKeyPair")
        .def_static("generate", &SignatureKeyPair::generate, nb::arg("version"))
        .def_static("load", &SignatureKeyPair::load, nb::arg("version"), nb::arg("data"))
        .def("dump", &SignatureKeyPair::dump, nb::arg("version"));

    nb::class_<dave::IKeyRatchet>(m, "IKeyRatchet");

    nb::class_<dave::EncryptorStats>(m, "EncryptorStats")
        .def_ro("passthrough_count", &dave::EncryptorStats::passthroughCount)
        .def_ro("encrypt_success_count", &dave::EncryptorStats::encryptSuccessCount)
        .def_ro("encrypt_failure_count", &dave::EncryptorStats::encryptFailureCount)
        .def_ro("encrypt_duration", &dave::EncryptorStats::encryptDuration)
        .def_ro("encrypt_attempts", &dave::EncryptorStats::encryptAttempts)
        .def_ro("encrypt_max_attempts", &dave::EncryptorStats::encryptMaxAttempts)
        .def_ro("encrypt_missing_key_count", &dave::EncryptorStats::encryptMissingKeyCount);

    nb::class_<dave::DecryptorStats>(m, "DecryptorStats")
        .def_ro("passthrough_count", &dave::DecryptorStats::passthroughCount)
        .def_ro("decrypt_success_count", &dave::DecryptorStats::decryptSuccessCount)
        .def_ro("decrypt_failure_count", &dave::DecryptorStats::decryptFailureCount)
        .def_ro("decrypt_duration", &dave::DecryptorStats::decryptDuration)
        .def_ro("decrypt_attempts", &dave::DecryptorStats::decryptAttempts)
        .def_ro("decrypt_missing_key_count", &dave::DecryptorStats::decryptMissingKeyCount)
        .def_ro("decrypt_invalid_nonce_count", &dave::DecryptorStats::decryptInvalidNonceCount);

    nb::class_<SessionWrapper>(m, "Session")
        .def(nb::init<dave::mls::MLSFailureCallback>(), nb::arg("mls_failure_callback"))
        .def(
            "init",
            &SessionWrapper::Init,
            nb::arg("version"),
            nb::arg("group_id"),
            nb::arg("self_user_id"),
            nb::arg("transient_key").none()
        )
        .def("reset", &SessionWrapper::Reset)
        .def("set_protocol_version", &SessionWrapper::SetProtocolVersion, nb::arg("version"))
        .def("get_protocol_version", &SessionWrapper::GetProtocolVersion)
        .def("get_last_epoch_authenticator", &SessionWrapper::GetLastEpochAuthenticator)
        .def(
            "set_external_sender",
            &SessionWrapper::SetExternalSender,
            nb::arg("external_sender_package")
        )
        .def(
            "process_proposals",
            &SessionWrapper::ProcessProposals,
            nb::arg("proposals"),
            nb::arg("recognized_user_ids")
        )
        .def("process_commit", &SessionWrapper::ProcessCommit, nb::arg("commit"))
        .def(
            "process_welcome",
            &SessionWrapper::ProcessWelcome,
            nb::arg("welcome"),
            nb::arg("recognized_user_ids")
        )
        .def("get_marshalled_key_package", &SessionWrapper::GetMarshalledKeyPackage)
        .def(
            "get_key_ratchet",
            &SessionWrapper::GetKeyRatchet,
            nb::arg("user_id"),
            // explicit signature as this can return a nullptr
            nb::sig("def get_key_ratchet(self, user_id: str) -> IKeyRatchet | None")
        )
        .def(
            "get_pairwise_fingerprint",
            &SessionWrapper::GetPairwiseFingerprint,
            nb::arg("version"),
            nb::arg("user_id"),
            nb::sig(
                "def get_pairwise_fingerprint(self, version: int, user_id: str) -> "
                "asyncio.Future[bytes]"
            )
        );

    nb::class_<EncryptorWrapper>(m, "Encryptor")
        .def(nb::init<>())
        .def("set_key_ratchet", &EncryptorWrapper::SetKeyRatchet, nb::arg("key_ratchet").none())
        .def(
            "set_passthrough_mode",
            &EncryptorWrapper::SetPassthroughMode,
            nb::arg("passthrough_mode")
        )
        .def("has_key_ratchet", &EncryptorWrapper::HasKeyRatchet)
        .def("is_passthrough_mode", &EncryptorWrapper::IsPassthroughMode)
        .def(
            "assign_ssrc_to_codec",
            &EncryptorWrapper::AssignSsrcToCodec,
            nb::arg("ssrc"),
            nb::arg("codec_type")
        )
        .def("codec_for_ssrc", &EncryptorWrapper::CodecForSsrc, nb::arg("ssrc"))
        .def(
            "encrypt",
            &EncryptorWrapper::Encrypt,
            nb::arg("media_type"),
            nb::arg("ssrc"),
            nb::arg("frame")
        )
        .def("get_stats", &EncryptorWrapper::GetStats, nb::arg("media_type"))
        .def(
            "set_protocol_version_changed_callback",
            &EncryptorWrapper::SetProtocolVersionChangedCallback,
            nb::arg("callback")
        )
        .def("get_protocol_version", &EncryptorWrapper::GetProtocolVersion);

    nb::class_<DecryptorWrapper>(m, "Decryptor")
        .def(nb::init<>())
        .def(
            "transition_to_key_ratchet",
            &DecryptorWrapper::TransitionToKeyRatchet,
            nb::arg("key_ratchet"),
            nb::arg("transition_expiry") = dave::kDefaultTransitionDuration
        )
        .def(
            "transition_to_passthrough_mode",
            &DecryptorWrapper::TransitionToPassthroughMode,
            nb::arg("passthrough_mode"),
            nb::arg("transition_expiry") = dave::kDefaultTransitionDuration
        )
        .def("decrypt", &DecryptorWrapper::Decrypt, nb::arg("media_type"), nb::arg("frame"))
        .def("get_stats", &DecryptorWrapper::GetStats, nb::arg("media_type"));
}
