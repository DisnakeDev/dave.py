#include <iostream>

#include <nanobind/nanobind.h>
#include <nanobind/stl/function.h>
#include <nanobind/stl/vector.h>
#include <nanobind/stl/set.h>
#include <nanobind/stl/map.h>
#include <nanobind/stl/shared_ptr.h>
#include <nanobind/stl/unique_ptr.h>
#include <nanobind/stl/string.h>
#include <nanobind/stl/optional.h>
#include <nanobind/stl/variant.h>

#include <mls/crypto.h>

#include <dave/common.h>
#include <dave/encryptor.h>
#include <dave/version.h>
#include <dave/mls/session.h>
#include <dave_interfaces.h>

#include "logging.hpp"
#include "utils.hpp"

namespace nb = nanobind;

// used instead of std::variant for hard-/soft-rejecting messages
enum RejectType : uint8_t {
    Failed,  // dave::failed_t
    Ignored  // dave::ignored_t
};

template <class T>
std::variant<RejectType, T> unwrapRejection(std::variant<discord::dave::failed_t, discord::dave::ignored_t, T>&& variant) {
    if (std::holds_alternative<discord::dave::failed_t>(variant))
        return RejectType::Failed;
    else if (std::holds_alternative<discord::dave::ignored_t>(variant))
        return RejectType::Ignored;
    return std::get<T>(std::move(variant));
}

class SessionWrapper {
private:
    std::unique_ptr<discord::dave::mls::Session> _session;
public:
    SessionWrapper(
        discord::dave::mls::KeyPairContextType context,
        std::string authSessionId,
        discord::dave::mls::MLSFailureCallback callback)
    {
        _session = std::make_unique<discord::dave::mls::Session>(context, authSessionId, callback);
    }

    void Init(
        discord::dave::ProtocolVersion version,
        uint64_t groupId,
        std::string const& selfUserId,
        std::shared_ptr<::mlspp::SignaturePrivateKey>& transientKey)
    {
        _session->Init(version, groupId, selfUserId, transientKey);
    }

    void Reset() { _session->Reset(); }

    void SetProtocolVersion(discord::dave::ProtocolVersion version) { _session->SetProtocolVersion(version); }

    discord::dave::ProtocolVersion GetProtocolVersion() { return _session->GetProtocolVersion(); }

    void SetExternalSender(nb::bytes marshalledExternalSender) {
        return _session->SetExternalSender(nb::bytes_to_vector(marshalledExternalSender));
    }

    std::optional<nb::bytes> ProcessProposals(
        nb::bytes proposals,
        std::set<std::string> const& recognizedUserIDs
    ) {
        auto res = _session->ProcessProposals(
            nb::bytes_to_vector(proposals),
            recognizedUserIDs
        );
        if (res)
            return nb::vector_to_bytes(*res);
        return std::nullopt;
    }

    std::variant<RejectType, discord::dave::RosterMap> ProcessCommit(nb::bytes commit) {
        return unwrapRejection(_session->ProcessCommit(nb::bytes_to_vector(commit)));
    }

    std::optional<discord::dave::RosterMap> ProcessWelcome(
        nb::bytes welcome,
        std::set<std::string> const& recognizedUserIDs
    ) {
        return _session->ProcessWelcome(
            nb::bytes_to_vector(welcome),
            recognizedUserIDs
        );
    }

    nb::bytes GetMarshalledKeyPackage() {
        return nb::vector_to_bytes(_session->GetMarshalledKeyPackage());
    }

    nb::bytes GetLastEpochAuthenticator() {
        return nb::vector_to_bytes(_session->GetLastEpochAuthenticator());
    }

    std::unique_ptr<discord::dave::MlsKeyRatchet> GetKeyRatchet(std::string const& userId) const noexcept {
        auto ratchet = _session->GetKeyRatchet(userId);
        // XXX: since we expose MlsKeyRatchet as an opaque type anyway, could we actually just return the opaque IKeyRatchet?
        // required to cast unique_ptr<IKeyRatchet> to unique_ptr<MlsKeyRatchet>
        return std::unique_ptr<discord::dave::MlsKeyRatchet>(
            static_cast<discord::dave::MlsKeyRatchet*>(ratchet.release())
        );
    }

    nb::object GetPairwiseFingerprint(
        uint16_t version, std::string const& userId
    ) {
        auto fut = nb::module_::import_("asyncio").attr("Future")();
        _session->GetPairwiseFingerprint(
            version,
            userId,
            [fut = gil_object_wrapper(fut)] (std::vector<uint8_t> const& result) {
                nb::gil_scoped_acquire acquire;
                auto call_soon_threadsafe = fut->attr("get_loop")().attr("call_soon_threadsafe");
                call_soon_threadsafe(
                    fut->attr("set_result"),
                    nb::vector_to_bytes(std::move(result))
                );
            }
        );
        return fut;
    }
};

class EncryptorWrapper {
private:
    std::unique_ptr<discord::dave::Encryptor> _encryptor;
public:
    EncryptorWrapper() {
        _encryptor = std::make_unique<discord::dave::Encryptor>();
    }

    void SetKeyRatchet(std::unique_ptr<discord::dave::MlsKeyRatchet> keyRatchet) {
        return _encryptor->SetKeyRatchet(std::move(keyRatchet));
    }

    void SetPassthroughMode(bool passthroughMode) { _encryptor->SetPassthroughMode(passthroughMode); }

    bool HasKeyRatchet() { return _encryptor->HasKeyRatchet(); }

    bool IsPassthroughMode() { return _encryptor->IsPassthroughMode(); }

    void AssignSsrcToCodec(uint32_t ssrc, discord::dave::Codec codecType) {
        _encryptor->AssignSsrcToCodec(ssrc, codecType);
    }

    discord::dave::Codec CodecForSsrc(uint32_t ssrc) { return _encryptor->CodecForSsrc(ssrc); }

    std::optional<nb::bytes> Encrypt(
        discord::dave::MediaType mediaType,
        uint32_t ssrc,
        nb::bytes frame
    ) {
        auto frameView = discord::dave::MakeArrayView(
            reinterpret_cast<const uint8_t*>(frame.data()),
            frame.size()
        );

        auto requiredSize = GetMaxCiphertextByteSize(mediaType, frameView.size());
        std::vector<uint8_t> outFrame(requiredSize);
        auto outFrameView = discord::dave::MakeArrayView(outFrame);

        size_t bytesWritten = 0;
        auto result = _encryptor->Encrypt(
            mediaType,
            ssrc,
            frameView,
            outFrameView,
            &bytesWritten
        );

        // TODO: use resultcode enum
        if (result != 0) {
            DISCORD_LOG(LS_ERROR) << "encryption failed: " << result;
            return std::nullopt;
        }
        return nb::bytes(outFrame.data(), bytesWritten);
    }

    // FIXME: this isn't really needed in the public interface
    size_t GetMaxCiphertextByteSize(discord::dave::MediaType mediaType, size_t frameSize) {
        return _encryptor->GetMaxCiphertextByteSize(mediaType, frameSize);
    }

    discord::dave::EncryptorStats GetStats(discord::dave::MediaType mediaType) {
        return _encryptor->GetStats(mediaType);
    }

    void SetProtocolVersionChangedCallback(discord::dave::Encryptor::ProtocolVersionChangedCallback callback) {
        _encryptor->SetProtocolVersionChangedCallback(callback);
    }

    discord::dave::ProtocolVersion GetProtocolVersion() { return _encryptor->GetProtocolVersion(); }
};

NB_MODULE(_dave_impl, m) {
    init_logging();

    m.doc() = "Python bindings to the C++ impl of Discord's DAVE protocol";

    m.attr("k_init_transition_id") = discord::dave::kInitTransitionId;
    m.attr("k_disabled_version") = discord::dave::kDisabledVersion;

    nb::enum_<RejectType>(m, "RejectType", nb::is_arithmetic(), "")
        .value("failed", RejectType::Failed, "")
        .value("ignored", RejectType::Ignored, "");

    nb::enum_<discord::dave::MediaType>(m, "MediaType", nb::is_arithmetic(), "")
        .value("audio", discord::dave::MediaType::Audio, "")
        .value("video", discord::dave::MediaType::Video, "");


    nb::enum_<discord::dave::Codec>(m, "Codec", nb::is_arithmetic(), "")
        .value("unknown", discord::dave::Codec::Unknown, "")
        .value("opus", discord::dave::Codec::Opus, "")
        .value("vp8", discord::dave::Codec::VP8, "")
        .value("vp9", discord::dave::Codec::VP9, "")
        .value("h264", discord::dave::Codec::H264, "")
        .value("h265", discord::dave::Codec::H265, "")
        .value("av1", discord::dave::Codec::AV1, "");

    m.def("get_max_supported_protocol_version", discord::dave::MaxSupportedProtocolVersion);

    nb::class_<::mlspp::SignaturePrivateKey>(m, "SignaturePrivateKey");
    nb::class_<discord::dave::MlsKeyRatchet>(m, "MlsKeyRatchet");

    nb::class_<discord::dave::EncryptorStats>(m, "EncryptorStats")
        .def_ro("passthrough_count", &discord::dave::EncryptorStats::passthroughCount)
        .def_ro("encrypt_success_count", &discord::dave::EncryptorStats::encryptSuccessCount)
        .def_ro("encrypt_failure_count", &discord::dave::EncryptorStats::encryptFailureCount)
        .def_ro("encrypt_duration", &discord::dave::EncryptorStats::encryptDuration)
        .def_ro("encrypt_attempts", &discord::dave::EncryptorStats::encryptAttempts)
        .def_ro("encrypt_max_attempts", &discord::dave::EncryptorStats::encryptMaxAttempts)
        .def_ro("encrypt_missing_key_count", &discord::dave::EncryptorStats::encryptMissingKeyCount);

    nb::class_<SessionWrapper>(m, "Session")
        .def(nb::init<discord::dave::mls::KeyPairContextType, std::string, discord::dave::mls::MLSFailureCallback>(),
            nb::arg("context"), nb::arg("auth_session_id"), nb::arg("mls_failure_callback"))
        .def("init",
            &SessionWrapper::Init, nb::arg("version"), nb::arg("group_id"), nb::arg("self_user_id"), nb::arg("transient_key").none())
        .def("reset",
            &SessionWrapper::Reset)
        .def("set_protocol_version",
            &SessionWrapper::SetProtocolVersion, nb::arg("version"))
        .def("get_protocol_version",
            &SessionWrapper::GetProtocolVersion)
        .def("get_last_epoch_authenticator",
            &SessionWrapper::GetLastEpochAuthenticator)
        .def("set_external_sender",
            &SessionWrapper::SetExternalSender, nb::arg("external_sender_package"))
        .def("process_proposals",
            &SessionWrapper::ProcessProposals, nb::arg("proposals"), nb::arg("recognized_user_ids"))
        .def("process_commit",
            &SessionWrapper::ProcessCommit, nb::arg("commit"))
        .def("process_welcome",
            &SessionWrapper::ProcessWelcome, nb::arg("welcome"), nb::arg("recognized_user_ids"))
        .def("get_marshalled_key_package",
            &SessionWrapper::GetMarshalledKeyPackage)
        .def("get_key_ratchet",
            &SessionWrapper::GetKeyRatchet, nb::arg("user_id"),
            // TODO: fix by using optional?
            // explicit signature as this can return a nullptr
            nb::sig("def get_key_ratchet(self, user_id: str) -> MlsKeyRatchet | None"))
        .def("get_pairwise_fingerprint",
            &SessionWrapper::GetPairwiseFingerprint, nb::arg("version"), nb::arg("user_id"),
            nb::sig("def get_pairwise_fingerprint(self, version: int, user_id: str) -> asyncio.Future[bytes]"));

    nb::class_<EncryptorWrapper>(m, "Encryptor")
        .def(nb::init<>())
        .def("set_key_ratchet",
            &EncryptorWrapper::SetKeyRatchet, nb::arg("key_ratchet").none())
        .def("set_passthrough_mode",
            &EncryptorWrapper::SetPassthroughMode, nb::arg("passthrough_mode"))
        .def("has_key_ratchet",
            &EncryptorWrapper::HasKeyRatchet)
        .def("is_passthrough_mode",
            &EncryptorWrapper::IsPassthroughMode)
        .def("assign_ssrc_to_codec",
            &EncryptorWrapper::AssignSsrcToCodec, nb::arg("ssrc"), nb::arg("codec_type"))
        .def("codec_for_ssrc",
            &EncryptorWrapper::CodecForSsrc, nb::arg("ssrc"))
        .def("encrypt",
            &EncryptorWrapper::Encrypt, nb::arg("media_type"), nb::arg("ssrc"), nb::arg("frame"))
        .def("get_max_ciphertext_byte_size",
            &EncryptorWrapper::GetMaxCiphertextByteSize, nb::arg("media_type"), nb::arg("frame_size"))
        .def("get_stats",
            &EncryptorWrapper::GetStats, nb::arg("media_type"))
        .def("set_protocol_version_changed_callback",
            &EncryptorWrapper::SetProtocolVersionChangedCallback, nb::arg("callback"))
        .def("get_protocol_version",
            &EncryptorWrapper::GetProtocolVersion);
}
