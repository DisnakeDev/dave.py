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
#include <dave/utils/array_view.h>

#include "logging.h"

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

class SessionWrapper : public discord::dave::mls::Session {
public:
    // inherit constructor
    using discord::dave::mls::Session::Session;

    std::variant<RejectType, discord::dave::RosterMap> ProcessCommit(std::vector<uint8_t> commit) noexcept {
        return unwrapRejection(discord::dave::mls::Session::ProcessCommit(commit));
    }
};

class EncryptorWrapper : public discord::dave::Encryptor {
public:
    // inherit constructor
    using discord::dave::Encryptor::Encryptor;

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
        auto result = discord::dave::Encryptor::Encrypt(
            mediaType,
            ssrc,
            frameView,
            outFrameView,
            &bytesWritten
        );

        if (result != 0) {
            DISCORD_LOG(LS_ERROR) << "encryption failed: " << result;
            return std::nullopt;
        }
        return nb::bytes(outFrame.data(), bytesWritten);
    }
};

NB_MODULE(example, m) {
    init_logging();

    m.attr("kInitTransitionId") = discord::dave::kInitTransitionId;
    m.attr("kDisabledVersion") = discord::dave::kDisabledVersion;

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

    nb::class_<SessionWrapper>(m, "Session")
        .def(nb::init<discord::dave::mls::KeyPairContextType, std::string, discord::dave::mls::Session::MLSFailureCallback>(),
            nb::arg("context"), nb::arg("auth_session_id"), nb::arg("callback"))
        .def("init",
            &SessionWrapper::Init, nb::arg("version"), nb::arg("group_id"), nb::arg("self_user_id"), nb::arg("transient_key"))
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
            &SessionWrapper::GetKeyRatchet, nb::arg("user_id"))
        .def("get_pairwise_fingerprint",
            &SessionWrapper::GetPairwiseFingerprint, nb::arg("version"), nb::arg("user_id"), nb::arg("callback"));

    nb::class_<EncryptorWrapper>(m, "Encryptor")
        .def(nb::init<>())
        .def("set_key_ratchet",
            &discord::dave::Encryptor::SetKeyRatchet, nb::arg("key_ratchet"))
        .def("set_passthrough_mode",
            &discord::dave::Encryptor::SetPassthroughMode, nb::arg("passthrough_mode"))
        .def("has_key_ratchet",
            &discord::dave::Encryptor::HasKeyRatchet)
        .def("is_passthrough_mode",
            &discord::dave::Encryptor::IsPassthroughMode)
        .def("assign_ssrc_to_codec",
            &discord::dave::Encryptor::AssignSsrcToCodec, nb::arg("ssrc"), nb::arg("codec_type"))
        .def("codec_for_ssrc",
            &discord::dave::Encryptor::CodecForSsrc, nb::arg("ssrc"))
        .def("encrypt",
            &EncryptorWrapper::Encrypt, nb::arg("media_type"), nb::arg("ssrc"), nb::arg("frame"))
        .def("get_max_ciphertext_byte_size",
            &discord::dave::Encryptor::GetMaxCiphertextByteSize, nb::arg("media_type"), nb::arg("frame_size"))
        .def("get_stats",
            &discord::dave::Encryptor::GetStats, nb::arg("media_type"))
        .def("set_protocol_version_changed_callback",
            &discord::dave::Encryptor::SetProtocolVersionChangedCallback, nb::arg("callback"))
        .def("get_protocol_version",
            &discord::dave::Encryptor::GetProtocolVersion);
}
