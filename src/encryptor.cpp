#include <dave/encryptor.h>
#include <dave/logger.h>

#include "binding_core.hpp"

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

void bindEncryptor(nb::module_& m) {
    nb::class_<dave::EncryptorStats>(m, "EncryptorStats")
        .def_ro("passthrough_count", &dave::EncryptorStats::passthroughCount)
        .def_ro("encrypt_success_count", &dave::EncryptorStats::encryptSuccessCount)
        .def_ro("encrypt_failure_count", &dave::EncryptorStats::encryptFailureCount)
        .def_ro("encrypt_duration", &dave::EncryptorStats::encryptDuration)
        .def_ro("encrypt_attempts", &dave::EncryptorStats::encryptAttempts)
        .def_ro("encrypt_max_attempts", &dave::EncryptorStats::encryptMaxAttempts)
        .def_ro("encrypt_missing_key_count", &dave::EncryptorStats::encryptMissingKeyCount);

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
}
