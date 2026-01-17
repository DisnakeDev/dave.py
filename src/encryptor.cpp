#include <dave/logger.h>
#include <encryptor.h>

#include "binding_core.hpp"

std::vector<nb::handle> encryptor_refs(dave::Encryptor* self) {
    return {nb::find(self->GetProtocolVersionChangedCallback())};
}
GC_TRAVERSE(encryptor_tp_traverse, dave::Encryptor, encryptor_refs)

PyType_Slot encryptor_slots[] = {
    {Py_tp_traverse, (void*)encryptor_tp_traverse},
    {0, 0},
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

    nb::class_<dave::Encryptor>(m, "Encryptor", nb::type_slots(encryptor_slots))
        .def(nb::init<>())
        .def("set_key_ratchet", &dave::Encryptor::SetKeyRatchet, nb::arg("key_ratchet").none())
        .def(
            "set_passthrough_mode",
            &dave::Encryptor::SetPassthroughMode,
            nb::arg("passthrough_mode")
        )
        .def("has_key_ratchet", &dave::Encryptor::HasKeyRatchet)
        .def("is_passthrough_mode", &dave::Encryptor::IsPassthroughMode)
        .def(
            "assign_ssrc_to_codec",
            &dave::Encryptor::AssignSsrcToCodec,
            nb::arg("ssrc"),
            nb::arg("codec_type")
        )
        .def("codec_for_ssrc", &dave::Encryptor::CodecForSsrc, nb::arg("ssrc"))
        .def(
            "encrypt",
            [](
                dave::Encryptor& self, dave::MediaType mediaType, uint32_t ssrc, nb::bytes frame
            ) -> std::optional<nb::bytes> {
                auto frameView = dave::MakeArrayView(
                    reinterpret_cast<const uint8_t*>(frame.data()), frame.size()
                );

                auto requiredSize = self.GetMaxCiphertextByteSize(mediaType, frameView.size());
                std::vector<uint8_t> outFrame(requiredSize);
                auto outFrameView = dave::MakeArrayView(outFrame);

                size_t bytesWritten = 0;
                auto result = self.Encrypt(mediaType, ssrc, frameView, outFrameView, &bytesWritten);

                if (result != dave::Encryptor::ResultCode::Success) {
                    DISCORD_LOG(LS_ERROR) << "encryption failed: " << result;
                    return std::nullopt;
                }
                return nb::bytes(outFrame.data(), bytesWritten);
            },
            nb::arg("media_type"),
            nb::arg("ssrc"),
            nb::arg("frame")
        )
        .def("get_stats", &dave::Encryptor::GetStats, nb::arg("media_type"))
        .def(
            "set_protocol_version_changed_callback",
            &dave::Encryptor::SetProtocolVersionChangedCallback,
            nb::arg("callback").none() = nullptr
        )
        .def("get_protocol_version", &dave::Encryptor::GetProtocolVersion);
}
