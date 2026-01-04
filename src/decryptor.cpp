#include <dave/decryptor.h>
#include <dave/logger.h>

#include "binding_core.hpp"

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

void bindDecryptor(nb::module_& m) {
    nb::class_<dave::DecryptorStats>(m, "DecryptorStats")
        .def_ro("passthrough_count", &dave::DecryptorStats::passthroughCount)
        .def_ro("decrypt_success_count", &dave::DecryptorStats::decryptSuccessCount)
        .def_ro("decrypt_failure_count", &dave::DecryptorStats::decryptFailureCount)
        .def_ro("decrypt_duration", &dave::DecryptorStats::decryptDuration)
        .def_ro("decrypt_attempts", &dave::DecryptorStats::decryptAttempts)
        .def_ro("decrypt_missing_key_count", &dave::DecryptorStats::decryptMissingKeyCount)
        .def_ro("decrypt_invalid_nonce_count", &dave::DecryptorStats::decryptInvalidNonceCount);

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
