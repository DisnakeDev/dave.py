#include <dave/common.h>

#include "binding_core.hpp"
#include "logging.hpp"

// since these are all (mostly) self-contained bindings,
// just forward-declare these functions instead of writing headers for everything
void bindDecryptor(nb::module_& m);
void bindEncryptor(nb::module_& m);
void bindSession(nb::module_& m);
void bindSignatureKeyPair(nb::module_& m);

NB_MODULE(_dave_impl, m) {
    init_logging();

    m.doc() = "Python bindings to the C++ impl of Discord's DAVE protocol";

    m.attr("k_init_transition_id") = dave::kInitTransitionId;
    m.attr("k_disabled_version") = dave::kDisabledVersion;

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

    // opaque type, for passing between session and encryptor/decryptor
    nb::class_<dave::IKeyRatchet>(m, "IKeyRatchet");

    bindSignatureKeyPair(m);
    bindSession(m);

    bindEncryptor(m);
    bindDecryptor(m);
}
