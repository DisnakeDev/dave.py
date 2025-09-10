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
#include <dave/version.h>
#include <dave/mls/session.h>

#include "logging.h"

namespace nb = nanobind;

NB_MODULE(example, m) {
    std::cout << "init" << std::endl;
    init_logging();

    m.attr("kInitTransitionId") = discord::dave::kInitTransitionId;
    m.attr("kDisabledVersion") = discord::dave::kDisabledVersion;

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

    nb::class_<discord::dave::failed_t>(m, "FailedT");
    nb::class_<discord::dave::ignored_t>(m, "IgnoredT");
    nb::class_<::mlspp::SignaturePrivateKey>(m, "SignaturePrivateKey");

    nb::class_<discord::dave::mls::Session>(m, "Session")
        .def(nb::init<discord::dave::mls::KeyPairContextType, std::string, discord::dave::mls::Session::MLSFailureCallback>(),
            nb::arg("context"), nb::arg("auth_session_id"), nb::arg("callback"))
        .def("init",
            &discord::dave::mls::Session::Init, nb::arg("version"), nb::arg("group_id"), nb::arg("self_user_id"), nb::arg("transient_key"))
        .def("reset",
            &discord::dave::mls::Session::Reset)
        .def("set_protocol_version",
            &discord::dave::mls::Session::SetProtocolVersion, nb::arg("version"))
        .def("get_protocol_version",
            &discord::dave::mls::Session::GetProtocolVersion)
        .def("get_last_epoch_authenticator",
            &discord::dave::mls::Session::GetLastEpochAuthenticator)
        .def("set_external_sender",
            &discord::dave::mls::Session::SetExternalSender, nb::arg("external_sender_package"))
        .def("process_proposals",
            &discord::dave::mls::Session::ProcessProposals, nb::arg("proposals"), nb::arg("recognized_user_ids"))
        .def("process_commit",
            &discord::dave::mls::Session::ProcessCommit, nb::arg("commit"))
        .def("process_welcome",
            &discord::dave::mls::Session::ProcessWelcome, nb::arg("welcome"), nb::arg("recognized_user_ids"))
        .def("get_marshalled_key_package",
            &discord::dave::mls::Session::GetMarshalledKeyPackage)
        .def("get_key_ratchet",
            &discord::dave::mls::Session::GetKeyRatchet, nb::arg("user_id"))
        .def("get_pairwise_fingerprint",
            &discord::dave::mls::Session::GetPairwiseFingerprint, nb::arg("version"), nb::arg("user_id"), nb::arg("callback"));
}
