#include <dave/mls/session.h>

#include "binding_core.hpp"
#include "utils.hpp"

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

void bindSession(nb::module_& m) {
    nb::enum_<RejectType>(m, "RejectType", nb::is_arithmetic(), "")
        .value("failed", RejectType::Failed, "")
        .value("ignored", RejectType::Ignored, "");

    nb::class_<dave::mls::Session>(m, "Session")
        .def(
            "__init__",
            [](dave::mls::Session* self, dave::mls::MLSFailureCallback callback) {
                // context and authSessionId are only used for persistent keys, which we don't
                // implement (it builds with the null/placeholder implementation, so the key store
                // would never return anything anyway)
                new (self) dave::mls::Session("", "", callback);
            },
            nb::arg("mls_failure_callback")
        )
        .def(
            "init",
            &dave::mls::Session::Init,
            nb::arg("version"),
            nb::arg("group_id"),
            nb::arg("self_user_id"),
            nb::arg("transient_key").none()
        )
        .def("reset", &dave::mls::Session::Reset)
        .def("set_protocol_version", &dave::mls::Session::SetProtocolVersion, nb::arg("version"))
        .def("get_protocol_version", &dave::mls::Session::GetProtocolVersion)
        .def(
            "get_last_epoch_authenticator",
            [](const dave::mls::Session& self) {
                return nb::vector_to_bytes(self.GetLastEpochAuthenticator());
            }
        )
        .def(
            "set_external_sender",
            [](dave::mls::Session& self, nb::bytes marshalledExternalSender) {
                return self.SetExternalSender(nb::bytes_to_vector(marshalledExternalSender));
            },
            nb::arg("external_sender_package")
        )
        .def(
            "process_proposals",
            [](dave::mls::Session& self,
               nb::bytes proposals,
               std::set<std::string> const& recognizedUserIDs) -> std::optional<nb::bytes> {
                auto res = self.ProcessProposals(nb::bytes_to_vector(proposals), recognizedUserIDs);
                if (res) return nb::vector_to_bytes(*res);
                return std::nullopt;
            },
            nb::arg("proposals"),
            nb::arg("recognized_user_ids")
        )
        .def(
            "process_commit",
            [](dave::mls::Session& self,
               nb::bytes commit) -> std::variant<RejectType, dave::RosterMap> {
                return unwrapRejection(self.ProcessCommit(nb::bytes_to_vector(commit)));
            },
            nb::arg("commit")
        )
        .def(
            "process_welcome",
            [](dave::mls::Session& self,
               nb::bytes welcome,
               std::set<std::string> const& recognizedUserIDs) {
                return self.ProcessWelcome(nb::bytes_to_vector(welcome), recognizedUserIDs);
            },
            nb::arg("welcome"),
            nb::arg("recognized_user_ids")
        )
        .def(
            "get_marshalled_key_package",
            [](dave::mls::Session& self) {
                return nb::vector_to_bytes(self.GetMarshalledKeyPackage());
            }
        )
        .def(
            "get_key_ratchet",
            &dave::mls::Session::GetKeyRatchet,
            nb::arg("user_id"),
            // explicit signature as this can return a nullptr
            nb::sig("def get_key_ratchet(self, user_id: str) -> IKeyRatchet | None")
        )
        .def(
            "get_pairwise_fingerprint",
            [](const dave::mls::Session& self, uint16_t version, std::string const& userId) {
                auto fut = nb::module_::import_("asyncio").attr("Future")();
                self.GetPairwiseFingerprint(
                    version,
                    userId,
                    [fut = gil_object_wrapper(fut)](std::vector<uint8_t> const& result) {
                        nb::gil_scoped_acquire acquire;
                        auto call_soon_threadsafe =
                            fut->attr("get_loop")().attr("call_soon_threadsafe");
                        call_soon_threadsafe(
                            fut->attr("set_result"), nb::vector_to_bytes(std::move(result))
                        );
                    }
                );
                return fut;
            },
            nb::arg("version"),
            nb::arg("user_id"),
            nb::sig(
                "def get_pairwise_fingerprint(self, version: int, user_id: str) -> "
                "asyncio.Future[bytes]"
            )
        );
}
