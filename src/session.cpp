#include <dave/mls/session.h>

#include "binding_core.hpp"
#include "signature_key_pair.hpp"
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

void bindSession(nb::module_& m) {
    nb::enum_<RejectType>(m, "RejectType", nb::is_arithmetic(), "")
        .value("failed", RejectType::Failed, "")
        .value("ignored", RejectType::Ignored, "");

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
}
