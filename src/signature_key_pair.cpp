#include <mls/parameters.h>

#include "binding_core.hpp"

// Thin wrapper around mlspp's SignaturePrivateKey for generating and
// serializing/deserializing said keys for storage.

// For future proofing, these methods all accept a DAVE protocol version,
// despite there currently really only being one possible version and
// CiphersuiteForProtocolVersion() returning a constant value.
// For further future proofing, load() and dump() values should
// probably be treated as opaque strings.

void bindSignatureKeyPair(nb::module_& m) {
    nb::class_<mlspp::SignaturePrivateKey>(m, "SignatureKeyPair")
        .def_static(
            "generate",
            [](dave::ProtocolVersion version) {
                auto suite = dave::mls::CiphersuiteForProtocolVersion(version);
                return std::make_shared<mlspp::SignaturePrivateKey>(
                    mlspp::SignaturePrivateKey::generate(suite)
                );
            },
            nb::arg("version")
        )
        .def_static(
            "load",
            [](dave::ProtocolVersion version, std::string data) {
                auto suite = dave::mls::CiphersuiteForProtocolVersion(version);
                return std::make_shared<mlspp::SignaturePrivateKey>(
                    mlspp::SignaturePrivateKey::from_jwk(suite, data)
                );
            },
            nb::arg("version"),
            nb::arg("data")
        )
        .def(
            "dump",
            [](const mlspp::SignaturePrivateKey& self, dave::ProtocolVersion version) {
                auto suite = dave::mls::CiphersuiteForProtocolVersion(version);
                return self.to_jwk(suite);
            },
            nb::arg("version")
        );
}
