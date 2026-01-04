#include "signature_key_pair.hpp"

#include <dave/mls/parameters.h>

#include "binding_core.hpp"

SignatureKeyPair SignatureKeyPair::generate(dave::ProtocolVersion version) {
    auto suite = dave::mls::CiphersuiteForProtocolVersion(version);
    return {
        std::make_shared<mlspp::SignaturePrivateKey>(mlspp::SignaturePrivateKey::generate(suite))
    };
}

SignatureKeyPair SignatureKeyPair::load(dave::ProtocolVersion version, const std::string& str) {
    auto suite = dave::mls::CiphersuiteForProtocolVersion(version);
    return {std::make_shared<mlspp::SignaturePrivateKey>(
        mlspp::SignaturePrivateKey::from_jwk(suite, str)
    )};
}

std::string SignatureKeyPair::dump(dave::ProtocolVersion version) {
    auto suite = dave::mls::CiphersuiteForProtocolVersion(version);
    return privateKey->to_jwk(suite);
}

void bindSignatureKeyPair(nb::module_& m) {
    nb::class_<SignatureKeyPair>(m, "SignatureKeyPair")
        .def_static("generate", &SignatureKeyPair::generate, nb::arg("version"))
        .def_static("load", &SignatureKeyPair::load, nb::arg("version"), nb::arg("data"))
        .def("dump", &SignatureKeyPair::dump, nb::arg("version"));
}
