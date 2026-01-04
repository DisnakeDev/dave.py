#pragma once

#include <dave/mls/parameters.h>
#include <nanobind/nanobind.h>

namespace dave = discord::dave;

class SignatureKeyPair {
private:
    SignatureKeyPair(std::shared_ptr<mlspp::SignaturePrivateKey> privateKey)
        : privateKey(privateKey) {}

public:
    std::shared_ptr<mlspp::SignaturePrivateKey> privateKey;

    static SignatureKeyPair generate(dave::ProtocolVersion version);
    static SignatureKeyPair load(dave::ProtocolVersion version, const std::string& str);

    std::string dump(dave::ProtocolVersion version);
};
