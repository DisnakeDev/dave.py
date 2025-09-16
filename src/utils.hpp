#include <nanobind/nanobind.h>
#include <vector>

NAMESPACE_BEGIN(NB_NAMESPACE)

inline nanobind::bytes vector_to_bytes(const std::vector<uint8_t>& vec) {
    return nanobind::bytes(vec.data(), vec.size());
}

inline std::vector<uint8_t> bytes_to_vector(nanobind::bytes bytes) {
  const auto* ptr = static_cast<const uint8_t *>(bytes.data());
  return {ptr, ptr + bytes.size()};
}

NAMESPACE_END(NB_NAMESPACE)
