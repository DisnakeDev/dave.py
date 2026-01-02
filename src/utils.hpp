#include <nanobind/nanobind.h>

#include <vector>

NAMESPACE_BEGIN(NB_NAMESPACE)

inline nanobind::bytes vector_to_bytes(const std::vector<uint8_t>& vec) {
    return nanobind::bytes(vec.data(), vec.size());
}

inline std::vector<uint8_t> bytes_to_vector(nanobind::bytes bytes) {
    const auto* ptr = static_cast<const uint8_t*>(bytes.data());
    return {ptr, ptr + bytes.size()};
}

NAMESPACE_END(NB_NAMESPACE)

// Wrapper object to safely capture refcounted objects in lambdas while the GIL is not necessarily
// being held. Basically, the only point of this is to ensure the GIL is held in the destructor.
//
// nanobind itself does something similar for function objects in the corresponding type caster:
// https://github.com/wjakob/nanobind/blob/babec16ecdc8d49239d1b9e2991db85e2b5deac6/include/nanobind/stl/function.h#L36-L41
//
// To elaborate: this is needed for the GetPairwiseFingerprint callback.
// GetPairwiseFingerprint runs a scrypt hash in a separate thread, and calls the provided callback
// from there. That's fine and all, since we can just acquire the GIL inside the callback we
// provide.
//
// Problem is, since we (need to) capture the asyncio.Future nb::object by value, it'll
// have to be decref'd when the thread exits, since the lambda gets deallocated;
// this, however, obviously happens after the GIL we acquired in the callback got released again.
// Which is not great. It's UB on stable ABI (since nanobind doesn't check if the GIL is held
// there), and abort()'s otherwise.
//
// fun. c:
struct gil_object_wrapper {
    nb::object o;

    gil_object_wrapper(nb::object o) : o(std::move(o)) {}
    gil_object_wrapper(const gil_object_wrapper&) = default;
    gil_object_wrapper(gil_object_wrapper&&) noexcept = default;

    ~gil_object_wrapper() {
        if (o.is_valid()) {
            nb::gil_scoped_acquire acquire;
            o.reset();
        }
    }

    // convenience shortcut
    const nb::object* operator->() const { return &o; }

    // prevent assignment
    gil_object_wrapper& operator=(const gil_object_wrapper) = delete;
    gil_object_wrapper& operator=(gil_object_wrapper&&) = delete;
};
