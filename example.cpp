#include <dave/version.h>
#include <pybind11/pybind11.h>

namespace py = pybind11;

PYBIND11_MODULE(example, m, py::mod_gil_not_used()) {
    m.doc() = "boop";
    m.def("MaxSupportedProtocolVersion", &discord::dave::MaxSupportedProtocolVersion, "returns version");
}
