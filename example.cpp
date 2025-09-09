#include <dave/version.h>
#include <nanobind/nanobind.h>


NB_MODULE(example, m) {
    m.doc() = "boop";
    m.def("MaxSupportedProtocolVersion", &discord::dave::MaxSupportedProtocolVersion, "returns version");
}
