#pragma once

#include <nanobind/nanobind.h>
#include <nanobind/stl/chrono.h>
#include <nanobind/stl/function.h>
#include <nanobind/stl/map.h>
#include <nanobind/stl/optional.h>
#include <nanobind/stl/set.h>
#include <nanobind/stl/shared_ptr.h>
#include <nanobind/stl/string.h>
#include <nanobind/stl/unique_ptr.h>
#include <nanobind/stl/variant.h>
#include <nanobind/stl/vector.h>

#include <dave/version.h>

namespace nb = nanobind;

namespace dave = discord::dave;

// See https://nanobind.readthedocs.io/en/latest/refleaks.html#fixing-reference-leaks.
// This is basically meant to be a somewhat generic tp_traverse implementation to
// help out Python's GC with breaking up reference cycles, which can happen particularly
// with the (nanobind-wrapped) callback functions stored in libdave's Session and Encryptor.
#define GC_TRAVERSE(funcname, objtype, referencefunc)             \
    int funcname(PyObject* self, visitproc visit, void* arg) {    \
        Py_VISIT(Py_TYPE(self));                                  \
        if (!nb::inst_ready(self)) return 0;                      \
        auto ptr = nb::inst_ptr<objtype>(self);                   \
        for (auto& ref : referencefunc(ptr)) Py_VISIT(ref.ptr()); \
        return 0;                                                 \
    }
