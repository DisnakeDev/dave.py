#!/bin/bash -ex

_VCPKG_BINARY_PATH="./libdave/cpp/vcpkg/vcpkg"

# bootstrap vcpkg if binary doesn't already exist (in which case it was pulled from cache)
if [ -f "$_VCPKG_BINARY_PATH" ]; then
    exit 0
fi

# NOTE: regarding CMAKE_POLICY_VERSION_MINIMUM:
#   There are no prebuilt vcpkg binaries on some linux archs, so it has to build from source.
#   A dependency of vcpkg, CMakeRC, requires cmake 3.x, while the linux image used by cibw usually ships with 4.x.
#   The vcpkg authors patch the version requirement (https://github.com/microsoft/vcpkg-tool/blob/main/cmake/CMakeRC_cmake_4.patch),
#   however the patch didn't quite work up until vcpkg-tool 2025-10-10, while our/libdave's vcpkg submodule still uses 2025-06-02.
#   Until the submodule is updated, this env variable is needed.
#   See also https://github.com/apache/arrow/pull/47616#issuecomment-3387347510.
env CMAKE_POLICY_VERSION_MINIMUM=3.5 ./libdave/cpp/vcpkg/bootstrap-vcpkg.sh -disableMetrics

# copy binary to host for caching, this is only relevant in CI
if [ -n "$COPY_VCPKG_BINARY_PATH" ]; then
    cp "$_VCPKG_BINARY_PATH" "$COPY_VCPKG_BINARY_PATH"
fi
