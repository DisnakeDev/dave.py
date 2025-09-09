#!/bin/bash -xe

CRYPTO="${CRYPTO:-boringssl}"
BUILD_DIR="$PWD/build_$CRYPTO"

cd libdave/cpp

# set up vcpkg
if [ ! -f ./vcpkg/vcpkg ]; then
    ./vcpkg/bootstrap-vcpkg.sh
fi

export CMAKE_TOOLCHAIN_FILE="$PWD/vcpkg/scripts/buildsystems/vcpkg.cmake"
export CMAKE_BUILD_PARALLEL_LEVEL="$(nproc)"

# configure
cmake -B "$BUILD_DIR" -DVCPKG_MANIFEST_DIR="./vcpkg-alts/boringssl"

# build
cmake --build "$BUILD_DIR"
