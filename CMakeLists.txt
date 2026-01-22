cmake_minimum_required(VERSION 3.19)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Warn if the user invokes CMake directly
if (NOT SKBUILD)
  message(WARNING "\
  This CMake file is meant to be executed using 'scikit-build-core'.
  Running it directly will almost certainly not produce the desired
  result. If you are a user trying to install this package, use the
  command below, which will install all necessary build dependencies,
  compile the package in an isolated environment, and then install it.
  =====================================================================
   $ pip install .
  =====================================================================
  If you are a software developer contributing to this package,
  follow the instructions in the README instead to set up a more
  developer-friendly build environment.")
endif()


# (somewhat) configurable
set(
    LIBDAVE_CRYPTO "openssl_3"
    CACHE STRING "which crypto library to use, one of 'openssl_3', 'openssl_1.1', 'boringssl'"
)

# General build environment/toolchain setup
set(LIBDAVE_SRC_PATH ${CMAKE_CURRENT_SOURCE_DIR}/libdave/cpp)
set(VCPKG_MANIFEST_DIR "${LIBDAVE_SRC_PATH}/vcpkg-alts/${LIBDAVE_CRYPTO}" CACHE STRING "")

set(_VCPKG_TOOLCHAIN "${LIBDAVE_SRC_PATH}/vcpkg/scripts/buildsystems/vcpkg.cmake")
if (NOT EXISTS ${_VCPKG_TOOLCHAIN})
    if (DEFINED ENV{VCPKG_ROOT})
        set(_VCPKG_TOOLCHAIN "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake")
    else()
        message(FATAL_ERROR "\
        vcpkg toolchain not found.
        If you're installing from PyPI, clone https://github.com/microsoft/vcpkg
        and set the $VCPKG_ROOT environment variable to that location.
        (If you are a developer contributing to this package, ensure that
        all submodules are initialized instead).
        ")
    endif()
endif()
set(CMAKE_TOOLCHAIN_FILE ${_VCPKG_TOOLCHAIN} CACHE STRING "")
message(STATUS "Using vcpkg toolchain ${CMAKE_TOOLCHAIN_FILE}")


# Architecture-specific ~~hacks~~ target specification
if (WIN32)
    if (CMAKE_GENERATOR_PLATFORM STREQUAL "x64")
        set(VCPKG_TARGET_TRIPLET "x64-windows-static-md")
    elseif (CMAKE_GENERATOR_PLATFORM STREQUAL "ARM64")
        set(VCPKG_TARGET_TRIPLET "arm64-windows-static-md")
    else()
        message(FATAL_ERROR "unexpected platform: ${CMAKE_GENERATOR_PLATFORM}")
    endif()
endif()

# This is more of a best-effort thing and not entirely reliable.
# CMAKE_SIZEOF_VOID_P is only set after project(), which doesn't provide
# great DX considering you'd have to first wait several minutes for vcpkg deps
# to install, only to find out 32-bit systems aren't supported.
if ("${VCPKG_TARGET_TRIPLET}" STREQUAL "")
    cmake_host_system_information(RESULT IS_64BIT QUERY IS_64BIT)
    cmake_host_system_information(RESULT OS_PLATFORM QUERY OS_PLATFORM)
    # (armv8l is aarch64 running in 32-bit mode)
    if (NOT IS_64BIT OR OS_PLATFORM STREQUAL "armv8l")
        message(FATAL_ERROR "32-bit platforms are not supported.")
    endif()
endif()


project(dave LANGUAGES CXX)


# Set up python/nanobind (see also https://nanobind.readthedocs.io/en/latest/building.html)
find_package(Python REQUIRED COMPONENTS Interpreter Development.Module)

execute_process(
  COMMAND "${Python_EXECUTABLE}" -m nanobind --cmake_dir
  OUTPUT_STRIP_TRAILING_WHITESPACE OUTPUT_VARIABLE nanobind_ROOT)
find_package(nanobind CONFIG REQUIRED)

nanobind_add_module(
    _dave_impl
    src/dave.cpp
    src/decryptor.cpp
    src/encryptor.cpp
    src/session.cpp
    src/signature_key_pair.cpp
)

if (MSVC)
    target_compile_options(_dave_impl PRIVATE /W4 /WX)
else()
    target_compile_options(_dave_impl PRIVATE -Wall -pedantic -Wextra -Werror -Wconversion)
endif()


# Link libdave
add_subdirectory(${LIBDAVE_SRC_PATH} EXCLUDE_FROM_ALL)

target_include_directories(_dave_impl PRIVATE "${LIBDAVE_SRC_PATH}/src")
target_link_libraries(_dave_impl PRIVATE libdave)


# Generate typing stub, additionally storing it in src directory for type hints during development.
set(STUB_OUTPUT_PATH "${CMAKE_SOURCE_DIR}/src/dave/_dave_impl.pyi")
nanobind_add_stub(
    dave_stub
    MODULE _dave_impl
    OUTPUT ${STUB_OUTPUT_PATH}
    PYTHON_PATH $<TARGET_FILE_DIR:_dave_impl>
    DEPENDS _dave_impl
    PATTERN_FILE "${CMAKE_SOURCE_DIR}/scripts/nanobind_stub_pattern.txt"
)

# Install library and stub file in wheel
install(TARGETS _dave_impl LIBRARY DESTINATION dave)
install(FILES ${STUB_OUTPUT_PATH} DESTINATION dave)


# Add all the required licenses to built wheel
execute_process(
    COMMAND "${Python_EXECUTABLE}" "scripts/collect_licenses.py"
    "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}" "${LIBDAVE_CRYPTO}"
    COMMAND_ERROR_IS_FATAL ANY
    OUTPUT_STRIP_TRAILING_WHITESPACE OUTPUT_VARIABLE LICENSE_DATA
)
foreach(_LICENSE_DATA ${LICENSE_DATA})
    list(GET _LICENSE_DATA 0 LICENSE_NAME)
    list(GET _LICENSE_DATA 1 LICENSE_PATH)
    install(FILES ${LICENSE_PATH} DESTINATION "${SKBUILD_METADATA_DIR}/licenses" RENAME ${LICENSE_NAME})
endforeach()
