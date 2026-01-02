cmake_minimum_required(VERSION 3.18)

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

set(LIBDAVE_SRC_PATH ${CMAKE_CURRENT_SOURCE_DIR}/libdave/cpp)

# this is probably not the proper way to do this
set(CMAKE_TOOLCHAIN_FILE ${LIBDAVE_SRC_PATH}/vcpkg/scripts/buildsystems/vcpkg.cmake CACHE STRING "")
set(VCPKG_MANIFEST_DIR ${LIBDAVE_SRC_PATH}/vcpkg-alts/openssl_3 CACHE STRING "")

if (WIN32)
    if (CMAKE_GENERATOR_PLATFORM STREQUAL "x64")
        set(VCPKG_TARGET_TRIPLET "x64-windows-static-md")
    elseif (CMAKE_GENERATOR_PLATFORM STREQUAL "ARM64")
        set(VCPKG_TARGET_TRIPLET "arm64-windows-static-md")
    else()
        message(FATAL_ERROR "unexpected platform: ${CMAKE_GENERATOR_PLATFORM}")
    endif()
endif()

cmake_host_system_information(RESULT PLATFORM QUERY OS_PLATFORM)
if (PLATFORM STREQUAL "armv8l")
    # vcpkg doesn't seem to understand armv8l (i.e. aarch64 running in 32-bit mode),
    # it only knows aarch64 and armv7l, so we must explicitly tell it what we're building
    set(VCPKG_TARGET_TRIPLET "arm-linux")
endif()

set(CMAKE_POSITION_INDEPENDENT_CODE ON)


project(dave LANGUAGES CXX)

find_package(
    Python
    REQUIRED COMPONENTS Interpreter Development.Module
    OPTIONAL_COMPONENTS Development.SABIModule
)

# Find (and load) nanobind, see https://nanobind.readthedocs.io/en/latest/building.html#finding-nanobind
execute_process(
  COMMAND "${Python_EXECUTABLE}" -m nanobind --cmake_dir
  OUTPUT_STRIP_TRAILING_WHITESPACE OUTPUT_VARIABLE nanobind_ROOT)
find_package(nanobind CONFIG REQUIRED)

nanobind_add_module(_dave_impl STABLE_ABI src/dave.cpp)

add_subdirectory(${LIBDAVE_SRC_PATH})
target_link_libraries(_dave_impl PRIVATE libdave)

# Generate typing stub, additionally storing it in src directory for type hints during development.
# If we ever add other dependencies, this will have to be gated by if(SKBUILD)
set(STUB_OUTPUT_PATH "${CMAKE_SOURCE_DIR}/src/dave/_dave_impl.pyi")
nanobind_add_stub(
    dave_stub
    MODULE _dave_impl
    OUTPUT ${STUB_OUTPUT_PATH}
    PYTHON_PATH $<TARGET_FILE_DIR:_dave_impl>
    DEPENDS _dave_impl
)

# install library and stub file in wheel
install(TARGETS _dave_impl LIBRARY DESTINATION dave)
install(FILES ${STUB_OUTPUT_PATH} DESTINATION dave)
