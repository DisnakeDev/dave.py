cmake_minimum_required(VERSION 3.18)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(LIBDAVE_SRC_PATH ${CMAKE_CURRENT_SOURCE_DIR}/libdave/cpp)

# this is probably not the proper way to do this
set(CMAKE_TOOLCHAIN_FILE ${LIBDAVE_SRC_PATH}/vcpkg/scripts/buildsystems/vcpkg.cmake CACHE STRING "")
set(VCPKG_MANIFEST_DIR ${LIBDAVE_SRC_PATH}/vcpkg-alts/openssl_3 CACHE STRING "")


project(example LANGUAGES CXX)

find_package(Python COMPONENTS Interpreter Development.Module REQUIRED)
add_subdirectory(nanobind)

nanobind_add_module(example example.cpp)
nanobind_add_stub(
    example_stub
    MODULE example
    OUTPUT example.pyi
    PYTHON_PATH $<TARGET_FILE_DIR:example>
    DEPENDS example
)

add_subdirectory(${LIBDAVE_SRC_PATH})
# find_package(libdave CONFIG REQUIRED)
target_link_libraries(example PRIVATE libdave)
