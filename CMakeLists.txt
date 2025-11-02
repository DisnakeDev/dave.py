cmake_minimum_required(VERSION 3.18)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(LIBDAVE_SRC_PATH ${CMAKE_CURRENT_SOURCE_DIR}/libdave/cpp)

# this is probably not the proper way to do this
set(CMAKE_TOOLCHAIN_FILE ${LIBDAVE_SRC_PATH}/vcpkg/scripts/buildsystems/vcpkg.cmake CACHE STRING "")
set(VCPKG_MANIFEST_DIR ${LIBDAVE_SRC_PATH}/vcpkg-alts/boringssl CACHE STRING "")


project(dave LANGUAGES CXX)

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
  If you are a software developer, and this is your own package, then
  it is usually much more efficient to install the build dependencies
  in your environment once and use the following command that avoids
  a costly creation of a new virtual environment at every compilation:
  =====================================================================
   $ pip install nanobind scikit-build-core[pyproject]
   $ pip install --no-build-isolation -ve .
  =====================================================================
  You may optionally add -Ceditable.rebuild=true to auto-rebuild when
  the package is imported. Otherwise, you need to rerun the above
  after editing C++ files.")
endif()

find_package(
    Python
    REQUIRED COMPONENTS Interpreter Development.Module
    OPTIONAL_COMPONENTS Development.SABIModule
)
add_subdirectory(nanobind)

nanobind_add_module(_dave_impl STABLE_ABI src/dave.cpp)
nanobind_add_stub(
    dave_stub
    MODULE _dave_impl
    OUTPUT _dave_impl.pyi
    PYTHON_PATH $<TARGET_FILE_DIR:_dave_impl>
    DEPENDS _dave_impl
)
add_custom_command(
    TARGET dave_stub
    POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_BINARY_DIR}/_dave_impl.pyi ${CMAKE_CURRENT_SOURCE_DIR}/src/dave/
)

add_subdirectory(${LIBDAVE_SRC_PATH})
target_link_libraries(_dave_impl PRIVATE libdave)
install(TARGETS _dave_impl LIBRARY DESTINATION dave)
