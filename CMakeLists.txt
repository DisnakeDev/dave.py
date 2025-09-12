cmake_minimum_required(VERSION 3.18)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(LIBDAVE_SRC_PATH ${CMAKE_CURRENT_SOURCE_DIR}/libdave/cpp)

# this is probably not the proper way to do this
set(CMAKE_TOOLCHAIN_FILE ${LIBDAVE_SRC_PATH}/vcpkg/scripts/buildsystems/vcpkg.cmake CACHE STRING "")
set(VCPKG_MANIFEST_DIR ${LIBDAVE_SRC_PATH}/vcpkg-alts/openssl_3 CACHE STRING "")


project(libdave.py LANGUAGES CXX)

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

find_package(Python COMPONENTS Interpreter Development.Module REQUIRED)
add_subdirectory(nanobind CONFIG REQUIRED)

nanobind_add_module(libdave.py STABLE_ABI libdave.py/python_bindings.cpp)
nanobind_add_stub(
    libdave_stub
    MODULE libdave.py
    OUTPUT __init__.pyi
    PYTHON_PATH $<TARGET_FILE_DIR:libdave.py>
    DEPENDS libdave.py
)
add_custom_command(
    TARGET libdave_stub
    POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_BINARY_DIR}/__init__.pyi ${CMAKE_CURRENT_SOURCE_DIR}/
)

add_subdirectory(${LIBDAVE_SRC_PATH})
# find_package(libdave CONFIG REQUIRED)
target_link_libraries(libdave.py PRIVATE libdave)
install(TARGETS libdave.py LIBRARY DESTINATION ${CMAKE_CURRENT_SOURCE_DIR}/)