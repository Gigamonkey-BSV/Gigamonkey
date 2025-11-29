cmake_minimum_required (VERSION 3.16)

if (PROJECT_SOURCE_DIR STREQUAL PROJECT_BINARY_DIR)
  message (FATAL_ERROR "In-source builds are not allowed")
endif ()

set (CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_LIST_DIR}/cmake" CACHE STRING "Modules for CMake" FORCE)

# ---------------------------------------------------------
#  Project info
# ---------------------------------------------------------
project (
  gigamonkey
  VERSION 0.0.19
  DESCRIPTION "open-source Bitcoin library in c++"
  LANGUAGES CXX
)

set (CMAKE_CXX_STANDARD 23)
set (CMAKE_CXX_STANDARD_REQUIRED ON)

# ---------------------------------------------------------
#  Build type setup (default to Debug for single-config)
# ---------------------------------------------------------
if (NOT CMAKE_CONFIGURATION_TYPES)   # True for Make/Ninja
    if (NOT CMAKE_BUILD_TYPE)
        set (CMAKE_BUILD_TYPE "Debug" CACHE STRING "Choose the build type." FORCE)
    endif ()
endif ()

# List of supported build types
set (_supported_build_types
    "Debug"
    "Release"
    "RelWithDebInfo"
    "MinSizeRel"
)

set (_build_type_descriptions
    "Debug          - For development. Enables debug symbols, sanitizers, and minimal optimization."
    "Release        - For distribution. Full optimization, no debug symbols, no assertions."
    "RelWithDebInfo - Optimized but retains debug info. Good for profiling and crash investigation."
    "MinSizeRel     - Focuses on shrinking the binary. Useful for constrained environments."
)

# ---------------------------------------------------------
#  User message explaining usage
# ---------------------------------------------------------
message (STATUS "")
message (STATUS "Build type selected: ${CMAKE_BUILD_TYPE}")
message (STATUS "To choose a different build type, configure with:")
message (STATUS "    cmake -DCMAKE_BUILD_TYPE=<type> ..")
message (STATUS "Available build types:")
foreach (line IN LISTS _build_type_descriptions)
    message (STATUS "  • ${line}")
endforeach ()
message (STATUS "")

# ---------------------------------------------------------
#  Compiler flags
# ---------------------------------------------------------

# Base flags for each type (C and C++)
set (CMAKE_C_FLAGS_RELEASE        "-O3 -DNDEBUG")
set (CMAKE_CXX_FLAGS_RELEASE      "-O3 -DNDEBUG")

set (CMAKE_C_FLAGS_RELWITHDEBINFO   "-O2 -g -DNDEBUG")
set (CMAKE_CXX_FLAGS_RELWITHDEBINFO "-O2 -g -DNDEBUG")

set (CMAKE_C_FLAGS_DEBUG        "-O1 -g3 -fno-omit-frame-pointer")
set (CMAKE_CXX_FLAGS_DEBUG      "-O1 -g3 -fno-omit-frame-pointer")

# ---------------------------------------------------------
#  Sanitizers (enabled only in Debug)
# ---------------------------------------------------------
if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    message (STATUS "Enabling sanitizers for Debug build.")

    set (_san_flags "-fsanitize=address,undefined")

    add_compile_options (${_san_flags})
    add_link_options (${_san_flags})
endif ()

# ---------------------------------------------------------
# User option: build tests
# ---------------------------------------------------------
option(PACKAGE_TESTS "Build the unit tests for this project" ON)

if (PACKAGE_TESTS)
    message (STATUS "Tests: enabled")
else ()
    message (STATUS "Tests: disabled")
endif ()

message (STATUS "To change this setting, reconfigure with:")
message (STATUS "    cmake -DPACKAGE_TESTS=ON  ..   # build tests")
message (STATUS "    cmake -DPACKAGE_TESTS=OFF ..   # skip building tests")
message (STATUS "")

# ---------------------------------------------------------
# Concepts diagnostics depth (GCC/Clang only)
# ---------------------------------------------------------
include (CheckCXXCompilerFlag)

check_cxx_compiler_flag ("-fconcepts-diagnostics-depth=20" HAS_CONCEPTS_DEPTH)

if (HAS_CONCEPTS_DEPTH)
    add_compile_options ("-fconcepts-diagnostics-depth=20")
endif ()

# ---------------------------------------------------------
# Dependencies
# ---------------------------------------------------------

find_package (Boost 1.86 COMPONENTS thread chrono log_setup log REQUIRED)
# if we do not have boost
#   * linux:
#     * go to the boost website, download and extract the latest version.
#     * `./bootstrap.sh`
#     * `./b2`
#     * `sudo ./b2 install`

add_definitions ("-DHAS_BOOST")

find_package (OpenSSL REQUIRED Crypto SSL)
# if we do not have openssl
#   * on linux, `sudo apt-get install libssl-dev`

find_package (SECP256K1 REQUIRED)
# if we do not have SECP256K1
#   * on linux
#     * go to `https://github.com/bitcoin-core/secp256k1`, download the repo, and follow the instructions.
#     * you mighht need autoconf: `sudo apt install autoconf`
#     * and libtool: `sudo apt-get install libtool-bin`

find_package (pegtl REQUIRED)
# If we do not have PegTL
#   * on linux, `sudo apt-get install tao-pegtl-dev`

find_package (PkgConfig REQUIRED)
# If we do not have PkgConfig
#   * on linux, `sudo apt-get install pkg-config`

IF (WIN32)
  pkg_check_modules (cryptopp REQUIRED IMPORTED_TARGET cryptopp)
ELSE ()
  pkg_check_modules (cryptopp REQUIRED IMPORTED_TARGET libcrypto++)
  # If we do not have crypto++, `sudo apt install libcrypto++-dev`
ENDIF ()

find_package (SECP256K1 REQUIRED)
# if we do not have SECP256K1
#   * on linux
#     * go to `https://github.com/bitcoin-core/secp256k1`, download the repo, and follow the instructions.
#     * you mighht need autoconf: `sudo apt install autoconf`
#     * and libtool: `sudo apt-get install libtool-bin`

## Enable testing
include (FetchContent)
cmake_policy (SET CMP0135 NEW)

FetchContent_Declare (json URL https://github.com/nlohmann/json/releases/download/v3.12.0/json.tar.xz)
FetchContent_MakeAvailable (json)

FetchContent_Declare (argh URL https://github.com/adishavit/argh/archive/refs/tags/v1.3.2.zip)
FetchContent_MakeAvailable (argh)

FetchContent_Declare (ctre URL https://github.com/hanickadot/compile-time-regular-expressions/archive/refs/tags/v3.10.0.zip)
FetchContent_MakeAvailable (ctre)

find_package (data CONFIG REQUIRED)

# Check if GTests is installed. If not, install it
if (PACKAGE_TESTS)
  include (CTest)
  FetchContent_Declare (
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.14.0)

  set (gtest_force_shared_crt ON CACHE BOOL "" FORCE)
  FetchContent_MakeAvailable (googletest)
  enable_testing ()
  add_subdirectory (test)
endif ()

add_subdirectory (src bin)
