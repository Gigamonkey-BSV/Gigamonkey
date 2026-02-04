
cmake_minimum_required (VERSION 3.1...3.14)

# Back compatibility for VERSION range
if (${CMAKE_VERSION} VERSION_LESS 3.12)
    cmake_policy (VERSION ${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION})
endif ()

include (GoogleTest)

add_executable (unit_tests
    base_58_check.cpp
    format.cpp
    timestamp.cpp
    address.cpp
    expand_compact.cpp
    Merkle.cpp
    push.cpp
    number.cpp
    signature.cpp
    script.cpp
    transaction.cpp
    difficulty.cpp
    work_string.cpp
    work.cpp
    boost.cpp
    BIP32.cpp
    BIP32Derivations.cpp
    BIP39.cpp
    BUMP.cpp
    BEEF.cpp
    SPV.cpp
    Stratum.cpp
)

target_link_libraries (
    unit_tests
    PRIVATE
    gigamonkey Data::data util gtest_main gmock
)

gtest_discover_tests (unit_tests)
