
cmake_minimum_required (VERSION 3.1...3.14)

# Back compatibility for VERSION range
if (${CMAKE_VERSION} VERSION_LESS 3.12)
    cmake_policy (VERSION ${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION})
endif ()

include (GoogleTest)
add_executable(unit_tests 
testBase58Check.cpp
testFormat.cpp
testTimestamp.cpp
testAddress.cpp
testExpandCompact.cpp
testMerkle.cpp
testPush.cpp
testNumber.cpp
testSignature.cpp
testScript.cpp
testTransaction.cpp
testDifficulty.cpp
testWorkString.cpp
testWork.cpp
testBoost.cpp
testBip32.cpp
testBip32Derivations.cpp
testBip39.cpp
testBUMP.cpp
testBEEF.cpp
testStratum.cpp
)
target_link_libraries(unit_tests
PRIVATE gigamonkey Data::data util gtest_main gmock)
gtest_discover_tests(unit_tests)
