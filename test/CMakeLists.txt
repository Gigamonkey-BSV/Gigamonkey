
cmake_minimum_required(VERSION 3.1...3.14)

# Back compatibility for VERSION range
if(${CMAKE_VERSION} VERSION_LESS 3.12)
    cmake_policy(VERSION ${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION})
endif()

macro(package_add_test TESTNAME)
    # create an exectuable in which the tests will be stored
    add_executable(${TESTNAME} ${ARGN})
    # link the Google test infrastructure, mocking library, and a default main fuction to
    # the test executable.  Remove g_test_main if writing your own main function.
    target_include_directories(${TESTNAME} PUBLIC .)
    target_link_libraries(${TESTNAME} gmock_main gigamonkey data gtest_main)
    # gtest_discover_tests replaces gtest_add_tests,
    # see https://cmake.org/cmake/help/v3.10/module/GoogleTest.html for more options to pass to it
    
    gtest_discover_tests(${TESTNAME}
        # set a working directory so your project root so that you can find test data via paths relative to the project root
        SOURCES ${ARGN}
        WORKING_DIRECTORY ${PROJECT_DIR}
        PROPERTIES VS_DEBUGGER_WORKING_DIRECTORY "${PROJECT_DIR}"
    )
    set_target_properties(${TESTNAME} PROPERTIES FOLDER tests)
endmacro()

package_add_test(testBase58 testBase58.cpp)
package_add_test(testFormat testFormat.cpp)
package_add_test(testTimestamp testTimestamp.cpp)
package_add_test(testAddress testAddress.cpp)
package_add_test(testExpandCompact testExpandCompact.cpp)
package_add_test(testMerkle testMerkle.cpp)
#package_add_test(testGenesis testGenesis.cpp)
package_add_test(testDifficulty testDifficulty.cpp)
package_add_test(testWorkString testWorkString.cpp)
package_add_test(testWork testWork.cpp)
package_add_test(testBoost testBoost.cpp)
package_add_test(testBip32 testBip32.cpp)
package_add_test(testBip32Derivations testBip32Derivations.cpp)
package_add_test(testBip39 testBip39.cpp)
package_add_test(testStratum testStratum.cpp)
#package_add_test(testRPC testRPC.cpp)
