cmake_minimum_required(VERSION 3.1...3.14)

# Back compatibility for VERSION range
if(${CMAKE_VERSION} VERSION_LESS 3.12)
    cmake_policy(VERSION ${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION})
endif()

project(gigamonkey 	VERSION 1.0
		DESCRIPTION "open-source Bitcoin library in c++"
		LANGUAGES CXX)

# Set cmake as import path for Find*.cmake files
set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})

### Require out-of-source builds
file(TO_CMAKE_PATH "${PROJECT_BINARY_DIR}/CMakeLists.txt" LOC_PATH)
if(EXISTS "${LOC_PATH}")
    message(FATAL_ERROR "You cannot build in a source directory (or any directory with a CMakeLists.txt file). Please make a build subdirectory. Feel free to remove CMakeCache.txt and CMakeFiles.")
endif()

## Check if GTests is installed. If not, install it

option(PACKAGE_TESTS "Build the tests" ON)
if(NOT TARGET gtest_main AND PACKAGE_TESTS)
	# Download and unpack googletest at configure time
	configure_file(cmake/gtests.txt.in googletest-download/CMakeLists.txt)
	execute_process(COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
			RESULT_VARIABLE result
			WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/googletest-download )
	if(result)
		message(FATAL_ERROR "CMake step for googletest failed: ${result}")
	endif()
	execute_process(COMMAND ${CMAKE_COMMAND} --build .
			RESULT_VARIABLE result
			WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/googletest-download )
	if(result)
		message(FATAL_ERROR "Build step for googletest failed: ${result}")
	endif()

	# Prevent overriding the parent project's compiler/linker
	# settings on Windows
	set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
	
	# Add googletest directly to our build. This defines
	# the gtest and gtest_main targets.
	add_subdirectory(${CMAKE_CURRENT_BINARY_DIR}/googletest-src
			${CMAKE_CURRENT_BINARY_DIR}/googletest-build)
include(GoogleTest)

endif()

# Include libraries

# Boost settings
set(Boost_LIB_PREFIX            "lib"       CACHE STRING "")
set(Boost_USE_MULTITHREADED     ON          CACHE BOOL "") # '-mt' flag
set(Boost_USE_STATIC_LIBS       ON          CACHE BOOL "")
set(Boost_USE_STATIC_RUNTIME    OFF         CACHE BOOL "") # '-s' tag
set(Boost_USE_DEBUG_RUNTIME     OFF         CACHE BOOL "") # '-g' tag
set(Boost_COMPILER              "-mgw49"    CACHE STRING "")

# Include Boost
find_package(Boost 1.72.0 COMPONENTS system locale  REQUIRED)

if(Boost_FOUND)

    message(STATUS "Boost_INCLUDE_DIRS: ${Boost_INCLUDE_DIRS}")
    message(STATUS "Boost_LIBRARIES: ${Boost_LIBRARIES}")
    message(STATUS "Boost_VERSION: ${Boost_VERSION}")

    include_directories(${Boost_INCLUDE_DIRS})
    add_definitions("-DHAS_BOOST")

endif()

#find_package(ICU 60.2 COMPONENTS uc i18n REQUIRED)
find_package(OpenSSL REQUIRED)
message("OpenSSL include dir: ${OPENSSL_INCLUDE_DIR}")
        message("OpenSSL libraries: ${OPENSSL_LIBRARIES}")

        include_directories(${OPENSSL_INCLUDE_DIR})

# Find Crypto++
find_package(CryptoPP REQUIRED)
if(CRYPTOPP_INCLUDE_DIRS)

	message(STATUS "Crypto++ INCLUIDE DIRS: ${CRYPTOPP_INCLUDE_DIRS}")
	include_directories(${CRYPTOPP_INCLUDE_DIRS})
endif()

# Check data library
if(NOT EXISTS "${PROJECT_SOURCE_DIR}/extern/data/CMakeLists.txt")
    message(FATAL_ERROR "The submodules were not downloaded! GIT_SUBMODULE was turned off or failed. Please update submodules and try again.")
endif()

## Enable testing
include(CTest)

if(PACKAGE_TESTS)
	enable_testing()
	add_subdirectory(test)
endif()
find_package(nlohmann_json 3.2.0 REQUIRED)
if(nlohmann_json_FOUND)

	message(STATUS "nlohmann_json_INCLUDE_DIRS: ${nlohmann_json_INCLUDE_DIRS}")
	message(STATUS "nlohmann_json_LIBRARIES: ${nlohmann_json_LIBRARIES}")

endif()

add_subdirectory("${PROJECT_SOURCE_DIR}/extern/data/")
add_subdirectory("${CHAIN_SRC_ROOT}" bitcoin-sv)

add_library(gigamonkey STATIC 
    src/sv/support/cleanse.cpp
    src/sv/crypto/sha1.cpp
    src/sv/crypto/sha256.cpp
    src/sv/crypto/ripemd160.cpp
    src/sv/utilstrencodings.cpp
    src/sv/arith_uint256.cpp
    src/sv/primitives/transaction.cpp
    
    src/sv/script/interpreter.cpp
    #src/sv/uint256.cpp

    src/gigamonkey/hash.cpp
    src/gigamonkey/signature.cpp
    src/gigamonkey/script/script.cpp
    src/gigamonkey/timestamp.cpp
    src/gigamonkey/secp256k1.cpp
    src/gigamonkey/merkle.cpp
    src/gigamonkey/script.cpp
    src/gigamonkey/address.cpp
    src/gigamonkey/wif.cpp
    src/gigamonkey/timechain.cpp
    src/gigamonkey/work.cpp
    src/gigamonkey/redeem.cpp
    src/gigamonkey/schema/hd.cpp
    src/gigamonkey/schema/random.cpp
    src/gigamonkey/wallet.cpp
    src/gigamonkey/stratum/error.cpp
    src/gigamonkey/stratum/stratum.cpp
    src/gigamonkey/stratum/difficulty.cpp
    src/gigamonkey/stratum/mining_subscribe.cpp
    src/gigamonkey/stratum/mining_authorize.cpp
    src/gigamonkey/stratum/mining.cpp
    src/gigamonkey/boost/boost.cpp
)

target_link_libraries(gigamonkey PUBLIC data common util ${OPENSSL_LIBRARIES} ${CRYPTOPP_LIBRARIES} ${Boost_LIBRARIES} ${GMPXX_LIBRARY} ${GMP_LIBRARY} nlohmann_json::nlohmann_json )

target_include_directories(gigamonkey PUBLIC include)

# Set C++ version
target_compile_features(gigamonkey PUBLIC cxx_std_17)
set_target_properties(gigamonkey PROPERTIES CXX_EXTENSIONS OFF)
