cmake_minimum_required(VERSION 3.1...3.14)

# Back compatibility for VERSION range
if(${CMAKE_VERSION} VERSION_LESS 3.12)
    cmake_policy(VERSION ${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION})
endif()
set(CMAKE_C_COMPILER "gcc-10")
set(CMAKE_CXX_COMPILER "g++-10")
project(gigamonkey 	VERSION 1.0
		DESCRIPTION "open-source Bitcoin library in c++"
		LANGUAGES CXX)

# Set cmake as import path for Find*.cmake files
include(${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)
conan_basic_setup(TARGETS)

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



## Enable testing
include(CTest)

if(PACKAGE_TESTS)
	enable_testing()
	add_subdirectory(test)
endif()



add_library(gigamonkey STATIC
    src/sv/random.cpp
    src/sv/big_int.cpp
    src/sv/script/opcodes.cpp
    src/sv/script/script_error.cpp
    src/sv/script/script_num.cpp
    src/sv/script/script.cpp
    src/sv/config.cpp
    src/sv/script/interpreter.cpp
    
    src/gigamonkey/p2p/var_int.cpp
    src/gigamonkey/p2p/checksum.cpp
    src/gigamonkey/number.cpp
    src/gigamonkey/secp256k1.cpp
    src/gigamonkey/timestamp.cpp
    src/gigamonkey/incomplete.cpp
    src/gigamonkey/sighash.cpp
    src/gigamonkey/signature.cpp
    
    src/gigamonkey/script/instruction.cpp
    src/gigamonkey/script/script.cpp
    src/gigamonkey/script/counter.cpp
    src/gigamonkey/script/pattern.cpp
    src/gigamonkey/script/machine.cpp
    
    src/gigamonkey/address.cpp
    src/gigamonkey/wif.cpp
    src/gigamonkey/merkle.cpp
    src/gigamonkey/timechain.cpp
    src/gigamonkey/work.cpp
    src/gigamonkey/redeem.cpp
    src/gigamonkey/schema/hd.cpp
    src/gigamonkey/schema/random.cpp
    src/gigamonkey/wallet.cpp
    src/gigamonkey/spv.cpp
    src/gigamonkey/accounts.cpp
    
    src/gigamonkey/merkle/dual.cpp
    src/gigamonkey/merkle/serialize.cpp
    
    src/gigamonkey/stratum/method.cpp
    src/gigamonkey/stratum/error.cpp
    src/gigamonkey/stratum/stratum.cpp
    src/gigamonkey/stratum/extensions.cpp
    src/gigamonkey/stratum/mining_subscribe.cpp
    src/gigamonkey/stratum/mining_authorize.cpp
    src/gigamonkey/stratum/mining.cpp
    src/gigamonkey/stratum/mining_configure.cpp
    src/gigamonkey/stratum/json_bi_stream.cpp
    src/gigamonkey/stratum/remote.cpp
    src/gigamonkey/stratum/client_session.cpp
    src/gigamonkey/stratum/miner.cpp
    src/gigamonkey/stratum/server_session.cpp
    
    src/gigamonkey/boost/boost.cpp
    
    src/gigamonkey/mapi/mapi.cpp
    src/gigamonkey/mapi/envelope.cpp
    src/gigamonkey/p2p/messages/messageHeader.cpp
		src/gigamonkey/p2p/networks.cpp
		src/gigamonkey/p2p/address.cpp

        src/gigamonkey/p2p/var_util.cpp
		src/gigamonkey/p2p/var_int.cpp
		src/gigamonkey/p2p/messages/message.cpp
		src/gigamonkey/p2p/node.cpp
		src/gigamonkey/p2p/association_id.cpp
    
)

target_link_libraries(gigamonkey PUBLIC CONAN_PKG::data util CONAN_PKG::boost CONAN_PKG::openssl CONAN_PKG::cryptopp CONAN_PKG::nlohmann_json CONAN_PKG::gmp )

target_include_directories(gigamonkey PUBLIC include)

# Set C++ version
target_compile_features(gigamonkey PUBLIC cxx_std_20)
set_target_properties(gigamonkey PROPERTIES CXX_EXTENSIONS ON)
target_compile_options(gigamonkey PUBLIC "-fconcepts")

