cmake_minimum_required (VERSION 3.1...3.14)

# Back compatibility for VERSION range
if (${CMAKE_VERSION} VERSION_LESS 3.12)
    cmake_policy (VERSION ${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION})
endif ()

project (gigamonkey 	VERSION 0.0.15
		DESCRIPTION "open-source Bitcoin library in c++"
		LANGUAGES CXX)

## Check if GTests is installed. If not, install it

option (PACKAGE_TESTS "Build the tests" ON)

## Enable testing

find_package (data CONFIG REQUIRED)
find_package (Boost CONFIG REQUIRED)
find_package (OpenSSL CONFIG REQUIRED)
find_package (cryptopp CONFIG REQUIRED)
find_package (nlohmann_json CONFIG REQUIRED)
find_package (gmp CONFIG REQUIRED)

if (PACKAGE_TESTS)
	include (CTest)
	find_package (GTest REQUIRED)
	enable_testing ()
	add_subdirectory (test)
endif ()

add_library (gigamonkey STATIC
    
    src/sv/random.cpp
    src/sv/big_int.cpp
    src/sv/script/script_num.cpp
    src/sv/script/script.cpp
    
    src/gigamonkey/p2p/var_int.cpp
    src/gigamonkey/p2p/checksum.cpp
    src/gigamonkey/p2p/version.cpp

    src/gigamonkey/secp256k1.cpp
    src/gigamonkey/timestamp.cpp
    src/gigamonkey/incomplete.cpp
    src/gigamonkey/sighash.cpp
    src/gigamonkey/signature.cpp
    src/gigamonkey/script.cpp
    
    src/gigamonkey/script/instruction.cpp
    src/gigamonkey/script/error.cpp
    src/gigamonkey/script/config.cpp
    src/gigamonkey/script/opcodes.cpp
    src/gigamonkey/script/counter.cpp
    src/gigamonkey/script/pattern.cpp
    src/gigamonkey/script/stack.cpp
    src/gigamonkey/script/interpreter.cpp
    src/gigamonkey/script/machine.cpp
    src/gigamonkey/script/typed_data_bip_276.cpp
    
    src/gigamonkey/address.cpp
    src/gigamonkey/wif.cpp
    src/gigamonkey/merkle.cpp
    src/gigamonkey/work.cpp
    src/gigamonkey/timechain.cpp
    src/gigamonkey/pay/extended.cpp
    src/gigamonkey/SPV.cpp
    src/gigamonkey/redeem.cpp
    
    src/gigamonkey/schema/random.cpp
    src/gigamonkey/schema/hd.cpp
    src/gigamonkey/schema/bip_39.cpp
    src/gigamonkey/schema/electrum_SV.cpp
    
    src/gigamonkey/merkle/dual.cpp
    src/gigamonkey/merkle/serialize.cpp
    src/gigamonkey/merkle/BUMP.cpp

    src/gigamonkey/pay/envelope.cpp
    src/gigamonkey/pay/MAPI.cpp
    src/gigamonkey/pay/SPV_envelope.cpp
    src/gigamonkey/pay/BEEF.cpp
    src/gigamonkey/pay/pay.cpp
    src/gigamonkey/pay/ARC.cpp
    
    src/gigamonkey/stratum/method.cpp
    src/gigamonkey/stratum/error.cpp
    src/gigamonkey/stratum/stratum.cpp
    src/gigamonkey/stratum/extensions.cpp
    src/gigamonkey/stratum/mining_subscribe.cpp
    src/gigamonkey/stratum/mining_authorize.cpp
    src/gigamonkey/stratum/mining.cpp
    src/gigamonkey/stratum/mining_configure.cpp
    src/gigamonkey/stratum/remote.cpp
    src/gigamonkey/stratum/client_session.cpp
    src/gigamonkey/stratum/server_session.cpp

    src/gigamonkey/boost/boost.cpp
    
)

target_link_libraries (gigamonkey PUBLIC
data::data 
util 
boost::boost 
openssl::openssl 
cryptopp::cryptopp 
nlohmann_json::nlohmann_json 
gmp::gmp )


target_include_directories (gigamonkey PUBLIC include)

# Set C++ version
target_compile_features (gigamonkey PUBLIC cxx_std_20)
set_target_properties (gigamonkey PROPERTIES CXX_EXTENSIONS OFF)
target_compile_options (gigamonkey PUBLIC "-fconcepts")

install (DIRECTORY include/ DESTINATION include)
install (TARGETS gigamonkey)
