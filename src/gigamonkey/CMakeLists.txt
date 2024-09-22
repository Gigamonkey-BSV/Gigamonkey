add_library (gigamonkey STATIC
    
    p2p/var_int.cpp
    p2p/checksum.cpp
    p2p/version.cpp

    secp256k1.cpp
    timestamp.cpp
    incomplete.cpp
    sighash.cpp
    signature.cpp
    script.cpp
    
    script/instruction.cpp
    script/error.cpp
    script/config.cpp
    script/opcodes.cpp
    script/counter.cpp
    script/pattern.cpp
    script/stack.cpp
    script/interpreter.cpp
    script/machine.cpp
    script/typed_data_bip_276.cpp
    
    address.cpp
    wif.cpp
    merkle.cpp
    work.cpp
    timechain.cpp
    pay/extended.cpp
    SPV.cpp
    redeem.cpp
    
    schema/random.cpp
    schema/hd.cpp
    schema/bip_39.cpp
    schema/electrum_SV.cpp
    
    merkle/dual.cpp
    merkle/serialize.cpp
    merkle/BUMP.cpp

    pay/envelope.cpp
    pay/MAPI.cpp
    pay/SPV_envelope.cpp
    pay/BEEF.cpp
    pay/pay.cpp
    pay/ARC.cpp
    
    stratum/method.cpp
    stratum/error.cpp
    stratum/stratum.cpp
    stratum/extensions.cpp
    stratum/mining_subscribe.cpp
    stratum/mining_authorize.cpp
    stratum/mining.cpp
    stratum/mining_configure.cpp
    stratum/remote.cpp
    stratum/client_session.cpp
    stratum/server_session.cpp

    boost/boost.cpp  
)

configure_file(include/gigamonkey/version.hpp.in generated/gigamonkey/version.hpp )

target_include_directories(gigamonkey PUBLIC  $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/generated/> $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
target_include_directories (gigamonkey PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)

target_link_libraries (gigamonkey PUBLIC
nlohmann_json::nlohmann_json 
Data::data 
util
sv_giga

# boost::boost 
# openssl::openssl 
# cryptopp::cryptopp 

# gmp::gmp 
)


# Set C++ version
target_compile_features (gigamonkey PUBLIC cxx_std_20)
set_target_properties (gigamonkey PROPERTIES CXX_EXTENSIONS OFF)
target_compile_options (gigamonkey PUBLIC "-fconcepts")


include(GNUInstallDirs)
install(DIRECTORY
  include/
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)
install(TARGETS gigamonkey sv_giga nlohmann_json
EXPORT GigamonkeyTargets ARCHIVE 
)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/generated/gigamonkey/version.hpp 
DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/gigamonkey)

install(EXPORT GigamonkeyTargets
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/gigamonkey
  FILE gigamonkeyTargets.cmake
  NAMESPACE Gigamonkey::
)

include(CMakePackageConfigHelpers)
# generate the config file that includes the exports
configure_package_config_file(${CMAKE_CURRENT_SOURCE_DIR}/Config.cmake.in
  "${CMAKE_CURRENT_BINARY_DIR}/gigamonkeyConfig.cmake"
  INSTALL_DESTINATION "lib/cmake/gigamonkeyFunctions"
  NO_SET_AND_CHECK_MACRO
  NO_CHECK_REQUIRED_COMPONENTS_MACRO
  )

  write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/gigamonkeyConfigVersion.cmake"
  COMPATIBILITY AnyNewerVersion
)
install(FILES
  ${CMAKE_CURRENT_BINARY_DIR}/gigamonkeyConfig.cmake
  ${CMAKE_CURRENT_BINARY_DIR}/gigamonkeyConfigVersion.cmake
  DESTINATION lib/cmake/gigamonkey
  )

  set(CPACK_PACKAGE_VENDOR "Daniel Krawisz")
set(CPACK_PACKAGE_CONTACT "email@example.com")
set(CPACK_PACKAGE_DESCRIPTION "Gigamonkey")
include(CPack)