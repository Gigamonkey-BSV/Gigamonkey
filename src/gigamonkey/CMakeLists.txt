
add_library (base58_check STATIC)
add_library (numbers STATIC)
add_library (gigamonkey_secp256k1 STATIC)
add_library (Merkle STATIC)
add_library (gigamonkey STATIC)
add_library (Stratum STATIC)

add_library (Gigamonkey::base58_check ALIAS base58_check)
add_library (Gigamonkey::numbers ALIAS numbers)
add_library (Gigamonkey::secp256k1 ALIAS gigamonkey_secp256k1)
add_library (Gigamonkey::Merkle ALIAS Merkle)
add_library (Gigamonkey::gigamonkey ALIAS gigamonkey)
add_library (Gigamonkey::Stratum ALIAS Stratum)

set_target_properties (base58_check PROPERTIES
  OUTPUT_NAME "gigamonkey_base58_check"
)

set_target_properties (numbers PROPERTIES
  OUTPUT_NAME "gigamonkey_numbers"
)

set_target_properties (gigamonkey_secp256k1 PROPERTIES
  OUTPUT_NAME "gigamonkey_secp256k1"
)

set_target_properties (Merkle PROPERTIES
  OUTPUT_NAME "gigamonkey_Merkle"
)

set_target_properties (gigamonkey PROPERTIES
  OUTPUT_NAME "gigamonkey_gigamonkey"
)

set_target_properties (Stratum PROPERTIES
  OUTPUT_NAME "gigamonkey_Stratum"
)

target_sources (
  base58_check

  PRIVATE

  p2p/var_int.cpp
  p2p/checksum.cpp
  p2p/version.cpp

)

target_include_directories (
  base58_check
  PUBLIC  $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/generated/>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)

target_compile_features (base58_check PUBLIC cxx_std_23)
set_target_properties (base58_check PROPERTIES CXX_EXTENSIONS OFF)

target_link_libraries (
  base58_check

  PUBLIC

  Data::numbers
)

target_sources (
  gigamonkey_secp256k1

  PRIVATE

  secp256k1.cpp

)

target_include_directories (
  gigamonkey_secp256k1
  PUBLIC  $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/generated/>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)

target_link_libraries (
  gigamonkey_secp256k1

  PUBLIC

  Data::numbers

  secp256k1
)

# Set C++ version
target_compile_features (gigamonkey_secp256k1 PUBLIC cxx_std_23)
set_target_properties (gigamonkey_secp256k1 PROPERTIES CXX_EXTENSIONS OFF)

target_sources (
  numbers

  PRIVATE

  numbers.cpp
)

target_include_directories (
  numbers
  PUBLIC  $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/generated/>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)

target_link_libraries (
  numbers

  PUBLIC

  Data::numbers
)

# Set C++ version
target_compile_features (numbers PUBLIC cxx_std_23)
set_target_properties (numbers PROPERTIES CXX_EXTENSIONS OFF)

target_sources (
  Merkle

  PRIVATE

  merkle.cpp

  merkle/dual.cpp
  merkle/serialize.cpp
  merkle/BUMP.cpp
)

target_include_directories (
  Merkle
  PUBLIC  $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/generated/>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)

target_link_libraries (
  Merkle

  PUBLIC

  Data::numbers
  nlohmann_json::nlohmann_json
)

# Set C++ version
target_compile_features (Merkle PUBLIC cxx_std_23)
set_target_properties (Merkle PROPERTIES CXX_EXTENSIONS OFF)

target_sources (
  gigamonkey

  PRIVATE
    
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
  timechain.cpp
  work.cpp
  pay/extended.cpp
  SPV.cpp
  redeem.cpp
    
  schema/random.cpp
  schema/hd.cpp
  schema/bip_39.cpp
  schema/electrum_SV.cpp

  pay/envelope.cpp
  pay/MAPI.cpp
  pay/SPV_envelope.cpp
  pay/BEEF.cpp
  pay/pay.cpp
  pay/ARC.cpp

  boost/boost.cpp
)

configure_file (include/gigamonkey/version.hpp.in generated/gigamonkey/version.hpp)

target_include_directories (
  gigamonkey
  PUBLIC  $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/generated/>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)

target_link_libraries (
  gigamonkey

  PUBLIC

  Gigamonkey::Merkle
  Gigamonkey::base58_check
  Gigamonkey::secp256k1
  Gigamonkey::numbers
  Data::crypto
  Data::net
  Data::data
  nlohmann_json::nlohmann_json
  PkgConfig::cryptopp
  util
  sv_giga

)

# Set C++ version
target_compile_features (gigamonkey PUBLIC cxx_std_23)
set_target_properties (gigamonkey PROPERTIES CXX_EXTENSIONS OFF)
target_compile_options (gigamonkey PUBLIC "-fconcepts")

target_sources (
  Stratum

  PRIVATE

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
)

target_include_directories (
  Stratum
  PUBLIC  $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/generated/>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)

target_link_libraries (
  Stratum

  PUBLIC

  Gigamonkey::gigamonkey
  Data::numbers
  nlohmann_json::nlohmann_json
)

# Set C++ version
target_compile_features (Stratum PUBLIC cxx_std_23)
set_target_properties (Stratum PROPERTIES CXX_EXTENSIONS OFF)

include (GNUInstallDirs)

# copy include directory into install destination
install (
  DIRECTORY include/
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install (
  TARGETS Stratum gigamonkey Merkle numbers gigamonkey_secp256k1 base58_check sv_giga nlohmann_json
  EXPORT GigamonkeyTargets
  ARCHIVE
)

install (
  FILES ${CMAKE_CURRENT_BINARY_DIR}/generated/gigamonkey/version.hpp
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/gigamonkey
)

install (
  EXPORT GigamonkeyTargets
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/gigamonkey
  FILE gigamonkeyTargets.cmake
  NAMESPACE Gigamonkey::
)

include (CMakePackageConfigHelpers)

# generate the config file that includes the exports
configure_package_config_file (
  ${CMAKE_CURRENT_SOURCE_DIR}/Config.cmake.in
  "${CMAKE_CURRENT_BINARY_DIR}/gigamonkeyConfig.cmake"
  INSTALL_DESTINATION "lib/cmake/gigamonkeyFunctions"
  NO_SET_AND_CHECK_MACRO
  NO_CHECK_REQUIRED_COMPONENTS_MACRO
)

write_basic_package_version_file (
  "${CMAKE_CURRENT_BINARY_DIR}/gigamonkeyConfigVersion.cmake"
  COMPATIBILITY AnyNewerVersion
)

install (FILES
  ${CMAKE_CURRENT_BINARY_DIR}/gigamonkeyConfig.cmake
  ${CMAKE_CURRENT_BINARY_DIR}/gigamonkeyConfigVersion.cmake
  DESTINATION lib/cmake/gigamonkey
)

set (CPACK_PACKAGE_VENDOR "Daniel Krawisz")
#set(CPACK_PACKAGE_CONTACT "email@example.com")
set (CPACK_PACKAGE_DESCRIPTION "Gigamonkey")
include (CPack)
