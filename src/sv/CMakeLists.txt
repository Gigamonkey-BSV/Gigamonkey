add_library (sv_giga
  OBJECT
  random.cpp
)

target_link_libraries (
  sv_giga

  PUBLIC

  Data::hash

)

target_include_directories(sv_giga PUBLIC
$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

include (GNUInstallDirs)

install (DIRECTORY
  include/sv
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install (
  TARGETS sv_giga
  EXPORT sv_gigaTargets ARCHIVE
)
