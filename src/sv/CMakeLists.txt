add_library (sv_giga
  OBJECT
  random.cpp
)

target_link_libraries (
  sv_giga

  PUBLIC

  Data::sv

)

target_include_directories(sv_giga PUBLIC
$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)


add_library(sv_interface INTERFACE)

target_include_directories(sv_interface INTERFACE
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

target_link_libraries(sv_interface INTERFACE Data::sv)

# Object library for compiled code
add_library(sv_giga OBJECT
  random.cpp
)

target_link_libraries(sv_giga PUBLIC sv_interface)


include (GNUInstallDirs)

install (DIRECTORY
  include/sv
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install (
  TARGETS sv_giga
  EXPORT sv_gigaTargets ARCHIVE
)
