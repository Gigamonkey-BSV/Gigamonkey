# - Try to find the GMP libraries
# This module defines:
#  GMP_FOUND             - system has GMP lib
#  GMP_INCLUDE_DIR       - the GMP include directory
#  GMP_LIBRARIES_DIR     - directory where the GMP libraries are located
#  GMP_LIBRARIES         - Link these to use GMP


function(define_imported_target library headers)
  add_library(GMP::GMP UNKNOWN IMPORTED)
  set_target_properties(GMP::GMP PROPERTIES
    IMPORTED_LOCATION ${library}
    INTERFACE_INCLUDE_DIRECTORIES ${headers}
  )
  set(GMP_FOUND 1 CACHE INTERNAL "GMP found" FORCE)
  set(GMP_LIBRARIES ${library}
      CACHE STRING "Path to gmp library" FORCE)
  set(GMP_INCLUDES ${headers}
      CACHE STRING "Path to gmp headers" FORCE)
  mark_as_advanced(FORCE GMP_LIBRARIES)
  mark_as_advanced(FORCE GMP_INCLUDES)
endfunction()

# Accepting user-provided paths and reusing cached values
if (GMP_LIBRARIES AND GMP_INCLUDES)
  define_imported_target(${GMP_LIBRARIES} ${GMP_INCLUDES})
  return()
endif()

set(QUIET_ARG)
if(GMP_FIND_QUIETLY)
  set(QUIET_ARG QUIET)
endif()

set(REQUIRED_ARG)
if(GMP_FIND_REQUIRED)
  set(REQUIRED_ARG REQUIRED)
endif()

file(TO_CMAKE_PATH "$ENV{GMP_DIR}" _GMP_DIR)

include(FindPackageHandleStandardArgs)

  find_path(GMP_INCLUDE_DIR
            NAMES gmp.h
            HINTS ENV GMP_INC_DIR
                  ENV GMP_DIR
                  $ENV{GMP_DIR}/include
            PATH_SUFFIXES include
  	        DOC "The directory containing the GMP header files"
           )

  find_library(GMP_LIBRARY_RELEASE NAMES gmp libgmp-10 gmp-10 mpir
    HINTS ENV GMP_LIB_DIR
          ENV GMP_DIR
          $ENV{GMP_DIR}/lib
    PATH_SUFFIXES lib
    DOC "Path to the Release GMP library"
    )

  find_library(GMP_LIBRARY_DEBUG NAMES gmpd gmp libgmp-10 gmp-10 mpir
    HINTS ENV GMP_LIB_DIR
          ENV GMP_DIR
          $ENV{GMP_DIR}/include
    PATH_SUFFIXES lib
    DOC "Path to the Debug GMP library"
    )

  
    if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
      set(GMP_LIBRARIES ${GMP_LIBRARY_DEBUG})
    else()
      set(GMP_LIBRARIES ${GMP_LIBRARY_RELEASE})
    endif()

  # Attempt to load a user-defined configuration for GMP if couldn't be found
  if ( NOT GMP_INCLUDE_DIR OR NOT GMP_LIBRARIES)
    include( GMPConfig OPTIONAL )
  endif()

find_package_handle_standard_args(GMP DEFAULT_MSG GMP_LIBRARIES GMP_INCLUDE_DIR)
if (GMP_FOUND)
  define_imported_target(
    "${GMP_LIBRARIES}"
    "${GMP_INCLUDE_DIR}"
  )
elseif(GMP_FIND_REQUIRED)
  message(FATAL_ERROR "Required Gmp library not found")
endif()
