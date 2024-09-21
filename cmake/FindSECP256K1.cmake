# - Try to find the SECP256k1 libraries
# This module defines:
#  SECP256K1_FOUND             - system has SECP256K1 lib
#  SECP256K1_INCLUDE_DIR       - the SECP256K1 include directory
#  SECP256K1_LIBRARIES_DIR     - directory where the SECP256K1 libraries are located
#  SECP256K1_LIBRARIES         - Link these to use SECP256K1

# TODO: support MacOSX

include(FindPackageHandleStandardArgs)

if(SECP256K1_INCLUDE_DIR)
  set(SECP256K1_in_cache TRUE)
else()
  set(SECP256K1_in_cache FALSE)
endif()
if(NOT SECP256K1_LIBRARIES)
  set(SECP256K1_in_cache FALSE)
endif()

# Is it already configured?
if( NOT SECP256K1_in_cache )

  find_path(SECP256K1_INCLUDE_DIR
            NAMES secp256k1.h
            HINTS ENV SECP256K1_INC_DIR
                  ENV SECP256K1_DIR
                  $ENV{SECP256K1_DIR}/include
            PATH_SUFFIXES include
  	        DOC "The directory containing the SECP256K1 header files"
           )

  find_library(SECP256K1_LIBRARY_RELEASE NAMES secp256k1
    HINTS ENV SECP256K1_LIB_DIR
          ENV SECP256K1_DIR
          $ENV{SECP256K1_DIR}/lib
    PATH_SUFFIXES lib
    DOC "Path to the Release SECP256K1 library"
    )

set(SECP256K1_LIBRARIES ${SECP256K1_LIBRARY_RELEASE})


  # Attempt to load a user-defined configuration for SECP256K1 if couldn't be found
  if ( NOT SECP256K1_INCLUDE_DIR OR NOT SECP256K1_LIBRARIES)
    include( SECP256K1Config OPTIONAL )
  endif()

endif()

find_package_handle_standard_args(SECP256K1 "DEFAULT_MSG" SECP256K1_LIBRARIES SECP256K1_INCLUDE_DIR)
