
cmake_minimum_required(VERSION 3.1...3.14)

# Back compatibility for VERSION range
if(${CMAKE_VERSION} VERSION_LESS 3.12)
    cmake_policy(VERSION ${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION})
endif()


ADD_EXECUTABLE(testGigamonkey  
testFormat.cpp 
testAddress.cpp
testExpandCompact.cpp
testDifficulty.cpp
testWorkString.cpp
testWork.cpp 
#testGenesis.cpp 
testBoost.cpp
testLib.cpp )
target_include_directories(testGigamonkey PUBLIC .)
target_link_libraries(testGigamonkey gmock_main gigamonkey data ${LIB_BITCOIN_LIBRARIES} ${CRYPTOPP_LIBRARIES} ${Boost_LIBRARIES} ${GMPXX_LIBRARY} ${GMP_LIBRARY})
get_target_property(OUT testGigamonkey LINK_LIBRARIES)
message(STATUS ${OUT})
