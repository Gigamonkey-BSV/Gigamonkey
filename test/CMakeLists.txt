
cmake_minimum_required(VERSION 3.1...3.14)

# Back compatibility for VERSION range
if(${CMAKE_VERSION} VERSION_LESS 3.12)
    cmake_policy(VERSION ${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION})
endif()


ADD_EXECUTABLE(testGigamonkey  
testBase58.cpp 
testFormat.cpp 
testAddress.cpp
testExpandCompact.cpp
testDifficulty.cpp
testWorkString.cpp
testWork.cpp 

#testECIES.cpp 
#testWallet.cpp 
#testGenesis.cpp 

testBoost.cpp
testBip32.cpp
testBip32Derivations.cpp
testLib.cpp )
target_include_directories(testGigamonkey PUBLIC .)
target_link_libraries(testGigamonkey gmock_main gigamonkey data)
get_target_property(OUT testGigamonkey LINK_LIBRARIES)
message(STATUS ${OUT})
