
cmake_minimum_required(VERSION 3.1...3.14)

# Back compatibility for VERSION range
if(${CMAKE_VERSION} VERSION_LESS 3.12)
    cmake_policy(VERSION ${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION})
endif()



package_add_test(testP2P testP2p.cpp)
package_add_test(testVersionPayload testVersionPayload.cpp)
package_add_test(testMessage testMessage.cpp)
package_add_test(testNode testNode.cpp)
package_add_test(testAddresses testAddresses.cpp)

