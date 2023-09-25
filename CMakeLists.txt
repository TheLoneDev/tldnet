cmake_minimum_required(VERSION 3.15)

project(tldnet LANGUAGES CXX VERSION 0.0.1)

set(CMAKE_CXX_STANDARD 17)
#set(CMAKE_CXX_FLAGS "-O3 -Wall -Wextra")
#set(CMAKE_CXX_FLAGS_DEBUG "-g")


add_library(tldnet INTERFACE) 
target_sources(tldnet INTERFACE include/tldnet.h)
target_include_directories(tldnet INTERFACE "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>")

# Uncomment to enable tests. Currently disabled until we had GTest as a submodule (didn't get to it lol)
#include(CTest) 
#if(BUILD_TESTING)
#    add_subdirectory(vendor/googletest)
#    include_directories(vendor/googletest/googletest/include)
#    file(GLOB TESTSRC "tests/*.cpp")
#    add_executable(tldnet_test ${TESTSRC})
#    target_link_libraries(tldnet_test gtest gtest_main)
#    target_include_directories(tldnet_test PRIVATE ${TLDNET_HEADERS})
#    include(GoogleTest)
#    gtest_discover_tests(tldnet_test)
#endif()