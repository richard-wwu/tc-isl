        cmake_minimum_required(VERSION 2.8.2)

include(ExternalProject)

# Set default ExternalProject root directory
SET_DIRECTORY_PROPERTIES(PROPERTIES EP_PREFIX ${CMAKE_BINARY_DIR}/test/googletest)

ExternalProject_Add(
    googletest
    URL https://github.com/google/googletest/archive/release-1.8.0.tar.gz
    URL_HASH        SHA1=e7e646a6204638fe8e87e165292b8dd9cd4c36ed
    INSTALL_COMMAND ""
)

# Specify include dir
ExternalProject_Get_Property(googletest source_dir)
set(GTEST_INCLUDE_DIR ${source_dir}/include)

# Library
ExternalProject_Get_Property(googletest binary_dir)
set(GTEST_LIBRARY_PATH ${binary_dir}/${CMAKE_FIND_LIBRARY_PREFIXES}gtest.a)
add_library(GTEST_LIBRARY SHARED IMPORTED)
set_property(TARGET ${GTEST_LIBRARY} PROPERTY IMPORTED_LOCATION ${GTEST_LIBRARY_PATH} )
add_dependencies(GTEST_LIBRARY googletest)
