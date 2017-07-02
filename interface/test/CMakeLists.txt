cmake_minimum_required (VERSION 2.6)

if(CMAKE_VERSION VERSION_LESS "3.1")
  include(CheckCXXCompilerFlag)
  CHECK_CXX_COMPILER_FLAG("-std=c++11" COMPILER_SUPPORTS_CXX11)
  if(NOT COMPILER_SUPPORTS_CXX11)
    MESSAGE(FATAL_ERROR "Your compiler does not support c++11")
  endif()
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
else()
  set(CMAKE_CXX_STANDARD 11)
endif()

project(test_islpp)

set(ISL_INCLUDE_DIR ${ISL_PREFIX}/include)
set(ISLPP_INCLUDE_DIR ${ISL_PREFIX}/include/isl/interface)

# For OSX with brew
# set(PROTOBUF_LIB_PATH /usr/local/Cellar/)

enable_testing()
find_library(GTEST_LIB gtest HINTS $ENV{C2ISL_DIR}/third-party-install/lib)
find_library(GTEST_MAIN_LIB gtest_main HINTS $ENV{C2ISL_DIR}/third-party-install/lib)
find_library(GMOCK_LIB gmock HINTS $ENV{C2ISL_DIR}/third-party-install/lib)
set(GOOGLE_LIBS ${GTEST_LIB} ${GTEST_MAIN_LIB} ${GMOCK_LIB_LIB})

find_library(ISL_LIB isl HINTS ${ISL_PREFIX}/lib)

include_directories(${ISL_INCLUDE_DIR} ${ISLPP_INCLUDE_DIR})

add_executable(test_islpp test_islpp.cc)

target_link_libraries(test_islpp ${ISL_LIB} ${GOOGLE_LIBS})
