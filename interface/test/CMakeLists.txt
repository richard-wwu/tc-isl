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

# Download and unpack googletest v1.8.0 (latest stable) at configure time
configure_file(gtest.cmake googletest/CMakeLists.txt)
execute_process(COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
  RESULT_VARIABLE result
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/googletest )
if(result)
  message(FATAL_ERROR "CMake step for googletest failed: ${result}")
endif()
execute_process(COMMAND ${CMAKE_COMMAND} --build .
  RESULT_VARIABLE result
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/googletest )
if(result)
  message(FATAL_ERROR "Build step for googletest failed: ${result}")
endif()
# Prevent overriding the parent project's compiler/linker
# settings on Windows
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
# Add googletest directly to our build. This defines
# the gtest and gtest_main targets.
add_subdirectory(${CMAKE_BINARY_DIR}/test/googletest/src
                 ${CMAKE_BINARY_DIR}/test/googletest/build)
# The gtest/gtest_main targets carry header search path
# dependencies automatically when using CMake 2.8.11 or
# later. Otherwise we have to add them here ourselves.
if (CMAKE_VERSION VERSION_LESS 2.8.11)
  include_directories("${gtest_SOURCE_DIR}/include")
endif()

link_directories(${CMAKE_BINARY_DIR}/test/googletest/src/googletest-build/googlemock/)
link_directories(${CMAKE_BINARY_DIR}/test/googletest/src/googletest-build/googlemock/gtest/)
set(GOOGLE_LIBS gtest gtest_main gmock gmock_main ${GFLAGS_LIBRARIES})

find_library(ISL_LIB isl HINTS ${ISL_PREFIX}/lib)

include_directories(${ISL_INCLUDE_DIR} ${ISLPP_INCLUDE_DIR})

add_executable(test_islpp test_islpp.cc)

target_link_libraries(test_islpp ${ISL_LIB} ${GOOGLE_LIBS} pthread)
