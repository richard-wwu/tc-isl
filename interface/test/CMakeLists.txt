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

################################################################################
# Download and unpack googletest v1.8.0 (latest stable) at configure time.
################################################################################
configure_file(gtest.cmake googletest/CMakeLists.txt)
execute_process(COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
  RESULT_VARIABLE result
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/interface/test/googletest )
if(result)
  message(FATAL_ERROR "CMake step for googletest failed: ${result}")
endif()
execute_process(COMMAND ${CMAKE_COMMAND} --build .
  RESULT_VARIABLE result
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/interface/test/googletest )
if(result)
  message(FATAL_ERROR "Build step for googletest failed: ${result}")
endif()

################################################################################
# Add googletest directly to our build. This defines the gtest and gtest_main
# targets.
################################################################################
add_subdirectory(${CMAKE_BINARY_DIR}/test/googletest/src
                 ${CMAKE_BINARY_DIR}/test/googletest/build)

################################################################################
# Don't ask ... TODO: cleanup gtest
################################################################################
include_directories(${CMAKE_BINARY_DIR}/test/googletest/src/googletest/googletest/include)
link_directories(${CMAKE_BINARY_DIR}/test/googletest/src/googletest-build/googlemock/)
link_directories(${CMAKE_BINARY_DIR}/test/googletest/src/googletest-build/googlemock/gtest/)
set(GOOGLE_LIBS gtest gtest_main gmock gmock_main ${GFLAGS_LIBRARIES})

################################################################################
# test_islpp depends on
################################################################################
include_directories(${ISL_BINARY_DIR})
add_executable(test_islpp test_islpp.cc)
add_dependencies(test_islpp generate_isl-noexceptions)

target_link_libraries(test_islpp isl ${GOOGLE_LIBS} pthread)
