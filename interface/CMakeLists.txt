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
# Verify clang 4.0.0
################################################################################
if(NOT EXISTS ${CLANG_PREFIX}/bin/llvm-config)
  message(FATAL_ERROR "Missing: " ${CLANG_PREFIX}/bin/llvm-config)
  return()
endif()
execute_process(COMMAND ${CLANG_PREFIX}/bin/llvm-config --version
                OUTPUT_VARIABLE CLANG_VERSION)
if ((NOT CLANG_VERSION GREATER 4.0.0) AND (NOT CLANG_VERSION EQUAL 4.0.0))
  message(FATAL_ERROR  " Must use Clang >= 4.0.0, but found " ${CLANG_PREFIX}/bin/llvm-config with version " " ${CLANG_VERSION})
endif()

################################################################################
# The utter horror...
################################################################################
set(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} -fno-rtti" )

# Cleanup by looking at isl_config.h.cmake in ..
add_definitions(-DADDPATH_TAKES_4_ARGUMENTS)
add_definitions(-DCREATEPREPROCESSOR_TAKES_TUKIND)
add_definitions(-DCREATETARGETINFO_TAKES_SHARED_PTR)
#add_definitions(-DHAVE_ADT_OWNINGPTR_H)
add_definitions(-DHAVE_BASIC_DIAGNOSTICOPTIONS_H)
add_definitions(-DHAVE_LEX_PREPROCESSOROPTIONS_H)
add_definitions(-DCLANG_PREFIX="${CLANG_PREFIX}")
add_definitions(-DgetNumArgs=getNumParams)
add_definitions(-DgetArgType=getParamType)
add_definitions(-DHandleTopLevelDeclContinue=true)
add_definitions(-DHandleTopLevelDeclReturn=bool)
add_definitions(-DSETINVOCATION_TAKES_SHARED_PTR)
add_definitions(-DSETLANGDEFAULTS_TAKES_5_ARGUMENTS)
add_definitions(-DHAVE_SETMAINFILEID)


################################################################################
# Extract_interface
################################################################################
include_directories(..)
include_directories(${ISL_BINARY_DIR})
execute_process(COMMAND ${CLANG_PREFIX}/bin/llvm-config --includedir OUTPUT_VARIABLE LLVM_INCDIR OUTPUT_STRIP_TRAILING_WHITESPACE)
execute_process(COMMAND ${CLANG_PREFIX}/bin/llvm-config --libdir  OUTPUT_VARIABLE LLVM_LIBDIR OUTPUT_STRIP_TRAILING_WHITESPACE)
include_directories(${LLVM_INCDIR})
link_directories(${LLVM_LIBDIR})
add_executable(extract_interface cpp.cc extract_interface.cc generator.cc python.cc)

target_link_libraries(extract_interface isl clangFrontend clangParse clangSema clangEdit clangAnalysis clangAST clangLex clangBasic clangDriver clangSerialization clang LLVM rt dl pthread z m)

################################################################################
# Generate isl-noexceptions.h and isl.h
################################################################################
# TODO: another level or horror to make this work.. still it seems to build
execute_process(COMMAND bash "-c" "echo | ${CLANG_PREFIX}/bin/clang++ -x c++ -E -Wp,-v - 2>&1 | sed -e 's/^[^ ].*//' | uniq -u | tr '\n' ' ' | sed -e 's:\\s\\+:-I:g'"
                OUTPUT_VARIABLE SYSTEM_INCLUDES)
string(REPLACE "-I" ";-I" SYSTEM_INCLUDES ${SYSTEM_INCLUDES})
set(LIST_SYSTEM_INCLUDES ${SYSTEM_INCLUDES})

add_custom_command(
  OUTPUT isl-noexceptions.h
  DEPENDS ${CMAKE_CURRENT_LIST_DIR}/isl-noexceptions.h.top
  DEPENDS ${CMAKE_CURRENT_LIST_DIR}/isl-noexceptions.h.pre
  DEPENDS ${CMAKE_CURRENT_LIST_DIR}/all.h
  DEPENDS ${CMAKE_CURRENT_LIST_DIR}/isl-noexceptions.h.bot
  COMMAND cat ${CMAKE_CURRENT_LIST_DIR}/isl-noexceptions.h.top > isl-noexceptions.h
  COMMAND cat ${CMAKE_CURRENT_LIST_DIR}/all.h >> isl-noexceptions.h
  COMMAND cat ${CMAKE_CURRENT_LIST_DIR}/isl-noexceptions.h.pre >> isl-noexceptions.h
  COMMAND extract_interface --language=cpp-noexceptions
  -I${CMAKE_CURRENT_BINARY_DIR} -I${CMAKE_CURRENT_BINARY_DIR}/../include
  -I${CMAKE_CURRENT_LIST_DIR}/.. -I${CMAKE_CURRENT_LIST_DIR}/../include
  -I${CMAKE_CURRENT_LIST_DIR}
  ${LIST_SYSTEM_INCLUDES} -I.
  ${CMAKE_CURRENT_LIST_DIR}/all.h >> isl-noexceptions.h
  COMMAND cat ${CMAKE_CURRENT_LIST_DIR}/isl-noexceptions.h.bot >> isl-noexceptions.h
  DEPENDS extract_interface
)

add_custom_command(
  OUTPUT isl.h
  DEPENDS ${CMAKE_CURRENT_LIST_DIR}/isl.h.top
  DEPENDS ${CMAKE_CURRENT_LIST_DIR}/isl.h.pre
  DEPENDS ${CMAKE_CURRENT_LIST_DIR}/all.h
  DEPENDS ${CMAKE_CURRENT_LIST_DIR}/isl.h.bot
  COMMAND cat ${CMAKE_CURRENT_LIST_DIR}/isl.h.top > isl.h
  COMMAND cat ${CMAKE_CURRENT_LIST_DIR}/all.h >> isl.h
  COMMAND cat ${CMAKE_CURRENT_LIST_DIR}/isl.h.pre >> isl.h
  COMMAND extract_interface --language=cpp
  -I${CMAKE_CURRENT_BINARY_DIR} -I${CMAKE_CURRENT_BINARY_DIR}/../include
  -I${CMAKE_CURRENT_LIST_DIR}/.. -I${CMAKE_CURRENT_LIST_DIR}/../include
  -I${CMAKE_CURRENT_LIST_DIR}
  ${LIST_SYSTEM_INCLUDES} -I.
  ${CMAKE_CURRENT_LIST_DIR}/all.h >> isl.h
  COMMAND cat ${CMAKE_CURRENT_LIST_DIR}/isl.h.bot >> isl.h
  DEPENDS extract_interface
)

################################################################################
# Custom target for targets that depend on isl-noexceptions.h or isl.h
################################################################################
add_custom_target(generate_isl-noexceptions DEPENDS isl-noexceptions.h)
add_custom_target(generate_isl DEPENDS isl.h)

################################################################################
# isl_test_cpp-noexceptions and isl_test_cpp (no gtest yet here)
################################################################################
include_directories(${CMAKE_CURRENT_BINARY_DIR})
add_executable(isl_test_cpp-noexceptions isl_test_cpp-noexceptions.cc)
target_link_libraries(isl_test_cpp-noexceptions isl)
add_dependencies(isl_test_cpp-noexceptions generate_isl-noexceptions)
add_executable(isl_test_cpp isl_test_cpp.cc)
target_link_libraries(isl_test_cpp isl)
add_dependencies(isl_test_cpp generate_isl)

################################################################################
# Install generated interfaces isl.h and isl-noexceptions.h
################################################################################
install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR} DESTINATION include/isl FILES_MATCHING PATTERN "isl.h")
install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR} DESTINATION include/isl FILES_MATCHING PATTERN "isl-noexceptions.h")
