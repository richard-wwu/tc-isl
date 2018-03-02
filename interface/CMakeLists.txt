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
