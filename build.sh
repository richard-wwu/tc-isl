#! /bin/bash
# use --clean to force total rebuild
set -ex

. flags.sh echo

clean=""
if [[ $* == *--clean* ]]
then
    echo "Forcing clean"
    clean="1"
fi

isl=""
if [[ $* == *--isl* ]]
then
    echo "Building ISL"
    isl="1"
fi

all=""
if [[ $* == *--all* ]]
then
    echo "Building ALL"
    all="1"
fi

export ISL_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

CORES=${CORES:=32}
VERBOSE=${VERBOSE:=0}
CMAKE_VERSION=${CMAKE_VERSION:="cmake3"}
DEBUG_MODE=Debug
export DBG_FLAGS=--enable-debug CFLAGS="-g" CXXFLAGS="-g"

CLANG_PREFIX=${CLANG_PREFIX=$(llvm-config --prefix)}
echo CLANG_PREFIX ${CLANG_PREFIX}

function install_isl() {
  mkdir -p ${ISL_DIR}/build || exit 1
  cd       ${ISL_DIR}/build || exit 1

  VERBOSE=${VERBOSE} ${CMAKE_VERSION} -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DISL_INT=gmp -DCLANG_PREFIX=${CLANG_PREFIX} -DCMAKE_INSTALL_PREFIX=${ISL_DIR}/install ..
  VERBOSE=${VERBOSE} make -j $CORES -s || exit 1

  make install -j $CORES -s || exit 1
  echo "Successfully installed isl"
}

if ! test -z $isl || ! test -z $all; then
    install_isl
fi
