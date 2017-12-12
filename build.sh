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
UBUNTU=${TRAVIS}

if ! test ${TRAVIS}; then
    if test -z $(grep 'Debian\|Ubuntu' /etc/issue | cut -d" " -f 1); then
	PACKAGES="automake \
cmake3 \
gcc \
gcc-c++ \
git \
kernel-devel \
leveldb-devel \
lmdb-devel \
libtool \
snappy-devel"
	for p in $PACKAGES; do
            rpm -q $p > /dev/null 2>&1 || sudo yum install -q -y $p
	done
     else
    UBUNTU=1
	PACKAGES="\
build-essential \
cmake \
git \
libgoogle-glog-dev \
libgtest-dev \
automake \
libgmp3-dev \
libtool \
libyaml-dev \
realpath "
	for p in $PACKAGES; do
            dpkg-query --show $p > /dev/null 2>&1 || sudo apt-get install -q -y --no-install-recommends $p
	done
    fi
fi

CLANG_PREFIX=${CLANG_PREFIX=$(llvm-config --prefix)}
echo CLANG_PREFIX ${CLANG_PREFIX}

function install_isl() {
  mkdir -p ${ISL_DIR}/build || exit 1
  cd       ${ISL_DIR}/build || exit 1

  VERBOSE=${VERBOSE} ${CMAKE_VERSION} -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DISL_INT=gmp -DCLANG_PREFIX=${CLANG_PREFIX} -DCMAKE_INSTALL_PREFIX=${ISL_DIR}/install -DTRAVIS=${TRAVIS} ..
  VERBOSE=${VERBOSE} make -j $CORES -s || exit 1

  make install -j $CORES -s || exit 1
  echo "Successfully installed isl"
}

if ! test -z $isl || ! test -z $all; then
    install_isl
fi
