#!/usr/bin/env bash

set -ex

CORES=${CORES:=CORES}

rm -Rf build && mkdir -p build && cd build
VERBOSE=1 cmake -DISL_INT=gmp -DCLANG_PREFIX=/tmp/clang+llvm/ -DCMAKE_INSTALL_PREFIX=/tmp/install -DTRAVIS=true ..
VERBOSE=1 make -j ${CORES}
make install
