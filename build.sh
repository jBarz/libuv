#!/bin/bash -x

echo "Configure"
export CC=/bin/xlc
export PATH=/u/jenkins/buildtools/bin:/bin
./autogen.sh
./configure --enable-shared=no --enable-static=yes

echo "Build..."
gmake V=1
gmake V=1 test/run-tests

echo "Run..."
export EXE_PATH=$PWD/test/run-tests
export UV_TAP_OUTPUT=1
./test/run-tests
