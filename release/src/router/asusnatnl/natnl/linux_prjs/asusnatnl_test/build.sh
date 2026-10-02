#!/bin/sh

# build asus natnl shared library
rm libasusnatnl.so
cd ../../
make clean
make linux-lib
cp libasusnatnl.so linux_prjs/asusnatnl_test/libasusnatnl.so

# build asus natnl test program
cd linux_prjs/asusnatnl_test
make clean
make

var_path=`dirname "$0"`
export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:$var_path

cp libasusnatnl.so /usr/lib/
cp libasusnatnl.so /lib/
