#!/bin/sh

# build asus natnl shared library
#rm libasusnatnl.so
#cd ../../../
#./install-nat-linux-lib.sh
#cp release/linux/libasusnatnl.so natnl/msvc_prjs/asusnatnl_test/libasusnatnl.so

# build asus natnl test program
cd natnl/msvc_prjs/asusnatnl_test
make clean
make

#cp libasusnatnl.so /usr/lib/
#cp libasusnatnl.so /lib/
