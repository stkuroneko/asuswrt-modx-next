#!/bin/sh
# file: arm-none-eabi.sh
#
# This script downloads, compiles and installs an ARM toolchain for 
# building QCA PLC Hosted Applications;
#
# This script is my version of http://blog.tan-ce.com/gcc-bare-metal/
# charles maier <cmaier@qca.qualcomm.com>
#
# ====================================================================
# install packages;
# --------------------------------------------------------------------

apt-get install texinfo

# ====================================================================
# define folders
# --------------------------------------------------------------------

tmp=~
opt=/opt
pkg=arm-none-eabi

# ====================================================================
# define toolchain programs
# --------------------------------------------------------------------

GCC=gcc-4.7.1
BIN=binutils-2.22
GDB=gdb-7.4
LIB=newlib-1.20.0

# ====================================================================
#
# --------------------------------------------------------------------

mkdir ${tmp}/${pkg} ${opt}/${pkg}
cd ${tmp}/${pkg}
mkdir src bld

# ====================================================================
# download tools;
# --------------------------------------------------------------------

cd ${tmp}/${pkg}/src

if [ ! -f ${GCC}.tar.bz2 ]; then
	wget ftp://ftp.gnu.org/gnu/gcc/${GCC}/${GCC}.tar.bz2
	fi
if [ ! -f ${BIN}.tar.bz2 ]; then
	wget ftp://ftp.gnu.org/gnu/binutils/${BIN}.tar.bz2
	fi
if [ ! -f ${GDB}.tar.bz2 ]; then
	wget ftp://ftp.gnu.org/gnu/gdb/${GDB}.tar.bz2
	fi
if [ ! -f ${LIB}.tar.gz ]; then
	wget ftp://sources.redhat.com/pub/newlib/${LIB}.tar.gz
	fi

# ====================================================================
# unpack tools;
# --------------------------------------------------------------------

cd ${tmp}/${pkg}/src

if [ ! -d ${GCC} ]; then
	tar -xf ${GCC}.tar.bz2
	fi
if [ ! -d ${BIN} ]; then
	tar -xf ${BIN}.tar.bz2
	fi
if [ ! -d ${GDB} ]; then
	tar -xf ${GDB}.tar.bz2
	fi
if [ ! -d ${LIB} ]; then
	tar -xf ${LIB}.tar.gz
	fi

# ====================================================================
# build binutils
# --------------------------------------------------------------------

cd ${tmp}/${pkg}/bld

mkdir ${BIN}
cd ${BIN}
../../src/${BIN}/configure \
	--target=${pkg} \
	--prefix=${opt}/${pkg} \
	--enable-interwork \
	--enable-multilib
make all install

# ====================================================================
# build gcc
# --------------------------------------------------------------------

cd ${tmp}/${pkg}/bld

mkdir ${GCC}
cd ${GCC}
../../src/${GCC}/configure 
	--target=${pkg} \
	--prefix=${opt}/${pkg} \
	--enable-interwork \
	--enable-multilib \
  	--enable-languages="c,c++" \
	--with-newlib \
  	--with-headers=../../src/${LIB}/newlib/libc/include \
  	--with-system-zlib
make all-gcc install-gcc

# ====================================================================
# build newlib
# --------------------------------------------------------------------

cd ${tmp}/${pkg}/bld

mkdir ${LIB}
cd ${LIB}
../../src/${LIB}/configure \
	--target=${pkg} \
	--prefix=${opt}/${pkg} \
	--enable-interwork \
	--enable-multilib \
	--disable-newlib-supplied-syscalls
make all install

# ====================================================================
# complete gcc build
# --------------------------------------------------------------------

cd ${tmp}/${pkg}/bld/${GCC}
make all install

# ====================================================================
# build gdb
# --------------------------------------------------------------------

cd ${tmp}/${pkg}/bld

mkdir ${GDB}
cd ${GDB}
../../src/${GDB}/configure \
	--target=${pkg} \
	--prefix=${opt}/${pkg} \
	--enable-interwork \
	--enable-multilib
make all install

# ====================================================================
# export PATH
# --------------------------------------------------------------------

export PATH="$PATH:${opt}/${pkg}/bin"

