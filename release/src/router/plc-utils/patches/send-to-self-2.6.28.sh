#!/bin/bash
# file: patches/send-to-self-2.6.28.sh

# ====================================================================
# environment variables;
# --------------------------------------------------------------------

VERSION=2.6.28
CURRENT=9
VARIANT=send-to-self
PACKAGE=linux-source-${VERSION}
ARCHIVE=${PACKAGE}.tar.bz2
PATCH=send-to-self-2.6.26-1.diff 

# ====================================================================
# extend version string;
# --------------------------------------------------------------------

if [ ! -z ${CURRENT} ]; then
	VERSION+=.${CURRENT}
fi
if [ ! -z ${VARIANT} ]; then
	VERSION+=-${VARIANT}
fi

# ====================================================================
# install required software;
# --------------------------------------------------------------------

if [ ! -f ${ARCHIVE} ]; then
	wget http://www.ssi.bg/~ja/${PATCH}
 	apt-get install ${PACKAGE} 
#	apt-get install ${PACKAGE} --reinstall
	apt-get install binutils patch gcc g++
	apt-get install ncurses-dev
	mv /usr/src/${ARCHIVE} . 
fi

# ====================================================================
# confirm archive file exists;
# --------------------------------------------------------------------

if [ ! -f ${ARCHIVE} ]; then
	echo "File ${ARCHIVE} is missing or misplaced"
	exit 1
fi

# ====================================================================
# confirm patch file exists;
# --------------------------------------------------------------------

if [ ! -f ${PATCH} ]; then
	echo "File ${PATCH} is missing or misplaced"
	exit 1
fi

# ====================================================================
# remove old kernel source if present;
# --------------------------------------------------------------------

if [ -d ${PACKAGE} ]; then
	echo "Removing old source ..."
	rm -fr ${PACKAGE}
fi

# ====================================================================
# extract kernel source;
# --------------------------------------------------------------------

tar -vjxf ${ARCHIVE}
if [ ! -d ${PACKAGE} ]; then
	echo "Folder ${PACKAGE} does not exist"
	exit 1
fi
cd ${PACKAGE}

# ====================================================================
# patch kernel source;
# --------------------------------------------------------------------

patch -p1 < ../${PATCH}

# ====================================================================
# compile kernel source; 
# --------------------------------------------------------------------

make mrproper
make menuconfig
make 

# ====================================================================
# install kernel source; 
# --------------------------------------------------------------------

make modules_install
make install

# ====================================================================
# install kernel source; 
# --------------------------------------------------------------------

mkinitramfs -o /boot/initrd.img-${VERSION} ${VERSION}
ln -fs config-${VERSION} /boot/config
ln -fs initrd.img-${VERSION} /boot/initrd.img
ln -fs System.map-${VERSION} /boot/System.map
ln -fs vmlinuz-${VERSION} /boot/vmlinuz

