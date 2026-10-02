# Makefile for The PCI Utilities
# (c) 1998--2010 Martin Mares <mj@ucw.cz>

OPT=-O2
CFLAGS=$(OPT) -Wall -W -Wno-parentheses -Wstrict-prototypes -Wmissing-prototypes

VERSION=3.1.7
DATE=2010-01-31

# Host OS and release (override if you are cross-compiling)
HOST=
RELEASE=
CROSS_COMPILE=arm-openwrt-linux-uclibcgnueabi-

LDFLAGS=-L$(TOP)/zlib
# Support for compressed pci.ids (yes/no, default: detect)
ZLIB=

# Support for resolving ID's by DNS (yes/no, default: detect)
DNS=

# Build libpci as a shared library (yes/no; or local for testing; requires GCC)
SHARED=no

# ABI version suffix in the name of the shared library
ABI_VERSION=.3

# Installation directories
PREFIX=/usr/local
SBINDIR=$(PREFIX)/sbin
SHAREDIR=$(PREFIX)/share
IDSDIR=$(SHAREDIR)
MANDIR:=$(shell if [ -d $(PREFIX)/share/man ] ; then echo $(PREFIX)/share/man ; else echo $(PREFIX)/man ; fi)
INCDIR=$(PREFIX)/include
LIBDIR=$(PREFIX)/lib
PKGCFDIR=$(LIBDIR)/pkgconfig

# Commands
INSTALL=install
DIRINSTALL=install -d
STRIP=-s
CC=$(CROSS_COMPILE)gcc
AR=$(CROSS_COMPILE)ar
RANLIB=$(CROSS_COMPILE)ranlib

# Base name of the library (overriden on NetBSD, which has its own libpci)
LIBNAME=libpci

-include lib/config.mk

PCIINC=lib/config.h lib/header.h lib/pci.h lib/types.h lib/sysdep.h
PCIINC_INS=lib/config.h lib/header.h lib/pci.h lib/types.h

export

all: lib/$(PCILIB) 114xfwdl

lib/$(PCILIB): $(PCIINC) force
	$(MAKE) -C lib all

force:

lib/config.h lib/config.mk:
	cd lib && ./configure

114xfwdl: 114xfwdl.o config.o interctl.o pci.o xhci.o lib/$(PCILIB)


LSPCIINC=config.h interctl.h pci.h typedef.h xhci.h $(PCIINC)
114xfwdl.o: 114xfwdl.c $(LSPCIINC)
config.o: config.c $(LSPCIINC)
interctl.o: interctl.c $(LSPCIINC)
pci.o: pci.c $(LSPCIINC)
xhci.o: xhci.c $(LSPCIINC)


%: %.o
	$(CC) -I$(TOP)/zlib $(LDFLAGS) $(TARGET_ARCH) $^ $(LDLIBS) -o $@

clean:
	rm -f `find . -name "*~" -o -name "*.[oa]" -o -name "\#*\#" -o -name TAGS -o -name core -o -name "*.orig"`
	rm -f update-pciids lspci setpci example lib/config.* *.[78] pci.ids.* lib/*.pc lib/*.so lib/*.so.*
	rm -rf maint/dist

distclean: clean

install-lib: $(PCIINC_INS) lib/$(PCILIB) lib/$(PCILIBPC)
	$(DIRINSTALL) -m 755 $(DESTDIR)$(INCDIR)/pci $(DESTDIR)$(LIBDIR) $(DESTDIR)$(PKGCFDIR)
	$(INSTALL) -c -m 644 $(PCIINC_INS) $(DESTDIR)$(INCDIR)/pci
	$(INSTALL) -c -m 644 lib/$(PCILIB) $(DESTDIR)$(LIBDIR)
	$(INSTALL) -c -m 644 lib/$(PCILIBPC) $(DESTDIR)$(PKGCFDIR)
ifeq ($(SHARED),yes)
	ln -sf $(LIBNAME).so$(ABI_VERSION) $(DESTDIR)$(LIBDIR)/$(LIBNAME).so
endif


pci.ids.gz: pci.ids
	gzip -9n <$< >$@

.PHONY: all clean distclean install install-lib uninstall force
