
KERNEL_HEADERS=-I/repo/Pass_GPL/asuswrt/release/src-ra-openwrt-4210/router/kernel_header/include

AR=ar
RANLIB=/opt/lede-toolchain-ramips-mt7621_gcc-5.4.0_musl-1.1.24.Linux-x86_64/toolchain-mipsel_24kc_gcc-5.4.0_musl-1.1.24/bin/mipsel-openwrt-linux-musl-ranlib

CC=/opt/lede-toolchain-ramips-mt7621_gcc-5.4.0_musl-1.1.24.Linux-x86_64/toolchain-mipsel_24kc_gcc-5.4.0_musl-1.1.24/bin/mipsel-openwrt-linux-musl-gcc
CFLAGS= $(OPTCFLAGS) -Wall -g $(KERNEL_HEADERS)

prefix=
exec_prefix=${prefix}
includedir=${prefix}/include
libdir=${exec_prefix}/lib

libbridge_SOURCES= \
	libbridge_devif.c \
	libbridge_if.c \
	libbridge_init.c \
	libbridge_misc.c 

libbridge_OBJECTS=$(libbridge_SOURCES:.c=.o)

all:	libbridge.a

install: libbridge.a
	mkdir -p $(DESTDIR)$(includedir)
	install -m 644 libbridge.h $(DESTDIR)$(includedir)
	mkdir -p $(DESTDIR)$(libdir)
	install -m 644 libbridge.a $(DESTDIR)$(libdir)


clean:
	rm -f *.o libbridge.a

libbridge.a:	$(libbridge_OBJECTS)
	$(AR) rcs $@ $(libbridge_OBJECTS)
	$(RANLIB) $@

%.o: %.c libbridge.h libbridge_private.h
	$(CC) $(CFLAGS) $(INCLUDE) -c $<

libbridge_compat.o:	libbridge_compat.c if_index.c
	$(CC) $(CFLAGS) -c libbridge_compat.c
