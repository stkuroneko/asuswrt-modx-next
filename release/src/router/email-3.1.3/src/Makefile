MAKE = make
VERSION = @VERSION@
SRCDIR = .
CC = /opt/lede-toolchain-ramips-mt7621_gcc-5.4.0_musl-1.1.24.Linux-x86_64/toolchain-mipsel_24kc_gcc-5.4.0_musl-1.1.24/bin/mipsel-openwrt-linux-musl-gcc
CFLAGS = -Os -Wall -I/repo/Pass_GPL/asuswrt/release/src-ra-openwrt-4210/router/mipsel-musl/stage/usr/include -I/repo/Pass_GPL/asuswrt/release/src-ra-openwrt-4210/router/nt_center/lib -I/repo/Pass_GPL/asuswrt/release/src-ra-openwrt-4210/router/sqlite -DRTCONFIG_NOTIFICATION_CENTER -Wall -W -DUSE_GNU_STRFTIME -I/repo/Pass_GPL/asuswrt/release/src-ra-openwrt-4210/router/email-3.1.3 -I/repo/Pass_GPL/asuswrt/release/src-ra-openwrt-4210/router/email-3.1.3/src -I/repo/Pass_GPL/asuswrt/release/src-ra-openwrt-4210/router/email-3.1.3/include -I../include -I/repo/Pass_GPL/asuswrt/release/src-ra-openwrt-4210/router/email-3.1.3/dlib/include -I../dlib/include -DEMAIL_VERSION='"3.1.3"' -DCOMPILE_DATE='"10/31/2010-01:13:35PM_EDT"' -DEMAIL_DIR='"/etc/email"' -DHAVE_CONFIG_H
LDFLAGS = -L/repo/Pass_GPL/asuswrt/release/src-ra-openwrt-4210/router/mipsel-musl/stage/usr/lib -L/repo/Pass_GPL/asuswrt/release/src-ra-openwrt-4210/router/nt_center/lib -L/repo/Pass_GPL/asuswrt/release/src-ra-openwrt-4210/router/sqlite/.libs
LIBS =   -lnt -lsqlite3 -lpthread -lcrypto -lssl 
DLIB = ../dlib/libdlib.a

prefix = /usr/local
bindir = ${exec_prefix}/bin
sbindir = ${exec_prefix}/sbin
mandir = ${datarootdir}/man
sysconfdir = /etc
datarootdir = ${prefix}/share

FILES = email.o addr_parse.o addy_book.o conf.o error.o execgpg.o file_io.o \
        message.o mimeutils.o processmail.o progress_bar.o \
	remotesmtp.o sig_file.o smtpcommands.o utils.o

all: $(FILES)
	$(CC) $(CFLAGS) -o email $(FILES) $(OTHER_FILES) $(DLIB) $(LDFLAGS) $(LIBS)

clean:
	rm -f *.o *.d email

clean-all:
	rm -rf Makefile *.o *.d email

