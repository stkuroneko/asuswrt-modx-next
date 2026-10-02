MAKE = make
VERSION = 3.1.3
SRCDIR = src/
DESTDIR = 
CC = /opt/lede-toolchain-ramips-mt7621_gcc-5.4.0_musl-1.1.24.Linux-x86_64/toolchain-mipsel_24kc_gcc-5.4.0_musl-1.1.24/bin/mipsel-openwrt-linux-musl-gcc
CFLAGS = -Os -Wall -I/repo/Pass_GPL/asuswrt/release/src-ra-openwrt-4210/router/mipsel-musl/stage/usr/include -I/repo/Pass_GPL/asuswrt/release/src-ra-openwrt-4210/router/nt_center/lib -I/repo/Pass_GPL/asuswrt/release/src-ra-openwrt-4210/router/sqlite -DRTCONFIG_NOTIFICATION_CENTER -Wall -W -DUSE_GNU_STRFTIME -I/repo/Pass_GPL/asuswrt/release/src-ra-openwrt-4210/router/email-3.1.3 -I/repo/Pass_GPL/asuswrt/release/src-ra-openwrt-4210/router/email-3.1.3/src -I/repo/Pass_GPL/asuswrt/release/src-ra-openwrt-4210/router/email-3.1.3/include -I../include -I/repo/Pass_GPL/asuswrt/release/src-ra-openwrt-4210/router/email-3.1.3/dlib/include -I../dlib/include -DEMAIL_VERSION='"3.1.3"' -DCOMPILE_DATE='"10/31/2010-01:13:35PM_EDT"' -DEMAIL_DIR='"/etc/email"' -DHAVE_CONFIG_H
LDFLAGS = -L/repo/Pass_GPL/asuswrt/release/src-ra-openwrt-4210/router/mipsel-musl/stage/usr/lib -L/repo/Pass_GPL/asuswrt/release/src-ra-openwrt-4210/router/nt_center/lib -L/repo/Pass_GPL/asuswrt/release/src-ra-openwrt-4210/router/sqlite/.libs
LIBS =   -lnt -lsqlite3 -lpthread -lcrypto -lssl 
DLIB = dlib/

prefix = /usr/local
exec_prefix = ${prefix}
bindir = ${exec_prefix}/bin
sbindir = ${exec_prefix}/sbin
mandir = ${datarootdir}/man
docdir = ${datarootdir}/doc/${PACKAGE_TARNAME}
sysconfdir = /etc
datarootdir = ${prefix}/share

bin_suffix = 

.PHONY: all clean-all clean distclean install uninstall

all:
	cd $(DLIB) && $(MAKE)
	cd $(SRCDIR) && $(MAKE)

install:
	./install.sh --bindir "$(DESTDIR)$(bindir)" --sysconfdir "$(DESTDIR)$(sysconfdir)" \
		--mandir "$(DESTDIR)$(mandir)" --binext "$(bin_suffix)" --version "$(VERSION)" \
        --docdir "$(DESTDIR)$(docdir)"

distclean:
	cd $(DLIB) && $(MAKE) clean-all
	cd $(SRCDIR) && $(MAKE) clean-all
	rm -rf Makefile config.status VERSION email.help email.1

clean:
	cd $(SRCDIR) && $(MAKE) clean
	cd $(DLIB) && $(MAKE) clean

clean-all:
	cd $(DLIB) && $(MAKE) clean-all
	cd $(SRCDIR) && $(MAKE) clean-all
	rm -rf autom4* Makefile config.status VERSION email.help email.1 configure \
	config.log configure.in

uninstall:
	./uninstall.sh --bindir "$(DEST_DIR)$(bindir)" --sysconfdir "$(DEST_DIR)$(sysconfdir)" \
	    --mandir "$(DEST_DIR)$(mandir)" --docdir "$(DEST_DIR)$(docdir)" --version "$(VERSION)"


