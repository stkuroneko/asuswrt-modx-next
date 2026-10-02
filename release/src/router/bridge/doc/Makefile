
DESTDIR=
KERNEL_HEADERS=-I/repo/Fail_GPL/asuswrt/release/src-ra-openwrt-4210/router/kernel_header/include

INSTALL=install -s

prefix=
exec_prefix=${prefix}
bindir=${exec_prefix}/bin
sbindir=${exec_prefix}/sbin
mandir=${prefix}/man

SUBDIRS=libbridge brctl

all:

clean:

install:
	mkdir -p $(DESTDIR)$(mandir)/man8
	install -m 644 brctl.8 $(DESTDIR)$(mandir)/man8
