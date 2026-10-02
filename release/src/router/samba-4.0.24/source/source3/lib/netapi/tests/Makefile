KRB5LIBS=
LDAP_LIBS=
LIBS=-lresolv -lrt -lpthread -lnetapi -ltdb -ltalloc
DEVELOPER_CFLAGS=-DDEBUG_PASSWORD -DDEVELOPER -g -Wall -Wshadow -Wpointer-arith -Wcast-align -Wwrite-strings
CCFLAGS=-I../ -L../../../bin  -I../lib/zlib -DLINUX26 -DCONFIG_RALINK -DMUSL_LIBC -DDEBUG_NOISY -DDEBUG_RCTEST -D_GNU_SOURCE -D__UAPI_DEF_ETHHDR -DRALINK_DBDC_MODE -pipe -funit-at-a-time -Wno-pointer-sign -mtune=mips32 -mips32 -DLINUX_KERNEL_VERSION=263366 --sysroot=/opt/lede-toolchain-ramips-mt7621_gcc-5.4.0_musl-1.1.24.Linux-x86_64/toolchain-mipsel_24kc_gcc-5.4.0_musl-1.1.24 -Os -ffunction-sections -fdata-sections -DMAX_DEBUG_LEVEL=-1 -Wl,-z,relro,-z,now -D_REENTRANT -D_POSIX_PTHREAD_SEMANTICS $(FLAGS) -D_SAMBA_BUILD_=3 $(GTK_FLAGS)
CC=/opt/lede-toolchain-ramips-mt7621_gcc-5.4.0_musl-1.1.24.Linux-x86_64/toolchain-mipsel_24kc_gcc-5.4.0_musl-1.1.24/bin/mipsel-openwrt-linux-musl-gcc
PICFLAG=-fPIC
LDFLAGS= -ffunction-sections -fdata-sections -Wl,--gc-sections -L./bin
DYNEXP=-Wl,--export-dynamic
NETAPI_LIBS=$(LIBS) $(KRB5LIBS) $(LDAP_LIBS)
CMDLINE_LIBS=$(NETAPI_LIBS) $(POPT_OBJ)

# Compile a source file.
COMPILE_CC = $(CC) -I. $(CCFLAGS) $(PICFLAG) -c $< -o $@
COMPILE = $(COMPILE_CC)

PROGS = bin/netapitest

all: $(PROGS)

MAKEDIR = || exec false; \
	  if test -d "$$dir"; then :; else \
	  echo mkdir "$$dir"; \
	  mkdir -p "$$dir" >/dev/null 2>&1 || \
	  test -d "$$dir" || \
	  mkdir "$$dir" || \
	  exec false; fi || exec false

BINARY_PREREQS = bin/.dummy

bin/.dummy:
	@if (: >> $@ || : > $@) >/dev/null 2>&1; then :; else \
	  dir=bin $(MAKEDIR); fi
	@: >> $@ || : > $@ # what a fancy emoticon!

.c.o:
	@if (: >> $@ || : > $@) >/dev/null 2>&1; then rm -f $@; else \
	 dir=`echo $@ | sed 's,/[^/]*$$,,;s,^$$,.,'` $(MAKEDIR); fi
	@echo Compiling $*.c
	@$(COMPILE) && exit 0;\
		echo "The following command failed:" 1>&2;\
		echo "$(COMPILE_CC)" 1>&2;\
		$(COMPILE_CC) >/dev/null 2>&1

CMDLINE_OBJ = common.o
NETAPIBUFFER_OBJ = netapibuffer.o
NETAPITEST_OBJ = netapitest.o netlocalgroup.o netuser.o netgroup.o netdisplay.o netshare.o netfile.o netserver.o $(CMDLINE_OBJ)

bin/netapitest: $(BINARY_PREREQS) $(NETAPITEST_OBJ)
	@echo Linking $@
	@$(CC) $(CCFLAGS) -o $@ $(NETAPITEST_OBJ) $(LDFLAGS) $(DYNEXP) $(CMDLINE_LIBS)

clean:
	-rm -f $(PROGS)
	-rm -f core */*~ *~ \
		*/*.o */*/*.o */*/*/*.o

