# -*- Makefile -*-

include ../../common.mak

top_builddir := ..
builddir     := .
top_srcdir  := ..
srcdir      := .
ksourcedir  := /repo/Fail_GPL/asuswrt/release/src-ra-openwrt-4210/linux/linux-4.4.198
prefix      := /usr
exec_prefix := ${prefix}
libdir      := /usr/lib
libexecdir  := ${exec_prefix}/libexec
xtlibdir    := /usr/lib/xtables

CC             := /opt/lede-toolchain-ramips-mt7621_gcc-5.4.0_musl-1.1.24.Linux-x86_64/toolchain-mipsel_24kc_gcc-5.4.0_musl-1.1.24/bin/mipsel-openwrt-linux-musl-gcc
CCLD           := ${CC}
CFLAGS         := -Os -DLINUX26 -DCONFIG_RALINK -DMUSL_LIBC -DDEBUG_NOISY -DDEBUG_RCTEST -D_GNU_SOURCE -D__UAPI_DEF_ETHHDR -DRALINK_DBDC_MODE -pipe -funit-at-a-time -Wno-pointer-sign -mtune=mips32 -mips32 -DLINUX_KERNEL_VERSION=263366 --sysroot=/opt/lede-toolchain-ramips-mt7621_gcc-5.4.0_musl-1.1.24.Linux-x86_64/toolchain-mipsel_24kc_gcc-5.4.0_musl-1.1.24  -U CONFIG_NVRAM_SIZE
CPPFLAGS       := 
LDFLAGS        := 
regular_CFLAGS := -Wall -Waggregate-return -Wmissing-declarations 	-Wmissing-prototypes -Wredundant-decls -Wshadow -Wstrict-prototypes 	-Winline -pipe
regular_CPPFLAGS := -D_LARGEFILE_SOURCE=1 -D_LARGE_FILES -D_FILE_OFFSET_BITS=64 -D_REENTRANT 	-DXTABLES_LIBDIR=\"${xtlibdir}\" -DXTABLES_INTERNAL
kinclude_CPPFLAGS :=  -I/repo/Fail_GPL/asuswrt/release/src-ra-openwrt-4210/linux/linux-4.4.198/include/uapi -I/repo/Fail_GPL/asuswrt/release/src-ra-openwrt-4210/linux/linux-4.4.198/include -I/repo/Fail_GPL/asuswrt/release/src-ra-openwrt-4210/linux/linux-4.4.198/include/uapi -I/repo/Fail_GPL/asuswrt/release/src-ra-openwrt-4210/linux/linux-4.4.198/include

ifneq ($(findstring CONFIG_BCM_KF_NETFILTER=, $(shell cat $(LINUXDIR)/.config)),)
CFLAGS         += -DBCM_KF_NETFILTER
endif

AM_CFLAGS      := ${regular_CFLAGS}
AM_CPPFLAGS     = ${regular_CPPFLAGS} -I${top_builddir}/include -I${top_builddir} -I${top_srcdir}/include ${kinclude_CPPFLAGS}
AM_DEPFLAGS     = -Wp,-MMD,$(@D)/.$(@F).d,-MT,$@

ifeq (${V},)
AM_LIBTOOL_SILENT = --silent
AM_VERBOSE_CC     = @echo "  CC      " $@;
AM_VERBOSE_CCLD   = @echo "  CCLD    " $@;
AM_VERBOSE_CXX    = @echo "  CXX     " $@;
AM_VERBOSE_CXXLD  = @echo "  CXXLD   " $@;
AM_VERBOSE_AR     = @echo "  AR      " $@;
AM_VERBOSE_GEN    = @echo "  GEN     " $@;
endif

#
#	Wildcard module list
#
pfx_build_mod := $(patsubst ${srcdir}/libxt_%.c,%,$(sort $(wildcard ${srcdir}/libxt_*.c)))
 pf4_build_mod := $(patsubst ${srcdir}/libipt_%.c,%,$(sort $(wildcard ${srcdir}/libipt_*.c)))
 pf6_build_mod := $(patsubst ${srcdir}/libip6t_%.c,%,$(sort $(wildcard ${srcdir}/libip6t_*.c)))
pfx_build_mod := $(filter-out ,${pfx_build_mod})
pfx_build_mod := $(filter-out layer7, ${pfx_build_mod})
ifneq ($(HND_ROUTER),y)
pfx_build_mod := $(filter-out DC, ${pfx_build_mod})
pfx_build_mod := $(filter-out layer7, ${pfx_build_mod})
pfx_build_mod := $(filter-out SKIPLOG, ${pfx_build_mod})
endif
ifeq ($(or $(OPENVPN),$(WIREGUARD)),y)
ifeq ($(findstring $(HND_ROUTER)$(PLATFORM_ROUTER), y spf11.1 ipq807x ipq60xx ipq50xx ipq40xx),)
pf6_build_mod := $(filter-out MASQUERADE, ${pf6_build_mod})
endif
endif
KERNEL_VERSION_GT_390 := $(shell expr $(LINUX_KERNEL_VERSION) \> 198909)
ifneq ($(KERNEL_VERSION_GT_390), 1)
pf6_build_mod := $(filter-out DNAT, ${pf6_build_mod})
endif

pf4_build_mod := $(filter-out webmon, ${pf4_build_mod})
pf6_build_mod := $(filter-out webmon, ${pf6_build_mod})
pf4_build_mod := $(filter-out ,${pf4_build_mod})
pf6_build_mod := $(filter-out ,${pf6_build_mod})
pfx_objs      := $(patsubst %,libxt_%.o,${pfx_build_mod})
pf4_objs      := $(patsubst %,libipt_%.o,${pf4_build_mod})
pf6_objs      := $(patsubst %,libip6t_%.o,${pf6_build_mod})
pfx_solibs    := $(patsubst %,libxt_%.so,${pfx_build_mod})
pf4_solibs    := $(patsubst %,libipt_%.so,${pf4_build_mod})
pf6_solibs    := $(patsubst %,libip6t_%.so,${pf6_build_mod})


#
# Building blocks
#
targets := libext.a libext4.a libext6.a \
           matches4.man matches6.man \
           targets4.man targets6.man
targets_install :=
# libext_objs := ${pfx_objs}
# libext4_objs := ${pf4_objs}
# libext6_objs := ${pf6_objs}
 targets += ${pfx_solibs} ${pf4_solibs} ${pf6_solibs}
 targets_install += ${pfx_solibs} ${pf4_solibs} ${pf6_solibs}

.SECONDARY:

.PHONY: all install clean distclean FORCE

#all: ${targets} check
all: ${targets}

check: ${targets}
	@echo "  CHECK    unknown symbols in .so files"; \
	. ../libxtables/libxtables.la; \
	for i in lib*.so; do \
		[ "$$i" = "lib*.so" ] && continue; \
		LD_PRELOAD="$$dlname" LD_LIBRARY_PATH=../libxtables/.libs \
			ldd -r $$i 2>&1 >/dev/null; \
	done;

install: ${targets_install}
	@mkdir -p "${DESTDIR}${xtlibdir}";
	if test -n "${targets_install}"; then install -pm0755 $^ "${DESTDIR}${xtlibdir}/"; fi;

clean:
	rm -f *.o *.oo *.so *.a {matches,targets}[46].man initext.c initext4.c initext6.c;

distclean: clean
	rm -f .*.d .*.dd;

init%.o: init%.c
	${AM_VERBOSE_CC} ${CC} ${AM_CPPFLAGS} ${AM_DEPFLAGS} ${AM_CFLAGS} -D_INIT=$*_init ${CFLAGS} -o $@ -c $<;

-include .*.d


#
#	Shared libraries
#
lib%.so: lib%.oo
	${AM_VERBOSE_CCLD} ${CCLD} ${AM_LDFLAGS} -shared ${LDFLAGS} -o $@ $< ${$*_LIBADD};

lib%.oo: ${srcdir}/lib%.c
	${AM_VERBOSE_CC} ${CC} ${AM_CPPFLAGS} ${AM_DEPFLAGS} ${AM_CFLAGS} -D_INIT=lib$*_init -DPIC -fPIC ${CFLAGS} -o $@ -c $<;

# Need the LIBADDs in iptables/Makefile.am too for libxtables_la_LIBADD
xt_RATEEST_LIBADD   = -lm
xt_statistic_LIBADD = -lm


#
#	Static bits
#
#	If static building is disabled, libext*.a will still be generated,
#	but will be empty. This is good since we can do with less case
#	handling code in the Makefiles.
#
lib%.o: ${srcdir}/lib%.c
	${AM_VERBOSE_CC} ${CC} ${AM_CPPFLAGS} ${AM_DEPFLAGS} ${AM_CFLAGS} -DNO_SHARED_LIBS=1 -D_INIT=lib$*_init ${CFLAGS} -o $@ -c $<;

libext.a: initext.o ${libext_objs}
	${AM_VERBOSE_AR} ${AR} crs $@ $^;

libext4.a: initext4.o ${libext4_objs}
	${AM_VERBOSE_AR} ${AR} crs $@ $^;

libext6.a: initext6.o ${libext6_objs}
	${AM_VERBOSE_AR} ${AR} crs $@ $^;

initext_func  := $(addprefix xt_,${pfx_build_mod})
initext4_func := $(addprefix ipt_,${pf4_build_mod})
initext6_func := $(addprefix ip6t_,${pf6_build_mod})

.initext.dd: FORCE
	@echo "${initext_func}" >$@.tmp; \
	cmp -s $@ $@.tmp || mv $@.tmp $@; \
	rm -f $@.tmp;

.initext4.dd: FORCE
	@echo "${initext4_func}" >$@.tmp; \
	cmp -s $@ $@.tmp || mv $@.tmp $@; \
	rm -f $@.tmp;

.initext6.dd: FORCE
	@echo "${initext6_func}" >$@.tmp; \
	cmp -s $@ $@.tmp || mv $@.tmp $@; \
	rm -f $@.tmp;

initext.c: .initext.dd
	${AM_VERBOSE_GEN}
	@( \
	echo "" >$@; \
	for i in ${initext_func}; do \
		echo "extern void lib$${i}_init(void);" >>$@; \
	done; \
	echo "void init_extensions(void);" >>$@; \
	echo "void init_extensions(void)" >>$@; \
	echo "{" >>$@; \
	for i in ${initext_func}; do \
		echo  " ""lib$${i}_init();" >>$@; \
	done; \
	echo "}" >>$@; \
	);

initext4.c: .initext4.dd
	${AM_VERBOSE_GEN}
	@( \
	echo "" >$@; \
	for i in ${initext4_func}; do \
		echo "extern void lib$${i}_init(void);" >>$@; \
	done; \
	echo "void init_extensions4(void);" >>$@; \
	echo "void init_extensions4(void)" >>$@; \
	echo "{" >>$@; \
	for i in ${initext4_func}; do \
		echo  " ""lib$${i}_init();" >>$@; \
	done; \
	echo "}" >>$@; \
	);

initext6.c: .initext6.dd
	${AM_VERBOSE_GEN}
	@( \
	echo "" >$@; \
	for i in ${initext6_func}; do \
		echo "extern void lib$${i}_init(void);" >>$@; \
	done; \
	echo "void init_extensions6(void);" >>$@; \
	echo "void init_extensions6(void)" >>$@; \
	echo "{" >>$@; \
	for i in ${initext6_func}; do \
		echo " ""lib$${i}_init();" >>$@; \
	done; \
	echo "}" >>$@; \
	);

#
#	Manual pages
#
ex_matches = $(shell echo ${1} | LC_ALL=POSIX grep -Eo '\b[[:lower:][:digit:]_]+\b')
ex_targets = $(shell echo ${1} | LC_ALL=POSIX grep -Eo '\b[[:upper:][:digit:]_]+\b')
man_run    = \
	${AM_VERBOSE_GEN} \
	for ext in $(sort ${1}); do \
		f="${srcdir}/libxt_$$ext.man"; \
		cf="${srcdir}/libxt_$$ext.c"; \
		if [ -f "$$f" ] && grep -Eq "$(3)|NFPROTO_UNSPEC" "$$cf"; then \
			echo -e "\t+ $$f" >&2; \
			echo ".SS $$ext"; \
			cat "$$f" || exit $$?; \
			continue; \
		fi; \
		f="${srcdir}/lib$(2)t_$$ext.man"; \
		if [ -f "$$f" ]; then \
			echo -e "\t+ $$f" >&2; \
			echo ".SS $$ext"; \
			cat "$$f" || exit $$?; \
			continue; \
		fi; \
	done >$@;

matches4.man: .initext.dd .initext4.dd $(wildcard ${srcdir}/lib*.man)
	$(call man_run,$(call ex_matches,${pfx_build_mod} ${pf4_build_mod}),ip,NFPROTO_IPV4)

matches6.man: .initext.dd .initext6.dd $(wildcard ${srcdir}/lib*.man)
	$(call man_run,$(call ex_matches,${pfx_build_mod} ${pf6_build_mod}),ip6,NFPROTO_IPV6)

targets4.man: .initext.dd .initext4.dd $(wildcard ${srcdir}/lib*.man)
	$(call man_run,$(call ex_targets,${pfx_build_mod} ${pf4_build_mod}),ip,NFPROTO_IPV4)

targets6.man: .initext.dd .initext6.dd $(wildcard ${srcdir}/lib*.man)
	$(call man_run,$(call ex_targets,${pfx_build_mod} ${pf6_build_mod}),ip6,NFPROTO_IPV6)
