#
# Makefile for ppacmd
#

#CFLAGS += -O2 -I$(KERNEL_INCLUDE_PATH)
PPA_CFG_FLAG +=-DCONFIG_LTQ_PPA_IPv6_ENABLE
PPA_CFG_FLAG +=-DCONFIG_LTQ_PPA_QOS
PPA_CFG_FLAG +=-DCONFIG_LTQ_PPA_QOS_WFQ
PPA_CFG_FLAG +=-DCONFIG_LTQ_PPA_QOS_RATE_SHAPING
ifeq ($(CONFIG_TARGET_lantiq_xrx500),y)
PPA_CFG_FLAG +=-DCONFIG_LTQ_PPA_HAL_SELECTOR -DCONFIG_LTQ_PPA_GRX500
endif
ifeq ($(CONFIG_TARGET_x86_puma_puma7),y)
PPA_CFG_FLAG +=-DCONFIG_LTQ_PPA_HAL_SELECTOR -DCONFIG_PPA_PUMA7 -DCONFIG_LTQ_PPA_API -DCONFIG_PPA_PUMA_HAL 
endif
ifeq ($(CONFIG_PACKAGE_kmod-lantiq-swaccel),y)
PPA_CFG_FLAG +=-DCONFIG_LTQ_PPA_API_SW_FASTPATH
endif
ifeq ($(CONFIG_FEATURE_SESSION_LIMIT),y)
PPA_CFG_FLAG +=-DCONFIG_LTQ_PPA_HANDLE_CONNTRACK_SESSIONS
endif

CFLAGS += -O2 $(PPA_CFG_FLAG) -I./

all: ppacmd

ppacmd.o: ppacmd.c
ppacmd_autotest.o: ppacmd_autotest.c

ppacmd: ppacmd_autotest.o ppacmd.o

install:
	echo "ppacmd install: do nothing"

clean:
	rm -f *.o ppacmd
