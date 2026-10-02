include ../common.mak
include $(SRCBASE)/.config

CFLAGS += -Wall -Os $(EXTRACFLAGS)

PROG1=quectel-CM
PROG2=quectel-qmi-proxy

#ifneq ($(CROSS_COMPILE),)
#CROSS-COMPILE:=$(CROSS_COMPILE)
#endif
#CROSS-COMPILE:=/workspace/buildroot/buildroot-qemu_mips_malta_defconfig/output/host/usr/bin/mips-buildroot-linux-uclibc-
#CROSS-COMPILE:=/workspace/buildroot/buildroot-qemu_arm_vexpress_defconfig/output/host/usr/bin/arm-buildroot-linux-uclibcgnueabi-
#CROSS-COMPILE:=/workspace/buildroot-git/qemu_mips64_malta/output/host/usr/bin/mips-gnu-linux-
#ifeq ($(CC),cc)
#CC:=$(CROSS-COMPILE)gcc
#endif
#LD:=$(CROSS-COMPILE)ld

QL_CM_SRC=QmiWwanCM.c GobiNetCM.c main.c MPQMUX.c QMIThread.c util.c qmap_bridge_mode.c mbim-cm.c device.c
ifeq (1,1)
QL_CM_DHCP=udhcpc.c
else
LIBMNL=libmnl/ifutils.c libmnl/attr.c libmnl/callback.c libmnl/nlmsg.c libmnl/socket.c
DHCP=libmnl/dhcp/dhcpclient.c libmnl/dhcp/dhcpmsg.c libmnl/dhcp/packet.c
QL_CM_DHCP=udhcpc_netlink.c
QL_CM_DHCP+=${LIBMNL}
endif

all: $(PROG1)

install: all
	@echo "[$(PROG1)] Installing..."
	@install -m 755 -D $(PROG1) $(INSTALLDIR)/usr/sbin/$(PROG1)
	@$(STRIP) $(INSTALLDIR)/usr/sbin/$(PROG1)
	@install -m 755 -D $(PROG2) $(INSTALLDIR)/usr/sbin/$(PROG2)
	@$(STRIP) $(INSTALLDIR)/usr/sbin/$(PROG2)


$(PROG1): $(PROG2)
	$(CC) -Wall -s ${QL_CM_SRC} ${QL_CM_DHCP} -o $@ -lpthread

debug: clean
	$(CC) -Wall -g -DCM_DEBUG ${QL_CM_SRC} ${QL_CM_DHCP} -o $(PROG1) -lpthread

$(PROG2):
	$(CC) -Wall -s quectel-qmi-proxy.c -o $(PROG2) -lpthread

clean:
	rm -rf $(PROG1) *~
	rm -rf $(PROG2)

