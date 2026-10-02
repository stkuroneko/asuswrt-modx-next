# Makefile2.6
ifneq ($(KERNELRELEASE),)
#kbuild syntax. dependency relationshsip of files and target modules are listed here.
#sprdu2s-objs := sprdu2s.o
sciu2s-objs := sprdu2s.o
obj-m := sciu2s.o
else
PWD  := $(shell pwd)
KVER := $(shell uname -r)
KDIR := /lib/modules/$(KVER)/build
HASUSBSERVIAL := $(shell lsmod | grep usbserial)
HASSCIU2S := $(shell lsmod | grep sciu2s)

all:
	$(MAKE) -C $(LINUXDIR) CROSS_COMPILE=$(patsubst %-gcc,%-,$(KERNELCC)) M=$(PWD) modules
clean:
	$(MAKE) -C $(LINUXDIR) M=$(PWD) clean
	rm -rf .*.cmd *.o *.mod.c *.ko .tmp_versions
install:
	$(MAKE) -C $(LINUXDIR) CROSS_COMPILE=$(patsubst %-gcc,%-,$(KERNELCC)) M=$(PWD) modules INSTALL_MOD_PATH=$(INSTALLDIR) modules_install
	@find $(INSTALLDIR) -name "modules.*" | xargs rm -f
	@find $(INSTALLDIR) -name "*.ko" | xargs $(STRIPX)
uninstall:
	$(RM) *.o *.ko *.mod.*
endif
