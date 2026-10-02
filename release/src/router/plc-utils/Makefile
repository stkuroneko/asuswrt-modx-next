PLCUTILS_EXEC=$(wildcard prebuild/*)

all:

install:
	@[ -d $(INSTALLDIR)/usr/local/bin ] || install -d $(INSTALLDIR)/usr/local/bin
	@for i in $(PLCUTILS_EXEC); do cp -a $$i $(INSTALLDIR)/usr/local/bin ; done
ifeq ($(QCA_PLC2),y)
	@[ -d prebuild_rom ] && install -d $(INSTALLDIR)/lib/firmware/plc && install -D prebuild_rom/* $(INSTALLDIR)/lib/firmware/plc
endif

clean:
