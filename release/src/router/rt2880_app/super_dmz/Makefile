EXEC = super_dmz

all: $(EXEC) 

romfs:
	$(STRIP) super_dmz
	$(ROMFSINST) -e CONFIG_RALINKAPP_SUPERDMZ /bin/super_dmz
	$(ROMFSINST) -e CONFIG_RALINKAPP_SUPERDMZ /bin/udhcpd_superdmz.sh

