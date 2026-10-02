NVDIR = $(ROOTDIR)/lib/libnvram
CFLAGS += -I$(NVDIR) -I$(ROOTDIR)/$(LINUXDIR)/drivers/char
LDFLAGS += -lnvram
EXEC = nvram_daemon ralink_init
CONF_H	= $(ROOTDIR)/$(LINUXDIR)/include/linux/autoconf.h
UCONF_H	= $(ROOTDIR)/config/autoconf.h


all: $(EXEC)

ifdef CONFIG_RT2880_L2_MANAGE
nvram_daemon: md5c.o rmmsg.o ramad.o nvram_daemon.o
else
nvram_daemon: nvram_daemon.o
endif
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

ralink_init: ralink_init.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

ralink_init.o: $(CONF_H) $(UCONF_H)

nvram_daemon.o: $(CONF_H) $(UCONF_H)

clean:
	rm -f *.o $(EXEC)

romfs:
	for i in $(EXEC) ; do $(ROMFSINST) /bin/$$i ; done
	ln -sf ralink_init nvram_get
	ln -sf ralink_init nvram_set
	mv -f nvram_get $(ROMFSDIR)/bin
	mv -f nvram_set $(ROMFSDIR)/bin

$(CONF_H):
	$(MAKE) -C $(ROOTDIR)/$(LINUXDIR) include/config/auto.conf || $(MAKE) -C $(ROOTDIR)/$(LINUXDIR) prepare
