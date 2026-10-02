SCRIPTS = $(notdir $(wildcard *.sh))

all:

clean:

romfs:
	sed -e '/^#/d' ${ROOTDIR}/${CONFIG_LINUXDIR}/.config > .config
	chmod 755 .config
	$(ROMFSINST) .config /sbin/config.sh
	for i in $(SCRIPTS) ; do \
		$(ROMFSINST) $$i /sbin/$$i ; \
	done

ifeq ("$(CONFIG_USER_STORAGE)", "")	
	rm $(ROMFSDIR)/sbin/storage.sh
endif

ifeq ("$(CONFIG_USER_3G)", "")	
	rm $(ROMFSDIR)/sbin/3g.sh
	rm $(ROMFSDIR)/sbin/config-3g-ppp.sh
endif

ifeq ("$(CONFIG_USER_GOAHEAD_GreenAP)", "")	
	rm $(ROMFSDIR)/sbin/greenap.sh
endif

ifeq ("$(CONFIG_USER_INADYN)", "")	
	rm $(ROMFSDIR)/sbin/ddns.sh
endif

ifeq ("$(CONFIG_USER_WSYS_TR069_AGENT)", "")
	rm $(ROMFSDIR)/sbin/tr069.sh
endif

ifeq ("$(CONFIG_USER_SNMPD)", "")
	rm $(ROMFSDIR)/sbin/mini-snmp.sh
endif

ifeq ("$(CONFIG_USER_NETSNMP_SNMPD)", "")
	rm $(ROMFSDIR)/sbin/net-snmp.sh
endif
