
all:
	mkdir -p bndstrg_plus
	cp prebuilt/RT-AX53U/bndstrg2 bndstrg_plus/bndstrg2

install:
	mkdir -p $(INSTALLDIR)/usr/sbin
	install -D bndstrg_plus/bndstrg2 $(INSTALLDIR)/usr/sbin/bndstrg2
	chmod 755 $(INSTALLDIR)/usr/sbin/bndstrg2
	$(STRIP) $(INSTALLDIR)/usr/sbin/bndstrg2 || true

clean:

