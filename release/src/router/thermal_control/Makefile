include ../common.mak
include $(SRCBASE)/router/.config

SOURCES=ther_control.c
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=ther_control

CFLAGS += -I$(LINUXDIR)/drivers/net/wireless/realtek/rtl8192cd/ -I$(LINUXDIR)/../include/linux/

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

.cpp.o:
	$(CC) $(CFLAGS) $< -o $@

install:
	install -D ther_config/ther.conf-98D-V100 $(INSTALLDIR)/rom/etc/ther.conf
	install -D $(EXECUTABLE) $(INSTALLDIR)/bin/$(EXECUTABLE)
	$(STRIP) $(INSTALLDIR)/bin/$(EXECUTABLE)

.PHONY: ther_control

clean: 
	rm -rf $(EXECUTABLE) *.o
