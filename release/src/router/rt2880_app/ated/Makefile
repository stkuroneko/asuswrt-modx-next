#NVDIR = $(ROOTDIR)/lib/libnvram
#CFLAGS += -I$(NVDIR) 
#LDFLAGS += -lnvram
EXEC = ated
SRCS = ated.c

#EXTRA_CFLAGS += -DDBG

all: $(EXEC)

$(EXEC): $(SRCS) $(ROOTDIR)/$(LINUXDIR)/include/linux/autoconf.h
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) $(LDFLAGS) -o $@ $@.c $(LDLIBS)

romfs:
	$(ROMFSINST) /bin/$(EXEC)

clean:
	-rm -f $(EXEC) *.o

$(ROOTDIR)/$(LINUXDIR)/include/linux/autoconf.h:
	$(MAKE) -C $(ROOTDIR)/$(LINUXDIR) include/config/auto.conf || $(MAKE) -C $(ROOTDIR)/$(LINUXDIR) prepare
