EXEC = csr_go
OBJS = csr_test.o csr_netlink.o csr_sysinfo.o
CFLAGS += -I$(ROOTDIR)/$(LINUXDIR)/include

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS)

romfs:
	$(ROMFSINST) /bin/$(EXEC)

clean:
	rm -f core *.o $(EXEC)
