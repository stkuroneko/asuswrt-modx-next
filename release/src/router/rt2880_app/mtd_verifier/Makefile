EXEC = mtdc_rd mtdc_wt
CFLAGS += -I$(ROOTDIR)/$(LINUXDIR)

all: $(EXEC)

mtdc_rd: mtdc_rd.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

mtdc_wt: mtdc_wt.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

romfs:
	$(ROMFSINST) /bin/mtdc_rd
	$(ROMFSINST) /bin/mtdc_wt

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o

