include ../common.mak

CFLAGS += -I. -I$(TOP)/shared$(RPEX) -I$(SRCBASE)/include
ifneq ($(BUILD_NAME),RP-AC56)
LDFLAGS += -L$(TOP_PLATFORM)/nvram -lnvram
endif
LDFLAGS +=-L$(TOP)/shared$(RPEX) -lshared

EXEC = flash
OBJS = flash_mtd.o

ifneq ($(wildcard ./prebuild/$(BUILD_NAME)),)
all:
	-cp prebuild/$(BUILD_NAME)/$(EXEC) $(EXEC)
else
all: $(EXEC) 
endif

$(EXEC): $(OBJS)
	echo "Build_Name:"$(BUILD_NAME) 
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) $(LDFLAGS) -o $@ $(OBJS)

install: all
	install -D $(EXEC) $(INSTALLDIR)/bin/$(EXEC)
	$(STRIP) $(INSTALLDIR)/bin/$(EXEC)
	chmod 0500 $(INSTALLDIR)/bin/$(EXEC)

clean:
	-rm -f $(EXEC) *.o

