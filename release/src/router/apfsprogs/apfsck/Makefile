SRCS = apfsck.c btree.c dir.c extents.c htable.c \
       inode.c key.c object.c spaceman.c super.c xattr.c
OBJS = $(SRCS:.c=.o)
DEPS = $(SRCS:.c=.d)

LIBDIR = ../lib
LIBRARY = $(LIBDIR)/libapfs.a

BINDIR = $(INSTALLDIR)/bin
MANDIR = $(INSTALLDIR)/share/man/man8
#BINDIR = ~/bin
#MANDIR = ~/share/man/man8

SPARSE_VERSION := $(shell sparse --version 2>/dev/null)

override CFLAGS += -Wall -Wno-address-of-packed-member -fno-strict-aliasing -I$(CURDIR)/../include $(COPTS) $(MIPS16_OPT) -ffunction-sections -fdata-sections $(LTO) -DNEED_PRINTF

apfsck: $(OBJS) $(LIBRARY)
	@echo '  Linking...'
	$(CC) $(CFLAGS) -o apfsck $(OBJS) $(LDLTO) $(LIBRARY)
	@echo '  Build complete'

# Build the common libraries
$(LIBRARY): FORCE
	@echo '  Building libraries...'
	@$(MAKE) -C $(LIBDIR) --silent --no-print-directory
	@echo '  Library build complete'
FORCE:

%.o: %.c
	@echo '  Compiling $<...'
	$(CC) $(CFLAGS) -o $@ -MMD -MP -c $<
ifdef SPARSE_VERSION
	@sparse $(CFLAGS) $<
endif

-include $(DEPS)

clean:
	rm -f $(OBJS) $(DEPS) apfsck
install:
	install -d $(BINDIR)
	install -t $(BINDIR) apfsck
	cd $(BINDIR) && ln -fs -T apfsck fsck.apfs
#	ln -fs -T $(BINDIR)/apfsck $(BINDIR)/fsck.apfs
#	install -d $(MANDIR)
#	install -m 644 -t $(MANDIR) apfsck.8
#	ln -fs -T $(MANDIR)/apfsck.8 $(MANDIR)/fsck.apfs.8
