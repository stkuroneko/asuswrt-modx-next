export STAGING_DIR=/opt/sw_toolchains/ugw/64bit/toolchain-mips_r2_gcc-4.8-linaro_uClibc-0.9.33.2_linux_3_10/include
CC = /opt/sw_toolchains/ugw/64bit/toolchain-mips_r2_gcc-4.8-linaro_uClibc-0.9.33.2_linux_3_10/bin/mips-openwrt-linux-gcc

TARGET := target-mips-openwrt-linux-uclibc_grx350_gw_he_vdsl_lte_new_framework_sample

STAGING_DIR := ../../../../staging_dir/$(TARGET)

LIBPATH := $(STAGING_DIR)/usr/lib/
INCLUDE_PATH := $(STAGING_DIR)/usr/include

CFLAGS  := -I$(INCLUDE_PATH) -MP -MD -DLOGGING_ID=100 -DPACKAGE_ID=101 -DMEM_DEBUG
LDFLAGS := -L$(LIBPATH) -lscapi -lugwhelper -Wl,-rpath-link=$(LIBPATH)

#creating output names
SRCS = $(wildcard *.c)
UTILITIES = $(patsubst %.c, %, $(SRCS))
OBJS = $(patsubst %.c, %.o, $(SRCS))
DEPS := $(patsubst %.c, %.d, $(SRCS))


#implicit SUFFIX rules for $(OBJS) and $(UTILITIES)
all: $(DEPS) $(OBJS) $(UTILITIES)

#constucts curren_match.o: current_match.c all_h_files_that_current_match_.c_file_includes_recursively. Needs to be done before .c.o(%.o: %.c) suffix rule 
%.d: %.c
	$(CC) -MM $(CFLAGS) $< > $@
	$(CC) -MM $(CFLAGS) $< | sed s/\\.o/.d/ >> $@

clean:
	rm -f $(UTILITIES) $(DEPS) *.o

-include $(DEPS)
