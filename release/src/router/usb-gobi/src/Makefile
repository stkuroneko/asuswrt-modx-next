include ../../common.mak

TOOLLIB=$(shell dirname $(shell which $(CXX)))/../lib

CFLAGS += -Iinclude
LDFLAGS += -L$(GOBI_LIB_DIR) -lGobiConnectionMgmt -L$(TOOLLIB) -lrt -lpthread -lstdc++ -lm -ldl

ifeq ($(or $(RTCONFIG_BCMARM),$(RTCONFIG_SOC_IPQ40XX)),y)
LDFLAGS += -lgcc_s
endif


TARGET = gobi_api
TARGET += sample
#TARGET += open_tty

all: $(TARGET)
	@echo "target=$(TARGET)"

sample: Sample_Main.cpp
	$(CC) $^ -o $@ $(LDFLAGS) $(CFLAGS)

gobi_api: gobi_api.cpp
	$(CC) $^ -o $@ $(LDFLAGS) $(CFLAGS)

open_tty: open_ttyAcm0.c
	$(CC) open_ttyAcm0.c -o $@ $(LDFLAGS) $(CFLAGS)

clean:
	rm -f $(TARGET)
	rm -f lib/libGobiConnectionMgmt*

install: $(TARGET)


.PHONY: all clean install

