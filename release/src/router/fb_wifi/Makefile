#***********************************************************************
#
# Makefile
#
#***********************************************************************
include ../common.mak

CFLAGS += -I$(TOP)/openssl/include -I$(TOP)/curl-7.21.7/include

CFLAGS_l = -I$(TOP)/openssl/include
CFLAGS += -I$(SRCBASE) -I$(SRCBASE)/include -I. -I$(TOP)/shared -DNVRAM_

CFLAGS_l += -I$(SRCBASE) -I$(SRCBASE)/include -I. -I$(TOP)/shared -DNVRAM_

LDFLAGS = -L$(TOP)/curl-7.21.7/lib/.libs -L$(TOP)/openssl -L$(TOP_PLATFORM)/nvram${BCMEX} -L$(TOP)/shared -lshared

LDFLAGS_l = -L$(TOP)/openssl -L$(TOP_PLATFORM)/nvram${BCMEX} -L$(TOP)/shared -lshared

LIBS = -lnvram -lshared -lcrypto -lssl -lcurl -lm

LIBS_l = -lnvram -lshared -lcrypto -lssl -lm

ifeq ($(RTCONFIG_BCM_502L07P2),y)
LDFLAGS += -L$(TOP_PLATFORM)/ethctl_lib
LDFLAGS_l += -L$(TOP_PLATFORM)/ethctl_lib
LIBS += -lethctl
LIBS_l += -lethctl
endif

ifeq ($(RTCONFIG_QTN),y)
LDFLAGS += -L$(TOP)/libqcsapi_client
LIBS += -lqcsapi_client
endif

ifeq ($(RTCONFIG_BCMARM),y)
CFLAGS += -I$(SRCBASE)/shared/bcmwifi/include -DTYPEDEF_FLOAT_T
CFLAGS += -I$(SRCBASE)/common/include
endif

ifeq ($(BUILD_NAME),RT-AC3200)
CFLAGS_l += -DHAVE_5g_2
endif

#all: fb_wifi_register fb_wifi_check libfbwifi.so test
all: fb_wifi_register fb_wifi_check libfbwifi.so

fb_wifi_register:fb_wifi.o cJSON.o 
	$(CC) $(CFLAGS) $(LDFLAGS) $(LIBS) $^ -o $@

#test:test.o
#	$(CC) $(CFLAGS) $(LDFLAGS) $(LIBS) $^ -o $@

fb_wifi_re:fb_wifi_re.o
	$(CC) $(CFLAGS) $(LDFLAGS) $(LIBS) $^ -o $@

fb_wifi_check:fb_wifi_check.o cJSON.o
	$(CC) $(CFLAGS) $(LDFLAGS) $(LIBS) $^ -o $@

libfbwifi.so:fbwifi.c md5.c hmac_sha256.c
	$(CC) -fPIC -shared $(CFLAGS_l) $(LDFLAGS_l) $(LIBS_l) $^ -o $@

.PHONY:clean
clean:
	rm -rf *.o fb_wifi_register fb_wifi_check libfbwifi.so

