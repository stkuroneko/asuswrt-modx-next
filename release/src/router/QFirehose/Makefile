NDK_BUILD:=/workspace/android-ndk/android-ndk-r10e/ndk-build
include ../common.mak
#CFLAGS += -Wextra -Wwrite-strings -Wno-unused-parameter -Wno-error=cpp -MD -Wshadow -Wno-error=deprecated-declarations --std=gnu99 -Werror
ifeq ($(CC),cc)
CC=${CROSS_COMPILE}gcc
endif

all: linux

linux: clean
	${CC} -g -Wall -DUSE_IPC_FILE -s -L$(TOP_PLATFORM)/nvram${BCMEX}${EX7} -lnvram -L$(TOP)/shared -lshared -lcrypt -ldl ${CFLAGS} firehose_protocol.c  qfirehose.c  sahara_protocol.c usb_linux.c stream_download_protocol.c md5.c usb2tcp.c -o QFirehose -lpthread -ldl

debug: clean
	${CC} -Wall -g -DFH_DEBUG -s firehose_protocol.c  qfirehose.c  sahara_protocol.c usb_linux.c stream_download_protocol.c md5.c usb2tcp.c -o QFirehose -lpthread -ldl
	
android: clean
	$(NDK_BUILD) V=0 APP_BUILD_SCRIPT=Android.mk NDK_PROJECT_PATH=`pwd` NDK_DEBUG=0 APP_ABI='armeabi-v7a,arm64-v8a'
	rm -rf obj
	mv libs android

clean:
	rm -rf QFirehose obj libs android usb2tcp *~

install:
	install -D QFirehose $(INSTALLDIR)/sbin/QFirehose
	$(STRIP) $(INSTALLDIR)/sbin/QFirehose
	chmod 777 $(INSTALLDIR)/sbin/QFirehose

.PHONY: all clean install
