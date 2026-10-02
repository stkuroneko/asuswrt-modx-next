#Modify this to point to the PJSIP location.
PJBASE=../../pjproject-1.12
UPNPBASE=../../miniupnpc-1.6
NATBASE=/home/charles0000/asusnatnl-android/natnl
CURBASE=.
LIB_MINIUPNPC=miniupnpc
LIB_NATNL=natnl

include $(PJBASE)/build.mak

CC      = $(PJ_CC)
AR      = $(PJ_AR)
LDFLAGS = $(PJ_LDFLAGS)
LDLIBS  = $(PJ_LDLIBS)
LDLIBS += -l$(LIB_MINIUPNPC) -l$(LIB_NATNL)
CFLAGS  = $(PJ_CFLAGS)
CPPFLAGS= ${CFLAGS}
CFLAGS += -g -I.
CFLAGS += -I$(UPNPBASE) -I$(NATBASE) -I$(CURBASE)
LDFLAGS += -L$(UPNPBASE) -L$(NATBASE) -L$(SYSROOT)/usr/lib -llog
#CFLAGS += -Wall
#CFLAGS += -DNO_CONFERENCE

CFLAGS += -DDEBUG_PRINT
CFLAGS += -DPJMEDIA_HAS_NAT_TUNNEL_CODEC=1 -DPJ_ANDROID=1 -DNATNL_LIB=1# -I/home/charles0000/android-toolchain/sysroot/usr/include
#set maximum udptunnel data length 
#note that it must less than PJMEDIA_MAX_MTU of pjsip
CFLAGS += -DMSG_MAX_LEN=8192
#enable=1 or disable=0 dump transfer data in hex.
CFLAGS += -DDUMP_HEX=0

OBJS = client.o server.o \
#        http_client.o webdav.o  
#		file_sender.o file_receiver.o tunnel.o ruler_port.o \

# If your application is in a file named main.cpp or main.c
# this is the line you will need to build the binary.
all: libnatapi.so
#all: natapi_test

#natapi_test: main.c $(OBJS)
libnatapi.so: natapi.c $(OBJS) 
	$(CC) -shared -o $@ $< $(CPPFLAGS) $(LDFLAGS) $(OBJS) $(LDLIBS) #-lminiupnpc
#	$(CC) -o $@ $< $(CPPFLAGS) $(LDFLAGS) $(OBJS) $(LDLIBS) #-lminiupnpc

.c.o:
	$(CC) -c -o $@ $(CPPFLAGS) $(CFLAGS) $<

clean:
	rm -f *.o libnatapi.so 

