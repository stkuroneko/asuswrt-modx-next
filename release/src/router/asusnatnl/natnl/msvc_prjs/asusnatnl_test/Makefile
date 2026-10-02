#Modify this to point to the PJSIP location.
NATBASE=../../
#LIBBASE=../../../release/linux/
LIBBASE=../..
PJBASE=$(NATBASE)/../pjproject-1.12
include $(PJBASE)/build.mak

#CC      = gcc 
#C++		= g++
CC      = $(PJ_CC)
C++	= $(PJ_CXX)
CFLAGS  = $(PJ_CFLAGS)
LDFLAGS = $(PJ_LDFLAGS)
LDLIBS += $(PJ_LDLIBS)
CFLAGS += -g -I. -I$(NATBASE)
LDFLAGS += -ldl -lpthread 
LDFLAGS += -L$(LIBBASE)
#CFLAGS += -I$(UPNPBASE)
#CFLAGS += -Wall
#CFLAGS += -DNO_CONFERENCE

OBJS = getopt.o config.o

# If your application is in a file named main.cpp or main.c
# this is the line you will need to build the binary.
#all: natnl
all: asusnatnl_test 

asusnatnl_test: main.c $(OBJS) 
	$(C++) -o $@ $< $(CFLAGS) $(OBJS) $(LDFLAGS) $(LDLIBS)

%.o: %.c
	$(C++) -c -o $@ $(CPPFLAGS) $(CFLAGS) $<

clean:
	rm -f *.o asusnatnl_test
