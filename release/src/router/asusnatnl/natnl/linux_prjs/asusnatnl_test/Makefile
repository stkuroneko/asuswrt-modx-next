#Modify this to point to the PJSIP location.
NATBASE=../../

CC      = gcc 
LDLIBS += -L. -lasusnatnl
CFLAGS += -g -I. -I$(NATBASE)
#CFLAGS += -I$(UPNPBASE)
#CFLAGS += -Wall
#CFLAGS += -DNO_CONFERENCE

# If your application is in a file named main.cpp or main.c
# this is the line you will need to build the binary.
#all: natnl
all: asusnatnl_test 

asusnatnl_test: main.c
	$(CC) -o $@ $< $(CFLAGS) $(LDFLAGS) $(OBJS) $(LDLIBS)

%.o: %.c
	$(CC) -c -o $@ $(CPPFLAGS) $(CFLAGS) $<

clean:
	rm -f *.o asusnatnl_test
