CC = gcc

COMMON_SRCDIR ?= ../../../src
TOOLKIT_SRCDIR ?= $(COMMON_SRCDIR)/toolkit


override CFLAGS +=  -O2 -Wall

dtd-compress:
	$(CC) $(TOOLKIT_SRCDIR)/sshxml/dtd-compress.c -o $@

clean:
	rm -rf dtd-compress
