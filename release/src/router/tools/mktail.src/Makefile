CC	   = gcc
CFLAGS	   = -O2
#LFLAGS     = -m32
STRIP	   = strip

all:	mktail

mktail : mktail.o
	$(CC) $(LFLAGS) -o $@ $^
	$(STRIP) $@

mktail.o : mktail.c
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f *.o *~ mktail
