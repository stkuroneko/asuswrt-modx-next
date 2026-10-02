CC=gcc
CFLAGS=-DUSE_HOSTCC
TARGET=modifyData mk_factory_image mt7620a_ecc mk_factory_image2

all: $(TARGET)

mk_factory_image: mk_factory_image.o crc32.o
	$(CC) -Wall -o $@ $^

mk_factory_image2: mk_factory_image2.o crc32.o
	$(CC) -Wall -o $@ $^

mt7620a_ecc: mt7620a_ecc.o
	$(CC) -Wall -o $@ $^

%.o: %.c
	$(CC) -Wall -o $@ $(CFLAGS) -c $<
