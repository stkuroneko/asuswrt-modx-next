EXEC = i2scmd
#MP3PATH = ./libmad-0.15.1b
#MP3OBJS = $(MP3PATH)/bit.o $(MP3PATH)/decoder.o \
			$(MP3PATH)/frame.o	$(MP3PATH)/fixed.o	\
			$(MP3PATH)/huffman.o	$(MP3PATH)/layer3.o	\
			$(MP3PATH)/layer12.o	$(MP3PATH)/stream.o	\
			$(MP3PATH)/synth.o	$(MP3PATH)/timer.o	\
			$(MP3PATH)/version.o \
			$(MP3PATH)/minimad.o
			
OBJS = i2scmd.o 
#$(MP3OBJS) 
#MP3_CFLAGS = -O3 -DFPM_MIPS -DOPT_SPEED
CFLAGS += -I$(ROOTDIR)/$(LINUXDIR)/include -I$(ROOTDIR)/$(LINUXDIR)/drivers/char/i2s
#-I$(MP3PATH) 
#$(MP3_CFLAGS)

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS)

romfs:
	$(ROMFSINST) /bin/$(EXEC)

clean:
	rm -f core *.o $(EXEC)
