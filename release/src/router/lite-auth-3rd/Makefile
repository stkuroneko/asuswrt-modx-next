include ../common.mak

STATICLIB = libsw_hw_auth.a
TOOL = sample_test

CFLAGS  += -Wall -fPIC -I. -s -O2

OBJS = auth.o

all : $(STATICLIB) $(TOOL)

$(STATICLIB): $(OBJS)
	@echo " [lite-auth-3rd] AR $@"
	@rm -f $@
	@$(AR) cru $@ $^

$(TOOL): main.o
	@echo "[lite-auth-3rd] $(TOOL)"
	$(CC) $(CFLAGS) -o $@ $^ $(STATICLIB) 

clean:
	rm -f *.o *.so $(STATICLIB) $(TOOL)
