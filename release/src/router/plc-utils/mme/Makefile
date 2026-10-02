#!/usr/bin/make -f
# file: mme/Makefile

# ====================================================================
# environment definitions;
# --------------------------------------------------------------------

include ../make.def

# ====================================================================
# symbols;
# --------------------------------------------------------------------

CFLAGS+=
LDFLAGS+=
TRASH=*.o *.obj *.exe t t.* *~ *.[0-9][0-9][0-9] *.out
FILES=Makefile *.mak *.sh *.txt *.c *.h *.xml *.css
TOOLS=hpav mme 
PAGES=hpav.1 mme.1

# ====================================================================
# pseudo targets;
# --------------------------------------------------------------------

all compile: ${TOOLS}
compact: compile
	if [ ! -z ${STRIP} ]; then ${STRIP} ${TOOLS}; fi
	if [ -x /usr/local/bin/upx ]; then upx --best ${TOOLS}; fi
library:
ifeq ($(PLC_UTILS),y)
	install -d ${BIN}
else
	install -m ${DIR_PERM} -o ${OWNER} -g ${GROUP} -d ${BIN}
endif
scripts:
manuals:
	if [ ! -d ${MAN} ]; then install -m ${DIR_PERM} -o ${OWNER} -g ${GROUP} -d ${MAN}; fi
	install -m ${MAN_PERM} -o ${OWNER} -g ${GROUP} ${PAGES} ${MAN}
install: compile library
ifeq ($(PLC_UTILS),y)
	install ${TOOLS} ${BIN}
else
	install -m ${BIN_PERM} -o ${OWNER} -g ${GROUP} ${TOOLS} ${BIN}
endif
uninstall:
	cd ${BIN}; rm -f ${TOOLS}
clean:
	rm -f ${TOOLS} ${TRASH}
check:
	${SHELL} mme.sh
ignore:
	echo ${TOOLS} | tr ' ' '\n' > .gitignore

# ====================================================================
# rules;
# --------------------------------------------------------------------

%: %.o
	${CC} -o ${@} ${^} ${LDFLAGS}
%.o: %.c
	${CC} -c ${<} ${CFLAGS}
%.h: %.h

# ====================================================================
# programs; 
# --------------------------------------------------------------------

hpav: hpav.o getoptv.o putoptv.o version.o hexdump.o hexdecode.o hexstring.o error.o channel.o openchannel.o closechannel.o sendpacket.o readpacket.o MMEPeek.o MMEShow.o MMEName.o MMEMode.o uintspec.o todigit.o hexstream.o
hpavd: hpavd.o getoptv.o putoptv.o version.o hexdump.o hexdecode.o hexstring.o error.o channel.o openchannel.o closechannel.o sendpacket.o readpacket.o MMEPeek.o MMEName.o MMEMode.o 
mme: mme.o getoptv.o putoptv.o version.o uintspec.o todigit.o output.o error.o MMEName.o MMEMode.o

# ====================================================================
# includes; 
# --------------------------------------------------------------------

include ../tools/tools.mak
include ../ether/ether.mak
include ../mme/mme.mak
include ../plc/plc.mak

