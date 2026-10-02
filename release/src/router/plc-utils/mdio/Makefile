#!/usr/bin/make -f
# file: mdio/Makefile

# ====================================================================
# environment definitions;
# --------------------------------------------------------------------

include ../make.def

# ====================================================================
# symbols;
# --------------------------------------------------------------------

CFLAGS+=
LDFLAGS+=
TRASH=*.o *.obj *.exe t t.* *~ *.[0-9][0-9][0-9]
FILES=Makefile *.mak *.sh *.c *.h 
TOOLS=mdioblock mdioblock2 mdiodump mdiogen
PAGES=mdioblock.1 mdioblock2.1 mdiodump.1

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
	cd ${BIN}; rm -f int6k ${TOOLS}
	cd ${MAN}; rm -f int6k ${PAGES}
clean:
	rm -f ${TRASH} ${TOOLS}
check:
	${SHELL} mdio.sh
ignore:
	echo ${TOOLS} | tr ' ' '\n' > .gitignore

# ====================================================================
# programs;     
# --------------------------------------------------------------------

%: %.o
	${CC} -o ${@} ${^} ${LDFLAGS}
%.o: %.c
	${CC} -c ${<} ${CFLAGS}
%.h: %.h

# ====================================================================
# programs;     
# --------------------------------------------------------------------

mdioblock: mdioblock.o error.o getoptv.o putoptv.o todigit.o version.o
mdioblock2: mdioblock2.o error.o getoptv.o putoptv.o todigit.o version.o
mdiodump: mdiodump.o assist.o error.o codelist.o getoptv.o hexdecode.o hexstring.o lookup.o putoptv.o version.o
mdiogen: mdiogen.o error.o

# ====================================================================
# includes;
# --------------------------------------------------------------------

include ../mdio/mdio.mak
include ../tools/tools.mak
include ../key/key.mak
include ../ether/ether.mak
include ../nodes/nodes.mak
include ../ram/ram.mak
include ../pib/pib.mak
include ../nvm/nvm.mak
include ../mme/mme.mak
include ../plc/plc.mak


