#!/usr/bin/make -f
# file: nvm/Makefile

# ====================================================================
# environment definitions;
# --------------------------------------------------------------------

include ../make.def

# ====================================================================
# symbols;
# --------------------------------------------------------------------

CFLAGS+=
LDFLAGS+=
TRASH=*.o *.obj *.exe t t.* *~ *.[0-9][0-9][0-9] *.test *-[0-9][0-9].nvm
FILES=Makefile *.mak *.sh *.txt *.c *.h *.xml *.css
TOOLS=chknvm chknvm1 chknvm2 nvmsplit nvmmerge tonvm
PAGES=chknvm.1 chknvm1.1 chknvm2.1 nvmsplit.1 nvmmerge.1 tonvm.1

# ====================================================================
# pseudo targets;
# --------------------------------------------------------------------

all compile: ${TOOLS}
compact: compile
	if [ ! -z ${STRIP} ]; then ${STRIP} ${TOOLS}; fi
	if [ -x /usr/local/bin/upx ]; then upx --best ${TOOLS}; fi
scripts:
manuals:
	if [ ! -d ${MAN} ]; then install -m ${DIR_PERM} -o ${OWNER} -g ${GROUP} -d ${MAN}; fi
	install -m ${MAN_PERM} -o ${OWNER} -g ${GROUP} ${PAGES} ${MAN}
library:
ifeq ($(PLC_UTILS),y)
	install -d ${BIN}
else
	install -m ${DIR_PERM} -o ${OWNER} -g ${GROUP} -d ${BIN}
endif
install: compile library
ifeq ($(PLC_UTILS),y)
	install ${TOOLS} ${BIN}
else
	install -m ${BIN_PERM} -o ${OWNER} -g ${GROUP} ${TOOLS} ${BIN}
endif
uninstall:
	cd ${BIN}; rm -f ${TOOLS}
clean:
	rm -f ${TRASH} ${TOOLS}
check:
	${SHELL} nvm.sh
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

chknvm: chknvm.o checksum32.o error.o fdchecksum32.o getoptv.o fdmanifest.o fdrevision.o panther_nvm_manifest.o nvm.o nvmpeek.o lightning_nvm_peek.o panther_nvm_peek.o putoptv.o panther_nvm_revision.o sdrampeek.o strfbits.o version.o hexout.o
chknvm1: chknvm1.o checksum32.o error.o fdchecksum32.o getoptv.o fdmanifest.o fdrevision.o panther_nvm_manifest.o nvm.o nvmpeek.o lightning_nvm_peek.o panther_nvm_peek.o putoptv.o panther_nvm_revision.o sdrampeek.o strfbits.o version.o hexout.o
chknvm2: chknvm2.o checksum32.o error.o getoptv.o panther_nvm_manifest.o panther_nvm_revision.o nvm.o nvmpeek.o lightning_nvm_peek.o panther_nvm_peek.o putoptv.o strfbits.o version.o hexout.o
nvmmerge: nvmmerge.o checksum32.o error.o getoptv.o putoptv.o version.o
nvmsplit: nvmsplit.o checksum32.o error.o getoptv.o putoptv.o version.o
tonvm: tonvm.o basespec.o checksum32.o efreopen.o error.o getoptv.o putoptv.o todigit.o version.o

# ====================================================================
# includes;
# --------------------------------------------------------------------

include ../tools/tools.mak
include ../ether/ether.mak
include ../key/key.mak
include ../ram/ram.mak
include ../nvm/nvm.mak
include ../plc/plc.mak

