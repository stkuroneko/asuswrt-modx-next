#!/bin/make -f
# file: tools/Makefile

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
FILES=Makefile *.mak *.sh *.txt *.c *.h *.xml *.css
TOOLS=grab pad
PAGES=grab.1 pad.1

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
	cd ${MAN}; rm -f ${PAGES}
clean:
	rm -f ${TOOLS} ${TRASH}
check: 
	${SHELL} tools.sh
ignore:
	echo ${TOOLS} | tr ' ' '\n' > .gitignore

# ====================================================================
#
# --------------------------------------------------------------------

%: %.o
	${CC} -o ${@} ${^} ${LDFLAGS}
%.o: %.c
	${CC} -c ${<} ${CFLAGS}
%.h: %.h

# ====================================================================
# programs;
# --------------------------------------------------------------------

grab: grab.o getoptv.o putoptv.o version.o basespec.o todigit.o error.o efreopen.o
pad: pad.o efreopen.o error.o getoptv.o putoptv.o todigit.o uintspec.o version.o

# ====================================================================
# libraries;
# --------------------------------------------------------------------

libmtools.a: binout.o bytespec.o confirmfilename.o checksum32.o dataspec.o decdecode.o decout.o emalloc.o endian.o error.o fdchecksum32.o filepart.o getoptv.o hexdecode.o hexdump.o hexencode.o hexin.o hexout.o hexstring.o hexview.o regview.o ipv4spec.o ipv6spec.o memdecr.o memincr.o memswap.o output.o putoptv.o strdecr.o strfbits.o strincr.o synonym.o todigit.o typename.o basespec.o uintspec.o version.o
	rm -f ${@}
	$(AR) rc ${@} ${^}
	$(RANLIB) ${@}

# ====================================================================
#
# --------------------------------------------------------------------

include ../nodes/nodes.mak


