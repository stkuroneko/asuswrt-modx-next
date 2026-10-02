#!/usr/bin/make -f
# file: lldp/Makefile

# ====================================================================
# environment definitions;
# --------------------------------------------------------------------

include ../make.def

# ====================================================================
# symbols;
# --------------------------------------------------------------------

CFLAGS+=-g
LDFLAGS+=
TRASH=*.o *.obj *.exe t t.* *~ *.[0-9][0-9][0-9] 
FILES=Makefile *.mak *.sh *.c 
TOOLS=solicit respond
PAGES=solicit.1 respond.1

# ====================================================================
# pseudo targets;
# --------------------------------------------------------------------

all compile: ${TOOLS}
compact: compile
	if [ ! -z ${STRIP} ]; then ${STRIP} ${TOOLS}; fi
	if [ -x /usr/local/bin/upx ]; then upx --best ${TOOLS}; fi
library:
	install -m ${DIR_PERM} -o ${OWNER} -g ${GROUP} -d ${BIN}
scripts:
manuals:
	if [ ! -d ${MAN} ]; then install -m ${DIR_PERM} -o ${OWNER} -g ${GROUP} -d ${MAN}; fi
	install -m ${MAN_PERM} -o ${OWNER} -g ${GROUP} ${PAGES} ${MAN}
install: compile library
	install -m ${SUID_PERM} -o ${OWNER} -g ${GROUP} ${TOOLS} ${BIN}
uninstall:
	cd ${BIN}; rm -f int6k ${TOOLS}
	cd ${MAN}; rm -f int6k ${PAGES}
clean:
	rm -f ${TRASH} ${TOOLS} 
check:
	${SHELL} lldp.sh
ignore:
	echo ${TOOLS} | tr ' ' '\n' > .gitignore

# ====================================================================
# rules; 
# --------------------------------------------------------------------

%: %.o
	${CC} -o ${@} ${^} ${LDFLAGS}
%.o: %.c
	${CC} -c ${<} ${CFLAGS}

# ====================================================================
# programs;     
# --------------------------------------------------------------------

respond: respond.o EthernetHeader.o lldp.o TLVPack.o TLVPackOS.o TLVPeek.o TLVPick.o channel.o closechannel.o config.o decdecode.o decstring.o error.o getoptv.o hexcopy.o hexdecode.o hexdump.o hexencode.o hexstring.o openchannel.o putoptv.o readpacket.o sendpacket.o strfbits.o synonym.o todigit.o uintspec.o version.o
solicit: solicit.o EthernetHeader.o lldp.o TLVPack.o TLVPackOS.o TLVPeek.o TLVPick.o channel.o closechannel.o decdecode.o decstring.o error.o getoptv.o hexdecode.o hexdump.o hexencode.o hexstring.o memswap.o openchannel.o putoptv.o readpacket.o sendpacket.o strfbits.o synonym.o todigit.o uintspec.o version.o

# ====================================================================
# includes;
# --------------------------------------------------------------------

include ../tools/tools.mak
include ../ether/ether.mak
include ../mme/mme.mak
include ../plc/plc.mak

