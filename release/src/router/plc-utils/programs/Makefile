#!/usr/bin/make -f
# file: programs/Makefile

# ====================================================================
# environment definitions;
# --------------------------------------------------------------------

include ../make.def

# ====================================================================
# symbols;
# --------------------------------------------------------------------

CXXFLAGS+=
LDFLAGS+=
VPATH=../classes:../tools
TRASH=*.o *.obj *.exe t t.* *~ *.[0-9][0-9][0-9]
FILES=*.cpp *.hpp *.h *.sh *.xml *.txt *.mak Makefile Makefile.*
TOOLS=netifs hpavkey example-1 example-2 example-3 example-4 example-5
TOOLS=netifs hpavkey plcnets chknvm3
TOOLS+=example-1 example-2 example-3 example-4 example-5
PAGES=hpavkey.1 netifs.1 plcnets.1

# ====================================================================
# pseudo targets;
# --------------------------------------------------------------------

all compile: ${TOOLS}
	echo ${TOOLS} | tr ' ' '\n' > .gitignore
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
	install -m ${MAN_PERM} -o ${OWNER} -g ${GROUP} ${PAGES} ${MAN}
install: compile library
ifeq ($(PLC_UTILS),y)
	install ${TOOLS} ${BIN}
else
	install -m ${SUID_PERM} -o ${OWNER} -g ${GROUP} ${TOOLS} ${BIN}
endif
uninstall:
	root -c cd ${BIN}; rm -f ${TOOLS}
clean:
	rm -f ${TOOLS} ${TRASH} 
check:
	${SHELL} programs.sh
ignore:
	echo ${TOOLS} | tr ' ' '\n' > .gitignore

# ====================================================================
# programs;
# --------------------------------------------------------------------

%: %.o 
	${CXX} -o ${@} ${^} ${LDFLAGS}
%.o: %.cpp
	${CXX} -c ${<} ${CXXFLAGS}
%.hpp: %.hpp

# ====================================================================
# programs;
# --------------------------------------------------------------------

netifs: netifs.o omemory.o oerror.o ointerface.o ointerfaces.o 
hpavkey: hpavkey.o ogetoptv.o oputoptv.o oversion.o oerror.o oflagword.o omemory.o oSHA256.o oHPAVKey.o 
plcnets: plcnets.o ogetoptv.o oputoptv.o oversion.o oerror.o oflagword.o omemory.o oethernet.o ohomeplug.o ointellon.o ointerface.o ointerfaces.o CPLChannel.o CPLNetworks.o CPLNetwork.o CPLStation.o

# ====================================================================
# examples;
# --------------------------------------------------------------------

chknvm3: chknvm3.o ogetoptv.o oputoptv.o oversion.o oerror.o omemory.o ointerface.o oethernet.o ointellon.o ohomeplug.o oflagword.o CPLFirmware.o CPLChannel.o 
example-1: example-1.o omemory.o oerror.o ointerface.o ointerfaces.o 
example-2: example-2.o omemory.o oerror.o oflagword.o oethernet.o ohomeplug.o ointellon.o ointerface.o ointerfaces.o CPLChannel.o 
example-3: example-3.o omemory.o oerror.o oflagword.o oethernet.o ohomeplug.o ointellon.o ointerface.o CPLChannel.o CPLNetwork.o CPLStation.o
example-4: example-4.o omemory.o oerror.o oflagword.o oethernet.o ohomeplug.o ointellon.o ointerface.o ointerfaces.o CPLChannel.o CPLNetwork.o CPLStation.o
example-5: example-5.o omemory.o oerror.o oflagword.o oethernet.o ohomeplug.o ointellon.o ointerface.o ointerfaces.o CPLChannel.o CPLNetworks.o CPLNetwork.o CPLStation.o

# ====================================================================
# 
# --------------------------------------------------------------------

include ../programs/programs.mak
include ../classes/classes.mak
include ../tools/tools.mak

