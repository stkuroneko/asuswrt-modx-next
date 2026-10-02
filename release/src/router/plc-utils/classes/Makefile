#!/usr/bin/make -f
# file: classes/Makefile

# ====================================================================
# environment definitions;
# --------------------------------------------------------------------

include ../make.def

# ====================================================================
# symbols;
# --------------------------------------------------------------------

CXXFLAGS+=
LDFLAGS+=
VPATH=../classes
TRASH=*.o *.obj *.exe t t.* *~ *.[0-9][0-9][0-9] 
TOOLS=
FILES=*.cpp *.hpp *.h *.sh *.mak Makefile Makefile.*
PAGES=

# ====================================================================
# pseudo targets;
# --------------------------------------------------------------------

all compile: ${TOOLS}
compact: compile
	if [ ! -z ${STRIP} ]; then ${STRIP} ${TOOLS}; fi
	if [ -x /usr/local/bin/upx ]; then upx --best ${TOOLS}; fi
library:
	install -m ${DIR_PERM} -o 0 -g 0 -d ${BIN}
scripts:
manuals:
	if [ ! -d ${MAN} ]; then install -m ${DIR_PERM} -o ${OWNER} -g ${GROUP} -d ${MAN}; fi
	install -m ${MAN_PERM} -o 0 -g 0 ${PAGES} ${MAN}
install: compile library
#	install -m ${BIN_PERM} -o 0 -g 0 ${TOOLS} ${BIN}
uninstall:
	cd ${BIN}; rm -f ${TOOLS}
clean:
	rm -f ${TOOLS} ${TRASH}
check:
	${SHELL} classes.sh
ignore:
	echo ${TOOLS} | tr ' ' '\n' > .gitignore

# ====================================================================
# rules;
# --------------------------------------------------------------------

%: %.o 
	${CXX} -o ${@} ${^} ${LDFLAGS}
%.o: %.cpp
	${CXX} -c ${<} ${CXXFLAGS}
%.hpp: %.hpp

# ====================================================================
# 
# --------------------------------------------------------------------

include ../classes/classes.mak

