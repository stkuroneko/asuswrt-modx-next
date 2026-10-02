#!/usr/bin/make -f
# file: VisualStudioNET/Makefile

# ====================================================================
# environment definitions;
# --------------------------------------------------------------------

include ../make.def

# ====================================================================
# 
# --------------------------------------------------------------------

CFLAGS+=
LDFLAGS+=
TRASH=*.o t t.* *.[0-9][0-9][0-9] *~ *.log *.obj *.exe *.suo *.ncb 
TOOLS=

# ====================================================================
# pseudo targets;
# --------------------------------------------------------------------

all compile: ${TOOLS}
library:
#	install -m ${DIR_PERM} -o ${OWNER} -g ${GROUP} -d ${BIN}
scripts manuals:
install: compile library
#	install -m ${BIN_PERM} -o ${OWNER} -g ${GROUP} ${TOOLS} ${BIN}
uninstall:
#	cd ${BIN}; rm -f ${TOOLS}
#	cd ${MAN}; rm -f ${PAGES}
clean:
	rm -fr _UpgradeReport_Files *.XML .#*
	rm -fr */[Dd]ebug */[Rr]elease */*.[0-9][0-9][0-9] 
	rm -fr Objects/2003/*.?db Objects/2003/*.tlog 
	rm -fr */*.log */*.tlog */*.manifest */*.unsuccessfulbuild */*.cache
	rm -f ${TOOLS} ${TRASH} 
check:
#	${SHELL} VisualStudioNET.sh
ignore:
#
#	Please do not over-write the local .gitignore file;
#
#	echo ${TOOLS} | tr ' ' '\n' > .gitignore
#

