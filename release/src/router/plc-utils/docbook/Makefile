#!/bin/make -f
# file: docbook/Makefile

# ====================================================================
# environment definitions;
# --------------------------------------------------------------------

include ../make.def

DOCBOOK=/usr/share/xml/docbook/stylesheet/docbook-xsl/fo  
DOCBOOK=/usr/share/xml/docbook/stylesheet/docbook-xsl/html
LIBRARY=${DOC}/plc-utils
XFLAGS=--skip-validation

# ====================================================================
# symbols;
# --------------------------------------------------------------------

TRASH=*~ *.[0-9][0-9][0-9] t t.* *.1 *.1a *.1.html *.c.html *.cpp.html *.h.html *.hpp.html *.1.html *.1a.html *.sh.html *.xml.html *.xsd.html ch[0-9][0-9]*.html hpp.txt cpp.txt piboffset.* plc-utils.txt cpp.txt hpp.txt
STYLES=param.xsl lists.xsl synop.xsl
BOOKS=index.html 

# ====================================================================
# pseudo targets;
# --------------------------------------------------------------------

all compile: manuals ${BOOKS}
manuals: 
	${SHELL} ../docbook/manuals
scripts:
library: 
	install -m ${DIR_PERM} -o ${OWNER} -g ${GROUP} -d ${LIBRARY}
install: compile library 
	if [ -d ${LIBRARY} ]; then install -m ${WWW_PERM} -o ${OWNER} -g ${GROUP} *.html *.css *.png *.jpg ${LIBRARY}; fi
uninstall:
	rm -f ${LIBRARY}/*.c.html ${LIBRARY}/*.h.html ${LIBRARY}/*.1.html
setup:
	install ${STYLES} ${DOCBOOK}
clean:
	rm -f ${BOOKS} ${TRASH} 
check:
#	${SHELL} docbook.sh
ignore:
	echo ${TOOLS} | tr ' ' '\n' > .gitignore

# ====================================================================
# pseudo targets;
# --------------------------------------------------------------------

index.html: plc-utils.xml *.xml *.png
	xmlto ${XFLAGS} -o . html ${<} 
plc-utils.pdf: *.xml *.png
	docbook2pdf ${<}
plc-utils.txt: *.xml 
	xmlto ${XFLAGS} txt ${<}

