#!/bin/make -f
# file: docbook2/Makefile

# ====================================================================
# environment definitions;
# --------------------------------------------------------------------

include ../make.def

DOCBOOK=/usr/share/xml/docbook/stylesheet/docbook-xsl/fo  
DOCBOOK=/usr/share/xml/docbook/stylesheet/docbook-xsl/html
LIBRARY=${DOC}/plc-classes

# ====================================================================
# symbols;
# --------------------------------------------------------------------

TRASH=*~ *.[0-9][0-9][0-9] t t.* *.1.html *.c.html *.cpp.html *.h.html *.hpp.html *.1.html *.1a.html *.sh.html *.xml.html *.xsd.html ch[0-9][0-9]*.html 
FILES=Makefile *.txt *.xml *.xsl
STYLES=param.xsl lists.xsl synop.xsl
PAGES=plc-classes.xml 
IMAGES=
BOOKS=plc-classes.html plc-classes.txt  plc-classes.pdf
BOOKS=plc-classes.html 

# ====================================================================
# pseudo targets;
# --------------------------------------------------------------------

all compile: ${BOOKS} 
	change *.html -e "</html>0" -t "</html>"
	rm -fr *.[0-9][0-9][0-9]
manuals: 
scripts:
library:
	install -m ${DIR_PERM} -o ${OWNER} -g ${GROUP} -d ${LIBRARY}
install: compile library manuals
	if [ -d ${LIBRARY} ]; then install -m 0664 -o ${OWNER} -g ${GROUP} *.html *.css *.pdf ${LIBRARY}; fi
uninstall:
	rm -f ${LIBRARY}/*.c.html ${LIBRARY}/*.h.html ${LIBRARY}/*.1.html
setup:
	install ${STYLES} ${DOCBOOK}
clean:
	rm -f ${TRASH} ${BOOKS}
check:
#	${SHELL} docbook2.sh
ignore:
	echo ${TOOLS} | tr ' ' '\n' > .gitignore

# ====================================================================
# pseudo targets;
# --------------------------------------------------------------------

plc-classes.html: ${PAGES}
	xmlto -o . html ${<} 
plc-classes.pdf: ${PAGES} ${IMAGES}
	docbook2pdf ${<}
plc-classes.txt: ${PAGES} 
	xmlto txt ${<}
plc-classes.xml: CPLChannel.xml CPLFirmware.xml CPLMessage.xml CPLNetworks.xml CPLNetwork.xml CPLParameters.xml CPLStation.xml ochannel.xml oerror.xml oethernet.xml oflagword.xml ohomeplug.xml oHPAVKey.xml ointellon.xml ointerfaces.xml ointerface.xml omemory.xml onetwork.xml onumber.xml oSHA256.xml

