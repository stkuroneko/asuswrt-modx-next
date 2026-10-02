QUICKSEC_SRCDIR ?= ../../../src

QUICKSEC_ABSSRC = $(shell cd $(QUICKSEC_SRCDIR); pwd)

all: initialize
	$(if $(LINUXDIR),,\
	    $(eval LINUXDIR:= /lib/modules/$(shell uname -r)/build)\
	    $(warning defaulting LINUXDIR to $(LINUXDIR)))
	$(MAKE) -C "$(LINUXDIR)" M="`pwd`" modules

initialize:
	rm -rf obj
	mkdir obj
	cd $(QUICKSEC_SRCDIR)
	( cd $(QUICKSEC_SRCDIR) && find * -type d ) | sort | \
	while read d; do mkdir "obj/$$d"; done
	( cd $(QUICKSEC_SRCDIR) && find * -type f -name '*.[chS]' ) | \
	while read f; do ln -s "$(QUICKSEC_ABSSRC)/$$f" "obj/$$f"; done
	touch $@

clean:
	rm -f initialize
	rm -rf obj quicksec* .quicksec* .tmp_versions [Mm]odule*

-include Makefile.inc
-include Makefile.internal
