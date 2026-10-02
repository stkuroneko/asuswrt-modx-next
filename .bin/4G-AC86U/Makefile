#*
# ****************************************************************
# *   Copyright 2012, ASUSTek COMPUTER Inc.  All Rights Reserved *
# ****************************************************************
#
# THIS SOFTWARE IS OFFERED "AS IS", AND ASUSTek GRANTS NO WARRANTIES OF ANY
# KIND, EXPRESS OR IMPLIED, BY STATUTE, COMMUNICATION OR OTHERWISE.  ASUSTek
# SPECIFICALLY DISCLAIMS ANY IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS
# FOR A SPECIFIC PURPOSE OR NONINFRINGEMENT CONCERNING THIS SOFTWARE
#

# O:	/PATH/TO/OUTPUT_DIRECTORY
# FW_FN:Firmware filename

ifeq ($(SRCBASE),)
	export SRCBASE := $(shell (cd ../../ && pwd))
endif

-include ../../.config
-include ../../../src/router/common.mak

ifeq ($(and $(O),$(FW_FN)),)
$(error O or FW_FN is not defined)
endif

#FW_FILE = $(O)/$(FW_FN)

all: tools mk_single_img

mk_single_img:
	./mk_single_img.sh $(O) $(FW_FN)

tools:
	$(MAKE) -C ..

.PHONY: all tools mk_single_img
