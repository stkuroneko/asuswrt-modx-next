#!/usr/bin/make -f
# file: rom/Makefile

# ====================================================================
# environment definitions;
# --------------------------------------------------------------------

include ../make.def
include dep.mak

# ====================================================================
# pseudo targets;
# --------------------------------------------------------------------
export PWD=$(shell pwd)

install:
ifneq ($(PIB_EU),)
	rm -rf $(FM_DIR)
	install -d $(FM_DIR)
	install ${BUILD_NAME}/${NVM} $(FM_DIR)    && cd $(FM_DIR) && ln -sf ${NVM} fw.nvm
	install ${BUILD_NAME}/$(PIB_EU) $(FM_DIR) && cd $(FM_DIR) && cp $(PIB_EU) eu.pib
	install ${BUILD_NAME}/$(PIB_US) $(FM_DIR) && cd $(FM_DIR) && cp $(PIB_US) us.pib
	#set EU pib
	cd $(FM_DIR) && $(PWD)/bin/setpib eu.pib   0xFF byte 0x00	#4BF Membership bit to 0
	cd $(FM_DIR) && $(PWD)/bin/setpib eu.pib 0x231E byte 0x01	#26DE input : GPIO 0
	cd $(FM_DIR) && $(PWD)/bin/setpib eu.pib 0x2320 byte 0x00	#26E0 output: 0
	cd $(FM_DIR) && $(PWD)/bin/setpib eu.pib 0x233B byte 0x01	#26FB Simple Connect ID, GPIO 0
	cd $(FM_DIR) && $(PWD)/bin/setpib eu.pib 0x234D byte 0x00	#270D NMK Randomization, Disable
	cd $(FM_DIR) && $(PWD)/bin/setpib eu.pib 0x2355 byte 0x00	#2715 Factory Defaults, Disable
	cd $(FM_DIR) && $(PWD)/bin/setpib eu.pib 0x2335 byte 0xD0 byte 0x07 byte 0xD0 byte 0x07	#26F5 Min Hold Time (2.00) and Max Hold Time (2.00)
	cd $(FM_DIR) && $(PWD)/bin/setpib eu.pib 0x2339 byte 0x10 byte 0x27                    	#26F9             Error event timer (10000 ms)
	cd $(FM_DIR) && $(PWD)/bin/setpib eu.pib 0x2345 byte 0x10 byte 0x27 byte 0x10 byte 0x27	#2705 Timeout and Error event timer (10000 ms)

	# for Test in CAP and RE
#	cd $(FM_DIR) && $(PWD)/bin/setpib eu.pib  0x136 byte 0x90	#Enable EN50561 Test && Dynamic power
#	cd $(FM_DIR) && $(PWD)/bin/setpib eu.pib   0xF4 byte 0x02
#	cd $(FM_DIR) && $(PWD)/bin/setpib eu.pib 0x10C2 byte 0x01
#	cd $(FM_DIR) && $(PWD)/bin/setpib eu.pib 0x25AF byte 0x03

	# for Test in RE
#	cd $(FM_DIR) && $(PWD)/bin/setpib eu.pib   0xF4 byte 0x01
#	cd $(FM_DIR) && $(PWD)/bin/setpib eu.pib  0x137 byte 0x01	#Enable EN50561 AE Mode for RE


	#set US pib
	cd $(FM_DIR) && $(PWD)/bin/setpib us.pib   0xFF byte 0x00	#4BF Membership bit to 0
	cd $(FM_DIR) && $(PWD)/bin/setpib us.pib 0x231E byte 0x01	#26DE input : GPIO 0
	cd $(FM_DIR) && $(PWD)/bin/setpib us.pib 0x2320 byte 0x00	#26E0 output: 0
	cd $(FM_DIR) && $(PWD)/bin/setpib us.pib 0x233B byte 0x01	#26FB Simple Connect ID, GPIO 0
	cd $(FM_DIR) && $(PWD)/bin/setpib us.pib 0x234D byte 0x00	#270D NMK Randomization, Disable
	cd $(FM_DIR) && $(PWD)/bin/setpib us.pib 0x2355 byte 0x00	#2715 Factory Defaults, Disable
	cd $(FM_DIR) && $(PWD)/bin/setpib us.pib 0x2335 byte 0xD0 byte 0x07 byte 0xD0 byte 0x07	#26F5 Min Hold Time (2.00) and Max Hold Time (2.00)
	cd $(FM_DIR) && $(PWD)/bin/setpib us.pib 0x2339 byte 0x10 byte 0x27                    	#26F9             Error event timer (10000 ms)
	cd $(FM_DIR) && $(PWD)/bin/setpib us.pib 0x2345 byte 0x10 byte 0x27 byte 0x10 byte 0x27	#2705 Timeout and Error event timer (10000 ms)

	cd $(FM_DIR) && cp eu.pib eu_mb.pib && $(PWD)/bin/setpib eu_mb.pib 0xFF byte 0x01	#4BF Membership bit
	cd $(FM_DIR) && cp us.pib us_mb.pib && $(PWD)/bin/setpib us_mb.pib 0xFF byte 0x01	#4BF Membership bit
else
	@if [ -e ${BUILD_NAME}/${NVM} ]; then \
		install ${BUILD_NAME}/${NVM} ${BIN}; \
		cd ${BIN} && ln -sf ${NVM} asus.nvm; \
	fi
	@if [ -e ${BUILD_NAME}/${PIB} ]; then \
		install ${BUILD_NAME}/${PIB} ${BIN}; \
		cd ${BIN} && ln -sf ${PIB} asus.pib; \
	fi
endif
