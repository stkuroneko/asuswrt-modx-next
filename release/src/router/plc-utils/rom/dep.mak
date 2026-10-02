# ====================================================================
# symbols;
# --------------------------------------------------------------------

ifeq ($(AR7420),y)
NVM=MAC-7420-v1.2.0-01-CS.nvm
PIB=QCA7420-WallAdapter-PL29-EN50561-1.pib
else ifeq ($(QCA7500),y)
NVM=MAC-7500-v2.2.1-00-X-CS.nvm
PIB=QCA7500-WallAdapter_EN50561-1.pib
else ifeq ($(BUILD_NAME),PL-AX56_XP4)
NVM=mac-release-X.nvm
PIB_EU=QCA7550-WallAdapter_EN50561-1_20210506.pib
PIB_US=QCA7550-WallAdapter-HomePlugAV_NorthAmerica_20210513.pib
FM_DIR=$(ROOTFS)/lib/firmware/plc/
else
NVM=xxx
PIB=xxx
$(error NOT define valid data)
endif
