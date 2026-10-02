# Shared by the local and production firmware target definitions.
MT7621_BOARD_PROFILES := C-Life-XG1 H3C-TX180X JCG-Q20 CMCC-A9 CMCC-A9.2 CR660X XY-C3N SIM-AX18 RX6000 G-AX1800 KOMI-A8
ifneq ($(BOARD_PROFILE),)
ifeq ($(filter $(BOARD_PROFILE),$(MT7621_BOARD_PROFILES)),)
$(error Unsupported BOARD_PROFILE '$(BOARD_PROFILE)'; choose one of: $(MT7621_BOARD_PROFILES))
endif
include $(dir $(realpath $(lastword $(MAKEFILE_LIST))))$(BOARD_PROFILE).mak
endif

# RT-AX54 libbwdpi requires the Softwire46 service detection symbols.
export RT-AX54 += IPV6S46=y
