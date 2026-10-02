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

BOOTLOADER_VERSION = 1000

$(info $(wildcard $(BUILD_NAME.lds.tmpl)))

FW_FILE = $(O)/$(FW_FN)
BOOT_FILE = $(BUILD_NAME)_$(BOOTLOADER_VERSION).U-BOOT.bin
BIN_FILE = $(addsuffix .FLASH.bin,$(basename $(FW_FN)))

RAW_BOOT_FILE = $(addsuffix .raw_bin,$(basename $(BOOT_FILE)))
RAW_BIN_FILE = $(addsuffix .raw_bin,$(basename $(BIN_FILE)))

$(info FW $(FW_FILE))
$(info BOOT $(BOOT_FILE))
$(info BIN $(BIN_FILE))
$(info RAW_BOOT $(RAW_BOOT_FILE))
$(info RAW_BIN $(RAW_BIN_FILE))

# Flash partition layout
# offset	length		name		block num
# ==========================================================
# 0x00000000	0x000e0000	Bootloader	0~6 (7)
# 0x000e0000	0x00100000	nvram		7~0xE (8)
# 0x001e0000	0x00100000	Factory		0xF~0x16 (8)
# 0x002e0000	0x00100000	Factory2	0xF~0x16 (8)
# 0x003e0000	0x035e0000	linux		0x17~0x18F (0x190)
# 0x035e0000	0x067e0000	linux2		0x190~0x31F (0x190)
# 0x06b80000	0x01400000	jffs2

# dev:    size   erasesize  name
# mtd0: 000e0000 00020000 "Bootloader"
# mtd1: 00100000 00020000 "nvram"
# mtd2: 00100000 00020000 "Factory"
# mtd3: 00100000 00020000 "Factory2"
# mtd4: 03200000 00020000 "Kernel"
# mtd5: 001e0000 00020000 "kernel"
# mtd6: 03035414 00020000 "rootfs"
# mtd7: 03200000 00020000 "Kernel2"
# mtd8: 00140000 00020000 "jffs2"

STAGE1		= u-boot_v1.0.0.1_RT-AX54_20210908.bin
STAGE1_BASE	= 0x00000000
BOOTLOADER	= $(BUILD_NAME).U-BOOT
BOOTLOADER_BASE	= 0x00000000
BOOTLOADER_SIZE	= 0x000e0000
NVRAM_BASE 	= 0x00100000
EEPROM1_BASE	= 0x00000000
#EEPROM2_BASE	= 0x00008000
EEPROM1		= 20210630_RT-AX54_Factory_Setting.bin
TRX1		= $(BUILD_NAME).TRX1.bin
TRX1_BASE 	= 0x003e0000
TRX2		= $(BUILD_NAME).TRX2.bin
TRX2_BASE 	= 0x035e0000
FLASH_SIZE 	= 0x08000000

$(info BOOTLOADER $(BOOTLOADER))

FACTORY1_BASE	= 0x001e0000
FACTORY2_BASE	= 0x002e0000
FACTORY_SIZE	= 0x00100000
FACTORY		= $(BUILD_NAME).FACTORY
FACTORY_POSTFIX	= $(addsuffix .postfix,$(FACTORY))
FACTORY_CHECKSUM	= $(addsuffix .checksum,$(FACTORY))
FACTORY1_CHECKSUM	= $(FACTORY_CHECKSUM).1
FACTORY2_CHECKSUM	= $(FACTORY_CHECKSUM).2

# Print difference between file1 and file2
# $(1): file1
# $(2): file2
define compare_binary_file
	cmp -l $(1) $(2) | awk '{printf "%08X %02X %02X\n", $$1 - 1, strtonum(0$$2), strtonum(0$$3)}'
endef

all: tools clean image $(BUILD_NAME)_PartitionTable.mbn $(BUILD_NAME)_PartitionTable.def

tools:
	$(MAKE) -C ..

$(BUILD_NAME)_PartitionTable.mbn: UDLEN=$(shell echo "(`stat -c %s $(TRX1)` + 131072 - 1)/131072"|bc)
$(BUILD_NAME)_PartitionTable.mbn: image
	@dd if=/dev/zero of=$(BUILD_NAME)_PartitionTable.mbn bs=1 count=256
	@sed -ie "s,\x00,\xff,g" $(BUILD_NAME)_PartitionTable.mbn
	@# Start block:		(0),
	@# End block:		(0),
	@# Length:		First block of bootloader. (1) (unit: block),
	@# 	attribute:	no skip bad-block mechanism and abandon the data if bad-block met.
	@#			(you can request factory to configure software to disallow any bad-block in first 1 block)
	@../modifyData $@ 0x000 hex 00:00:00:00
	@../modifyData $@ 0x004 hex 00:00:00:00
	@../modifyData $@ 0x008 hex 01:00:00:00
	@../modifyData $@ 0x00C hex 00:00:00:00
	@# Start block:		(1),
	@# End block:		(6),
	@# Length:		Rest blocks of bootloader. (6) (unit: block),
	@#	attribute:	skip-bad-block (1), up to 1 (1 << 16) bad-block accepted
	@../modifyData $@ 0x010 hex 01:00:00:00
	@../modifyData $@ 0x014 hex 03:00:00:00
	@../modifyData $@ 0x018 hex 06:00:00:00
	@../modifyData $@ 0x01C hex 01:00:01:00
	@# Start block:		(0xF), first block of factory partition,
	@# End block:		(0x16), end block of factory partition,
	@# Length:		Rest blocks of factory. (8) (unit: block),
	@#	attribute:	skip-bad-block (1), up to 1 (1 << 16) bad-block accepted
	@../modifyData $@ 0x020 hex 0F:00:00:00
	@../modifyData $@ 0x024 hex 16:00:00:00
	@../modifyData $@ 0x028 hex 08:00:00:00
	@../modifyData $@ 0x02C hex 01:00:01:00
	@# Start block:		(0x17), first block of factory2 partition,
	@# End block:		(0x1E), end block of factory2 partition,
	@# Length:		Rest blocks of factory2. (8) (unit: block),
	@#	attribute:	skip-bad-block (1), up to 1 (1 << 16) bad-block accepted
	@../modifyData $@ 0x030 hex 17:00:00:00
	@../modifyData $@ 0x034 hex 1E:00:00:00
	@../modifyData $@ 0x038 hex 08:00:00:00
	@../modifyData $@ 0x03C hex 01:00:01:00
	@# Start block:		(0x1F), first block of linux partition,
	@# End block:		(0x1AE), end block of linux partition,
	@# Length:		linux partition length (unit: block),
	@#	attribute:	skip-bad-block (1), up to 200 (0xC8 << 16) bad-block accepted
	@../modifyData $@ 0x040 hex 1F:00:00:00
	@../modifyData $@ 0x044 hex A6:01:00:00
	@../modifyData $@ 0x048 hex $(shell printf "%02X" `echo "$(UDLEN) % 256"|bc`):$(shell printf "%02X" `echo "$(UDLEN) / 256"|bc`):00:00
	@../modifyData $@ 0x04C hex 01:00:C8:00
	@# Start block:		(0x1AF), first block of linux2 partition,
	@# End block:		(0x33E), end block of linux2 partition,
	@# Length:		linux partition length (unit: block),
	@#	attribute:	skip-bad-block (1), up to 200 (0xC8 << 16) bad-block accepted
	@../modifyData $@ 0x050 hex AF:01:00:00
	@../modifyData $@ 0x054 hex 3E:03:00:00
	@../modifyData $@ 0x058 hex $(shell printf "%02X" `echo "$(UDLEN) % 256"|bc`):$(shell printf "%02X" `echo "$(UDLEN) / 256"|bc`):00:00
	@../modifyData $@ 0x05C hex 01:00:C8:00
	@cp -f $@ $(O)/$@

$(BUILD_NAME)_PartitionTable.def: UDLEN=$(shell echo "(`stat -c %s $(TRX1)` + 131072 - 1)/131072"|bc)
$(BUILD_NAME)_PartitionTable.def: image
	@dd if=/dev/zero of=$(BUILD_NAME)_PartitionTable.def bs=1 count=256
	@sed -ie "s,\x00,\xff,g" $(BUILD_NAME)_PartitionTable.def
	@# Magic number:	"GROUP DEFINE2" ASCIIZ string, 16 bytes
	@../modifyData $@ 0x000 hex 47:52:4F:55:50:20:44:45:46:49:4E:45:32:00:00:00
	@# Attribute:		01:00:00:00 (fix pattern, undocument)
	@# Start block:		(0) of 1st block of bootloader,
	@# End block:		(0xE) of 1st block of bootloader,
	@# Data length:		(2) (unit: block),
	@../modifyData $@ 0x010 hex 01:00:00:00
	@../modifyData $@ 0x014 hex 00:00:00:00
	@../modifyData $@ 0x018 hex 0E:00:00:00
	@../modifyData $@ 0x01C hex 03:00:00:00
	@# Attribute:		01:00:00:00 (fix pattern, undocument)
	@# Start block:		(0xF) of rest blocks of factory,
	@# End block:		(0x16) of rest blocks of factory,
	@# Data length:		(2) (unit: block)
	@../modifyData $@ 0x020 hex 01:00:00:00
	@../modifyData $@ 0x024 hex 0F:00:00:00
	@../modifyData $@ 0x028 hex 16:00:00:00
	@../modifyData $@ 0x02C hex 02:00:00:00
	@# Attribute:		01:00:00:00 (fix pattern, undocument)
	@# Start block:		(0xF) of first blocks of factory2,
	@# End block:		(0x16) of last blocks of factory2,
	@# Data length:		(2) (unit: block)
	@../modifyData $@ 0x030 hex 01:00:00:00
	@../modifyData $@ 0x034 hex 17:00:00:00
	@../modifyData $@ 0x038 hex 1E:00:00:00
	@../modifyData $@ 0x03C hex 02:00:00:00
	@# Attribute:		01:00:00:00 (fix pattern, undocument)
	@# Start block:		(0x1F), fist block of linux partition,
	@# End block:		(0x1AE), last block of linux partition,
	@# Data length:		linux partition length (unit: block)
	@../modifyData $@ 0x040 hex 01:00:00:00
	@../modifyData $@ 0x044 hex 1F:00:00:00
	@../modifyData $@ 0x048 hex AE:01:00:00
	@../modifyData $@ 0x04C hex $(shell printf "%02X" `echo "$(UDLEN) % 256"|bc`):$(shell printf "%02X" `echo "$(UDLEN) / 256"|bc`):00:00
	@# Attribute:		01:00:00:00 (fix pattern, undocument)
	@# Start block:		(0x1AF), fist block of linux2 partition,
	@# End block:		(0x33E), last block of linux2 partition,
	@# Data length:		linux partition length (unit: block)
	@../modifyData $@ 0x050 hex 01:00:00:00
	@../modifyData $@ 0x054 hex AF:01:00:00
	@../modifyData $@ 0x058 hex 3E:03:00:00
	@../modifyData $@ 0x05C hex $(shell printf "%02X" `echo "$(UDLEN) % 256"|bc`):$(shell printf "%02X" `echo "$(UDLEN) / 256"|bc`):00:00
	@cp -f $@ $(O)/$@

image: $(BOOTLOADER) $(FACTORY_POSTFIX) $(FACTORY_CHECKSUM)
	@echo; echo "Prepare image $(BIN_FILE)"
	@cp -f $(FW_FILE) $(TRX1)
	@cp -f $(FW_FILE) $(TRX2)
	@cp -f $(FACTORY_CHECKSUM) $(FACTORY1_CHECKSUM)
	@cp -f $(FACTORY_CHECKSUM) $(FACTORY2_CHECKSUM)
	@sed	-e 's,@BOOTLOADER@,$(BOOTLOADER),' \
		-e 's,@BOOTLOADER_BASE@,$(BOOTLOADER_BASE),' \
		-e 's,@NVRAM_BASE@,$(NVRAM_BASE),' \
		-e 's,@FACTORY1_BASE@,$(FACTORY1_BASE),' \
		-e 's,@FACTORY1@,$(FACTORY1_CHECKSUM),' \
		-e 's,@FACTORY2_BASE@,$(FACTORY2_BASE),' \
		-e 's,@FACTORY2@,$(FACTORY2_CHECKSUM),' \
		-e 's,@TRX1@,$(TRX1),' \
		-e 's,@TRX1_BASE@,$(TRX1_BASE),' \
		-e 's,@TRX2@,$(TRX2),' \
		-e 's,@TRX2_BASE@,$(TRX2_BASE),' \
		$(BUILD_NAME).lds.tmpl > $(BUILD_NAME).lds
	@$(LD) -o $@.o \
		-b binary $(BOOTLOADER) \
		-b binary $(FACTORY1_CHECKSUM) \
		-b binary $(FACTORY2_CHECKSUM) \
		-b binary $(TRX1) \
		-b binary $(TRX2) \
		-T $(BUILD_NAME).lds -Map $(BUILD_NAME).map \
		-b elf32-tradlittlemips
	@$(OBJCOPY) --gap-fill=0xff --pad-to $(FLASH_SIZE) -O binary $@.o $(BIN_FILE)
	@cp -f $(BOOTLOADER) $(BOOT_FILE)
	@./BCH e 2048 64 $(BIN_FILE) $(RAW_BIN_FILE)
	#@sleep 240
	@ls -la $(RAW_BIN_FILE)
	@cp -f $(RAW_BIN_FILE) $(O)/$(RAW_BIN_FILE)

$(BOOTLOADER):
	@echo; echo "Prepare $@"
	@sed	-e 's,@STAGE1@,$(STAGE1),' \
		-e 's,@STAGE1_BASE@,$(STAGE1_BASE),' \
		$(BOOTLOADER).lds.tmpl > $(BOOTLOADER).lds
	@$(LD) -o $@.o \
		-b binary $(STAGE1) \
		-T $(BOOTLOADER).lds -Map $(BOOTLOADER).map \
		-b elf32-tradlittlemips
	@$(OBJCOPY) --gap-fill=0xff --pad-to $(BOOTLOADER_SIZE) -O binary $@.o $(BOOTLOADER)

$(FACTORY_CHECKSUM): $(FACTORY_POSTFIX)
	@echo; echo "Prepare $@"
	@../mk_factory_image2 -c 1 -d $< -o $@
	@echo "Checksum result:"
	@$(call compare_binary_file,$(FACTORY_CHECKSUM),$(FACTORY_POSTFIX))

$(FACTORY_POSTFIX): $(FACTORY)
	@echo; echo "Prepare $@"
	@cp -f $(FACTORY) $(FACTORY_POSTFIX)
	# set 2G default mac
	#../modifyData $(FACTORY_POSTFIX) 0x4 hex 00:0C:43:76:20:50
	# disable br stp 
	../modifyData $(FACTORY_POSTFIX) 0x2ff7e "1"
	# Force USB3 for ATE
	../modifyData $(FACTORY_POSTFIX) 0x2ff60 hex 31
	# set default PIN code
	../modifyData $(FACTORY_POSTFIX) 0x2ff70 "12345670"
	# Replace data at offset 0xff78 to "DB100X".  It should be at offset 0xff78 of source file. The 100X is equal to BOOTLOADER_VERSION.
	../modifyData $(FACTORY_POSTFIX) 0x2ff78 "DB$(BOOTLOADER_VERSION)"
	# 2G_CH14
	#../modifyData $(FACTORY_POSTFIX) 0x234 hex 32:47:5F:43:48:31:34:00:00:00
	# 5G_ALL
	#../modifyData $(FACTORY_POSTFIX) 0x23E hex 35:47:5F:41:4C:4C:00:00:00:00
	# set 5G default mac
	#../modifyData $(FACTORY_POSTFIX) 0x8004 hex 00:0C:43:76:20:54
	# set MTK default HW ID
	../modifyData $(FACTORY_POSTFIX) 0x2fe00 "A"
	@echo "Post fix result:"
	@$(call compare_binary_file,$(FACTORY),$(FACTORY_POSTFIX))

$(FACTORY):
	@echo; echo "Prepare $@"
	@sed	-e 's,@EEPROM1@,$(EEPROM1),' \
		-e 's,@EEPROM1_BASE@,$(EEPROM1_BASE),' \
		$(FACTORY).lds.tmpl > $(FACTORY).lds
	@$(LD) -o $@.o \
		-b binary $(EEPROM1) \
		-T $(FACTORY).lds -Map $(FACTORY).map \
		-b elf32-tradlittlemips
	@$(OBJCOPY) --gap-fill=0xff --pad-to $(FACTORY_SIZE) -O binary $@.o $(FACTORY)

clean:
	@-$(RM) -f *.lds *.o *.ini *.postfix $(BIN_FILE) $(UBI_FILE) $(BOOT_FILE) $(RAW_BIN_FILE) $(RAW_UBI_FILE) $(RAW_BOOT_FILE) *.ecc_log *.mbn *.mbne

.PHONY: all tools clean image $(BUILD_NAME)_PartitionTable.mbn $(BOOTLOADER) $(UBI_DEV) $(FACTORY) $(FACTORY_POSTFIX) $(FACTORY_CHECKSUM) 
