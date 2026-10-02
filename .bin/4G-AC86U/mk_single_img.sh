#!/bin/sh

. ./flash.info

# Modify input/output image name
PRELOADER=preloader_evb7622_64_forspinand-20200518.bin
PRELOADER_NAME=preloader_evb7622_64.bin
ATF_NAME=atf-20200528.bin
UBOOT_NAME=u-boot_v1.0.0.0_4G-AC86U_20200609.bin
FACTORY_NAME=Factory.bin
KERNEL_NAME=$1/$2
OUTPUT_NAME=$1/$2.img
JFFS_NAME=jffs.bin
MT7622_NAME=MT7622_EEPROM.bin
MT7615E_NAME=MT7615E_EEPROM.bin
# Skip first 128k block of preloader header
dd if="$PRELOADER" of="$PRELOADER_NAME" bs=1k skip=128

# Modify BLOCK_SIZE in case nand block size is not 0x20000=131072 
declare -i BLOCK_SIZE=131072

# Modify below if Partition layput is changed
# Preloader = 0x80000 = 524288
# ATF = 0x40000 = 262144
# Uboot + Config  = 0x80000 + 0x100000  = 1572864
# Factory = 0x100000 = 1048576
# Firmwary 0x3200000 = 52428800
# JFFS = 0x1700000 = 24117248

#Create Factory.bin=MT7622_EEPROM.BIN + MT7615E_EEPROM.bin

./sbch i "$FLASH_NAME" "$MT7622_NAME" "$MT7622_NAME".pad 0 0 1
dd if=./"$MT7622_NAME".pad of=./"$FACTORY_NAME" bs=1k count=20
cat "$MT7615E_NAME" >> "$FACTORY_NAME"

declare -i PRELOADER_SZ=`ls "$PRELOADER_NAME" -la | awk '{print $5}'`
declare -i UBOOT_SZ=`ls "$UBOOT_NAME" -la | awk '{print $5}'`
declare -i ATF_SZ=`ls "$ATF_NAME" -la | awk '{print $5}'`
declare -i KERNEL_SZ=`ls "$KERNEL_NAME" -la | awk '{print $5}'`
declare -i FACTORY_SZ=`ls "$FACTORY_NAME" -la | awk '{print $5}'`
declare -i PRELOADER_PAD=(524288/"$BLOCK_SIZE")-1-"$PRELOADER_SZ"/"$BLOCK_SIZE"
declare -i ATF_PAD=(262144/"$BLOCK_SIZE")-"$ATF_SZ"/"$BLOCK_SIZE"
declare -i UBOOT_PAD=(1572864/"$BLOCK_SIZE")-"$UBOOT_SZ"/"$BLOCK_SIZE"
declare -i FACTORY_PAD=(1048576/"$BLOCK_SIZE")-"$FACTORY_SZ"/"$BLOCK_SIZE"
declare -i KERNEL_PAD=(52428800/"$BLOCK_SIZE")-"$KERNEL_SZ"/"$BLOCK_SIZE"

declare -i JFFS_PAD=24117248/"$BLOCK_SIZE"

# Pad each image

# Preloader partition size is 0x80000
# Device-header has 1 block, so preloader image should have 4 - 1 = 3 block
#echo "$PRELOADER_PAD"
#echo "$ATF_PAD"
#echo "$UBOOT_PAD"

./sbch i "$FLASH_NAME" "$PRELOADER_NAME" "$PRELOADER_NAME".pad 0 0 "$PRELOADER_PAD"
./sbch i "$FLASH_NAME" "$PRELOADER_NAME".pad "$PRELOADER_NAME".img 1 64 0

# ATF's size is 0x40000, image size should be 2 block
./sbch i "$FLASH_NAME" "$ATF_NAME" "$ATF_NAME".pad 0 0 "$ATF_PAD"

# Uboot/Config/RF partition has 0x80000 + 0x80000 + 0x40000 = 0x140000
# so UBOOT Need to pad to 10 blocks
./sbch i "$FLASH_NAME" "$UBOOT_NAME" "$UBOOT_NAME".pad 0 0 "$UBOOT_PAD"
./sbch i "$FLASH_NAME" "$FACTORY_NAME" "$FACTORY_NAME".pad 0 0 "$FACTORY_PAD"
./sbch i "$FLASH_NAME" "$KERNEL_NAME" "$2".pad 0 0 "$KERNEL_PAD"
./sbch i "$FLASH_NAME" "$JFFS_NAME" "$JFFS_NAME".pad 0 0 "$JFFS_PAD"

# Kernel is the last image, no pad is necessary

# set MTK default HW ID "A"
../modifyData "$FACTORY_NAME".pad 0xfe00 "A"

# Generate a single image by attach each padded images
cp "$PRELOADER_NAME".img "$OUTPUT_NAME"
cat "$ATF_NAME".pad >> "$OUTPUT_NAME"
cat "$UBOOT_NAME".pad >> "$OUTPUT_NAME"
cat "$FACTORY_NAME".pad >> "$OUTPUT_NAME"
cat "$FACTORY_NAME".pad >> "$OUTPUT_NAME"
cat "$2".pad >> "$OUTPUT_NAME"
cat "$2".pad >> "$OUTPUT_NAME"
cat "$JFFS_NAME".pad >> "$OUTPUT_NAME"

rm *.pad -rf
rm "$PRELOADER_NAME".img
rm "$PRELOADER_NAME"

./sbch e "$FLASH_NAME" "$OUTPUT_NAME" "$OUTPUT_NAME"_ecc 0 0 0
