#!/bin/sh

. ./flash.info

rm -rf flashimage.bin
rm -rf flashimage.ecc

# Modify input/output image name
UBOOT_NAME=u-boot_v1.0.0.4_RT-ACRH18_20200527.bin
KERNEL_NAME=RT-ACRH18_9.0.0.4_386_8740-g3112e0b.trx
FACTORY_NAME=20200605_RT-ACRH18_Factory_Setting.bin
#FACTORY2_NAME=20200605_RT-ACRH18_Factory_Setting.bin
OUTPUT_NAME=flashimage.bin

# Modify PAGE_SIZE according to SPI Nand device Spec
declare -i PAGE_SIZE=2048
declare -i BLOCK_SIZE=$[$PAGE_SIZE * 64]
declare -i HDR_LY_SIZE=$[$PAGE_SIZE * 2]

hexdump "$UBOOT_NAME" -n 10 -C | grep BOOTLOADER
if [ $? -eq 0 ]; then
	echo "Header included! Remove the old header use new header!"
	dd bs=2048 skip=2 if="$UBOOT_NAME" of=uboot.no_hdr
else
	echo "Header not included, add header!"
	cp "$UBOOT_NAME" uboot.no_hdr
fi

./sbch h "$FLASH_NAME" 0 hdr_ly.binary 1 64 0

# pad device header & layout to u-boot-mtk.bin
declare -i UBOOT_SIZE=`ls uboot.no_hdr -la | awk '{print $5}'`
#echo "UBOOT_SIZE="$UBOOT_SIZE
dd if=uboot.no_hdr of=hdr_ly.binary bs=1 seek="$HDR_LY_SIZE" count="$UBOOT_SIZE" conv=notrunc
cp hdr_ly.binary "$UBOOT_NAME"

# Pad Uboot
# Modify below if Partition layput is changed
# Uboot + config + factorty = 0x100000 + 0X40000 + 0X80000 = 1835008
# Uboot + nvram + factorty + factorty2 = 0xE0000 + 0x100000 + 0x100000 + 0x100000 = 4063232(31)
# Uboot + nvram + factorty + factorty2 = 0xE0000 + 0x100000 = 1966080(15)
# so UBOOT Need to pad to 14 blocks
declare -i UBOOT_SZ=`ls "$UBOOT_NAME"  -la | awk '{print $5}'`
#echo "UBOOT_SZ="$UBOOT_SZ
#declare -i UBOOT_PAD=(4063232/"$BLOCK_SIZE")-"$UBOOT_SZ"/"$BLOCK_SIZE"
declare -i UBOOT_PAD=(1966080/"$BLOCK_SIZE")-"$UBOOT_SZ"/"$BLOCK_SIZE"	#UBOOT_PAD=14

./sbch i "$FLASH_NAME" "$UBOOT_NAME"  u-boot.pad 0 0 "$UBOOT_PAD"

# Kernel is the last image, no pad is necessary

# Generate a single image by attach padded images
cp u-boot.pad "$OUTPUT_NAME"

cat "$FACTORY_NAME" >> "$OUTPUT_NAME"
# Uboot + nvram + factorty = 0x2E0000=3014656
declare -i OUTPUT_SIZE=`ls "$OUTPUT_NAME"  -la | awk '{print $5}'`	#OUTPUT_SIZE=1967104
declare -i F1_PAD=(3014656/"$BLOCK_SIZE")-"$OUTPUT_SIZE"/"$BLOCK_SIZE"	#F1_PAD=8
./sbch i "$FLASH_NAME" "$OUTPUT_NAME"  factory.pad 0 0 "$F1_PAD"

cp factory.pad "$OUTPUT_NAME"
cat "$FACTORY_NAME" >> "$OUTPUT_NAME"

# Uboot + nvram + factorty + factorty2 = 0x3E0000=4063232
declare -i OUTPUT_SIZE=`ls "$OUTPUT_NAME"  -la | awk '{print $5}'`
declare -i F2_PAD=(4063232/"$BLOCK_SIZE")-"$OUTPUT_SIZE"/"$BLOCK_SIZE"
./sbch i "$FLASH_NAME" "$OUTPUT_NAME"  factory2.pad 0 0 "$F2_PAD"

cp factory2.pad "$OUTPUT_NAME"
cat "$KERNEL_NAME" >> "$OUTPUT_NAME"

# Uboot + nvram + factorty + factorty2 + Kernel = 0x35e0000=56492032
declare -i OUTPUT_SIZE=`ls "$OUTPUT_NAME"  -la | awk '{print $5}'`
declare -i K_PAD=(56492032/"$BLOCK_SIZE")-"$OUTPUT_SIZE"/"$BLOCK_SIZE"
./sbch i "$FLASH_NAME" "$OUTPUT_NAME"  kernel.pad 0 0 "$K_PAD"

cp kernel.pad "$OUTPUT_NAME"
cat "$KERNEL_NAME" >> "$OUTPUT_NAME" # Kernel2

# Uboot + nvram + factorty + factorty2 + Kernel + Kernel2 = 0x67e0000=108920832
declare -i OUTPUT_SIZE=`ls "$OUTPUT_NAME"  -la | awk '{print $5}'`
declare -i K2_PAD=(108920832/"$BLOCK_SIZE")-"$OUTPUT_SIZE"/"$BLOCK_SIZE"
./sbch i "$FLASH_NAME" "$OUTPUT_NAME"  kernel2.pad 0 0 "$K2_PAD"

cp kernel2.pad "$OUTPUT_NAME"

# Uboot + nvram + factorty + factorty2 + Kernel + Kernel2 + jffs2 = 0x8000000=128*1024*1024
declare -i OUTPUT_SIZE=`ls "$OUTPUT_NAME"  -la | awk '{print $5}'`
declare -i OUTPAD_PAD=(128*1024*1024/"$BLOCK_SIZE")-"$OUTPUT_SIZE"/"$BLOCK_SIZE"
./sbch i "$FLASH_NAME" "$OUTPUT_NAME"  output.pad 0 0 "$OUTPAD_PAD"

cp output.pad "$OUTPUT_NAME"

rm *.pad -rf
rm *.binary -rf

. ./gen_ecc.sh
