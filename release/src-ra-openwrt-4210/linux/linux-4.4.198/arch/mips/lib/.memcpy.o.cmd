cmd_arch/mips/lib/memcpy.o := /opt/lede-toolchain-ramips-mt7621_gcc-5.4.0_musl-1.1.24.Linux-x86_64/toolchain-mipsel_24kc_gcc-5.4.0_musl-1.1.24/bin/mipsel-openwrt-linux-musl-gcc -Wp,-MD,arch/mips/lib/.memcpy.o.d  -nostdinc -isystem /opt/lede-toolchain-ramips-mt7621_gcc-5.4.0_musl-1.1.24.Linux-x86_64/toolchain-mipsel_24kc_gcc-5.4.0_musl-1.1.24/bin/../lib/gcc/mipsel-openwrt-linux-musl/5.4.0/include -I./arch/mips/include -Iarch/mips/include/generated/uapi -Iarch/mips/include/generated  -Iinclude -I./arch/mips/include/uapi -Iarch/mips/include/generated/uapi -I./include/uapi -Iinclude/generated/uapi -include ./include/linux/kconfig.h -D__KERNEL__ -DVMLINUX_LOAD_ADDRESS=0xffffffff80001000+0x1000000 -DDATAOFFSET=0   -D__ASSEMBLY__ -fno-PIE  -mno-check-zero-division -mabi=32 -G 0 -mno-abicalls -fno-pic -pipe -mno-branch-likely -msoft-float -DGAS_HAS_SET_HARDFLOAT -Wa,-msoft-float -ffreestanding  -march=mips32r2 -mtune=34kc -Wa,-mips32r2 -Wa,--trap -I./arch/mips/include/asm/mach-ralink -I./arch/mips/include/asm/mach-ralink/mt7621 -I./arch/mips/include/asm/mach-generic -DCC_HAVE_ASM_GOTO -Wa,-gdwarf-2            -c -o arch/mips/lib/memcpy.o arch/mips/lib/memcpy.S

source_arch/mips/lib/memcpy.o := arch/mips/lib/memcpy.S

deps_arch/mips/lib/memcpy.o := \
    $(wildcard include/config/dma/noncoherent.h) \
    $(wildcard include/config/cpu/has/prefetch.h) \
    $(wildcard include/config/mips/malta.h) \
    $(wildcard include/config/64bit.h) \
    $(wildcard include/config/cpu/little/endian.h) \
    $(wildcard include/config/cpu/daddi/workarounds.h) \
    $(wildcard include/config/cpu/mipsr6.h) \
    $(wildcard include/config/cpu/sb1.h) \
    $(wildcard include/config/eva.h) \
  arch/mips/include/asm/asm.h \
    $(wildcard include/config/printk.h) \
    $(wildcard include/config/sgi/ip28.h) \
  arch/mips/include/uapi/asm/sgidefs.h \
  arch/mips/include/asm/asm-eva.h \
    $(wildcard include/config/32bit.h) \
  arch/mips/include/asm/asm-offsets.h \
  include/generated/asm-offsets.h \
  arch/mips/include/asm/regdef.h \

arch/mips/lib/memcpy.o: $(deps_arch/mips/lib/memcpy.o)

$(deps_arch/mips/lib/memcpy.o):
