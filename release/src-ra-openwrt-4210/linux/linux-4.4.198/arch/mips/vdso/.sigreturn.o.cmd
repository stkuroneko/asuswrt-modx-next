cmd_arch/mips/vdso/sigreturn.o := /opt/lede-toolchain-ramips-mt7621_gcc-5.4.0_musl-1.1.24.Linux-x86_64/toolchain-mipsel_24kc_gcc-5.4.0_musl-1.1.24/bin/mipsel-openwrt-linux-musl-gcc -Wp,-MD,arch/mips/vdso/.sigreturn.o.d  -nostdinc -isystem /opt/lede-toolchain-ramips-mt7621_gcc-5.4.0_musl-1.1.24.Linux-x86_64/toolchain-mipsel_24kc_gcc-5.4.0_musl-1.1.24/bin/../lib/gcc/mipsel-openwrt-linux-musl/5.4.0/include -I./arch/mips/include -Iarch/mips/include/generated/uapi -Iarch/mips/include/generated  -Iinclude -I./arch/mips/include/uapi -Iarch/mips/include/generated/uapi -I./include/uapi -Iinclude/generated/uapi -include ./include/linux/kconfig.h -D__KERNEL__ -DVMLINUX_LOAD_ADDRESS=0xffffffff80001000+0x1000000 -DDATAOFFSET=0   -I./arch/mips/include/asm/mach-ralink -I./arch/mips/include/asm/mach-ralink/mt7621 -I./arch/mips/include/asm/mach-generic   -march=mips32r2 -msoft-float -D__VDSO__ -I./arch/mips/include/asm/mach-ralink -I./arch/mips/include/asm/mach-ralink/mt7621 -I./arch/mips/include/asm/mach-generic  -D__ASSEMBLY__ -Wa,-gdwarf-2 -mabi=32         -c -o arch/mips/vdso/sigreturn.o arch/mips/vdso/sigreturn.S

source_arch/mips/vdso/sigreturn.o := arch/mips/vdso/sigreturn.S

deps_arch/mips/vdso/sigreturn.o := \
  arch/mips/vdso/vdso.h \
    $(wildcard include/config/64bit.h) \
    $(wildcard include/config/32bit.h) \
    $(wildcard include/config/cpu/mipsr6.h) \
    $(wildcard include/config/clksrc/mips/gic.h) \
  arch/mips/include/uapi/asm/sgidefs.h \
  arch/mips/include/uapi/asm/unistd.h \
  arch/mips/include/asm/regdef.h \
  arch/mips/include/asm/asm.h \
    $(wildcard include/config/printk.h) \
    $(wildcard include/config/cpu/has/prefetch.h) \
    $(wildcard include/config/sgi/ip28.h) \
  arch/mips/include/asm/asm-eva.h \
    $(wildcard include/config/eva.h) \

arch/mips/vdso/sigreturn.o: $(deps_arch/mips/vdso/sigreturn.o)

$(deps_arch/mips/vdso/sigreturn.o):
