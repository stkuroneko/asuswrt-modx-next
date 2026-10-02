cmd_arch/mips/vdso/vdso.lds := /opt/lede-toolchain-ramips-mt7621_gcc-5.4.0_musl-1.1.24.Linux-x86_64/toolchain-mipsel_24kc_gcc-5.4.0_musl-1.1.24/bin/mipsel-openwrt-linux-musl-gcc -E -Wp,-MD,arch/mips/vdso/.vdso.lds.d  -nostdinc -isystem /opt/lede-toolchain-ramips-mt7621_gcc-5.4.0_musl-1.1.24.Linux-x86_64/toolchain-mipsel_24kc_gcc-5.4.0_musl-1.1.24/bin/../lib/gcc/mipsel-openwrt-linux-musl/5.4.0/include -I./arch/mips/include -Iarch/mips/include/generated/uapi -Iarch/mips/include/generated  -Iinclude -I./arch/mips/include/uapi -Iarch/mips/include/generated/uapi -I./include/uapi -Iinclude/generated/uapi -include ./include/linux/kconfig.h -I./arch/mips/include/asm/mach-ralink -I./arch/mips/include/asm/mach-ralink/mt7621 -I./arch/mips/include/asm/mach-generic   -march=mips32r2 -msoft-float -D__VDSO__ -DDISABLE_MIPS_VDSO -mabi=32    -P -C -Umips -D__ASSEMBLY__ -DLINKER_SCRIPT -o arch/mips/vdso/vdso.lds arch/mips/vdso/vdso.lds.S

source_arch/mips/vdso/vdso.lds := arch/mips/vdso/vdso.lds.S

deps_arch/mips/vdso/vdso.lds := \
  arch/mips/include/uapi/asm/sgidefs.h \

arch/mips/vdso/vdso.lds: $(deps_arch/mips/vdso/vdso.lds)

$(deps_arch/mips/vdso/vdso.lds):
