cmd_usr/initramfs_data.o := /opt/lede-toolchain-ramips-mt7621_gcc-5.4.0_musl-1.1.24.Linux-x86_64/toolchain-mipsel_24kc_gcc-5.4.0_musl-1.1.24/bin/mipsel-openwrt-linux-musl-gcc -Wp,-MD,usr/.initramfs_data.o.d  -nostdinc -isystem /opt/lede-toolchain-ramips-mt7621_gcc-5.4.0_musl-1.1.24.Linux-x86_64/toolchain-mipsel_24kc_gcc-5.4.0_musl-1.1.24/bin/../lib/gcc/mipsel-openwrt-linux-musl/5.4.0/include -I./arch/mips/include -Iarch/mips/include/generated/uapi -Iarch/mips/include/generated  -Iinclude -I./arch/mips/include/uapi -Iarch/mips/include/generated/uapi -I./include/uapi -Iinclude/generated/uapi -include ./include/linux/kconfig.h -D__KERNEL__ -DVMLINUX_LOAD_ADDRESS=0xffffffff80001000+0x1000000 -DDATAOFFSET=0   -D__ASSEMBLY__ -fno-PIE  -mno-check-zero-division -mabi=32 -G 0 -mno-abicalls -fno-pic -pipe -mno-branch-likely -msoft-float -DGAS_HAS_SET_HARDFLOAT -Wa,-msoft-float -ffreestanding  -march=mips32r2 -mtune=34kc -Wa,-mips32r2 -Wa,--trap -I./arch/mips/include/asm/mach-ralink -I./arch/mips/include/asm/mach-ralink/mt7621 -I./arch/mips/include/asm/mach-generic -DCC_HAVE_ASM_GOTO -Wa,-gdwarf-2         -DINITRAMFS_IMAGE="usr/initramfs_data.cpio"   -c -o usr/initramfs_data.o usr/initramfs_data.S

source_usr/initramfs_data.o := usr/initramfs_data.S

deps_usr/initramfs_data.o := \
    $(wildcard include/config/64bit.h) \
  include/linux/stringify.h \
  include/asm-generic/vmlinux.lds.h \
    $(wildcard include/config/hotplug/cpu.h) \
    $(wildcard include/config/memory/hotplug.h) \
    $(wildcard include/config/ftrace/mcount/record.h) \
    $(wildcard include/config/trace/branch/profiling.h) \
    $(wildcard include/config/profile/all/branches.h) \
    $(wildcard include/config/kprobes.h) \
    $(wildcard include/config/event/tracing.h) \
    $(wildcard include/config/tracing.h) \
    $(wildcard include/config/ftrace/syscalls.h) \
    $(wildcard include/config/serial/earlycon.h) \
    $(wildcard include/config/clksrc/of.h) \
    $(wildcard include/config/irqchip.h) \
    $(wildcard include/config/common/clk.h) \
    $(wildcard include/config/of/iommu.h) \
    $(wildcard include/config/of/reserved/mem.h) \
    $(wildcard include/config/smp.h) \
    $(wildcard include/config/cpu/idle.h) \
    $(wildcard include/config/acpi.h) \
    $(wildcard include/config/constructors.h) \
    $(wildcard include/config/generic/bug.h) \
    $(wildcard include/config/pm/trace.h) \
    $(wildcard include/config/blk/dev/initrd.h) \
  include/linux/export.h \
    $(wildcard include/config/have/underscore/symbol/prefix.h) \
    $(wildcard include/config/modules.h) \
    $(wildcard include/config/modversions.h) \
    $(wildcard include/config/unused/symbols.h) \

usr/initramfs_data.o: $(deps_usr/initramfs_data.o)

$(deps_usr/initramfs_data.o):
