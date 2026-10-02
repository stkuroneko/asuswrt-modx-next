	.section .mdebug.abi32
	.previous
	.nan	legacy
	.module	softfloat
	.module	oddspreg

 # -G value = 0, Arch = mips32r2, ISA = 33
 # GNU C89 (LEDE GCC 5.4.0 unknown) version 5.4.0 (mipsel-openwrt-linux-musl)
 #	compiled by GNU C version 7.5.0, GMP version 6.1.2, MPFR version 3.1.5, MPC version 1.0.3
 # GGC heuristics: --param ggc-min-expand=100 --param ggc-min-heapsize=131072
 # options passed:  -nostdinc -I ./arch/mips/include
 # -I arch/mips/include/generated/uapi -I arch/mips/include/generated
 # -I include -I ./arch/mips/include/uapi
 # -I arch/mips/include/generated/uapi -I ./include/uapi
 # -I include/generated/uapi -I ./arch/mips/include/asm/mach-ralink
 # -I ./arch/mips/include/asm/mach-ralink/mt7621
 # -I ./arch/mips/include/asm/mach-generic
 # -iprefix /opt/lede-toolchain-ramips-mt7621_gcc-5.4.0_musl-1.1.24.Linux-x86_64/toolchain-mipsel_24kc_gcc-5.4.0_musl-1.1.24/bin/../lib/gcc/mipsel-openwrt-linux-musl/5.4.0/
 # -isysroot /opt/lede-toolchain-ramips-mt7621_gcc-5.4.0_musl-1.1.24.Linux-x86_64/toolchain-mipsel_24kc_gcc-5.4.0_musl-1.1.24/bin//../..
 # -idirafter /opt/lede-toolchain-ramips-mt7621_gcc-5.4.0_musl-1.1.24.Linux-x86_64/toolchain-mipsel_24kc_gcc-5.4.0_musl-1.1.24/usr/include
 # -D __KERNEL__ -D VMLINUX_LOAD_ADDRESS=0xffffffff80001000+0x1000000
 # -D DATAOFFSET=0 -D GAS_HAS_SET_HARDFLOAT -D CC_HAVE_ASM_GOTO
 # -D KBUILD_STR(s)=#s -D KBUILD_BASENAME=KBUILD_STR(bounds)
 # -D KBUILD_MODNAME=KBUILD_STR(bounds)
 # -isystem /opt/lede-toolchain-ramips-mt7621_gcc-5.4.0_musl-1.1.24.Linux-x86_64/toolchain-mipsel_24kc_gcc-5.4.0_musl-1.1.24/bin/../lib/gcc/mipsel-openwrt-linux-musl/5.4.0/include
 # -include ./include/linux/kconfig.h -MD kernel/.bounds.s.d
 # kernel/bounds.c -G 0 -mel -mno-check-zero-division -mabi=32
 # -mno-abicalls -mno-branch-likely -msoft-float -march=mips32r2
 # -mtune=34kc -mllsc -mplt -mips32r2 -mno-shared
 # -auxbase-strip kernel/bounds.s -g -O2 -Wall -Wundef -Wstrict-prototypes
 # -Wno-trigraphs -Werror=implicit-function-declaration
 # -Wno-format-security -Wno-maybe-uninitialized -Wframe-larger-than=1024
 # -Wno-unused-but-set-variable -Wdeclaration-after-statement
 # -Wno-pointer-sign -Werror=implicit-int -Werror=strict-prototypes
 # -Werror=date-time -std=gnu90 -fno-strict-aliasing -fno-common -fno-pic
 # -ffreestanding -fno-delete-null-pointer-checks -fno-reorder-blocks
 # -fno-tree-ch -fstack-protector -fomit-frame-pointer
 # -fno-var-tracking-assignments -femit-struct-debug-baseonly
 # -fno-var-tracking -fno-strict-overflow -fno-merge-all-constants
 # -fmerge-constants -fstack-check=no -fconserve-stack -ffunction-sections
 # -fdata-sections -fverbose-asm --param allow-store-data-races=0
 # options enabled:  -faggressive-loop-optimizations -falign-functions
 # -falign-jumps -falign-labels -falign-loops -fauto-inc-dec
 # -fbranch-count-reg -fcaller-saves -fchkp-check-incomplete-type
 # -fchkp-check-read -fchkp-check-write -fchkp-instrument-calls
 # -fchkp-narrow-bounds -fchkp-optimize -fchkp-store-bounds
 # -fchkp-use-static-bounds -fchkp-use-static-const-bounds
 # -fchkp-use-wrappers -fcombine-stack-adjustments -fcompare-elim
 # -fcprop-registers -fcrossjumping -fcse-follow-jumps -fdata-sections
 # -fdefer-pop -fdelayed-branch -fdevirtualize -fdevirtualize-speculatively
 # -fdwarf2-cfi-asm -fearly-inlining -feliminate-unused-debug-types
 # -fexpensive-optimizations -fforward-propagate -ffunction-cse
 # -ffunction-sections -fgcse -fgcse-lm -fgnu-runtime -fgnu-unique
 # -fguess-branch-probability -fhoist-adjacent-loads -fident
 # -fif-conversion -fif-conversion2 -findirect-inlining -finline
 # -finline-atomics -finline-functions-called-once -finline-small-functions
 # -fipa-cp -fipa-cp-alignment -fipa-icf -fipa-icf-functions
 # -fipa-icf-variables -fipa-profile -fipa-pure-const -fipa-ra
 # -fipa-reference -fipa-sra -fira-hoist-pressure -fira-share-save-slots
 # -fira-share-spill-slots -fisolate-erroneous-paths-dereference -fivopts
 # -fkeep-static-consts -fleading-underscore -flifetime-dse -flra-remat
 # -flto-odr-type-merging -fmath-errno -fmerge-constants
 # -fmerge-debug-strings -fmove-loop-invariants -fomit-frame-pointer
 # -foptimize-sibling-calls -foptimize-strlen -fpartial-inlining
 # -fpcc-struct-return -fpeephole -fpeephole2 -fplt -fprefetch-loop-arrays
 # -freorder-functions -frerun-cse-after-loop
 # -fsched-critical-path-heuristic -fsched-dep-count-heuristic
 # -fsched-group-heuristic -fsched-interblock -fsched-last-insn-heuristic
 # -fsched-rank-heuristic -fsched-spec -fsched-spec-insn-heuristic
 # -fsched-stalled-insns-dep -fschedule-fusion -fschedule-insns
 # -fschedule-insns2 -fsemantic-interposition -fshow-column -fshrink-wrap
 # -fsigned-zeros -fsplit-ivs-in-unroller -fsplit-wide-types -fssa-phiopt
 # -fstack-protector -fstdarg-opt -fstrict-volatile-bitfields
 # -fsync-libcalls -fthread-jumps -ftoplevel-reorder -ftrapping-math
 # -ftree-bit-ccp -ftree-builtin-call-dce -ftree-ccp -ftree-coalesce-vars
 # -ftree-copy-prop -ftree-copyrename -ftree-cselim -ftree-dce
 # -ftree-dominator-opts -ftree-dse -ftree-forwprop -ftree-fre
 # -ftree-loop-if-convert -ftree-loop-im -ftree-loop-ivcanon
 # -ftree-loop-optimize -ftree-parallelize-loops= -ftree-phiprop -ftree-pre
 # -ftree-pta -ftree-reassoc -ftree-scev-cprop -ftree-sink -ftree-slsr
 # -ftree-sra -ftree-switch-conversion -ftree-tail-merge -ftree-ter
 # -ftree-vrp -funit-at-a-time -fverbose-asm -fzero-initialized-in-bss
 # -mdivide-traps -mdouble-float -mel -mexplicit-relocs -mextern-sdata
 # -mfp-exceptions -mfp32 -mfused-madd -mgp32 -mgpopt -mimadd -mllsc
 # -mlocal-sdata -mlong32 -mlra -mmusl -mno-mdmx -mno-mips16 -mno-mips3d
 # -modd-spreg -mplt -msoft-float -msplit-addresses

	.text
$Ltext0:
	.cfi_sections	.debug_frame
	.section	.text.startup.main,"ax",@progbits
	.align	2
	.globl	main
$LFB149 = .
	.file 1 "kernel/bounds.c"
	.loc 1 16 0
	.cfi_startproc
	.set	nomips16
	.set	nomicromips
	.ent	main
	.type	main, @function
main:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.loc 1 18 0
#APP
 # 18 "kernel/bounds.c" 1
	
.ascii "->NR_PAGEFLAGS 21 __NR_PAGEFLAGS"	 #
 # 0 "" 2
	.loc 1 19 0
 # 19 "kernel/bounds.c" 1
	
.ascii "->MAX_NR_ZONES 3 __MAX_NR_ZONES"	 #
 # 0 "" 2
	.loc 1 21 0
 # 21 "kernel/bounds.c" 1
	
.ascii "->NR_CPUS_BITS 2 ilog2(CONFIG_NR_CPUS)"	 #
 # 0 "" 2
	.loc 1 23 0
 # 23 "kernel/bounds.c" 1
	
.ascii "->SPINLOCK_SIZE 4 sizeof(spinlock_t)"	 #
 # 0 "" 2
	.loc 1 27 0
#NO_APP
	.set	noreorder
	.set	nomacro
	j	$31
	move	$2,$0	 #,
	.set	macro
	.set	reorder

	.end	main
	.cfi_endproc
$LFE149:
	.size	main, .-main
	.text
$Letext0:
	.file 2 "include/linux/page-flags.h"
	.file 3 "include/linux/mmzone.h"
	.file 4 "./arch/mips/include/asm/cpu-info.h"
	.file 5 "include/linux/printk.h"
	.file 6 "include/linux/kernel.h"
	.section	.debug_info,"",@progbits
$Ldebug_info0:
	.4byte	0x1dd
	.2byte	0x4
	.4byte	$Ldebug_abbrev0
	.byte	0x4
	.uleb128 0x1
	.4byte	$LASF50
	.byte	0x1
	.4byte	$LASF51
	.4byte	$LASF52
	.4byte	$Ldebug_ranges0+0
	.4byte	0
	.4byte	$Ldebug_line0
	.uleb128 0x2
	.byte	0x1
	.byte	0x6
	.4byte	$LASF0
	.uleb128 0x2
	.byte	0x1
	.byte	0x8
	.4byte	$LASF1
	.uleb128 0x2
	.byte	0x2
	.byte	0x5
	.4byte	$LASF2
	.uleb128 0x2
	.byte	0x2
	.byte	0x7
	.4byte	$LASF3
	.uleb128 0x3
	.byte	0x4
	.byte	0x5
	.ascii	"int\000"
	.uleb128 0x2
	.byte	0x4
	.byte	0x7
	.4byte	$LASF4
	.uleb128 0x2
	.byte	0x8
	.byte	0x5
	.4byte	$LASF5
	.uleb128 0x2
	.byte	0x8
	.byte	0x7
	.4byte	$LASF6
	.uleb128 0x2
	.byte	0x4
	.byte	0x5
	.4byte	$LASF7
	.uleb128 0x2
	.byte	0x4
	.byte	0x7
	.4byte	$LASF8
	.uleb128 0x2
	.byte	0x1
	.byte	0x6
	.4byte	$LASF9
	.uleb128 0x2
	.byte	0x1
	.byte	0x2
	.4byte	$LASF10
	.uleb128 0x4
	.4byte	$LASF53
	.uleb128 0x5
	.4byte	0x6b
	.uleb128 0x6
	.4byte	$LASF39
	.byte	0x4
	.4byte	0x48
	.byte	0x2
	.byte	0x4a
	.4byte	0x13c
	.uleb128 0x7
	.4byte	$LASF11
	.byte	0
	.uleb128 0x7
	.4byte	$LASF12
	.byte	0x1
	.uleb128 0x7
	.4byte	$LASF13
	.byte	0x2
	.uleb128 0x7
	.4byte	$LASF14
	.byte	0x3
	.uleb128 0x7
	.4byte	$LASF15
	.byte	0x4
	.uleb128 0x7
	.4byte	$LASF16
	.byte	0x5
	.uleb128 0x7
	.4byte	$LASF17
	.byte	0x6
	.uleb128 0x7
	.4byte	$LASF18
	.byte	0x7
	.uleb128 0x7
	.4byte	$LASF19
	.byte	0x8
	.uleb128 0x7
	.4byte	$LASF20
	.byte	0x9
	.uleb128 0x7
	.4byte	$LASF21
	.byte	0xa
	.uleb128 0x7
	.4byte	$LASF22
	.byte	0xb
	.uleb128 0x7
	.4byte	$LASF23
	.byte	0xc
	.uleb128 0x7
	.4byte	$LASF24
	.byte	0xd
	.uleb128 0x7
	.4byte	$LASF25
	.byte	0xe
	.uleb128 0x7
	.4byte	$LASF26
	.byte	0xf
	.uleb128 0x7
	.4byte	$LASF27
	.byte	0x10
	.uleb128 0x7
	.4byte	$LASF28
	.byte	0x11
	.uleb128 0x7
	.4byte	$LASF29
	.byte	0x12
	.uleb128 0x7
	.4byte	$LASF30
	.byte	0x13
	.uleb128 0x7
	.4byte	$LASF31
	.byte	0x14
	.uleb128 0x7
	.4byte	$LASF32
	.byte	0x15
	.uleb128 0x7
	.4byte	$LASF33
	.byte	0x8
	.uleb128 0x7
	.4byte	$LASF34
	.byte	0xc
	.uleb128 0x7
	.4byte	$LASF35
	.byte	0x8
	.uleb128 0x7
	.4byte	$LASF36
	.byte	0x4
	.uleb128 0x7
	.4byte	$LASF37
	.byte	0x8
	.uleb128 0x7
	.4byte	$LASF38
	.byte	0xb
	.byte	0
	.uleb128 0x8
	.4byte	$LASF40
	.byte	0x4
	.4byte	0x48
	.byte	0x3
	.2byte	0x115
	.4byte	0x166
	.uleb128 0x7
	.4byte	$LASF41
	.byte	0
	.uleb128 0x7
	.4byte	$LASF42
	.byte	0x1
	.uleb128 0x7
	.4byte	$LASF43
	.byte	0x2
	.uleb128 0x7
	.4byte	$LASF44
	.byte	0x3
	.byte	0
	.uleb128 0x9
	.4byte	$LASF54
	.byte	0x1
	.byte	0xf
	.4byte	0x41
	.4byte	$LFB149
	.4byte	$LFE149-$LFB149
	.uleb128 0x1
	.byte	0x9c
	.uleb128 0xa
	.4byte	0x79
	.4byte	0x186
	.uleb128 0xb
	.byte	0
	.uleb128 0xc
	.4byte	$LASF45
	.byte	0x4
	.byte	0x60
	.4byte	0x17b
	.uleb128 0xa
	.4byte	0x41
	.4byte	0x19c
	.uleb128 0xb
	.byte	0
	.uleb128 0xc
	.4byte	$LASF46
	.byte	0x5
	.byte	0x2e
	.4byte	0x191
	.uleb128 0xd
	.4byte	$LASF47
	.byte	0x6
	.2byte	0x1c0
	.4byte	0x41
	.uleb128 0xa
	.4byte	0x7e
	.4byte	0x1be
	.uleb128 0xb
	.byte	0
	.uleb128 0xd
	.4byte	$LASF48
	.byte	0x6
	.2byte	0x1f8
	.4byte	0x1ca
	.uleb128 0x5
	.4byte	0x1b3
	.uleb128 0xd
	.4byte	$LASF49
	.byte	0x6
	.2byte	0x203
	.4byte	0x1db
	.uleb128 0x5
	.4byte	0x1b3
	.byte	0
	.section	.debug_abbrev,"",@progbits
$Ldebug_abbrev0:
	.uleb128 0x1
	.uleb128 0x11
	.byte	0x1
	.uleb128 0x25
	.uleb128 0xe
	.uleb128 0x13
	.uleb128 0xb
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x1b
	.uleb128 0xe
	.uleb128 0x55
	.uleb128 0x17
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x10
	.uleb128 0x17
	.byte	0
	.byte	0
	.uleb128 0x2
	.uleb128 0x24
	.byte	0
	.uleb128 0xb
	.uleb128 0xb
	.uleb128 0x3e
	.uleb128 0xb
	.uleb128 0x3
	.uleb128 0xe
	.byte	0
	.byte	0
	.uleb128 0x3
	.uleb128 0x24
	.byte	0
	.uleb128 0xb
	.uleb128 0xb
	.uleb128 0x3e
	.uleb128 0xb
	.uleb128 0x3
	.uleb128 0x8
	.byte	0
	.byte	0
	.uleb128 0x4
	.uleb128 0x13
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3c
	.uleb128 0x19
	.byte	0
	.byte	0
	.uleb128 0x5
	.uleb128 0x26
	.byte	0
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x6
	.uleb128 0x4
	.byte	0x1
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0xb
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x7
	.uleb128 0x28
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x1c
	.uleb128 0xb
	.byte	0
	.byte	0
	.uleb128 0x8
	.uleb128 0x4
	.byte	0x1
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0xb
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0x5
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x9
	.uleb128 0x2e
	.byte	0
	.uleb128 0x3f
	.uleb128 0x19
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x27
	.uleb128 0x19
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x12
	.uleb128 0x6
	.uleb128 0x40
	.uleb128 0x18
	.uleb128 0x2117
	.uleb128 0x19
	.byte	0
	.byte	0
	.uleb128 0xa
	.uleb128 0x1
	.byte	0x1
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0xb
	.uleb128 0x21
	.byte	0
	.byte	0
	.byte	0
	.uleb128 0xc
	.uleb128 0x34
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x3f
	.uleb128 0x19
	.uleb128 0x3c
	.uleb128 0x19
	.byte	0
	.byte	0
	.uleb128 0xd
	.uleb128 0x34
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0x5
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x3f
	.uleb128 0x19
	.uleb128 0x3c
	.uleb128 0x19
	.byte	0
	.byte	0
	.byte	0
	.section	.debug_aranges,"",@progbits
	.4byte	0x1c
	.2byte	0x2
	.4byte	$Ldebug_info0
	.byte	0x4
	.byte	0
	.2byte	0
	.2byte	0
	.4byte	$LFB149
	.4byte	$LFE149-$LFB149
	.4byte	0
	.4byte	0
	.section	.debug_ranges,"",@progbits
$Ldebug_ranges0:
	.4byte	$LFB149
	.4byte	$LFE149
	.4byte	0
	.4byte	0
	.section	.debug_line,"",@progbits
$Ldebug_line0:
	.section	.debug_str,"MS",@progbits,1
$LASF25:
	.ascii	"PG_head\000"
$LASF46:
	.ascii	"console_printk\000"
$LASF21:
	.ascii	"PG_reserved\000"
$LASF42:
	.ascii	"ZONE_NORMAL\000"
$LASF27:
	.ascii	"PG_mappedtodisk\000"
$LASF11:
	.ascii	"PG_locked\000"
$LASF15:
	.ascii	"PG_dirty\000"
$LASF24:
	.ascii	"PG_writeback\000"
$LASF22:
	.ascii	"PG_private\000"
$LASF32:
	.ascii	"__NR_PAGEFLAGS\000"
$LASF53:
	.ascii	"cpuinfo_mips\000"
$LASF44:
	.ascii	"__MAX_NR_ZONES\000"
$LASF34:
	.ascii	"PG_fscache\000"
$LASF38:
	.ascii	"PG_slob_free\000"
$LASF13:
	.ascii	"PG_referenced\000"
$LASF26:
	.ascii	"PG_swapcache\000"
$LASF52:
	.ascii	"/repo/Pass_GPL/asuswrt/release/src-ra-openwrt-4210/linux"
	.ascii	"/linux-4.4.198\000"
$LASF40:
	.ascii	"zone_type\000"
$LASF8:
	.ascii	"long unsigned int\000"
$LASF3:
	.ascii	"short unsigned int\000"
$LASF29:
	.ascii	"PG_swapbacked\000"
$LASF33:
	.ascii	"PG_checked\000"
$LASF1:
	.ascii	"unsigned char\000"
$LASF51:
	.ascii	"kernel/bounds.c\000"
$LASF19:
	.ascii	"PG_owner_priv_1\000"
$LASF50:
	.ascii	"GNU C89 5.4.0 -G 0 -mel -mno-check-zero-division -mabi=3"
	.ascii	"2 -mno-abicalls -mno-branch-likely -msoft-float -march=m"
	.ascii	"ips32r2 -mtune=34kc -mllsc -mplt -mips32r2 -mno-shared -"
	.ascii	"g -O2 -std=gnu90 -fno-strict-aliasing -fno-common -fno-p"
	.ascii	"ic -ffreestanding -fno-delete-null-pointer-checks -fno-r"
	.ascii	"eorder-blocks -fno-tree-ch -fstack-protector -fomit-fram"
	.ascii	"e-pointer -fno-var-tracking-assignments -femit-struct-de"
	.ascii	"bug-baseonly -fno-var-tracking -fno-strict-overflow -fno"
	.ascii	"-merge-all-constants -fmerge-constants -fstack-check=no "
	.ascii	"-fconserve-stack -ffunction-sections -fdata-sections --p"
	.ascii	"aram allow-store-data-races=0\000"
$LASF54:
	.ascii	"main\000"
$LASF39:
	.ascii	"pageflags\000"
$LASF4:
	.ascii	"unsigned int\000"
$LASF12:
	.ascii	"PG_error\000"
$LASF6:
	.ascii	"long long unsigned int\000"
$LASF35:
	.ascii	"PG_pinned\000"
$LASF18:
	.ascii	"PG_slab\000"
$LASF45:
	.ascii	"cpu_data\000"
$LASF49:
	.ascii	"hex_asc_upper\000"
$LASF17:
	.ascii	"PG_active\000"
$LASF23:
	.ascii	"PG_private_2\000"
$LASF5:
	.ascii	"long long int\000"
$LASF16:
	.ascii	"PG_lru\000"
$LASF9:
	.ascii	"char\000"
$LASF30:
	.ascii	"PG_unevictable\000"
$LASF36:
	.ascii	"PG_savepinned\000"
$LASF2:
	.ascii	"short int\000"
$LASF48:
	.ascii	"hex_asc\000"
$LASF20:
	.ascii	"PG_arch_1\000"
$LASF37:
	.ascii	"PG_foreign\000"
$LASF7:
	.ascii	"long int\000"
$LASF43:
	.ascii	"ZONE_MOVABLE\000"
$LASF14:
	.ascii	"PG_uptodate\000"
$LASF0:
	.ascii	"signed char\000"
$LASF28:
	.ascii	"PG_reclaim\000"
$LASF47:
	.ascii	"panic_timeout\000"
$LASF10:
	.ascii	"_Bool\000"
$LASF31:
	.ascii	"PG_mlocked\000"
$LASF41:
	.ascii	"ZONE_DMA\000"
	.ident	"GCC: (LEDE GCC 5.4.0 unknown) 5.4.0"
	.section	.note.GNU-stack,"",@progbits
