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
 # -D KBUILD_STR(s)=#s -D KBUILD_BASENAME=KBUILD_STR(asm_offsets)
 # -D KBUILD_MODNAME=KBUILD_STR(asm_offsets)
 # -isystem /opt/lede-toolchain-ramips-mt7621_gcc-5.4.0_musl-1.1.24.Linux-x86_64/toolchain-mipsel_24kc_gcc-5.4.0_musl-1.1.24/bin/../lib/gcc/mipsel-openwrt-linux-musl/5.4.0/include
 # -include ./include/linux/kconfig.h -MD arch/mips/kernel/.asm-offsets.s.d
 # arch/mips/kernel/asm-offsets.c -G 0 -mel -mno-check-zero-division
 # -mabi=32 -mno-abicalls -mno-branch-likely -msoft-float -march=mips32r2
 # -mtune=34kc -mllsc -mplt -mips32r2 -mno-shared
 # -auxbase-strip arch/mips/kernel/asm-offsets.s -g -O2 -Wall -Wundef
 # -Wstrict-prototypes -Wno-trigraphs -Werror=implicit-function-declaration
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
	.section	.text.output_ptreg_defines,"ax",@progbits
	.align	2
	.globl	output_ptreg_defines
$LFB2757 = .
	.file 1 "arch/mips/kernel/asm-offsets.c"
	.loc 1 25 0
	.cfi_startproc
	.set	nomips16
	.set	nomicromips
	.ent	output_ptreg_defines
	.type	output_ptreg_defines, @function
output_ptreg_defines:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.loc 1 26 0
#APP
 # 26 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->#MIPS pt_regs offsets."
 # 0 "" 2
	.loc 1 27 0
 # 27 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->PT_R0 32 offsetof(struct pt_regs, regs[0])"	 #
 # 0 "" 2
	.loc 1 28 0
 # 28 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->PT_R1 36 offsetof(struct pt_regs, regs[1])"	 #
 # 0 "" 2
	.loc 1 29 0
 # 29 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->PT_R2 40 offsetof(struct pt_regs, regs[2])"	 #
 # 0 "" 2
	.loc 1 30 0
 # 30 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->PT_R3 44 offsetof(struct pt_regs, regs[3])"	 #
 # 0 "" 2
	.loc 1 31 0
 # 31 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->PT_R4 48 offsetof(struct pt_regs, regs[4])"	 #
 # 0 "" 2
	.loc 1 32 0
 # 32 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->PT_R5 52 offsetof(struct pt_regs, regs[5])"	 #
 # 0 "" 2
	.loc 1 33 0
 # 33 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->PT_R6 56 offsetof(struct pt_regs, regs[6])"	 #
 # 0 "" 2
	.loc 1 34 0
 # 34 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->PT_R7 60 offsetof(struct pt_regs, regs[7])"	 #
 # 0 "" 2
	.loc 1 35 0
 # 35 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->PT_R8 64 offsetof(struct pt_regs, regs[8])"	 #
 # 0 "" 2
	.loc 1 36 0
 # 36 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->PT_R9 68 offsetof(struct pt_regs, regs[9])"	 #
 # 0 "" 2
	.loc 1 37 0
 # 37 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->PT_R10 72 offsetof(struct pt_regs, regs[10])"	 #
 # 0 "" 2
	.loc 1 38 0
 # 38 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->PT_R11 76 offsetof(struct pt_regs, regs[11])"	 #
 # 0 "" 2
	.loc 1 39 0
 # 39 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->PT_R12 80 offsetof(struct pt_regs, regs[12])"	 #
 # 0 "" 2
	.loc 1 40 0
 # 40 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->PT_R13 84 offsetof(struct pt_regs, regs[13])"	 #
 # 0 "" 2
	.loc 1 41 0
 # 41 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->PT_R14 88 offsetof(struct pt_regs, regs[14])"	 #
 # 0 "" 2
	.loc 1 42 0
 # 42 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->PT_R15 92 offsetof(struct pt_regs, regs[15])"	 #
 # 0 "" 2
	.loc 1 43 0
 # 43 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->PT_R16 96 offsetof(struct pt_regs, regs[16])"	 #
 # 0 "" 2
	.loc 1 44 0
 # 44 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->PT_R17 100 offsetof(struct pt_regs, regs[17])"	 #
 # 0 "" 2
	.loc 1 45 0
 # 45 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->PT_R18 104 offsetof(struct pt_regs, regs[18])"	 #
 # 0 "" 2
	.loc 1 46 0
 # 46 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->PT_R19 108 offsetof(struct pt_regs, regs[19])"	 #
 # 0 "" 2
	.loc 1 47 0
 # 47 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->PT_R20 112 offsetof(struct pt_regs, regs[20])"	 #
 # 0 "" 2
	.loc 1 48 0
 # 48 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->PT_R21 116 offsetof(struct pt_regs, regs[21])"	 #
 # 0 "" 2
	.loc 1 49 0
 # 49 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->PT_R22 120 offsetof(struct pt_regs, regs[22])"	 #
 # 0 "" 2
	.loc 1 50 0
 # 50 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->PT_R23 124 offsetof(struct pt_regs, regs[23])"	 #
 # 0 "" 2
	.loc 1 51 0
 # 51 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->PT_R24 128 offsetof(struct pt_regs, regs[24])"	 #
 # 0 "" 2
	.loc 1 52 0
 # 52 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->PT_R25 132 offsetof(struct pt_regs, regs[25])"	 #
 # 0 "" 2
	.loc 1 53 0
 # 53 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->PT_R26 136 offsetof(struct pt_regs, regs[26])"	 #
 # 0 "" 2
	.loc 1 54 0
 # 54 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->PT_R27 140 offsetof(struct pt_regs, regs[27])"	 #
 # 0 "" 2
	.loc 1 55 0
 # 55 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->PT_R28 144 offsetof(struct pt_regs, regs[28])"	 #
 # 0 "" 2
	.loc 1 56 0
 # 56 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->PT_R29 148 offsetof(struct pt_regs, regs[29])"	 #
 # 0 "" 2
	.loc 1 57 0
 # 57 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->PT_R30 152 offsetof(struct pt_regs, regs[30])"	 #
 # 0 "" 2
	.loc 1 58 0
 # 58 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->PT_R31 156 offsetof(struct pt_regs, regs[31])"	 #
 # 0 "" 2
	.loc 1 59 0
 # 59 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->PT_LO 168 offsetof(struct pt_regs, lo)"	 #
 # 0 "" 2
	.loc 1 60 0
 # 60 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->PT_HI 164 offsetof(struct pt_regs, hi)"	 #
 # 0 "" 2
	.loc 1 64 0
 # 64 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->PT_EPC 180 offsetof(struct pt_regs, cp0_epc)"	 #
 # 0 "" 2
	.loc 1 65 0
 # 65 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->PT_BVADDR 172 offsetof(struct pt_regs, cp0_badvaddr)"	 #
 # 0 "" 2
	.loc 1 66 0
 # 66 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->PT_STATUS 160 offsetof(struct pt_regs, cp0_status)"	 #
 # 0 "" 2
	.loc 1 67 0
 # 67 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->PT_CAUSE 176 offsetof(struct pt_regs, cp0_cause)"	 #
 # 0 "" 2
	.loc 1 72 0
 # 72 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->PT_SIZE 184 sizeof(struct pt_regs)"	 #
 # 0 "" 2
	.loc 1 73 0
 # 73 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->"
 # 0 "" 2
#NO_APP
	j	$31
	.end	output_ptreg_defines
	.cfi_endproc
$LFE2757:
	.size	output_ptreg_defines, .-output_ptreg_defines
	.section	.text.output_task_defines,"ax",@progbits
	.align	2
	.globl	output_task_defines
$LFB2758 = .
	.loc 1 77 0
	.cfi_startproc
	.set	nomips16
	.set	nomicromips
	.ent	output_task_defines
	.type	output_task_defines, @function
output_task_defines:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.loc 1 78 0
#APP
 # 78 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->#MIPS task_struct offsets."
 # 0 "" 2
	.loc 1 79 0
 # 79 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->TASK_STATE 0 offsetof(struct task_struct, state)"	 #
 # 0 "" 2
	.loc 1 80 0
 # 80 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->TASK_THREAD_INFO 4 offsetof(struct task_struct, stack)"	 #
 # 0 "" 2
	.loc 1 81 0
 # 81 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->TASK_FLAGS 12 offsetof(struct task_struct, flags)"	 #
 # 0 "" 2
	.loc 1 82 0
 # 82 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->TASK_MM 452 offsetof(struct task_struct, mm)"	 #
 # 0 "" 2
	.loc 1 83 0
 # 83 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->TASK_PID 584 offsetof(struct task_struct, pid)"	 #
 # 0 "" 2
	.loc 1 85 0
 # 85 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->TASK_STACK_CANARY 592 offsetof(struct task_struct, stack_canary)"	 #
 # 0 "" 2
	.loc 1 87 0
 # 87 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->TASK_STRUCT_SIZE 1504 sizeof(struct task_struct)"	 #
 # 0 "" 2
	.loc 1 88 0
 # 88 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->"
 # 0 "" 2
#NO_APP
	j	$31
	.end	output_task_defines
	.cfi_endproc
$LFE2758:
	.size	output_task_defines, .-output_task_defines
	.section	.text.output_thread_info_defines,"ax",@progbits
	.align	2
	.globl	output_thread_info_defines
$LFB2759 = .
	.loc 1 92 0
	.cfi_startproc
	.set	nomips16
	.set	nomicromips
	.ent	output_thread_info_defines
	.type	output_thread_info_defines, @function
output_thread_info_defines:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.loc 1 93 0
#APP
 # 93 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->#MIPS thread_info offsets."
 # 0 "" 2
	.loc 1 94 0
 # 94 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->TI_TASK 0 offsetof(struct thread_info, task)"	 #
 # 0 "" 2
	.loc 1 95 0
 # 95 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->TI_FLAGS 4 offsetof(struct thread_info, flags)"	 #
 # 0 "" 2
	.loc 1 96 0
 # 96 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->TI_TP_VALUE 8 offsetof(struct thread_info, tp_value)"	 #
 # 0 "" 2
	.loc 1 97 0
 # 97 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->TI_CPU 12 offsetof(struct thread_info, cpu)"	 #
 # 0 "" 2
	.loc 1 98 0
 # 98 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->TI_PRE_COUNT 16 offsetof(struct thread_info, preempt_count)"	 #
 # 0 "" 2
	.loc 1 99 0
 # 99 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->TI_R2_EMUL_RET 20 offsetof(struct thread_info, r2_emul_return)"	 #
 # 0 "" 2
	.loc 1 100 0
 # 100 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->TI_ADDR_LIMIT 24 offsetof(struct thread_info, addr_limit)"	 #
 # 0 "" 2
	.loc 1 101 0
 # 101 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->TI_REGS 28 offsetof(struct thread_info, regs)"	 #
 # 0 "" 2
	.loc 1 102 0
 # 102 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->_THREAD_SIZE 8192 THREAD_SIZE"	 #
 # 0 "" 2
	.loc 1 103 0
 # 103 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->_THREAD_MASK 8191 THREAD_MASK"	 #
 # 0 "" 2
	.loc 1 104 0
 # 104 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->_IRQ_STACK_SIZE 8192 IRQ_STACK_SIZE"	 #
 # 0 "" 2
	.loc 1 105 0
 # 105 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->_IRQ_STACK_START 8176 IRQ_STACK_START"	 #
 # 0 "" 2
	.loc 1 106 0
 # 106 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->"
 # 0 "" 2
#NO_APP
	j	$31
	.end	output_thread_info_defines
	.cfi_endproc
$LFE2759:
	.size	output_thread_info_defines, .-output_thread_info_defines
	.section	.text.output_thread_defines,"ax",@progbits
	.align	2
	.globl	output_thread_defines
$LFB2760 = .
	.loc 1 110 0
	.cfi_startproc
	.set	nomips16
	.set	nomicromips
	.ent	output_thread_defines
	.type	output_thread_defines, @function
output_thread_defines:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.loc 1 111 0
#APP
 # 111 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->#MIPS specific thread_struct offsets."
 # 0 "" 2
	.loc 1 112 0
 # 112 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->THREAD_REG16 1096 offsetof(struct task_struct, thread.reg16)"	 #
 # 0 "" 2
	.loc 1 113 0
 # 113 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->THREAD_REG17 1100 offsetof(struct task_struct, thread.reg17)"	 #
 # 0 "" 2
	.loc 1 114 0
 # 114 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->THREAD_REG18 1104 offsetof(struct task_struct, thread.reg18)"	 #
 # 0 "" 2
	.loc 1 115 0
 # 115 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->THREAD_REG19 1108 offsetof(struct task_struct, thread.reg19)"	 #
 # 0 "" 2
	.loc 1 116 0
 # 116 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->THREAD_REG20 1112 offsetof(struct task_struct, thread.reg20)"	 #
 # 0 "" 2
	.loc 1 117 0
 # 117 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->THREAD_REG21 1116 offsetof(struct task_struct, thread.reg21)"	 #
 # 0 "" 2
	.loc 1 118 0
 # 118 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->THREAD_REG22 1120 offsetof(struct task_struct, thread.reg22)"	 #
 # 0 "" 2
	.loc 1 119 0
 # 119 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->THREAD_REG23 1124 offsetof(struct task_struct, thread.reg23)"	 #
 # 0 "" 2
	.loc 1 120 0
 # 120 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->THREAD_REG29 1128 offsetof(struct task_struct, thread.reg29)"	 #
 # 0 "" 2
	.loc 1 121 0
 # 121 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->THREAD_REG30 1132 offsetof(struct task_struct, thread.reg30)"	 #
 # 0 "" 2
	.loc 1 122 0
 # 122 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->THREAD_REG31 1136 offsetof(struct task_struct, thread.reg31)"	 #
 # 0 "" 2
	.loc 1 123 0
 # 123 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->THREAD_STATUS 1140 offsetof(struct task_struct, thread.cp0_status)"	 #
 # 0 "" 2
	.loc 1 125 0
 # 125 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->THREAD_FPU 1144 offsetof(struct task_struct, thread.fpu)"	 #
 # 0 "" 2
	.loc 1 127 0
 # 127 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->THREAD_BVADDR 1480 offsetof(struct task_struct, thread.cp0_badvaddr)"	 #
 # 0 "" 2
	.loc 1 129 0
 # 129 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->THREAD_BUADDR 1484 offsetof(struct task_struct, thread.cp0_baduaddr)"	 #
 # 0 "" 2
	.loc 1 131 0
 # 131 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->THREAD_ECODE 1488 offsetof(struct task_struct, thread.error_code)"	 #
 # 0 "" 2
	.loc 1 133 0
 # 133 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->THREAD_TRAPNO 1492 offsetof(struct task_struct, thread.trap_nr)"	 #
 # 0 "" 2
	.loc 1 134 0
 # 134 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->"
 # 0 "" 2
#NO_APP
	j	$31
	.end	output_thread_defines
	.cfi_endproc
$LFE2760:
	.size	output_thread_defines, .-output_thread_defines
	.section	.text.output_thread_fpu_defines,"ax",@progbits
	.align	2
	.globl	output_thread_fpu_defines
$LFB2761 = .
	.loc 1 138 0
	.cfi_startproc
	.set	nomips16
	.set	nomicromips
	.ent	output_thread_fpu_defines
	.type	output_thread_fpu_defines, @function
output_thread_fpu_defines:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.loc 1 139 0
#APP
 # 139 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->THREAD_FPR0 1144 offsetof(struct task_struct, thread.fpu.fpr[0])"	 #
 # 0 "" 2
	.loc 1 140 0
 # 140 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->THREAD_FPR1 1152 offsetof(struct task_struct, thread.fpu.fpr[1])"	 #
 # 0 "" 2
	.loc 1 141 0
 # 141 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->THREAD_FPR2 1160 offsetof(struct task_struct, thread.fpu.fpr[2])"	 #
 # 0 "" 2
	.loc 1 142 0
 # 142 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->THREAD_FPR3 1168 offsetof(struct task_struct, thread.fpu.fpr[3])"	 #
 # 0 "" 2
	.loc 1 143 0
 # 143 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->THREAD_FPR4 1176 offsetof(struct task_struct, thread.fpu.fpr[4])"	 #
 # 0 "" 2
	.loc 1 144 0
 # 144 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->THREAD_FPR5 1184 offsetof(struct task_struct, thread.fpu.fpr[5])"	 #
 # 0 "" 2
	.loc 1 145 0
 # 145 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->THREAD_FPR6 1192 offsetof(struct task_struct, thread.fpu.fpr[6])"	 #
 # 0 "" 2
	.loc 1 146 0
 # 146 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->THREAD_FPR7 1200 offsetof(struct task_struct, thread.fpu.fpr[7])"	 #
 # 0 "" 2
	.loc 1 147 0
 # 147 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->THREAD_FPR8 1208 offsetof(struct task_struct, thread.fpu.fpr[8])"	 #
 # 0 "" 2
	.loc 1 148 0
 # 148 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->THREAD_FPR9 1216 offsetof(struct task_struct, thread.fpu.fpr[9])"	 #
 # 0 "" 2
	.loc 1 149 0
 # 149 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->THREAD_FPR10 1224 offsetof(struct task_struct, thread.fpu.fpr[10])"	 #
 # 0 "" 2
	.loc 1 150 0
 # 150 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->THREAD_FPR11 1232 offsetof(struct task_struct, thread.fpu.fpr[11])"	 #
 # 0 "" 2
	.loc 1 151 0
 # 151 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->THREAD_FPR12 1240 offsetof(struct task_struct, thread.fpu.fpr[12])"	 #
 # 0 "" 2
	.loc 1 152 0
 # 152 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->THREAD_FPR13 1248 offsetof(struct task_struct, thread.fpu.fpr[13])"	 #
 # 0 "" 2
	.loc 1 153 0
 # 153 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->THREAD_FPR14 1256 offsetof(struct task_struct, thread.fpu.fpr[14])"	 #
 # 0 "" 2
	.loc 1 154 0
 # 154 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->THREAD_FPR15 1264 offsetof(struct task_struct, thread.fpu.fpr[15])"	 #
 # 0 "" 2
	.loc 1 155 0
 # 155 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->THREAD_FPR16 1272 offsetof(struct task_struct, thread.fpu.fpr[16])"	 #
 # 0 "" 2
	.loc 1 156 0
 # 156 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->THREAD_FPR17 1280 offsetof(struct task_struct, thread.fpu.fpr[17])"	 #
 # 0 "" 2
	.loc 1 157 0
 # 157 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->THREAD_FPR18 1288 offsetof(struct task_struct, thread.fpu.fpr[18])"	 #
 # 0 "" 2
	.loc 1 158 0
 # 158 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->THREAD_FPR19 1296 offsetof(struct task_struct, thread.fpu.fpr[19])"	 #
 # 0 "" 2
	.loc 1 159 0
 # 159 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->THREAD_FPR20 1304 offsetof(struct task_struct, thread.fpu.fpr[20])"	 #
 # 0 "" 2
	.loc 1 160 0
 # 160 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->THREAD_FPR21 1312 offsetof(struct task_struct, thread.fpu.fpr[21])"	 #
 # 0 "" 2
	.loc 1 161 0
 # 161 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->THREAD_FPR22 1320 offsetof(struct task_struct, thread.fpu.fpr[22])"	 #
 # 0 "" 2
	.loc 1 162 0
 # 162 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->THREAD_FPR23 1328 offsetof(struct task_struct, thread.fpu.fpr[23])"	 #
 # 0 "" 2
	.loc 1 163 0
 # 163 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->THREAD_FPR24 1336 offsetof(struct task_struct, thread.fpu.fpr[24])"	 #
 # 0 "" 2
	.loc 1 164 0
 # 164 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->THREAD_FPR25 1344 offsetof(struct task_struct, thread.fpu.fpr[25])"	 #
 # 0 "" 2
	.loc 1 165 0
 # 165 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->THREAD_FPR26 1352 offsetof(struct task_struct, thread.fpu.fpr[26])"	 #
 # 0 "" 2
	.loc 1 166 0
 # 166 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->THREAD_FPR27 1360 offsetof(struct task_struct, thread.fpu.fpr[27])"	 #
 # 0 "" 2
	.loc 1 167 0
 # 167 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->THREAD_FPR28 1368 offsetof(struct task_struct, thread.fpu.fpr[28])"	 #
 # 0 "" 2
	.loc 1 168 0
 # 168 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->THREAD_FPR29 1376 offsetof(struct task_struct, thread.fpu.fpr[29])"	 #
 # 0 "" 2
	.loc 1 169 0
 # 169 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->THREAD_FPR30 1384 offsetof(struct task_struct, thread.fpu.fpr[30])"	 #
 # 0 "" 2
	.loc 1 170 0
 # 170 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->THREAD_FPR31 1392 offsetof(struct task_struct, thread.fpu.fpr[31])"	 #
 # 0 "" 2
	.loc 1 172 0
 # 172 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->THREAD_FCR31 1400 offsetof(struct task_struct, thread.fpu.fcr31)"	 #
 # 0 "" 2
	.loc 1 173 0
 # 173 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->THREAD_MSA_CSR 1404 offsetof(struct task_struct, thread.fpu.msacsr)"	 #
 # 0 "" 2
	.loc 1 174 0
 # 174 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->"
 # 0 "" 2
#NO_APP
	j	$31
	.end	output_thread_fpu_defines
	.cfi_endproc
$LFE2761:
	.size	output_thread_fpu_defines, .-output_thread_fpu_defines
	.section	.text.output_mm_defines,"ax",@progbits
	.align	2
	.globl	output_mm_defines
$LFB2762 = .
	.loc 1 178 0
	.cfi_startproc
	.set	nomips16
	.set	nomicromips
	.ent	output_mm_defines
	.type	output_mm_defines, @function
output_mm_defines:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.loc 1 179 0
#APP
 # 179 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->#Size of struct page"
 # 0 "" 2
	.loc 1 180 0
 # 180 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->STRUCT_PAGE_SIZE 32 sizeof(struct page)"	 #
 # 0 "" 2
	.loc 1 181 0
 # 181 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->"
 # 0 "" 2
	.loc 1 182 0
 # 182 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->#Linux mm_struct offsets."
 # 0 "" 2
	.loc 1 183 0
 # 183 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->MM_USERS 40 offsetof(struct mm_struct, mm_users)"	 #
 # 0 "" 2
	.loc 1 184 0
 # 184 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->MM_PGD 36 offsetof(struct mm_struct, pgd)"	 #
 # 0 "" 2
	.loc 1 185 0
 # 185 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->MM_CONTEXT 352 offsetof(struct mm_struct, context)"	 #
 # 0 "" 2
	.loc 1 186 0
 # 186 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->"
 # 0 "" 2
	.loc 1 187 0
 # 187 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->_PGD_T_SIZE 4 sizeof(pgd_t)"	 #
 # 0 "" 2
	.loc 1 188 0
 # 188 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->_PMD_T_SIZE 4 sizeof(pmd_t)"	 #
 # 0 "" 2
	.loc 1 189 0
 # 189 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->_PTE_T_SIZE 4 sizeof(pte_t)"	 #
 # 0 "" 2
	.loc 1 190 0
 # 190 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->"
 # 0 "" 2
	.loc 1 191 0
 # 191 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->_PGD_T_LOG2 2 PGD_T_LOG2"	 #
 # 0 "" 2
	.loc 1 195 0
 # 195 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->_PTE_T_LOG2 2 PTE_T_LOG2"	 #
 # 0 "" 2
	.loc 1 196 0
 # 196 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->"
 # 0 "" 2
	.loc 1 197 0
 # 197 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->_PGD_ORDER 0 PGD_ORDER"	 #
 # 0 "" 2
	.loc 1 201 0
 # 201 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->_PTE_ORDER 0 PTE_ORDER"	 #
 # 0 "" 2
	.loc 1 202 0
 # 202 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->"
 # 0 "" 2
	.loc 1 203 0
 # 203 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->_PMD_SHIFT 22 PMD_SHIFT"	 #
 # 0 "" 2
	.loc 1 204 0
 # 204 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->_PGDIR_SHIFT 22 PGDIR_SHIFT"	 #
 # 0 "" 2
	.loc 1 205 0
 # 205 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->"
 # 0 "" 2
	.loc 1 206 0
 # 206 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->_PTRS_PER_PGD 1024 PTRS_PER_PGD"	 #
 # 0 "" 2
	.loc 1 207 0
 # 207 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->_PTRS_PER_PMD 1 PTRS_PER_PMD"	 #
 # 0 "" 2
	.loc 1 208 0
 # 208 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->_PTRS_PER_PTE 1024 PTRS_PER_PTE"	 #
 # 0 "" 2
	.loc 1 209 0
 # 209 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->"
 # 0 "" 2
	.loc 1 210 0
 # 210 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->_PAGE_SHIFT 12 PAGE_SHIFT"	 #
 # 0 "" 2
	.loc 1 211 0
 # 211 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->_PAGE_SIZE 4096 PAGE_SIZE"	 #
 # 0 "" 2
	.loc 1 212 0
 # 212 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->"
 # 0 "" 2
#NO_APP
	j	$31
	.end	output_mm_defines
	.cfi_endproc
$LFE2762:
	.size	output_mm_defines, .-output_mm_defines
	.section	.text.output_sc_defines,"ax",@progbits
	.align	2
	.globl	output_sc_defines
$LFB2763 = .
	.loc 1 217 0
	.cfi_startproc
	.set	nomips16
	.set	nomicromips
	.ent	output_sc_defines
	.type	output_sc_defines, @function
output_sc_defines:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.loc 1 218 0
#APP
 # 218 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->#Linux sigcontext offsets."
 # 0 "" 2
	.loc 1 219 0
 # 219 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->SC_REGS 16 offsetof(struct sigcontext, sc_regs)"	 #
 # 0 "" 2
	.loc 1 220 0
 # 220 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->SC_FPREGS 272 offsetof(struct sigcontext, sc_fpregs)"	 #
 # 0 "" 2
	.loc 1 221 0
 # 221 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->SC_ACX 528 offsetof(struct sigcontext, sc_acx)"	 #
 # 0 "" 2
	.loc 1 222 0
 # 222 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->SC_MDHI 552 offsetof(struct sigcontext, sc_mdhi)"	 #
 # 0 "" 2
	.loc 1 223 0
 # 223 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->SC_MDLO 560 offsetof(struct sigcontext, sc_mdlo)"	 #
 # 0 "" 2
	.loc 1 224 0
 # 224 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->SC_PC 8 offsetof(struct sigcontext, sc_pc)"	 #
 # 0 "" 2
	.loc 1 225 0
 # 225 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->SC_FPC_CSR 532 offsetof(struct sigcontext, sc_fpc_csr)"	 #
 # 0 "" 2
	.loc 1 226 0
 # 226 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->SC_FPC_EIR 536 offsetof(struct sigcontext, sc_fpc_eir)"	 #
 # 0 "" 2
	.loc 1 227 0
 # 227 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->SC_HI1 568 offsetof(struct sigcontext, sc_hi1)"	 #
 # 0 "" 2
	.loc 1 228 0
 # 228 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->SC_LO1 572 offsetof(struct sigcontext, sc_lo1)"	 #
 # 0 "" 2
	.loc 1 229 0
 # 229 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->SC_HI2 576 offsetof(struct sigcontext, sc_hi2)"	 #
 # 0 "" 2
	.loc 1 230 0
 # 230 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->SC_LO2 580 offsetof(struct sigcontext, sc_lo2)"	 #
 # 0 "" 2
	.loc 1 231 0
 # 231 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->SC_HI3 584 offsetof(struct sigcontext, sc_hi3)"	 #
 # 0 "" 2
	.loc 1 232 0
 # 232 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->SC_LO3 588 offsetof(struct sigcontext, sc_lo3)"	 #
 # 0 "" 2
	.loc 1 233 0
 # 233 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->"
 # 0 "" 2
#NO_APP
	j	$31
	.end	output_sc_defines
	.cfi_endproc
$LFE2763:
	.size	output_sc_defines, .-output_sc_defines
	.section	.text.output_signal_defined,"ax",@progbits
	.align	2
	.globl	output_signal_defined
$LFB2764 = .
	.loc 1 252 0
	.cfi_startproc
	.set	nomips16
	.set	nomicromips
	.ent	output_signal_defined
	.type	output_signal_defined, @function
output_signal_defined:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.loc 1 253 0
#APP
 # 253 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->#Linux signal numbers."
 # 0 "" 2
	.loc 1 254 0
 # 254 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->_SIGHUP 1 SIGHUP"	 #
 # 0 "" 2
	.loc 1 255 0
 # 255 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->_SIGINT 2 SIGINT"	 #
 # 0 "" 2
	.loc 1 256 0
 # 256 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->_SIGQUIT 3 SIGQUIT"	 #
 # 0 "" 2
	.loc 1 257 0
 # 257 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->_SIGILL 4 SIGILL"	 #
 # 0 "" 2
	.loc 1 258 0
 # 258 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->_SIGTRAP 5 SIGTRAP"	 #
 # 0 "" 2
	.loc 1 259 0
 # 259 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->_SIGIOT 6 SIGIOT"	 #
 # 0 "" 2
	.loc 1 260 0
 # 260 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->_SIGABRT 6 SIGABRT"	 #
 # 0 "" 2
	.loc 1 261 0
 # 261 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->_SIGEMT 7 SIGEMT"	 #
 # 0 "" 2
	.loc 1 262 0
 # 262 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->_SIGFPE 8 SIGFPE"	 #
 # 0 "" 2
	.loc 1 263 0
 # 263 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->_SIGKILL 9 SIGKILL"	 #
 # 0 "" 2
	.loc 1 264 0
 # 264 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->_SIGBUS 10 SIGBUS"	 #
 # 0 "" 2
	.loc 1 265 0
 # 265 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->_SIGSEGV 11 SIGSEGV"	 #
 # 0 "" 2
	.loc 1 266 0
 # 266 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->_SIGSYS 12 SIGSYS"	 #
 # 0 "" 2
	.loc 1 267 0
 # 267 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->_SIGPIPE 13 SIGPIPE"	 #
 # 0 "" 2
	.loc 1 268 0
 # 268 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->_SIGALRM 14 SIGALRM"	 #
 # 0 "" 2
	.loc 1 269 0
 # 269 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->_SIGTERM 15 SIGTERM"	 #
 # 0 "" 2
	.loc 1 270 0
 # 270 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->_SIGUSR1 16 SIGUSR1"	 #
 # 0 "" 2
	.loc 1 271 0
 # 271 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->_SIGUSR2 17 SIGUSR2"	 #
 # 0 "" 2
	.loc 1 272 0
 # 272 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->_SIGCHLD 18 SIGCHLD"	 #
 # 0 "" 2
	.loc 1 273 0
 # 273 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->_SIGPWR 19 SIGPWR"	 #
 # 0 "" 2
	.loc 1 274 0
 # 274 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->_SIGWINCH 20 SIGWINCH"	 #
 # 0 "" 2
	.loc 1 275 0
 # 275 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->_SIGURG 21 SIGURG"	 #
 # 0 "" 2
	.loc 1 276 0
 # 276 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->_SIGIO 22 SIGIO"	 #
 # 0 "" 2
	.loc 1 277 0
 # 277 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->_SIGSTOP 23 SIGSTOP"	 #
 # 0 "" 2
	.loc 1 278 0
 # 278 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->_SIGTSTP 24 SIGTSTP"	 #
 # 0 "" 2
	.loc 1 279 0
 # 279 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->_SIGCONT 25 SIGCONT"	 #
 # 0 "" 2
	.loc 1 280 0
 # 280 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->_SIGTTIN 26 SIGTTIN"	 #
 # 0 "" 2
	.loc 1 281 0
 # 281 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->_SIGTTOU 27 SIGTTOU"	 #
 # 0 "" 2
	.loc 1 282 0
 # 282 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->_SIGVTALRM 28 SIGVTALRM"	 #
 # 0 "" 2
	.loc 1 283 0
 # 283 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->_SIGPROF 29 SIGPROF"	 #
 # 0 "" 2
	.loc 1 284 0
 # 284 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->_SIGXCPU 30 SIGXCPU"	 #
 # 0 "" 2
	.loc 1 285 0
 # 285 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->_SIGXFSZ 31 SIGXFSZ"	 #
 # 0 "" 2
	.loc 1 286 0
 # 286 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->"
 # 0 "" 2
#NO_APP
	j	$31
	.end	output_signal_defined
	.cfi_endproc
$LFE2764:
	.size	output_signal_defined, .-output_signal_defined
	.section	.text.output_kvm_defines,"ax",@progbits
	.align	2
	.globl	output_kvm_defines
$LFB2765 = .
	.loc 1 344 0
	.cfi_startproc
	.set	nomips16
	.set	nomicromips
	.ent	output_kvm_defines
	.type	output_kvm_defines, @function
output_kvm_defines:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.loc 1 345 0
#APP
 # 345 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "-># KVM/MIPS Specfic offsets. "
 # 0 "" 2
	.loc 1 346 0
 # 346 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_ARCH_SIZE 2512 sizeof(struct kvm_vcpu_arch)"	 #
 # 0 "" 2
	.loc 1 347 0
 # 347 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_RUN 56 offsetof(struct kvm_vcpu, run)"	 #
 # 0 "" 2
	.loc 1 348 0
 # 348 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_HOST_ARCH 264 offsetof(struct kvm_vcpu, arch)"	 #
 # 0 "" 2
	.loc 1 350 0
 # 350 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_HOST_EBASE 0 offsetof(struct kvm_vcpu_arch, host_ebase)"	 #
 # 0 "" 2
	.loc 1 351 0
 # 351 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_GUEST_EBASE 4 offsetof(struct kvm_vcpu_arch, guest_ebase)"	 #
 # 0 "" 2
	.loc 1 353 0
 # 353 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_HOST_STACK 12 offsetof(struct kvm_vcpu_arch, host_stack)"	 #
 # 0 "" 2
	.loc 1 354 0
 # 354 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_HOST_GP 16 offsetof(struct kvm_vcpu_arch, host_gp)"	 #
 # 0 "" 2
	.loc 1 356 0
 # 356 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_HOST_CP0_BADVADDR 20 offsetof(struct kvm_vcpu_arch, host_cp0_badvaddr)"	 #
 # 0 "" 2
	.loc 1 357 0
 # 357 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_HOST_CP0_CAUSE 24 offsetof(struct kvm_vcpu_arch, host_cp0_cause)"	 #
 # 0 "" 2
	.loc 1 358 0
 # 358 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_HOST_EPC 28 offsetof(struct kvm_vcpu_arch, host_cp0_epc)"	 #
 # 0 "" 2
	.loc 1 359 0
 # 359 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_HOST_ENTRYHI 32 offsetof(struct kvm_vcpu_arch, host_cp0_entryhi)"	 #
 # 0 "" 2
	.loc 1 361 0
 # 361 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_GUEST_INST 36 offsetof(struct kvm_vcpu_arch, guest_inst)"	 #
 # 0 "" 2
	.loc 1 363 0
 # 363 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_R0 40 offsetof(struct kvm_vcpu_arch, gprs[0])"	 #
 # 0 "" 2
	.loc 1 364 0
 # 364 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_R1 44 offsetof(struct kvm_vcpu_arch, gprs[1])"	 #
 # 0 "" 2
	.loc 1 365 0
 # 365 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_R2 48 offsetof(struct kvm_vcpu_arch, gprs[2])"	 #
 # 0 "" 2
	.loc 1 366 0
 # 366 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_R3 52 offsetof(struct kvm_vcpu_arch, gprs[3])"	 #
 # 0 "" 2
	.loc 1 367 0
 # 367 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_R4 56 offsetof(struct kvm_vcpu_arch, gprs[4])"	 #
 # 0 "" 2
	.loc 1 368 0
 # 368 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_R5 60 offsetof(struct kvm_vcpu_arch, gprs[5])"	 #
 # 0 "" 2
	.loc 1 369 0
 # 369 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_R6 64 offsetof(struct kvm_vcpu_arch, gprs[6])"	 #
 # 0 "" 2
	.loc 1 370 0
 # 370 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_R7 68 offsetof(struct kvm_vcpu_arch, gprs[7])"	 #
 # 0 "" 2
	.loc 1 371 0
 # 371 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_R8 72 offsetof(struct kvm_vcpu_arch, gprs[8])"	 #
 # 0 "" 2
	.loc 1 372 0
 # 372 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_R9 76 offsetof(struct kvm_vcpu_arch, gprs[9])"	 #
 # 0 "" 2
	.loc 1 373 0
 # 373 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_R10 80 offsetof(struct kvm_vcpu_arch, gprs[10])"	 #
 # 0 "" 2
	.loc 1 374 0
 # 374 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_R11 84 offsetof(struct kvm_vcpu_arch, gprs[11])"	 #
 # 0 "" 2
	.loc 1 375 0
 # 375 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_R12 88 offsetof(struct kvm_vcpu_arch, gprs[12])"	 #
 # 0 "" 2
	.loc 1 376 0
 # 376 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_R13 92 offsetof(struct kvm_vcpu_arch, gprs[13])"	 #
 # 0 "" 2
	.loc 1 377 0
 # 377 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_R14 96 offsetof(struct kvm_vcpu_arch, gprs[14])"	 #
 # 0 "" 2
	.loc 1 378 0
 # 378 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_R15 100 offsetof(struct kvm_vcpu_arch, gprs[15])"	 #
 # 0 "" 2
	.loc 1 379 0
 # 379 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_R16 104 offsetof(struct kvm_vcpu_arch, gprs[16])"	 #
 # 0 "" 2
	.loc 1 380 0
 # 380 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_R17 108 offsetof(struct kvm_vcpu_arch, gprs[17])"	 #
 # 0 "" 2
	.loc 1 381 0
 # 381 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_R18 112 offsetof(struct kvm_vcpu_arch, gprs[18])"	 #
 # 0 "" 2
	.loc 1 382 0
 # 382 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_R19 116 offsetof(struct kvm_vcpu_arch, gprs[19])"	 #
 # 0 "" 2
	.loc 1 383 0
 # 383 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_R20 120 offsetof(struct kvm_vcpu_arch, gprs[20])"	 #
 # 0 "" 2
	.loc 1 384 0
 # 384 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_R21 124 offsetof(struct kvm_vcpu_arch, gprs[21])"	 #
 # 0 "" 2
	.loc 1 385 0
 # 385 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_R22 128 offsetof(struct kvm_vcpu_arch, gprs[22])"	 #
 # 0 "" 2
	.loc 1 386 0
 # 386 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_R23 132 offsetof(struct kvm_vcpu_arch, gprs[23])"	 #
 # 0 "" 2
	.loc 1 387 0
 # 387 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_R24 136 offsetof(struct kvm_vcpu_arch, gprs[24])"	 #
 # 0 "" 2
	.loc 1 388 0
 # 388 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_R25 140 offsetof(struct kvm_vcpu_arch, gprs[25])"	 #
 # 0 "" 2
	.loc 1 389 0
 # 389 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_R26 144 offsetof(struct kvm_vcpu_arch, gprs[26])"	 #
 # 0 "" 2
	.loc 1 390 0
 # 390 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_R27 148 offsetof(struct kvm_vcpu_arch, gprs[27])"	 #
 # 0 "" 2
	.loc 1 391 0
 # 391 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_R28 152 offsetof(struct kvm_vcpu_arch, gprs[28])"	 #
 # 0 "" 2
	.loc 1 392 0
 # 392 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_R29 156 offsetof(struct kvm_vcpu_arch, gprs[29])"	 #
 # 0 "" 2
	.loc 1 393 0
 # 393 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_R30 160 offsetof(struct kvm_vcpu_arch, gprs[30])"	 #
 # 0 "" 2
	.loc 1 394 0
 # 394 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_R31 164 offsetof(struct kvm_vcpu_arch, gprs[31])"	 #
 # 0 "" 2
	.loc 1 395 0
 # 395 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_LO 172 offsetof(struct kvm_vcpu_arch, lo)"	 #
 # 0 "" 2
	.loc 1 396 0
 # 396 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_HI 168 offsetof(struct kvm_vcpu_arch, hi)"	 #
 # 0 "" 2
	.loc 1 397 0
 # 397 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_PC 176 offsetof(struct kvm_vcpu_arch, pc)"	 #
 # 0 "" 2
	.loc 1 398 0
 # 398 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->"
 # 0 "" 2
	.loc 1 400 0
 # 400 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_FPR0 184 offsetof(struct kvm_vcpu_arch, fpu.fpr[0])"	 #
 # 0 "" 2
	.loc 1 401 0
 # 401 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_FPR1 192 offsetof(struct kvm_vcpu_arch, fpu.fpr[1])"	 #
 # 0 "" 2
	.loc 1 402 0
 # 402 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_FPR2 200 offsetof(struct kvm_vcpu_arch, fpu.fpr[2])"	 #
 # 0 "" 2
	.loc 1 403 0
 # 403 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_FPR3 208 offsetof(struct kvm_vcpu_arch, fpu.fpr[3])"	 #
 # 0 "" 2
	.loc 1 404 0
 # 404 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_FPR4 216 offsetof(struct kvm_vcpu_arch, fpu.fpr[4])"	 #
 # 0 "" 2
	.loc 1 405 0
 # 405 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_FPR5 224 offsetof(struct kvm_vcpu_arch, fpu.fpr[5])"	 #
 # 0 "" 2
	.loc 1 406 0
 # 406 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_FPR6 232 offsetof(struct kvm_vcpu_arch, fpu.fpr[6])"	 #
 # 0 "" 2
	.loc 1 407 0
 # 407 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_FPR7 240 offsetof(struct kvm_vcpu_arch, fpu.fpr[7])"	 #
 # 0 "" 2
	.loc 1 408 0
 # 408 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_FPR8 248 offsetof(struct kvm_vcpu_arch, fpu.fpr[8])"	 #
 # 0 "" 2
	.loc 1 409 0
 # 409 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_FPR9 256 offsetof(struct kvm_vcpu_arch, fpu.fpr[9])"	 #
 # 0 "" 2
	.loc 1 410 0
 # 410 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_FPR10 264 offsetof(struct kvm_vcpu_arch, fpu.fpr[10])"	 #
 # 0 "" 2
	.loc 1 411 0
 # 411 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_FPR11 272 offsetof(struct kvm_vcpu_arch, fpu.fpr[11])"	 #
 # 0 "" 2
	.loc 1 412 0
 # 412 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_FPR12 280 offsetof(struct kvm_vcpu_arch, fpu.fpr[12])"	 #
 # 0 "" 2
	.loc 1 413 0
 # 413 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_FPR13 288 offsetof(struct kvm_vcpu_arch, fpu.fpr[13])"	 #
 # 0 "" 2
	.loc 1 414 0
 # 414 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_FPR14 296 offsetof(struct kvm_vcpu_arch, fpu.fpr[14])"	 #
 # 0 "" 2
	.loc 1 415 0
 # 415 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_FPR15 304 offsetof(struct kvm_vcpu_arch, fpu.fpr[15])"	 #
 # 0 "" 2
	.loc 1 416 0
 # 416 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_FPR16 312 offsetof(struct kvm_vcpu_arch, fpu.fpr[16])"	 #
 # 0 "" 2
	.loc 1 417 0
 # 417 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_FPR17 320 offsetof(struct kvm_vcpu_arch, fpu.fpr[17])"	 #
 # 0 "" 2
	.loc 1 418 0
 # 418 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_FPR18 328 offsetof(struct kvm_vcpu_arch, fpu.fpr[18])"	 #
 # 0 "" 2
	.loc 1 419 0
 # 419 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_FPR19 336 offsetof(struct kvm_vcpu_arch, fpu.fpr[19])"	 #
 # 0 "" 2
	.loc 1 420 0
 # 420 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_FPR20 344 offsetof(struct kvm_vcpu_arch, fpu.fpr[20])"	 #
 # 0 "" 2
	.loc 1 421 0
 # 421 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_FPR21 352 offsetof(struct kvm_vcpu_arch, fpu.fpr[21])"	 #
 # 0 "" 2
	.loc 1 422 0
 # 422 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_FPR22 360 offsetof(struct kvm_vcpu_arch, fpu.fpr[22])"	 #
 # 0 "" 2
	.loc 1 423 0
 # 423 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_FPR23 368 offsetof(struct kvm_vcpu_arch, fpu.fpr[23])"	 #
 # 0 "" 2
	.loc 1 424 0
 # 424 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_FPR24 376 offsetof(struct kvm_vcpu_arch, fpu.fpr[24])"	 #
 # 0 "" 2
	.loc 1 425 0
 # 425 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_FPR25 384 offsetof(struct kvm_vcpu_arch, fpu.fpr[25])"	 #
 # 0 "" 2
	.loc 1 426 0
 # 426 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_FPR26 392 offsetof(struct kvm_vcpu_arch, fpu.fpr[26])"	 #
 # 0 "" 2
	.loc 1 427 0
 # 427 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_FPR27 400 offsetof(struct kvm_vcpu_arch, fpu.fpr[27])"	 #
 # 0 "" 2
	.loc 1 428 0
 # 428 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_FPR28 408 offsetof(struct kvm_vcpu_arch, fpu.fpr[28])"	 #
 # 0 "" 2
	.loc 1 429 0
 # 429 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_FPR29 416 offsetof(struct kvm_vcpu_arch, fpu.fpr[29])"	 #
 # 0 "" 2
	.loc 1 430 0
 # 430 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_FPR30 424 offsetof(struct kvm_vcpu_arch, fpu.fpr[30])"	 #
 # 0 "" 2
	.loc 1 431 0
 # 431 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_FPR31 432 offsetof(struct kvm_vcpu_arch, fpu.fpr[31])"	 #
 # 0 "" 2
	.loc 1 433 0
 # 433 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_FCR31 440 offsetof(struct kvm_vcpu_arch, fpu.fcr31)"	 #
 # 0 "" 2
	.loc 1 434 0
 # 434 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_MSA_CSR 444 offsetof(struct kvm_vcpu_arch, fpu.msacsr)"	 #
 # 0 "" 2
	.loc 1 435 0
 # 435 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->"
 # 0 "" 2
	.loc 1 437 0
 # 437 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_COP0 452 offsetof(struct kvm_vcpu_arch, cop0)"	 #
 # 0 "" 2
	.loc 1 438 0
 # 438 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_GUEST_KERNEL_ASID 1612 offsetof(struct kvm_vcpu_arch, guest_kernel_asid)"	 #
 # 0 "" 2
	.loc 1 439 0
 # 439 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VCPU_GUEST_USER_ASID 1596 offsetof(struct kvm_vcpu_arch, guest_user_asid)"	 #
 # 0 "" 2
	.loc 1 441 0
 # 441 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->COP0_TLB_HI 320 offsetof(struct mips_coproc, reg[10][0])"	 #
 # 0 "" 2
	.loc 1 442 0
 # 442 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->COP0_STATUS 384 offsetof(struct mips_coproc, reg[12][0])"	 #
 # 0 "" 2
	.loc 1 443 0
 # 443 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->"
 # 0 "" 2
#NO_APP
	j	$31
	.end	output_kvm_defines
	.cfi_endproc
$LFE2765:
	.size	output_kvm_defines, .-output_kvm_defines
	.section	.text.output_cps_defines,"ax",@progbits
	.align	2
	.globl	output_cps_defines
$LFB2766 = .
	.loc 1 448 0
	.cfi_startproc
	.set	nomips16
	.set	nomicromips
	.ent	output_cps_defines
	.type	output_cps_defines, @function
output_cps_defines:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.loc 1 449 0
#APP
 # 449 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "-># MIPS CPS offsets. "
 # 0 "" 2
	.loc 1 451 0
 # 451 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->COREBOOTCFG_VPEMASK 0 offsetof(struct core_boot_config, vpe_mask)"	 #
 # 0 "" 2
	.loc 1 452 0
 # 452 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->COREBOOTCFG_VPECONFIG 4 offsetof(struct core_boot_config, vpe_config)"	 #
 # 0 "" 2
	.loc 1 453 0
 # 453 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->COREBOOTCFG_SIZE 8 sizeof(struct core_boot_config)"	 #
 # 0 "" 2
	.loc 1 455 0
 # 455 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VPEBOOTCFG_PC 0 offsetof(struct vpe_boot_config, pc)"	 #
 # 0 "" 2
	.loc 1 456 0
 # 456 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VPEBOOTCFG_SP 4 offsetof(struct vpe_boot_config, sp)"	 #
 # 0 "" 2
	.loc 1 457 0
 # 457 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VPEBOOTCFG_GP 8 offsetof(struct vpe_boot_config, gp)"	 #
 # 0 "" 2
	.loc 1 458 0
 # 458 "arch/mips/kernel/asm-offsets.c" 1
	
.ascii "->VPEBOOTCFG_SIZE 12 sizeof(struct vpe_boot_config)"	 #
 # 0 "" 2
#NO_APP
	j	$31
	.end	output_cps_defines
	.cfi_endproc
$LFE2766:
	.size	output_cps_defines, .-output_cps_defines
	.text
$Letext0:
	.file 2 "include/linux/types.h"
	.file 3 "include/asm-generic/atomic-long.h"
	.file 4 "include/linux/cpumask.h"
	.file 5 "./arch/mips/include/asm/page.h"
	.file 6 "include/linux/mm.h"
	.file 7 "./arch/mips/include/asm/cpu-info.h"
	.file 8 "include/linux/printk.h"
	.file 9 "include/linux/kernel.h"
	.file 10 "./arch/mips/include/asm/thread_info.h"
	.file 11 "./arch/mips/include/asm/io.h"
	.file 12 "./arch/mips/include/asm/mips-cm.h"
	.file 13 "./arch/mips/include/asm/smp.h"
	.file 14 "./arch/mips/include/asm/smp-ops.h"
	.file 15 "include/linux/jiffies.h"
	.file 16 "include/linux/workqueue.h"
	.file 17 "include/linux/highuid.h"
	.file 18 "include/linux/seq_file.h"
	.file 19 "include/linux/sched.h"
	.file 20 "include/asm-generic/percpu.h"
	.file 21 "include/linux/mmzone.h"
	.file 22 "include/linux/percpu_counter.h"
	.file 23 "include/linux/hrtimer.h"
	.file 24 "include/linux/debug_locks.h"
	.file 25 "./arch/mips/include/asm/pgtable-32.h"
	.file 26 "./arch/mips/include/asm/pgtable.h"
	.file 27 "include/asm-generic/pgtable.h"
	.file 28 "include/linux/vmstat.h"
	.file 29 "include/asm-generic/sections.h"
	.file 30 "include/linux/dcache.h"
	.file 31 "include/linux/quota.h"
	.file 32 "include/linux/fs.h"
	.file 33 "include/linux/jump_label.h"
	.file 34 "include/linux/of.h"
	.file 35 "./arch/mips/include/asm/irq.h"
	.file 36 "include/linux/swap.h"
	.file 37 "include/linux/suspend.h"
	.file 38 "include/linux/slab.h"
	.file 39 "include/linux/interrupt.h"
	.section	.debug_info,"",@progbits
$Ldebug_info0:
	.4byte	0x57d
	.2byte	0x4
	.4byte	$Ldebug_abbrev0
	.byte	0x4
	.uleb128 0x1
	.4byte	$LASF98
	.byte	0x1
	.4byte	$LASF99
	.4byte	$LASF100
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
	.uleb128 0x4
	.4byte	$LASF11
	.byte	0x2
	.byte	0x1d
	.4byte	0x7d
	.uleb128 0x2
	.byte	0x1
	.byte	0x2
	.4byte	$LASF10
	.uleb128 0x5
	.uleb128 0x4
	.4byte	$LASF12
	.byte	0x2
	.byte	0xb1
	.4byte	0x84
	.uleb128 0x6
	.4byte	$LASF14
	.uleb128 0x7
	.4byte	0x6b
	.uleb128 0x4
	.4byte	$LASF13
	.byte	0x3
	.byte	0x1e
	.4byte	0x85
	.uleb128 0x6
	.4byte	$LASF15
	.uleb128 0x4
	.4byte	$LASF16
	.byte	0x4
	.byte	0xf
	.4byte	0xa5
	.uleb128 0x2
	.byte	0x4
	.byte	0x7
	.4byte	$LASF17
	.uleb128 0x6
	.4byte	$LASF18
	.uleb128 0x8
	.byte	0x4
	.uleb128 0x5
	.uleb128 0x4
	.4byte	$LASF19
	.byte	0x5
	.byte	0x80
	.4byte	0xc3
	.uleb128 0x9
	.byte	0x4
	.4byte	0xd5
	.uleb128 0x6
	.4byte	$LASF20
	.uleb128 0x6
	.4byte	$LASF21
	.uleb128 0xa
	.ascii	"pid\000"
	.uleb128 0x9
	.byte	0x4
	.4byte	0xea
	.uleb128 0xb
	.4byte	0xf5
	.uleb128 0xc
	.4byte	0x64
	.byte	0
	.uleb128 0x6
	.4byte	$LASF22
	.uleb128 0x9
	.byte	0x4
	.4byte	0x100
	.uleb128 0x7
	.4byte	0xa5
	.uleb128 0x6
	.4byte	$LASF23
	.uleb128 0xd
	.4byte	$LASF24
	.byte	0x6
	.2byte	0x222
	.4byte	0x116
	.uleb128 0xb
	.4byte	0x121
	.uleb128 0xc
	.4byte	0xcf
	.byte	0
	.uleb128 0x6
	.4byte	$LASF25
	.uleb128 0x6
	.4byte	$LASF26
	.uleb128 0x6
	.4byte	$LASF27
	.uleb128 0x6
	.4byte	$LASF28
	.uleb128 0x9
	.byte	0x4
	.4byte	0x130
	.uleb128 0x6
	.4byte	$LASF29
	.uleb128 0xe
	.4byte	$LASF30
	.byte	0x1
	.byte	0x18
	.4byte	$LFB2757
	.4byte	$LFE2757-$LFB2757
	.uleb128 0x1
	.byte	0x9c
	.uleb128 0xe
	.4byte	$LASF31
	.byte	0x1
	.byte	0x4c
	.4byte	$LFB2758
	.4byte	$LFE2758-$LFB2758
	.uleb128 0x1
	.byte	0x9c
	.uleb128 0xe
	.4byte	$LASF32
	.byte	0x1
	.byte	0x5b
	.4byte	$LFB2759
	.4byte	$LFE2759-$LFB2759
	.uleb128 0x1
	.byte	0x9c
	.uleb128 0xe
	.4byte	$LASF33
	.byte	0x1
	.byte	0x6d
	.4byte	$LFB2760
	.4byte	$LFE2760-$LFB2760
	.uleb128 0x1
	.byte	0x9c
	.uleb128 0xe
	.4byte	$LASF34
	.byte	0x1
	.byte	0x89
	.4byte	$LFB2761
	.4byte	$LFE2761-$LFB2761
	.uleb128 0x1
	.byte	0x9c
	.uleb128 0xe
	.4byte	$LASF35
	.byte	0x1
	.byte	0xb1
	.4byte	$LFB2762
	.4byte	$LFE2762-$LFB2762
	.uleb128 0x1
	.byte	0x9c
	.uleb128 0xe
	.4byte	$LASF36
	.byte	0x1
	.byte	0xd8
	.4byte	$LFB2763
	.4byte	$LFE2763-$LFB2763
	.uleb128 0x1
	.byte	0x9c
	.uleb128 0xe
	.4byte	$LASF37
	.byte	0x1
	.byte	0xfb
	.4byte	$LFB2764
	.4byte	$LFE2764-$LFB2764
	.uleb128 0x1
	.byte	0x9c
	.uleb128 0xf
	.4byte	$LASF38
	.byte	0x1
	.2byte	0x157
	.4byte	$LFB2765
	.4byte	$LFE2765-$LFB2765
	.uleb128 0x1
	.byte	0x9c
	.uleb128 0xf
	.4byte	$LASF39
	.byte	0x1
	.2byte	0x1bf
	.4byte	$LFB2766
	.4byte	$LFE2766-$LFB2766
	.uleb128 0x1
	.byte	0x9c
	.uleb128 0x6
	.4byte	$LASF40
	.uleb128 0x6
	.4byte	$LASF41
	.uleb128 0x6
	.4byte	$LASF42
	.uleb128 0x6
	.4byte	$LASF43
	.uleb128 0x10
	.4byte	0x90
	.4byte	0x20b
	.uleb128 0x11
	.byte	0
	.uleb128 0x12
	.4byte	$LASF44
	.byte	0x7
	.byte	0x60
	.4byte	0x200
	.uleb128 0x10
	.4byte	0x41
	.4byte	0x221
	.uleb128 0x11
	.byte	0
	.uleb128 0x12
	.4byte	$LASF45
	.byte	0x8
	.byte	0x2e
	.4byte	0x216
	.uleb128 0x13
	.4byte	$LASF46
	.byte	0x9
	.2byte	0x1c0
	.4byte	0x41
	.uleb128 0x10
	.4byte	0x95
	.4byte	0x243
	.uleb128 0x11
	.byte	0
	.uleb128 0x13
	.4byte	$LASF47
	.byte	0x9
	.2byte	0x1f8
	.4byte	0x24f
	.uleb128 0x7
	.4byte	0x238
	.uleb128 0x13
	.4byte	$LASF48
	.byte	0x9
	.2byte	0x203
	.4byte	0x260
	.uleb128 0x7
	.4byte	0x238
	.uleb128 0x12
	.4byte	$LASF49
	.byte	0x4
	.byte	0x25
	.4byte	0x41
	.uleb128 0x12
	.4byte	$LASF50
	.byte	0x4
	.byte	0x59
	.4byte	0x27b
	.uleb128 0x7
	.4byte	0xfa
	.uleb128 0x10
	.4byte	0x296
	.4byte	0x296
	.uleb128 0x14
	.4byte	0xb5
	.byte	0x20
	.uleb128 0x14
	.4byte	0xb5
	.byte	0
	.byte	0
	.uleb128 0x7
	.4byte	0x64
	.uleb128 0x13
	.4byte	$LASF51
	.byte	0x4
	.2byte	0x2fc
	.4byte	0x2a7
	.uleb128 0x7
	.4byte	0x280
	.uleb128 0x15
	.4byte	$LASF52
	.byte	0xa
	.byte	0x38
	.4byte	0x2b9
	.uleb128 0x1
	.byte	0x6c
	.uleb128 0x9
	.byte	0x4
	.4byte	0xbc
	.uleb128 0x12
	.4byte	$LASF53
	.byte	0x5
	.byte	0x58
	.4byte	0x64
	.uleb128 0x12
	.4byte	$LASF54
	.byte	0x5
	.byte	0x65
	.4byte	0xe4
	.uleb128 0x12
	.4byte	$LASF55
	.byte	0x6
	.byte	0x22
	.4byte	0x64
	.uleb128 0x12
	.4byte	$LASF56
	.byte	0xb
	.byte	0x3f
	.4byte	0x296
	.uleb128 0x12
	.4byte	$LASF57
	.byte	0xc
	.byte	0x14
	.4byte	0xc1
	.uleb128 0x12
	.4byte	$LASF58
	.byte	0xc
	.byte	0x17
	.4byte	0xc1
	.uleb128 0x12
	.4byte	$LASF59
	.byte	0xc
	.byte	0x31
	.4byte	0x41
	.uleb128 0x12
	.4byte	$LASF60
	.byte	0xd
	.byte	0x17
	.4byte	0x41
	.uleb128 0x12
	.4byte	$LASF61
	.byte	0xd
	.byte	0x69
	.4byte	0x322
	.uleb128 0x9
	.byte	0x4
	.4byte	0xda
	.uleb128 0x12
	.4byte	$LASF62
	.byte	0xe
	.byte	0x44
	.4byte	0xda
	.uleb128 0x12
	.4byte	$LASF63
	.byte	0xe
	.byte	0x61
	.4byte	0xda
	.uleb128 0x10
	.4byte	0xaa
	.4byte	0x349
	.uleb128 0x11
	.byte	0
	.uleb128 0x12
	.4byte	$LASF64
	.byte	0xd
	.byte	0x18
	.4byte	0x33e
	.uleb128 0x12
	.4byte	$LASF65
	.byte	0xf
	.byte	0x4d
	.4byte	0x35f
	.uleb128 0x16
	.4byte	0x64
	.uleb128 0x13
	.4byte	$LASF66
	.byte	0x10
	.2byte	0x161
	.4byte	0x370
	.uleb128 0x9
	.byte	0x4
	.4byte	0x1f1
	.uleb128 0x12
	.4byte	$LASF67
	.byte	0x11
	.byte	0x22
	.4byte	0x41
	.uleb128 0x12
	.4byte	$LASF68
	.byte	0x11
	.byte	0x23
	.4byte	0x41
	.uleb128 0x12
	.4byte	$LASF69
	.byte	0x12
	.byte	0x93
	.4byte	0x1ec
	.uleb128 0x13
	.4byte	$LASF70
	.byte	0x13
	.2byte	0xa55
	.4byte	0x1fb
	.uleb128 0x10
	.4byte	0x64
	.4byte	0x3b3
	.uleb128 0x14
	.4byte	0xb5
	.byte	0x3
	.byte	0
	.uleb128 0x12
	.4byte	$LASF71
	.byte	0x14
	.byte	0x12
	.4byte	0x3a3
	.uleb128 0x12
	.4byte	$LASF72
	.byte	0x15
	.byte	0x4e
	.4byte	0x41
	.uleb128 0x13
	.4byte	$LASF73
	.byte	0x15
	.2byte	0x271
	.4byte	0xcf
	.uleb128 0x13
	.4byte	$LASF74
	.byte	0x15
	.2byte	0x357
	.4byte	0xf5
	.uleb128 0x12
	.4byte	$LASF75
	.byte	0x16
	.byte	0x1c
	.4byte	0x41
	.uleb128 0x13
	.4byte	$LASF76
	.byte	0x17
	.2byte	0x132
	.4byte	0x48
	.uleb128 0x13
	.4byte	$LASF77
	.byte	0x13
	.2byte	0x8ae
	.4byte	0x404
	.uleb128 0x9
	.byte	0x4
	.4byte	0xdf
	.uleb128 0x12
	.4byte	$LASF78
	.byte	0x18
	.byte	0xa
	.4byte	0x41
	.uleb128 0x10
	.4byte	0xc4
	.4byte	0x426
	.uleb128 0x17
	.4byte	0xb5
	.2byte	0x3ff
	.byte	0
	.uleb128 0x12
	.4byte	$LASF79
	.byte	0x19
	.byte	0x59
	.4byte	0x415
	.uleb128 0x12
	.4byte	$LASF80
	.byte	0x1a
	.byte	0x53
	.4byte	0x64
	.uleb128 0x13
	.4byte	$LASF81
	.byte	0x1b
	.2byte	0x261
	.4byte	0x64
	.uleb128 0x10
	.4byte	0x459
	.4byte	0x453
	.uleb128 0x11
	.byte	0
	.uleb128 0x9
	.byte	0x4
	.4byte	0x10a
	.uleb128 0x7
	.4byte	0x453
	.uleb128 0x13
	.4byte	$LASF82
	.byte	0x6
	.2byte	0x22d
	.4byte	0x46a
	.uleb128 0x7
	.4byte	0x448
	.uleb128 0x10
	.4byte	0x9a
	.4byte	0x47f
	.uleb128 0x14
	.4byte	0xb5
	.byte	0x21
	.byte	0
	.uleb128 0x12
	.4byte	$LASF83
	.byte	0x1c
	.byte	0x6f
	.4byte	0x46f
	.uleb128 0x10
	.4byte	0x6b
	.4byte	0x495
	.uleb128 0x11
	.byte	0
	.uleb128 0x12
	.4byte	$LASF84
	.byte	0x1d
	.byte	0x21
	.4byte	0x48a
	.uleb128 0x12
	.4byte	$LASF85
	.byte	0x1d
	.byte	0x21
	.4byte	0x48a
	.uleb128 0x13
	.4byte	$LASF86
	.byte	0x6
	.2byte	0x7ea
	.4byte	0x64
	.uleb128 0x13
	.4byte	$LASF87
	.byte	0x1e
	.2byte	0x20f
	.4byte	0x41
	.uleb128 0x13
	.4byte	$LASF25
	.byte	0x1f
	.2byte	0x105
	.4byte	0x121
	.uleb128 0x13
	.4byte	$LASF88
	.byte	0x20
	.2byte	0x938
	.4byte	0x4db
	.uleb128 0x9
	.byte	0x4
	.4byte	0x126
	.uleb128 0x12
	.4byte	$LASF89
	.byte	0x21
	.byte	0x51
	.4byte	0x72
	.uleb128 0x12
	.4byte	$LASF90
	.byte	0x22
	.byte	0x66
	.4byte	0x12b
	.uleb128 0x12
	.4byte	$LASF91
	.byte	0x22
	.byte	0x86
	.4byte	0x135
	.uleb128 0x10
	.4byte	0xc1
	.4byte	0x512
	.uleb128 0x14
	.4byte	0xb5
	.byte	0x3
	.byte	0
	.uleb128 0x12
	.4byte	$LASF92
	.byte	0x23
	.byte	0x17
	.4byte	0x502
	.uleb128 0x13
	.4byte	$LASF93
	.byte	0x24
	.2byte	0x14d
	.4byte	0x41
	.uleb128 0x13
	.4byte	$LASF94
	.byte	0x24
	.2byte	0x1a2
	.4byte	0x9a
	.uleb128 0x13
	.4byte	$LASF95
	.byte	0x24
	.2byte	0x1a3
	.4byte	0x5d
	.uleb128 0x12
	.4byte	$LASF29
	.byte	0x25
	.byte	0x4a
	.4byte	0x13b
	.uleb128 0x10
	.4byte	0x55c
	.4byte	0x55c
	.uleb128 0x14
	.4byte	0xb5
	.byte	0xd
	.byte	0
	.uleb128 0x9
	.byte	0x4
	.4byte	0x1f6
	.uleb128 0x13
	.4byte	$LASF96
	.byte	0x26
	.2byte	0x10d
	.4byte	0x54c
	.uleb128 0x13
	.4byte	$LASF97
	.byte	0x27
	.2byte	0x1cd
	.4byte	0x57a
	.uleb128 0x9
	.byte	0x4
	.4byte	0x105
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
	.uleb128 0x16
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x5
	.uleb128 0x13
	.byte	0
	.uleb128 0x3c
	.uleb128 0x19
	.byte	0
	.byte	0
	.uleb128 0x6
	.uleb128 0x13
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3c
	.uleb128 0x19
	.byte	0
	.byte	0
	.uleb128 0x7
	.uleb128 0x26
	.byte	0
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x8
	.uleb128 0xf
	.byte	0
	.uleb128 0xb
	.uleb128 0xb
	.byte	0
	.byte	0
	.uleb128 0x9
	.uleb128 0xf
	.byte	0
	.uleb128 0xb
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0xa
	.uleb128 0x13
	.byte	0
	.uleb128 0x3
	.uleb128 0x8
	.uleb128 0x3c
	.uleb128 0x19
	.byte	0
	.byte	0
	.uleb128 0xb
	.uleb128 0x15
	.byte	0x1
	.uleb128 0x27
	.uleb128 0x19
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0xc
	.uleb128 0x5
	.byte	0
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0xd
	.uleb128 0x16
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0x5
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0xe
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
	.uleb128 0xf
	.uleb128 0x2e
	.byte	0
	.uleb128 0x3f
	.uleb128 0x19
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0x5
	.uleb128 0x27
	.uleb128 0x19
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
	.uleb128 0x10
	.uleb128 0x1
	.byte	0x1
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x11
	.uleb128 0x21
	.byte	0
	.byte	0
	.byte	0
	.uleb128 0x12
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
	.uleb128 0x13
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
	.uleb128 0x14
	.uleb128 0x21
	.byte	0
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x2f
	.uleb128 0xb
	.byte	0
	.byte	0
	.uleb128 0x15
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
	.uleb128 0x2
	.uleb128 0x18
	.byte	0
	.byte	0
	.uleb128 0x16
	.uleb128 0x35
	.byte	0
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x17
	.uleb128 0x21
	.byte	0
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x2f
	.uleb128 0x5
	.byte	0
	.byte	0
	.byte	0
	.section	.debug_aranges,"",@progbits
	.4byte	0x64
	.2byte	0x2
	.4byte	$Ldebug_info0
	.byte	0x4
	.byte	0
	.2byte	0
	.2byte	0
	.4byte	$LFB2757
	.4byte	$LFE2757-$LFB2757
	.4byte	$LFB2758
	.4byte	$LFE2758-$LFB2758
	.4byte	$LFB2759
	.4byte	$LFE2759-$LFB2759
	.4byte	$LFB2760
	.4byte	$LFE2760-$LFB2760
	.4byte	$LFB2761
	.4byte	$LFE2761-$LFB2761
	.4byte	$LFB2762
	.4byte	$LFE2762-$LFB2762
	.4byte	$LFB2763
	.4byte	$LFE2763-$LFB2763
	.4byte	$LFB2764
	.4byte	$LFE2764-$LFB2764
	.4byte	$LFB2765
	.4byte	$LFE2765-$LFB2765
	.4byte	$LFB2766
	.4byte	$LFE2766-$LFB2766
	.4byte	0
	.4byte	0
	.section	.debug_ranges,"",@progbits
$Ldebug_ranges0:
	.4byte	$LFB2757
	.4byte	$LFE2757
	.4byte	$LFB2758
	.4byte	$LFE2758
	.4byte	$LFB2759
	.4byte	$LFE2759
	.4byte	$LFB2760
	.4byte	$LFE2760
	.4byte	$LFB2761
	.4byte	$LFE2761
	.4byte	$LFB2762
	.4byte	$LFE2762
	.4byte	$LFB2763
	.4byte	$LFE2763
	.4byte	$LFB2764
	.4byte	$LFE2764
	.4byte	$LFB2765
	.4byte	$LFE2765
	.4byte	$LFB2766
	.4byte	$LFE2766
	.4byte	0
	.4byte	0
	.section	.debug_line,"",@progbits
$Ldebug_line0:
	.section	.debug_str,"MS",@progbits,1
$LASF21:
	.ascii	"plat_smp_ops\000"
$LASF44:
	.ascii	"cpu_data\000"
$LASF40:
	.ascii	"user_namespace\000"
$LASF94:
	.ascii	"nr_swap_pages\000"
$LASF85:
	.ascii	"__init_end\000"
$LASF55:
	.ascii	"max_mapnr\000"
$LASF76:
	.ascii	"hrtimer_resolution\000"
$LASF46:
	.ascii	"panic_timeout\000"
$LASF87:
	.ascii	"sysctl_vfs_cache_pressure\000"
$LASF26:
	.ascii	"super_block\000"
$LASF2:
	.ascii	"short int\000"
$LASF61:
	.ascii	"mp_ops\000"
$LASF90:
	.ascii	"of_node_ktype\000"
$LASF23:
	.ascii	"task_struct\000"
$LASF91:
	.ascii	"of_root\000"
$LASF16:
	.ascii	"cpumask_t\000"
$LASF70:
	.ascii	"init_pid_ns\000"
$LASF86:
	.ascii	"stack_guard_gap\000"
$LASF95:
	.ascii	"total_swap_pages\000"
$LASF31:
	.ascii	"output_task_defines\000"
$LASF63:
	.ascii	"vsmp_smp_ops\000"
$LASF69:
	.ascii	"init_user_ns\000"
$LASF77:
	.ascii	"cad_pid\000"
$LASF50:
	.ascii	"cpu_online_mask\000"
$LASF83:
	.ascii	"vm_stat\000"
$LASF45:
	.ascii	"console_printk\000"
$LASF100:
	.ascii	"/repo/Fail_GPL/asuswrt/release/src-ra-openwrt-4210/linux"
	.ascii	"/linux-4.4.198\000"
$LASF43:
	.ascii	"pid_namespace\000"
$LASF14:
	.ascii	"cpuinfo_mips\000"
$LASF11:
	.ascii	"bool\000"
$LASF99:
	.ascii	"arch/mips/kernel/asm-offsets.c\000"
$LASF88:
	.ascii	"blockdev_superblock\000"
$LASF29:
	.ascii	"suspend_stats\000"
$LASF66:
	.ascii	"system_wq\000"
$LASF78:
	.ascii	"debug_locks\000"
$LASF5:
	.ascii	"long long int\000"
$LASF36:
	.ascii	"output_sc_defines\000"
$LASF71:
	.ascii	"__per_cpu_offset\000"
$LASF75:
	.ascii	"percpu_counter_batch\000"
$LASF20:
	.ascii	"page\000"
$LASF7:
	.ascii	"long int\000"
$LASF39:
	.ascii	"output_cps_defines\000"
$LASF58:
	.ascii	"mips_cm_l2sync_base\000"
$LASF56:
	.ascii	"mips_io_port_base\000"
$LASF34:
	.ascii	"output_thread_fpu_defines\000"
$LASF35:
	.ascii	"output_mm_defines\000"
$LASF38:
	.ascii	"output_kvm_defines\000"
$LASF18:
	.ascii	"thread_info\000"
$LASF84:
	.ascii	"__init_begin\000"
$LASF62:
	.ascii	"up_smp_ops\000"
$LASF32:
	.ascii	"output_thread_info_defines\000"
$LASF28:
	.ascii	"device_node\000"
$LASF13:
	.ascii	"atomic_long_t\000"
$LASF98:
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
$LASF1:
	.ascii	"unsigned char\000"
$LASF68:
	.ascii	"overflowgid\000"
$LASF19:
	.ascii	"pte_t\000"
$LASF0:
	.ascii	"signed char\000"
$LASF73:
	.ascii	"mem_map\000"
$LASF6:
	.ascii	"long long unsigned int\000"
$LASF37:
	.ascii	"output_signal_defined\000"
$LASF4:
	.ascii	"unsigned int\000"
$LASF33:
	.ascii	"output_thread_defines\000"
$LASF64:
	.ascii	"cpu_sibling_map\000"
$LASF72:
	.ascii	"page_group_by_mobility_disabled\000"
$LASF60:
	.ascii	"smp_num_siblings\000"
$LASF25:
	.ascii	"dqstats\000"
$LASF82:
	.ascii	"compound_page_dtors\000"
$LASF3:
	.ascii	"short unsigned int\000"
$LASF22:
	.ascii	"pglist_data\000"
$LASF80:
	.ascii	"zero_page_mask\000"
$LASF15:
	.ascii	"cpumask\000"
$LASF9:
	.ascii	"char\000"
$LASF52:
	.ascii	"__current_thread_info\000"
$LASF53:
	.ascii	"shm_align_mask\000"
$LASF10:
	.ascii	"_Bool\000"
$LASF57:
	.ascii	"mips_cm_base\000"
$LASF27:
	.ascii	"kobj_type\000"
$LASF92:
	.ascii	"irq_stack\000"
$LASF49:
	.ascii	"nr_cpu_ids\000"
$LASF8:
	.ascii	"long unsigned int\000"
$LASF93:
	.ascii	"vm_swappiness\000"
$LASF97:
	.ascii	"ksoftirqd\000"
$LASF65:
	.ascii	"jiffies\000"
$LASF96:
	.ascii	"kmalloc_caches\000"
$LASF81:
	.ascii	"zero_pfn\000"
$LASF47:
	.ascii	"hex_asc\000"
$LASF24:
	.ascii	"compound_page_dtor\000"
$LASF51:
	.ascii	"cpu_bit_bitmap\000"
$LASF79:
	.ascii	"invalid_pte_table\000"
$LASF17:
	.ascii	"sizetype\000"
$LASF67:
	.ascii	"overflowuid\000"
$LASF42:
	.ascii	"kmem_cache\000"
$LASF54:
	.ascii	"flush_data_cache_page\000"
$LASF41:
	.ascii	"workqueue_struct\000"
$LASF59:
	.ascii	"mips_cm_is64\000"
$LASF74:
	.ascii	"contig_page_data\000"
$LASF30:
	.ascii	"output_ptreg_defines\000"
$LASF89:
	.ascii	"static_key_initialized\000"
$LASF12:
	.ascii	"atomic_t\000"
$LASF48:
	.ascii	"hex_asc_upper\000"
	.ident	"GCC: (LEDE GCC 5.4.0 unknown) 5.4.0"
	.section	.note.GNU-stack,"",@progbits
