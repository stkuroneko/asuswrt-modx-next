/*
 *
 * Automatically generated file; DO NOT EDIT.
 * Linux/mips 4.4.198 Kernel Configuration
 *
 */
/*
 * Helper macros to use CONFIG_ options in C/CPP expressions. Note that
 * these only work with boolean and tristate options.
 */
/*
 * Getting something that works in C and CPP for an arg that may or may
 * not be defined is tricky.  Here, if we have "#define CONFIG_BOOGER 1"
 * we match on the placeholder define, insert the "0," for arg1 and generate
 * the triplet (0, 1, 0).  Then the last step cherry picks the 2nd arg (a one).
 * When CONFIG_BOOGER is not defined, we generate a (... 1, 0) pair, and when
 * the last step cherry picks the 2nd arg, we get a zero.
 */
/*
 * IS_BUILTIN(CONFIG_FOO) evaluates to 1 if CONFIG_FOO is set to 'y', 0
 * otherwise. For boolean options, this is equivalent to
 * IS_ENABLED(CONFIG_FOO).
 */
/*
 * IS_MODULE(CONFIG_FOO) evaluates to 1 if CONFIG_FOO is set to 'm', 0
 * otherwise.
 */
/*
 * IS_REACHABLE(CONFIG_FOO) evaluates to 1 if the currently compiled
 * code can call a function defined in code compiled based on CONFIG_FOO.
 * This is similar to IS_ENABLED(), but returns false when invoked from
 * built-in code when CONFIG_FOO is set to 'm'.
 */
/*
 * IS_ENABLED(CONFIG_FOO) evaluates to 1 if CONFIG_FOO is set to 'y' or 'm',
 * 0 otherwise.
 */
/*
 * Copyright (C) 2015 Imagination Technologies
 * Author: Alex Smith <alex.smith@imgtec.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 */
/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 1996, 1999, 2001 Ralf Baechle
 * Copyright (C) 1999 Silicon Graphics, Inc.
 * Copyright (C) 2001 MIPS Technologies, Inc.
 */
/*
 * Definitions for the ISA levels
 *
 * With the introduction of MIPS32 / MIPS64 instruction sets definitions
 * MIPS ISAs are no longer subsets of each other.  Therefore comparisons
 * on these symbols except with == may result in unexpected results and
 * are forbidden!
 */
/*
 * Subprogram calling convention
 */
OUTPUT_FORMAT("elf32-tradlittlemips", "elf32-tradbigmips", "elf32-tradlittlemips")
OUTPUT_ARCH(mips)
SECTIONS
{
 PROVIDE(_start = .);
 . = SIZEOF_HEADERS;
 /*
	 * In order to retain compatibility with older toolchains we provide the
	 * ABI flags section ourself. Newer assemblers will automatically
	 * generate .MIPS.abiflags sections so we discard such input sections,
	 * and then manually define our own section here. genvdso will patch
	 * this section to have the correct name/type.
	 */
 .mips_abiflags : { *(.mips_abiflags) } :text :abiflags
 .reginfo : { *(.reginfo) } :text :reginfo
 .hash : { *(.hash) } :text
 .gnu.hash : { *(.gnu.hash) }
 .dynsym : { *(.dynsym) }
 .dynstr : { *(.dynstr) }
 .gnu.version : { *(.gnu.version) }
 .gnu.version_d : { *(.gnu.version_d) }
 .gnu.version_r : { *(.gnu.version_r) }
 .note : { *(.note.*) } :text :note
 .text : { *(.text*) } :text
 PROVIDE (__etext = .);
 PROVIDE (_etext = .);
 PROVIDE (etext = .);
 .eh_frame_hdr : { *(.eh_frame_hdr) } :text :eh_frame_hdr
 .eh_frame : { KEEP (*(.eh_frame)) } :text
 .dynamic : { *(.dynamic) } :text :dynamic
 .rodata : { *(.rodata*) } :text
 _end = .;
 PROVIDE(end = .);
 /DISCARD/ : {
  *(.MIPS.abiflags)
  *(.gnu.attributes)
  *(.note.GNU-stack)
  *(.data .data.* .gnu.linkonce.d.* .sdata*)
  *(.bss .sbss .dynbss .dynsbss)
 }
}
PHDRS
{
 /*
	 * Provide a PT_MIPS_ABIFLAGS header to assign the ABI flags section
	 * to. We can specify the header type directly here so no modification
	 * is needed later on.
	 */
 abiflags 0x70000003;
 /*
	 * The ABI flags header must exist directly after the PT_INTERP header,
	 * so we must explicitly place the PT_MIPS_REGINFO header after it to
	 * stop the linker putting one in at the start.
	 */
 reginfo 0x70000000;
 text PT_LOAD FLAGS(5) FILEHDR PHDRS; /* PF_R|PF_X */
 dynamic PT_DYNAMIC FLAGS(4); /* PF_R */
 note PT_NOTE FLAGS(4); /* PF_R */
 eh_frame_hdr PT_GNU_EH_FRAME;
}
VERSION
{
 LINUX_2.6 {
 local: *;
 };
}
