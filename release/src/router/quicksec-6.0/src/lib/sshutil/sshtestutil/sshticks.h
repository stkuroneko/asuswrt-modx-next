/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Platform-dependent cycle counters used for very detailed
   profiling.

   File: sshticks.h

   @description
   The purpose is to measure, with as little overhead as
   possible, very small differences in time, such as the execution of
   a few to a few hundred instructions.  This file is *not* intended
   for coarser profiling.

   The macro 'SSH_TICKS_READ32' assumes it is given an lvalue of type
   'SshUInt32', and 'SSH_TICKS_READ64' assumes it is given an lvalue
   of type 'SshUInt64'.  Should no suitable cycle counter be
   available, then 'SSH_TICKS_READ32' and 'SSH_TICKS_READ64'
   initialize their arguments to zero.
*/

#ifndef SSH_TICKS_H_INCLUDED
#define SSH_TICKS_H_INCLUDED  1

#ifdef __GNUC__

#ifdef __i386__
/** Read ticks (64 bits).

    The rdtsc insn, available in Pentia and any newer processors,
    stores the clock counter's low 32 bits in the 'eax' register and
    the upper bits in the 'edx' register.  If we're interested only in
    the lowest 32 bits, we store 'eax' in the argument variable 't' and
    inform the compiler that the 'edx' register is clobbered. */
#define SSH_TICKS_READ64(t)  asm volatile ("rdtsc" : "=A" (t))

/** Read ticks (32 bits). */
#define SSH_TICKS_READ32(t)  asm volatile ("rdtsc" : "=a" (t) : : "edx")
#endif /* __i386__ */


#ifdef __sparc_v9__
/* Note: there seems to be no way to distinguish from cpp macros
   whether we have are really able to compile and run the code below.
   At least on two tested machines, if you give to gcc the flag
   '-mcpu=ultrasparc', then the macro above is defined and the
   assembler is passed the flag '-xarch=v8plusa', and everything works
   well.  But if you give only '-mcpu=v9', then the assembler is not
   passed the option, and it barfs. */
#define SSH_TICKS_READ32(t)  asm volatile("rd %%tick,%0" : "=r" (t))




#endif  /* __sparc_v9__ */


#ifdef PPC
#define SSH_TICKS_READ32(t)  asm volatile("mfspr %0,268" : "=r" (t))
/* Power PC's increment a 64-bit counter, but its semantics is totally
   system dependent.  On one platform we observed it increment once
   every fourth bus clock cycle.

   The procedure for reading a 64-bit tick in PPC is not that simple:
   the ticks are stored in two 32-bit special purpose registers and we
   have to reconstruct the 64-bit value from them.  Note that we need
   to reread the upper 32 bits to notice whether the low 32-bit
   counter wrapped around. */
#define SSH_TICKS_READ64(t)                             \
do                                                      \
{                                                       \
  SshUInt32 __u1__, __l__, __u2__;                      \
  do {                                                  \
    asm volatile("mfspr %0,269" : "=r" (__u1__));       \
    asm volatile("mfspr %0,268" : "=r" (__l__));        \
    asm volatile("mfspr %0,269" : "=r" (__u2__));       \
  } while (__u1__ != __u2__);                           \
  (t) = (((SshUInt64) __u1__) << 32) | __l__;           \
} while (0)
#endif  /* PPC */

#endif /* __GNUC__ */


/* On any other platform where we don't have a *efficient* tick
   implementation, don't do anything.  The alternative would be to use
   e.g. 'gettimeofday', but that would be innefficient and the call
   would affect too much the code being measured.  The alternative
   below is, however, better, since it gives obviously false instead
   of misleading results. */

#ifndef SSH_TICKS_READ32
#define SSH_TICKS_READ32(t)  do { (t) = 0; } while (0)
#endif /* !SSH_TICKS_READ32 */

#ifndef SSH_TICKS_READ64
#define SSH_TICKS_READ64(t)  do { (t) = 0; } while (0)
#endif /* !SSH_TICKS_READ64 */


#endif /* !SSH_TICKS_H_INCLUDED */
