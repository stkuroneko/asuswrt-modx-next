/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   Macros for storing and retrieving integers in MSB first and LSB first
   order.  This interface can also be called from an other thread than
   the SSH main thread.

   <keywords getput, utility functions/getput, storing integers,
   retrieving integers, integer/storing & retrieving>
*/

#ifndef SSHGETPUT_H
#define SSHGETPUT_H

#define SSH_GET_8BIT(cp) (*(uint8_t *)(cp))
#define SSH_PUT_8BIT(cp, value) (*(uint8_t *)(cp)) = \
  (uint8_t)(value)
#define SSH_GET_4BIT_LOW(cp) (*(uint8_t *)(cp) & 0x0f)
#define SSH_GET_4BIT_HIGH(cp) ((*(uint8_t *)(cp) >> 4) & 0x0f)
#define SSH_PUT_4BIT_LOW(cp, value) (*(uint8_t *)(cp) = \
  (uint8_t)((*(uint8_t *)(cp) & 0xf0) | ((value) & 0x0f)))
#define SSH_PUT_4BIT_HIGH(cp, value) (*(uint8_t *)(cp) = \
  (uint8_t)((*(uint8_t *)(cp) & 0x0f) | (((value) & 0x0f) << 4)))

#ifdef SSHUINT64_IS_64BITS


#define SSH_GET_64BIT(cp) (((uint64_t)SSH_GET_32BIT((cp)) << 32) | \
                           ((uint64_t)SSH_GET_32BIT((cp) + 4)))
#define SSH_PUT_64BIT(cp, value) do { \
  SSH_PUT_32BIT((cp), (uint32_t)((uint64_t)(value) >> 32)); \
  SSH_PUT_32BIT((cp) + 4, (uint32_t)(value)); } while (0)


#define SSH_GET_64BIT_LSB_FIRST(cp) \
     (((uint64_t)SSH_GET_32BIT_LSB_FIRST((cp))) | \
      ((uint64_t)SSH_GET_32BIT_LSB_FIRST((cp) + 4) << 32))
#define SSH_PUT_64BIT_LSB_FIRST(cp, value) do { \
  SSH_PUT_32BIT_LSB_FIRST((cp), (uint32_t)(value)); \
  SSH_PUT_32BIT_LSB_FIRST((cp) + 4, (uint32_t)((uint64_t)(value) >> 32)); \
} while (0)

#define SSH_GET_40BIT(cp) (((uint64_t)SSH_GET_8BIT((cp)) << 32) | \
                           ((uint64_t)SSH_GET_32BIT((cp) + 1)))
#define SSH_PUT_40BIT(cp, value) do { \
  SSH_PUT_8BIT((cp), (uint32_t)((uint64_t)(value) >> 32)); \
  SSH_PUT_32BIT((cp) + 1, (uint32_t)(value)); } while (0)

#define SSH_GET_40BIT_LSB_FIRST(cp) \
     (((uint64_t)SSH_GET_32BIT_LSB_FIRST((cp))) | \
      ((uint64_t)SSH_GET_8BIT((cp) + 4) << 32))
#define SSH_PUT_40BIT_LSB_FIRST(cp, value) do { \
  SSH_PUT_32BIT_LSB_FIRST((cp), (uint32_t)(value)); \
  SSH_PUT_8BIT((cp) + 4, (uint32_t)((uint64_t)(value) >> 32)); } while (0)

#else /* SSHUINT64_IS_64BITS */

#define SSH_GET_64BIT(cp) ((uint64_t)SSH_GET_32BIT((cp) + 4))
#define SSH_PUT_64BIT(cp, value) do { \
  SSH_PUT_32BIT((cp), 0L); \
  SSH_PUT_32BIT((cp) + 4, (uint32_t)(value)); } while (0)
#define SSH_GET_64BIT_LSB_FIRST(cp) ((uint64_t)SSH_GET_32BIT((cp)))
#define SSH_PUT_64BIT_LSB_FIRST(cp, value) do { \
  SSH_PUT_32BIT_LSB_FIRST((cp), (uint32_t)(value)); \
  SSH_PUT_32BIT_LSB_FIRST((cp) + 4, 0L); } while (0)

#define SSH_GET_40BIT(cp) ((uint64_t)SSH_GET_32BIT((cp) + 1))
#define SSH_PUT_40BIT(cp, value) do { \
  SSH_PUT_8BIT((cp), 0); \
  SSH_PUT_32BIT((cp) + 1, (uint32_t)(value)); } while (0)
#define SSH_GET_40BIT_LSB_FIRST(cp) ((uint64_t)SSH_GET_32BIT_LSB_FIRST((cp)))
#define SSH_PUT_40BIT_LSB_FIRST(cp, value) do { \
  SSH_PUT_32BIT_LSB_FIRST((cp), (uint32_t)(value)); \
  SSH_PUT_8BIT((cp) + 4, 0); } while (0)

#endif /* SSHUINT64_IS_64BITS */

#define SSH_GET_24BIT(cp) \
     ((((uint32_t) ((uint8_t *) (cp))[0]) << 16) | \
      (((uint32_t) ((uint8_t *) (cp))[1]) << 8) | \
      ((uint32_t) ((uint8_t *) (cp))[2]))
#define SSH_GET_24BIT_LSB_FIRST(cp) \
     ((((uint32_t) ((uint8_t *) (cp))[2]) << 16) | \
      (((uint32_t) ((uint8_t *) (cp))[1]) << 8) | \
      ((uint32_t) ((uint8_t *) (cp))[0]))
#define SSH_PUT_24BIT(cp, value) do { \
  ((uint8_t *)(cp))[0] = (uint8_t)((value) >> 16); \
  ((uint8_t *)(cp))[1] = (uint8_t)((value) >> 8); \
  ((uint8_t *)(cp))[2] = (uint8_t)(value); } while (0)
#define SSH_PUT_24BIT_LSB_FIRST(cp, value) do { \
  ((uint8_t *)(cp))[2] = (uint8_t)((value) >> 16); \
  ((uint8_t *)(cp))[1] = (uint8_t)((value) >> 8); \
  ((uint8_t *)(cp))[0] = (uint8_t)(value); } while (0)

/*------------ macros for storing/extracting msb first words -------------*/













#define SSH_GET_32BIT(cp) \
  ((((uint32_t)((uint8_t *)(cp))[0]) << 24) | \
   (((uint32_t)((uint8_t *)(cp))[1]) << 16) | \
   (((uint32_t)((uint8_t *)(cp))[2]) << 8) | \
   ((uint32_t)((uint8_t *)(cp))[3]))

#define SSH_GET_16BIT(cp) \
     ((uint16_t) ((((uint32_t)((uint8_t *)(cp))[0]) << 8) | \
      ((uint32_t)((uint8_t *)(cp))[1])))

#define SSH_PUT_32BIT(cp, value) do { \
  ((uint8_t *)(cp))[0] = (uint8_t)((value) >> 24); \
  ((uint8_t *)(cp))[1] = (uint8_t)((value) >> 16); \
  ((uint8_t *)(cp))[2] = (uint8_t)((value) >> 8); \
  ((uint8_t *)(cp))[3] = (uint8_t)(value); } while (0)

#define SSH_PUT_16BIT(cp, value) do { \
  ((uint8_t *)(cp))[0] = (uint8_t)((value) >> 8); \
  ((uint8_t *)(cp))[1] = (uint8_t)(value); } while (0)



/*------------ macros for storing/extracting lsb first words -------------*/

#define SSH_GET_32BIT_LSB_FIRST(cp) \
  (((uint32_t)((uint8_t *)(cp))[0]) | \
  (((uint32_t)((uint8_t *)(cp))[1]) << 8) | \
  (((uint32_t)((uint8_t *)(cp))[2]) << 16) | \
  (((uint32_t)((uint8_t *)(cp))[3]) << 24))

#define SSH_GET_16BIT_LSB_FIRST(cp) \
  ((uint16_t) (((uint32_t)((uint8_t *)(cp))[0]) | \
  (((uint32_t)((uint8_t *)(cp))[1]) << 8)))

#define SSH_PUT_32BIT_LSB_FIRST(cp, value) do { \
  ((uint8_t *)(cp))[0] = (uint8_t)(value); \
  ((uint8_t *)(cp))[1] = (uint8_t)((value) >> 8); \
  ((uint8_t *)(cp))[2] = (uint8_t)((value) >> 16); \
  ((uint8_t *)(cp))[3] = (uint8_t)((value) >> 24); } while (0)

#define SSH_PUT_16BIT_LSB_FIRST(cp, value) do { \
  ((uint8_t *)(cp))[0] = (uint8_t)(value); \
  ((uint8_t *)(cp))[1] = (uint8_t)((value) >> 8); } while (0)

#if defined(_MSC_VER) && !defined(_WIN64) && !defined(_WIN32_WCE) && \
  (defined (WIN32) || defined(KERNEL) && (defined(WIN95) || defined(WINNT)))
/* optimizations for microsoft visual C++ */

#undef SSH_GET_32BIT_LSB_FIRST
#undef SSH_GET_16BIT_LSB_FIRST
#undef SSH_PUT_32BIT_LSB_FIRST
#undef SSH_PUT_16BIT_LSB_FIRST
#undef SSH_GET_32BIT
#undef SSH_GET_16BIT
#undef SSH_PUT_32BIT
#undef SSH_PUT_16BIT

#define SSH_GET_32BIT_LSB_FIRST(cp) (*(uint32_t *)(cp))
#define SSH_GET_16BIT_LSB_FIRST(cp) (*(uint16_t *)(cp))
#define SSH_PUT_32BIT_LSB_FIRST(cp,x) (*(uint32_t *)(cp)) = (x)
#define SSH_PUT_16BIT_LSB_FIRST(cp,x) (*(uint16_t *)(cp)) = (x)

/* Getting bytes msb first */
#define SSH_GET_16BIT(cp) \
     ((uint16_t) ((((uint32_t)((uint8_t *)(cp))[0]) << 8) | \
      ((uint32_t)((uint8_t *)(cp))[1])))

#define SSH_PUT_16BIT(cp, value) do { \
  ((uint8_t *)(cp))[0] = (uint8_t)((value) >> 8); \
  ((uint8_t *)(cp))[1] = (uint8_t)(value); } while (0)


#pragma warning( disable : 4035 )
static __inline void SSH_PUT_32BIT(void *cp, uint32_t value)
{
    __asm
    {
        mov eax, value
        mov ebx, cp
#ifdef NO_386_COMPAT
        bswap eax
#else
        rol ax,8
        rol eax,16
        rol ax,8
#endif
        mov [ebx], eax
    }
}

static __inline uint32_t SSH_GET_32BIT(const char *cp)
{
    __asm
    {
        mov ebx, cp
        mov eax, [ebx]
#ifdef NO_386_COMPAT
        bswap eax
#else
        rol ax,8
        rol eax,16
        rol ax,8
#endif

    }
    /* eax is interpreted as return value */
}

#pragma warning( default : 4035 )

#else

/* This `|| 1' thing disables the GCC i386 optimizations.  They seem
   to be very mysticly broken so it is better to disable them. */
#if !defined(NO_INLINE_GETPUT) && defined(__i386__) && defined(__GNUC__)

/* Intel i386 processor, using AT&T syntax for gcc compiler. */

#undef SSH_GET_32BIT_LSB_FIRST
#undef SSH_GET_16BIT_LSB_FIRST
#undef SSH_PUT_32BIT_LSB_FIRST
#undef SSH_PUT_16BIT_LSB_FIRST
#undef SSH_GET_32BIT
#undef SSH_PUT_32BIT

/* LSB first cases could be done efficiently also with just C definitions
   to just copy values.  i386 has no alignment restrictions. */

#define SSH_GET_32BIT_LSB_FIRST(cp) (*(uint32_t *)(cp))
#define SSH_GET_16BIT_LSB_FIRST(cp) (*(uint16_t *)(cp))
#define SSH_PUT_32BIT_LSB_FIRST(cp,x) (*(uint32_t *)(cp)) = (x)
#define SSH_PUT_16BIT_LSB_FIRST(cp,x) (*(uint16_t *)(cp)) = (x)

/* Getting bytes MSB first */

#ifdef NO_386_COMPAT
#define SSH_GET_32BIT(cp) \
({  \
  uint32_t __v__; \
  __asm__ volatile ("movl (%1), %%ecx; " \
                    "bswap %%ecx;" \
          : "=c" (__v__) \
          : "r" (cp) : "cc"); \
  __v__; \
})
#else
#define SSH_GET_32BIT(cp) \
({  \
  uint32_t __v__; \
  __asm__ volatile ("movl (%1), %%ecx; rolw $8, %%cx; " \
                    "roll $16, %%ecx; rolw $8, %%cx;" \
          : "=c" (__v__) \
          : "r" (cp) : "cc"); \
  __v__; \
})

#endif
#if 0
#define SSH_GET_16BIT(cp) \
({ \
  uint16_t __v__; \
  __asm__ volatile ("movw (%1), %0; rolw $8, %0;" \
          : "=r" (__v__) \
          : "r" (cp) : "cc"); \
  __v__; \
})
#endif

#define SSH_PUT_32BIT(cp, v) \
__asm__ volatile ("movl %1, %%ecx; rolw $8, %%cx; " \
                  "roll $16, %%ecx; rolw $8, %%cx;" \
         "movl %%ecx, (%0);" \
         : : "S" (cp), "a" ((uint32_t) (v)) : "%ecx", "memory", "cc")

#if 0
/* Note that the following code is broken on newer GCCs
   with optimizations, as it does not tell that the code
   globbers ax. This could be fixed by adding rolw $8, %%ax; at
   the end which would set the ax back to its original
   state. */
#define SSH_PUT_16BIT(cp,v)  \
__asm__ volatile ("rolw $8, %%ax; movw %%ax, (%0); " \
        : : "S" (cp), "a" ((uint16_t) (v)) : "memory", "cc")
#endif

#endif /* __i386__ */

#endif /* GETPUT_MSVC */

#endif /* GETPUT_H */
