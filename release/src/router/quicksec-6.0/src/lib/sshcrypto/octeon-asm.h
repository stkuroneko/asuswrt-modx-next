/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#ifndef OCTEON_ASM_H
#define OCTEON_ASM_H

/* Prefetching data */
#define OCTEON_PREFETCH(address, offset) \
 asm volatile ("pref 0, " #offset "(%[rbase])" : : [rbase] "d" (address))

/* MD5 and SHA-1 */

#define OCTEON_SET_HASH_DAT(x, p) do {                        \
    SSH_ASSERT((p)>= 0 && (p) <=6);                           \
    asm volatile ("dmtc2 %[rt],0x0040+" #p : : [rt] "d" (x)); \
  } while(0);


#define OCTEON_SET_HASH_DATZ(p) do {                          \
     SSH_ASSERT((p)>= 0 && (p) <=6);                          \
     asm volatile ("dmtc2 $0,0x0040+" #p : : );               \
  } while(0);

#define OCTEON_SET_HASH_STARTMD5(val)   \
    asm volatile ("dmtc2 %[rt],0x4047" : : [rt] "d" (val))
#define OCTEON_SET_HASH_STARTSHA(val)   \
    asm volatile ("dmtc2 %[rt],0x4057" : : [rt] "d" (val))

#define  OCTEON_SET_HASH_IV(x, p) do {                        \
    SSH_ASSERT((p)>= 0 && (p) <=2);                           \
    asm volatile ("dmtc2   %[rt],0x0048+" #p : : [rt] "d" (x));  \
  } while(0);

#define OCTEON_GET_HASH_DAT(x, p)      do {                     \
    SSH_ASSERT((p)>= 0 && (p) <=6);                             \
    asm volatile ("dmfc2 %[rt],0x0040+" #p : [rt] "=d" (x) : ); \
  } while(0);

#define OCTEON_GET_HASH_IV(x, p)      do {                      \
    SSH_ASSERT((p)>= 0 && (p) <=2);                             \
    asm volatile ("dmfc2 %[rt],0x0048+" #p : [rt] "=d" (x) : ); \
  } while(0);

#define OCTEON_LOAD_SHA_UNIT(dat, next)  { \
   if (next == 0) {                        \
      next = 1;                            \
      OCTEON_SET_HASH_DAT(dat, 0);         \
   } else if (next == 1) {                 \
      next = 2;                            \
      OCTEON_SET_HASH_DAT(dat, 1);         \
   } else if (next == 2) {                 \
      next = 3;                            \
      OCTEON_SET_HASH_DAT(dat, 2);         \
   } else if (next == 3) {                 \
      next = 4;                            \
      OCTEON_SET_HASH_DAT(dat, 3);         \
   } else if (next == 4) {                 \
      next = 5;                            \
      OCTEON_SET_HASH_DAT(dat, 4);         \
   } else if (next == 5) {                 \
      next = 6;                            \
      OCTEON_SET_HASH_DAT(dat, 5);         \
   } else if (next == 6) {                 \
      next = 7;                            \
      OCTEON_SET_HASH_DAT(dat, 6);         \
   } else {                                \
    OCTEON_SET_HASH_STARTSHA (dat);        \
     next = 0;                             \
   }                                       \
}

#define OCTEON_LOAD2_SHA_UNIT(dat1, dat2, next)  { \
   if (next == 0) {                          \
      OCTEON_SET_HASH_DAT(dat1, 0);          \
      OCTEON_SET_HASH_DAT(dat2, 1);          \
      next = 2;                              \
   } else if (next == 1) {                   \
      OCTEON_SET_HASH_DAT(dat1, 1);          \
      OCTEON_SET_HASH_DAT(dat2, 2);          \
      next = 3;                              \
   } else if (next == 2) {                   \
      OCTEON_SET_HASH_DAT(dat1, 2);          \
      OCTEON_SET_HASH_DAT(dat2, 3);          \
      next = 4;                              \
   } else if (next == 3) {                   \
      OCTEON_SET_HASH_DAT(dat1, 3);          \
      OCTEON_SET_HASH_DAT(dat2, 4);          \
      next = 5;                              \
   } else if (next == 4) {                   \
      OCTEON_SET_HASH_DAT(dat1, 4);          \
      OCTEON_SET_HASH_DAT(dat2, 5);          \
      next = 6;                              \
   } else if (next == 5) {                   \
      OCTEON_SET_HASH_DAT(dat1, 5);          \
      OCTEON_SET_HASH_DAT(dat2, 6);          \
      next = 7;                              \
   } else if (next == 6) {                   \
      OCTEON_SET_HASH_DAT(dat1, 6);          \
      OCTEON_SET_HASH_STARTSHA (dat2);       \
      next = 0;                              \
   } else {                                  \
     OCTEON_SET_HASH_STARTSHA (dat1);        \
     OCTEON_SET_HASH_DAT(dat2, 0);           \
     next = 1;                               \
   }                                         \
}

#define OCTEON_LOAD_MD5_UNIT(dat, next)  { \
   if (next == 0) {                     \
      next = 1;                         \
      OCTEON_SET_HASH_DAT(dat, 0);      \
   } else if (next == 1) {              \
      next = 2;                         \
      OCTEON_SET_HASH_DAT(dat, 1);      \
   } else if (next == 2) {              \
      next = 3;                         \
      OCTEON_SET_HASH_DAT(dat, 2);      \
   } else if (next == 3) {              \
      next = 4;                         \
      OCTEON_SET_HASH_DAT(dat, 3);      \
   } else if (next == 4) {              \
      next = 5;                         \
      OCTEON_SET_HASH_DAT(dat, 4);      \
   } else if (next == 5) {              \
      next = 6;                         \
      OCTEON_SET_HASH_DAT(dat, 5);      \
   } else if (next == 6) {              \
      next = 7;                         \
      OCTEON_SET_HASH_DAT(dat, 6);      \
   } else {                             \
     OCTEON_SET_HASH_STARTMD5(dat);     \
     next = 0;                          \
   }                                    \
}


#define OCTEON_LOAD2_MD5_UNIT(dat1, dat2, next)  { \
   if (next == 0) {                      \
      OCTEON_SET_HASH_DAT(dat1, 0);      \
      OCTEON_SET_HASH_DAT(dat2, 1);      \
      next = 2;                          \
   } else if (next == 1) {               \
      OCTEON_SET_HASH_DAT(dat1, 1);      \
      OCTEON_SET_HASH_DAT(dat2, 2);      \
      next = 3;                          \
   } else if (next == 2) {               \
      OCTEON_SET_HASH_DAT(dat1, 2);      \
      OCTEON_SET_HASH_DAT(dat2, 3);      \
      next = 4;                          \
   } else if (next == 3) {               \
      OCTEON_SET_HASH_DAT(dat1, 3);      \
      OCTEON_SET_HASH_DAT(dat2, 4);      \
      next = 5;                          \
   } else if (next == 4) {               \
      OCTEON_SET_HASH_DAT(dat1, 4);      \
      OCTEON_SET_HASH_DAT(dat2, 5);      \
      next = 6;                          \
   } else if (next == 5) {               \
      OCTEON_SET_HASH_DAT(dat1, 5);      \
      OCTEON_SET_HASH_DAT(dat2, 6);      \
      next = 7;                          \
   } else if (next == 6) {               \
      OCTEON_SET_HASH_DAT(dat1, 6);      \
      OCTEON_SET_HASH_STARTMD5(dat2);    \
      next = 0;                          \
   } else {                              \
     OCTEON_SET_HASH_STARTMD5(dat1);     \
     OCTEON_SET_HASH_DAT(dat2, 0);       \
     next = 1;                           \
   }                                     \
}



/* 3DES */

/* pos can be 0-2 */
#define OCTEON_SET_3DES_KEY(x, p)     do {                    \
    SSH_ASSERT((p)>= 0 && (p) <=2);                           \
    asm volatile ("dmtc2 %[rt],0x0080+" #p : : [rt] "d" (x)); \
  } while(0);

#define OCTEON_SET_3DES_IV(x)        \
   asm volatile ("dmtc2 %[rt],0x0084" : : [rt] "d" (x))
#define OCTEON_GET_3DES_IV(x)        \
   asm volatile ("dmfc2 %[rt],0x0084" : [rt] "=d" (x) : )
#define OCTEON_SET_3DES_ENC_CBC(x)   \
   asm volatile ("dmtc2 %[rt],0x4088" : : [rt] "d" (x))
#define OCTEON_SET_3DES_ENC(x)       \
   asm volatile ("dmtc2 %[rt],0x408a" : : [rt] "d" (x))
#define OCTEON_SET_3DES_DEC_CBC(x)   \
   asm volatile ("dmtc2 %[rt],0x408c" : : [rt] "d" (x))
#define OCTEON_SET_3DES_DEC(x)       \
   asm volatile ("dmtc2 %[rt],0x408e" : : [rt] "d" (x))
#define OCTEON_SET_3DES_RESULT(x)    \
   asm volatile ("dmtc2 %[rt],0x0098" : : [rt] "d" (x))
#define OCTEON_GET_3DES_RESULT(x)    \
   asm volatile ("dmfc2 %[rt],0x0088" : [rt] "=d" (x) : )


/* AES */

#define OCTEON_SET_AES_ENC_CBC0(x)   \
   asm volatile ("dmtc2 %[rt],0x0108" : : [rt] "d" (x))
#define OCTEON_SET_AES_ENC_CBC1(x)   \
   asm volatile ("dmtc2 %[rt],0x3109" : : [rt] "d" (x))
#define OCTEON_SET_AES_ENC0(x)       \
   asm volatile ("dmtc2 %[rt],0x010a" : : [rt] "d" (x))
#define OCTEON_SET_AES_ENC1(x)       \
   asm volatile ("dmtc2 %[rt],0x310b" : : [rt] "d" (x))
#define OCTEON_SET_AES_DEC_CBC0(x)   \
   asm volatile ("dmtc2 %[rt],0x010c" : : [rt] "d" (x))
#define OCTEON_SET_AES_DEC_CBC1(x)   \
   asm volatile ("dmtc2 %[rt],0x310d" : : [rt] "d" (x))
#define OCTEON_SET_AES_DEC0(x)       \
   asm volatile ("dmtc2 %[rt],0x010e" : : [rt] "d" (x))
#define OCTEON_SET_AES_DEC1(x)       \
   asm volatile ("dmtc2 %[rt],0x310f" : : [rt] "d" (x))

#define OCTEON_SET_AES_KEY(x, p)     do {                     \
    SSH_ASSERT((p)>= 0 && (p) <=3);                           \
    asm volatile ("dmtc2 %[rt],0x0104+" #p : : [rt] "d" (x)); \
  } while(0);

#define OCTEON_SET_AES_IV(x, p)      do {                     \
    SSH_ASSERT((p)>= 0 && (p) <=1);                           \
    asm volatile ("dmtc2 %[rt],0x0102+" #p : : [rt] "d" (x)); \
  } while(0);

#define OCTEON_SET_AES_KEYLENGTH(x)  \
   asm volatile ("dmtc2 %[rt],0x0110" : : [rt] "d" (x))

#define OCTEON_SET_AES_RESULT(x, p)      do {                 \
    SSH_ASSERT((p)>= 0 && (p) <=1);                           \
    asm volatile ("dmtc2 %[rt],0x0100+" #p : : [rt] "d" (x)); \
  } while(0);

#define OCTEON_GET_AES_RESULT(x, p)      do {                   \
    SSH_ASSERT((p)>= 0 && (p) <=1);                             \
    asm volatile ("dmfc2 %[rt],0x0100+" #p : [rt] "=d" (x) : ); \
  } while(0);

#define OCTEON_GET_AES_IV(x, p)      do {                       \
    SSH_ASSERT((p)>= 0 && (p) <=1);                             \
    asm volatile ("dmfc2 %[rt],0x0102+" #p : [rt] "=d" (x) : ); \
  } while(0);



#ifdef KERNEL
#include "asm/processor.h"

#define COP0_STATUS "$12,0"
#define ENABLE_COP2() do {                                      \
    uint32_t reg;                                               \
    reg = read_c0_status();                                     \
    reg |= 0x40000000;                                          \
    write_c0_status(reg);                                       \
  } while(0);

#define DISABLE_COP2()
#endif /* KERNEL */

#endif /* OCTEON_ASM_H */
