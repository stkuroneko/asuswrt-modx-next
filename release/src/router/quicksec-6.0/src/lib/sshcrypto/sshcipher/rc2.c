/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This implementation follows the RFC-2268 which was previosly known
   as the internet draft draft-rivest-rc2desc-00.txt.

   The algorithm is also described in the paper

   Lars R. Knudsen, Vincet Rijmen, Ronald L. Rivest, and
   M.J.B. Robshaw, "On the Design and Security of RC2". FSE'98?
*/

#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshgetput.h"
#include "rc2.h"

/* RC2 is a block cipher depending of use of 16-bit words.

   Throughout this file we assume that SshUInt64 is the maximum
   word size of the machine (and also the fastest). This
   will probably be good guess. (Note that SshUInt64 is the
   largest available word size for < 64-bit computers. Always
   thus atleast 32-bit.)
 */

typedef SshUInt32 SshWord;

typedef struct
{
  /* The expanded key. */
  SshWord k[64];
  /* Indicator whether the algorithm is in encryption or decryption mode. */
  Boolean for_encryption;
  /* The effective key length indicator. */
  unsigned int t1;
} SshRC2Context;


/* The infamous PITABLE. The precise algorithm for generating this
   is unknown, it probably contains a backdoor (this under the
   very pessimistic assumption!).

        0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f
   00: d9 78 f9 c4 19 dd b5 ed 28 e9 fd 79 4a a0 d8 9d
   10: c6 7e 37 83 2b 76 53 8e 62 4c 64 88 44 8b fb a2
   20: 17 9a 59 f5 87 b3 4f 13 61 45 6d 8d 09 81 7d 32
   30: bd 8f 40 eb 86 b7 7b 0b f0 95 21 22 5c 6b 4e 82
   40: 54 d6 65 93 ce 60 b2 1c 73 56 c0 14 a7 8c f1 dc
   50: 12 75 ca 1f 3b be e4 d1 42 3d d4 30 a3 3c b6 26
   60: 6f bf 0e da 46 69 07 57 27 f2 1d 9b bc 94 43 03
   70: f8 11 c7 f6 90 ef 3e e7 06 c3 d5 2f c8 66 1e d7
   80: 08 e8 ea de 80 52 ee f7 84 aa 72 ac 35 4d 6a 2a
   90: 96 1a d2 71 5a 15 49 74 4b 9f d0 5e 04 18 a4 ec
   a0: c2 e0 41 6e 0f 51 cb cc 24 91 af 50 a1 f4 70 39
   b0: 99 7c 3a 85 23 b8 b4 7a fc 02 36 5b 25 55 97 31
   c0: 2d 5d fa 98 e3 8a 92 ae 05 df 29 10 67 6c ba c9
   d0: d3 00 e6 cf e1 9e a8 2c 63 16 01 3f 58 e2 89 a9
   e0: 0d 38 34 1b ab 33 ff b0 bb 48 0c 5f b9 b1 cd 2e
   f0: c5 f3 db 47 e5 a5 9c 77 0a a6 20 68 fe 7f c1 ad
   */

const unsigned char ssh_rc2_pitable[256] =
{
  0xd9, 0x78, 0xf9, 0xc4, 0x19, 0xdd, 0xb5, 0xed,
  0x28, 0xe9, 0xfd, 0x79, 0x4a, 0xa0, 0xd8, 0x9d,
  0xc6, 0x7e, 0x37, 0x83, 0x2b, 0x76, 0x53, 0x8e,
  0x62, 0x4c, 0x64, 0x88, 0x44, 0x8b, 0xfb, 0xa2,
  0x17, 0x9a, 0x59, 0xf5, 0x87, 0xb3, 0x4f, 0x13,
  0x61, 0x45, 0x6d, 0x8d, 0x09, 0x81, 0x7d, 0x32,
  0xbd, 0x8f, 0x40, 0xeb, 0x86, 0xb7, 0x7b, 0x0b,
  0xf0, 0x95, 0x21, 0x22, 0x5c, 0x6b, 0x4e, 0x82,
  0x54, 0xd6, 0x65, 0x93, 0xce, 0x60, 0xb2, 0x1c,
  0x73, 0x56, 0xc0, 0x14, 0xa7, 0x8c, 0xf1, 0xdc,
  0x12, 0x75, 0xca, 0x1f, 0x3b, 0xbe, 0xe4, 0xd1,
  0x42, 0x3d, 0xd4, 0x30, 0xa3, 0x3c, 0xb6, 0x26,
  0x6f, 0xbf, 0x0e, 0xda, 0x46, 0x69, 0x07, 0x57,
  0x27, 0xf2, 0x1d, 0x9b, 0xbc, 0x94, 0x43, 0x03,
  0xf8, 0x11, 0xc7, 0xf6, 0x90, 0xef, 0x3e, 0xe7,
  0x06, 0xc3, 0xd5, 0x2f, 0xc8, 0x66, 0x1e, 0xd7,
  0x08, 0xe8, 0xea, 0xde, 0x80, 0x52, 0xee, 0xf7,
  0x84, 0xaa, 0x72, 0xac, 0x35, 0x4d, 0x6a, 0x2a,
  0x96, 0x1a, 0xd2, 0x71, 0x5a, 0x15, 0x49, 0x74,
  0x4b, 0x9f, 0xd0, 0x5e, 0x04, 0x18, 0xa4, 0xec,
  0xc2, 0xe0, 0x41, 0x6e, 0x0f, 0x51, 0xcb, 0xcc,
  0x24, 0x91, 0xaf, 0x50, 0xa1, 0xf4, 0x70, 0x39,
  0x99, 0x7c, 0x3a, 0x85, 0x23, 0xb8, 0xb4, 0x7a,
  0xfc, 0x02, 0x36, 0x5b, 0x25, 0x55, 0x97, 0x31,
  0x2d, 0x5d, 0xfa, 0x98, 0xe3, 0x8a, 0x92, 0xae,
  0x05, 0xdf, 0x29, 0x10, 0x67, 0x6c, 0xba, 0xc9,
  0xd3, 0x00, 0xe6, 0xcf, 0xe1, 0x9e, 0xa8, 0x2c,
  0x63, 0x16, 0x01, 0x3f, 0x58, 0xe2, 0x89, 0xa9,
  0x0d, 0x38, 0x34, 0x1b, 0xab, 0x33, 0xff, 0xb0,
  0xbb, 0x48, 0x0c, 0x5f, 0xb9, 0xb1, 0xcd, 0x2e,
  0xc5, 0xf3, 0xdb, 0x47, 0xe5, 0xa5, 0x9c, 0x77,
  0x0a, 0xa6, 0x20, 0x68, 0xfe, 0x7f, 0xc1, 0xad,
};


size_t ssh_rc2_ctxsize(void)
{
  return sizeof(SshRC2Context);
}

SshCryptoStatus ssh_rc2_keyset(SshRC2Context *ctx,
                               const unsigned char *key, size_t keylen)
{
  unsigned char L[128], tm;
  unsigned int t8;
  size_t i;

  if (keylen == 0)
    return SSH_CRYPTO_KEY_TOO_SHORT;

  memset(ctx->k, 0, sizeof(SshWord)*64);
  memcpy(L, key, keylen);

  /* Perform the mixing. */
  for (i = keylen; i < 128; i++)
    L[i] = ssh_rc2_pitable[(L[i-1] + L[i-keylen]) & 0xff];

  /* Now compute t8 and tm. */
  t8 = (ctx->t1 + 7)/8;
  tm = 0xff & (((unsigned int)1 << (8 + ctx->t1 - 8*t8)) - 1);
  L[128 - t8] = ssh_rc2_pitable[L[128-t8] & tm];

  for (i = (127 - t8) + 1; i > 0; i--)
    L[i-1] = ssh_rc2_pitable[(L[(i-1)+1] ^ L[(i-1)+t8]) & 0xff];

  /* Convert the by-octet expanded key to the word key. */
  for (i = 0; i < 64; i++)
    ctx->k[i] = ((SshWord)L[2*i]) + (((SshWord)L[2*i+1])<<8);

  /* We actually succeeded. */
  return SSH_CRYPTO_OK;
}

SshCryptoStatus ssh_rc2_init(void *ptr,
                             const unsigned char *key, size_t keylen,
                             Boolean for_encryption)
{
  SshRC2Context *ctx = ptr;

  /* Set the for encryption part. */
  ctx->for_encryption = for_encryption;
  /* Fixed effective key size. You may write alternative versions of
     this function to modify this. */
  if (keylen > 128)
    keylen = 128;

  ctx->t1             = keylen * 8;

  return ssh_rc2_keyset(ctx, key, keylen);
}

SshCryptoStatus ssh_rc2_128_init(void *ptr,
                                 const unsigned char *key, size_t keylen,
                                 Boolean for_encryption)
{
  SshRC2Context *ctx = ptr;

  /* Set the for encryption part. */
  ctx->for_encryption = for_encryption;
  /* Fixed effective key size. You may write alternative versions of
     this function to modify this. */
  if (keylen > 128)
    keylen = 128;

  ctx->t1             = 128;

  return ssh_rc2_keyset(ctx, key, keylen);
}

/* Here is the actual encryption and decryption code. And the Mix and Mash
   operations. */

#define MIXUP(g0,g1,g2,g3,z,s) \
do { \
  SshWord t; \
  t  = (g0 + z + (g1 & g2) + (g3 & (~g1))) & 0xffff; \
  g0 = (t << s) | (t >> (16-s)); \
} while (0)

#define MASHUP(g0,g1,g2,g3) \
  g0 = g0 + k[g1 & 63]

#define MIX(j) \
  MIXUP(r0,r3,r2,r1,k[j+0], 1); \
  MIXUP(r1,r0,r3,r2,k[j+1], 2); \
  MIXUP(r2,r1,r0,r3,k[j+2], 3); \
  MIXUP(r3,r2,r1,r0,k[j+3], 5)

#define MASH \
  MASHUP(r0,r3,r2,r1); \
  MASHUP(r1,r0,r3,r2); \
  MASHUP(r2,r1,r0,r3); \
  MASHUP(r3,r2,r1,r0)

/* Reverse operations for decryption. */
#define RMIXUP(g0,g1,g2,g3,z,s) \
do { \
  SshWord t; \
  t = g0 & 0xffff; \
  t = (t >> s) | (t << (16-s)); \
  g0 = t - z - (g1 & g2) - (g3 & (~g1)); \
} while(0)

#define RMASHUP(g0,g1,g2,g3) \
  g0 = g0 - k[g1 & 63]

#define RMIX(j) \
  RMIXUP(r3,r2,r1,r0,k[j+3], 5); \
  RMIXUP(r2,r1,r0,r3,k[j+2], 3); \
  RMIXUP(r1,r0,r3,r2,k[j+1], 2); \
  RMIXUP(r0,r3,r2,r1,k[j+0], 1)

#define RMASH \
  RMASHUP(r3,r2,r1,r0); \
  RMASHUP(r2,r1,r0,r3); \
  RMASHUP(r1,r0,r3,r2); \
  RMASHUP(r0,r3,r2,r1)

void ssh_rc2_encrypt(SshUInt32 l, SshUInt32 r, SshUInt32 output[2],
                     SshWord *k, Boolean for_encryption)
{
  SshWord r0, r1, r2, r3;

  /* Convert 16-bit words. */
  r0 = l & 0xffff;
  r1 = (l >> 16);
  r2 = r & 0xffff;
  r3 = (r >> 16);

  if (for_encryption)
    {
      /* 5 mixups. */
      MIX( 0); MIX( 4); MIX( 8); MIX(12); MIX(16);

      /* 1 mash. */
      MASH;

      /* 6 mixups. */
      MIX(20); MIX(24); MIX(28); MIX(32); MIX(36); MIX(40);

      /* 1 mash. */
      MASH;

      /* 5 mixups. */
      MIX(44); MIX(48); MIX(52); MIX(56); MIX(60);
    }
  else
    {
      /* 5 rmixups. */
      RMIX(60); RMIX(56); RMIX(52); RMIX(48); RMIX(44);

      /* 1 rmash. */
      RMASH;

      /* 6 rmixups. */
      RMIX(40); RMIX(36); RMIX(32); RMIX(28); RMIX(24); RMIX(20);

      /* 1 rmash. */
      RMASH;

      /* 5 rmixups. */
      RMIX(16); RMIX(12); RMIX( 8); RMIX( 4); RMIX( 0);
    }

  /* Convert to the output. */
  r0 &= 0xffff;
  r1 &= 0xffff;
  r2 &= 0xffff;
  r3 &= 0xffff;

  output[0] = ((r1 << 16) | r0);
  output[1] = ((r3 << 16) | r2);
}

/* The RC2 specific portion ends here. Following code is
   for implementing all the possible cipher modes for this
   particular cipher. */


SshCryptoStatus ssh_rc2_ecb(void *context, unsigned char *dest,
                            const unsigned char *src, size_t len,
                            unsigned char *iv)
{
  SshRC2Context *ctx = context;
  SshUInt32 output[2], l, r;
  Boolean for_encryption = ctx->for_encryption;

  while (len)
    {
      l = SSH_GET_32BIT_LSB_FIRST(src);
      r = SSH_GET_32BIT_LSB_FIRST(src + 4);

      ssh_rc2_encrypt(l, r, output, ctx->k, for_encryption);

      SSH_PUT_32BIT_LSB_FIRST(dest, output[0]);
      SSH_PUT_32BIT_LSB_FIRST(dest + 4, output[1]);

      src += 8;
      dest += 8;
      len -= 8;
    }
  return SSH_CRYPTO_OK;
}

SshCryptoStatus ssh_rc2_cbc(void *context, unsigned char *dest,
                            const unsigned char *src, size_t len,
                            unsigned char *iv_arg)
{
  SshRC2Context *ctx = context;
  SshUInt32 l, r, iv[2], temp[2];
  Boolean for_encryption = ctx->for_encryption;

  iv[0] = SSH_GET_32BIT_LSB_FIRST(iv_arg);
  iv[1] = SSH_GET_32BIT_LSB_FIRST(iv_arg + 4);

  if (for_encryption)
    {
      while (len)
        {
          l = SSH_GET_32BIT_LSB_FIRST(src) ^ iv[0];
          r = SSH_GET_32BIT_LSB_FIRST(src + 4) ^ iv[1];

          ssh_rc2_encrypt(l, r, iv, ctx->k, for_encryption);

          SSH_PUT_32BIT_LSB_FIRST(dest, iv[0]);
          SSH_PUT_32BIT_LSB_FIRST(dest + 4, iv[1]);

          src += 8;
          dest += 8;
          len -= 8;
        }
    }
  else
    {
      while (len)
        {
          l = SSH_GET_32BIT_LSB_FIRST(src);
          r = SSH_GET_32BIT_LSB_FIRST(src + 4);

          ssh_rc2_encrypt(l, r, temp, ctx->k, for_encryption);

          temp[0] ^= iv[0];
          temp[1] ^= iv[1];

          SSH_PUT_32BIT_LSB_FIRST(dest, temp[0]);
          SSH_PUT_32BIT_LSB_FIRST(dest + 4, temp[1]);

          iv[0] = l;
          iv[1] = r;

          src += 8;
          dest += 8;
          len -= 8;
        }
    }

  SSH_PUT_32BIT_LSB_FIRST(iv_arg, iv[0]);
  SSH_PUT_32BIT_LSB_FIRST(iv_arg + 4, iv[1]);
  return SSH_CRYPTO_OK;
}

SshCryptoStatus ssh_rc2_cfb(void *context, unsigned char *dest,
                            const unsigned char *src, size_t len,
                            unsigned char *iv)
{
  SshRC2Context *ctx = context;
  SshUInt32 l, r, temp[2];

  l = SSH_GET_32BIT_LSB_FIRST(iv);
  r = SSH_GET_32BIT_LSB_FIRST(iv + 4);

  if (ctx->for_encryption)
    {
      while (len)
        {
          ssh_rc2_encrypt(l, r, temp, ctx->k, TRUE);

          l = SSH_GET_32BIT_LSB_FIRST(src) ^ temp[0];
          r = SSH_GET_32BIT_LSB_FIRST(src + 4) ^ temp[1];

          temp[0] = l;
          temp[1] = r;

          SSH_PUT_32BIT_LSB_FIRST(dest, temp[0]);
          SSH_PUT_32BIT_LSB_FIRST(dest + 4, temp[1]);

          src += 8;
          dest += 8;
          len -= 8;
        }
    }
  else
    {
      while (len)
        {
          ssh_rc2_encrypt(l, r, temp, ctx->k, TRUE);

          l = SSH_GET_32BIT_LSB_FIRST(src);
          r = SSH_GET_32BIT_LSB_FIRST(src + 4);

          temp[0] ^= l;
          temp[1] ^= r;

          SSH_PUT_32BIT_LSB_FIRST(dest, temp[0]);
          SSH_PUT_32BIT_LSB_FIRST(dest + 4, temp[1]);

          src += 8;
          dest += 8;
          len -= 8;
        }
    }

  SSH_PUT_32BIT_LSB_FIRST(iv, l);
  SSH_PUT_32BIT_LSB_FIRST(iv + 4, r);
  return SSH_CRYPTO_OK;
}

SshCryptoStatus ssh_rc2_ofb(void *context, unsigned char *dest,
                            const unsigned char *src, size_t len,
                            unsigned char *iv_arg)
{
  SshRC2Context *ctx = context;
  SshUInt32 iv[2], l, r;

  iv[0] = SSH_GET_32BIT_LSB_FIRST(iv_arg);
  iv[1] = SSH_GET_32BIT_LSB_FIRST(iv_arg + 4);

  while (len)
    {
      l = iv[0];
      r = iv[1];

      ssh_rc2_encrypt(l, r, iv, ctx->k, TRUE);

      l = SSH_GET_32BIT_LSB_FIRST(src) ^ iv[0];
      r = SSH_GET_32BIT_LSB_FIRST(src + 4) ^ iv[1];

      SSH_PUT_32BIT_LSB_FIRST(dest, l);
      SSH_PUT_32BIT_LSB_FIRST(dest + 4, r);

      src += 8;
      dest += 8;
      len -= 8;
    }

  SSH_PUT_32BIT_LSB_FIRST(iv_arg, iv[0]);
  SSH_PUT_32BIT_LSB_FIRST(iv_arg + 4, iv[1]);
  return SSH_CRYPTO_OK;
}

/* rc2.c */
