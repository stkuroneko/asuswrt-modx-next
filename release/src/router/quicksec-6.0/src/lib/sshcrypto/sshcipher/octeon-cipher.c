/**
   @copyright
   Copyright (c) 2006 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Cipher routines for the Cavium Octeon crypto coprocessors.
*/

#include "sshincludes.h"
#include "sshgetput.h"
#include "sshcrypt.h"
#include "sshcipher_i.h"
#include "rijndael.h"
#include "des.h"

#ifdef SSHDIST_IPSEC_HWACCEL_OCTEON
#ifdef ASM_PLATFORM_OCTEON

#define SSH_DEBUG_MODULE "SshOcteonCipher"

#include "octeon-asm.h"

/* ****************** AES *********************************************/

typedef struct {
  size_t key_len;
  SshUInt64 key[4];
  Boolean for_encryption;
} *SshRijndaelContext, SshRijndaelContextStruct;

SshCryptoStatus ssh_rijndael_init_fb(void *context,
                                    const unsigned char *key,
                                     size_t keylen,
                                     Boolean for_encryption)
{
  SshRijndaelContext ctx = (SshRijndaelContext)context;
  SshCryptoStatus status;

  status = ssh_rijndael_init(context, key, keylen, TRUE);
  ctx->for_encryption = for_encryption;

  return status;
}


SshCryptoStatus ssh_rijndael_init(void *context,
                                  const unsigned char *key,
                                  size_t keylen,
                                  Boolean for_encryption)
{
  SshRijndaelContext ctx = (SshRijndaelContext) context;
  size_t i, key_words = 0;

  if (keylen <= 16)
    {
      key_words = 2;
      ctx->key_len = 16;
    }
  else if (keylen <= 24)
    {
      key_words = 3;
      ctx->key_len = 24;
    }
  else
    {
      key_words = 4;
      ctx->key_len = 32;
    }

  ctx->for_encryption = for_encryption;

  for (i = 0; i < key_words; i++)
    ctx->key[i] =
      (((SshUInt64) ((((i * 8) + 0) < keylen) ? key[(i * 8) + 0] : 0)) << 56) |
      (((SshUInt64) ((((i * 8) + 1) < keylen) ? key[(i * 8) + 1] : 0)) << 48) |
      (((SshUInt64) ((((i * 8) + 2) < keylen) ? key[(i * 8) + 2] : 0)) << 40) |
      (((SshUInt64) ((((i * 8) + 3) < keylen) ? key[(i * 8) + 3] : 0)) << 32) |
      (((SshUInt64) ((((i * 8) + 4) < keylen) ? key[(i * 8) + 4] : 0)) << 24) |
      (((SshUInt64) ((((i * 8) + 5) < keylen) ? key[(i * 8) + 5] : 0)) << 16) |
      (((SshUInt64) ((((i * 8) + 6) < keylen) ? key[(i * 8) + 6] : 0)) << 8) |
      (((SshUInt64) ((((i * 8) + 7) < keylen) ? key[(i * 8) + 7] : 0)));

  return SSH_CRYPTO_OK;
}

void ssh_rijndael_uninit(void *context)
{
  return;
}

SshCryptoStatus ssh_aes_init(void *context,
                             const unsigned char *key,
                             size_t keylen,
                             Boolean for_encryption)
{
  if (keylen < 16)
    return SSH_CRYPTO_KEY_TOO_SHORT;

  return ssh_rijndael_init(context, key, keylen, for_encryption);
}

SshCryptoStatus ssh_aes_init_fb(void *context,
                                const unsigned char *key,
                                size_t keylen,
                                Boolean for_encryption)
{
  if (keylen < 16)
    return SSH_CRYPTO_KEY_TOO_SHORT;

  return ssh_rijndael_init_fb(context, key, keylen, for_encryption);
}

void ssh_aes_uninit(void *context)
{
  ssh_rijndael_uninit(context);
}


static void ssh_octeon_set_key(SshRijndaelContext ctx)
{
  switch (ctx->key_len)
    {
    case 16:
      OCTEON_SET_AES_KEY(ctx->key[0],0);
      OCTEON_SET_AES_KEY(ctx->key[1],1);
      OCTEON_SET_AES_KEYLENGTH(1);
      break;

    case 24:
      OCTEON_SET_AES_KEY(ctx->key[0],0);
      OCTEON_SET_AES_KEY(ctx->key[1],1);
      OCTEON_SET_AES_KEY(ctx->key[2],2);
      OCTEON_SET_AES_KEYLENGTH(2);
      break;

    case 32:
      OCTEON_SET_AES_KEY(ctx->key[0],0);
      OCTEON_SET_AES_KEY(ctx->key[1],1);
      OCTEON_SET_AES_KEY(ctx->key[2],2);
      OCTEON_SET_AES_KEY(ctx->key[3],3);
      OCTEON_SET_AES_KEYLENGTH(3);
      break;
    }
}


/* Gets the size of Rijndael context. */
size_t ssh_rijndael_ctxsize()
{
  return sizeof(SshRijndaelContextStruct);
}

/* Encryption and decryption in electronic codebook mode */
SshCryptoStatus ssh_rijndael_ecb(void *context, unsigned char *dest,
                                 const unsigned char *src, size_t len,
                                 unsigned char *iv)
{
  SshRijndaelContext ctx = (SshRijndaelContext) context;
#ifdef KERNEL
  ENABLE_COP2();
#endif /* KERNEL */
  ssh_octeon_set_key(ctx);

  if (ctx->for_encryption)
    {
      while (len > 0)
        {
          OCTEON_SET_AES_ENC0(*((SshUInt64 *)(src)));
          OCTEON_SET_AES_ENC1(*((SshUInt64 *)(src + 8)));

          OCTEON_GET_AES_RESULT(*((SshUInt64 *)(dest)), 0);
          OCTEON_GET_AES_RESULT(*((SshUInt64 *)(dest + 8)), 1);

          src += 16;
          dest += 16;
          len -= 16;
        }
    }
  else
    {
      while (len > 0)
        {
          OCTEON_SET_AES_DEC0(*((SshUInt64 *)(src)));
          OCTEON_SET_AES_DEC1(*((SshUInt64 *)(src + 8)));

          OCTEON_GET_AES_RESULT(*((SshUInt64 *)(dest)), 0);
          OCTEON_GET_AES_RESULT(*((SshUInt64 *)(dest + 8)), 1);

          src += 16;
          dest += 16;
          len -= 16;
        }
    }




  return SSH_CRYPTO_OK;
}

SshCryptoStatus ssh_rijndael_cbc(void *context, unsigned char *dest,
                                 const unsigned char *src, size_t len,
                                 unsigned char *iv_arg)
{
  SshRijndaelContext ctx = (SshRijndaelContext) context;
#ifdef KERNEL
  ENABLE_COP2();
#endif /* KERNEL */
  ssh_octeon_set_key(ctx);

  OCTEON_SET_AES_IV(*((SshUInt64 *)(iv_arg)), 0);
  OCTEON_SET_AES_IV(*((SshUInt64 *)(iv_arg + 8)), 1);

  if (ctx->for_encryption)
    {
      while (len > 0)
        {
          OCTEON_SET_AES_ENC_CBC0(*((SshUInt64 *)(src)));
          OCTEON_SET_AES_ENC_CBC1(*((SshUInt64 *)(src + 8)));

          OCTEON_GET_AES_RESULT(*((SshUInt64 *)(dest)), 0);
          OCTEON_GET_AES_RESULT(*((SshUInt64 *)(dest + 8)), 1);

          src += 16;
          dest += 16;
          len -= 16;
        }
    }
  else
    {
      while (len > 0)
        {
          OCTEON_SET_AES_DEC_CBC0(*((SshUInt64 *)(src)));
          OCTEON_SET_AES_DEC_CBC1(*((SshUInt64 *)(src + 8)));

          OCTEON_GET_AES_RESULT(*((SshUInt64 *)(dest)), 0);
          OCTEON_GET_AES_RESULT(*((SshUInt64 *)(dest + 8)), 1);

          src += 16;
          dest += 16;
          len -= 16;
        }
    }

  OCTEON_GET_AES_IV(*((SshUInt64 *)(iv_arg)), 0);
  OCTEON_GET_AES_IV(*((SshUInt64 *)(iv_arg + 8)), 1);




  return SSH_CRYPTO_OK;
}


/* Encrypt/decrypt in output feedback mode. */
SshCryptoStatus ssh_rijndael_ofb(void *context, unsigned char *dest,
                                 const unsigned char *src, size_t len,
                                 unsigned char *iv_arg)
{
  SshRijndaelContext ctx = (SshRijndaelContext) context;
  SshUInt64 iv[2];

#ifdef KERNEL
  ENABLE_COP2();
#endif /* KERNEL */
  ssh_octeon_set_key(ctx);

  iv[0] = ((SshUInt64 *)iv_arg)[0];
  iv[1] = ((SshUInt64 *)iv_arg)[1];

  while (len > 0)
    {
      OCTEON_SET_AES_ENC0(iv[0]);
      OCTEON_SET_AES_ENC1(iv[1]);

      OCTEON_GET_AES_RESULT(iv[0], 0);
      OCTEON_GET_AES_RESULT(iv[1], 1);

      *((SshUInt64 *)(dest)) = *((SshUInt64 *)(src)) ^ iv[0];
      *((SshUInt64 *)(dest+8)) = *((SshUInt64 *)(src+8)) ^ iv[1];

      src += 16;
      dest += 16;
      len -= 16;
    }

  ((SshUInt64 *)iv_arg)[0] = iv[0];
  ((SshUInt64 *)iv_arg)[1] = iv[1];



  return SSH_CRYPTO_OK;
}

/* Encrypt in counter mode. The call to `ssh_rijndael_encrypt'
   should be made inline (as is done for cbc mode) if counter mode
   needs to be optimized. Notice also that counter mode does not
   require ssh_rijndael_decrypt.

   We assume the counter buffer '*ctr_arg' is treated as a MSB first
   integer and incremented after each block encryption. */

SshCryptoStatus ssh_rijndael_ctr(void *context, unsigned char *dest,
                                 const unsigned char *src, size_t len,
                                 unsigned char *ctr_arg)
{
  SshRijndaelContext ctx = (SshRijndaelContext) context;
  SshUInt64 iv[4], ctr[4];

  ctr[0] = SSH_GET_64BIT(ctr_arg);
  ctr[1] = SSH_GET_64BIT(ctr_arg + 8);

#ifdef KERNEL
  ENABLE_COP2();
#endif /* KERNEL */
  ssh_octeon_set_key(ctx);

  while (len >= 16)
    {
      OCTEON_SET_AES_ENC0(ctr[0]);
      OCTEON_SET_AES_ENC1(ctr[1]);

      OCTEON_GET_AES_RESULT(iv[0], 0);
      OCTEON_GET_AES_RESULT(iv[1], 1);

      *((SshUInt64 *)(dest)) = *((SshUInt64 *)(src)) ^ iv[0];
      *((SshUInt64 *)(dest+8)) = *((SshUInt64 *)(src+8)) ^ iv[1];

      src += 16;
      dest += 16;
      len -= 16;

      /* Increment the counter by 1 (treated as a MSB first integer). */
      if (++ctr[1] == 0)
        ++ctr[0];
    }

  /* Encrypt the last block (which may be less than 16 bytes) */
  if (len)
    {
      unsigned char tmp[16];

      SSH_ASSERT(len < 16);

      memset(tmp, 0, sizeof(tmp));
      memcpy(tmp, src, len);

      OCTEON_SET_AES_ENC0(ctr[0]);
      OCTEON_SET_AES_ENC1(ctr[1]);

      OCTEON_GET_AES_RESULT(iv[0], 0);
      OCTEON_GET_AES_RESULT(iv[1], 1);

      *((SshUInt64 *)(tmp)) = *((SshUInt64 *)(tmp)) ^ iv[0];
      *((SshUInt64 *)(tmp+8)) = *((SshUInt64 *)(tmp+8)) ^ iv[1];

      memcpy(dest, tmp, len);

      /* Increment the counter by 1 (treated as a MSB first integer). */
      if (++ctr[1] == 0)
        ++ctr[0];
  }

  /* Set the new counter value. */
  SSH_PUT_64BIT(ctr_arg, ctr[0]);
  SSH_PUT_64BIT(ctr_arg + 8, ctr[1]);




  return SSH_CRYPTO_OK;
}



/* Encrypt/decrypt in cipher feedback mode */
SshCryptoStatus ssh_rijndael_cfb(void *context, unsigned char *dest,
                                 const unsigned char *src, size_t len,
                                 unsigned char *iv_arg)
{
  SshRijndaelContext ctx = (SshRijndaelContext) context;
  SshUInt64 t, iv[2];

  iv[0] = ((SshUInt64 *)iv_arg)[0];
  iv[1] = ((SshUInt64 *)iv_arg)[1];

#ifdef KERNEL
  ENABLE_COP2();
#endif /* KERNEL */
  ssh_octeon_set_key(ctx);

  if (ctx->for_encryption)
    {
      while (len > 0)
        {
          OCTEON_SET_AES_ENC0(iv[0]);
          OCTEON_SET_AES_ENC1(iv[1]);

          OCTEON_GET_AES_RESULT(iv[0], 0);
          OCTEON_GET_AES_RESULT(iv[1], 1);

          *((SshUInt64 *)(dest)) = iv[0] = *((SshUInt64 *)(src)) ^ iv[0];
          *((SshUInt64 *)(dest+8)) = iv[1] = *((SshUInt64 *)(src+8)) ^ iv[1];

          src += 16;
          dest += 16;
          len -= 16;
        }
    }
  else
    {
      while (len > 0)
        {
          OCTEON_SET_AES_ENC0(iv[0]);
          OCTEON_SET_AES_ENC1(iv[1]);

          OCTEON_GET_AES_RESULT(iv[0], 0);
          OCTEON_GET_AES_RESULT(iv[1], 1);

          t=*((SshUInt64 *)(src));
          *((SshUInt64 *)(dest)) = iv[0] ^ t;
          iv[0] = t;

          t=*((SshUInt64 *)(src + 8));
          *((SshUInt64 *)(dest + 8)) = iv[1] ^ t;
          iv[1] = t;

          src += 16;
          dest += 16;
          len -= 16;
        }
    }

  ((SshUInt64 *)iv_arg)[0] = iv[0];
  ((SshUInt64 *)iv_arg)[1] = iv[1];




  return SSH_CRYPTO_OK;
}

SshCryptoStatus
ssh_rijndael_cbc_mac(void *context, const unsigned char *src, size_t len,
                     unsigned char *iv_arg)
{
  SshRijndaelContext ctx = (SshRijndaelContext) context;
  SshUInt64 iv[2];

  iv[0] = ((SshUInt64 *)iv_arg)[0];
  iv[1] = ((SshUInt64 *)iv_arg)[1];

#ifdef KERNEL
  ENABLE_COP2();
#endif /* KERNEL */
  ssh_octeon_set_key(ctx);

  while (len > 0)
    {
      iv[0] ^= ((SshUInt64 *)src)[0];
      iv[1] ^= ((SshUInt64 *)src)[1];

      OCTEON_SET_AES_ENC0(iv[0]);
      OCTEON_SET_AES_ENC1(iv[1]);

      OCTEON_GET_AES_RESULT(iv[0], 0);
      OCTEON_GET_AES_RESULT(iv[1], 1);

      src += 16;
      len -= 16;
    }

  ((SshUInt64 *)iv_arg)[0] = iv[0];
  ((SshUInt64 *)iv_arg)[1] = iv[1];





  return SSH_CRYPTO_OK;
}



static inline SshUInt64 swap64(SshUInt64 a)
{
  return ((a >> 56) |
          (((a >> 48) & 0xfful) << 8) |
          (((a >> 40) & 0xfful) << 16) |
          (((a >> 32) & 0xfful) << 24) |
          (((a >> 24) & 0xfful) << 32) |
          (((a >> 16) & 0xfful) << 40) |
          (((a >> 8) & 0xfful) << 48) |
          (((a >> 0) & 0xfful) << 56));
}

void
octeon_hmac_init(Boolean is_sha,
                 SshUInt64 *key,
                 unsigned char *inner,
                 unsigned char *outer)
{
  unsigned char hash_key[64];
  SshUInt64 *key1;
  register SshUInt64 xor1 = 0x3636363636363636ULL;
  register SshUInt64 xor2 = 0x5c5c5c5c5c5c5c5cULL;

   memset(hash_key, 0, sizeof(hash_key));
   memcpy(hash_key, (unsigned char *)key, (is_sha ? 20 : 16));
   key1 = (SshUInt64 *)hash_key;

#ifdef KERNEL
   ENABLE_COP2();
#endif

   if (is_sha)
     {
       OCTEON_SET_HASH_IV(0x67452301EFCDAB89ULL, 0);
       OCTEON_SET_HASH_IV(0x98BADCFE10325476ULL, 1);
       OCTEON_SET_HASH_IV(0xC3D2E1F000000000ULL, 2);
     }
   else
     {
       OCTEON_SET_HASH_IV(0x0123456789ABCDEFULL, 0);
       OCTEON_SET_HASH_IV(0xFEDCBA9876543210ULL, 1);
     }


   OCTEON_SET_HASH_DAT((*key1 ^ xor1), 0);
   key1++;
   OCTEON_SET_HASH_DAT((*key1 ^ xor1), 1);
   key1++;
   OCTEON_SET_HASH_DAT((*key1 ^ xor1), 2);
   key1++;
   OCTEON_SET_HASH_DAT((*key1 ^ xor1), 3);
   key1++;
   OCTEON_SET_HASH_DAT((*key1 ^ xor1), 4);
   key1++;
   OCTEON_SET_HASH_DAT((*key1 ^ xor1), 5);
   key1++;
   OCTEON_SET_HASH_DAT((*key1 ^ xor1), 6);
   key1++;

   if (is_sha)
     OCTEON_SET_HASH_STARTSHA((*key1 ^ xor1));
   else
     OCTEON_SET_HASH_STARTMD5((*key1 ^ xor1));

   OCTEON_GET_HASH_IV(((SshUInt64 *)inner)[0], 0);
   OCTEON_GET_HASH_IV(((SshUInt64 *)inner)[1], 1);

   if (is_sha)
     {
       ((SshUInt64 *)inner)[2] = 0;
       OCTEON_GET_HASH_IV(((SshUInt64 *)inner)[2], 2);
     }

   memset(hash_key, 0, sizeof(hash_key));
   memcpy(hash_key, (unsigned char *)key, (is_sha ? 20 : 16));

   key = (SshUInt64 *)hash_key;

   if (is_sha)
     {
       OCTEON_SET_HASH_IV(0x67452301EFCDAB89ULL, 0);
       OCTEON_SET_HASH_IV(0x98BADCFE10325476ULL, 1);
       OCTEON_SET_HASH_IV(0xC3D2E1F000000000ULL, 2);
     }
   else
     {
       OCTEON_SET_HASH_IV(0x0123456789ABCDEFULL, 0);
       OCTEON_SET_HASH_IV(0xFEDCBA9876543210ULL, 1);
     }

   OCTEON_SET_HASH_DAT((*key ^ xor2), 0);
   key++;
   OCTEON_SET_HASH_DAT((*key ^ xor2), 1);
   key++;
   OCTEON_SET_HASH_DAT((*key ^ xor2), 2);
   key++;
   OCTEON_SET_HASH_DAT((*key ^ xor2), 3);
   key++;
   OCTEON_SET_HASH_DAT((*key ^ xor2), 4);
   key++;
   OCTEON_SET_HASH_DAT((*key ^ xor2), 5);
   key++;
   OCTEON_SET_HASH_DAT((*key ^ xor2), 6);
   key++;

   if (is_sha)
     OCTEON_SET_HASH_STARTSHA((*key1 ^ xor2));
   else
     OCTEON_SET_HASH_STARTMD5((*key1 ^ xor2));

   OCTEON_GET_HASH_IV(((SshUInt64 *)outer)[0], 0);
   OCTEON_GET_HASH_IV(((SshUInt64 *)outer)[1], 1);

   if (is_sha)
     {
       ((SshUInt64 *)outer)[2] = 0;
       OCTEON_GET_HASH_IV(((SshUInt64 *)outer)[2], 2);
     }
#ifdef KERNEL
   DISABLE_COP2();
#endif
   return;
}

Boolean
aes_cbc_sha1_encrypt(unsigned char *dest,
                     const unsigned char *src,
                     SshUInt32 len,
                     SshUInt32 enc_ofs,
                     unsigned char *aes_key, int aes_key_len,
                     unsigned char *aes_iv,
                     SshUInt64 *start_inner_sha,
                     SshUInt64 *start_outer_sha,
                     unsigned char *digest)
{
  SshUInt64 *res = (SshUInt64 *)dest, *data = (SshUInt64 *)src;
  register SshUInt64 in1, in2, out1, out2;
  register int next = 0;
  int inplen;

   SSH_DEBUG(10, ("Entered len=%d", len));

#ifdef KERNEL
   ENABLE_COP2();
#endif

   OCTEON_PREFETCH(aes_iv, 0);
   OCTEON_PREFETCH(start_inner_sha, 0);
   OCTEON_PREFETCH(data, 0);

   OCTEON_SET_AES_KEY(((SshUInt64 *)aes_key)[0], 0);
   OCTEON_SET_AES_KEY(((SshUInt64 *)aes_key)[1], 1);

   if (aes_key_len == 16)
     {
       OCTEON_SET_AES_KEY(0x0, 2);
       OCTEON_SET_AES_KEY(0x0, 3);
     }
   else if (aes_key_len == 24)
     {
       OCTEON_SET_AES_KEY(((SshUInt64 *)aes_key)[2], 2);
       OCTEON_SET_AES_KEY(0x0, 3);
     }
   else if (aes_key_len == 32)
     {
       OCTEON_SET_AES_KEY(((SshUInt64 *)aes_key)[2], 2);
       OCTEON_SET_AES_KEY(((SshUInt64 *)aes_key)[3], 3);
     }
   else
     {
       return FALSE;
     }
   OCTEON_SET_AES_KEYLENGTH (aes_key_len/8 - 1);

   OCTEON_SET_AES_IV(((SshUInt64 *)aes_iv)[0], 0);
   OCTEON_SET_AES_IV(((SshUInt64 *)aes_iv)[1], 1);

   /* Load SHA1 IV */
   OCTEON_SET_HASH_IV(start_inner_sha[0], 0);
   OCTEON_SET_HASH_IV(start_inner_sha[1], 1);
   OCTEON_SET_HASH_IV(start_inner_sha[2], 2);

   /* Inplace */
   res = (SshUInt64 *)(src + enc_ofs);
   data = (SshUInt64 *)(src + enc_ofs);
   inplen = len - enc_ofs;

   in1 = *data++;
   in2 = *data++;
   inplen -= 16;

   OCTEON_SET_AES_ENC_CBC0(in1);
   OCTEON_SET_AES_ENC_CBC1(in2);

   OCTEON_LOAD_SHA_UNIT(*(SshUInt64 *)src, next);
   OCTEON_LOAD_SHA_UNIT(*(SshUInt64 *)(src + sizeof(SshUInt64)), next);
   OCTEON_LOAD_SHA_UNIT(*(SshUInt64 *)(src + 2 * sizeof(SshUInt64)), next);

   if (inplen < 16)
      goto res_done;

   in1 = *data++;
   in2 = *data++;

   /* Loop through input */
   /* Assumed that data is 16 byte aligned */
   if (inplen >= 32)
     {
       while (1)
         {
           OCTEON_GET_AES_RESULT(out1, 0);
           OCTEON_GET_AES_RESULT(out2, 1);
           OCTEON_SET_AES_ENC_CBC0(in1);
           OCTEON_SET_AES_ENC_CBC1(in2);
           OCTEON_LOAD2_SHA_UNIT (out1, out2, next);

           res[0] = out1;
           res[1] = out2;
           in1 = data[0];
           in2 = data[1];
           res += 2;
           data += 2;
           OCTEON_GET_AES_RESULT(out1, 0);
           OCTEON_GET_AES_RESULT(out2, 1);
           OCTEON_SET_AES_ENC_CBC0(in1);
           OCTEON_SET_AES_ENC_CBC1(in2);
           OCTEON_LOAD2_SHA_UNIT (out1, out2, next);
           res[0] = out1;
           res[1] = out2;
           in1 = data[0];
           in2 = data[1];
           res += 2;
           data += 2;
           inplen -= 32;
           if (inplen < 32)
             break;
         }
     }


   /* inplen < 32  ==> inplen = 16 or inplen = 0
      (Assuming 16 byte aligned data only) */
   if (inplen)
     {
       OCTEON_GET_AES_RESULT(out1, 0);
       OCTEON_GET_AES_RESULT(out2, 1);
       OCTEON_SET_AES_ENC_CBC0(in1);
       OCTEON_SET_AES_ENC_CBC0(in2);
       OCTEON_LOAD2_SHA_UNIT (out1, out2, next);
       res[0] = out1;
       res[1] = out2;
       res += 2;
   }

 res_done:
   OCTEON_GET_AES_RESULT(out1, 0);
   OCTEON_GET_AES_RESULT(out2, 1);
   OCTEON_LOAD2_SHA_UNIT (out1, out2, next);
    res[0] = out1;
    res[1] = out2;

   OCTEON_PREFETCH(start_outer_sha, 0);

   /* Finish Inner hash */
   OCTEON_LOAD_SHA_UNIT(0x8000000000000000ULL, next);
   while (next != 7)
     OCTEON_LOAD_SHA_UNIT(((SshUInt64)0x0ULL), next);

   OCTEON_LOAD_SHA_UNIT((SshUInt64)((len + 64) << 3), next);

   /* Get the inner hash of HMAC */
   OCTEON_GET_HASH_IV(in1, 0);
   OCTEON_GET_HASH_IV(in2, 1);
   out1 = 0;
   OCTEON_GET_HASH_IV(out1, 2);

   OCTEON_SET_HASH_IV(start_outer_sha[0], 0);
   OCTEON_SET_HASH_IV(start_outer_sha[1], 1);
   OCTEON_SET_HASH_IV(start_outer_sha[2], 2);

   OCTEON_SET_HASH_DAT(in1, 0);
   OCTEON_SET_HASH_DAT(in2, 1);
   out1 |= 0x0000000080000000;
   OCTEON_SET_HASH_DAT(out1, 2);
   OCTEON_SET_HASH_DATZ(3);
   OCTEON_SET_HASH_DATZ(4);
   OCTEON_SET_HASH_DATZ(5);
   OCTEON_SET_HASH_DATZ(6);
   OCTEON_SET_HASH_STARTSHA((SshUInt64)((64 + 20) << 3));

   /* Write the HMAC */
   res = (SshUInt64 *)digest;
   OCTEON_GET_HASH_IV(*res++, 0);
   OCTEON_GET_HASH_IV(out1, 1);
   *((SshUInt32 *)res) = (SshUInt32)(out1 >> 32);

   OCTEON_GET_HASH_IV(out1, 2);

#ifdef KERNEL
   DISABLE_COP2();
#endif
   return TRUE;
}

Boolean
aes_cbc_sha1_decrypt(unsigned char *dest,
                     const unsigned char *src,
                     SshUInt32 len,
                     SshUInt32 enc_ofs,
                     unsigned char *aes_key, int aes_key_len,
                     unsigned char *aes_iv,
                     SshUInt64 *start_inner_sha, SshUInt64 *start_outer_sha,
                     unsigned char *digest)
{
  SshUInt64 *res = (SshUInt64 *)dest, *data = (SshUInt64 *)src;
  register SshUInt64 in1, in2, out1, out2;
  register int next = 0;
  int inplen;

#ifdef KERNEL
   ENABLE_COP2();
#endif

   OCTEON_PREFETCH(aes_iv, 0);
   OCTEON_PREFETCH(start_inner_sha, 0);
   OCTEON_PREFETCH(data, 0);

   OCTEON_SET_AES_KEY(((SshUInt64 *)aes_key)[0], 0);
   OCTEON_SET_AES_KEY(((SshUInt64 *)aes_key)[1], 1);

   if (aes_key_len == 16)
     {
       OCTEON_SET_AES_KEY(0x0, 2);
       OCTEON_SET_AES_KEY(0x0, 3);
     }
   else if (aes_key_len == 24)
     {
       OCTEON_SET_AES_KEY(((SshUInt64 *)aes_key)[2], 2);
       OCTEON_SET_AES_KEY(0x0, 3);
     }
   else if (aes_key_len == 32)
     {
       OCTEON_SET_AES_KEY(((SshUInt64 *)aes_key)[2], 2);
       OCTEON_SET_AES_KEY(((SshUInt64 *)aes_key)[3], 3);
     }
   else
     {
       return FALSE;
     }
   OCTEON_SET_AES_KEYLENGTH (aes_key_len / 8 - 1);

   OCTEON_SET_AES_IV(((SshUInt64 *)aes_iv)[0], 0);
   OCTEON_SET_AES_IV(((SshUInt64 *)aes_iv)[1], 1);

   /* Load SHA1 IV */
   OCTEON_SET_HASH_IV(start_inner_sha[0], 0);
   OCTEON_SET_HASH_IV(start_inner_sha[1], 1);
   OCTEON_SET_HASH_IV(start_inner_sha[2], 2);

   data = (SshUInt64 *)(src + enc_ofs);
   res = (SshUInt64 *)(dest + enc_ofs);

   inplen = len - enc_ofs;

   in1 = *data++;
   in2 = *data++;
   inplen -= 16;

   OCTEON_SET_AES_DEC_CBC0(in1);
   OCTEON_SET_AES_DEC_CBC1(in2);

   OCTEON_LOAD_SHA_UNIT(*(SshUInt64 *)src, next);
   OCTEON_LOAD_SHA_UNIT(*(SshUInt64 *)(src + sizeof(SshUInt64)), next);
   OCTEON_LOAD_SHA_UNIT(*(SshUInt64 *)(src + 2*sizeof(SshUInt64)), next);

   OCTEON_LOAD2_SHA_UNIT(in1, in2, next);

   if (inplen < 16)
      goto res_done;

   in1 = *data++;
   in2 = *data++;

   /* Loop through input */
   /* Assumed that data is 16 byte aligned */
   if (inplen >= 32)
     {
      while (1)
        {
          OCTEON_GET_AES_RESULT(out1, 0);
          OCTEON_GET_AES_RESULT(out2, 1);
          OCTEON_SET_AES_DEC_CBC0(in1);
          OCTEON_SET_AES_DEC_CBC1(in2);
          OCTEON_LOAD2_SHA_UNIT (in1, in2, next);
          res[0] = out1;
          res[1] = out2;
          in1 = data[0];
          in2 = data[1];
          res += 2;
          data += 2;
          OCTEON_GET_AES_RESULT(out1, 0);
          OCTEON_GET_AES_RESULT(out2, 1);
          OCTEON_SET_AES_DEC_CBC0(in1);
          OCTEON_SET_AES_DEC_CBC1(in2);
          OCTEON_LOAD2_SHA_UNIT (in1, in2, next);
          res[0] = out1;
          res[1] = out2;
          in1 = data[0];
          in2 = data[1];
          res += 2;
          data += 2;
          inplen -= 32;
          if (inplen < 32)
            break;
        }
   }

   /* inplen < 32  ==> inplen = 16 or inplen = 0
      (Assuming 16 byte aligned data only) */
   if (inplen)
     {
       OCTEON_GET_AES_RESULT(out1, 0);
       OCTEON_GET_AES_RESULT(out2, 1);
       OCTEON_SET_AES_DEC_CBC0(in1);
       OCTEON_SET_AES_DEC_CBC0(in2);
       OCTEON_LOAD2_SHA_UNIT (in1, in2, next);
       res[0] = out1;
       res[1] = out2;
       res += 2;
     }

res_done:
   OCTEON_GET_AES_RESULT(out1, 0);
   OCTEON_GET_AES_RESULT(out2, 1);
    res[0] = out1;
    res[1] = out2;

   OCTEON_PREFETCH(start_outer_sha, 0);
   /* Finish Inner hash */
   OCTEON_LOAD_SHA_UNIT(0x8000000000000000ULL, next);
   while (next != 7)
     OCTEON_LOAD_SHA_UNIT(((SshUInt64)0x0ULL), next);

   OCTEON_LOAD_SHA_UNIT((SshUInt64)((len + 64) << 3), next);

   /* Get the inner hash of HMAC */
   OCTEON_GET_HASH_IV(in1, 0);
   OCTEON_GET_HASH_IV(in2, 1);
   out1 = 0;
   OCTEON_GET_HASH_IV(out1, 2);

   OCTEON_PREFETCH(src + len, 0);

   OCTEON_SET_HASH_IV(start_outer_sha[0], 0);
   OCTEON_SET_HASH_IV(start_outer_sha[1], 1);
   OCTEON_SET_HASH_IV(start_outer_sha[2], 2);

   OCTEON_SET_HASH_DAT(in1, 0);
   OCTEON_SET_HASH_DAT(in2, 1);
   out1 |= 0x0000000080000000;
   OCTEON_SET_HASH_DAT(out1, 2);
   OCTEON_SET_HASH_DATZ(3);
   OCTEON_SET_HASH_DATZ(4);
   OCTEON_SET_HASH_DATZ(5);
   OCTEON_SET_HASH_DATZ(6);
   OCTEON_SET_HASH_STARTSHA((SshUInt64)((64 + 20) << 3));

   /* Get and compare the HMAC */
   res = (SshUInt64 *)digest;
   OCTEON_GET_HASH_IV(out1, 0);
   if (out1 != *res)
     goto fail;

   OCTEON_GET_HASH_IV(out2, 1);
   if (*(SshUInt32 *)(res + 1) != (SshUInt32)(out2 >> 32))
     goto fail;

   OCTEON_GET_HASH_IV(out2, 2);

#ifdef KERNEL
   DISABLE_COP2();
#endif
   return TRUE;

 fail:
#ifdef KERNEL
   DISABLE_COP2();
#endif
  return FALSE;
}

Boolean
aes_cbc_md5_encrypt(unsigned char *dest,
                    const unsigned char *src,
                    SshUInt32 len,
                    SshUInt32 enc_ofs,
                    unsigned char *aes_key, int aes_key_len,
                    unsigned char *aes_iv,
                    SshUInt64 *start_inner_md5,
                    SshUInt64 *start_outer_md5,
                    unsigned char *digest)
{
  SshUInt64 *res = (SshUInt64 *)dest, *data = (SshUInt64 *)src;
  register SshUInt64 in1, in2, out1, out2;
  register int next = 0;
  int inplen;

   SSH_DEBUG(10, ("Entered len=%d", len));

#ifdef KERNEL
   ENABLE_COP2();
#endif

   OCTEON_PREFETCH(aes_iv, 0);
   OCTEON_PREFETCH(start_inner_md5, 0);
   OCTEON_PREFETCH(data, 0);

   OCTEON_SET_AES_KEY(((SshUInt64 *)aes_key)[0], 0);
   OCTEON_SET_AES_KEY(((SshUInt64 *)aes_key)[1], 1);

   if (aes_key_len == 16)
     {
       OCTEON_SET_AES_KEY(0x0, 2);
       OCTEON_SET_AES_KEY(0x0, 3);
     }
   else if (aes_key_len == 24)
     {
       OCTEON_SET_AES_KEY(((SshUInt64 *)aes_key)[2], 2);
       OCTEON_SET_AES_KEY(0x0, 3);
     }
   else if (aes_key_len == 32)
     {
       OCTEON_SET_AES_KEY(((SshUInt64 *)aes_key)[2], 2);
       OCTEON_SET_AES_KEY(((SshUInt64 *)aes_key)[3], 3);
     }
   else
     {
       return FALSE;
     }
   OCTEON_SET_AES_KEYLENGTH (aes_key_len/8 - 1);

   OCTEON_SET_AES_IV(((SshUInt64 *)aes_iv)[0], 0);
   OCTEON_SET_AES_IV(((SshUInt64 *)aes_iv)[1], 1);

   /* Load MD5  IV */
   OCTEON_SET_HASH_IV(start_inner_md5[0], 0);
   OCTEON_SET_HASH_IV(start_inner_md5[1], 1);

   /* Inplace */
   res = (SshUInt64 *)(src + enc_ofs);
   data = (SshUInt64 *)(src + enc_ofs);
   inplen = len - enc_ofs;

   in1 = *data++;
   in2 = *data++;
   inplen -= 16;

   OCTEON_SET_AES_ENC_CBC0(in1);
   OCTEON_SET_AES_ENC_CBC1(in2);

   OCTEON_LOAD_MD5_UNIT(*(SshUInt64 *)src, next);
   OCTEON_LOAD_MD5_UNIT(*(SshUInt64 *)(src + sizeof(SshUInt64)), next);
   OCTEON_LOAD_MD5_UNIT(*(SshUInt64 *)(src + 2 * sizeof(SshUInt64)), next);

   if (inplen < 16)
      goto res_done;

   in1 = *data++;
   in2 = *data++;

   /* Loop through input */
   /* Assumed that data is 16 byte aligned */
   if (inplen >= 32)
     {
       while (1)
         {
           OCTEON_GET_AES_RESULT(out1, 0);
           OCTEON_GET_AES_RESULT(out2, 1);
           OCTEON_SET_AES_ENC_CBC0(in1);
           OCTEON_SET_AES_ENC_CBC1(in2);
           OCTEON_LOAD2_MD5_UNIT(out1, out2, next);

           res[0] = out1;
           res[1] = out2;
           in1 = data[0];
           in2 = data[1];
           res += 2;
           data += 2;
           OCTEON_GET_AES_RESULT(out1, 0);
           OCTEON_GET_AES_RESULT(out2, 1);
           OCTEON_SET_AES_ENC_CBC0(in1);
           OCTEON_SET_AES_ENC_CBC1(in2);
           OCTEON_LOAD2_MD5_UNIT(out1, out2, next);
           res[0] = out1;
           res[1] = out2;
           in1 = data[0];
           in2 = data[1];
           res += 2;
           data += 2;
           inplen -= 32;
           if (inplen < 32)
             break;
         }
     }


   /* inplen < 32  ==> inplen = 16 or inplen = 0
      (Assuming 16 byte aligned data only) */
   if (inplen)
     {
       OCTEON_GET_AES_RESULT(out1, 0);
       OCTEON_GET_AES_RESULT(out2, 1);
       OCTEON_SET_AES_ENC_CBC0(in1);
       OCTEON_SET_AES_ENC_CBC0(in2);
       OCTEON_LOAD2_MD5_UNIT(out1, out2, next);
       res[0] = out1;
       res[1] = out2;
       res += 2;
   }

 res_done:
   OCTEON_GET_AES_RESULT(out1, 0);
   OCTEON_GET_AES_RESULT(out2, 1);
   OCTEON_LOAD2_MD5_UNIT (out1, out2, next);
   res[0] = out1;
   res[1] = out2;

   OCTEON_PREFETCH(start_outer_md5, 0);

   /* Finish Inner hash */
   OCTEON_LOAD_MD5_UNIT(0x8000000000000000ULL, next);
   while (next != 7)
     OCTEON_LOAD_MD5_UNIT(((SshUInt64)0x0ULL), next);

   OCTEON_LOAD_MD5_UNIT(swap64((SshUInt64)((len + 64) << 3)), next);

   /* Get the inner hash of HMAC */
   OCTEON_GET_HASH_IV(in1, 0);
   OCTEON_GET_HASH_IV(in2, 1);

   OCTEON_SET_HASH_IV(start_outer_md5[0], 0);
   OCTEON_SET_HASH_IV(start_outer_md5[1], 1);

   OCTEON_SET_HASH_DAT(in1, 0);
   OCTEON_SET_HASH_DAT(in2, 1);
   out1 = 0x8000000000000000ULL;
   OCTEON_SET_HASH_DAT(out1, 2);
   OCTEON_SET_HASH_DATZ(3);
   OCTEON_SET_HASH_DATZ(4);
   OCTEON_SET_HASH_DATZ(5);
   OCTEON_SET_HASH_DATZ(6);
   OCTEON_SET_HASH_STARTMD5(swap64((SshUInt64)((64 + 16) << 3)));

   /* Write the HMAC */
   res = (SshUInt64 *)digest;
   OCTEON_GET_HASH_IV(*res++, 0);
   OCTEON_GET_HASH_IV(out1, 1);
   *((SshUInt32 *)res) = (SshUInt32)(out1 >> 32);

#ifdef KERNEL
   DISABLE_COP2();
#endif
   return TRUE;
}

Boolean
aes_cbc_md5_decrypt(unsigned char *dest,
                    const unsigned char *src,
                    SshUInt32 len,
                    SshUInt32 enc_ofs,
                    unsigned char *aes_key, int aes_key_len,
                    unsigned char *aes_iv,
                    SshUInt64 *start_inner_md5,
                    SshUInt64 *start_outer_md5,
                    unsigned char *digest)
{
  SshUInt64 *res = (SshUInt64 *)dest, *data = (SshUInt64 *)src;
  register SshUInt64 in1, in2, out1, out2;
  register int next = 0;
  int inplen;

#ifdef KERNEL
   ENABLE_COP2();
#endif

   OCTEON_PREFETCH(aes_iv, 0);
   OCTEON_PREFETCH(start_inner_md5, 0);
   OCTEON_PREFETCH(data, 0);

   OCTEON_SET_AES_KEY(((SshUInt64 *)aes_key)[0], 0);
   OCTEON_SET_AES_KEY(((SshUInt64 *)aes_key)[1], 1);

   if (aes_key_len == 16)
     {
       OCTEON_SET_AES_KEY(0x0, 2);
       OCTEON_SET_AES_KEY(0x0, 3);
     }
   else if (aes_key_len == 24)
     {
       OCTEON_SET_AES_KEY(((SshUInt64 *)aes_key)[2], 2);
       OCTEON_SET_AES_KEY(0x0, 3);
     }
   else if (aes_key_len == 32)
     {
       OCTEON_SET_AES_KEY(((SshUInt64 *)aes_key)[2], 2);
       OCTEON_SET_AES_KEY(((SshUInt64 *)aes_key)[3], 3);
     }
   else
     {
       return FALSE;
     }
   OCTEON_SET_AES_KEYLENGTH (aes_key_len / 8 - 1);

   OCTEON_SET_AES_IV(((SshUInt64 *)aes_iv)[0], 0);
   OCTEON_SET_AES_IV(((SshUInt64 *)aes_iv)[1], 1);

   /* Load MD5 IV */
   OCTEON_SET_HASH_IV(start_inner_md5[0], 0);
   OCTEON_SET_HASH_IV(start_inner_md5[1], 1);

   data = (SshUInt64 *)(src + enc_ofs);
   res = (SshUInt64 *)(dest + enc_ofs);

   inplen = len - enc_ofs;

   in1 = *data++;
   in2 = *data++;
   inplen -= 16;

   OCTEON_SET_AES_DEC_CBC0(in1);
   OCTEON_SET_AES_DEC_CBC1(in2);

   OCTEON_LOAD_MD5_UNIT(*(SshUInt64 *)src, next);
   OCTEON_LOAD_MD5_UNIT(*(SshUInt64 *)(src + sizeof(SshUInt64)), next);
   OCTEON_LOAD_MD5_UNIT(*(SshUInt64 *)(src + 2*sizeof(SshUInt64)), next);

   OCTEON_LOAD2_MD5_UNIT(in1, in2, next);

   if (inplen < 16)
      goto res_done;

   in1 = *data++;
   in2 = *data++;

   /* Loop through input */
   /* Assumed that data is 16 byte aligned */
   if (inplen >= 32)
     {
      while (1)
        {
          OCTEON_GET_AES_RESULT(out1, 0);
          OCTEON_GET_AES_RESULT(out2, 1);
          OCTEON_SET_AES_DEC_CBC0(in1);
          OCTEON_SET_AES_DEC_CBC1(in2);
          OCTEON_LOAD2_MD5_UNIT(in1, in2, next);
          res[0] = out1;
          res[1] = out2;
          in1 = data[0];
          in2 = data[1];
          res += 2;
          data += 2;
          OCTEON_GET_AES_RESULT(out1, 0);
          OCTEON_GET_AES_RESULT(out2, 1);
          OCTEON_SET_AES_DEC_CBC0(in1);
          OCTEON_SET_AES_DEC_CBC1(in2);
          OCTEON_LOAD2_MD5_UNIT(in1, in2, next);
          res[0] = out1;
          res[1] = out2;
          in1 = data[0];
          in2 = data[1];
          res += 2;
          data += 2;
          inplen -= 32;
          if (inplen < 32)
            break;
        }
   }

   /* inplen < 32  ==> inplen = 16 or inplen = 0
      (Assuming 16 byte aligned data only) */
   if (inplen)
     {
       OCTEON_GET_AES_RESULT(out1, 0);
       OCTEON_GET_AES_RESULT(out2, 1);
       OCTEON_SET_AES_DEC_CBC0(in1);
       OCTEON_SET_AES_DEC_CBC0(in2);
       OCTEON_LOAD2_MD5_UNIT (in1, in2, next);
       res[0] = out1;
       res[1] = out2;
       res += 2;
     }

res_done:
   OCTEON_GET_AES_RESULT(out1, 0);
   OCTEON_GET_AES_RESULT(out2, 1);
    res[0] = out1;
    res[1] = out2;

   OCTEON_PREFETCH(start_outer_md5, 0);
   /* Finish Inner hash */
   OCTEON_LOAD_MD5_UNIT(0x8000000000000000ULL, next);
   while (next != 7)
     OCTEON_LOAD_MD5_UNIT(((SshUInt64)0x0ULL), next);

   OCTEON_LOAD_MD5_UNIT(swap64((SshUInt64)((len + 64) << 3)), next);

   /* Get the inner hash of HMAC */
   OCTEON_GET_HASH_IV(in1, 0);
   OCTEON_GET_HASH_IV(in2, 1);

   OCTEON_PREFETCH(src + len, 0);

   OCTEON_SET_HASH_IV(start_outer_md5[0], 0);
   OCTEON_SET_HASH_IV(start_outer_md5[1], 1);

   OCTEON_SET_HASH_DAT(in1, 0);
   OCTEON_SET_HASH_DAT(in2, 1);
   out1 = 0x8000000000000000ULL;
   OCTEON_SET_HASH_DAT(out1, 2);
   OCTEON_SET_HASH_DATZ(3);
   OCTEON_SET_HASH_DATZ(4);
   OCTEON_SET_HASH_DATZ(5);
   OCTEON_SET_HASH_DATZ(6);
   OCTEON_SET_HASH_STARTMD5(swap64((SshUInt64)((64 + 16) << 3)));

   /* Get and compare the HMAC */
   res = (SshUInt64 *)digest;
   OCTEON_GET_HASH_IV(out1, 0);
   if (out1 != *res)
     goto fail;

   OCTEON_GET_HASH_IV(out2, 1);
   if (*(SshUInt32 *)(res + 1) != (SshUInt32)(out2 >> 32))
     goto fail;

#ifdef KERNEL
   DISABLE_COP2();
#endif
   return TRUE;

 fail:
#ifdef KERNEL
   DISABLE_COP2();
#endif
  return FALSE;

}


typedef struct SshAesHMacContextRec {
  SshRijndaelContextStruct ciph;
  Boolean for_encryption;
  unsigned char inner_hash[24];
  unsigned char outer_hash[24];
} *SshAesHMacContext, SshAesHMacContextStruct;


size_t ssh_aes_sha1_ctxsize(void)
{
  return sizeof (SshAesHMacContextStruct);
}

SshCryptoStatus ssh_aes_sha1_init(void *context,
                                  const unsigned char *cipher_key,
                                  size_t cipher_keylen,
                                  const unsigned char *mac_key,
                                  size_t mac_keylen,
                                  Boolean for_encryption)
{
  SshAesHMacContext ctx = (SshAesHMacContext)context;
  SshCryptoStatus status;

  SSH_DEBUG(10, ("Entered"));

  status = ssh_rijndael_init(&ctx->ciph, cipher_key, cipher_keylen,
                             for_encryption);

  if (status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(3, ("ERROR"));
      return status;
    }

  ctx->for_encryption = for_encryption;

  /* Initialize mac compute inner and outer digest */
  octeon_hmac_init(TRUE, (SshUInt64*)mac_key,
                   ctx->inner_hash, ctx->outer_hash);
  return SSH_CRYPTO_OK;
}

Boolean ssh_aes_sha1_transform(void *context, unsigned char *dest,
                               const unsigned char *src,
                               size_t len,
                               size_t enc_ofs,
                               unsigned char *iv,
                               unsigned char *digest)
{
  SshAesHMacContext ctx = (SshAesHMacContext)context;

  if (ctx->for_encryption)
    return aes_cbc_sha1_encrypt(dest, src, len, enc_ofs,
                                (unsigned char *)ctx->ciph.key,
                                ctx->ciph.key_len,
                                iv,
                                (SshUInt64 *)ctx->inner_hash,
                                (SshUInt64 *)ctx->outer_hash,
                                digest);
  else
    return aes_cbc_sha1_decrypt(dest, src, len, enc_ofs,
                                (unsigned char *)ctx->ciph.key,
                                ctx->ciph.key_len,
                                iv,
                                (SshUInt64 *)ctx->inner_hash,
                                (SshUInt64 *)ctx->outer_hash,
                                digest);
}

size_t ssh_aes_md5_ctxsize(void)
{
  return sizeof (SshAesHMacContextStruct);
}

SshCryptoStatus ssh_aes_md5_init(void *context,
                                  const unsigned char *cipher_key,
                                  size_t cipher_keylen,
                                  const unsigned char *mac_key,
                                  size_t mac_keylen,
                                  Boolean for_encryption)
{
  SshAesHMacContext ctx = (SshAesHMacContext)context;
  SshCryptoStatus status;

  SSH_DEBUG(10, ("Entered"));

  status = ssh_rijndael_init(&ctx->ciph, cipher_key, cipher_keylen,
                             for_encryption);

  if (status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(3, ("ERROR"));
      return status;
    }

  ctx->for_encryption = for_encryption;

  /* Initialize mac compute inner and outer digest */
  octeon_hmac_init(FALSE, (SshUInt64*)mac_key,
                   ctx->inner_hash, ctx->outer_hash);

  return SSH_CRYPTO_OK;
}

Boolean ssh_aes_md5_transform(void *context, unsigned char *dest,
                              const unsigned char *src, size_t len,
                               size_t enc_ofs,
                               unsigned char *iv,
                               unsigned char *digest)
{
  SshAesHMacContext ctx = (SshAesHMacContext)context;

  if (ctx->for_encryption)
    return aes_cbc_md5_encrypt(dest, src, len, enc_ofs,
                               (unsigned char *)ctx->ciph.key,
                               ctx->ciph.key_len,
                               iv,
                               (SshUInt64 *)ctx->inner_hash,
                               (SshUInt64 *)ctx->outer_hash,
                               digest);
  else
    return aes_cbc_md5_decrypt(dest, src, len, enc_ofs,
                               (unsigned char *)ctx->ciph.key,
                               ctx->ciph.key_len,
                               iv,
                               (SshUInt64 *)ctx->inner_hash,
                               (SshUInt64 *)ctx->outer_hash,
                               digest);
}



/* ****************** 3 DES *********************************************/

typedef struct
{
  Boolean for_encryption;
  SshUInt64 key[3];
} SshTripleDESContext;


size_t ssh_des3_ctxsize()
{
  return sizeof(SshTripleDESContext);
}

SshCryptoStatus ssh_des3_init(void *ptr,
                             const unsigned char *key, size_t keylen,
                             Boolean for_encryption)
{
  SshTripleDESContext *ctx = (SshTripleDESContext *)ptr;
  int i;

  if (keylen < 24)
    return SSH_CRYPTO_KEY_TOO_SHORT;

  ctx->for_encryption = for_encryption;

  SSH_DEBUG(SSH_D_MY, ("In Octeon 3des init"));

  for (i = 0; i < 3; i++)
    ctx->key[i] =
      (((SshUInt64) key[(i * 8) + 0]) << 56) |
      (((SshUInt64) key[(i * 8) + 1]) << 48) |
      (((SshUInt64) key[(i * 8) + 2]) << 40) |
      (((SshUInt64) key[(i * 8) + 3]) << 32) |
      (((SshUInt64) key[(i * 8) + 4]) << 24) |
      (((SshUInt64) key[(i * 8) + 5]) << 16) |
      (((SshUInt64) key[(i * 8) + 6]) << 8) |
      ((SshUInt64) key[(i * 8) + 7]);

  return SSH_CRYPTO_OK;
}

void ssh_des3_uninit(void *context)
{
  return;
}


SshCryptoStatus
ssh_des3_init_with_key_check(void *ptr,
                            const unsigned char *key, size_t keylen,
                            Boolean for_encryption)
{
  SshTripleDESContext *ctx = (SshTripleDESContext *)ptr;
  int i;

  SSH_DEBUG(SSH_D_MY, ("In Octeon 3des init with key check"));

  if (keylen < 24)
    return SSH_CRYPTO_KEY_TOO_SHORT;

  if (ssh_des_init_is_weak_key(key))
    return SSH_CRYPTO_KEY_WEAK;

  /* Not a weak key continue. */
  ctx->for_encryption = for_encryption;

  for (i = 0; i < 3; i++)
    ctx->key[i] =
      (((SshUInt64) key[(i * 8) + 0]) << 56) |
      (((SshUInt64) key[(i * 8) + 1]) << 48) |
      (((SshUInt64) key[(i * 8) + 2]) << 40) |
      (((SshUInt64) key[(i * 8) + 3]) << 32) |
      (((SshUInt64) key[(i * 8) + 4]) << 24) |
      (((SshUInt64) key[(i * 8) + 5]) << 16) |
      (((SshUInt64) key[(i * 8) + 6]) << 8) |
      ((SshUInt64) key[(i * 8) + 7]);

  return SSH_CRYPTO_OK;
}


/* Encryption and decryption in electronic codebook mode */
SshCryptoStatus ssh_des3_ecb(void *context, unsigned char *dest,
                             const unsigned char *src, size_t len,
                             unsigned char *iv)
{
  SshTripleDESContext *ctx = (SshTripleDESContext *) context;

#ifdef KERNEL
  ENABLE_COP2();
#endif /* KERNEL */
  OCTEON_SET_3DES_KEY(ctx->key[0], 0);
  OCTEON_SET_3DES_KEY(ctx->key[1], 1);
  OCTEON_SET_3DES_KEY(ctx->key[2], 2);

  if (ctx->for_encryption)
    {
      while (len > 0)
        {
          OCTEON_SET_3DES_ENC(*((SshUInt64 *)(src)));
          OCTEON_GET_3DES_RESULT(*((SshUInt64 *)(dest)));

          src += 8;
          dest += 8;
          len -= 8;
        }
    }
  else
    {
      while (len > 0)
        {
          OCTEON_SET_3DES_DEC(*((SshUInt64 *)(src)));
          OCTEON_GET_3DES_RESULT(*((SshUInt64 *)(dest)));

          src += 8;
          dest += 8;
          len -= 8;
        }
    }




  return SSH_CRYPTO_OK;
}

SshCryptoStatus ssh_des3_cbc(void *context, unsigned char *dest,
                             const unsigned char *src, size_t len,
                             unsigned char *iv_arg)
{
  SshTripleDESContext *ctx = (SshTripleDESContext *)context;

#ifdef KERNEL
    ENABLE_COP2();
#endif /* KERNEL */
  OCTEON_SET_3DES_KEY(ctx->key[0], 0);
  OCTEON_SET_3DES_KEY(ctx->key[1], 1);
  OCTEON_SET_3DES_KEY(ctx->key[2], 2);

  OCTEON_SET_3DES_IV(*((SshUInt64 *)(iv_arg)));

  if (ctx->for_encryption)
    {
      while (len > 0)
        {
          OCTEON_SET_3DES_ENC_CBC(*((SshUInt64 *)(src)));
          OCTEON_GET_3DES_RESULT(*((SshUInt64 *)(dest)));

          src += 8;
          dest += 8;
          len -= 8;
        }
    }
  else
    {
      while (len > 0)
        {
          OCTEON_SET_3DES_DEC_CBC(*((SshUInt64 *)(src)));
          OCTEON_GET_3DES_RESULT(*((SshUInt64 *)(dest)));

          src += 8;
          dest += 8;
          len -= 8;
        }
    }

 OCTEON_GET_3DES_IV(*((SshUInt64 *)(iv_arg)));




  return SSH_CRYPTO_OK;
}


/* Encrypt/decrypt in output feedback mode. */
SshCryptoStatus ssh_des3_ofb(void *context, unsigned char *dest,
                             const unsigned char *src, size_t len,
                             unsigned char *iv_arg)
{
  SshTripleDESContext *ctx = (SshTripleDESContext *) context;
  SshUInt64 iv, t;

  SSH_DEBUG(SSH_D_MY, ("In Octeon 3des OFB"));

#ifdef KERNEL
    ENABLE_COP2();
#endif /* KERNEL */
  OCTEON_SET_3DES_KEY(ctx->key[0], 0);
  OCTEON_SET_3DES_KEY(ctx->key[1], 1);
  OCTEON_SET_3DES_KEY(ctx->key[2], 2);

  iv = ((SshUInt64 *)iv_arg)[0];

  while (len > 0)
    {
      OCTEON_SET_3DES_ENC(iv);
      OCTEON_GET_3DES_RESULT(iv);

      t = *((SshUInt64 *)(src)) ^ iv;
      *((SshUInt64 *)(dest)) = t;

      src += 8;
      dest += 8;
      len -= 8;
    }

  ((SshUInt64 *)iv_arg)[0] = iv;




  return SSH_CRYPTO_OK;
}


/* Encrypt/decrypt in cipher feedback mode */
SshCryptoStatus ssh_des3_cfb(void *context, unsigned char *dest,
                             const unsigned char *src, size_t len,
                             unsigned char *iv_arg)
{
  SshTripleDESContext *ctx = (SshTripleDESContext *) context;
  SshUInt64 t, iv;

  iv = ((SshUInt64 *)iv_arg)[0];

#ifdef KERNEL
    ENABLE_COP2();
#endif /* KERNEL */
  OCTEON_SET_3DES_KEY(ctx->key[0], 0);
  OCTEON_SET_3DES_KEY(ctx->key[1], 1);
  OCTEON_SET_3DES_KEY(ctx->key[2], 2);

  if (ctx->for_encryption)
    {
      while (len > 0)
        {
          OCTEON_SET_3DES_ENC(iv);
          OCTEON_GET_3DES_RESULT(iv);

          *((SshUInt64 *)(dest)) = iv = *((SshUInt64 *)(src)) ^ iv;

          src += 8;
          dest += 8;
          len -= 8;
        }
    }
  else
    {
      while (len > 0)
        {
          OCTEON_SET_3DES_ENC(iv);
          OCTEON_GET_3DES_RESULT(iv);

          t = *((SshUInt64 *)(src));
          *((SshUInt64 *)(dest)) = iv ^ t;
          iv  = t;

          src += 8;
          dest += 8;
          len -= 8;
        }
    }

  ((SshUInt64 *)iv_arg)[0] = iv;




  return SSH_CRYPTO_OK;
}

Boolean
des3_cbc_sha1_encrypt(unsigned char *dest,
                      const unsigned char *src,
                      SshUInt32 len,
                      SshUInt32 enc_ofs,
                      unsigned char *des_key,
                      unsigned char *des_iv,
                      SshUInt64 *start_inner_sha,
                      SshUInt64 *start_outer_sha,
                      unsigned char *digest)
{
  SshUInt64 *res = (SshUInt64 *)dest, *data = (SshUInt64 *)src;
  register SshUInt64 in, out, tmp;
  register int next = 0;
  int inplen;

   SSH_DEBUG(10, ("Entered len=%d", len));

#ifdef KERNEL
   ENABLE_COP2();
#endif

   OCTEON_PREFETCH(des_iv, 0);
   OCTEON_PREFETCH(start_inner_sha, 0);
   OCTEON_PREFETCH(data, 0);

   OCTEON_SET_3DES_KEY(((SshUInt64 *)des_key)[0], 0);
   OCTEON_SET_3DES_KEY(((SshUInt64 *)des_key)[1], 1);
   OCTEON_SET_3DES_KEY(((SshUInt64 *)des_key)[2], 2);

   out = *(SshUInt64 *)des_iv;
   OCTEON_SET_3DES_IV(out);

   /* Load SHA1 IV */
   OCTEON_SET_HASH_IV(start_inner_sha[0], 0);
   OCTEON_SET_HASH_IV(start_inner_sha[1], 1);
   OCTEON_SET_HASH_IV(start_inner_sha[2], 2);

   res = (SshUInt64 *)(src + enc_ofs);
   data = (SshUInt64 *)(src + enc_ofs);
   inplen = len - enc_ofs;

   in = *data++;
   inplen -= 8;

   OCTEON_SET_3DES_ENC_CBC(in);

   OCTEON_LOAD_SHA_UNIT(*(SshUInt64 *)src, next);
   OCTEON_LOAD_SHA_UNIT(*(SshUInt64 *)(src + sizeof(SshUInt64)), next);

   if (inplen < 8)
      goto res_done;

   in = *data++;

   /* Loop through input */
   /* Assumed that data is 8 byte aligned */
   if (inplen >= 16)
     {
       while (1)
         {
           OCTEON_GET_3DES_RESULT(out);
           OCTEON_SET_3DES_ENC_CBC(in);
           OCTEON_LOAD_SHA_UNIT (out, next);
           res[0] = out;
           in = data[0];
           res++;
           data++;
           OCTEON_GET_3DES_RESULT(out);
           OCTEON_SET_3DES_ENC_CBC(in);
           OCTEON_LOAD_SHA_UNIT(out, next);
           res[0] = out;
           in = data[0];
           res++;
           data++;
           inplen -= 16;
           if (inplen < 16)
             break;
         }
     }
   /* inplen < 16 ==> inplen = 8 or inplen = 0
      (Assuming 8 byte aligned data only) */
   if (inplen)
     {
       OCTEON_GET_3DES_RESULT(out);
       OCTEON_SET_3DES_ENC_CBC(in);
       OCTEON_LOAD_SHA_UNIT (out, next);
       res[0] = out;
       res++;
     }

 res_done:
   OCTEON_GET_3DES_RESULT(out);
   OCTEON_LOAD_SHA_UNIT (out, next);
   res[0] = out;


   OCTEON_PREFETCH(start_outer_sha, 0);
   /* Finish Inner hash */
   {
     OCTEON_LOAD_SHA_UNIT(0x8000000000000000ULL, next);
     while (next != 7) {
       OCTEON_LOAD_SHA_UNIT(((SshUInt64)0x0ULL), next);
     }
     OCTEON_LOAD_SHA_UNIT((SshUInt64)((len + 64) << 3), next);
   }

   /* Get the inner hash of HMAC */
   OCTEON_GET_HASH_IV(in, 0);
   OCTEON_GET_HASH_IV(tmp, 1);
   out = 0;
   OCTEON_GET_HASH_IV(out, 2);

   /* Initialize hash unit */
   OCTEON_SET_HASH_IV(start_outer_sha[0], 0);
   OCTEON_SET_HASH_IV(start_outer_sha[1], 1);
   OCTEON_SET_HASH_IV(start_outer_sha[2], 2);

   OCTEON_SET_HASH_DAT(in, 0);
   OCTEON_SET_HASH_DAT(tmp, 1);
   out |= 0x0000000080000000;
   OCTEON_SET_HASH_DAT(out, 2);
   OCTEON_SET_HASH_DATZ(3);
   OCTEON_SET_HASH_DATZ(4);
   OCTEON_SET_HASH_DATZ(5);
   OCTEON_SET_HASH_DATZ(6);
   OCTEON_SET_HASH_STARTSHA((SshUInt64)((64 + 20) << 3));

   /* Get the HMAC */
   res = (SshUInt64 *)digest;
   OCTEON_GET_HASH_IV(*res++, 0);
   OCTEON_GET_HASH_IV(out, 1);
   *((SshUInt32 *)res) = (SshUInt32)(out >> 32);

   OCTEON_GET_HASH_IV(out, 2);

#ifdef KERNEL
   DISABLE_COP2();
#endif
   return TRUE;
}

Boolean
des3_cbc_sha1_decrypt(unsigned char *dest,
                      const unsigned char *src,
                      SshUInt32 len,
                      SshUInt32 enc_ofs,
                      unsigned char *des_key,
                      unsigned char *des_iv,
                      SshUInt64 *start_inner_sha,
                      SshUInt64 *start_outer_sha,
                      unsigned char *digest)
{
  SshUInt64 *res = (SshUInt64 *)dest, *data = (SshUInt64 *)src;
  register SshUInt64 in, out, tmp;
  register int next = 0;
  int inplen;

#ifdef KERNEL
   ENABLE_COP2();
#endif

   OCTEON_PREFETCH(des_iv, 0);
   OCTEON_PREFETCH(start_inner_sha, 0);
   OCTEON_PREFETCH(data, 0);

   /* load 3DES Key */
   OCTEON_SET_3DES_KEY(((SshUInt64 *)des_key)[0], 0);
   OCTEON_SET_3DES_KEY(((SshUInt64 *)des_key)[1], 1);
   OCTEON_SET_3DES_KEY(((SshUInt64 *)des_key)[2], 2);

   out = *(SshUInt64 *)des_iv;
   OCTEON_SET_3DES_IV(out);

   /* Load SHA1 IV */
   OCTEON_SET_HASH_IV(start_inner_sha[0], 0);
   OCTEON_SET_HASH_IV(start_inner_sha[1], 1);
   OCTEON_SET_HASH_IV(start_inner_sha[2], 2);

   data = (SshUInt64 *)(src + enc_ofs);
   res = (SshUInt64 *)(dest + enc_ofs);

   inplen = len - enc_ofs;

   in = *data++;
   inplen -= 8;

   OCTEON_SET_3DES_DEC_CBC(in);

   OCTEON_LOAD_SHA_UNIT(*(SshUInt64 *)src, next);
   OCTEON_LOAD_SHA_UNIT(*(SshUInt64 *)(src + sizeof(SshUInt64)), next);

   OCTEON_LOAD_SHA_UNIT(in, next);

   if (inplen < 8)
      goto res_done;

   in = *data++;

   /* Loop through input */
   /* Assumed that data is 8 byte aligned */
   if (inplen >= 16)
     {
      while (1)
        {
          OCTEON_GET_3DES_RESULT(out);
          OCTEON_SET_3DES_DEC_CBC(in);
          OCTEON_LOAD_SHA_UNIT(in, next);
          res[0] = out;
          in = data[0];
          res++;
          data++;
          OCTEON_GET_3DES_RESULT(out);
          OCTEON_SET_3DES_DEC_CBC(in);
          OCTEON_LOAD_SHA_UNIT(in, next);
          res[0] = out;
          in = data[0];
          res++;
          data++;
          inplen -= 16;
          if (inplen < 16)
            break;
        }
     }

   /* inplen < 16 ==> inplen = 8 or inplen = 0
      (Assuming 8 byte aligned data only) */
   if (inplen)
     {
       OCTEON_GET_3DES_RESULT(out);
       OCTEON_SET_3DES_DEC_CBC(in);
       OCTEON_LOAD_SHA_UNIT (in, next);
       res[0] = out;
       res++;
     }

 res_done:
   OCTEON_GET_3DES_RESULT(out);
   res[0] = out;

   OCTEON_PREFETCH(start_outer_sha, 0);

   /* Finish Inner hash */
   OCTEON_LOAD_SHA_UNIT(0x8000000000000000ULL, next);

   while (next != 7)
     OCTEON_LOAD_SHA_UNIT(((SshUInt64)0x0ULL), next);

   OCTEON_LOAD_SHA_UNIT((SshUInt64)((len + 64) << 3), next);

   /* Get the inner hash of HMAC */
   OCTEON_GET_HASH_IV(in, 0);
   OCTEON_GET_HASH_IV(tmp, 1);
   out = 0;
   OCTEON_GET_HASH_IV(out, 2);

   OCTEON_PREFETCH(src + len, 0);
   /* Initialize hash unit */
   OCTEON_SET_HASH_IV(start_outer_sha[0], 0);
   OCTEON_SET_HASH_IV(start_outer_sha[1], 1);
   OCTEON_SET_HASH_IV(start_outer_sha[2], 2);

   OCTEON_SET_HASH_DAT(in, 0);
   OCTEON_SET_HASH_DAT(tmp, 1);
   out |= 0x0000000080000000;
   OCTEON_SET_HASH_DAT(out, 2);
   OCTEON_SET_HASH_DATZ(3);
   OCTEON_SET_HASH_DATZ(4);
   OCTEON_SET_HASH_DATZ(5);
   OCTEON_SET_HASH_DATZ(6);
   OCTEON_SET_HASH_STARTSHA((SshUInt64)((64 + 20) << 3));

   /* Get and compare the HMAC */
   res = (SshUInt64 *)digest;
   OCTEON_GET_HASH_IV(out, 0);

   if (out != *res)
     goto fail;

   OCTEON_GET_HASH_IV(out, 1);
   if (*(SshUInt32 *)(res + 1) != (SshUInt32)(out >> 32))
     goto fail;

#ifdef KERNEL
   DISABLE_COP2();
#endif
   return TRUE;

 fail:
#ifdef KERNEL
   DISABLE_COP2();
#endif
  return FALSE;
}

Boolean
des3_cbc_md5_encrypt(unsigned char *dest,
                     const unsigned char *src,
                     SshUInt32 len,
                     SshUInt32 enc_ofs,
                     unsigned char *des_key,
                     unsigned char *des_iv,
                     SshUInt64 *start_inner_md5,
                     SshUInt64 *start_outer_md5,
                     unsigned char *digest)
{
  SshUInt64 *res = (SshUInt64 *)dest, *data = (SshUInt64 *)src;
  register SshUInt64 in, out, tmp;
  register int next = 0;
  int inplen;

   SSH_DEBUG(10, ("Entered len=%d", len));

#ifdef KERNEL
   ENABLE_COP2();
#endif

   OCTEON_PREFETCH(des_iv, 0);
   OCTEON_PREFETCH(start_inner_md5, 0);
   OCTEON_PREFETCH(data, 0);

   OCTEON_SET_3DES_KEY(((SshUInt64 *)des_key)[0], 0);
   OCTEON_SET_3DES_KEY(((SshUInt64 *)des_key)[1], 1);
   OCTEON_SET_3DES_KEY(((SshUInt64 *)des_key)[2], 2);

   out = *(SshUInt64 *)des_iv;
   OCTEON_SET_3DES_IV(out);

   /* Load MD5 IV */
   OCTEON_SET_HASH_IV(start_inner_md5[0], 0);
   OCTEON_SET_HASH_IV(start_inner_md5[1], 1);

   res = (SshUInt64 *)(src + enc_ofs);
   data = (SshUInt64 *)(src + enc_ofs);
   inplen = len - enc_ofs;

   in = *data++;
   inplen -= 8;

   OCTEON_SET_3DES_ENC_CBC(in);

   OCTEON_LOAD_MD5_UNIT(*(SshUInt64 *)src, next);
   OCTEON_LOAD_MD5_UNIT(*(SshUInt64 *)(src + sizeof(SshUInt64)), next);

   if (inplen < 8)
      goto res_done;

   in = *data++;

   /* Loop through input */
   /* Assumed that data is 8 byte aligned */
   if (inplen >= 16)
     {
       while (1)
         {
           OCTEON_GET_3DES_RESULT(out);
           OCTEON_SET_3DES_ENC_CBC(in);
           OCTEON_LOAD_MD5_UNIT(out, next);
           res[0] = out;
           in = data[0];
           res++;
           data++;
           OCTEON_GET_3DES_RESULT(out);
           OCTEON_SET_3DES_ENC_CBC(in);
           OCTEON_LOAD_MD5_UNIT(out, next);
           res[0] = out;
           in = data[0];
           res++;
           data++;
           inplen -= 16;
           if (inplen < 16)
             break;
         }
     }
   /* inplen < 16 ==> inplen = 8 or inplen = 0
      (Assuming 8 byte aligned data only) */
   if (inplen)
     {
       OCTEON_GET_3DES_RESULT(out);
       OCTEON_SET_3DES_ENC_CBC(in);
       OCTEON_LOAD_MD5_UNIT(out, next);
       res[0] = out;
       res++;
     }

 res_done:
   OCTEON_GET_3DES_RESULT(out);
   OCTEON_LOAD_MD5_UNIT(out, next);
   res[0] = out;

   OCTEON_PREFETCH(start_outer_md5, 0);

   /* Finish Inner hash */
   OCTEON_LOAD_MD5_UNIT(0x8000000000000000ULL, next);
   while (next != 7)
     OCTEON_LOAD_MD5_UNIT(((SshUInt64)0x0ULL), next);

   OCTEON_LOAD_MD5_UNIT(swap64((SshUInt64)((len + 64) << 3)), next);

   /* Get the inner hash of HMAC */
   OCTEON_GET_HASH_IV(in, 0);
   OCTEON_GET_HASH_IV(tmp, 1);

   /* Initialize hash unit */
   OCTEON_SET_HASH_IV(start_outer_md5[0], 0);
   OCTEON_SET_HASH_IV(start_outer_md5[1], 1);

   OCTEON_SET_HASH_DAT(in, 0);
   OCTEON_SET_HASH_DAT(tmp, 1);
   out = 0x8000000000000000ULL;
   OCTEON_SET_HASH_DAT(out, 2);
   OCTEON_SET_HASH_DATZ(3);
   OCTEON_SET_HASH_DATZ(4);
   OCTEON_SET_HASH_DATZ(5);
   OCTEON_SET_HASH_DATZ(6);
   OCTEON_SET_HASH_STARTMD5(swap64((SshUInt64)((64 + 16) << 3)));

   /* Get the HMAC */
   res = (SshUInt64 *)digest;
   OCTEON_GET_HASH_IV(*res++, 0);
   OCTEON_GET_HASH_IV(out, 1);
   *((SshUInt32 *)res) = (SshUInt32)(out >> 32);

#ifdef KERNEL
   DISABLE_COP2();
#endif
   return TRUE;
}

Boolean
des3_cbc_md5_decrypt(unsigned char *dest,
                     const unsigned char *src,
                     SshUInt32 len,
                     SshUInt32 enc_ofs,
                     unsigned char *des_key,
                     unsigned char *des_iv,
                     SshUInt64 *start_inner_md5,
                     SshUInt64 *start_outer_md5,
                     unsigned char *digest)
{
  SshUInt64 *res = (SshUInt64 *)dest, *data = (SshUInt64 *)src;
  register SshUInt64 in, out, tmp;
  register int next = 0;
  int inplen;

#ifdef KERNEL
   ENABLE_COP2();
#endif

   OCTEON_PREFETCH(des_iv, 0);
   OCTEON_PREFETCH(start_inner_md5, 0);
   OCTEON_PREFETCH(data, 0);

   /* load 3DES Key */
   OCTEON_SET_3DES_KEY(((SshUInt64 *)des_key)[0], 0);
   OCTEON_SET_3DES_KEY(((SshUInt64 *)des_key)[1], 1);
   OCTEON_SET_3DES_KEY(((SshUInt64 *)des_key)[2], 2);

   out = *(SshUInt64 *)des_iv;
   OCTEON_SET_3DES_IV(out);

   /* Load MD5 IV */
   OCTEON_SET_HASH_IV(start_inner_md5[0], 0);
   OCTEON_SET_HASH_IV(start_inner_md5[1], 1);

   data = (SshUInt64 *)(src + enc_ofs);
   res = (SshUInt64 *)(dest + enc_ofs);

   inplen = len - enc_ofs;

   in = *data++;
   inplen -= 8;

   OCTEON_SET_3DES_DEC_CBC(in);

   OCTEON_LOAD_MD5_UNIT(*(SshUInt64 *)src, next);
   OCTEON_LOAD_MD5_UNIT(*(SshUInt64 *)(src + sizeof(SshUInt64)), next);

   OCTEON_LOAD_MD5_UNIT(in, next);

   if (inplen < 8)
      goto res_done;

   in = *data++;

   /* Loop through input */
   /* Assumed that data is 8 byte aligned */
   if (inplen >= 16)
     {
      while (1)
        {
          OCTEON_GET_3DES_RESULT(out);
          OCTEON_SET_3DES_DEC_CBC(in);
          OCTEON_LOAD_MD5_UNIT(in, next);
          res[0] = out;
          in = data[0];
          res++;
          data++;
          OCTEON_GET_3DES_RESULT(out);
          OCTEON_SET_3DES_DEC_CBC(in);
          OCTEON_LOAD_MD5_UNIT(in, next);
          res[0] = out;
          in = data[0];
          res++;
          data++;
          inplen -= 16;
          if (inplen < 16)
            break;
        }
     }

   /* inplen < 16 ==> inplen = 8 or inplen = 0
      (Assuming 8 byte aligned data only) */
   if (inplen)
     {
       OCTEON_GET_3DES_RESULT(out);
       OCTEON_SET_3DES_DEC_CBC(in);
       OCTEON_LOAD_MD5_UNIT (in, next);
       res[0] = out;
       res++;
     }

 res_done:
   OCTEON_GET_3DES_RESULT(out);
   res[0] = out;

   OCTEON_PREFETCH(start_outer_md5, 0);

   /* Finish Inner hash */
   OCTEON_LOAD_MD5_UNIT(0x8000000000000000ULL, next);

   while (next != 7)
     OCTEON_LOAD_MD5_UNIT(((SshUInt64)0x0ULL), next);

   OCTEON_LOAD_MD5_UNIT(swap64((SshUInt64)((len + 64) << 3)), next);

   /* Get the inner hash of HMAC */
   OCTEON_GET_HASH_IV(in, 0);
   OCTEON_GET_HASH_IV(tmp, 1);


   OCTEON_PREFETCH(src + len, 0);
   /* Initialize hash unit */
   OCTEON_SET_HASH_IV(start_outer_md5[0], 0);
   OCTEON_SET_HASH_IV(start_outer_md5[1], 1);

   OCTEON_SET_HASH_DAT(in, 0);
   OCTEON_SET_HASH_DAT(tmp, 1);
   out = 0x8000000000000000ULL;
   OCTEON_SET_HASH_DAT(out, 2);
   OCTEON_SET_HASH_DATZ(3);
   OCTEON_SET_HASH_DATZ(4);
   OCTEON_SET_HASH_DATZ(5);
   OCTEON_SET_HASH_DATZ(6);
   OCTEON_SET_HASH_STARTMD5(swap64((SshUInt64)((64 + 16) << 3)));

   /* Get and compare the HMAC */
   res = (SshUInt64 *)digest;
   OCTEON_GET_HASH_IV(out, 0);

   if (out != *res)
     goto fail;

   OCTEON_GET_HASH_IV(out, 1);
   if (*(SshUInt32 *)(res + 1) != (SshUInt32)(out >> 32))
     goto fail;

#ifdef KERNEL
   DISABLE_COP2();
#endif
   return TRUE;

 fail:

#ifdef KERNEL
   DISABLE_COP2();
#endif
  return FALSE;
}


typedef struct Ssh3DesHMacContextRec {
  SshTripleDESContext ciph;
  Boolean for_encryption;
  unsigned char inner_hash[24];
  unsigned char outer_hash[24];
} *Ssh3DesHMacContext, Ssh3DesHMacContextStruct;


size_t ssh_3des_sha1_ctxsize(void)
{
  return sizeof (Ssh3DesHMacContextStruct);
}



SshCryptoStatus ssh_3des_sha1_init(void *context,
                                   const unsigned char *cipher_key,
                                   size_t cipher_keylen,
                                   const unsigned char *mac_key,
                                   size_t mac_keylen,
                                   Boolean for_encryption)
{
  Ssh3DesHMacContext ctx = (Ssh3DesHMacContext)context;
  SshCryptoStatus status;

  SSH_DEBUG(10, ("Entered"));

  status = ssh_des3_init(&ctx->ciph, cipher_key, cipher_keylen,
                         for_encryption);

  if (status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(3, ("ERROR"));
      return status;
    }

  ctx->for_encryption = for_encryption;

  /* Initialize mac compute inner and outer digest */
  octeon_hmac_init(TRUE, (SshUInt64*)mac_key,
                   ctx->inner_hash, ctx->outer_hash);
  return SSH_CRYPTO_OK;
}

Boolean ssh_3des_sha1_transform(void *context, unsigned char *dest,
                                const unsigned char *src,
                                size_t len,
                                size_t enc_ofs,
                                unsigned char *iv,
                                unsigned char *digest)
{
  Ssh3DesHMacContext ctx = (Ssh3DesHMacContext)context;

  if (ctx->for_encryption)
    return des3_cbc_sha1_encrypt(dest, src, len, enc_ofs,
                                 (unsigned char *)ctx->ciph.key,
                                 iv,
                                 (SshUInt64 *)ctx->inner_hash,
                                 (SshUInt64 *)ctx->outer_hash,
                                 digest);
  else
    return des3_cbc_sha1_decrypt(dest, src, len, enc_ofs,
                                 (unsigned char *)ctx->ciph.key,
                                 iv,
                                 (SshUInt64 *)ctx->inner_hash,
                                 (SshUInt64 *)ctx->outer_hash,
                                 digest);
}


size_t ssh_3des_md5_ctxsize(void)
{
  return sizeof (Ssh3DesHMacContextStruct);
}

SshCryptoStatus ssh_3des_md5_init(void *context,
                                  const unsigned char *cipher_key,
                                  size_t cipher_keylen,
                                  const unsigned char *mac_key,
                                  size_t mac_keylen,
                                  Boolean for_encryption)
{
  Ssh3DesHMacContext ctx = (Ssh3DesHMacContext)context;
  SshCryptoStatus status;

  SSH_DEBUG(10, ("Entered"));

  status = ssh_des3_init(&ctx->ciph, cipher_key, cipher_keylen,
                         for_encryption);

  if (status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(3, ("ERROR"));
      return status;
    }

  ctx->for_encryption = for_encryption;

  /* Initialize mac compute inner and outer digest */
  octeon_hmac_init(FALSE, (SshUInt64*)mac_key,
                   ctx->inner_hash, ctx->outer_hash);
  return SSH_CRYPTO_OK;
}

Boolean ssh_3des_md5_transform(void *context, unsigned char *dest,
                               const unsigned char *src,
                               size_t len,
                               size_t enc_ofs,
                               unsigned char *iv,
                               unsigned char *digest)
{
  Ssh3DesHMacContext ctx = (Ssh3DesHMacContext)context;

  if (ctx->for_encryption)
    return des3_cbc_md5_encrypt(dest, src, len, enc_ofs,
                                (unsigned char *)ctx->ciph.key,
                                iv,
                                (SshUInt64 *)ctx->inner_hash,
                                (SshUInt64 *)ctx->outer_hash,
                                digest);
  else
    return des3_cbc_md5_decrypt(dest, src, len, enc_ofs,
                                (unsigned char *)ctx->ciph.key,
                                iv,
                                (SshUInt64 *)ctx->inner_hash,
                                (SshUInt64 *)ctx->outer_hash,
                                digest);
}



#endif /* ASM_PLATFORM_OCTEON */
#endif /* SSHDIST_IPSEC_HWACCEL_OCTEON */
