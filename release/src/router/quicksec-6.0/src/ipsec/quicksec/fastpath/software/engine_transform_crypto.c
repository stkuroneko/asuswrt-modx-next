/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
  Implements functions declared in engine_transform_crypto.h. This
  implementation calls the internal functions of different
  cryptographic algorithms directly passing the generic ssh crypto
  API.
*/

#include "sshincludes.h"
#include "engine_internal.h"

#include "hmac.h"
#ifdef SSHDIST_CRYPT_DES
#include "des.h"
#endif /* SSHDIST_CRYPT_DES */
#ifdef SSHDIST_CRYPT_RIJNDAEL
#include "rijndael.h"
#ifdef SSHDIST_CRYPT_MODE_GCM
#include "mode-gcm.h"
#endif /* SSHDIST_CRYPT_MODE_GCM */
#endif /* SSHDIST_CRYPT_RIJNDAEL */





#ifdef SSHDIST_CRYPT_MD5
#include "md5.h"
#endif /* SSHDIST_CRYPT_MD5 */
#ifdef SSHDIST_CRYPT_SHA
#include "sha.h"
#endif /* SSHDIST_CRYPT_SHA */
#ifdef SSHDIST_CRYPT_SHA256
#include "sha256.h"
#endif /* SSHDIST_CRYPT_SHA256 */
#ifdef SSHDIST_CRYPT_SHA512
#include "sha512.h"
#endif /* SSHDIST_CRYPT_SHA512 */
#ifdef SSHDIST_CRYPT_XCBCMAC
#include "xcbc-mac.h"
#endif /* SSHDIST_CRYPT_XCBCMAC */

#include "fastpath_swi.h"
#include "engine_transform_crypto.h"


#define SSH_DEBUG_MODULE "SshEngineFastpathTransformCrypto"


#ifdef SSHDIST_CRYPT_DES
SSH_RODATA
const SshCipherDefStruct ssh_fastpath_3des_cbc_def =
  {
    "3des-cbc",
    0,
    8, 8,
    {24, 24, 24},
    ssh_des3_ctxsize, ssh_des3_init, ssh_des3_init_with_key_check,
    ssh_des3_cbc, ssh_des3_uninit, FALSE, 0, NULL_FNPTR, NULL_FNPTR,
    NULL_FNPTR, NULL_FNPTR
  };

SSH_RODATA
const SshCipherDefStruct ssh_fastpath_des_cbc_def =
  {
    "des-cbc",
    0,
    8, 8,
    {8, 8, 8},
    ssh_des_ctxsize, ssh_des_init, ssh_des_init_with_key_check,
    ssh_des_cbc, ssh_des_uninit, FALSE, 0, NULL_FNPTR, NULL_FNPTR,
    NULL_FNPTR, NULL_FNPTR
  };
#endif /* SSHDIST_CRYPT_DES */

#ifdef SSHDIST_CRYPT_RIJNDAEL
SSH_RODATA
const SshCipherDefStruct ssh_fastpath_aes128_cbc_def =
  {
    "aes128-cbc",
    0,
    16, 16,
    {16, 16, 16},
    ssh_rijndael_ctxsize, ssh_rijndael_init, ssh_rijndael_init,
    ssh_rijndael_cbc, ssh_rijndael_uninit, FALSE, 0, NULL_FNPTR, NULL_FNPTR,
    NULL_FNPTR, NULL_FNPTR
  };

SSH_RODATA
const SshCipherDefStruct ssh_fastpath_aes128_ctr_def =
  {
    "aes128-ctr",
    0,
    16, 16,
    {16, 16, 16},
    ssh_rijndael_ctxsize, ssh_rijndael_init, ssh_rijndael_init,
    ssh_rijndael_ctr, ssh_rijndael_uninit, FALSE, 0, NULL_FNPTR, NULL_FNPTR,
    NULL_FNPTR, NULL_FNPTR
  };

#ifdef SSHDIST_CRYPT_MODE_GCM
SSH_RODATA
const SshCipherDefStruct ssh_fastpath_aes128_gcm_def =
  {
    "aes128-gcm",
    0,
    16, 16,
    {16, 16, 16},
#ifdef SSH_IPSEC_SMALL
    ssh_gcm_aes_table_256_ctxsize,
    ssh_gcm_aes_table_256_init, ssh_gcm_aes_table_256_init,
#else /* SSH_IPSEC_SMALL */
    ssh_gcm_aes_table_4k_ctxsize,
    ssh_gcm_aes_table_4k_init, ssh_gcm_aes_table_4k_init,
#endif /* SSH_IPSEC_SMALL */
    ssh_gcm_transform,
    NULL_FNPTR, TRUE,
    16, ssh_gcm_reset, ssh_gcm_update, ssh_gcm_final, NULL_FNPTR
  };

SSH_RODATA
const SshCipherDefStruct ssh_fastpath_aes128_gcm_64_def =
  {
    "aes128-gcm-8",
    0,
    16, 16,
    {16, 16, 16},
#ifdef SSH_IPSEC_SMALL
    ssh_gcm_aes_table_256_ctxsize,
    ssh_gcm_aes_table_256_init, ssh_gcm_aes_table_256_init,
#else /* SSH_IPSEC_SMALL */
    ssh_gcm_aes_table_4k_ctxsize,
    ssh_gcm_aes_table_4k_init, ssh_gcm_aes_table_4k_init,
#endif /* SSH_IPSEC_SMALL */
    ssh_gcm_transform,
    NULL_FNPTR, TRUE,
    8, ssh_gcm_reset, ssh_gcm_update, ssh_gcm_64_final, NULL_FNPTR
  };

SSH_RODATA
const SshCipherDefStruct ssh_fastpath_null_auth_aes128_gmac_def =
  {
    "aes128-gmac",
    0,
    16, 16,
    {16, 16, 16},
#ifdef SSH_IPSEC_SMALL
    ssh_gcm_aes_table_256_ctxsize,
    ssh_gcm_aes_table_256_init, ssh_gcm_aes_table_256_init,
#else /* SSH_IPSEC_SMALL */
    ssh_gcm_aes_table_4k_ctxsize,
    ssh_gcm_aes_table_4k_init, ssh_gcm_aes_table_4k_init,
#endif /* SSH_IPSEC_SMALL */
    ssh_gcm_update_and_copy,
    NULL_FNPTR, TRUE,
    16, ssh_gcm_reset, ssh_gcm_update, ssh_gcm_final, NULL_FNPTR
  };
#endif /* SSHDIST_CRYPT_MODE_GCM */
#endif /* SSHDIST_CRYPT_RIJNDAEL */


















#ifdef SSHDIST_CRYPT_MD5
SSH_RODATA_IN_TEXT
SshHashMacDefStruct ssh_fastpath_hash_hmac_md5_96_def =
  {
    "hmac-md5-96",
    0,
    12,
    FALSE,
    &ssh_hash_md5_def,
    ssh_hmac_ctxsize, ssh_hmac_init, ssh_hmac_uninit,
    ssh_hmac_start, ssh_hmac_update,
    ssh_hmac_96_final, NULL_FNPTR,
    NULL_FNPTR,
  };

SSH_RODATA_IN_TEXT
SshMacDefStruct ssh_fastpath_hmac_md5_96_def =
  {
    TRUE, &ssh_fastpath_hash_hmac_md5_96_def, NULL
  };
#endif /* SSHDIST_CRYPT_MD5 */

#ifdef SSHDIST_CRYPT_SHA
SSH_RODATA_IN_TEXT
SshHashMacDefStruct ssh_fastpath_hash_hmac_sha1_96_def =
  {
    "hmac-sha1-96",
    0,
    12,
    FALSE,
    &ssh_hash_sha_def,
    ssh_hmac_ctxsize, ssh_hmac_init, ssh_hmac_uninit,
    ssh_hmac_start, ssh_hmac_update,
    ssh_hmac_96_final, NULL_FNPTR,
    NULL_FNPTR,
  };

SSH_RODATA_IN_TEXT
SshMacDefStruct ssh_fastpath_hmac_sha1_96_def =
  {
    TRUE, &ssh_fastpath_hash_hmac_sha1_96_def, NULL
  };
#endif /* SSHDIST_CRYPT_SHA */

#ifdef SSHDIST_CRYPT_SHA256
SSH_RODATA_IN_TEXT
SshHashMacDefStruct ssh_fastpath_hash_hmac_sha256_128_def =
  {
    "hmac-sha256-128",
    0,
    16,
    FALSE,
    &ssh_hash_sha256_def,
    ssh_hmac_ctxsize, ssh_hmac_init, ssh_hmac_uninit,
    ssh_hmac_start, ssh_hmac_update,
    ssh_hmac_128_final, NULL_FNPTR,
    NULL_FNPTR,
  };

SSH_RODATA_IN_TEXT
SshMacDefStruct ssh_fastpath_hmac_sha256_128_def =
  {
    TRUE, &ssh_fastpath_hash_hmac_sha256_128_def, NULL
  };
#endif /* SSHDIST_CRYPT_SHA256 */

#ifdef SSHDIST_CRYPT_SHA512
SSH_RODATA_IN_TEXT
SshHashMacDefStruct ssh_fastpath_hash_hmac_sha384_192_def =
  {
    "hmac-sha384-192",
    0,
    24,
    FALSE,
    &ssh_hash_sha384_def,
    ssh_hmac_ctxsize, ssh_hmac_init, ssh_hmac_uninit,
    ssh_hmac_start, ssh_hmac_update,
    ssh_hmac_192_final, NULL_FNPTR,
    NULL_FNPTR,
  };

SSH_RODATA_IN_TEXT
SshMacDefStruct ssh_fastpath_hmac_sha384_192_def =
  {
    TRUE, &ssh_fastpath_hash_hmac_sha384_192_def, NULL
  };

SSH_RODATA_IN_TEXT
SshHashMacDefStruct ssh_fastpath_hash_hmac_sha512_256_def =
  {
    "hmac-sha512-256",
    0,
    32,
    FALSE,
    &ssh_hash_sha512_def,
    ssh_hmac_ctxsize, ssh_hmac_init, ssh_hmac_uninit,
    ssh_hmac_start, ssh_hmac_update,
    ssh_hmac_256_final, NULL_FNPTR,
    NULL_FNPTR,
  };

SSH_RODATA_IN_TEXT
SshMacDefStruct ssh_fastpath_hmac_sha512_256_def =
  {
    TRUE, &ssh_fastpath_hash_hmac_sha512_256_def, NULL
  };
#endif /* SSHDIST_CRYPT_SHA512 */

#ifdef SSHDIST_CRYPT_XCBCMAC
#ifdef SSHDIST_CRYPT_RIJNDAEL
SSH_RODATA_IN_TEXT
SshCipherMacBaseDefStruct ssh_ciphermac_base_aes_def =
  { 16, ssh_rijndael_ctxsize, ssh_rijndael_init, ssh_rijndael_uninit,
    ssh_rijndael_cbc_mac };

SSH_RODATA_IN_TEXT
SshCipherMacDefStruct ssh_fastpath_cipher_xcbc_aes_96_def =
  {
    "xcbcmac-aes-96",
    FALSE, 12, { 16, 16, 16 },
    &ssh_ciphermac_base_aes_def,
    ssh_xcbcmac_ctxsize,
    ssh_xcbcmac_init,
    ssh_xcbcmac_uninit,
    ssh_xcbcmac_start,
    ssh_xcbcmac_update,
    ssh_xcbcmac_96_final,
  };

SSH_RODATA_IN_TEXT
SshMacDefStruct ssh_fastpath_xcbc_aes_96_def =
  {
    FALSE, NULL, &ssh_fastpath_cipher_xcbc_aes_96_def
  };
#endif /* SSHDIST_CRYPT_RIJNDAEL */
#endif /* SSHDIST_CRYPT_XCBCMAC */

static const SshCipherDefStruct *
fastpath_get_cipher_def(
        SshEngineTransformRun trr,
        SshUInt32 transform)
{
  const SshCipherDefStruct *cipher;
  cipher = NULL;

  if (0)
    {
      /* To avoid the case where SSHDIST_CRYPT_RIJNDAEL is undefined */
    }
#ifdef SSHDIST_CRYPT_RIJNDAEL
  else if (transform & SSH_PM_CRYPT_AES)
    {
      cipher = &ssh_fastpath_aes128_cbc_def;
      SSH_ASSERT(trr->cipher_key_size);
    }
  else if (transform & SSH_PM_CRYPT_AES_CTR)
    {
      cipher = &ssh_fastpath_aes128_ctr_def;

      SSH_ASSERT(trr->cipher_key_size);
      SSH_ASSERT(trr->cipher_iv_size == 8);
      SSH_ASSERT(trr->cipher_nonce_size == 4);
    }
#ifdef SSHDIST_CRYPT_MODE_GCM
  else if (transform & SSH_PM_CRYPT_AES_GCM)
    {
      cipher = &ssh_fastpath_aes128_gcm_def;

      SSH_ASSERT(trr->cipher_key_size);
      SSH_ASSERT(trr->cipher_iv_size == 8);
      SSH_ASSERT(trr->cipher_nonce_size == 4);
    }
  else if (transform & SSH_PM_CRYPT_AES_GCM_8)
    {
      cipher = &ssh_fastpath_aes128_gcm_64_def;

      SSH_ASSERT(trr->cipher_key_size);
      SSH_ASSERT(trr->cipher_iv_size == 8);
      SSH_ASSERT(trr->cipher_nonce_size == 4);
    }
  else if (transform & SSH_PM_CRYPT_NULL_AUTH_AES_GMAC)
    {
      cipher = &ssh_fastpath_null_auth_aes128_gmac_def;

      SSH_ASSERT(trr->cipher_key_size);
      SSH_ASSERT(trr->cipher_iv_size == 8);
      SSH_ASSERT(trr->cipher_nonce_size == 4);
    }
#endif /* SSHDIST_CRYPT_MODE_GCM */
#endif /* SSHDIST_CRYPT_RIJNDAEL */
#ifdef SSHDIST_CRYPT_DES
  else if (transform & SSH_PM_CRYPT_3DES)
    {
      cipher = &ssh_fastpath_3des_cbc_def;
      SSH_ASSERT(trr->cipher_key_size == 24);
    }
  else if (transform & SSH_PM_CRYPT_DES)
    {
      cipher = &ssh_fastpath_des_cbc_def;
      SSH_ASSERT(trr->cipher_key_size == 8);
    }
#endif /* SSHDIST_CRYPT_DES */
  else if (transform & SSH_PM_CRYPT_EXT1)
    {
      if (cipher == NULL)
        {
          ssh_warning("EXT1 cipher not configured");
          return NULL;
        }
    }
  else if (transform & SSH_PM_CRYPT_EXT2)
    {






      if (cipher == NULL)
        {
          ssh_warning("EXT2 cipher not configured");
          return NULL;
        }
    }
  else
    {
      /* No cipher configured. */
      SSH_ASSERT(trr->cipher_key_size == 0);
    }

  return cipher;
}

const SshMacDefStruct * fastpath_get_mac_def(SshEngineTransformRun trr,
                                             SshUInt32 transform)
{
  const SshMacDefStruct *mac;

  mac = NULL;

  if (0)
    {
      /* To avoid the case where SSHDIST_CRYPT_MD5 is undefined */
    }
#ifdef SSHDIST_CRYPT_MD5
  else if (transform & SSH_PM_MAC_HMAC_MD5)
    {
      mac = &ssh_fastpath_hmac_md5_96_def;
      SSH_ASSERT(trr->mac_key_size == 16);
    }
#endif /* SSHDIST_CRYPT_MD5 */
#ifdef SSHDIST_CRYPT_SHA
  else if (transform & SSH_PM_MAC_HMAC_SHA1)
    {
      mac = &ssh_fastpath_hmac_sha1_96_def;
      SSH_ASSERT(trr->mac_key_size == 20);
    }
#endif /* SSHDIST_CRYPT_SHA */
#ifdef SSHDIST_CRYPT_SHA256
  else if ((transform & SSH_PM_MAC_HMAC_SHA2) &&
           trr->mac_key_size == 32)
    {
      mac = &ssh_fastpath_hmac_sha256_128_def;
    }
#endif /* SSHDIST_CRYPT_SHA256 */
#ifdef SSHDIST_CRYPT_SHA512
  else if ((transform & SSH_PM_MAC_HMAC_SHA2) &&
           trr->mac_key_size == 48)
    {
      mac = &ssh_fastpath_hmac_sha384_192_def;
    }
  else if ((transform & SSH_PM_MAC_HMAC_SHA2) &&
           trr->mac_key_size == 64)
    {
      mac = &ssh_fastpath_hmac_sha512_256_def;
    }
#endif /* SSHDIST_CRYPT_SHA512 */
  else if ((transform & SSH_PM_MAC_HMAC_SHA2))
    {
      SSH_ASSERT(0); /* Unsupported sha2 key size requested... */
    }
#ifdef SSHDIST_CRYPT_XCBCMAC
#ifdef SSHDIST_CRYPT_RIJNDAEL
  else if (transform & SSH_PM_MAC_XCBC_AES)
    {
      mac = &ssh_fastpath_xcbc_aes_96_def;
      SSH_ASSERT(trr->mac_key_size == 16);
    }
#endif /* SSHDIST_CRYPT_RIJNDAEL */
#endif /* SSHDIST_CRYPT_XCBCMAC */
  else if (transform & SSH_PM_MAC_EXT1)
    {
      ssh_warning("EXT1 MAC not yet supported");
      return NULL;
    }
  else if (transform & SSH_PM_MAC_EXT2)
    {
      ssh_warning("EXT2 MAC not yet supported");
      return NULL;
    }
  else
    {
      /* No MAC configured. */
      SSH_ASSERT(trr->mac_key_size == 0);
    }

  return mac;
}




typedef struct SshTransformSwCryptoContextRec
{
  /* Cipher descriptor.  This is NULL if no encryption is to be performed. */
  const SshCipherDefStruct *cipher;

  /* Cipher context, or NULL if encryption is performed by hardware
     acceleration. */
  void *cipher_context;

  /* Mac descriptor. */
  const SshMacDefStruct *mac;

  /* Mac context, or NULL if MAC is performed by hardware acceleration. */
  void *mac_context;
} * SshTransformSwCryptoContext;



SshTransformResult
transform_crypto_alloc(
        SshFastpathTransformContext tc,
        SshEngineTransformRun trr,
        SshUInt32 transform)
{
  SshTransformSwCryptoContext scc = NULL;
  const SshCipherDefStruct * cipher = NULL;
  const SshMacDefStruct * mac = NULL;

  SshCryptoStatus status;

  if (tc->with_sw_cipher)
    {
      cipher = fastpath_get_cipher_def(trr, transform);
      if (cipher == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Required SW cipher not found."));
          goto error;
        }
    }

  if (tc->with_sw_mac)
    {
      mac = fastpath_get_mac_def(trr, transform);
      if (mac == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Required SW mac not found."));
          goto error;
        }
    }

  scc = ssh_malloc(sizeof *scc);
  if (!scc)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to allocate cipher context"));
      goto error;
    }

  scc->cipher_context = NULL;
  scc->mac_context = NULL;
  scc->cipher = cipher;
  scc->mac = mac;


  tc->sw_crypto = scc;

  if (cipher)
    {
      scc->cipher_context = ssh_malloc((*cipher->ctxsize)());
      if (!scc->cipher_context)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Failed to allocate cipher context"));
          goto error;
        }

      /* For counter mode encryption is the same as decryption. */
      status = (*cipher->init)(scc->cipher_context,
                               trr->mykeymat, trr->cipher_key_size,
                               tc->counter_mode &&
                               (transform & (SSH_PM_CRYPT_AES_CTR |
                                             SSH_PM_CRYPT_NULL_AUTH_AES_GMAC))
                               ? TRUE : tc->for_output);
      if (status != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Cipher initialization failed: %d", status));
          goto error;
        }
    }

  if (mac)
    {
      if (mac->hmac)
        scc->mac_context =
          ssh_malloc((*mac->hash->ctxsize)(mac->hash->hash_def));
      else
        scc->mac_context =
          ssh_malloc((*mac->cipher->ctxsize)(mac->cipher->cipher_def));

      if (!scc->mac_context)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Failed to allocate MAC context"));
          goto error;
        }

      if (mac->hmac)
        status =
          (*mac->hash->init)(scc->mac_context,
                             trr->mykeymat + SSH_IPSEC_MAX_ESP_KEY_BITS/8,
                             trr->mac_key_size,
                             mac->hash->hash_def);
      else
        status =
          (*mac->cipher->init)(scc->mac_context,
                               trr->mykeymat + SSH_IPSEC_MAX_ESP_KEY_BITS/8,
                               trr->mac_key_size,
                               mac->cipher->cipher_def);
      if (status != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(SSH_D_FAIL, ("MAC initialization failed: %d", status));
          goto error;
        }
    }

  /* Determine cipher block length and MAC digest length. */
  if (scc->cipher)
    tc->cipher_block_len = (SshUInt8) scc->cipher->block_length;
  else
    tc->cipher_block_len = 0;

  if (scc->mac)
    tc->icv_len = scc->mac->hmac ? scc->mac->hash->digest_length :
      scc->mac->cipher->digest_length;
  else if (scc->cipher && scc->cipher->is_auth_cipher)
#ifdef SSH_IPSEC_AH
    if (transform & SSH_PM_IPSEC_AH)
      tc->icv_len = scc->cipher->digest_length + tc->cipher_iv_len;
    else
#endif /* SSH_IPSEC_AH */
      tc->icv_len = (SshUInt8)scc->cipher->digest_length;
  else
    tc->icv_len = 0;


  return SSH_TRANSFORM_SUCCESS;

 error:
  transform_crypto_free(tc);

  return SSH_TRANSFORM_FAILURE;
}

void
transform_crypto_free(
        SshFastpathTransformContext tc)
{
  SshTransformSwCryptoContext scc = tc->sw_crypto;

  if (scc != NULL)
    {
      if (scc->cipher_context != NULL)
        {
          if (scc->cipher->uninit)
            (*scc->cipher->uninit)(scc->cipher_context);
          ssh_free(scc->cipher_context);
        }

      if (scc->mac_context)
        {
          if (scc->mac->hash && scc->mac->hash->uninit)
            (*scc->mac->hash->uninit)(scc->mac_context);
          else if (scc->mac->cipher && scc->mac->cipher->uninit)
            (*scc->mac->cipher->uninit)(scc->mac_context);

          ssh_free(scc->mac_context);
        }

      ssh_free(scc);
    }

  tc->sw_crypto = NULL;
}


void
transform_crypto_reset(
        SshFastpathTransformContext tc)
{
  SshTransformSwCryptoContext scc = tc->sw_crypto;

  SSH_ASSERT(scc != NULL);

  if (scc->mac)
    {
      if (scc->mac->hmac)
        {
          (*scc->mac->hash->start)(scc->mac_context);
        }
      else
        {
          (*scc->mac->cipher->start)(scc->mac_context);
        }
    }

  if (scc->cipher)
    {
      if (tc->with_sw_auth_cipher)
        {
          (*scc->cipher->reset)(scc->cipher_context);
        }
    }
}


SshTransformResult
transform_mac_update(
        SshFastpathTransformContext tc,
        const unsigned char * buf,
        size_t len)
{
  SshTransformSwCryptoContext scc = tc->sw_crypto;

  SSH_ASSERT(scc != NULL);

  if (scc->mac)
    {
      if (scc->mac->hmac)
        {
          (*scc->mac->hash->update)(scc->mac_context, buf, len);
        }
      else
        {
          (*scc->mac->cipher->update)(scc->mac_context, buf, len);
        }
    }
  else
    {
      SSH_ASSERT(tc->with_sw_auth_cipher);

      (*scc->cipher->update)(scc->cipher_context, buf, len);
    }

  return SSH_TRANSFORM_SUCCESS;
}


SshTransformResult
transform_mac_finish(
        SshFastpathTransformContext tc,
        unsigned char *mac,
        unsigned char mac_len)
{
  SshTransformSwCryptoContext scc = tc->sw_crypto;
  SshCryptoStatus status;

  SSH_ASSERT(scc != NULL);

  if (scc->mac)
    {
      if (scc->mac->hmac)
        {
          status = (*scc->mac->hash->final)(scc->mac_context, mac);
        }
      else
        {
          status = (*scc->mac->cipher->final)(scc->mac_context, mac);
        }
    }
  else
    {
      SSH_ASSERT(tc->with_sw_auth_cipher);

      status = (*scc->cipher->final)(scc->cipher_context, mac);
    }

  if (status != SSH_CRYPTO_OK)
    {
      return SSH_TRANSFORM_FAILURE;
    }

  return SSH_TRANSFORM_SUCCESS;
}


SshTransformResult
transform_cipher_update(
        SshFastpathTransformContext tc,
        unsigned char *dest,
        const unsigned char *src,
        size_t len,
        unsigned char *iv)
{
  SshTransformSwCryptoContext scc = tc->sw_crypto;
  SshCryptoStatus status;

  SSH_ASSERT(scc != NULL);
  SSH_ASSERT(scc->cipher != NULL);

  /* Transform the split block in the separate buffer. */
  status = (*scc->cipher->transform)(scc->cipher_context, dest, src, len, iv);

  if (status != SSH_CRYPTO_OK)
    {
      return SSH_TRANSFORM_FAILURE;
    }

  return SSH_TRANSFORM_SUCCESS;
}


SshTransformResult
transform_cipher_update_remaining(
        SshFastpathTransformContext tc,
        unsigned char *dest,
        const unsigned char *src,
        size_t len,
        unsigned char *iv)
{
  return transform_cipher_update(tc, dest, src, len, iv);
}

