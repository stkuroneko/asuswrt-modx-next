/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Implements functions declared in engine_transform_crypto.h. This
   implementation uses the ssh crypto API.
*/

#include "sshincludes.h"
#include "engine_internal.h"

#include "fastpath_swi.h"
#include "engine_transform_crypto.h"

#include "sshcipher.h"
#include "sshmac.h"


#define SSH_DEBUG_MODULE "SshEngineFastpathTransformCryptoPublic"


static const unsigned char *
fastpath_get_cipher_type(
        SshEngineTransformRun trr,
        SshUInt32 transform)
{
  const char *cipher_type = NULL;

  if (0)
    {
      /* To avoid the case where SSHDIST_CRYPT_RIJNDAEL is undefined */
    }
#ifdef SSHDIST_CRYPT_RIJNDAEL
  else if (transform & SSH_PM_CRYPT_AES)
    {
      cipher_type = "aes-cbc";
      SSH_ASSERT(trr->cipher_key_size);
    }
  else if (transform & SSH_PM_CRYPT_AES_CTR)
    {
      cipher_type = "aes-ctr";

      SSH_ASSERT(trr->cipher_key_size);
      SSH_ASSERT(trr->cipher_iv_size == 8);
      SSH_ASSERT(trr->cipher_nonce_size == 4);
    }
#ifdef SSHDIST_CRYPT_MODE_GCM
  else if (transform & SSH_PM_CRYPT_AES_GCM)
    {
      cipher_type = "aes-gcm";

      SSH_ASSERT(trr->cipher_key_size);
      SSH_ASSERT(trr->cipher_iv_size == 8);
      SSH_ASSERT(trr->cipher_nonce_size == 4);
    }
  else if (transform & SSH_PM_CRYPT_AES_GCM_8)
    {
      cipher_type = "aes-gcm-8";

      SSH_ASSERT(trr->cipher_key_size);
      SSH_ASSERT(trr->cipher_iv_size == 8);
      SSH_ASSERT(trr->cipher_nonce_size == 4);
    }
  else if (transform & SSH_PM_CRYPT_NULL_AUTH_AES_GMAC)
    {
      cipher_type = "gmac-aes";

      SSH_ASSERT(trr->cipher_key_size);
      SSH_ASSERT(trr->cipher_iv_size == 8);
      SSH_ASSERT(trr->cipher_nonce_size == 4);
    }
#endif /* SSHDIST_CRYPT_MODE_GCM */
#endif /* SSHDIST_CRYPT_RIJNDAEL */
#ifdef SSHDIST_CRYPT_DES
  else if (transform & SSH_PM_CRYPT_3DES)
    {
      cipher_type = "3des-cbc";
      SSH_ASSERT(trr->cipher_key_size == 24);
    }
  else if (transform & SSH_PM_CRYPT_DES)
    {
      cipher_type = "des-cbc";
      SSH_ASSERT(trr->cipher_key_size == 8);
    }
#endif /* SSHDIST_CRYPT_DES */
  else if (transform & SSH_PM_CRYPT_EXT1)
    {
      ssh_warning("EXT1 cipher not configured");
    }
  else if (transform & SSH_PM_CRYPT_EXT2)
    {






      if (cipher_type == NULL)
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

  return  (const unsigned char *) cipher_type;
}


static const unsigned char *
fastpath_get_mac_type(SshEngineTransformRun trr,
                      SshUInt32 transform)
{
  const char * mac_type = NULL;

  if (0)
    {
      /* To avoid the case where SSHDIST_CRYPT_MD5 is undefined */
    }
#ifdef SSHDIST_CRYPT_MD5
  else if (transform & SSH_PM_MAC_HMAC_MD5)
    {
      mac_type = "hmac-md5-96";
      SSH_ASSERT(trr->mac_key_size == 16);
    }
#endif /* SSHDIST_CRYPT_MD5 */
#ifdef SSHDIST_CRYPT_SHA
  else if (transform & SSH_PM_MAC_HMAC_SHA1)
    {
      mac_type = "hmac-sha1-96";
      SSH_ASSERT(trr->mac_key_size == 20);
    }
#endif /* SSHDIST_CRYPT_SHA */
#ifdef SSHDIST_CRYPT_SHA256
  else if ((transform & SSH_PM_MAC_HMAC_SHA2) &&
           trr->mac_key_size == 32)
    {
      mac_type = "hmac-sha256-128";
    }
#endif /* SSHDIST_CRYPT_SHA256 */
#ifdef SSHDIST_CRYPT_SHA512
  else if ((transform & SSH_PM_MAC_HMAC_SHA2) &&
           trr->mac_key_size == 48)
    {
      mac_type = "hmac-sha384-192";
    }
  else if ((transform & SSH_PM_MAC_HMAC_SHA2) &&
           trr->mac_key_size == 64)
    {
      mac_type = "hmac-sha512-256";
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
      mac_type = "xcbcmac-aes";
      SSH_ASSERT(trr->mac_key_size == 16);
    }
#endif /* SSHDIST_CRYPT_RIJNDAEL */
#endif /* SSHDIST_CRYPT_XCBCMAC */
  else if (transform & SSH_PM_MAC_EXT1)
    {
      ssh_warning("EXT1 MAC not yet supported");
    }
  else if (transform & SSH_PM_MAC_EXT2)
    {
      ssh_warning("EXT2 MAC not yet supported");
    }
  else
    {
      /* No MAC configured. */
      SSH_ASSERT(trr->mac_key_size == 0);
    }

  return (const unsigned char *) mac_type;
}




typedef struct SshTransformSwCryptoPubContextRec
{
  SshCipher cipher;
  SshMac    mac;
} * SshTransformSwCryptoPubContext;



SshTransformResult
transform_crypto_alloc(
        SshFastpathTransformContext tc,
        SshEngineTransformRun trr,
        SshUInt32 transform)
{
  SshTransformSwCryptoPubContext scc = NULL;
  const unsigned char * cipher_type = NULL;

  const unsigned char * mac_type = NULL;
  SshCryptoStatus status;

  if (tc->with_sw_cipher)
    {
      cipher_type = fastpath_get_cipher_type(trr, transform);
      if (cipher_type == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Required SW cipher not found."));
          goto error;
        }
    }

  if (tc->with_sw_mac)
    {
      mac_type = fastpath_get_mac_type(trr, transform);
      if (mac_type == NULL)
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

  memset(scc, 0, sizeof *scc);

  tc->sw_crypto = scc;

  if (cipher_type)
    {
      Boolean for_encryption =
        (tc->for_output ||
         (tc->counter_mode &&
          (transform &
           (SSH_PM_CRYPT_AES_CTR |
            SSH_PM_CRYPT_NULL_AUTH_AES_GMAC))));

      status =
          ssh_cipher_allocate(
                  cipher_type,
                  trr->mykeymat,
                  trr->cipher_key_size,
                  for_encryption,
                  &scc->cipher);

      if (status != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Cipher initialization failed: %d",
                     (int) status));
          goto error;
        }
    }

  if (mac_type)
    {
      status =
          ssh_mac_allocate(
                  mac_type,
                  trr->mykeymat + SSH_IPSEC_MAX_ESP_KEY_BITS/8,
                  trr->mac_key_size,
                  &scc->mac);
      if (status != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("MAC initialization failed: %d",
                     (int) status));
          goto error;
        }
    }

  /* Determine cipher block length and MAC digest length. */
  if (scc->cipher)
    {
      if (tc->with_sw_auth_cipher)
        {
          tc->cipher_block_len = 16;
          tc->icv_len = ssh_cipher_auth_digest_length(cipher_type);
        }
      else
        {
          tc->cipher_block_len =
            (SshUInt8) ssh_cipher_get_block_length(cipher_type);
        }
    }
  else
    {
      tc->cipher_block_len = 0;
    }


  if (scc->mac)
    {
      tc->icv_len = ssh_mac_length(mac_type);
    }


#ifdef SSH_IPSEC_AH
  if (tc->icv_len != 0 && transform & SSH_PM_IPSEC_AH)
    {
      tc->icv_len += tc->cipher_iv_len;
    }
#endif /* SSH_IPSEC_AH */

  return SSH_TRANSFORM_SUCCESS;

 error:
  transform_crypto_free(tc);

  return SSH_TRANSFORM_FAILURE;
}

void
transform_crypto_free(
        SshFastpathTransformContext tc)
{
  SshTransformSwCryptoPubContext scc = tc->sw_crypto;

  if (scc != NULL)
    {
      if (scc->cipher != NULL)
        {
          ssh_cipher_free(scc->cipher);
        }

      if (scc->mac)
        {
          ssh_mac_free(scc->mac);
        }

      ssh_free(scc);
    }

  tc->sw_crypto = NULL;
}


void
transform_crypto_reset(
        SshFastpathTransformContext tc)
{
  SshTransformSwCryptoPubContext scc = tc->sw_crypto;

  SSH_ASSERT(scc != NULL);

  if (scc->mac)
    {
      ssh_mac_reset(scc->mac);
    }

  if (scc->cipher && tc->with_sw_auth_cipher)
    {
      ssh_cipher_auth_reset(scc->cipher);
    }
}


SshTransformResult
transform_mac_update(
        SshFastpathTransformContext tc,
        const unsigned char * buf,
        size_t len)
{
  SshTransformSwCryptoPubContext scc = tc->sw_crypto;

  SSH_ASSERT(scc != NULL);

  if (scc->mac)
    {
      ssh_mac_update(scc->mac, buf, len);
    }
  else
    {
      SSH_ASSERT(tc->with_sw_auth_cipher);

      ssh_cipher_auth_update(scc->cipher, buf, len);
    }

  return SSH_TRANSFORM_SUCCESS;
}


SshTransformResult
transform_mac_finish(
        SshFastpathTransformContext tc,
        unsigned char *mac,
        unsigned char mac_len)
{
  SshTransformSwCryptoPubContext scc = tc->sw_crypto;
  SshCryptoStatus status;

  SSH_ASSERT(scc != NULL);

  if (scc->mac)
    {
      status = ssh_mac_final(scc->mac, mac);
    }
  else
    {
      SSH_ASSERT(tc->with_sw_auth_cipher);

      status = ssh_cipher_auth_final(scc->cipher, mac);
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
  SshTransformSwCryptoPubContext scc = tc->sw_crypto;
  SshCryptoStatus status;

  SSH_ASSERT(scc != NULL);
  SSH_ASSERT(scc->cipher != NULL);

  /* Transform the split block in the separate buffer. */
  status = ssh_cipher_transform_with_iv(scc->cipher, dest, src, len, iv);
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
  SshTransformSwCryptoPubContext scc = tc->sw_crypto;
  SshCryptoStatus status;

  SSH_ASSERT(scc != NULL);
  SSH_ASSERT(scc->cipher != NULL);

  status = ssh_cipher_set_iv(scc->cipher, iv);
  if (status == SSH_CRYPTO_OK)
    {
      status =
          ssh_cipher_transform_remaining(
                  scc->cipher, dest, src, len);
    }

  if (status != SSH_CRYPTO_OK)
    {
      return SSH_TRANSFORM_FAILURE;
    }

  return SSH_TRANSFORM_SUCCESS;
}


