/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Message authentication code calculation routines, using the HMAC
   structure.
*/

#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshhash/sshhash_i.h"
#include "sshmac_i.h"
#include "hmac.h"

#define SSH_DEBUG_MODULE "SshCryptHmac"

#ifdef SSHDIST_CRYPT_MD5
#include "sshhash/md5.h"
#endif /* SSHDIST_CRYPT_MD5 */
#ifdef SSHDIST_CRYPT_SHA
#include "sshhash/sha.h"
#endif /* SSHDIST_CRYPT_SHA */

/* Generic Hmac interface code. */
typedef struct
{
  unsigned char *ipad, *opad;
  const SshHashDefStruct *hash_def;
  void *hash_context;
} SshHmacCtx;

size_t
ssh_hmac_ctxsize(const SshHashDefStruct *hash_def)
{
  return
    sizeof(SshHmacCtx) +
    (*hash_def->ctxsize)() +
    hash_def->input_block_length * 2;
}

SshCryptoStatus
ssh_hmac_init(void *context, const unsigned char *key, size_t keylen,
              const SshHashDefStruct *hash_def)
{
  SshHmacCtx *created = context;
  SshCryptoStatus status;
  unsigned int i;

  /* Compute positions in allocated space. */
  created->hash_context = (unsigned char *)created +
    sizeof(SshHmacCtx);
  created->ipad = (unsigned char *)created->hash_context +
    (*hash_def->ctxsize)();

  created->opad = created->ipad + hash_def->input_block_length;

  /* Clear pads. */
  memset(created->ipad, 0, hash_def->input_block_length * 2);

  /* Remember the hash function used to define this mac. */
  created->hash_def = hash_def;

  if (hash_def->init &&
      (*hash_def->init)(created->hash_context) != SSH_CRYPTO_OK)
    return SSH_CRYPTO_NO_MEMORY;

  if (keylen > created->hash_def->input_block_length)
    {
      /* Do some hashing. */

      /* Compute the ipad. */
      (*created->hash_def->reset_context)(created->hash_context);
      (*created->hash_def->update)(created->hash_context, key, keylen);
      status = (*created->hash_def->final)(created->hash_context,
                                           created->ipad);

      if (status != SSH_CRYPTO_OK)
        return status;

      memcpy(created->opad, created->ipad,
             created->hash_def->input_block_length);
    }
  else
    {
      memcpy(created->ipad, key, keylen);
      memcpy(created->opad, key, keylen);
    }

  for (i = 0; i < created->hash_def->input_block_length; i++)
    {
      created->ipad[i] ^= 0x36;
      created->opad[i] ^= 0x5c;
    }

  return SSH_CRYPTO_OK;
}

void ssh_hmac_uninit(void *context)
{
  SshHmacCtx *ctx = context;

  if (ctx->hash_def->uninit)
    (*ctx->hash_def->uninit)(ctx->hash_context);
}

/* Restart the Hmac operation. */
void ssh_hmac_start(void *context)
{
  SshHmacCtx *ctx = context;

  (*ctx->hash_def->reset_context)(ctx->hash_context);
  (*ctx->hash_def->update)(ctx->hash_context, ctx->ipad,
                           ctx->hash_def->input_block_length);
}

/* Update the Hmac context. */
void ssh_hmac_update(void *context, const unsigned char *buf,
                     size_t len)
{
  SshHmacCtx *ctx = context;
  (*ctx->hash_def->update)(ctx->hash_context, buf, len);
}

/* Finalize the digest. */
SshCryptoStatus ssh_hmac_final(void *context, unsigned char *digest)
{
  SshHmacCtx *ctx = context;
  SshCryptoStatus status;

  status = (*ctx->hash_def->final)(ctx->hash_context, digest);
  if (status != SSH_CRYPTO_OK)
    return status;

  (*ctx->hash_def->reset_context)(ctx->hash_context);
  (*ctx->hash_def->update)(ctx->hash_context, ctx->opad,
                           ctx->hash_def->input_block_length);
  (*ctx->hash_def->update)(ctx->hash_context, digest,
                           ctx->hash_def->digest_length);
  return (*ctx->hash_def->final)(ctx->hash_context, digest);
}

/* Finalize 128 bits of the digest. */
SshCryptoStatus ssh_hmac_256_final(void *context, unsigned char *digest)
{
  SshHmacCtx *ctx = context;
  SshCryptoStatus status;
  unsigned char buffer[SSH_MAX_HASH_DIGEST_LENGTH];

  status = (*ctx->hash_def->final)(ctx->hash_context, buffer);
  if (status != SSH_CRYPTO_OK)
    return status;

  (*ctx->hash_def->reset_context)(ctx->hash_context);
  (*ctx->hash_def->update)(ctx->hash_context, ctx->opad,
                           ctx->hash_def->input_block_length);
  (*ctx->hash_def->update)(ctx->hash_context, buffer,
                           ctx->hash_def->digest_length);
  status = (*ctx->hash_def->final)(ctx->hash_context, buffer);
  memcpy(digest, buffer, 32);
  return status;
}

/* Finalize 128 bits of the digest. */
SshCryptoStatus ssh_hmac_192_final(void *context, unsigned char *digest)
{
  SshHmacCtx *ctx = context;
  SshCryptoStatus status;
  unsigned char buffer[SSH_MAX_HASH_DIGEST_LENGTH];

  status = (*ctx->hash_def->final)(ctx->hash_context, buffer);
  if (status != SSH_CRYPTO_OK)
    return status;

  (*ctx->hash_def->reset_context)(ctx->hash_context);
  (*ctx->hash_def->update)(ctx->hash_context, ctx->opad,
                           ctx->hash_def->input_block_length);
  (*ctx->hash_def->update)(ctx->hash_context, buffer,
                           ctx->hash_def->digest_length);
  status = (*ctx->hash_def->final)(ctx->hash_context, buffer);
  memcpy(digest, buffer, 24);
  return status;
}

/* Finalize 128 bits of the digest. */
SshCryptoStatus ssh_hmac_128_final(void *context, unsigned char *digest)
{
  SshHmacCtx *ctx = context;
  SshCryptoStatus status;
  unsigned char buffer[SSH_MAX_HASH_DIGEST_LENGTH];

  status = (*ctx->hash_def->final)(ctx->hash_context, buffer);
  if (status != SSH_CRYPTO_OK)
    return status;

  (*ctx->hash_def->reset_context)(ctx->hash_context);
  (*ctx->hash_def->update)(ctx->hash_context, ctx->opad,
                           ctx->hash_def->input_block_length);
  (*ctx->hash_def->update)(ctx->hash_context, buffer,
                           ctx->hash_def->digest_length);
  status = (*ctx->hash_def->final)(ctx->hash_context, buffer);
  memcpy(digest, buffer, 16);
  return status;
}

/* Finalize 96 bits of the digest. */
SshCryptoStatus ssh_hmac_96_final(void *context, unsigned char *digest)
{
  SshHmacCtx *ctx = context;
  SshCryptoStatus status;
  unsigned char buffer[SSH_MAX_HASH_DIGEST_LENGTH];

  status = (*ctx->hash_def->final)(ctx->hash_context, buffer);
  if (status != SSH_CRYPTO_OK)
    return status;

  (*ctx->hash_def->reset_context)(ctx->hash_context);
  (*ctx->hash_def->update)(ctx->hash_context, ctx->opad,
                           ctx->hash_def->input_block_length);
  (*ctx->hash_def->update)(ctx->hash_context, buffer,
                           ctx->hash_def->digest_length);
  status = (*ctx->hash_def->final)(ctx->hash_context, buffer);
  memcpy(digest, buffer, 12);
  return status;
}

/* Do everything with just one call. */
SshCryptoStatus ssh_hmac_of_buffer(void *context, const unsigned char *buf,
                                   size_t len, unsigned char *digest)
{
  ssh_hmac_start(context);
  ssh_hmac_update(context, buf, len);
  return ssh_hmac_final(context, digest);
}

SshCryptoStatus ssh_hmac_256_of_buffer(void *context, const unsigned char *buf,
                                       size_t len, unsigned char *digest)
{
  ssh_hmac_start(context);
  ssh_hmac_update(context, buf, len);
  return ssh_hmac_256_final(context, digest);
}

SshCryptoStatus ssh_hmac_192_of_buffer(void *context, const unsigned char *buf,
                                       size_t len, unsigned char *digest)
{
  ssh_hmac_start(context);
  ssh_hmac_update(context, buf, len);
  return ssh_hmac_192_final(context, digest);
}

SshCryptoStatus ssh_hmac_128_of_buffer(void *context, const unsigned char *buf,
                                       size_t len, unsigned char *digest)
{
  ssh_hmac_start(context);
  ssh_hmac_update(context, buf, len);
  return ssh_hmac_128_final(context, digest);
}

SshCryptoStatus ssh_hmac_96_of_buffer(void *context, const unsigned char *buf,
                                      size_t len, unsigned char *digest)
{
  ssh_hmac_start(context);
  ssh_hmac_update(context, buf, len);
  return ssh_hmac_96_final(context, digest);
}

void ssh_hmac_zeroize(void *context)
{
  /* SshHmacCtx *ctx = context; */



  SSH_NOTREACHED;
}


/* Specific Hmac interface code.  */

#ifdef SSHDIST_CRYPT_MD5

/* HMAC-MD5 */

#define MD5_INPUT_BLOCK_SIZE 64
#define MD5_OUTPUT_BLOCK_SIZE 16

typedef struct SshHmacMd5Rec
{
  unsigned char ipad[MD5_INPUT_BLOCK_SIZE];
  unsigned char opad[MD5_INPUT_BLOCK_SIZE];
  unsigned char md5_context[1];
} SshHmacMd5;

size_t
ssh_hmac_md5_ctxsize()
{
  return sizeof(SshHmacMd5) + ssh_md5_ctxsize();
}

SshCryptoStatus
ssh_hmac_md5_init(void *context, const unsigned char *key, size_t keylen)
{
  SshHmacMd5 *created = (SshHmacMd5 *)context;
  int i;

  memset(created, 0, sizeof(*created) + ssh_md5_ctxsize());

  if (keylen > MD5_INPUT_BLOCK_SIZE)
    {
      ssh_md5_of_buffer(created->ipad, key, keylen);
      ssh_md5_of_buffer(created->opad, key, keylen);
    }
  else
    {
      memcpy(created->ipad, key, keylen);
      memcpy(created->opad, key, keylen);
    }

  for (i = 0; i < MD5_INPUT_BLOCK_SIZE; i++)
    {
      created->ipad[i] ^= 0x36;
      created->opad[i] ^= 0x5c;
    }
  return SSH_CRYPTO_OK;
}

void ssh_hmac_md5_start(void *context)
{
  SshHmacMd5 *ctx = context;
  ssh_md5_reset_context(ctx->md5_context);
  ssh_md5_update(ctx->md5_context, ctx->ipad, MD5_INPUT_BLOCK_SIZE);
}

void ssh_hmac_md5_update(void *context, const unsigned char *buf,
                         size_t len)
{
  SshHmacMd5 *ctx = context;
  ssh_md5_update(ctx->md5_context, buf, len);
}

SshCryptoStatus
ssh_hmac_md5_final(void *context, unsigned char *digest)
{
  SshHmacMd5 *ctx = context;
  SshCryptoStatus status;

  status = ssh_md5_final(ctx->md5_context, digest);
  if (status != SSH_CRYPTO_OK)
    return status;

  ssh_md5_reset_context(ctx->md5_context);
  ssh_md5_update(ctx->md5_context, ctx->opad, MD5_INPUT_BLOCK_SIZE);
  ssh_md5_update(ctx->md5_context, digest, MD5_OUTPUT_BLOCK_SIZE);
  return ssh_md5_final(ctx->md5_context, digest);
}

SshCryptoStatus
ssh_hmac_md5_96_final(void *context, unsigned char *digest)
{
  SshHmacMd5 *ctx = context;
  unsigned char buffer[16];
  SshCryptoStatus status;

  status = ssh_md5_final(ctx->md5_context, buffer);
  if (status != SSH_CRYPTO_OK)
    return status;

  ssh_md5_reset_context(ctx->md5_context);
  ssh_md5_update(ctx->md5_context, ctx->opad, MD5_INPUT_BLOCK_SIZE);
  ssh_md5_update(ctx->md5_context, buffer, MD5_OUTPUT_BLOCK_SIZE);
  status = ssh_md5_final(ctx->md5_context, buffer);
  memcpy(digest, buffer, 12);

  return status;
}

SshCryptoStatus
ssh_hmac_md5_of_buffer(void *context, const unsigned char *buf,
                            size_t len, unsigned char *digest)
{
  ssh_hmac_md5_start(context);
  ssh_hmac_md5_update(context, buf, len);
  return ssh_hmac_md5_final(context, digest);
}

SshCryptoStatus
ssh_hmac_md5_96_of_buffer(void *context, const unsigned char *buf,
                               size_t len, unsigned char *digest)
{
  ssh_hmac_md5_start(context);
  ssh_hmac_md5_update(context, buf, len);
  return ssh_hmac_md5_96_final(context, digest);
}
#endif /* SSHDIST_CRYPT_MD5 */

#ifdef SSHDIST_CRYPT_SHA

#define SHA_INPUT_BLOCK_SIZE 64
#define SHA_OUTPUT_BLOCK_SIZE 20

/* HMAC-SHA */

typedef struct SshHmacShaRec
{
  unsigned char ipad[SHA_INPUT_BLOCK_SIZE];
  unsigned char opad[SHA_INPUT_BLOCK_SIZE];

  unsigned char sha_context[1];
} SshHmacSha;

size_t
ssh_hmac_sha_ctxsize()
{
  return sizeof(SshHmacSha) + ssh_sha_ctxsize();
}

SshCryptoStatus
ssh_hmac_sha_init(void *context, const unsigned char *key, size_t keylen)
{
  SshHmacSha *ctx = (SshHmacSha *)context;
  int i;

  memset(ctx, 0, sizeof(*ctx) + ssh_sha_ctxsize());

  if (keylen > SHA_INPUT_BLOCK_SIZE)
    {
      ssh_sha_of_buffer(ctx->ipad, key, keylen);
      ssh_sha_of_buffer(ctx->opad, key, keylen);
    }
  else
    {
      memcpy(ctx->ipad, key, keylen);
      memcpy(ctx->opad, key, keylen);
    }

  for (i = 0; i < SHA_INPUT_BLOCK_SIZE; i++)
    {
      ctx->ipad[i] ^= 0x36;
      ctx->opad[i] ^= 0x5c;
    }

  return SSH_CRYPTO_OK;
}

void ssh_hmac_sha_start(void *context)
{
  SshHmacSha *ctx = context;

  ssh_sha_reset_context(ctx->sha_context);
  ssh_sha_update(ctx->sha_context, ctx->ipad, SHA_INPUT_BLOCK_SIZE);
}

void ssh_hmac_sha_update(void *context, const unsigned char *buf,
                         size_t len)
{
  SshHmacSha *ctx = context;
  ssh_sha_update(ctx->sha_context, buf, len);
}

SshCryptoStatus
ssh_hmac_sha_final(void *context, unsigned char *digest)
{
  SshHmacSha *ctx = context;
  SshCryptoStatus status;

  status = ssh_sha_final(ctx->sha_context, digest);
  if (status != SSH_CRYPTO_OK)
    return status;

  ssh_sha_reset_context(ctx->sha_context);
  ssh_sha_update(ctx->sha_context, ctx->opad, SHA_INPUT_BLOCK_SIZE);
  ssh_sha_update(ctx->sha_context, digest, SHA_OUTPUT_BLOCK_SIZE);
  return ssh_sha_final(ctx->sha_context, digest);
}

SshCryptoStatus
ssh_hmac_sha_of_buffer(void *context, const unsigned char *buf,
                       size_t len, unsigned char *digest)
{
  ssh_hmac_sha_start(context);
  ssh_hmac_sha_update(context, buf, len);
  return ssh_hmac_sha_final(context, digest);
}

SshCryptoStatus
ssh_hmac_sha_96_final(void *context, unsigned char *digest)
{
  SshHmacSha *ctx = context;
  SshCryptoStatus status;
  unsigned char buffer[20];

  status = ssh_sha_final(ctx->sha_context, buffer);
  if (status != SSH_CRYPTO_OK)
    return status;

  ssh_sha_reset_context(ctx->sha_context);
  ssh_sha_update(ctx->sha_context, ctx->opad, SHA_INPUT_BLOCK_SIZE);
  ssh_sha_update(ctx->sha_context, buffer, SHA_OUTPUT_BLOCK_SIZE);
  status = ssh_sha_final(ctx->sha_context, buffer);

  memcpy(digest, buffer, 12);
  return status;
}

SshCryptoStatus
ssh_hmac_sha_96_of_buffer(void *context, const unsigned char *buf,
                          size_t len, unsigned char *digest)
{
  ssh_hmac_sha_start(context);
  ssh_hmac_sha_update(context, buf, len);
  return ssh_hmac_sha_96_final(context, digest);
}

#endif /* SSHDIST_CRYPT_SHA */

/* hmac.c */
