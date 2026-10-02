/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshhash_i.h"
#include "sshmac_i.h"
#include "ssl3mac.h"
#include "sshdebug.h"

#ifdef SSHDIST_CRYPT_MD5
#include "md5.h"
#endif /* SSHDIST_CRYPT_MD5 */
#ifdef SSHDIST_CRYPT_SHA
#include "sha.h"
#endif /* SSHDIST_CRYPT_SHA */

#define SSH_DEBUG_MODULE "SshCryptoSSL3MAC"

typedef struct {
  unsigned char *i_prefix, *o_prefix;
  int prefix_len;
  const SshHashDefStruct *hash_def;
  unsigned char *hash_context;
} SshSSL3MACCtx;

size_t ssh_ssl3mac_ctxsize(const SshHashDefStruct *hash_def)
{
  return sizeof(SshSSL3MACCtx) + (*hash_def->ctxsize)() + 2 * 64;
}


SshCryptoStatus
ssh_ssl3mac_init(void *context, const unsigned char *key,
                      size_t key_len, const SshHashDefStruct *hash_def)
{
  int i;
  SshSSL3MACCtx *created = context;

  SSH_ASSERT(hash_def == &ssh_hash_sha_def ||
             hash_def == &ssh_hash_md5_def);

  if (hash_def == &ssh_hash_sha_def)
    created->prefix_len = 60;
  else
    created->prefix_len = 64;

  if (key_len > created->prefix_len)
    key_len = created->prefix_len;

  created->hash_def = hash_def;

  created->hash_context = (unsigned char *)created + sizeof(SshSSL3MACCtx);
  created->i_prefix = created->hash_context + (*hash_def->ctxsize)();
  created->o_prefix = created->i_prefix + 64;

  if (hash_def->init &&
      (*hash_def->init)(created->hash_context) != SSH_CRYPTO_OK)
    return SSH_CRYPTO_NO_MEMORY;

  memcpy(created->i_prefix, key, key_len);
  memcpy(created->o_prefix, key, key_len);

  for (i = key_len; i < created->prefix_len; i++)
    {
      created->i_prefix[i] = 0x36;
      created->o_prefix[i] = 0x5c;
    }
  return SSH_CRYPTO_OK;
}

void ssh_ssl3mac_uninit(void *context)
{
  SshSSL3MACCtx *ctx = context;

  if (ctx->hash_def->uninit)
    (*ctx->hash_def->uninit)(ctx->hash_context);
}

void ssh_ssl3mac_start(void *context)
{
  SshSSL3MACCtx *ctx = context;

  (*ctx->hash_def->reset_context)(ctx->hash_context);
  (*ctx->hash_def->update)(ctx->hash_context, ctx->i_prefix,
                           ctx->prefix_len);
}

void ssh_ssl3mac_update(void *context, const unsigned char *buf, size_t len)
{
  SshSSL3MACCtx *ctx = context;
  (*ctx->hash_def->update)(ctx->hash_context, buf, len);
}

SshCryptoStatus ssh_ssl3mac_final(void *context, unsigned char *digest)
{
  SshSSL3MACCtx *ctx = context;
  SshCryptoStatus status;

  status = (*ctx->hash_def->final)(ctx->hash_context, digest);
  if (status != SSH_CRYPTO_OK)
    return status;

  (*ctx->hash_def->reset_context)(ctx->hash_context);
  (*ctx->hash_def->update)(ctx->hash_context, ctx->o_prefix,
                           ctx->prefix_len);
  (*ctx->hash_def->update)(ctx->hash_context, digest,
                           ctx->hash_def->digest_length);
  return (*ctx->hash_def->final)(ctx->hash_context, digest);
}

SshCryptoStatus ssh_ssl3mac_of_buffer(void *context, const unsigned char *buf,
                                      size_t len, unsigned char *digest)
{
  SSH_NOTREACHED;
  return SSH_CRYPTO_UNSUPPORTED;
}
