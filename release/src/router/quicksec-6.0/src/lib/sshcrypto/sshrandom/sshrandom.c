/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   sshrandom.c (originally in sshcryptocore/genrand.c)
*/

#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshcrypt_i.h"
#include "sshrandom_i.h"
#include "sshgetput.h"

#include "sshhash/sshhash_i.h"
#include "sshhash/md5.h"

#define SSH_DEBUG_MODULE "GenRand"

/* Definitions for random state */
#define SSH_RANDOM_STATE_BITS 8192
#define SSH_RANDOM_STATE_BYTES (SSH_RANDOM_STATE_BITS / 8)
#define SSH_RANDOM_MD5_KEY_BYTES 64

/* The number of bytes output by this PRNG for which we assume 1 bit of
   random entropy is leaked. Keep this define a power of 2 to allow
   fast division. */
#define SSH_RANDOM_ENTROPY_LOSS_BYTES 8192


/* SshRandomStateRec represents a generic random state structure. */
typedef struct SshRandomSshStateRec {
  unsigned char state[SSH_RANDOM_STATE_BYTES];
  unsigned char stir_key[SSH_RANDOM_MD5_KEY_BYTES];
  size_t next_available_byte;
  size_t add_position;

  /* Estimate of how many entropy bits we have in the pool */
  size_t estimated_entropy_bits;
  /* Total count of the number of random bytes output */
  size_t bytes_output;

} *SshRandomSshState, SshRandomSshStateStruct;

static SshCryptoStatus
ssh_random_ssh_init(void **context_ret)
{
  SshRandomSshState state;

  if (!(state = ssh_crypto_calloc_i(1, sizeof(*state))))
    return SSH_CRYPTO_NO_MEMORY;

  state->add_position = 0;
  state->next_available_byte = SSH_RANDOM_STATE_BYTES;

  *context_ret = state;
  return SSH_CRYPTO_OK;
}

static void
ssh_random_ssh_stir(SshRandomSshState state)
{
  SshUInt32 iv[4];
  size_t i;

  /* Get IV from the beginning of the pool. */
  iv[0] = SSH_GET_32BIT(state->state + 0);
  iv[1] = SSH_GET_32BIT(state->state + 4);
  iv[2] = SSH_GET_32BIT(state->state + 8);
  iv[3] = SSH_GET_32BIT(state->state + 12);

  /* Get new key. */
  memcpy(state->stir_key, state->state, sizeof(state->stir_key));

  /* First pass. */
  for (i = 0; i < SSH_RANDOM_STATE_BYTES; i += 16)
    {
      ssh_md5_transform(iv, state->stir_key);
      iv[0] ^= SSH_GET_32BIT(state->state + i);
      SSH_PUT_32BIT(state->state + i, iv[0]);
      iv[1] ^= SSH_GET_32BIT(state->state + i + 4);
      SSH_PUT_32BIT(state->state + i + 4, iv[1]);
      iv[2] ^= SSH_GET_32BIT(state->state + i + 8);
      SSH_PUT_32BIT(state->state + i + 8, iv[2]);
      iv[3] ^= SSH_GET_32BIT(state->state + i + 12);
      SSH_PUT_32BIT(state->state + i + 12, iv[3]);
    }

  /* Get new key. */
  memcpy(state->stir_key, state->state, sizeof(state->stir_key));

  /* Second pass. */
  for (i = 0; i < SSH_RANDOM_STATE_BYTES; i += 16)
    {
      ssh_md5_transform(iv, state->stir_key);
      iv[0] ^= SSH_GET_32BIT(state->state + i);
      SSH_PUT_32BIT(state->state + i, iv[0]);
      iv[1] ^= SSH_GET_32BIT(state->state + i + 4);
      SSH_PUT_32BIT(state->state + i + 4, iv[1]);
      iv[2] ^= SSH_GET_32BIT(state->state + i + 8);
      SSH_PUT_32BIT(state->state + i + 8, iv[2]);
      iv[3] ^= SSH_GET_32BIT(state->state + i + 12);
      SSH_PUT_32BIT(state->state + i + 12, iv[3]);
    }

  memset(iv, 0, sizeof(iv));

  state->add_position = 0;

  /* Some data in the beginning is not returned to avoid giving an observer
     complete knowledge of the contents of our random pool. */
  state->next_available_byte = sizeof(state->stir_key);
}

static SshCryptoStatus
ssh_random_ssh_add_entropy(void *context,
                           const unsigned char *buf, size_t buflen,
                           size_t estimated_entropy_bits)
{
  size_t pos;
  const unsigned char *input = buf;
  SshRandomSshState state = (SshRandomSshState) context;
  pos = state->add_position;

  while (buflen > 0)
    {
      /* Only add noise to the part of the pool that is used to key MD5. */
      if (pos >= SSH_RANDOM_MD5_KEY_BYTES)
        {
          pos = 0;
          ssh_random_ssh_stir(state);
        }

      state->state[pos] ^= *input;
      input++;
      buflen--;
      pos++;
    }

  state->add_position = pos;

  /* For the sake of caution, let's assume we don't ever get more
     than 128 bits of entropy. */
  state->estimated_entropy_bits +=
    (estimated_entropy_bits > 128) ? 128 : estimated_entropy_bits;

  return SSH_CRYPTO_OK;
}

static SshCryptoStatus
ssh_random_ssh_get_bytes(void *context, unsigned char *buf, size_t buflen)
{
  int i;
  SshRandomSshState state = (SshRandomSshState) context;

  /* Ask for more noise if we have less than 128 bits of estimated
     randomness. */
  if (state->estimated_entropy_bits < 128)
    ssh_crypto_library_request_noise();

  for (i = 0; i < buflen; i++)
    {
      if (state->next_available_byte >= SSH_RANDOM_STATE_BYTES)
        ssh_random_ssh_stir(state);

      if (state->next_available_byte >= SSH_RANDOM_STATE_BYTES)
        {
          ssh_crypto_library_error(SSH_CRYPTO_ERROR_OTHER);
          return SSH_CRYPTO_LIBRARY_ERROR;
        }

      buf[i] = state->state[state->next_available_byte++];

      state->bytes_output++;

      /* Reduce the estimated entropy by one bit for every
         SSH_RANDOM_ENTROPY_LOSS_BYTES bytes output. */
      if (state->estimated_entropy_bits &&
          state->bytes_output % SSH_RANDOM_ENTROPY_LOSS_BYTES == 0)
        state->estimated_entropy_bits--;
    }

  return SSH_CRYPTO_OK;
}

static void ssh_random_ssh_uninit(void *context)
{
  SshRandomSshState state = (SshRandomSshState) context;

  memset(state, 0, sizeof(*state));
  ssh_crypto_free_i(state);
}


const SshRandomDefStruct ssh_random_ssh = {
  "ssh",
  0,
  ssh_random_ssh_init, ssh_random_ssh_uninit,
  ssh_random_ssh_add_entropy, ssh_random_ssh_get_bytes,
  NULL_FNPTR
};
