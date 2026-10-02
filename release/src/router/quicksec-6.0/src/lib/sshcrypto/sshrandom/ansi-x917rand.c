/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshcrypt_i.h"
#include "sshrandom_i.h"

#include "sshgetput.h"
#include "sshhash/sshhash_i.h"
#include "sshcipher/des.h"

#ifdef SSHDIST_CRYPT_SHA256
#include "sshhash/sha256.h"

#define SSH_DEBUG_MODULE "SshRandomAnsiX917"

/* This module implements the ANSI X9.17 Random Number Generator (RNG).
   Output blocks (consisting of 8 bytes) are obtained using three triple
   DES (3-DES) encryptions. The RNG requires as its seed material a 24 byte
   3-DES key and a special 8 byte seed block. In total this gives 32
   bytes of seed material, which must be externally supplied noise of high
   entropy. The security of the RNG is dependent on the quality of this
   external noise.

   To produce each output block, a timestamp is needed as input, it is
   encrypted with the secret key and then XORed with the present seed
   value, and finally encrypted again to give the output block. The seed
   is updated by XORing the output block with the encrypted timestamp and
   encrypting. See the ANSI standards for a more detailed description.

   The interfaces conform with those of the SSH random number generator,
   genrand.c, namely the ssh_random_add_noise(), ssh_random_stir(),
   ssh_random_get_byte() and ssh_random_free() functions. However the
   details of the two random number generators are quite different.
   External noise is added using the function ssh_random_noise(). Unlike
   the SSH random number generator, the added noise does not become
   effective until ssh_random_stir() is called, which reseeds the RNG.

   To preserve the interfaces between the two diffrerent RNG's, the
   ssh_random_add_noise() function takes as input an arbitrarily long
   buffer. This is then hashed (using SHA-256) to give a digest of 32
   bytes which is then used to seed the 3-DES key and the 8 byte seed block.
*/

#define KEY_BYTES    24
#define BLOCK_BYTES   8

/* The number of bytes output by this PRNG for which we assume 1 bit of
   radom entropy is leaked. Keep this define a power of 2 to allow
   fast division. */
#define SSH_X917_ENTROPY_LOSS_BYTES 8192


/* SshRandomAnsiStateRec represents a generic random state structure. */

typedef struct SshRandomAnsiStateRec {
  /* Holds the hash digest from SHA-256. */
  unsigned char digest[KEY_BYTES + BLOCK_BYTES];
  /* The first KEY_BYTES bytes of state are used to key 3-DES, the
     remaining BLOCK_BYTES bytes is the seed variable. */
  unsigned char state[KEY_BYTES + BLOCK_BYTES];
  unsigned char enc_time[BLOCK_BYTES];
  unsigned char   output[BLOCK_BYTES];
  size_t next_available_byte;
  void  *cipher;
  void  *hash;

  /* This data block of 32 bits is used for the FIPS continuous
     random number generator tests */
  unsigned char fips_block[4];

  /* An index to the above array */
  size_t fips_index;

  /* Counts how many consecutive identical bytes have been output. */
  size_t fips_count;

  /* If TRUE, the module has just been initialized and bytes obtained
     from ssh_random_get_byte() are not output, but instead stored in
     the fips_block[] array.  */
  Boolean fips_initializing;

  /* Estimate of how many entropy bits we have in the pool */
  size_t estimated_entropy_bits;
  /* Total count of the number of random bytes output */
  size_t bytes_output;

} *SshRandomAnsiState;

/* Mixes the bytes from the buffer into the state array. The pool should
   be stirred after a sufficient amount of noise has been added. The noise
   added from this function will not be utilized until the ssh_random_stir()
   function has been called.
*/

static SshCryptoStatus
ssh_random_ansi_x917_add_entropy(void *context,
                                 const unsigned char *buf, size_t buflen,
                                 size_t estimated_entropy_bits)
{
  size_t i;
  const unsigned char *input = buf;
  SshRandomAnsiState state = (SshRandomAnsiState) context;

  /* First hash the input to 32 bytes and put it into state->digest. */
  ssh_sha256_update(state->hash, input, buflen);
  ssh_sha256_final(state->hash, state->digest);

  /* XOR it to the entropy state pool. */
  for (i = 0; i < BLOCK_BYTES + KEY_BYTES; i++)
    state->state[i] ^= state->digest[i];

  /* Reset the hash context and clean. */
  ssh_sha256_reset_context(state->hash);
  memset(state->digest, 0, sizeof(*state->digest));

  /* Reset the 3-DES key. */
  ssh_des3_init(state->cipher, state->state, KEY_BYTES, TRUE);

  /* Reset the hash context. */
  ssh_sha256_reset_context(state->hash);

  state->next_available_byte = BLOCK_BYTES;

  /* The input is hashed to 32 bytes so we can't have more than 256
     bits of entropy. In addition for the sake of caution, let's
     assume we don't ever get more than 128 bits of entropy. */
  state->estimated_entropy_bits +=
    (estimated_entropy_bits > 128) ? 128 : estimated_entropy_bits;

  return SSH_CRYPTO_OK;
}

/* Returns a random byte. */
static SshCryptoStatus
ssh_random_ansi_x917_get_byte(SshRandomAnsiState state,
                              unsigned char *byte_ret)
{
  int i;
  SshUInt64 time;

  /* On initializing the PRNG we do not output the first 4 bytes,
     they are stored in the fips_block[] array. */
  if (state->fips_initializing)
    {
      memcpy(state->fips_block, state->state + state->next_available_byte, 4);
      state->next_available_byte += 4;
      state->fips_index = 0;
      state->fips_count = 0;
    }

  /* We are now initialized, and can start outputing random bytes */
  state->fips_initializing = FALSE;

  if (state->next_available_byte >= BLOCK_BYTES)
    {
      state->next_available_byte = 0;

      /* Get the current timestamp. */
      time = (SshUInt64) ssh_crypto_get_time();
      SSH_PUT_64BIT(state->enc_time, time);

      /* Encrypt the timestamp. */
      ssh_des3_ecb(state->cipher, state->enc_time, state->enc_time,
                   BLOCK_BYTES, NULL);

      /* Update the output block. */
      for (i = 0; i < BLOCK_BYTES; i++)
        state->output[i] = state->enc_time[i] ^ state->state[KEY_BYTES + i];

      /* Encrypt again. */
      ssh_des3_ecb(state->cipher, state->output,
                   state->output, BLOCK_BYTES, NULL);

      /* Update the seed block. */
      for (i = 0; i < BLOCK_BYTES; i++)
        state->state[KEY_BYTES + i] = state->enc_time[i] ^ state->output[i];

      ssh_des3_ecb(state->cipher, state->state + KEY_BYTES,
                   state->state + KEY_BYTES, BLOCK_BYTES, NULL);
    }

  *byte_ret = state->output[state->next_available_byte++];

  state->bytes_output++;

  /* Reduce the estimated entropy by one bit for every
     SSH_X917_ENTROPY_LOSS_BYTES bytes output. */
  if (state->estimated_entropy_bits &&
      state->bytes_output % SSH_X917_ENTROPY_LOSS_BYTES == 0)
    state->estimated_entropy_bits--;

  /* Ask for more noise if we have less than 128 bits of estimated
     randomness. */
  if (state->estimated_entropy_bits < 128)
    ssh_crypto_library_request_noise();

  return SSH_CRYPTO_OK;
}

static SshCryptoStatus
ssh_random_ansi_x917_get_bytes(void *context,
                               unsigned char *buf, size_t buflen)
{
  int i;
  SshRandomAnsiState state = (SshRandomAnsiState) context;
  SshCryptoStatus status;

  for (i = 0; i < buflen; i++)
    {
      status = ssh_random_ansi_x917_get_byte(state, &buf[i]);

      if (status != SSH_CRYPTO_OK)
        return status;
    }

  return SSH_CRYPTO_OK;
}

static SshCryptoStatus
ssh_random_ansi_x917_init(void **context_ret)
{
  size_t cipher_len, hash_len;
  SshRandomAnsiState state;

  cipher_len = ssh_des3_ctxsize();
  hash_len = ssh_sha256_ctxsize();

  if (!(state = ssh_crypto_calloc_i(1, sizeof(*state))))
    return SSH_CRYPTO_NO_MEMORY;

  /* Allocate memory for the 3-DES cipher context. */
  if (!(state->cipher = ssh_crypto_calloc_i(1, cipher_len)))
    goto failure;

  /* Allocate memory for the SHA-256 hash context. */
  if (!(state->hash = ssh_crypto_calloc_i(1, hash_len)))
    goto failure;

  state->fips_initializing = TRUE;

  /* Initialize the 3-DES context with the all zero key. */
  ssh_des3_init(state->cipher, state->state, KEY_BYTES, TRUE);

  /* Initialize the SHA256 context. */
  ssh_sha256_reset_context(state->hash);

  *context_ret = state;
  return SSH_CRYPTO_OK;

 failure:
  ssh_crypto_free_i(state->cipher);
  ssh_crypto_free_i(state);

  return SSH_CRYPTO_NO_MEMORY;
}

static void ssh_random_ansi_x917_uninit(void *context)
{
  SshRandomAnsiState state = (SshRandomAnsiState) context;

  ssh_crypto_free_i(state->hash);
  ssh_crypto_free_i(state->cipher);
  ssh_crypto_free_i(state);
}

const SshRandomDefStruct ssh_random_ansi_x917 = {
  "ansi-x9.17",



  0,
  ssh_random_ansi_x917_init,
  ssh_random_ansi_x917_uninit,
  ssh_random_ansi_x917_add_entropy,
  ssh_random_ansi_x917_get_bytes
};
#endif /* SSHDIST_CRYPT_SHA256 */
