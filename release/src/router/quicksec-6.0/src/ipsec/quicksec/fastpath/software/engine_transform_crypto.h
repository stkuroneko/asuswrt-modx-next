/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Declarations and definitions private to the software FastPath
   implementation.
*/

#ifndef ENGINE_FASTPATH_CRYPTO_H
#define ENGINE_FASTPATH_CRYPTO_H


typedef enum
{
  SSH_TRANSFORM_SUCCESS,
  SSH_TRANSFORM_FAILURE
}
SshTransformResult;


/*
  Allocates memory structures required for the cryptographic
  operations specified by trr and transform parameters. On success,
  the allocated memory is stored in sw_crypto pointer in tc.
  On failure no memory is allocated.
 */
SshTransformResult
transform_crypto_alloc(
        SshFastpathTransformContext tc,
        SshEngineTransformRun trr,
        SshUInt32 transform);

/*
  Frees all memory allocated by transform_crypto_alloc and sets
  sw_crypto pointer from in tc to NULL. Does nothing, if sw_crypto is
  already NULL.
 */
void
transform_crypto_free(
        SshFastpathTransformContext tc);


/*
  Resets state of allocated cryptographic structures. Especially
  resets the state of mac computation.
 */
void
transform_crypto_reset(
        SshFastpathTransformContext tc);


/*
  Updates mac computation state. The function is used for plain macs
  (e.g. hmac) and the AAD of authenticating ciphers.
 */
SshTransformResult
transform_mac_update(
        SshFastpathTransformContext tc,
        const unsigned char * buf,
        size_t len);


/*
  Finalizes mac computation and returns the mac value. Used for both
  normal macs and authenticating ciprhers. In case of authenticating
  ciphers all encrypted data i.e. all calls to transform_cipher_update
  and transform_cipher_update_remaining must be already done.
 */
SshTransformResult
transform_mac_finish(
        SshFastpathTransformContext tc,
        unsigned char *mac,
        unsigned char mac_len);


/*
  Update cipher state. Depending on the parameters to
  transform_cyrpto_alloc the function performs either decryption or
  encryption. In case of authenticating ciphers the mac computation
  state is also updated. The size in data should be cipher block size
  aligned. The iv parameter used for input and output of the
  inialization vector.
 */
SshTransformResult
transform_cipher_update(
        SshFastpathTransformContext tc,
        unsigned char *dest,
        const unsigned char *src,
        size_t len,
        unsigned char *iv);

/*
  Handles input data lengths that are not cipher block size aligned.
  Can only be called once per input data sequence. After calling this
  function the transform_cipher_update can not be called.
 */
SshTransformResult
transform_cipher_update_remaining(
        SshFastpathTransformContext tc,
        unsigned char *dest,
        const unsigned char *src,
        size_t len,
        unsigned char *iv);


#endif /* ENGINE_FASTPATH_CRYPTO_H */
