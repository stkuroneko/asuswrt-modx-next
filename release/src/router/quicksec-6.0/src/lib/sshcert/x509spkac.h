/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   SPKAC (Signed Public Key And Challenge) blobs emitted by Netscape
   in response to HTML forms containing the KEYGEN tag.
*/

#ifndef SSHX509SPKAC_H
#define SSHX509SPKAC_H

#include "x509.h"

typedef struct SshX509SpkacRec
{
  /* The public key contained in the spkac */
  SshX509PublicKey public_key;

  /* The challenge password contained in the spkac. Born
   * as an attribute to the KEYGEN tag. */
  unsigned char *challenge;
  size_t         challenge_length;

  /* The signature algorithm used in the signing operation. */
  const char *signature_algorithm;
  SshX509PkAlgorithm issuer_pk_type;

  /* The signature of the information. */
  unsigned char *signature;
  size_t         signature_length;

  /* The signed portion of the data (pkac). */
  unsigned char *signed_data;
  size_t         signed_data_length;

} *SshX509Spkac;


/*
 * Decode the BER encoded SPKAC blob in ber_buf and store the result in
 * an SPKAC structure.
 */
SshX509Status ssh_x509_spkac_decode(const unsigned char *ber_buf,
                                    size_t ber_length,
                                    SshX509Spkac *spkac);

/*
 *  Free an SPKAC structure.
 */
void ssh_x509_spkac_delete(SshX509Spkac spkac);

/* Verify the signature in the spkac structure. Uses the parameter "key"
 * for verification is it is not NULL, and the public key contained in
 * the  othwerwise.
 * This function returns true if the signature is valid, false if it isn't.
 */
SshOperationHandle
ssh_x509_spkac_verify_async(SshX509Spkac spkac, SshPublicKey key,
                            SshX509VerifyCB callback,
                            void *context);

Boolean ssh_x509_spkac_verify(SshX509Spkac spkac, SshPublicKey key);


/* Extract the public key from the spkac structure. The returned key
 * is not duplicated, ie. the caller must not free it. */
SshPublicKey ssh_x509_spkac_get_public_key(SshX509Spkac spkac);

/* Extract the challenge password from the spkac structure. The
 * challenge is not duplicated, ie. the caller must not free it. */
Boolean ssh_x509_spkac_get_challenge(SshX509Spkac spkac,
                                     unsigned char **challenge,
                                     size_t *challenge_length);

#endif /* SSHX509SPKAC_H */
