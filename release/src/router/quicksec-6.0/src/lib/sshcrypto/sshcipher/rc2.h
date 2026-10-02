/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   rc2.h
*/

#ifndef SSHRC2_H
#define SSHRC2_H

/* RC2 is a cipher developed by R. Rivest in 1989. This implementation
   was written based upon the RFC-2268. */

/* Return the size of the RC2 key context. */
size_t ssh_rc2_ctxsize(void);

/* Initialize the version of the RC2 with large key. Effective
   key length = 64 bits. */
SshCryptoStatus ssh_rc2_init(void *context,
                             const unsigned char *key,
                             size_t keylen,
                             Boolean for_encryption);

/* Initialize the version of the RC2 with large key. Effective
   key length = 128 bits. */
SshCryptoStatus ssh_rc2_128_init(void *context,
                                 const unsigned char *key,
                                 size_t keylen,
                                 Boolean for_encryption);

/* Remark. Other initialization routines will be added later as
   RC2 has specific effective key length parameter which is probably
   best handled by adding just new initialization functions (under
   our generic cipher interface). */

/* Encrypt in ecb/cbc/cfb/ofb modes. */
SshCryptoStatus ssh_rc2_ecb(void *context, unsigned char *dest,
                            const unsigned char *src, size_t len,
                            unsigned char *iv);

SshCryptoStatus ssh_rc2_cbc(void *context, unsigned char *dest,
                            const unsigned char *src, size_t len,
                            unsigned char *iv);

SshCryptoStatus ssh_rc2_cfb(void *context, unsigned char *dest,
                            const unsigned char *src, size_t len,
                            unsigned char *iv);

SshCryptoStatus ssh_rc2_ofb(void *context, unsigned char *dest,
                            const unsigned char *src, size_t len,
                            unsigned char *iv);

#endif /* SSHRC2_H */
