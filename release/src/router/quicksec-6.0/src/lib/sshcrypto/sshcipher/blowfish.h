/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   The blowfish encryption algorithm, created by Bruce Schneier.
*/

#ifndef BLOWFISH_H
#define BLOWFISH_H

/* Prototypes */

/* Gives the size of memory block allocated for blowfish context */
size_t ssh_blowfish_ctxsize(void);

/* Initializes an already allocated area for blowfish encryption/decryption */
SshCryptoStatus ssh_blowfish_init(void *context,
                                  const unsigned char *key, size_t keylen,
                                  Boolean for_encryption);

/* Encrypt/decrypt in electronic code book mode. */
SshCryptoStatus ssh_blowfish_ecb(void *context, unsigned char *dest,
                      const unsigned char *src, size_t len,
                      unsigned char *iv);

/* Encrypt/decrypt in cipher block chaining mode. */
SshCryptoStatus ssh_blowfish_cbc(void *context, unsigned char *dest,
                      const unsigned char *src, size_t len,
                      unsigned char *iv);

/* Encrypt/decrypt in cipher feedback mode. */
SshCryptoStatus ssh_blowfish_cfb(void *context, unsigned char *dest,
                      const unsigned char *src, size_t len,
                      unsigned char *iv);

/* Encrypt/decrypt in output feedback mode. */
SshCryptoStatus ssh_blowfish_ofb(void *context, unsigned char *dest,
                      const unsigned char *src, size_t len,
                      unsigned char *iv);
#endif
