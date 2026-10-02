/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   ARCFOUR cipher (based on a cipher posted on the Usenet in Spring-95).
   This cipher is widely believed and has been tested to be equivalent
   with the RC4 cipher from RSA Data Security, Inc.  (RC4 is a trademark
   of RSA Data Security)
*/

#ifndef ARCFOUR_H
#define ARCFOUR_H

/* Compute Arcfour context size. */
size_t ssh_arcfour_ctxsize(void);

/* Sets arcfour key for encryption. */
SshCryptoStatus ssh_arcfour_init(void *context,
                                 const unsigned char *key, size_t keylen,
                                 Boolean for_encryption);

/* Destroys any sensitive data in the context. */
void ssh_arcfour_free(void *context);

/* Encrypt/decrypt data. */
#ifdef NEED_ASM_LINKAGE
__attribute__((regparm(0)))
#endif /* NEED_ASM_LINKAGE */
SshCryptoStatus ssh_arcfour_transform(void *context, unsigned char *dest,
                           const unsigned char *src, size_t len,
                           unsigned char *iv);

#endif /* ARCFOUR_H */
