/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   ssl3mac.h
*/

#ifndef SSL3MAC_INCLUDED
#define SSL3MAC_INCLUDED

size_t ssh_ssl3mac_ctxsize(const SshHashDefStruct *hash_def);
SshCryptoStatus ssh_ssl3mac_init(void *context,
                                 const unsigned char *key,
                                 size_t keylen,
                                 const SshHashDefStruct *hash_def);
void ssh_ssl3mac_uninit(void *context);
void ssh_ssl3mac_start(void *context);
void ssh_ssl3mac_update(void *context, const unsigned char *buf,
                        size_t len);
SshCryptoStatus ssh_ssl3mac_final(void *context, unsigned char *digest);
SshCryptoStatus ssh_ssl3mac_of_buffer(void *context, const unsigned char *buf,
                                      size_t len, unsigned char *digest);

#endif /* SSL3MAC_INCLUDED */
