/**
   @copyright
   Copyright (c) 2007 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   octeon-cipher.h
*/

#ifndef OCTEON_CIPHER_H
#define OCTEON_CIPHER_H


typedef struct SshCombinedDefRec
{
  const char *name;

  /* Block length of the cipher */
  size_t block_len;
  size_t cipher_key_len;
  size_t mac_key_len;

  /* Digest length of the mac */
  size_t digest_len;

  size_t (*ctxsize)(void);

  /* Initialize with separate cipher and mac keys */
  SshCryptoStatus (*init)(void *context,
                          const unsigned char *cipher_key,
                          size_t cipher_keylen,
                          const unsigned char *mac_key,
                          size_t mac_keylen,
                          Boolean for_encryption);

  /* Perform combined cipher and mac transform. When encrypting
     ('for_encryption' was TRUE when 'init' was called) the data is first
     encrypted and then the mac is applied. It is assumed the data to
     be encrypted begins at an offset 'enc_ofs' from 'src' and extends to
     the end of the buffer 'src'. Encrypted data is copied to 'dest'.
     The resulting ciphertext is then mac'ed, with the digest placed
     in 'digest'. The application must ensure that the input data for
     encryption is padded to the appropriate block cipher length.

     When decrypting the reverse operation is performed. The input digest
     is supplied in 'digest' and this must be compared to the resulting
     digest from the mac output. If this does not agree this function must
     return FALSE. */
  Boolean (*transform)(void *context,
                       unsigned char *dest,
                       const unsigned char *src,
                       size_t len,
                       size_t enc_ofs,
                       unsigned char *iv,
                       unsigned char *digest);


} *SshCombinedDef, SshCombinedDefStruct;


size_t ssh_aes_sha1_ctxsize(void);

SshCryptoStatus ssh_aes_sha1_init(void *context,
                                  const unsigned char *cipher_key,
                                  size_t cipher_keylen,
                                  const unsigned char *mac_key,
                                  size_t mac_keylen,
                                  Boolean for_encryption);

Boolean ssh_aes_sha1_transform(void *context, unsigned char *dest,
                               const unsigned char *src,
                               size_t len,
                               size_t enc_ofs,
                               unsigned char *iv,
                               unsigned char *digest);

size_t ssh_aes_md5_ctxsize(void);

SshCryptoStatus ssh_aes_md5_init(void *context,
                                 const unsigned char *cipher_key,
                                 size_t cipher_keylen,
                                 const unsigned char *mac_key,
                                 size_t mac_keylen,
                                 Boolean for_encryption);

Boolean ssh_aes_md5_transform(void *context, unsigned char *dest,
                              const unsigned char *src,
                              size_t len,
                              size_t enc_ofs,
                              unsigned char *iv,
                              unsigned char *digest);

size_t ssh_3des_sha1_ctxsize(void);

SshCryptoStatus ssh_3des_sha1_init(void *context,
                                   const unsigned char *cipher_key,
                                   size_t cipher_keylen,
                                   const unsigned char *mac_key,
                                   size_t mac_keylen,
                                   Boolean for_encryption);

Boolean ssh_3des_sha1_transform(void *context, unsigned char *dest,
                                const unsigned char *src,
                                size_t len,
                                size_t enc_ofs,
                                unsigned char *iv,
                                unsigned char *digest);

size_t ssh_3des_md5_ctxsize(void);

SshCryptoStatus ssh_3des_md5_init(void *context,
                                  const unsigned char *cipher_key,
                                  size_t cipher_keylen,
                                  const unsigned char *mac_key,
                                  size_t mac_keylen,
                                  Boolean for_encryption);

Boolean ssh_3des_md5_transform(void *context, unsigned char *dest,
                               const unsigned char *src,
                               size_t len,
                               size_t enc_ofs,
                               unsigned char *iv,
                               unsigned char *digest);

#endif /* !OCTEON_CIPHER */
