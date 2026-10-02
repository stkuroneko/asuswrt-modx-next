/**
   @copyright
   Copyright (c) 2015 - 2015, INSIDE Secure Oy. All rights reserved.
*/

#ifndef SSH_IKEV2_SA_CRYPTO_H
#define SSH_IKEV2_SA_CRYPTO_H

Ikev2SaCrypto
ikev2_sa_crypto_create();

void
ikev2_sa_crypto_destroy();

/** Configure cipher and mac algorithms and keys for IKEv2 SA */
SshCryptoStatus
ikev2_sa_crypto_config(const char *cipher_alg,
                       unsigned char *cipher_key_out,
                       unsigned char *cipher_key_in,
                       size_t cipher_key_len,
                       const char *mac_alg,
                       unsigned char *mac_key_out,
                       unsigned char *mac_key_in,
                       size_t mac_key_len,
                       Ikev2SaCrypto context);

size_t
ikev2_sa_crypto_cipher_iv_len(Ikev2SaCrypto context);

size_t
ikev2_sa_crypto_cipher_block_len(Ikev2SaCrypto context);

size_t
ikev2_sa_crypto_checksum_len(Ikev2SaCrypto context);

/** Encrypt IKEv2 packet

    @param packet
    Pointer to the start of packet

    @param packet_len
    Packet length including padding and padding length, but without checksum
    field.

    @param unencrypted_len
    Length of the unencrypted part of the packet containing IKEv2 header,
    possible plaintext payloads and unencrypted part of the encrypted
    payload IV excluded.

    @param encrypted_payloads
    Pointer to start of payloads to be encrypted

    @param iv_field
    Pointer to IV field in the encrypted payload

    @param checksum_field
    Pointer to checksum field trailing the packet

    @param nonce
    Nonce to be used for IV in the CTR, GCM and CCM mode ciphers

*/
SshCryptoStatus
ikev2_sa_crypto_packet_encrypt(unsigned char *packet,
                               size_t packet_len,
                               size_t unencrypted_len,
                               unsigned char *encrypted_payloads,
                               size_t encrypted_payloads_len,
                               unsigned char *iv_field,
                               size_t iv_field_len,
                               unsigned char *checksum_field,
                               size_t checksum_field_len,
                               unsigned char *nonce,
                               size_t nonce_len,
                               Ikev2SaCrypto context);

/** Decrypt IKEv2 packet

    @param packet
    Pointer to the start of packet

    @param packet_len
    Packet length including padding and padding length, but without checksum
    field.

    @param unencrypted_len
    Length of the unencrypted part of the packet containing IKEv2 header,
    possible plaintext payloads and unencrypted part of the encrypted
    payload IV excluded.

    @param encrypted_payloads
    Pointer to start of payloads to be decrypted

    @param iv_field
    Pointer to IV field in the encrypted payload

    @param checksum_field
    Pointer to checksum field trailing the packet

    @param nonce
    Nonce to be used for IV in the CTR, GCM and CCM mode ciphers

*/
SshCryptoStatus
ikev2_sa_crypto_packet_decrypt(unsigned char *packet,
                               size_t packet_len,
                               size_t unencrypted_len,
                               unsigned char *encrypted_payloads,
                               size_t encrypted_payloads_len,
                               unsigned char *iv_field,
                               size_t iv_field_len,
                               unsigned char *checksum_field,
                               size_t checksum_field_len,
                               unsigned char *nonce,
                               size_t nonce_len,
                               Ikev2SaCrypto context);

#endif /* SSH_IKEV2_SA_CRYPTO_H */
