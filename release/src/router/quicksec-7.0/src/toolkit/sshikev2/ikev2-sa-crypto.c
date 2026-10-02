/**
   @copyright
   Copyright (c) 2015 - 2016, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"

#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"

#include "ikev2-internal.h"
#include "ikev2-sa-crypto.h"

#define SSH_DEBUG_MODULE "SshIkev2SaCrypto"

#define IKEV2_ALG_NAME_LEN_MAX 16
#define IKEV2_CIPHER_KEY_LEN_MAX 32
#define IKEV2_MAC_KEY_LEN_MAX 64

typedef struct Ikev2SaCryptoRec
{
    char cipher_name[IKEV2_ALG_NAME_LEN_MAX + 1];
    unsigned char cipher_key_out[IKEV2_CIPHER_KEY_LEN_MAX];
    unsigned char cipher_key_in[IKEV2_CIPHER_KEY_LEN_MAX];
    size_t cipher_key_len;

    char mac_name[IKEV2_ALG_NAME_LEN_MAX + 1];
    unsigned char mac_key_out[IKEV2_MAC_KEY_LEN_MAX];
    unsigned char mac_key_in[IKEV2_MAC_KEY_LEN_MAX];
    size_t mac_key_len;

    bool auth_cipher;
    bool ctr_cipher;
} Ikev2SaCryptoStruct;


Ikev2SaCrypto
ikev2_sa_crypto_create()
{
    Ikev2SaCrypto context;

    context = ssh_calloc(1, sizeof (Ikev2SaCryptoStruct));

    if (context == NULL)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed"));
    }

    return context;
}

void
ikev2_sa_crypto_destroy(Ikev2SaCrypto context)
{
    ssh_free(context);
}

SshCryptoStatus
ikev2_sa_crypto_config(const char *cipher_alg,
                       unsigned char *cipher_key_out,
                       unsigned char *cipher_key_in,
                       size_t cipher_key_len,
                       const char *mac_alg,
                       unsigned char *mac_key_out,
                       unsigned char *mac_key_in,
                       size_t mac_key_len,
                       Ikev2SaCrypto context)
{
    SSH_ASSERT(context != NULL);

    SSH_ASSERT(strlen(cipher_alg) < IKEV2_ALG_NAME_LEN_MAX);
    SSH_ASSERT(cipher_key_len <= IKEV2_CIPHER_KEY_LEN_MAX);

    if (ssh_cipher_supported(cipher_alg) == false)
    {
        SSH_DEBUG(SSH_D_FAIL,
                  ("Unsupported cipher algorithm: %s",
                   cipher_alg));
        return SSH_CRYPTO_UNSUPPORTED;
    }

    if (ssh_cipher_get_key_length(cipher_alg) != cipher_key_len)
    {
        SSH_DEBUG(SSH_D_FAIL,
                  ("Invalid key length (%u bytes) for cipher: %s",
                   (unsigned int)cipher_key_len, cipher_alg));
        return SSH_CRYPTO_UNSUPPORTED;
    }

    strncpy(context->cipher_name, cipher_alg, IKEV2_ALG_NAME_LEN_MAX);

    memcpy(context->cipher_key_out, cipher_key_out, cipher_key_len);
    memcpy(context->cipher_key_in, cipher_key_in, cipher_key_len);
    context->cipher_key_len = cipher_key_len;

    context->auth_cipher = ssh_cipher_is_auth_cipher(cipher_alg);
    context->ctr_cipher = (!strcmp(cipher_alg, "aes128-ctr") ||
                           !strcmp(cipher_alg, "aes192-ctr") ||
                           !strcmp(cipher_alg, "aes256-ctr"));

    if (context->auth_cipher == false)
    {
        SSH_ASSERT(mac_alg != NULL);
        SSH_ASSERT(strlen(mac_alg) < IKEV2_ALG_NAME_LEN_MAX);
        SSH_ASSERT(mac_key_len <= IKEV2_MAC_KEY_LEN_MAX);

        if (ssh_mac_supported(mac_alg) == false)
        {
            SSH_DEBUG(SSH_D_FAIL,
                  ("Unsupported mac algorithm: %s",
                   mac_alg));
            return SSH_CRYPTO_UNSUPPORTED;
        }

        strncpy(context->mac_name, mac_alg, IKEV2_ALG_NAME_LEN_MAX);

        memcpy(context->mac_key_out, mac_key_out, mac_key_len);
        memcpy(context->mac_key_in, mac_key_in, mac_key_len);
        context->mac_key_len = mac_key_len;
    }

    return SSH_CRYPTO_OK;
}

size_t
ikev2_sa_crypto_cipher_iv_len(Ikev2SaCrypto context)
{
    if (strlen(context->cipher_name) == 0)
      return 0;

    if (!strcmp(context->cipher_name, "aes128-ctr") ||
        !strcmp(context->cipher_name, "aes192-ctr") ||
        !strcmp(context->cipher_name, "aes256-ctr"))
      return 8;

    if (context->auth_cipher)
      return 8;

    return ssh_cipher_get_iv_length(context->cipher_name);
}

size_t
ikev2_sa_crypto_cipher_block_len(Ikev2SaCrypto context)
{
    if (strlen(context->cipher_name) == 0)
      return 0;

    return ssh_cipher_get_block_length(context->cipher_name);
}

size_t
ikev2_sa_crypto_checksum_len(Ikev2SaCrypto context)
{
    if (context->auth_cipher)
      return ssh_cipher_auth_digest_length(context->cipher_name);

    if (strlen(context->mac_name) == 0)
      return 0;

    return ssh_mac_length(context->mac_name);
}

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
                               Ikev2SaCrypto context)
{
    SshCryptoStatus status;
    SshCipher cipher = NULL;
    SshMac mac = NULL;
    int i;

    SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP,
                      ("Packet before encryption:"),
                      packet,
                      packet_len);

#ifdef SSH_IKEV2_CRYPTO_KEY_DEBUG
    SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP,
                      ("Using cipher %s with key:",
                       context->cipher_name),
                      context->cipher_key_out,
                      context->cipher_key_len);
#endif /* SSH_IKEV2_CRYPTO_KEY_DEBUG */

    status = ssh_cipher_allocate(context->cipher_name,
                                 context->cipher_key_out,
                                 context->cipher_key_len,
                                 true,
                                 &cipher);

    if (status != SSH_CRYPTO_OK)
    {
        SSH_DEBUG(SSH_D_FAIL,
                  ("Cipher allocation failed: %s",
                   ssh_crypto_status_message(status)));
        goto end;
    }

    if ((context->auth_cipher == true) ||
        (context->ctr_cipher == true))
    {
        unsigned char iv_buffer[SSH_CIPHER_MAX_IV_SIZE];

        SSH_ASSERT((nonce_len == IKEV2_CIPHER_AES_GCM_NONCE_LEN) ||
                   (nonce_len == IKEV2_CIPHER_AES_CCM_NONCE_LEN) ||
                   (nonce_len == IKEV2_CIPHER_AES_CTR_NONCE_LEN));

        SSH_ASSERT(iv_field_len == 8);

        for (i = 0; i < iv_field_len; i++)
          iv_field[i] = ssh_random_get_byte();

        memset(iv_buffer, 0x00, SSH_CIPHER_MAX_IV_SIZE);
        memcpy(iv_buffer, nonce, nonce_len);
        memcpy(iv_buffer + nonce_len, iv_field, iv_field_len);

        /* Initialize counter for counter mode (except CCM) as part of
           the iv */
        if (nonce_len != IKEV2_CIPHER_AES_CCM_NONCE_LEN)
        {
            iv_buffer[15] = 0x01;
        }

#ifdef SSH_IKEV2_CRYPTO_KEY_DEBUG
        SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP,
                          ("Header IV"),
                          iv_field,
                          iv_field_len);

        SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP,
                          ("Full IV"),
                          iv_buffer,
                          16);
#endif /* SSH_IKEV2_CRYPTO_KEY_DEBUG */

        status = ssh_cipher_set_iv(cipher, iv_buffer);
    }
    else
    {
        for (i = 0; i < iv_field_len; i++)
          iv_field[i] = ssh_random_get_byte();

#ifdef SSH_IKEV2_CRYPTO_KEY_DEBUG
        SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP,
                          ("IV"),
                          iv_field,
                          iv_field_len);
#endif /* SSH_IKEV2_CRYPTO_KEY_DEBUG */

        status = ssh_cipher_set_iv(cipher, iv_field);
    }

    if (status != SSH_CRYPTO_OK)
    {
        SSH_DEBUG(SSH_D_FAIL,
                  ("Cipher set iv failed: %s",
                   ssh_crypto_status_message(status)));
        goto end;
    }

    if (context->auth_cipher == true)
    {
#ifdef SSH_IKEV2_CRYPTO_KEY_DEBUG
        SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP, ("AAD"),
                          packet, packet_len);
#endif /* SSH_IKEV2_CRYPTO_KEY_DEBUG */

        status = ssh_cipher_auth_start(cipher,
                                       packet,
                                       unencrypted_len,
                                       encrypted_payloads_len);
    }
    else
    {
        status = ssh_cipher_start(cipher);
    }

    if (status != SSH_CRYPTO_OK)
    {
        SSH_DEBUG(SSH_D_FAIL,
                  ("Cipher start failed, %s",
                   ssh_crypto_status_message(status)));
        goto end;
    }

#ifdef SSH_IKEV2_CRYPTO_KEY_DEBUG
    SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP,
                      ("Encrypting %u bytes",
                       (unsigned int) encrypted_payloads_len),
                      encrypted_payloads,
                      encrypted_payloads_len);
#endif /* SSH_IKEV2_CRYPTO_KEY_DEBUG */

    status = ssh_cipher_transform(cipher,
                                  encrypted_payloads,
                                  encrypted_payloads,
                                  encrypted_payloads_len);

    if (status != SSH_CRYPTO_OK)
    {
        SSH_DEBUG(SSH_D_FAIL,
                  ("Cipher transform failed: %s",
                   ssh_crypto_status_message(status)));
        goto end;
    }

#ifdef SSH_IKEV2_CRYPTO_KEY_DEBUG
    SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP,
                      ("Encrypted %u bytes",
                       (unsigned int) encrypted_payloads_len),
                      encrypted_payloads,
                      encrypted_payloads_len);
#endif /* SSH_IKEV2_CRYPTO_KEY_DEBUG */

    if (context->auth_cipher == true)
    {
        status = ssh_cipher_auth_final(cipher, checksum_field);

        if (status != SSH_CRYPTO_OK)
        {
            SSH_DEBUG(SSH_D_FAIL,
                      ("Cipher auth finalize failed: %s",
                       ssh_crypto_status_message(status)));
            goto end;
        }
    }
    else
    {
#ifdef SSH_IKEV2_CRYPTO_KEY_DEBUG
        SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP,
                          ("Using MAC %s with key:",
                           context->mac_name),
                          context->mac_key_out,
                          context->mac_key_len);
#endif /* SSH_IKEV2_CRYPTO_KEY_DEBUG */

        status = ssh_mac_allocate(context->mac_name,
                                  context->mac_key_out,
                                  context->mac_key_len,
                                  &mac);

        if (status != SSH_CRYPTO_OK)
        {
            SSH_DEBUG(SSH_D_FAIL,
                      ("Mac allocate failed: %s",
                       ssh_crypto_status_message(status)));
            goto end;
        }

        ssh_mac_reset(mac);

#ifdef SSH_IKEV2_CRYPTO_KEY_DEBUG
        SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP,
                          ("MACing %u bytes",
                           (unsigned int) packet_len),
                          packet,
                          packet_len);
#endif /* SSH_IKEV2_CRYPTO_KEY_DEBUG */

        ssh_mac_update(mac, packet, packet_len);

        if (status != SSH_CRYPTO_OK)
        {
            SSH_DEBUG(SSH_D_FAIL,
                      ("Mac allocate failed: %s",
                       ssh_crypto_status_message(status)));
            goto end;
        }

        status = ssh_mac_final(mac, checksum_field);

        if (status != SSH_CRYPTO_OK)
        {
            SSH_DEBUG(SSH_D_FAIL,
                      ("Mac finalize failed: %s",
                       ssh_crypto_status_message(status)));
            goto end;
        }

    }

#ifdef SSH_IKEV2_CRYPTO_KEY_DEBUG
        SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP, ("MAC output"),
                          checksum_field, checksum_field_len);
#endif /* SSH_IKEV2_CRYPTO_KEY_DEBUG */

   end:
    if (cipher != NULL)
      ssh_cipher_free(cipher);

    if (mac != NULL)
      ssh_mac_free(mac);

    return status;
}

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
                               Ikev2SaCrypto context)
{
    SshCryptoStatus status;
    SshCipher cipher = NULL;
    SshMac mac = NULL;

#ifdef SSH_IKEV2_CRYPTO_KEY_DEBUG
    SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP,
                      ("Using cipher %s with key:",
                       context->cipher_name),
                      context->cipher_key_in,
                      context->cipher_key_len);
#endif /* SSH_IKEV2_CRYPTO_KEY_DEBUG */

    status = ssh_cipher_allocate(context->cipher_name,
                                 context->cipher_key_in,
                                 context->cipher_key_len,
                                 false,
                                 &cipher);

    if (status != SSH_CRYPTO_OK)
    {
        SSH_DEBUG(SSH_D_FAIL,
                  ("Cipher allocation failed: %s",
                   ssh_crypto_status_message(status)));
        goto end;
    }


    if (context->auth_cipher == false)
    {
        unsigned char checksum[SSH_MAX_HASH_DIGEST_LENGTH];

#ifdef SSH_IKEV2_CRYPTO_KEY_DEBUG
        SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP,
                          ("Using MAC %s with key:",
                           context->mac_name),
                          context->mac_key_in,
                          context->mac_key_len);
#endif /* SSH_IKEV2_CRYPTO_KEY_DEBUG */

        status = ssh_mac_allocate(context->mac_name,
                                  context->mac_key_in,
                                  context->mac_key_len,
                                  &mac);

        if (status != SSH_CRYPTO_OK)
        {
            SSH_DEBUG(SSH_D_FAIL,
                      ("Mac allocate failed: %s",
                       ssh_crypto_status_message(status)));
            goto end;
        }


        ssh_mac_reset(mac);

#ifdef SSH_IKEV2_CRYPTO_KEY_DEBUG
        SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP,
                          ("MACing %u bytes",
                           (unsigned int) packet_len),
                          packet,
                          packet_len);
#endif /* SSH_IKEV2_CRYPTO_KEY_DEBUG */

        ssh_mac_update(mac, packet, packet_len);

        if (status != SSH_CRYPTO_OK)
        {
            SSH_DEBUG(SSH_D_FAIL,
                      ("Mac allocate failed: %s",
                       ssh_crypto_status_message(status)));
            goto end;
        }

        status = ssh_mac_final(mac, checksum);

        if (status != SSH_CRYPTO_OK)
        {
            SSH_DEBUG(SSH_D_FAIL,
                      ("Mac finalize failed: %s",
                       ssh_crypto_status_message(status)));
            goto end;
        }

#ifdef SSH_IKEV2_CRYPTO_KEY_DEBUG
        SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP, ("MAC output"),
                          checksum, checksum_field_len);
#endif /* SSH_IKEV2_CRYPTO_KEY_DEBUG */

        /* Verify the mac. */
        if (memcmp(checksum, checksum_field, checksum_field_len)
            != 0)
        {
            SSH_DEBUG(SSH_D_NETGARB,
                      ("Error: Packet checksum comparison failed"));

            status = SSH_CRYPTO_SIGNATURE_CHECK_FAILED;
            goto end;
        }

        SSH_DEBUG(SSH_D_LOWOK,
                  ("Packet checksum comparison succeeded"));
    }

    if ((context->auth_cipher == true) ||
        (context->ctr_cipher == true))
    {
        unsigned char iv_buffer[SSH_CIPHER_MAX_IV_SIZE];

        SSH_ASSERT((nonce_len == IKEV2_CIPHER_AES_GCM_NONCE_LEN) ||
                   (nonce_len == IKEV2_CIPHER_AES_CCM_NONCE_LEN) ||
                   (nonce_len == IKEV2_CIPHER_AES_CTR_NONCE_LEN));

        SSH_ASSERT(iv_field_len == 8);

        memset(iv_buffer, 0x00, SSH_CIPHER_MAX_IV_SIZE);
        memcpy(iv_buffer, nonce, nonce_len);
        memcpy(iv_buffer + nonce_len, iv_field, iv_field_len);

        /* Initialize counter for counter mode (except CCM) as part of
           the iv */
        if (nonce_len != IKEV2_CIPHER_AES_CCM_NONCE_LEN)
        {
            iv_buffer[15] = 0x01;
        }

#ifdef SSH_IKEV2_CRYPTO_KEY_DEBUG
        SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP,
                          ("Header IV"),
                          iv_field,
                          iv_field_len);

        SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP,
                          ("Full IV"),
                          iv_buffer,
                          16);
#endif /* SSH_IKEV2_CRYPTO_KEY_DEBUG */

        status = ssh_cipher_set_iv(cipher, iv_buffer);
    }
    else
    {
#ifdef SSH_IKEV2_CRYPTO_KEY_DEBUG
        SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP,
                          ("IV"),
                          iv_field,
                          iv_field_len);
#endif /* SSH_IKEV2_CRYPTO_KEY_DEBUG */

        status = ssh_cipher_set_iv(cipher, iv_field);
    }

    if (status != SSH_CRYPTO_OK)
    {
        SSH_DEBUG(SSH_D_FAIL,
                  ("Cipher set iv failed: %s",
                   ssh_crypto_status_message(status)));
        goto end;
    }

    if (context->auth_cipher == true)
    {
#ifdef SSH_IKEV2_CRYPTO_KEY_DEBUG
        SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP, ("AAD"),
                          packet, unencrypted_len);
#endif /* SSH_IKEV2_CRYPTO_KEY_DEBUG */

        status = ssh_cipher_auth_start(cipher,
                                       packet,
                                       unencrypted_len,
                                       encrypted_payloads_len);
    }
    else
    {
        status = ssh_cipher_start(cipher);
    }

    if (status != SSH_CRYPTO_OK)
    {
        SSH_DEBUG(SSH_D_FAIL,
                  ("Cipher start failed, %s",
                   ssh_crypto_status_message(status)));
        goto end;
    }

    if (status != SSH_CRYPTO_OK)
    {
        SSH_DEBUG(SSH_D_FAIL,
                  ("Cipher start failed: %s",
                   ssh_crypto_status_message(status)));
        goto end;
    }

#ifdef SSH_IKEV2_CRYPTO_KEY_DEBUG
        SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP,
                          ("Encrypted buffer"),
                          encrypted_payloads,
                          encrypted_payloads_len);
#endif /* SSH_IKEV2_CRYPTO_KEY_DEBUG */

    status = ssh_cipher_transform(cipher,
                                  encrypted_payloads,
                                  encrypted_payloads,
                                  encrypted_payloads_len);

    if (status != SSH_CRYPTO_OK)
    {
        SSH_DEBUG(SSH_D_FAIL,
                  ("Cipher transform failed: %s",
                   ssh_crypto_status_message(status)));
        goto end;
    }

#ifdef SSH_IKEV2_CRYPTO_KEY_DEBUG
        SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP,
                          ("Decrypted buffer"),
                          encrypted_payloads,
                          encrypted_payloads_len);
#endif /* SSH_IKEV2_CRYPTO_KEY_DEBUG */

    if (context->auth_cipher == true)
    {
        status = ssh_cipher_auth_final_verify(cipher,
                                              checksum_field);

        if (status != SSH_CRYPTO_OK)
        {
            SSH_DEBUG(SSH_D_NETGARB,
                      ("Error: Packet checksum comparison failed"));

            status = SSH_CRYPTO_SIGNATURE_CHECK_FAILED;
            goto end;
        }

        SSH_DEBUG(SSH_D_LOWOK,
                  ("Packet checksum comparison succeeded"));
    }


   end:
    if (cipher != NULL)
      ssh_cipher_free(cipher);

    if (mac != NULL)
      ssh_mac_free(mac);

    return status;
}
