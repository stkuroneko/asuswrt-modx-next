/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshbuffer.h"
#include "sshgetput.h"
#include "sshcrypt.h"
#include "sshhash.h"
#include "sshenum.h"

#include "ssheap.h"
#include "ssheapi.h"
#include "ssheap_packet.h"

#define SSH_DEBUG_MODULE "SshEapPacket"

static const SshKeywordStruct ssheap_at_code_keywords[] =
{
    {"AT_RAND",                   SSH_EAP_AT_RAND},
    {"AT_AUTN",                   SSH_EAP_AT_AUTN},
    {"AT_RES",                    SSH_EAP_AT_RES},
    {"AT_AUTS",                   SSH_EAP_AT_AUTS},
    {"AT_PADDING",                SSH_EAP_AT_PADDING},
    {"AT_NONCE_MT",               SSH_EAP_AT_NONCE_MT},
    {"AT_PERMANENT_ID_REQ",       SSH_EAP_AT_PERMANENT_ID_REQ},
    {"AT_MAC",                    SSH_EAP_AT_MAC},
    {"AT_NOTIFICATION",           SSH_EAP_AT_NOTIFICATION},
    {"AT_ANY_ID_REQ",             SSH_EAP_AT_ANY_ID_REQ},
    {"AT_IDENTITY",               SSH_EAP_AT_IDENTITY},
    {"AT_VERSION_LIST",           SSH_EAP_AT_VERSION_LIST},
    {"AT_SELECTED_VERSION",       SSH_EAP_AT_SELECTED_VERSION},
    {"AT_FULLAUTH_ID_REQ",        SSH_EAP_AT_FULLAUTH_ID_REQ},
    {"AT_COUNTER",                SSH_EAP_AT_COUNTER},
    {"AT_COUNTER_TOO_SMALL",      SSH_EAP_AT_COUNTER_TOO_SMALL},
    {"AT_NONCE_S",                SSH_EAP_AT_NONCE_S},
    {"AT_CLIENT_ERROR_CODE",      SSH_EAP_AT_CLIENT_ERROR_CODE},
    {"AT_IV",                     SSH_EAP_AT_IV},
    {"AT_ENCR_DATA",              SSH_EAP_AT_ENCR_DATA},
    {"AT_NEXT_PSEUDONYM",         SSH_EAP_AT_NEXT_PSEUDONYM},
    {"AT_NEXT_REAUTH_ID",         SSH_EAP_AT_NEXT_REAUTH_ID},
    {"AT_CHECKCODE",              SSH_EAP_AT_CHECKCODE},
    {"AT_RESULT_IND",             SSH_EAP_AT_RESULT_IND},
    {"AT_BIDDING",                SSH_EAP_AT_BIDDING},
    {"AT_KDF_INPUT",              SSH_EAP_AT_KDF_INPUT},
    {"AT_KDF",                    SSH_EAP_AT_KDF},
    {NULL, 0},
};

const char*
ssh_eap_at_code_to_string(uint8_t code)
{
    const char *str;

    str = ssh_find_keyword_name(ssheap_at_code_keywords, code);

    if (str == NULL)
      str = "unknown";

    return str;
}

SshBuffer
ssh_eap_packet_append_res_attr(SshBuffer pkt,
                               uint8_t *res,
                               uint8_t res_len)
{
    uint8_t shdr[4]  = "";
    uint8_t pad_size = 0;
    uint32_t res_byte_len;

    res_byte_len = (res_len + 7) / 8;

    /* Static header portion, never changes. */
    shdr[0] = SSH_EAP_AT_RES;
    shdr[1] = 1 + (res_byte_len / 4);

    pad_size = 4 - (res_byte_len % 4);

    SSH_DEBUG(SSH_D_NICETOKNOW, ("Generating AT_RES res_byte_len %u.",
                                 res_byte_len));

    /* If we had to make padding, we'll have to increase
       the total length also. */
    if (pad_size != 4)
    {
        SSH_DEBUG(SSH_D_NICETOKNOW,
                  ("Padded AT_RES with %d bytes.", pad_size));
        shdr[1] += 1;
    }

    if (ssh_buffer_append(pkt, shdr, 2) != SSH_BUFFER_OK)
      return NULL;

    shdr[0] = 0;
    shdr[1] = (res_len & 0xFF);

    if (ssh_buffer_append(pkt, shdr, 2) != SSH_BUFFER_OK)
      return NULL;

    if (ssh_buffer_append(pkt, res, res_byte_len) != SSH_BUFFER_OK)
      return NULL;

    if (pad_size != 4)
    {
        memset (shdr, 0x0, sizeof(shdr));

        if (ssh_buffer_append(pkt, shdr, pad_size) != SSH_BUFFER_OK)
          return NULL;
    }

    return pkt;
}

SshBuffer
ssh_eap_packet_append_auts_attr(SshBuffer pkt, uint8_t *auts)
{
    uint8_t shdr[2] = "";

    /* Static header portion, never changes. */
    shdr[0] = SSH_EAP_AT_AUTS;
    shdr[1] = 4; /* For auts is always 4. */

    if (ssh_buffer_append(pkt, shdr, 2) != SSH_BUFFER_OK)
      return NULL;

    if (ssh_buffer_append(pkt, auts, 14) != SSH_BUFFER_OK)
      return NULL;

    return pkt;
}

SshBuffer
ssh_eap_packet_append_nonce_attr(SshBuffer pkt,
                                 uint8_t *nonce)
{
    uint8_t shdr[4] = "";

    /* Static header portion, never changes. */
    shdr[0] = SSH_EAP_AT_NONCE_MT;
    shdr[1] = 5; /* For nonce is always 5. */
    shdr[2] = shdr[3] = 0x00;

    if (ssh_buffer_append(pkt, shdr, 4) != SSH_BUFFER_OK)
    {
        return NULL;
    }

    if (ssh_buffer_append(pkt, nonce, 16) != SSH_BUFFER_OK)
    {
        return NULL;
    }

    return pkt;
}

SshBuffer
ssh_eap_packet_append_selected_version_attr(SshBuffer pkt,
                                            uint8_t *version)
{
    uint8_t shdr[2] = "";

    SSH_ASSERT(version != NULL);

    /* Static header portion, never changes. */
    shdr[0] = SSH_EAP_AT_SELECTED_VERSION;
    shdr[1] = 1; /* For selected version is always 1. */

    if (ssh_buffer_append(pkt, shdr, 2) != SSH_BUFFER_OK)
      return NULL;

    if (ssh_buffer_append(pkt, version, 2) != SSH_BUFFER_OK)
      return NULL;

    return pkt;
}

SshCryptoStatus
ssh_eap_aka_cipher_transform(unsigned char *payload,
                             size_t payload_len,
                             unsigned char *key,
                             unsigned char *iv,
                             bool encrypt)
{
    SshCryptoStatus status;
    SshCipher cipher = NULL;

    status = ssh_cipher_allocate("aes128-cbc",
                                 key,
                                 SSH_EAP_AKA_KENCR_LEN,
                                 encrypt,
                                 &cipher);

    if (status != SSH_CRYPTO_OK)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Failed to allocate cipher"));
        goto end;
    }

    status = ssh_cipher_set_iv(cipher, iv);

    if (status != SSH_CRYPTO_OK)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Failed to set IV"));
        goto end;
    }

    status = ssh_cipher_start(cipher);

    if (status != SSH_CRYPTO_OK)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Failed to start cipher operation"));
        goto end;
    }

    status = ssh_cipher_transform(cipher, payload, payload, payload_len);

    if (status != SSH_CRYPTO_OK)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Failed cipher transform"));
    }

end:
    if (cipher != NULL)
    {
        ssh_cipher_free(cipher);
    }

    return status;
}

static SshCryptoStatus
ssh_eap_packet_calculate_sha_mac(SshBuffer pkt,
                                 unsigned char *aad,
                                 size_t aad_len,
                                 unsigned char *key,
                                 size_t key_len,
                                 unsigned char *output,
                                 size_t output_len)
{
   SshCryptoStatus status;
   SshMac mac;
   unsigned char *packet_ptr;
   size_t packet_len;
   unsigned char mac_buffer[SSH_MAX_HASH_DIGEST_LENGTH];

   status = ssh_mac_allocate("hmac-sha1", key, key_len, &mac);

   if (status != SSH_CRYPTO_OK)
   {
       SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed"));
       return status;
   }

   packet_ptr = ssh_buffer_ptr(pkt);
   packet_len = ssh_buffer_len(pkt);

   SSH_ASSERT(packet_ptr != NULL);
   SSH_ASSERT(packet_len > 0);

   ssh_mac_update(mac, packet_ptr, packet_len);

   if (aad != NULL)
       ssh_mac_update(mac, aad, aad_len);

   status = ssh_mac_final(mac, mac_buffer);

   if (status != SSH_CRYPTO_OK)
   {
       SSH_DEBUG(SSH_D_FAIL, ("Mac calculation failed"));
   }
   else
   {
       memcpy(output, mac_buffer, output_len);
   }

   ssh_mac_free(mac);
   return status;
}

SshCryptoStatus
ssh_eap_packet_verify_mac(SshBuffer pkt,
                          unsigned char *aad,
                          size_t aad_len,
                          unsigned char *key,
                          size_t key_len,
                          unsigned char *packet_mac,
                          size_t packet_mac_len)
{
    unsigned char mac_buffer[SSH_MAX_HASH_DIGEST_LENGTH];
    SshCryptoStatus status;

    SSH_ASSERT(packet_mac_len <= SSH_MAX_HASH_DIGEST_LENGTH);

    status = ssh_eap_packet_calculate_sha_mac(pkt,
                                              aad,
                                              aad_len,
                                              key,
                                              key_len,
                                              mac_buffer,
                                              packet_mac_len);

    if (status != SSH_CRYPTO_OK)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Failed to calculate MAC"));
        return status;
    }

    if (memcmp(packet_mac, mac_buffer, packet_mac_len) != 0)
    {
        SSH_DEBUG(SSH_D_FAIL, ("MAC-verification failed"));
        status = SSH_CRYPTO_SIGNATURE_CHECK_FAILED;
    }

    return status;
}

bool
ssh_eap_packet_append_mac_attribute(SshBuffer pkt,
                                    unsigned char *aad,
                                    size_t aad_len,
                                    unsigned char *key,
                                    size_t key_len)
{
    unsigned char at_buffer[4 + SSH_EAP_AKA_MAC_LEN];
    unsigned char mac_buffer[SSH_EAP_AKA_MAC_LEN];
    SshCryptoStatus crypto_status;

    memset(at_buffer, 0, 4 + SSH_EAP_AKA_MAC_LEN);

    at_buffer[0] = SSH_EAP_AT_MAC;
    at_buffer[1] = 5;

    if (ssh_buffer_append(pkt, at_buffer, 4 + SSH_EAP_AKA_MAC_LEN)
        != SSH_BUFFER_OK)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed"));
        return false;
    }

    /* Calculate MAC over whole packet with zero MAC-value */
    crypto_status = ssh_eap_packet_calculate_sha_mac(pkt,
                                                     aad,
                                                     aad_len,
                                                     key,
                                                     key_len,
                                                     mac_buffer,
                                                     SSH_EAP_AKA_MAC_LEN);

    if (crypto_status != SSH_CRYPTO_OK)
    {
        SSH_DEBUG(SSH_D_FAIL, ("MAC calculation failed"));
        return false;
    }

    /* Insert new MAC to attribute */
    ssh_buffer_consume_end(pkt, SSH_EAP_AKA_MAC_LEN);

    if (ssh_buffer_append(pkt, mac_buffer, SSH_EAP_AKA_MAC_LEN)
        != SSH_BUFFER_OK)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed"));
        return false;
    }

    return true;
}

bool
ssh_eap_packet_append_at_counter(SshBuffer pkt,
                                 uint16_t counter)
{
    unsigned char attr[SSH_EAP_AKA_AT_LEN_MIN];

    attr[0] = SSH_EAP_AT_COUNTER;
    attr[1] = 1;
    SSH_PUT_16BIT(attr + 2, counter);

    if (ssh_buffer_append(pkt, attr, SSH_EAP_AKA_AT_LEN_MIN)
        != SSH_BUFFER_OK)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed"));
        return false;
    }

    return true;
}

bool
ssh_eap_packet_append_at_counter_too_small(SshBuffer pkt)
{
    unsigned char attr[SSH_EAP_AKA_AT_LEN_MIN];

    attr[0] = SSH_EAP_AT_COUNTER_TOO_SMALL;
    attr[1] = 1;
    attr[2] = 0;
    attr[3] = 0;

    if (ssh_buffer_append(pkt, attr, SSH_EAP_AKA_AT_LEN_MIN)
        != SSH_BUFFER_OK)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed"));
        return false;
    }

    return true;
}

bool
ssh_eap_packet_append_at_iv(SshBuffer pkt,
                            unsigned char *iv)
{
    unsigned char attr[4 + SSH_EAP_AKA_IV_LEN];

    attr[0] = SSH_EAP_AT_IV;
    attr[1] = 5;
    attr[2] = 0;
    attr[3] = 0;

    memcpy(attr + 4, iv, SSH_EAP_AKA_IV_LEN);

    if (ssh_buffer_append(pkt, attr, 4 + SSH_EAP_AKA_IV_LEN)
        != SSH_BUFFER_OK)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed"));
        return false;
    }

    return true;
}


#define SSH_EAP_AKA_AT_PADDING_LEN_MAX 12

static bool
ssh_eap_packet_append_at_padding(SshBuffer pkt,
                                 size_t padding_len)
{
    unsigned char at_padding[SSH_EAP_AKA_AT_PADDING_LEN_MAX];

    SSH_ASSERT((padding_len == 4) || (padding_len == 8) ||
               (padding_len == 12));

    memset(at_padding, 0x00, SSH_EAP_AKA_AT_PADDING_LEN_MAX);

    at_padding[0] = SSH_EAP_AT_PADDING;
    at_padding[1] = (uint8_t) (padding_len / 4);

    if (ssh_buffer_append(pkt, at_padding, padding_len)
        != SSH_BUFFER_OK)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed"));
        return false;
    }

    return true;
}

bool
ssh_eap_packet_append_at_encr_data(SshBuffer pkt,
                                   SshBuffer data,
                                   unsigned char *key,
                                   unsigned char *iv)
{
   unsigned char attr_header[SSH_EAP_AKA_AT_LEN_MIN];
   size_t at_encr_data_len = 0, at_padding_len = 0;
   SshCryptoStatus crypto_status;

   if (ssh_buffer_len(data) % 16)
       at_padding_len = 16 - (ssh_buffer_len(data) % 16);

   if ((at_padding_len > 0) &&
       (ssh_eap_packet_append_at_padding(data, at_padding_len) == false))
   {
       SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed"));
       return false;
   }

   SSH_ASSERT(ssh_buffer_len(data) % 16 == 0);

   crypto_status = ssh_eap_aka_cipher_transform(ssh_buffer_ptr(data),
                                                ssh_buffer_len(data),
                                                key,
                                                iv,
                                                true);

   if (crypto_status != SSH_CRYPTO_OK)
   {
       SSH_DEBUG(SSH_D_FAIL, ("Cipher operation failed"));
       return false;
   }

   at_encr_data_len = SSH_EAP_AKA_AT_LEN_MIN + ssh_buffer_len(data);

   attr_header[0] = SSH_EAP_AT_ENCR_DATA;
   attr_header[1] = (uint8_t) (at_encr_data_len / 4);
   attr_header[2] = 0;
   attr_header[3] = 0;

   if (ssh_buffer_append(pkt, attr_header, SSH_EAP_AKA_AT_LEN_MIN)
       != SSH_BUFFER_OK)
   {
       SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed"));
       return false;
   }

   if (ssh_buffer_append(pkt, ssh_buffer_ptr(data), ssh_buffer_len(data))
       != SSH_BUFFER_OK)
   {
       SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed"));
       return false;
   }

   return true;
}


SshBuffer
ssh_eap_packet_append_identity_attr(SshBuffer pkt,
                                    const uint8_t *id,
                                    uint8_t id_len)
{
    uint8_t shdr[4]  = "";
    uint8_t pad_size = 0;

    /* Static header portion, never changes. */
    shdr[0] = SSH_EAP_AT_IDENTITY;
    shdr[1] = 1 + (id_len / 4);

    pad_size = (id_len % 4);

    /* If we had to make padding, we'll have to increase
       the total length also. */
    if (pad_size)
      shdr[1] += 1;

    if (ssh_buffer_append(pkt, shdr, 2) != SSH_BUFFER_OK)
      return NULL;

    shdr[0] = 0;
    shdr[1] = (id_len & 0xFF);

    if (ssh_buffer_append(pkt, shdr, 2) != SSH_BUFFER_OK)
      return NULL;

    if (ssh_buffer_append(pkt, id, id_len) != SSH_BUFFER_OK)
      return NULL;

    if (pad_size)
    {
        memset (shdr, 0x0, sizeof(shdr));
        pad_size = 4 - pad_size;

        if (ssh_buffer_append(pkt, shdr, pad_size) != SSH_BUFFER_OK)
          return NULL;
    }

    return pkt;
}

uint8_t
ssh_eap_packet_get_code(SshBuffer buf)
{
    uint8_t *ptr = ssh_buffer_ptr(buf);

    if (!ptr)
    {
        SSH_NOTREACHED;
        return 0;
    }

    return ptr[0];
}

uint8_t
ssh_eap_packet_get_identifier(SshBuffer buf)
{
    uint8_t *ptr = ssh_buffer_ptr(buf);

    if (!ptr)
    {
        SSH_NOTREACHED;
        return 0;
    }
    return ptr[1];
}

uint16_t
ssh_eap_packet_get_length(SshBuffer buf)
{
    uint8_t *ptr = ssh_buffer_ptr(buf);

    if (!ptr)
    {
        SSH_NOTREACHED;
        return 0;
    }

    return SSH_GET_16BIT(ptr + 2);
}

void
ssh_eap_packet_strip_pad(SshBuffer buf)
{
    unsigned long len;
    unsigned long real_len;

    len = ssh_eap_packet_get_length(buf);
    real_len = (unsigned long)ssh_buffer_len(buf);

    SSH_ASSERT(real_len >= len);

    ssh_buffer_consume_end(buf, real_len - len);
}

uint8_t
ssh_eap_packet_get_type(SshBuffer buf)
{
    uint8_t *ptr = ssh_buffer_ptr(buf);

    if (!ptr)
    {
        SSH_NOTREACHED;
        return 0;
    }
    return ptr[4];
}

bool
ssh_eap_packet_isvalid(SshBuffer buf)
{
    uint8_t code;
    uint8_t *ptr;
    unsigned long len;

    if (buf == NULL)
      return false;

    ptr = ssh_buffer_ptr(buf);
    len = (unsigned long)ssh_buffer_len(buf);

    /* Make sure there is enough space in the buffer for a packet */
    if (ptr == NULL || len < 4)
      return false;

    SSH_ASSERT(ptr != NULL);

    /* Make sure that the buffer contains at least the packet */
    if (ssh_eap_packet_get_length(buf) > len)
    {
        SSH_DEBUG(SSH_D_FAIL,
                  ("Mismatching packet and buffer lengths, packet: %u, "
                   "buffer: %u",
                   (unsigned int) ssh_eap_packet_get_length(buf),
                   (unsigned int) len));
        return false;
    }

    /* Make sure the length of the packet in the header is
       at least as large as the header */
    if (ssh_eap_packet_get_length(buf) < 4)
    {
        SSH_DEBUG(SSH_D_FAIL,
                  ("Invalid packet length: %u",
                   (unsigned int) ssh_eap_packet_get_length(buf)));
        return false;
    }

    /* Make sure that if this is an EAP request or response,
       then the packet contains the EAP type field */
    code = ptr[0];

    if ((code == SSH_EAP_CODE_REQUEST || code == SSH_EAP_CODE_REPLY)
        && (ssh_eap_packet_get_length(buf) < 5))
    {
        SSH_DEBUG(SSH_D_FAIL,
                  ("Invalid packet length: %u",
                   (unsigned int) ssh_eap_packet_get_length(buf)));
        return false;
    }

    /* Ok for further processing */
    return true;

}

void
ssh_eap_packet_skip_hdr(SshBuffer buf)
{
    SSH_ASSERT(ssh_eap_packet_isvalid(buf));

    /* Assume existence of "type" field, which
       is not present in success or failure messages */

    SSH_ASSERT(ssh_eap_packet_get_length(buf) >= 5);

    ssh_buffer_consume(buf, 5);
}

bool
ssh_eap_packet_build_hdr(SshBuffer buf,
                         uint8_t code,
                         uint8_t id,
                         uint16_t length)
{
    uint8_t hdr[4];

    ssh_buffer_clear(buf);

    hdr[0] = code;
    hdr[1] = id;
    hdr[2] = ((length + 4) >> 8);
    hdr[3] = (length + 4) & 0xFF;

    if (ssh_buffer_append(buf, hdr, 4) == SSH_BUFFER_OK)
      return true;
    return false;
}

bool
ssh_eap_packet_build_hdr_with_type(SshBuffer buf,
                                   uint8_t code,
                                   uint8_t id,
                                   uint16_t length,
                                   uint8_t type)
{
    uint8_t hdr[5];

    ssh_buffer_clear(buf);

    hdr[0] = code;
    hdr[1] = id;
    hdr[2] = ((length + 5) >> 8);
    hdr[3] = (length + 5) & 0xFF;
    hdr[4] = type;

    if (ssh_buffer_append(buf, hdr, 5) == SSH_BUFFER_OK)
      return true;
    return false;
}
