/**
   @copyright
   Copyright (c) 2004 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   IKEv2 Packet Encode routine.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "ikev2-internal.h"
#include "ikev2-sa-crypto.h"
#include "sshencode.h"

#define SSH_DEBUG_MODULE "SshIkev2PacketEncode"

/* Length of Pad Length field. */
#define IKEV2_PAD_LENGTH_FIELD_LEN  1


/* This function encodes the IKEv2 Header.

                        1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       IKE SA Initiator's SPI                  |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       IKE SA Responder's SPI                  |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Next Payload | MjVer | MnVer | Exchange Type |     Flags     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          Message ID                           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                            Length                             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
static SshIkev2Error
ikev2_encode_header(SshIkev2Packet packet, SshIkev2Message message,
                    SshIkev2PayloadType next_payload, size_t *encoded_len)
{
    size_t natt_len = (packet->use_natt ? IKEV2_NON_ESP_MARKER_LEN : 0);
    unsigned char *message_data = message->data;
    size_t message_len = message->len;

    *encoded_len =
      ssh_encode_array(message_data,
                       message_len,
                       SSH_ENCODE_DATA(
                               (unsigned char *) "\0\0\0\0",
                               (size_t) (natt_len)),
                       SSH_ENCODE_DATA(packet->ike_spi_i, (size_t) 8),
                       SSH_ENCODE_DATA(packet->ike_spi_r, (size_t) 8),
                       SSH_ENCODE_CHAR((unsigned int) next_payload),
                       SSH_ENCODE_CHAR(
                         (unsigned int) ((packet->major_version << 4) |
                                         packet->minor_version)),
                       SSH_ENCODE_CHAR((unsigned int) packet->exchange_type),
                       SSH_ENCODE_CHAR((unsigned int) packet->flags),
                       SSH_ENCODE_UINT32(packet->message_id),
                       SSH_ENCODE_UINT32(message_len - natt_len),
                       SSH_FORMAT_END);

    if ((natt_len + IKEV2_HEADER_LEN) != *encoded_len)
      return SSH_IKEV2_ERROR_OUT_OF_MEMORY;

    return SSH_IKEV2_ERROR_OK;
}

/* This function encodes the header and the packet data
   (from `buffer') to the message field inside `packet'. */
SshIkev2Error
ikev2_encode_packet(SshIkev2Packet packet, SshBuffer buffer)
{
    SshIkev2PayloadType next_payload = packet->first_payload;
    size_t ike_payloads_len = ssh_buffer_len(buffer);
    unsigned char *ike_payloads = ssh_buffer_ptr(buffer);
    size_t natt_len = (packet->use_natt ? IKEV2_NON_ESP_MARKER_LEN : 0);
    SshIkev2Error error = SSH_IKEV2_ERROR_OK;
    SshIkev2Message message;
    size_t message_len;
    size_t encoded_len;

    /* Calculate size and allocate message. */
    message_len = natt_len + IKEV2_HEADER_LEN + ike_payloads_len;

    message = ikev2_message_alloc(NULL, message_len);
    if (message == NULL)
      return SSH_IKEV2_ERROR_OUT_OF_MEMORY;

    /* Encode the header and the packet data. */
    error = ikev2_encode_header(packet, message, next_payload, &encoded_len);
    if (error == SSH_IKEV2_ERROR_OK)
    {
        encoded_len +=
          ssh_encode_array(message->data + encoded_len,
                           message->len - encoded_len,
                           SSH_ENCODE_DATA(ike_payloads, ike_payloads_len),
                           SSH_FORMAT_END);

        if (encoded_len != message_len)
          error = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
    }

    if (error == SSH_IKEV2_ERROR_OK)
    {
        packet->message = message;

        if (ike_payloads != NULL)
        {
            ikev2_list_packet_payloads(packet, ike_payloads, ike_payloads_len,
                                    next_payload, false, true);
        }

        ikev2_debug_packet_out(packet, message);
    }
    else
    {
        ikev2_message_free(&message);
    }

    return error;
}

/* This function encrypts the message. */
static  SshIkev2Error
ikev2_encrypt_message(SshIkev2Packet packet, SshIkev2Message message,
                      size_t unencrypted_len, size_t iv_len, size_t mac_len)
{
    SshIkev2Sa ike_sa = packet->ike_sa;
    unsigned char *message_data = message->data;
    size_t message_len = message->len;
    SshCryptoStatus status;
    unsigned char *nonce;
    size_t nonce_len;

    nonce = (ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR) ?
      ike_sa->sk_ni : ike_sa->sk_nr;
    nonce_len = ike_sa->sk_n_len;

    if (packet->use_natt)
    {
        message_data    += IKEV2_NON_ESP_MARKER_LEN;
        message_len     -= IKEV2_NON_ESP_MARKER_LEN;
        unencrypted_len -= IKEV2_NON_ESP_MARKER_LEN;
    }

    status =
      ikev2_sa_crypto_packet_encrypt(message_data,
                                     message_len - mac_len,
                                     unencrypted_len,
                                     message_data + unencrypted_len + iv_len,
                                     (message_len - unencrypted_len - iv_len -
                                      mac_len),
                                     message_data + unencrypted_len,
                                     iv_len,
                                     message_data + message_len - mac_len,
                                     mac_len,
                                     nonce,
                                     nonce_len,
                                     ike_sa->crypto_context);

    if (status != SSH_CRYPTO_OK)
      return SSH_IKEV2_ERROR_CRYPTO_FAIL;

    return  SSH_IKEV2_ERROR_OK;
}

/* This function calculates the required padding length. */
static size_t
ikev2_get_pad_len(SshIkev2Packet packet, size_t ike_payloads_len)
{
    SshIkev2Sa ike_sa = packet->ike_sa;
    size_t cipher_block_len;
    size_t pad_len;

    /* Add the length of Pad Length field. */
    ike_payloads_len += IKEV2_PAD_LENGTH_FIELD_LEN;

    /* Get the block size. */
    cipher_block_len =
        ikev2_sa_crypto_cipher_block_len(ike_sa->crypto_context);

    SSH_ASSERT(cipher_block_len != 0);

    /* Calculate the padding length. */
    pad_len = cipher_block_len - (ike_payloads_len % cipher_block_len);
    if (pad_len == cipher_block_len)
      pad_len = 0;

    return pad_len;
}

/* This function encodes the encrypted message containing IKEv2 Header
   and Encrypted Payload shown below.

                       1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Next Payload  |C|  RESERVED   |         Payload Length        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     Initialization Vector                     |
   |         (length is block size for encryption algorithm)       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   ~                    Encrypted IKE Payloads                     ~
   +               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |               |             Padding (0-255 octets)            |
   +-+-+-+-+-+-+-+-+                               +-+-+-+-+-+-+-+-+
   |                                               |  Pad Length   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   ~                    Integrity Checksum Data                    ~
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
static SshIkev2Error
ikev2_encode_encrypted_message(SshIkev2Packet packet, SshBuffer buffer,
                               SshIkev2Message *message)
{
    unsigned char temp_buffer[SSH_MAX_HASH_DIGEST_LENGTH] = { 0 };
    SshIkev2Sa ike_sa = packet->ike_sa;
    size_t natt_len = (packet->use_natt ? IKEV2_NON_ESP_MARKER_LEN : 0);
    size_t ike_payloads_len = ssh_buffer_len(buffer);
    unsigned char *ike_payload = ssh_buffer_ptr(buffer);
    size_t encrypted_payload_len;
    size_t unencrypted_len;
    size_t message_len;
    SshIkev2Error error;
    size_t encoded_len;
    size_t mac_len;
    size_t iv_len;
    size_t pad_len;

    /* Lets check that the max IV size is smaller than the max HASH digest
       length, so we can use the digest buffer as a placeholder. */
    SSH_ASSERT(SSH_CIPHER_MAX_IV_SIZE < SSH_MAX_HASH_DIGEST_LENGTH);

    /* Get Initialization Vector, Pad and Integrity Checksum length. */

    iv_len = ikev2_sa_crypto_cipher_iv_len(ike_sa->crypto_context);

    pad_len = ikev2_get_pad_len(packet, ike_payloads_len);

    mac_len = ikev2_sa_crypto_checksum_len(ike_sa->crypto_context);

    /* The final length of the encrypted payload contents will be:
       Generic Payload Header + Initialization Vector + IKE payloads +
       Padding + Pad Length + Integrity Checksum. */
    encrypted_payload_len = (IKEV2_GENERIC_PAYLOAD_HEADER_LEN +
                             iv_len +
                             ike_payloads_len +
                             pad_len +
                             IKEV2_PAD_LENGTH_FIELD_LEN +
                             mac_len);

    /* Allocate the message. */
    message_len = natt_len + IKEV2_HEADER_LEN + encrypted_payload_len;
    *message = ikev2_message_alloc(NULL, message_len);
    if (*message == NULL)
      return SSH_IKEV2_ERROR_OUT_OF_MEMORY;

    /* Encode the IKEv2 Header and the Encrypted Payload. */
    error =
        ikev2_encode_header(
                packet, *message,
                SSH_IKEV2_PAYLOAD_TYPE_ENCRYPTED, &encoded_len);
    if (error == SSH_IKEV2_ERROR_OK)
    {
        encoded_len +=
          ssh_encode_array(
                  (*message)->data + encoded_len,
                  (*message)->len - encoded_len,
                  /* Generic Payload Header. */
                  SSH_ENCODE_CHAR((unsigned int) packet->first_payload),
                  SSH_ENCODE_CHAR((unsigned int) 0),
                  SSH_ENCODE_UINT16((uint16_t) encrypted_payload_len),
                  /* Initialization Vector. */
                  SSH_ENCODE_DATA(temp_buffer, iv_len),
                  /* Encrypted IKE Payloads. */
                  SSH_ENCODE_DATA(ike_payload, ike_payloads_len),
                  /* Padding. */
                  SSH_ENCODE_DATA(temp_buffer, pad_len),
                  /* Pad Length. */
                  SSH_ENCODE_CHAR((unsigned int) pad_len),
                  /* Integrity Checksum Data. */
                  SSH_ENCODE_DATA(temp_buffer, mac_len),
                  SSH_FORMAT_END);

        if (encoded_len != message_len)
        {
            error = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
        }
        else
        {
            ikev2_debug_packet_out(packet, *message);

            /* Don't encrypt Non-ESP Marker, IKEv2 Header and Generic
               Payload Header. */
            unencrypted_len = (natt_len +
                               IKEV2_HEADER_LEN +
                               IKEV2_GENERIC_PAYLOAD_HEADER_LEN);

            error = ikev2_encrypt_message(packet, *message, unencrypted_len,
                                          iv_len, mac_len);
        }
    }

    if (error != SSH_IKEV2_ERROR_OK)
      ikev2_message_free(message);

    return error;
}

static SshIkev2Error
ikev2_make_encrypted_message(SshIkev2Packet packet, SshBuffer buffer)
{
    SshIkev2Message message = NULL;
    SshIkev2Error error;

    error = ikev2_encode_encrypted_message(packet, buffer, &message);
    if (error == SSH_IKEV2_ERROR_OK)
    {
        packet->message = message;
    }

    return error;
}

/* This function encodes the encrypted fragment message containing
   IKEv2 header and Encrypted Fragment Payload show below.

                        1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Next Payload  |C|  RESERVED   |         Payload Length        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |        Fragment Number        |        Total Fragments        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     Initialization Vector                     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   ~                      Encrypted content                        ~
   +               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |               |             Padding (0-255 octets)            |
   +-+-+-+-+-+-+-+-+                               +-+-+-+-+-+-+-+-+
   |                                               |  Pad Length   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   ~                    Integrity Checksum Data                    ~
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
static SshIkev2Error
ikev2_encode_encrypted_fragment_message(SshIkev2Packet packet,
                                        void *fragment_data,
                                        size_t fragment_size,
                                        uint16_t fragment_number,
                                        uint16_t total_fragments,
                                        SshIkev2Message *message)
{
    unsigned char temp_buffer[SSH_MAX_HASH_DIGEST_LENGTH] = { 0 };
    unsigned char *ike_payloads = fragment_data;
    size_t ike_payloads_len = fragment_size;
    size_t natt_len = (packet->use_natt ? IKEV2_NON_ESP_MARKER_LEN : 0);
    SshIkev2Sa ike_sa = packet->ike_sa;
    SshIkev2PayloadType next_payload;
    SshIkev2Error error;
    size_t message_len;
    size_t unencrypted_len;
    size_t encrypted_payload_len;
    size_t encoded_len;
    size_t mac_len;
    size_t iv_len;
    size_t pad_len;
    size_t tmp_len;

    /* Lets check that the max IV size is smaller than the max HASH digest
       length, so we can use the digest buffer as a placeholder. */
    SSH_ASSERT(SSH_CIPHER_MAX_IV_SIZE < SSH_MAX_HASH_DIGEST_LENGTH);

    /* Get MAC, IV and Pad length. */
    mac_len = ikev2_sa_crypto_checksum_len(ike_sa->crypto_context);

    iv_len = ikev2_sa_crypto_cipher_iv_len(ike_sa->crypto_context);

    pad_len = ikev2_get_pad_len(packet, ike_payloads_len);

    /* The final length of the encrypted payload contents will be:
       Generic payload Header + Fragmentation fields + Initialization Vector +
       IKE payloads + Padding + Pad Length + Integrity Checksum. */
    encrypted_payload_len = (IKEV2_GENERIC_PAYLOAD_HEADER_LEN +
                             IKEV2_FRAGMENTATION_FIELDS_LEN +
                             iv_len +
                             ike_payloads_len +
                             pad_len +
                             IKEV2_PAD_LENGTH_FIELD_LEN +
                             mac_len);

    /* Allocate the message. */
    message_len = natt_len + IKEV2_HEADER_LEN + encrypted_payload_len;

    *message = ikev2_message_alloc(NULL, message_len);
    if (*message == NULL)
      return SSH_IKEV2_ERROR_OUT_OF_MEMORY;

    (*message)->fragment_number = fragment_number;
    (*message)->total_fragments = total_fragments;

    /* Encode the IKEv2 header and the Encrypted Fragment Payload. */
    error = ikev2_encode_header(packet, *message,
                                SSH_IKEV2_PAYLOAD_TYPE_ENCRYPTED_FRAGMENT,
                                &encoded_len);
    if (error == SSH_IKEV2_ERROR_OK)
    {
        /* Resolve next payload value. */
        if (fragment_number == 1)
          next_payload = packet->first_payload;
        else
          next_payload = 0;

        tmp_len =
            ssh_encode_array(
                    (*message)->data  + encoded_len,
                    (*message)->len - encoded_len,
                    /* Generic payload header. */
                    SSH_ENCODE_CHAR((unsigned int) next_payload),
                    SSH_ENCODE_CHAR((unsigned int) 0),
                    SSH_ENCODE_UINT16((uint16_t) encrypted_payload_len),
                    /* Fragmentation fields. */
                    SSH_ENCODE_UINT16(fragment_number),
                    SSH_ENCODE_UINT16(total_fragments),
                    /* Initialization Vector. */
                    SSH_ENCODE_DATA(temp_buffer, iv_len),
                    /* Data. */
                    SSH_ENCODE_DATA(ike_payloads, ike_payloads_len),
                    /* Padding. */
                    SSH_ENCODE_DATA(temp_buffer, pad_len),
                    /* Pad length. */
                    SSH_ENCODE_CHAR((unsigned int) pad_len),
                    /* Integrity Checksum. */
                    SSH_ENCODE_DATA(temp_buffer, mac_len),
                    SSH_FORMAT_END);

        if (encoded_len + tmp_len != message_len)
        {
            error = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
        }
        else
        {
            ikev2_debug_packet_out(packet, *message);

            /* Don't encrypt non-ESP marker, IKEv2 header, Generic Payload
               header and Fragmentation fields. */
            unencrypted_len = (natt_len +
                               IKEV2_HEADER_LEN +
                               IKEV2_GENERIC_PAYLOAD_HEADER_LEN +
                               IKEV2_FRAGMENTATION_FIELDS_LEN);

            error = ikev2_encrypt_message(packet, *message, unencrypted_len,
                                          iv_len, mac_len);
        }
    }

    if (error != SSH_IKEV2_ERROR_OK)
      ikev2_message_free(message);

    return error;
}

/* This function generates all encrypted fragment messages and stores
   them to message list inside `packet'. */
static SshIkev2Error
ikev2_make_encrypted_fragments(SshIkev2Packet packet, SshBuffer buffer,
                               size_t encrypt_max)
{
    unsigned char *ike_payloads = ssh_buffer_ptr(buffer);
    size_t ike_payloads_len = ssh_buffer_len(buffer);
    SshIkev2Message message_prev = NULL;
    SshIkev2Message message_new = NULL;
    uint16_t total_fragments;
    uint16_t fragment_number;
    SshIkev2Error error;
    int buffer_offset = 0;

    /* Resolve how many fragments are needed.  */
    total_fragments = (ike_payloads_len + encrypt_max - 1) / encrypt_max;

    /* Encode encrypted fragments. */
    for (fragment_number = 1; fragment_number <= total_fragments;
         fragment_number++)
    {
        int fragment_size = ike_payloads_len - buffer_offset;

        if (fragment_size > encrypt_max)
        {
            fragment_size = encrypt_max;
        }

        error =
            ikev2_encode_encrypted_fragment_message(
                    packet,
                    ike_payloads + buffer_offset,
                    fragment_size,
                    fragment_number,
                    total_fragments,
                    &message_new);

        if (error != SSH_IKEV2_ERROR_OK)
          return error;

        /* Add new message to packet's message list. */
        if (message_prev == NULL)
          packet->message = message_new;
        else
          message_prev->next = message_new;

        message_prev = message_new;
        message_new = NULL;

        buffer_offset += encrypt_max;
    }

    return SSH_IKEV2_ERROR_OK;
}

/* This function checks if message has to be fragmented. */
static bool
ikev2_is_fragmentation_needed(SshIkev2Packet packet, SshBuffer buffer,
                               size_t *encrypt_max)
{
    SshIkev2Sa ike_sa = packet->ike_sa;
    size_t variable_len = 0;
    size_t fixed_len = 0;
    size_t pad_overhead;

    /* By default there is no limitation for encrypted content length. */
    *encrypt_max = 0;

    /* Check if fragmentation enabled. */
    if (ike_sa->ikev2_fragmentation_limit == 0)
      return false;

    /* Calculate length of fixed part for IKEv2 message. */

    /* IP Header. */
    if (SSH_IP_IS4(ike_sa->server->ip_address))
      fixed_len += SSH_IPH4_HDRLEN;
    else
      fixed_len += SSH_IPH6_HDRLEN;

    /* Possible Non-ESP Marker and UDP Header. */
    fixed_len +=
      packet->use_natt ? (IKEV2_NON_ESP_MARKER_LEN + SSH_UDPH_HDRLEN) : 0;

    /* IKEv2 header + Generic Payload Header. */
    fixed_len += IKEV2_HEADER_LEN + IKEV2_GENERIC_PAYLOAD_HEADER_LEN;

    /* Initialization Vector. */
    fixed_len += ikev2_sa_crypto_cipher_iv_len(ike_sa->crypto_context);

    /* Integrity Checksum. */
    fixed_len += ikev2_sa_crypto_checksum_len(ike_sa->crypto_context);

    /* Calculate variable length of the IKEv2 message. */

    /* IKE Payloads length. */
    variable_len = ssh_buffer_len(buffer);

    /* Padding. */
    variable_len += ikev2_get_pad_len(packet, variable_len);

    /* Pad length. */
    variable_len += IKEV2_PAD_LENGTH_FIELD_LEN;

    if ((fixed_len + variable_len) <= ike_sa->ikev2_fragmentation_limit)
    {
        return false;
    }
    else
    {
        /* Encrypted Fragment Payload consumes 4 bytes more than normal
           Encrypted Payload. */
        fixed_len += IKEV2_FRAGMENTATION_FIELDS_LEN;

        /* Maximum encryption length. */
        variable_len =
          ike_sa->ikev2_fragmentation_limit
          - IKEV2_PAD_LENGTH_FIELD_LEN - fixed_len;

        /* Calculate padding overhead against maximum encryption length. */
        pad_overhead =
          ikev2_sa_crypto_cipher_block_len(ike_sa->crypto_context) -
          ikev2_get_pad_len(packet, variable_len);

        /* Decrease maximum encryption length with padding overhead. */
        *encrypt_max = variable_len - pad_overhead;

        return true;
    }
}

/* Encrypt the packet and calculate MAC of it. This will
   also encode the packet to the packet->encoded_packet. */
SshIkev2Error ikev2_encrypt_packet(SshIkev2Packet packet, SshBuffer buffer)
{
    bool fragmentation_needed;
    size_t encrypt_max;
    SshIkev2Error error;

    fragmentation_needed =
      ikev2_is_fragmentation_needed(packet, buffer, &encrypt_max);

    if (fragmentation_needed == false)
    {
        error = ikev2_make_encrypted_message(packet, buffer);
    }
    else
    {
        error = ikev2_make_encrypted_fragments(packet, buffer, encrypt_max);
    }

    if (error == SSH_IKEV2_ERROR_OK)
    {
        ikev2_list_packet_payloads(
                packet,
                ssh_buffer_ptr(buffer),
                ssh_buffer_len(buffer),
                packet->first_payload,
                fragmentation_needed,
                true);

        if (fragmentation_needed == true)
        {
            ikev2_list_packet_fragments(packet);
        }
    }

    return error;
}

unsigned char *
ikev2_get_encoded_packet(SshIkev2Packet packet, size_t *len)
{
    SSH_ASSERT(packet != NULL);

    if (packet->encoded_packet != NULL)
    {
        if (packet->use_natt)
        {
            *len = packet->encoded_packet_len - IKEV2_NON_ESP_MARKER_LEN;
            return packet->encoded_packet + IKEV2_NON_ESP_MARKER_LEN;
        }
        else
        {
            *len = packet->encoded_packet_len;
            return packet->encoded_packet;
        }
    }
    else
    {
        SSH_ASSERT(packet->message != NULL);

        if (packet->use_natt)
        {
            *len = packet->message->len - IKEV2_NON_ESP_MARKER_LEN;
            return packet->message->data + IKEV2_NON_ESP_MARKER_LEN;
        }
        else
        {
            *len = packet->message->len;
            return packet->message->data;
        }
    }
}
