/**
   @copyright
   Copyright (c) 2004 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   IKEv2 Packet Decode routine.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "sshikev2-util.h"
#include "ikev2-internal.h"
#include "ikev2-sa-crypto.h"

#define SSH_DEBUG_MODULE "SshIkev2PacketDecode"


/* This function decodes the header part of the input 'message_data'
   to packet descriptor 'header', and stores copy of 'message_data'
   to 'header->message'. */
SshIkev2Error
ikev2_decode_header(SshIkev2Packet packet,
                    const unsigned char *message_data,
                    size_t message_len)
{
    int len, offset;

    if (packet->use_natt)
    {
        if (message_len < IKEV2_NON_ESP_MARKER_LEN)
        {
            SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("Packet length(%d) < 4",
                                            message_len));
            return SSH_IKEV2_ERROR_INVALID_SYNTAX;
        }
        if (SSH_GET_32BIT(message_data) != 0)
        {
            SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                            ("NAT-T enabled, but first 4 bytes not 0 = %08lx",
                             (unsigned long)
                             SSH_GET_32BIT(message_data)));

            ikev2_audit(packet->ike_sa, SSH_AUDIT_IKE_BAD_PAYLOAD_SYNTAX,
                        "Malformed packet, NAT-T enabled, but first 4 "
                        "bytes not 0");
            return SSH_IKEV2_ERROR_INVALID_SYNTAX;
        }
        offset = IKEV2_NON_ESP_MARKER_LEN;
    }
    else
    {
        offset = 0;
    }

    if (message_len < IKEV2_HEADER_LEN + offset)
    {
        SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("Packet length(%d) < %d",
                                        message_len,
                                        IKEV2_HEADER_LEN + offset));

        ikev2_audit(packet->ike_sa, SSH_AUDIT_IKE_BAD_PAYLOAD_SYNTAX,
                    "Malformed message received, length too short");
        return SSH_IKEV2_ERROR_INVALID_SYNTAX;
    }

    memcpy(packet->ike_spi_i, message_data + offset, 8);
    memcpy(packet->ike_spi_r, message_data + offset + 8, 8);
    packet->first_payload = SSH_GET_8BIT(message_data + offset + 16);
    packet->major_version = SSH_GET_8BIT(message_data + offset + 17) >> 4;
    packet->minor_version = SSH_GET_8BIT(message_data + offset + 17) & 0x0f;
    packet->exchange_type = SSH_GET_8BIT(message_data + offset + 18);
    packet->flags = SSH_GET_8BIT(message_data + offset + 19);
    packet->message_id = SSH_GET_32BIT(message_data + offset + 20);
    len = SSH_GET_32BIT(message_data + offset + 24);

    /* Allow garbage at end of packet for IKEv1, due to Cisco
       implementation sending such packets. IKEv1 library will perform
       proper sanity checks for such packets. */
    if (((packet->major_version == 1)
         && (len + offset > message_len))
        || ((packet->major_version > 1)
            && (len + offset != message_len)))
    {
        SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("Length(%d) + %d != len from udp(%d)",
                                        len, offset, message_len));
        return SSH_IKEV2_ERROR_INVALID_SYNTAX;
    }

    packet->message = ikev2_message_alloc(message_data, message_len);
    if (packet->message == NULL)
    {
        SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("Cannot allocate memory for message",
                                        message_len));
        return SSH_IKEV2_ERROR_INVALID_SYNTAX;
    }

    packet->message->payload_offset = IKEV2_HEADER_LEN + offset;

    packet->encoded_packet = NULL;
    packet->encoded_packet_len = 0;
    return SSH_IKEV2_ERROR_OK;
}

/* Verify fragment. */
SshIkev2Error
ikev2_verify_fragment(SshIkev2Packet packet)
{
    SshIkev2Sa ike_sa = packet->ike_sa;
    SshIkev2Message message = packet->message;
    SshIkev2PayloadType next_payload;
    uint16_t fragment_number;
    uint16_t total_fragments;
    unsigned char *message_data;
    size_t payload_offset;
    size_t message_len;
    size_t payload_len;

    /* Check if this is fragment. */
    if (packet->first_payload == SSH_IKEV2_PAYLOAD_TYPE_ENCRYPTED_FRAGMENT)
    {
        packet->fragment = 1;
        packet->encrypted = 1;
    }
    else if (packet->first_payload == SSH_IKEV2_PAYLOAD_TYPE_ENCRYPTED)
    {
        packet->fragment = 0;
        packet->encrypted = 1;
    }
    else
    {
        packet->fragment = 0;
        packet->encrypted = 0;
    }

    if (packet->fragment == 1)
    {
        /* Check if fragmentation enabled. */
        if (ike_sa->ikev2_fragmentation_limit == 0)
        {
            SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                            ("Fragment received but fragmentation not "
                             "negotiated for this IKE SA"));
            return SSH_IKEV2_ERROR_DISCARD_PACKET;
        }

        message_data = message->data;
        message_len = message->len;
        payload_offset = message->payload_offset;

        /* Check the length. */
        if (message_len <
            (payload_offset + IKEV2_GENERIC_PAYLOAD_HEADER_LEN +
             IKEV2_FRAGMENTATION_FIELDS_LEN))
        {
            SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                            ("Message length(%d) < payload_offset (%d) + %d",
                             message_len,
                             payload_offset,
                             (IKEV2_GENERIC_PAYLOAD_HEADER_LEN +
                              IKEV2_FRAGMENTATION_FIELDS_LEN)));

            return SSH_IKEV2_ERROR_DISCARD_PACKET;
        }

        /* Get the next payload type. */
        next_payload = SSH_GET_8BIT(message_data + payload_offset);

        /* Check the packet length, this must be last payload and
           consume everything up to the end of packet. */
        payload_len = SSH_GET_16BIT(message_data + payload_offset + 2);
        if (payload_len != message_len - payload_offset)
        {
            SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                            ("Encr payload len(%d) != packet_len(%d) - "
                             "payload_offset(%d)",
                             payload_len,
                             message_len,
                             payload_offset));

            return SSH_IKEV2_ERROR_DISCARD_PACKET;
        }

        /* Skip the generic encryption payload header. */
        payload_offset += IKEV2_GENERIC_PAYLOAD_HEADER_LEN;

        fragment_number = SSH_GET_16BIT(message_data + payload_offset);
        total_fragments = SSH_GET_16BIT(message_data + payload_offset + 2);

        if ((fragment_number == 0) || (total_fragments == 0) ||
            (fragment_number > total_fragments))
        {
            SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                            ("Fragment fields are not valid, "
                             "fragment number (%d) total fragments (%d)",
                             fragment_number,
                             total_fragments));

            return SSH_IKEV2_ERROR_DISCARD_PACKET;
        }

        if (total_fragments > SSH_IKEV2_MAX_FRAGMENTS)
        {
            SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                            ("Maximum number of IKEv2 fragments (%d) "
                             "exceeded in packet: %d",
                             SSH_IKEV2_MAX_FRAGMENTS,
                             total_fragments));

            return SSH_IKEV2_ERROR_DISCARD_PACKET;
        }

        /* Sanity check Next Payload field */
        if (((fragment_number == 1) &&
             (next_payload == SSH_IKEV2_PAYLOAD_TYPE_NONE)) ||
            ((fragment_number > 1) &&
             (next_payload != SSH_IKEV2_PAYLOAD_TYPE_NONE)))
        {
            SSH_IKEV2_DEBUG(
                    SSH_D_NETGARB,
                    ("Invalid Next Payload type for fragment number "
                     "(%d): %s",
                     fragment_number,
                     ssh_ikev2_packet_payload_to_string(next_payload)));

            return SSH_IKEV2_ERROR_DISCARD_PACKET;
        }

        /* Skip the fragmentation fields. */
        payload_offset += IKEV2_FRAGMENTATION_FIELDS_LEN;

        message->payload_offset = payload_offset;

        message->next_payload = next_payload;
        message->fragment_number = fragment_number;
        message->total_fragments = total_fragments;
    }

    return SSH_IKEV2_ERROR_OK;
}

/* Decrypt the encrypted message. This function will "remove" the
   Padding, Pad Length and Integrity Checksum Data by modifying
   message->len and it also "removes" Initialization Vector by
   modifying message->payload_offset.

                          1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   ~                                                               ~
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
ikev2_decrypt_message(SshIkev2Packet packet, SshIkev2Message message)
{
    SshIkev2Sa ike_sa = packet->ike_sa;
    SshCryptoStatus crypto_status;
    size_t mac_len, iv_len, len;
    unsigned char *message_data = message->data;
    size_t message_len =  message->len;
    size_t payload_offset = message->payload_offset;
    size_t natt_offset;

    /* Checksum length. */
    mac_len = ikev2_sa_crypto_checksum_len(ike_sa->crypto_context);

    if (mac_len > message_len - payload_offset)
    {
        SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                        ("mac len(%zd) > payload len(%zd)",
                         mac_len,
                         message_len - payload_offset));

        ikev2_audit(ike_sa, SSH_AUDIT_IKE_BAD_PAYLOAD_SYNTAX,
                    "Malformed packet, length inconsistent with that "
                    "indicated in header");
        return SSH_IKEV2_ERROR_DISCARD_PACKET;
    }

    /* Remove Integrity Checksum. */
    message_len -= mac_len;

    ikev2_debug_packet_in(packet, message);

    /* Decrypt packet */
    iv_len = ikev2_sa_crypto_cipher_iv_len(ike_sa->crypto_context);
    payload_offset += iv_len;

    if (packet->use_natt)
      natt_offset = IKEV2_NON_ESP_MARKER_LEN;
    else
      natt_offset = 0;

    crypto_status =
      ikev2_sa_crypto_packet_decrypt(message_data + natt_offset,
                                     message_len - natt_offset,
                                     payload_offset - iv_len - natt_offset,
                                     message_data + payload_offset,
                                     message_len - payload_offset,
                                     message_data + payload_offset - iv_len,
                                     iv_len,
                                     message_data + message_len,
                                     mac_len,
                                     !(ike_sa->flags &
                                       SSH_IKEV2_IKE_SA_FLAGS_INITIATOR) ?
                                     ike_sa->sk_ni : ike_sa->sk_nr,
                                     ike_sa->sk_n_len,
                                     ike_sa->crypto_context);

    if (crypto_status == SSH_CRYPTO_SIGNATURE_CHECK_FAILED)
    {
        ikev2_audit(ike_sa,
                    SSH_AUDIT_IKE_INVALID_HASH_VALUE,
                    "Packet checksum comparison failed");
        return SSH_IKEV2_ERROR_DISCARD_PACKET;
    }
    else if (crypto_status != SSH_CRYPTO_OK)
    {
        SSH_DEBUG(SSH_D_FAIL, ("IKEv2 packet decrypt failed"));
        return SSH_IKEV2_ERROR_CRYPTO_FAIL;
    }


    SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP,
                      ("Packet after decryption"),
                      message_data, message_len);
    /* Check padding. */
    len = SSH_GET_8BIT(message_data + message_len - 1);
    if (len + 1 > message_len - payload_offset)
    {
        SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                        ("padding len(%d) > payload len(%d)",
                         len + 1,
                         message_len - payload_offset));

        ikev2_audit(ike_sa, SSH_AUDIT_IKE_BAD_PAYLOAD_SYNTAX,
                    "Malformed packet, invalid padding");

        return SSH_IKEV2_ERROR_INVALID_SYNTAX;
    }
    SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP,
                      ("Padding of %d bytes", len),
                      message_data +
                      message_len - len - 1, len);

    /* Remove Padding and Pad Length. */
    message_len -= len + 1;

    /* Update length in message struct and set payload offset. */
    message->len = message_len;
    message->payload_offset = payload_offset;

    if (packet->ed != NULL)
    {
        /** Packet authenticated so peer is still alive. */
        packet->ed->peer_alive = 1;
    }

    return SSH_IKEV2_ERROR_OK;
}

/* Decode the encrypted message, i.e check the mac and decrypt
   the message. This will modify the message->len, and set the
   message->payload_offset. The payload_offset must have the
   length of headers before the encrypted packet when this is
   called, and it will be incremented to include the headers to be
   skipped from the encrypted payload. The syntax of Encrypted Payload
   is shown below. Please note that this function only decodes the
   Generic Payload Header and rest of the decoding is done in
   ikev2_decrypt_message() function.

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
ikev2_decode_encr(SshIkev2Packet packet, SshIkev2Message message)
{
    unsigned char *message_data = message->data;
    size_t message_len =  message->len;
    size_t payload_offset = message->payload_offset;
    SshIkev2Error error;
    size_t len;

    /* Check the length. */
    if (message_len < (payload_offset + IKEV2_GENERIC_PAYLOAD_HEADER_LEN))
    {
        SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                        ("Message length(%d) < payload_offset (%d) + %d",
                         message_len,
                         payload_offset,
                         IKEV2_GENERIC_PAYLOAD_HEADER_LEN));

        ikev2_audit(packet->ike_sa, SSH_AUDIT_IKE_BAD_PAYLOAD_SYNTAX,
                    "Malformed message, length inconsistent with that "
                    "indicated in header");

        return SSH_IKEV2_ERROR_DISCARD_PACKET;
    }

    /* Get the payload type. */
    packet->first_payload = SSH_GET_8BIT(message_data + payload_offset);

    /* Check the packet length, this must be last payload and
       consume everything up to the end of packet. */
    len = SSH_GET_16BIT(message_data + payload_offset + 2);
    if (len != message_len - payload_offset)
    {
        SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                        ("Encr payload len(%d) != packet_len(%d) - "
                         "payload_offset(%d)",
                         len,
                         message_len,
                         payload_offset));

        ikev2_audit(packet->ike_sa, SSH_AUDIT_IKE_BAD_PAYLOAD_SYNTAX,
                    "Malformed packet, length inconsistent with that "
                    "indicated in header");

        return SSH_IKEV2_ERROR_DISCARD_PACKET;
    }


    /* Skip the generic encryption payload header. */
    message->payload_offset += IKEV2_GENERIC_PAYLOAD_HEADER_LEN;

    error = ikev2_decrypt_message(packet, message);
    if (error == SSH_IKEV2_ERROR_OK)
      SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Packet decrypted successfully"));

    return error;
}

/* This function decodes the encrypted fragment. Please note that
   Generic Payload Header and fragmentation fields are already decoded
   in ikev2_verify_fragment() function and rest of the decoding is
   done in ikev2_decrypt_message() function.

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
ikev2_decode_encrypted_fragment(SshIkev2Packet packet, SshIkev2Message message)
{
    SshIkev2Error error;

    /* Check that this is fragment. This flag is set in ikev2_verify_fragment()
       function which also decodes Generic Payload Header and fragmentation
       fields. */
    SSH_ASSERT(packet->fragment == 1);

    SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                    ("Decrypt encrypted fragment, "
                     "next payload (%d) fragment number (%u) "
                     "total fragments (%u)",
                     message->next_payload,
                     message->fragment_number,
                     message->total_fragments));

    error = ikev2_decrypt_message(packet, message);
    if (error == SSH_IKEV2_ERROR_OK)
      SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Fragment decrypted successfully"));

    ikev2_log_packet_fragment(packet, message, false);

    return error;
}

/** Check if packet decoding can be started. */
SshFSMStepStatus
ikev2_pre_decode_packet(SshIkev2Packet packet, bool *start_decode)
{
    SshIkev2Sa ike_sa = packet->ike_sa;
    SshIkev2Message message = packet->message;
    SshIkev2Error err;
    size_t len, payload_len;
    SshIkev2PayloadType curr_payload, next_payload;
    unsigned char *payload;

    SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Pre-decoding packet"));

    /* By default deny packet decoding. */
    *start_decode = false;

    /* First check if we have the encrypted payload, and if so
       we need to have the diffie-helman finished. */
    if (packet->first_payload == SSH_IKEV2_PAYLOAD_TYPE_ENCRYPTED)
    {
        SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Encrypted packet"));

        /* Check if there was error in the async operation, or if this
           is an encrypted packet without D-H having been done (e.g
           packet without initial exchange having been done).  */
        SSH_ASSERT(ike_sa->sk_d_len != 0);

        err = ikev2_decode_encr(packet, message);
        if (err != SSH_IKEV2_ERROR_OK)
          return ikev2_error(packet, err);

        /* Check IKE major version. Delete IKE SA if major version is not 2.*/
        if (packet->major_version != 2)
        {
            SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("Major version number(%d) != 2",
                                            packet->major_version));

            ikev2_audit(ike_sa, SSH_AUDIT_IKE_INVALID_VERSION,
                        "Invalid major version number");

            /* Send SSH_IKEV2_NOTIFY_INVALID_MAJOR_VERSION. */
            return ikev2_error(packet, SSH_IKEV2_ERROR_INVALID_MAJOR_VERSION);
        }
    }
    else if (packet->first_payload ==
             SSH_IKEV2_PAYLOAD_TYPE_ENCRYPTED_FRAGMENT)
    {
        SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Encrypted fragment packet"));

        /* Check if there was error in the async operation, or if this
           is an encrypted packet without D-H having been done (e.g
           packet without initial exchange having been done).  */
        SSH_ASSERT(ike_sa->sk_d_len != 0);

        err = ikev2_decode_encrypted_fragment(packet, message);
        if (err != SSH_IKEV2_ERROR_OK)
          return ikev2_error(packet, err);

        /* Check IKE major version. Delete IKE SA if major version is not 2.*/
        if (packet->major_version != 2)
        {
            SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("Major version number(%d) != 2",
                                            packet->major_version));

            ikev2_audit(ike_sa, SSH_AUDIT_IKE_INVALID_VERSION,
                        "Invalid major version number");

            /* Send SSH_IKEV2_NOTIFY_INVALID_MAJOR_VERSION. */
            return ikev2_error(packet, SSH_IKEV2_ERROR_INVALID_MAJOR_VERSION);
        }
    }
    else if (packet->exchange_type != SSH_IKEV2_EXCH_TYPE_IKE_SA_INIT)
    {
        /* All packets after IKE_SA_INIT should be encrypted. If not, then
           we may display the notify payloads within the packet to the policy
           manager and discard the packet. We only display notifies to the
           policy manager when the exchange state is IKE_AUTH, in this state
           the notifies may be useful as an aid for diagnosing IKE negotiation
           failures. */
        SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                        ("Plain text packet which is not IKE_SA_INIT"));
        if (ike_sa->initial_ed == NULL ||
            packet->exchange_type != SSH_IKEV2_EXCH_TYPE_IKE_AUTH)
          return SSH_FSM_FINISH;

        SSH_IKEV2_DEBUG(SSH_D_MIDOK,
                        ("Plain text packet at IKE_SA_AUTH state "
                         "displayed to the application"));

        /* Use the exchange data from the initial_ed unless proper one
           available. */
        if (packet->ed == NULL)
        {
            ikev2_reference_exchange_data(ike_sa->initial_ed);
            packet->ed = ike_sa->initial_ed;
        }

        /* Extract any notify payloads and display them to the policy
           manager */
        curr_payload = packet->first_payload;
        payload = message->data + message->payload_offset;
        len = message->len - message->payload_offset;

        while (curr_payload != 0)
        {
            if (len < 4)
              return SSH_FSM_FINISH;

            next_payload = SSH_GET_8BIT(payload);
            payload_len = SSH_GET_16BIT(payload + 2);

            if (payload_len < 4)
            {
                SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                                ("Short packet payload_len(%d) < 4",
                                 payload_len));

                ikev2_audit(ike_sa,
                            SSH_AUDIT_IKE_BAD_PAYLOAD_SYNTAX,
                            "Malformed payload, less than 4 bytes");
                return SSH_FSM_FINISH;
            }

            if (len < payload_len)
            {
                SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                                ("Short packet left(%d) < payload_len(%d)",
                                 len, payload_len));

                ikev2_audit(ike_sa,
                            SSH_AUDIT_IKE_BAD_PAYLOAD_SYNTAX,
                            "Malformed payload, greater than packet size");
                return SSH_FSM_FINISH;
            }

            SSH_DEBUG_HEXDUMP(110, ("Payload of type %d", curr_payload),
                              payload, payload_len);

            payload += 4;
            payload_len -= 4;
            len -= 4;

            switch (curr_payload)
            {
              case SSH_IKEV2_PAYLOAD_TYPE_NOTIFY:
                err = ikev2_decode_notify(packet, false, payload, payload_len);
                break;
              default:
                err = SSH_IKEV2_ERROR_OK;
                break;
            }
            if (err == SSH_IKEV2_ERROR_INVALID_SYNTAX)
            {
                ikev2_audit(ike_sa,
                            SSH_AUDIT_IKE_BAD_PAYLOAD_SYNTAX,
                            "Malformed payload received");
            }
            if (err != SSH_IKEV2_ERROR_OK)
              return SSH_FSM_FINISH;

            /* Get next payload. */
            curr_payload = next_payload;
            payload += payload_len;
            len -= payload_len;
        }
        return SSH_FSM_FINISH;
    }
    else if (packet->message_id != 0)
    {
        /* All IKE_SA_INIT must have message id 0. */
        SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                        ("IKE_SA_INIT packet with message id > 0"));
        SSH_ASSERT(packet->exchange_type == SSH_IKEV2_EXCH_TYPE_IKE_SA_INIT);

        ikev2_audit(ike_sa, SSH_AUDIT_IKE_BAD_PAYLOAD_SYNTAX,
                    "IKE_SA_INIT packet with message id larger than zero");

        return ikev2_error(packet, SSH_IKEV2_ERROR_DISCARD_PACKET);
    }
    else if (ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_IKE_SA_DONE)
    {
        /* As this must be first packet the IKE SA cannot be
           done yet. */
        SSH_IKEV2_DEBUG(
                SSH_D_NETGARB,
                ("IKE_SA_INIT with message id to already existing SA"));

        ikev2_audit(ike_sa, SSH_AUDIT_IKE_BAD_PAYLOAD_SYNTAX,
                    "IKE_SA_INIT with message id to already existing SA");

        SSH_ASSERT(packet->exchange_type == SSH_IKEV2_EXCH_TYPE_IKE_SA_INIT);
        return ikev2_error(packet, SSH_IKEV2_ERROR_DISCARD_PACKET);
    }

    /* Accept packet decoding. */
    *start_decode = true;

    return SSH_FSM_CONTINUE;
}

static size_t
ikev2_copy_fragment_data(SshIkev2Message fragment,
                         unsigned char *payload,
                         size_t offset)
{
    size_t len = fragment->len - fragment->payload_offset;

    memcpy(payload + offset, fragment->data + fragment->payload_offset, len);

    return len;
}

/* Reassemble queued fragments. */
bool
ikev2_reassemble_packet(SshIkev2Packet packet)
{
    SshIkev2PayloadType next_payload = SSH_IKEV2_PAYLOAD_TYPE_NONE;
    SshIkev2Message fragment;
    unsigned char *payload;
    uint16_t number;
    size_t len = 0;

    /* Calculate payload length. */
    for (fragment = packet->fragments_head;
         fragment != NULL;
         fragment = fragment->next)
    {
        len += fragment->len;
    }

    /* Allocate memory for IKE payload and reassemble it. */
    payload = ssh_malloc(len);
    if (payload == NULL)
    {
        return false;
    }

    len = 0;
    number = 1;

    for (fragment = packet->fragments_head;
         fragment != NULL;
         fragment = fragment->next)
    {
        len += ikev2_copy_fragment_data(fragment, payload, len);
        if (number == 1)
        {
            next_payload = fragment->next_payload;
        }

        number++;
    }

    packet->first_payload = next_payload;
    packet->encoded_packet = payload;
    packet->encoded_packet_len = len;
    packet->encoded_payload_offset = 0;

    return true;
}

/** Set encoded packet. */
SshFSMStepStatus
ikev2_set_encoded_packet(SshIkev2Packet packet)
{
    SshIkev2Message message = packet->message;

    SSH_ASSERT(message != NULL);
    SSH_ASSERT(packet->fragment == 0);

    packet->encoded_packet = ssh_malloc(message->len);
    if (packet->encoded_packet == NULL)
    {
        return SSH_FSM_FINISH;
    }

    memcpy(packet->encoded_packet, message->data, message->len);

    packet->encoded_packet_len = message->len;
    packet->encoded_payload_offset = message->payload_offset;

    return SSH_FSM_CONTINUE;
}

/* Decode the whole packet, i.e call the various decode
   payload functions to decode payloads. */
SshFSMStepStatus
ikev2_decode_packet(SshIkev2Packet packet)
{
    SshIkev2Sa ike_sa = packet->ike_sa;
    SshIkev2Error err;
    size_t len, payload_len;
    SshIkev2PayloadType curr_payload, next_payload;
    unsigned char *payload;

    SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Decoding packet"));

    curr_payload = packet->first_payload;
    payload = packet->encoded_packet + packet->encoded_payload_offset;
    len = packet->encoded_packet_len - packet->encoded_payload_offset;

    ikev2_list_packet_payloads(packet,
                               payload,
                               len,
                               curr_payload,
                               packet->fragment == 1 ? true : false,
                               false);

    if (packet->ed == NULL)
    {
        SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("No old context"));
        /* This is new exchange, as we do not have previous context. */
        if (packet->flags & SSH_IKEV2_PACKET_FLAG_RESPONSE)
        {
            /* This was response, but we do not know the
               context, so ignore the packet. */
            SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("No old context, and this is "
                                            "response, must be garbage"));
            return SSH_FSM_FINISH;
        }

        /* First see if we are doing initial exchange now. */
        if (ike_sa->initial_ed != NULL)
        {
            /* Yes, so this packet must be part of that
               exchange, and the exchange type must be IKE_AUTH.

               The RFC5996 states that CREATE_CHILD or INFORMATIONAL
               exchanges cannot be started before the initial exchange
               completes. If this end is the initiator and the IKE_AUTH
               response is lost, then the responder thinks that the
               initial exchange is completed and may start new
               CREATE_CHILD or INFORMATIONAL exchanges. In such case
               this end drops the request packets of this new exchange
               until it has received the IKE_AUTH response and
               successfully completed the initial exchange. */
            if (packet->exchange_type != SSH_IKEV2_EXCH_TYPE_IKE_AUTH)
            {
                SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("Exchange type != IKE_AUTH"));
                return SSH_FSM_FINISH;
            }

            /* Use the exchange data from the initial_ed. */
            ikev2_reference_exchange_data(ike_sa->initial_ed);
            packet->ed = ike_sa->initial_ed;

            /* Allocate IPsec SA if we are creating child SA. */
            err = ikev2_allocate_exchange_data_ipsec(packet->ed);
            if (err != SSH_IKEV2_ERROR_OK)
              return ikev2_error(packet, err);
        }
        else
        {
            /* Allocate new exchange_data now. */
            packet->ed = ikev2_allocate_exchange_data(ike_sa);
            if (packet->ed == NULL)
              return ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);
            packet->ed->ike_sa = ike_sa;

            switch (packet->exchange_type)
            {
              case SSH_IKEV2_EXCH_TYPE_IKE_SA_INIT:
                /* Allocate IKE SA exchange data for IKE_SA_INIT. */
                /* Do we already have the IKE SA ready? If so
                   ignore this. */
                if (ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_IKE_SA_DONE)
                {
                    SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                                    ("IKE_SA_INIT packet to finished IKE SA"));
                    ikev2_free_exchange_data(ike_sa, packet->ed);
                    packet->ed = NULL;
                    return SSH_FSM_FINISH;
                }
                SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Starting new exchange"));

                /* Nope, so allocate new IKE SA exchange data. */
                err = ikev2_allocate_exchange_data_ike(packet->ed);
                if (err != SSH_IKEV2_ERROR_OK)
                  return ikev2_error(packet, err);

                /* Store it to the initial_ed. */
                ikev2_reference_exchange_data(packet->ed);
                ike_sa->initial_ed = packet->ed;
                break;

              case SSH_IKEV2_EXCH_TYPE_IKE_AUTH:
                /* This cannot be IKE_AUTH, as we should have had
                   the initial_ed then. */
                SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("First packet was IKE_AUTH"));
                ikev2_free_exchange_data(ike_sa, packet->ed);
                packet->ed = NULL;
                return SSH_FSM_FINISH;

              case SSH_IKEV2_EXCH_TYPE_CREATE_CHILD_SA:
                /* Allocate IPsec SA if we are creating child SA. */
                err = ikev2_allocate_exchange_data_ipsec(packet->ed);
                if (err != SSH_IKEV2_ERROR_OK)
                  return ikev2_error(packet, err);
                break;

              case SSH_IKEV2_EXCH_TYPE_INFORMATIONAL:
                /* Allocate Info exchange */
                err = ikev2_allocate_exchange_data_info(packet->ed);
                if (err != SSH_IKEV2_ERROR_OK)
                  return ikev2_error(packet, err);

                break;

              default:
                /* Unknown exchange type. */
                SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("Unknown exchange type %d",
                                                packet->exchange_type));

                ikev2_audit(packet->ike_sa,
                            SSH_AUDIT_IKE_BAD_PAYLOAD_SYNTAX,
                            "Unknown exchange type in payload");

                ikev2_free_exchange_data(ike_sa, packet->ed);
                packet->ed = NULL;
                return SSH_FSM_FINISH;
            }
        }
    }
    else
    {
        /* Ok, we had the context from previous run. */
        SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("We have old context"));
        /* Check if we need to allocate IPsec SA context. */
        if (ike_sa->initial_ed != NULL &&
            packet->exchange_type == SSH_IKEV2_EXCH_TYPE_IKE_AUTH)
        {
            /* Allocate IPsec SA if we are creating IPsec. */
            err = ikev2_allocate_exchange_data_ipsec(packet->ed);
            if (err != SSH_IKEV2_ERROR_OK)
              return ikev2_error(packet, err);
        }
    }
    packet->ed->notify_count = 0;

#ifdef SSHDIST_IKE_MOBIKE
    *(packet->ed->remote_ip) = *(packet->remote_ip);
    packet->ed->remote_port = packet->remote_port;
    packet->ed->server = packet->server;
#endif /* SSHDIST_IKE_MOBIKE */

    /* Check if IKE SA is done and 1) port float is done and other end
       is behind NAT or 2) IKE SA is using TCP encapsulation, and the
       source ip or port has changed. */
    if ((ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_IKE_SA_DONE) &&
        (((ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_NAT_T_FLOAT_DONE) &&
          (ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_OTHER_END_BEHIND_NAT) &&
#ifdef SSHDIST_IKE_MOBIKE
          /* RFC 4555 IKEv2 packets MUST NOT cause dynamic updates of IPsec
             SA's */
          (!(ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_MOBIKE_ENABLED)) &&
#endif /* SSHDIST_IKE_MOBIKE */
          packet->use_natt)
         || (ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_TCPENCAP))
        && (ike_sa->remote_port != packet->remote_port ||
            SSH_IP_CMP(ike_sa->remote_ip, packet->remote_ip) != 0))
    {
        /* OK, added to the ike_state_decode. */
        SSH_IKEV2_POLICY_NOTIFY(ike_sa, ipsec_sa_update)
          (ike_sa->server->sad_handle, packet->ed,
           packet->remote_ip, packet->remote_port);
    }

    ikev2_debug_decode_start(packet);

    while (curr_payload != 0)
    {
        int reserved_byte;

        if (len < 4)
        {
            SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("Too short packet len(%d)", len));

            ikev2_audit(ike_sa, SSH_AUDIT_IKE_BAD_PAYLOAD_SYNTAX,
                        "Too short packet length");

            return ikev2_error(packet, SSH_IKEV2_ERROR_INVALID_SYNTAX);
        }

        next_payload = SSH_GET_8BIT(payload);
        reserved_byte = SSH_GET_8BIT(payload + 1);
        payload_len = SSH_GET_16BIT(payload + 2);

        if (payload_len < 4)
        {
            SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                            ("Short packet payload_len(%d) < 4",
                             payload_len));

            ikev2_audit(ike_sa, SSH_AUDIT_IKE_BAD_PAYLOAD_SYNTAX,
                        "Too short payload length");

            return ikev2_error(packet, SSH_IKEV2_ERROR_INVALID_SYNTAX);
        }

        if (len < payload_len)
        {
            SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                            ("Short packet left(%d) < payload_len(%d)",
                             len, payload_len));

            ikev2_audit(ike_sa, SSH_AUDIT_IKE_BAD_PAYLOAD_SYNTAX,
                        "Too short packet length, less than indicated "
                        "by payload length");

            return ikev2_error(packet, SSH_IKEV2_ERROR_INVALID_SYNTAX);
        }
        SSH_DEBUG_HEXDUMP(110,
                          ("Payload of type %d", curr_payload),
                          payload, payload_len);

        payload += 4;
        payload_len -= 4;
        len -= 4;
        switch (curr_payload)
        {
          case SSH_IKEV2_PAYLOAD_TYPE_SA:
            err = ikev2_decode_sa(packet, payload, payload_len);
            break;
          case SSH_IKEV2_PAYLOAD_TYPE_KE:
            err = ikev2_decode_ke(packet, payload, payload_len);
            break;
          case SSH_IKEV2_PAYLOAD_TYPE_ID_I:
            err = ikev2_decode_idi(packet, payload, payload_len);
            break;
          case SSH_IKEV2_PAYLOAD_TYPE_ID_R:
            err = ikev2_decode_idr(packet, payload, payload_len);
            break;
          case SSH_IKEV2_PAYLOAD_TYPE_CERT:
            err = ikev2_decode_cert(packet, payload, payload_len);
            break;
          case SSH_IKEV2_PAYLOAD_TYPE_CERT_REQ:
            err = ikev2_decode_certreq(packet, payload, payload_len);
            break;
          case SSH_IKEV2_PAYLOAD_TYPE_AUTH:
            err = ikev2_decode_auth(packet, payload, payload_len);
            break;
          case SSH_IKEV2_PAYLOAD_TYPE_NONCE:
            err = ikev2_decode_nonce(packet, payload, payload_len);
            break;
          case SSH_IKEV2_PAYLOAD_TYPE_NOTIFY:
            err = ikev2_decode_notify(packet,
                                      (ike_sa->flags &
                                       SSH_IKEV2_IKE_SA_FLAGS_IKE_SA_DONE),
                                      payload, payload_len);
            break;
          case SSH_IKEV2_PAYLOAD_TYPE_DELETE:
            err = ikev2_decode_delete(packet, payload, payload_len);
            break;
          case SSH_IKEV2_PAYLOAD_TYPE_VID:
            err = ikev2_decode_vendor_id(packet, payload, payload_len);
            break;
          case SSH_IKEV2_PAYLOAD_TYPE_TS_I:
            err = ikev2_decode_tsi(packet, payload, payload_len);
            break;
          case SSH_IKEV2_PAYLOAD_TYPE_TS_R:
            err = ikev2_decode_tsr(packet, payload, payload_len);
            break;
          case SSH_IKEV2_PAYLOAD_TYPE_ENCRYPTED:
            err = SSH_IKEV2_ERROR_INVALID_SYNTAX;
            break;
          case SSH_IKEV2_PAYLOAD_TYPE_CONF:
            err = ikev2_decode_conf(packet, payload, payload_len);
            break;
          case SSH_IKEV2_PAYLOAD_TYPE_EAP:
            err = ikev2_decode_eap(packet, payload, payload_len);
            break;
          default:
            /* Check for critical bit. */
            if (reserved_byte & 0x80)
            {
                err = SSH_IKEV2_ERROR_UNSUPPORTED_CRITICAL_PAYLOAD;
                SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP,
                                  ("Unsupported critical payload of type %d",
                                   curr_payload),
                                  payload, payload_len);

                ikev2_audit(packet->ike_sa,
                            SSH_AUDIT_IKE_UNSUPPORTED_CRITICAL_PAYLOAD,
                            "Unsupported critical payload in packet");
            }
            else
            {
                /* Just ignore. */
                SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP,
                                  ("Unsupported payload of type %d",
                                   curr_payload),
                                  payload, payload_len);
                err = SSH_IKEV2_ERROR_OK;
            }
            break;
        }

        if (err == SSH_IKEV2_ERROR_INVALID_SYNTAX)
        {
            ikev2_audit(packet->ike_sa,
                        SSH_AUDIT_IKE_BAD_PAYLOAD_SYNTAX,
                        "Malformed payload received");
        }

        if (err != SSH_IKEV2_ERROR_OK)
          return ikev2_error(packet, err);

        /* Get next payload. */
        curr_payload = next_payload;
        payload += payload_len;
        len -= payload_len;
    }
    if (len != 0)
    {
        SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                        ("Extra junk after packet len(%d)", len));

        ikev2_audit(ike_sa, SSH_AUDIT_IKE_BAD_PAYLOAD_SYNTAX,
                    "Extra junk after packet");
        return ikev2_error(packet, SSH_IKEV2_ERROR_INVALID_SYNTAX);
    }

    if (packet->message_id == 0
        && !(packet->flags & SSH_IKEV2_PACKET_FLAG_INITIATOR)
        && (packet->flags & SSH_IKEV2_PACKET_FLAG_RESPONSE)
        && (packet->exchange_type == SSH_IKEV2_EXCH_TYPE_IKE_SA_INIT)
        && (packet->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR)
        && (packet->ike_sa->initial_ed != NULL)
        && (packet->ike_sa->initial_ed->state == SSH_IKEV2_STATE_IKE_INIT_SA))
    {
        if (memcmp(packet->ike_sa->ike_spi_r, "\0\0\0\0\0\0\0\0", 8) != 0)
        {
            SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                            ("IKE SA %p has already responder IKE SPI set",
                             packet->ike_sa));
            ikev2_audit(ike_sa, SSH_AUDIT_IKE_BAD_PAYLOAD_SYNTAX,
                        "IKE_SA_INIT response packet with zero responder SPI");
            return SSH_FSM_FINISH;
        }

        /* Assert that initiator IKE SPI in packet matches the IKE SA.
           IKE SA lookup should not have succeeded otherwise. */
        SSH_ASSERT(memcmp(packet->ike_sa->ike_spi_i, packet->ike_spi_i,
                          sizeof(packet->ike_spi_i)) == 0);

        /* Copy responder IKE SPI to IKE SA if packet specifies it. */
        if (memcmp(packet->ike_spi_r, "\0\0\0\0\0\0\0\0", 8) != 0)
        {
            SSH_IKEV2_DEBUG(SSH_D_MIDOK,
                            ("Updating responder IKE SPI to IKE SA %p "
                             "I %08lx %08lx R %08lx %08lx ",
                             packet->ike_sa,
                             SSH_GET_32BIT(packet->ike_sa->ike_spi_i),
                             SSH_GET_32BIT(packet->ike_sa->ike_spi_i + 4),
                             SSH_GET_32BIT(packet->ike_spi_r),
                             SSH_GET_32BIT(packet->ike_spi_r + 4)));
            memcpy(packet->ike_sa->ike_spi_r, packet->ike_spi_r,
                   sizeof(packet->ike_spi_r));
        }
    }
    else
    {
        /* Assert that IKE SPIs in packet matches the IKE SA.
           IKE SA lookup should not have succeeded otherwise. */
        SSH_ASSERT(memcmp(packet->ike_sa->ike_spi_i, packet->ike_spi_i,
                          sizeof(packet->ike_spi_i)) == 0);
        SSH_ASSERT(memcmp(packet->ike_sa->ike_spi_r, packet->ike_spi_r,
                          sizeof(packet->ike_spi_r)) == 0);
    }

    return SSH_FSM_CONTINUE;
}
