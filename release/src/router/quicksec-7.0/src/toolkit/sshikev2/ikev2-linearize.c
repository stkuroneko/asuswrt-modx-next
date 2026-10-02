/**
   @copyright
   Copyright (c) 2005 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   IKEv2 linearize functions.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-util.h"
#include "sshikev2-exchange.h"
#include "ikev2-internal.h"
#include "ikev2-sa-crypto.h"
#include "sshencode.h"
#include "sshinetencode.h"

#ifdef SSHDIST_IKEV1
#include "isakmp_linearize.h"
#include "sshbuffer.h"
#endif /* SSHDIST_IKEV1 */

#define SSH_DEBUG_MODULE "SshIkev2Linearize"

#define SSH_IKEV2_LINEARIZE_MAGIC       0x41552335
#define SSH_IKEV2_LINEARIZE_VERSION     2

static SshIkev2Error
ikev2_window_encode_message(
        SshBuffer buffer,
        SshIkev2Message message)
{
    SshIkev2Error rv = SSH_IKEV2_ERROR_OK;
    size_t encoded_len;
    uint32_t payload_offset, next_payload;

    payload_offset = (uint32_t)message->payload_offset;
    next_payload   = (uint32_t)message->next_payload;

    encoded_len =
      ssh_encode_buffer(buffer,
                        SSH_ENCODE_UINT32_STR(message->data,
                                              message->len),
                        SSH_ENCODE_UINT32(payload_offset),
                        SSH_ENCODE_UINT32(next_payload),
                        SSH_ENCODE_UINT16(message->fragment_number),
                        SSH_ENCODE_UINT16(message->total_fragments),
                        SSH_FORMAT_END);

    if (encoded_len == 0)
      rv = SSH_IKEV2_ERROR_OUT_OF_MEMORY;

    return rv;
}

static SshIkev2Error
ikev2_window_encode_message_list(
        SshBuffer buffer,
        SshIkev2Message message_list)
{
    SshIkev2Message message_tmp;
    SshIkev2Error rv = SSH_IKEV2_ERROR_OK;

    for (message_tmp = message_list;
         message_tmp != NULL;
         message_tmp = message_tmp->next)
    {
        rv = ikev2_window_encode_message(buffer, message_tmp);

        if (rv != SSH_IKEV2_ERROR_OK)
          break;
    }

    return rv;
}

static SshIkev2Error
ikev2_window_decode_message(
        unsigned char *buffer,
        size_t buffer_len,
        SshIkev2Message prev_message,
        SshIkev2Message *message_out,
        size_t *bytes_read)
{
    SshIkev2Error rv = SSH_IKEV2_ERROR_OK;
    SshIkev2Message message = NULL;
    size_t parsed_bytes;
    unsigned char *message_data;
    size_t message_data_len;
    uint16_t fragment_number, total_fragments;
    uint32_t payload_offset, next_payload_u32;

    message = ssh_calloc(1, sizeof(*message));

    if (message == NULL)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed"));
        rv = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
    }

    if (rv == SSH_IKEV2_ERROR_OK)
    {
        parsed_bytes =
          ssh_decode_array(buffer, buffer_len,
                           SSH_DECODE_UINT32_STR_NOCOPY(&message_data,
                                                        &message_data_len),
                           SSH_DECODE_UINT32(&payload_offset),
                           SSH_DECODE_UINT32(&next_payload_u32),
                           SSH_DECODE_UINT16(&fragment_number),
                           SSH_DECODE_UINT16(&total_fragments),
                           SSH_FORMAT_END);

        if (parsed_bytes == 0)
        {
            rv = SSH_IKEV2_ERROR_INVALID_SYNTAX;
            ssh_free(message);
        }

        *bytes_read = parsed_bytes;
    }

    if (rv == SSH_IKEV2_ERROR_OK)
    {
        message->payload_offset = (size_t) payload_offset;
        message->next_payload = (SshIkev2PayloadType) next_payload_u32;

        message->fragment_number = fragment_number;
        message->total_fragments = total_fragments;

        message->data = ssh_memdup(message_data, message_data_len);
        message->len = message_data_len;

        if (message->data == NULL)
        {
            rv = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
            ssh_free(message);
        }
    }

    if (rv == SSH_IKEV2_ERROR_OK)
    {
        if (prev_message != NULL)
          prev_message->next = message;

        *message_out = message;
    }

    return rv;
}

static SshIkev2Error
ikev2_window_decode_message_list(
        unsigned char *buffer,
        size_t buffer_len,
        uint32_t num_messages,
        SshIkev2Message *message_list_out,
        size_t *bytes_read)
{
    SshIkev2Error rv = SSH_IKEV2_ERROR_OK;
    SshIkev2Message message_tmp = NULL, message_prev = NULL;
    size_t message_bytes;
    uint32_t i;

    *bytes_read = 0;
    *message_list_out = NULL;

    for (i = 0; i < num_messages; i++)
    {
        rv = ikev2_window_decode_message(buffer + *bytes_read,
                                         buffer_len - *bytes_read,
                                         message_prev,
                                         &message_tmp,
                                         &message_bytes);

        if (rv != SSH_IKEV2_ERROR_OK)
          break;

        *bytes_read += message_bytes;

        if (i == 0)
          *message_list_out = message_tmp;

        message_prev = message_tmp;
        message_tmp = NULL;
    }


    return rv;
}

/*
  Encode packet structure to given ssh buffer.
 */
static SshIkev2Error
ikev2_window_encode_packet(
        SshBuffer buffer,
        SshIkev2Packet packet)
{
    size_t offset;
    uint32_t num_messages = 0, num_fragments_head = 0;
    SshIkev2Message message_tmp = NULL;
    SshIkev2Error rv = SSH_IKEV2_ERROR_OK;

    for (message_tmp = packet->message;
         message_tmp != NULL;
         message_tmp = message_tmp->next)
    {
        num_messages++;
    }

    for (message_tmp = packet->fragments_head;
         message_tmp != NULL;
         message_tmp = message_tmp->next)
    {
        num_fragments_head++;
    }

    offset =
        ssh_encode_buffer(
                buffer,
                SSH_ENCODE_UINT32(packet->flags),
                SSH_ENCODE_UINT32(packet->message_id),
                SSH_ENCODE_DATA(packet->hash, sizeof(packet->hash)),
                SSH_ENCODE_UINT32_STR(
                        packet->encoded_packet,
                        packet->encoded_packet_len),
                SSH_ENCODE_UINT32(num_messages),
                SSH_ENCODE_UINT32(num_fragments_head),
                SSH_FORMAT_END);

    if (offset == 0)
    {
        rv = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
    }

    if (rv == SSH_IKEV2_ERROR_OK)
    {
        rv = ikev2_window_encode_message_list(buffer, packet->message);
    }

    if (rv == SSH_IKEV2_ERROR_OK)
    {
        rv = ikev2_window_encode_message_list(buffer, packet->fragments_head);
    }

    return rv;
}


/*
  Decode a packet from buffer buf of length len.  Uses ike_sa to find
  ikev2 context for packet allocation.  On success store pointer to
  allocated and decoded packet to store_p, return number of bytes
  consumed from buffer while decoding in parsed_bytes_p, and return
  SSH_IKEV2_ERROR_OK.

  On error, packet is not allocated, both parsed_bytes_p and
  store_p have undefined values, and an error value is returned.
 */
static SshIkev2Error
ikev2_window_decode_packet(
        SshIkev2Sa ike_sa,
        const unsigned char *buf,
        size_t len,
        size_t *parsed_bytes_p,
        SshIkev2Packet *store_p)
{
    SshIkev2Error status = SSH_IKEV2_ERROR_OK;
    SshIkev2 ikev2 = ike_sa->server->context;
    SshIkev2Packet packet;
    uint32_t num_messages = 0, num_fragments_head = 0;
    size_t parsed_bytes = 0;
    unsigned char *encoded_packet;
    size_t encoded_packet_len;
    uint32_t flags;

    packet = ikev2_packet_allocate(ikev2, NULL_FNPTR);
    if (packet == NULL)
    {
        status = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
    }

    if (status == SSH_IKEV2_ERROR_OK)
    {
        packet->log_facility = ike_sa->log_facility;

        parsed_bytes =
            ssh_decode_array(
                    buf, len,
                    SSH_DECODE_UINT32(&flags),
                    SSH_DECODE_UINT32(&packet->message_id),
                    SSH_DECODE_DATA(packet->hash, sizeof(packet->hash)),
                    SSH_DECODE_UINT32_STR_NOCOPY(
                            &encoded_packet,
                            &encoded_packet_len),
                    SSH_DECODE_UINT32(&num_messages),
                    SSH_DECODE_UINT32(&num_fragments_head),
                    SSH_FORMAT_END);

        if (parsed_bytes == 0)
        {
            status = SSH_IKEV2_ERROR_INVALID_SYNTAX;
        }

        *parsed_bytes_p = parsed_bytes;
    }

    if (status == SSH_IKEV2_ERROR_OK)
    {
        SshIkev2Message message_list;

        parsed_bytes = 0;

        status =
          ikev2_window_decode_message_list(
                  (unsigned char *)buf + *parsed_bytes_p,
                  len - *parsed_bytes_p,
                  num_messages,
                  &message_list,
                  &parsed_bytes);

        if (status == SSH_IKEV2_ERROR_OK)
        {
            *parsed_bytes_p += parsed_bytes;
            packet->message = message_list;
        }
    }

    if (status == SSH_IKEV2_ERROR_OK)
    {
        SshIkev2Message fragments_head;

        parsed_bytes = 0;

        status =
          ikev2_window_decode_message_list(
                  (unsigned char *)buf + *parsed_bytes_p,
                  len - *parsed_bytes_p,
                  num_fragments_head,
                  &fragments_head,
                  &parsed_bytes);

        if (status == SSH_IKEV2_ERROR_OK)
        {
            *parsed_bytes_p += parsed_bytes;
            packet->fragments_head = fragments_head;
        }
    }

    if (status == SSH_IKEV2_ERROR_OK)
    {
        packet->flags = flags;
        packet->in_window = 1;
        packet->server = ike_sa->server;

        if (encoded_packet_len)
        {
            packet->encoded_packet =
                ssh_memdup(
                        encoded_packet,
                        encoded_packet_len);
            packet->encoded_packet_len = encoded_packet_len;

            if (packet->encoded_packet == NULL)
            {
                status = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
            }
        }
    }

    if (status == SSH_IKEV2_ERROR_OK)
    {
        *store_p = packet;
    }


    if (status != SSH_IKEV2_ERROR_OK)
    {
        if (packet != NULL)
        {
            packet->in_window = 0;
            ikev2_packet_free(ikev2, packet);
        }
    }

    return status;
}


/*
  Encode transmit window to a linear memory buffer.
 */
SshIkev2Error
ikev2_transmit_window_encode(
        SshIkev2Sa ike_sa,
        unsigned char **buf,
        size_t *len)
{
    SshIkev2Error status = SSH_IKEV2_ERROR_OK;
    SshBufferStruct buffer;
    SshIkev2TransmitWindow transmit_window = ike_sa->transmit_window;
    SshIkev2Packet packet;
    uint32_t packet_count = 0;
    size_t offset;

    ssh_buffer_init(&buffer);

    for (packet = transmit_window->packets_head;
         packet != NULL;
         packet = packet->window_next)
    {
        ++packet_count;
    }

    offset =
        ssh_encode_buffer(
                &buffer,
                SSH_ENCODE_UINT32(transmit_window->next_message_id),
                SSH_ENCODE_UINT32(transmit_window->window_size),
                SSH_ENCODE_UINT32(packet_count),
                SSH_FORMAT_END);

    if (offset == 0)
    {
        SSH_DEBUG(
                SSH_D_FAIL,
                ("Transmit window %p: "
                 "Encode failed: out of memory.",
                         transmit_window));

        status = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
    }

    SSH_DEBUG(
            SSH_D_LOWOK,
            ("Transmit window %p: "
             "Encoding: next_message_id %u, window_size %u, packets %u.",
                     transmit_window,
                     transmit_window->next_message_id,
                     transmit_window->window_size,
                     (unsigned) packet_count));

    for (packet = transmit_window->packets_head;
         status == SSH_IKEV2_ERROR_OK &&
             packet != NULL;
         packet = packet->window_next)
    {
        SSH_DEBUG(
                SSH_D_LOWOK,
                ("Transmit window %p: "
                 "Encoding packet %p message_id %u.",
                         transmit_window,
                         packet,
                         packet->message_id));

        status =
            ikev2_window_encode_packet(
                    &buffer,
                    packet);
    }

    if (status == SSH_IKEV2_ERROR_OK)
    {
        *buf = ssh_buffer_steal(&buffer, len);
    }

    ssh_buffer_uninit(&buffer);

    return status;
}


/*
  Establish a new transmit window to given ike_sa decoding its
  contents from given buffer.
 */
SshIkev2Error
ikev2_transmit_window_decode(
        SshIkev2Sa ike_sa,
        unsigned char *buf,
        size_t len)
{
    SshIkev2Error status = SSH_IKEV2_ERROR_OK;
    SshIkev2TransmitWindow transmit_window = ike_sa->transmit_window;
    uint32_t packet_count;
    size_t offset = 0;

    ikev2_transmit_window_init(transmit_window);

    offset =
      ssh_decode_array(buf, len,
                       SSH_DECODE_UINT32(&transmit_window->next_message_id),
                       SSH_DECODE_UINT32(&transmit_window->window_size),
                       SSH_DECODE_UINT32(&packet_count),
                       SSH_FORMAT_END);

    if (offset == 0)
    {
        status = SSH_IKEV2_ERROR_INVALID_SYNTAX;
    }
    else
    {
        SSH_DEBUG(SSH_D_LOWOK,
                  ("Transmit window %p: "
                   "Decoding: next_message_id %u, window_size %u, packets %u.",
                   transmit_window,
                   transmit_window->next_message_id,
                   transmit_window->window_size,
                   (unsigned) packet_count));
    }

    if (status == SSH_IKEV2_ERROR_OK)
    {
        SshIkev2Packet *store_p = &transmit_window->packets_head;
        SshIkev2Packet last_packet = NULL;
        uint32_t decoded_packets = 0;

        while (status == SSH_IKEV2_ERROR_OK &&
               decoded_packets < packet_count)
        {
            size_t parsed_bytes;

            status =
                ikev2_window_decode_packet(
                        ike_sa,
                        buf + offset,
                        len - offset,
                        &parsed_bytes,
                        store_p);

            if (status == SSH_IKEV2_ERROR_OK)
            {
                offset += parsed_bytes;

                last_packet = *store_p;
                store_p = &last_packet->window_next;

                ++decoded_packets;

                SSH_DEBUG(
                        SSH_D_LOWOK,
                        ("Transmit window %p: "
                         "Decoding packet %p message_id %u.",
                                 transmit_window,
                                 last_packet,
                                 last_packet->message_id));
            }
        }

        transmit_window->packets_tail = last_packet;
    }

    if (status != SSH_IKEV2_ERROR_OK)
      ikev2_transmit_window_uninit(transmit_window);

    return status;
}

/*
  Encode receive window to a linear memory buffer.
 */
SshIkev2Error
ikev2_receive_window_encode(
        SshIkev2Sa ike_sa,
        unsigned char **buf,
        size_t *len)
{
    SshIkev2Error status = SSH_IKEV2_ERROR_OK;
    SshBufferStruct buffer;
    SshIkev2ReceiveWindow receive_window = ike_sa->receive_window;
    SshIkev2Packet packet;
    uint32_t packet_count = 0;
    size_t offset;

    ssh_buffer_init(&buffer);

    for (packet = receive_window->packets_head;
         packet != NULL;
         packet = packet->window_next)
    {
        ++packet_count;
    }

    offset =
        ssh_encode_buffer(
                &buffer,
                SSH_ENCODE_UINT32(receive_window->expected_id),
                SSH_ENCODE_UINT32(receive_window->window_size),
                SSH_ENCODE_UINT32(packet_count),
                SSH_FORMAT_END);

    if (offset == 0)
    {
        SSH_DEBUG(
                SSH_D_FAIL,
                ("Receive window %p: "
                 "Encode failed: out of memory.",
                         receive_window));

        status = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
    }

    SSH_DEBUG(
            SSH_D_LOWOK,
            ("Receive window %p: "
             "Encoding: expected_id %u, window_size %u, packets %u.",
                     receive_window,
                     receive_window->expected_id,
                     receive_window->window_size,
                     (unsigned) packet_count));


    for (packet = receive_window->packets_head;
         status == SSH_IKEV2_ERROR_OK &&
             packet != NULL;
         packet = packet->window_next)
    {
        SSH_DEBUG(
                SSH_D_LOWOK,
                ("Receive window %p: "
                 "Encoding packet %p message_id %u.",
                         receive_window,
                         packet,
                         packet->message_id));

        status =
            ikev2_window_encode_packet(
                    &buffer,
                    packet);
    }

    if (status == SSH_IKEV2_ERROR_OK)
    {
        *buf = ssh_buffer_steal(&buffer, len);
    }

    ssh_buffer_uninit(&buffer);

    return status;
}


/*
  Establish a new receive window to given ike_sa decoding its
  contents from given buffer.
 */
SshIkev2Error
ikev2_receive_window_decode(
        SshIkev2Sa ike_sa,
        unsigned char *buf,
        size_t len)
{
    SshIkev2Error status = SSH_IKEV2_ERROR_OK;
    SshIkev2ReceiveWindow receive_window = ike_sa->receive_window;
    uint32_t packet_count;
    size_t offset = 0;

    ikev2_receive_window_init(receive_window);

    offset = ssh_decode_array(buf, len,
                              SSH_DECODE_UINT32(&receive_window->expected_id),
                              SSH_DECODE_UINT32(&receive_window->window_size),
                              SSH_DECODE_UINT32(&packet_count),
                              SSH_FORMAT_END);

    if (offset == 0)
    {
        status = SSH_IKEV2_ERROR_INVALID_SYNTAX;
    }
    else
    {
        SSH_DEBUG(SSH_D_LOWOK,
                  ("Receive window %p: "
                   "Decoding: expected_id %u, window_size %u, packets %u.",
                   receive_window,
                   receive_window->expected_id,
                   receive_window->window_size,
                   (unsigned) packet_count));
    }

    if (status == SSH_IKEV2_ERROR_OK)
    {
        SshIkev2Packet *store_p = &receive_window->packets_head;
        SshIkev2Packet last_packet = NULL;
        uint32_t decoded_packets = 0;

        while (status == SSH_IKEV2_ERROR_OK &&
               decoded_packets < packet_count)
        {
            size_t parsed_bytes;

            status =
                ikev2_window_decode_packet(
                        ike_sa,
                        buf + offset,
                        len - offset,
                        &parsed_bytes,
                        store_p);

            if (status == SSH_IKEV2_ERROR_OK)
            {
                offset += parsed_bytes;

                last_packet = *store_p;
                store_p = &last_packet->window_next;

                ++decoded_packets;

                SSH_DEBUG(
                        SSH_D_LOWOK,
                        ("Receive window %p: "
                         "Decoding packet %p message_id %u.",
                                 receive_window,
                                 last_packet,
                                 last_packet->message_id));
            }
        }

        receive_window->packets_tail = last_packet;
    }

    if (status != SSH_IKEV2_ERROR_OK)
      ikev2_receive_window_uninit(receive_window);

    return status;
}

/* requires sa->server as set */
SshIkev2Error
ssh_ikev2_decode_sa(SshIkev2Sa sa, unsigned char *buf, size_t len)
{
    SshIkev2Error status;
    size_t offset, sklen, total_len;
    uint32_t magic, linearize_version;
    uint32_t encr_alg, prf_alg, mac_alg;
    uint32_t ike_frag;
    uint16_t normal_local_port, nat_t_local_port;
    SshIpAddrStruct local_address[1];
    uint32_t ike_version;
    unsigned char *mobike_param;
    size_t mobike_param_len;
    unsigned char *transmit_window;
    size_t transmit_window_len;
    unsigned char *receive_window;
    size_t receive_window_len;
    uint32_t sk_a_len;
    uint32_t sk_p_len;
    uint32_t sk_e_len;
    uint32_t sk_d_len;
    uint32_t sk_n_len;
    unsigned char *sk_d = NULL;
    SshCryptoStatus crypto_status;
    bool initiator;

    offset = ssh_decode_array(buf, len,
                              SSH_DECODE_UINT32(&magic),
                              SSH_DECODE_UINT32(&linearize_version),
                              SSH_DECODE_UINT32(&ike_version),
                              SSH_FORMAT_END);

    if (offset != 12
        || magic != SSH_IKEV2_LINEARIZE_MAGIC
        || linearize_version != SSH_IKEV2_LINEARIZE_VERSION)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Invalid IKE SA export header format"));
        status = SSH_IKEV2_ERROR_INVALID_SYNTAX;
        goto error;
    }
    total_len = offset;

    offset = ssh_decode_array(buf + total_len, len - total_len,
                              SSH_DECODE_SPECIAL_NOALLOC(
                              ssh_decode_ipaddr_array, local_address),
                              SSH_DECODE_UINT16(&normal_local_port),
                              SSH_DECODE_UINT16(&nat_t_local_port),
                              SSH_DECODE_SPECIAL_NOALLOC(
                              ssh_decode_ipaddr_array, sa->remote_ip),
                              SSH_DECODE_UINT16(&sa->remote_port),
                              SSH_DECODE_UINT32(&sa->flags),
                              SSH_DECODE_UINT32(&ike_frag),
                              SSH_DECODE_DATA(sa->ike_spi_i, (size_t) 8),
                              SSH_DECODE_DATA(sa->ike_spi_r, (size_t) 8),
                              SSH_DECODE_UINT32(&encr_alg),
                              SSH_DECODE_UINT32(&prf_alg),
                              SSH_DECODE_UINT32(&mac_alg),
                              SSH_DECODE_UINT16(&sa->dh_group),
                              SSH_FORMAT_END);
    if (offset == 0)
    {
        SSH_DEBUG(SSH_D_FAIL, ("IKE SA decode failed"));
        status = SSH_IKEV2_ERROR_INVALID_SYNTAX;
        goto error;
    }
    total_len += offset;

    if (mac_alg == SSH_IKEV2_TRANSFORM_AUTH_NONE)
    {
        /* This is legal when using combined algorithms */
        SSH_ASSERT(
                ((encr_alg & 0xff) == SSH_IKEV2_TRANSFORM_ENCR_AES_GCM_8) ||
                ((encr_alg & 0xff) == SSH_IKEV2_TRANSFORM_ENCR_AES_GCM_12) ||
                ((encr_alg & 0xff) == SSH_IKEV2_TRANSFORM_ENCR_AES_GCM_16) ||
                ((encr_alg & 0xff) == SSH_IKEV2_TRANSFORM_ENCR_AES_CCM_8) ||
                ((encr_alg & 0xff) == SSH_IKEV2_TRANSFORM_ENCR_AES_CCM_12) ||
                ((encr_alg & 0xff) == SSH_IKEV2_TRANSFORM_ENCR_AES_CCM_16));

        sa->mac_algorithm = NULL;
    }
    else
    {
        sa->mac_algorithm =
            ssh_find_keyword_name(ssh_ikev2_mac_algorithms, mac_alg);

        if (sa->mac_algorithm == NULL)
        {
            SSH_DEBUG(SSH_D_FAIL, ("Invalid IKE SA MAC algorithm"));
            status = SSH_IKEV2_ERROR_INVALID_SYNTAX;
            goto error;
        }
    }

    sa->prf_algorithm =
        ssh_find_keyword_name(ssh_ikev2_prf_algorithms, prf_alg);

    if (sa->prf_algorithm == NULL)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Invalid IKE SA PRF algorithm"));
        status = SSH_IKEV2_ERROR_INVALID_SYNTAX;
        goto error;
    }

    sa->encrypt_algorithm =
        ssh_find_keyword_name(ssh_ikev2_encr_algorithms, encr_alg);

    sa->ikev2_fragmentation_limit = ike_frag;

    if (sa->encrypt_algorithm == NULL)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Invalid IKE SA encrypt algorithm"));
        status = SSH_IKEV2_ERROR_INVALID_SYNTAX;
        goto error;
    }

#ifdef SSHDIST_IKEV1
    if (ike_version == 1)
    {
        SshBufferStruct  buffer;
        SshIkePMPhaseI pm_info;
        uint64_t last_input_stamp;

        /* First decode last input packet timestamp. */
        offset =
            ssh_decode_array(
                    buf + total_len,
                    len - total_len,
                    SSH_DECODE_UINT64(
                            &last_input_stamp),
                    SSH_FORMAT_END);

        if (offset == 0)
        {
            SSH_DEBUG(SSH_D_FAIL, ("IKEv1 SA decode failed"));
            status = SSH_IKEV2_ERROR_INVALID_SYNTAX;
            goto error;
        }

        sa->last_input_stamp = monotonic_time_from_ssh_time(last_input_stamp);

        total_len += offset;

        /* Next import the IKEv1 SA to Isakmp library. */
        ssh_buffer_init(&buffer);
        ssh_buffer_wrap(&buffer, buf + total_len, len - total_len);
        buffer.end = len - total_len;

        sa->v1_sa =
            ssh_ike_sa_import(&buffer, (SshIkeServerContext)sa->server);
        if (sa->v1_sa == NULL)
        {
            SSH_DEBUG(SSH_D_FAIL, ("IKEv1 SA decode failed"));
            status = SSH_IKEV2_ERROR_INVALID_SYNTAX;
            goto error;
        }

        SSH_DEBUG(SSH_D_LOWOK,
                  ("Taking reference to IKE SA %p to ref count %d",
                   sa, sa->ref_cnt + 1));
        sa->ref_cnt++;

        pm_info = ssh_ike_get_pm_phase_i_info_by_negotiation(sa->v1_sa);
        if (pm_info == NULL)
        {
            SSH_DEBUG(SSH_D_ERROR, ("Could not get PM info from IKE SA"));
            status = SSH_IKEV2_ERROR_SA_UNUSABLE;
            goto error;
        }
        pm_info->policy_manager_data = sa;

        sa->flags |= SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1;

        ssh_buffer_uninit(&buffer);

        return SSH_IKEV2_ERROR_OK;
    }
#endif /* SSHDIST_IKEV1 */

    if (ike_version != 2)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Invalid IKE version %d", ike_version));
        return SSH_IKEV2_ERROR_INVALID_MAJOR_VERSION;
    }

    offset = ssh_decode_array(buf + total_len, len - total_len,
                              SSH_DECODE_UINT32_STR_NOCOPY(&mobike_param,
                                                           &mobike_param_len),
                              SSH_FORMAT_END);
    if (offset == 0)
    {
        SSH_DEBUG(SSH_D_FAIL, ("IKE SA decode failed"));
        status = SSH_IKEV2_ERROR_INVALID_SYNTAX;
        goto error;
    }
    total_len += offset;

#ifdef SSHDIST_IKE_MOBIKE
    /* Decode MOBIKE specific information. */
    status = ikev2_mobike_decode(sa, mobike_param, mobike_param_len);
    if (status != SSH_IKEV2_ERROR_OK)
    {
        SSH_DEBUG(SSH_D_FAIL, ("IKE SA MOBIKE parameter decode failed"));
        goto error;
    }
#endif /* SSHDIST_IKE_MOBIKE */

    offset = ssh_decode_array(buf + total_len, len - total_len,
                              SSH_DECODE_UINT32_STR(&sk_d, &sklen),
                              SSH_DECODE_UINT32(&sk_d_len),
                              SSH_DECODE_UINT32(&sk_a_len),
                              SSH_DECODE_UINT32(&sk_e_len),
                              SSH_DECODE_UINT32(&sk_n_len),
                              SSH_DECODE_UINT32(&sk_p_len),
                              SSH_DECODE_UINT32_STR_NOCOPY(
                                      &transmit_window,
                                      &transmit_window_len),
                              SSH_DECODE_UINT32_STR_NOCOPY(
                                      &receive_window,
                                      &receive_window_len),
                              SSH_FORMAT_END);
    if (offset == 0)
    {
        SSH_DEBUG(SSH_D_FAIL, ("IKE SA decode failed"));
        status = SSH_IKEV2_ERROR_INVALID_SYNTAX;
        goto error;
    }
    total_len += offset;

    /* Decode window data. For this we'll need the ikev2 context, which we
       can get from the server, that needs to be given by the caller as
       sa->server->ikev2 */
    status =
        ikev2_transmit_window_decode(
                sa,
                transmit_window,
                transmit_window_len);

    if (status != SSH_IKEV2_ERROR_OK)
    {
        SSH_DEBUG(SSH_D_FAIL, ("IKE SA transmit window decode failed"));
        goto error;
    }

    /* Decode window data. For this we'll need the ikev2 context, which we
       can get from the server, that needs to be given by the caller as
       sa->server->ikev2 */
    status =
        ikev2_receive_window_decode(
                sa,
                receive_window,
                receive_window_len);

    if (status != SSH_IKEV2_ERROR_OK)
    {
        SSH_DEBUG(SSH_D_FAIL, ("IKE SA receive window decode failed"));
        goto error;
    }

    sa->sk_d = sk_d;
    sk_d = NULL;
    sa->sk_d_len = (size_t) sk_d_len;
    sa->sk_a_len = (size_t) sk_a_len;
    sa->sk_e_len = (size_t) sk_e_len;
    sa->sk_n_len = (size_t) sk_n_len;
    sa->sk_p_len = (size_t) sk_p_len;

    /* Verify that decoding consumed all data. */
    if (total_len != len)
    {
        SSH_DEBUG(SSH_D_FAIL,
                  ("IKE SA import buffer has %d bytes trailing garbage",
                   len - total_len));
        status = SSH_IKEV2_ERROR_INVALID_SYNTAX;
        goto error;
    }

    SSH_ASSERT(sklen ==  (sa->sk_d_len
                          + sa->sk_a_len * 2
                          + sa->sk_e_len * 2
                          + sa->sk_n_len * 2
                          + sa->sk_p_len * 2));

    sa->sk_ai = sa->sk_d  + sa->sk_d_len;
    sa->sk_ar = sa->sk_ai + sa->sk_a_len;
    sa->sk_ei = sa->sk_ar + sa->sk_a_len;
    sa->sk_ni = sa->sk_ei + sa->sk_e_len;
    sa->sk_er = sa->sk_ni + sa->sk_n_len;
    sa->sk_nr = sa->sk_er + sa->sk_e_len;
    sa->sk_pi = sa->sk_nr + sa->sk_n_len;
    sa->sk_pr = sa->sk_pi + sa->sk_p_len;

    if (sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR)
      initiator = true;
    else
      initiator = false;

    sa->crypto_context = ikev2_sa_crypto_create();

    if (sa->crypto_context == NULL)
    {
        status = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
        goto error;
    }

    crypto_status =
      ikev2_sa_crypto_config(sa->encrypt_algorithm,
                             initiator ? sa->sk_ei : sa->sk_er,
                             initiator ? sa->sk_er : sa->sk_ei,
                             sa->sk_e_len,
                             sa->mac_algorithm,
                             initiator ? sa->sk_ai : sa->sk_ar,
                             initiator ? sa->sk_ar : sa->sk_ai,
                             sa->sk_a_len,
                             sa->crypto_context);

    if (crypto_status != SSH_CRYPTO_OK)
    {
        status = SSH_IKEV2_ERROR_CRYPTO_FAIL;
        goto error;
    }

    return SSH_IKEV2_ERROR_OK;

   error:
    if (sk_d != NULL)
      ssh_free(sk_d);

    ssh_ikev2_ike_sa_uninit(sa);
    SSH_ASSERT(status != SSH_IKEV2_ERROR_OK);
    return status;
}

SshIkev2Error
ssh_ikev2_encode_sa(SshIkev2Sa sa, unsigned char **buf_ret, size_t *len_ret)
{
    SshIkev2Error status = SSH_IKEV2_ERROR_OK;
    size_t offset;
    uint32_t ike_version = 2;
    uint32_t encr_alg, prf_alg, mac_alg;
    uint32_t ike_frag;
    unsigned char *mobike_param = NULL;
    size_t mobike_param_len = 0;
    unsigned char *transmit_window = NULL;
    size_t transmit_window_len = 0;
    unsigned char *receive_window = NULL;
    size_t receive_window_len = 0;
    SshBufferStruct buffer;

    /* Skip IKE SAs which are not normal. */
    if ((sa->flags & SSH_IKEV2_IKE_SA_FLAGS_IKE_SA_DONE) == 0
        || sa->waiting_for_delete != NULL)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Invalid IKE SA state"));
        return SSH_IKEV2_ERROR_SA_UNUSABLE;
    }

    encr_alg = ssh_find_keyword_number(ssh_ikev2_encr_algorithms,
                                       sa->encrypt_algorithm);

    prf_alg = ssh_find_keyword_number(ssh_ikev2_prf_algorithms,
                                      sa->prf_algorithm);

    ike_frag = sa->ikev2_fragmentation_limit;

    if (sa->mac_algorithm == NULL)
    {
        /* This is legal when using combined algorithms */
        SSH_ASSERT(
                ((encr_alg & 0xff) == SSH_IKEV2_TRANSFORM_ENCR_AES_GCM_8) ||
                ((encr_alg & 0xff) == SSH_IKEV2_TRANSFORM_ENCR_AES_GCM_12) ||
                ((encr_alg & 0xff) == SSH_IKEV2_TRANSFORM_ENCR_AES_GCM_16) ||
                ((encr_alg & 0xff) == SSH_IKEV2_TRANSFORM_ENCR_AES_CCM_8) ||
                ((encr_alg & 0xff) == SSH_IKEV2_TRANSFORM_ENCR_AES_CCM_12) ||
                ((encr_alg & 0xff) == SSH_IKEV2_TRANSFORM_ENCR_AES_CCM_16));

        mac_alg = SSH_IKEV2_TRANSFORM_AUTH_NONE;
    }
    else
    {
        mac_alg = ssh_find_keyword_number(ssh_ikev2_mac_algorithms,
                                          sa->mac_algorithm);
    }

#ifdef SSHDIST_IKEV1
    if (sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1 && sa->v1_sa == NULL)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Invalid IKEv1 SA state"));
        return SSH_IKEV2_ERROR_SA_UNUSABLE;
    }
#endif /* SSHDIST_IKEV1 */

    ssh_buffer_init(&buffer);

#ifdef SSHDIST_IKEV1
    if (sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
      ike_version = 1;
#endif /* SSHDIST_IKEV1 */

    /* First encode the data common to IKEv1 and IKEv2 SA's */
    offset =
      ssh_encode_buffer(&buffer,
                        SSH_ENCODE_UINT32(
                        (uint32_t) SSH_IKEV2_LINEARIZE_MAGIC),
                        SSH_ENCODE_UINT32(
                        (uint32_t) SSH_IKEV2_LINEARIZE_VERSION),
                        SSH_ENCODE_UINT32(ike_version),
                        SSH_ENCODE_SPECIAL(
                        ssh_encode_ipaddr_encoder, sa->server->ip_address),
                        SSH_ENCODE_UINT16(
                        (uint16_t) sa->server->normal_local_port),
                        SSH_ENCODE_UINT16(
                        (uint16_t) sa->server->nat_t_local_port),
                        SSH_ENCODE_SPECIAL(
                        ssh_encode_ipaddr_encoder, sa->remote_ip),
                        SSH_ENCODE_UINT16((uint16_t) sa->remote_port),
                        SSH_ENCODE_UINT32((uint32_t) sa->flags),
                        SSH_ENCODE_UINT32(ike_frag),
                        SSH_ENCODE_DATA(sa->ike_spi_i, (size_t) 8),
                        SSH_ENCODE_DATA(sa->ike_spi_r, (size_t) 8),
                        SSH_ENCODE_UINT32(encr_alg),
                        SSH_ENCODE_UINT32(prf_alg),
                        SSH_ENCODE_UINT32(mac_alg),
                        SSH_ENCODE_UINT16((uint16_t) sa->dh_group),
                        SSH_FORMAT_END);
    if (offset == 0)
    {
        SSH_DEBUG(SSH_D_FAIL, ("IKE SA encode failed"));
        status = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
        goto error;
    }

#ifdef SSHDIST_IKEV1
    if (sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
    {
        /* First encode last input packet timestamp. */
        offset =
            ssh_encode_buffer(
                    &buffer,
                    SSH_ENCODE_UINT64(
                            ssh_time_from_monotonic_time(
                                    sa->last_input_stamp)),
                    SSH_FORMAT_END);
        if (offset == 0)
        {
            SSH_DEBUG(SSH_D_FAIL, ("IKEv1 SA encode failed"));
            status = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
            goto error;
        }

        /* Next export the IKEv1 SA data from Isakmp library. */
        offset = ssh_ike_sa_export(&buffer, sa->v1_sa);
        if (offset == 0)
        {
            SSH_DEBUG(SSH_D_FAIL, ("IKEv1 SA encode failed"));
            status = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
            goto error;
        }

        goto out;
    }
#endif /* SSHDIST_IKEV1 */

#ifdef SSHDIST_IKE_MOBIKE
    /* Encode MOBIKE specific information. */
    status = ikev2_mobike_encode(sa, &mobike_param, &mobike_param_len);
    if (status != SSH_IKEV2_ERROR_OK)
    {
        SSH_DEBUG(SSH_D_FAIL, ("IKE SA MOBIKE param encode failed"));
        goto error;
    }
#endif /* SSHDIST_IKE_MOBIKE */

    status =
        ikev2_transmit_window_encode(
                sa,
                &transmit_window,
                &transmit_window_len);

    if (status != SSH_IKEV2_ERROR_OK)
    {
        SSH_DEBUG(SSH_D_FAIL, ("IKE SA transmit window encode failed"));
        goto error;
    }

    status =
        ikev2_receive_window_encode(
                sa,
                &receive_window,
                &receive_window_len);

    if (status != SSH_IKEV2_ERROR_OK)
    {
        SSH_DEBUG(SSH_D_FAIL, ("IKE SA receive window encode failed"));
        goto error;
    }

    offset =
      ssh_encode_buffer(&buffer,
                        SSH_ENCODE_UINT32_STR(mobike_param, mobike_param_len),
                        SSH_ENCODE_UINT32_STR(sa->sk_d,
                                              (size_t) (sa->sk_d_len +
                                                        sa->sk_a_len * 2 +
                                                        sa->sk_e_len * 2 +
                                                        sa->sk_n_len * 2 +
                                                        sa->sk_p_len * 2)),
                        SSH_ENCODE_UINT32((uint32_t) sa->sk_d_len),
                        SSH_ENCODE_UINT32((uint32_t) sa->sk_a_len),
                        SSH_ENCODE_UINT32((uint32_t) sa->sk_e_len),
                        SSH_ENCODE_UINT32((uint32_t) sa->sk_n_len),
                        SSH_ENCODE_UINT32((uint32_t) sa->sk_p_len),
                        /* initial_ed is skipped. */
                        /* rekey is skipped. */
                        SSH_ENCODE_UINT32_STR(
                                transmit_window,
                                transmit_window_len),
                        SSH_ENCODE_UINT32_STR(
                                receive_window,
                                receive_window_len),
                        /* ref_cnt, sa_header, waiting_for_delete are
                           skipped. */
                        SSH_FORMAT_END);
    if (offset == 0)
    {
        SSH_DEBUG(SSH_D_FAIL, ("IKE SA encode failed"));
        status = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
        goto error;
    }

#ifdef SSHDIST_IKEV1
   out:
#endif /* SSHDIST_IKEV1 */
    SSH_ASSERT(status == SSH_IKEV2_ERROR_OK);
    ssh_free(mobike_param);
    ssh_free(transmit_window);
    ssh_free(receive_window);
    *buf_ret = ssh_buffer_steal(&buffer, len_ret);
    ssh_buffer_uninit(&buffer);

    return SSH_IKEV2_ERROR_OK;

   error:
    SSH_ASSERT(status != SSH_IKEV2_ERROR_OK);
    ssh_free(mobike_param);
    ssh_free(transmit_window);
    ssh_free(receive_window);
    ssh_buffer_uninit(&buffer);
    *buf_ret = 0;
    *len_ret = 0;

    return status;
}
