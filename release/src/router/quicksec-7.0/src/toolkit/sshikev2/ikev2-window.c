/**
   @copyright
   Copyright (c) 2004 - 2016, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshencode.h"
#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "sshikev2-util.h"
#include "ikev2-internal.h"


#define SSH_DEBUG_MODULE "SshIkev2NetWindow"

/*
  Reset window specific things from a packet and finish with the
  packet.
 */
static void
ikev2_window_packet_done(
        SshIkev2Packet packet)
{
    SSH_ASSERT(packet->reassemble_packet == NULL);

    packet->window_next = NULL;
    packet->in_window = 0;

    ikev2_packet_done(packet);
}


/*
  Disconnect reassemble packet from packet and finish reassemble packet.

 */
static void
ikev2_window_reassemble_packet_done(
        SshIkev2Packet packet)
{
    SshIkev2Packet reassemble_packet;

    SSH_ASSERT(packet->reassemble_packet != NULL);

    reassemble_packet = packet->reassemble_packet;
    packet->reassemble_packet = NULL;

    ikev2_window_packet_done(reassemble_packet);
}


/*
  Finish a list of packets linked as a list with window_next pointers.
 */
static void
ikev2_window_packet_list_done(
        SshIkev2Packet first_packet)
{
    SshIkev2Packet next_packet = first_packet;

    while (next_packet != NULL)
    {
        SshIkev2Packet packet = next_packet;

        next_packet = packet->window_next;

        /* Finish reassemble packet if it is still linked to window packet. */
        if (packet->reassemble_packet != NULL)
        {
            ikev2_window_reassemble_packet_done(packet);
        }

        ikev2_window_packet_done(packet);
    }
}


/*
  Compute a hash value of packet data and store it to the packet
  structure.
 */
static void
ikev2_window_packet_hash_compute(
        SshIkev2Packet packet)
{
    /* Compute hash only for packet which is not fragment. */
    if (packet->fragment == 0)
    {
        SshIkev2 ikev2 = packet->server->context;
        SshIkev2Message message = packet->message;

        ssh_hash_reset(ikev2->hash);

        ssh_hash_update(ikev2->hash, message->data, message->len);

        ssh_hash_final(ikev2->hash, packet->hash);

        SSH_DEBUG_HEXDUMP(
                SSH_D_LOWOK,
                ("Computed hash for packet %p", packet),
                packet->hash, sizeof(packet->hash));
    }
}


/*
  Compare hashes of two packets return true if are equal; false
  otherwise
 */
static bool
ikev2_window_packet_hash_equal(
        SshIkev2Packet packet_a,
        SshIkev2Packet packet_b)
{
    if (memcmp(packet_a->hash, packet_b->hash, sizeof (packet_a->hash)) == 0)
    {
        return true;
    }

    return false;
}


/*
  Copy a hash value from one packet structure to another.
 */
static void
ikev2_window_packet_hash_copy(
        SshIkev2Packet dst,
        SshIkev2Packet src)
{
    memcpy(dst->hash, src->hash, sizeof(src->hash));
}


/*
   Search a packet with given message_id from packet queue and return
   pointer to if found. Otherwise, return NULL.
 */
SshIkev2Packet
ikev2_window_search(
        SshIkev2Packet packets_head,
        uint32_t message_id)
{
    SshIkev2Packet packet;

    for (packet = packets_head;
         packet != NULL && packet->message_id != message_id;
         packet = packet->window_next)
      ;

    if (packet == NULL)
    {
        SSH_DEBUG(
                SSH_D_LOWOK,
                ("Window doesn't contain packet with message_id %u.",
                         message_id));
    }
    else
    {
        SSH_DEBUG(
                SSH_D_LOWOK,
                ("Window contains packet %p with message_id %u.",
                         packet,
                         message_id));
    }

    return packet;
}


/*
  Check if a fragment is new one and can be passed head.
 */
static bool
ikev2_window_is_new_fragment(
        SshIkev2Packet reassemble_packet,
        SshIkev2Packet packet)
{
    SshIkev2Message reassemble_fragment = reassemble_packet->fragments_head;

    SSH_ASSERT(packet->fragment == 1);

    /* Do check only if reassemble packet contains fragments. */
    if (reassemble_fragment != NULL)
    {
        SshIkev2Message fragment = packet->message;

        /* Check if all fragments are already seen. */
        if (reassemble_packet->all_fragments_received == 1)
        {
            return false;
        }

        /* Check if value of total fragments in new fragment is
           bigger than in reassembled packet. This can be true if sender
           has re-fragmented packet to smaller fragments. */
        if (fragment->total_fragments > reassemble_packet->total_fragments)
        {
            return true;
        }

        /* Check if fragment is already seen and handled. */
        do
        {
            if (reassemble_fragment->fragment_number ==
                fragment->fragment_number)
            {
                return false;
            }
            reassemble_fragment = reassemble_fragment->next;
        }
        while (reassemble_fragment != NULL);

        return true;
    }

    return false;
}


/*
  Continue reassembly by inserting new fragment to fragments list.
 */
static bool
ikev2_window_continue_reassembly(
        SshIkev2Packet reassemble_packet,
        SshIkev2Packet packet)
{
    SshIkev2Message *prev_fragment_p = &reassemble_packet->fragments_head;
    SshIkev2Message new_fragment = packet->message;
    SshIkev2Message tmp_fragment;

    /* Find correct place where to put new fragment. Fragments are stored
       to ascending order; 1, 2, 3... */
    for (tmp_fragment = *prev_fragment_p;
         (tmp_fragment != NULL &&
          tmp_fragment->fragment_number < new_fragment->fragment_number);
         tmp_fragment = tmp_fragment->next)
    {
        prev_fragment_p = &tmp_fragment->next;
    }

    if (*prev_fragment_p != NULL)
    {
        bool is_response =
          ((reassemble_packet->flags & SSH_IKEV2_PACKET_FLAG_RESPONSE) != 0) ?
          true : false;

        /* Check that same fragment number doesn't exist. */
        if ((*prev_fragment_p)->fragment_number
            == new_fragment->fragment_number)
        {
            SSH_DEBUG(
                    SSH_D_LOWOK,
                    ("Reassembly: "
                     "packet %p message_id %u fragment %u insert failed: "
                     "a %s packet %p already has this fragment.",
                             packet,
                             packet->message_id,
                             new_fragment->fragment_number,
                             ((is_response == true) ? "response" : "request"),
                             reassemble_packet));

            return false;
        }


        /* Check that value of total fragments is same that previous one. */
        if ((*prev_fragment_p)->total_fragments
            != new_fragment->total_fragments)
        {
            SSH_DEBUG(
                    SSH_D_LOWOK,
                    ("Reassembly: "
                     "packet %p message_id %u fragment %u insert failed: "
                     "a %s packet %p has different total fragments "
                     "value (%u != %u).",
                             packet,
                             packet->message_id,
                             new_fragment->fragment_number,
                             ((is_response == true) ? "response" : "request"),
                             reassemble_packet,
                             new_fragment->total_fragments,
                             (*prev_fragment_p)->total_fragments));

            return false;
        }
    }

    SSH_DEBUG(
            SSH_D_LOWOK,
            ("Window: reassembly continues: "
             "packet %p message_id %u fragment %u.",
                     reassemble_packet,
                     packet->message_id,
                     new_fragment->fragment_number));

    /* Add fragment to fragment list and remove it from packet. */
    *prev_fragment_p = new_fragment;
    new_fragment->next = tmp_fragment;

    reassemble_packet->fragments_count++;

    packet->message = NULL;

    return true;
}


/*
  Initialise transmit window structure.
  Initial window size is 1 and next_message_id 0.
 */
void
ikev2_transmit_window_init(SshIkev2TransmitWindow transmit_window)
{
    transmit_window->next_message_id = 0;
    transmit_window->window_size = 1;
    transmit_window->packets_head = NULL;
    transmit_window->packets_tail = NULL;
    SSH_DEBUG(SSH_D_LOWOK, ("Transmit window %p initialised",
                            transmit_window));
}


/*
  Reset transmit window to initial state; window_size == 1 and
  next_message_id == 0.
 */
void
ikev2_transmit_window_reset(
        SshIkev2TransmitWindow transmit_window)
{
    SSH_DEBUG(
            SSH_D_LOWOK,
            ("Transmit window %p: "
             "Reset; next_message_id %u -> %u; window_size %u -> %u.",
                     transmit_window,
                     transmit_window->next_message_id,
                     0,
                     transmit_window->window_size,
                     1));

    ikev2_transmit_window_flush(transmit_window);

    transmit_window->next_message_id = 0;
    transmit_window->window_size = 1;
}


/*
  Return true is transmit_window is full; false otherwise.
 */
bool
ikev2_transmit_window_full(
        SshIkev2TransmitWindow transmit_window)
{
    bool full = false;

    if (transmit_window->packets_head != NULL)
    {
        uint32_t window_size;

        window_size =
            transmit_window->next_message_id
            - transmit_window->packets_head->message_id;

        SSH_ASSERT(window_size <= transmit_window->window_size);

        if (window_size == transmit_window->window_size)
        {
            full = true;
        }
    }

    SSH_DEBUG(
            SSH_D_LOWOK,
            ("Transmit window %p: "
             "Window is %s.",
                     transmit_window,
                     (full ? "full" : "not full")));

    return full;
}


/*
  Assign next_message_id to packet and insert the packet to transmit
  window. On success return SSH_IKEV2_ERROR_OK. Fails when window is
  full returning SSH_IKEV2_ERROR_WINDOW_FULL.
 */
SshIkev2Error
ikev2_transmit_window_insert(
        SshIkev2TransmitWindow transmit_window,
        SshIkev2Packet packet)
{
    SshIkev2Error result = SSH_IKEV2_ERROR_OK;

    if (transmit_window->packets_head == NULL)
    {
        packet->message_id = transmit_window->next_message_id;

        ++transmit_window->next_message_id;

        transmit_window->packets_head = packet;
        transmit_window->packets_tail = packet;
        packet->window_next = NULL;
    }
    else
    {
        uint32_t window_size;

        window_size =
            transmit_window->next_message_id
            - transmit_window->packets_head->message_id;

        SSH_ASSERT(window_size <= transmit_window->window_size);

        if (window_size == transmit_window->window_size)
        {
            SSH_DEBUG(
                    SSH_D_LOWOK,
                    ("Transmit window %p: "
                     "Inserting packet %p failed.",
                             transmit_window,
                             packet));

            result = SSH_IKEV2_ERROR_WINDOW_FULL;
        }
        else
        {
            packet->message_id = transmit_window->next_message_id;

            ++transmit_window->next_message_id;

            transmit_window->packets_tail->window_next = packet;
            transmit_window->packets_tail = packet;
            packet->window_next = NULL;
        }
    }

    if (result == SSH_IKEV2_ERROR_OK)
    {
        SSH_DEBUG(
                SSH_D_LOWOK,
                ("Transmit window %p: "
                 "Inserted packet %p with message_id %u.",
                         transmit_window,
                         packet,
                         packet->message_id));

        packet->in_window = 1;
    }

    return result;
}


/*
   Find a request packet with given message_id from transmit window
   and return pointer to if found. Otherwise, return NULL.
 */
SshIkev2Packet
ikev2_transmit_window_find_request(
        SshIkev2TransmitWindow transmit_window,
        SshIkev2Packet packet)
{
    uint32_t message_id = packet->message_id;
    SshIkev2Packet request_packet;

    for (request_packet = transmit_window->packets_head;
         request_packet != NULL && request_packet->message_id != message_id;
         request_packet = request_packet->window_next)
      ;

    if (request_packet == NULL)
    {
        SSH_DEBUG(
                SSH_D_LOWOK,
                ("Transmit window %p: No packet with message_id %u.",
                         transmit_window,
                         message_id));
    }
    else if (request_packet->sent == 0)
    {
        SSH_DEBUG(
                SSH_D_LOWOK,
                ("Transmit window %p: "
                 "Found packet %p with message_id %u; packet not sent yet.",
                         transmit_window,
                         request_packet,
                         message_id));
        request_packet = NULL;
    }
    else if (packet->fragment == 1)
    {
        if (request_packet->reassemble_packet == NULL)
        {
            SSH_DEBUG(
                    SSH_D_LOWOK,
                    ("Transmit window %p: "
                     "packet %p message_id %u fragment %u is first fragment",
                             transmit_window,
                             packet,
                             message_id,
                             packet->message->fragment_number));
        }
        else if (ikev2_window_is_new_fragment(
                         request_packet->reassemble_packet,
                         packet)
                 == true)
        {
            SSH_DEBUG(
                    SSH_D_LOWOK,
                    ("Transmit window %p: "
                     "packet %p message_id %u fragment %u is new fragment",
                             transmit_window,
                             packet,
                             message_id,
                             packet->message->fragment_number));
        }
        else
        {
            SSH_DEBUG(
                    SSH_D_LOWOK,
                    ("Transmit window %p: "
                     "packet %p message_id %u fragment %u is already received",
                             transmit_window,
                             packet,
                             message_id,
                             packet->message->fragment_number));
            request_packet = NULL;
        }
    }
    else
    {
        SSH_DEBUG(
                SSH_D_LOWOK,
                ("Transmit window %p: "
                 "Returning packet %p with message_id %u.",
                         transmit_window,
                         request_packet,
                         message_id));
    }

    return request_packet;
}


/*
  Remove request from transmit window. Return pointer to request in
  successful case, otherwise NULL.
 */
static SshIkev2Packet
ikev2_transmit_window_remove_request(
        SshIkev2TransmitWindow transmit_window,
        uint32_t message_id)
{
    SshIkev2Packet packet;
    SshIkev2Packet packet_predecessor = NULL;

    for (packet = transmit_window->packets_head;
         packet != NULL && packet->message_id != message_id;
         packet = packet->window_next)
    {
        packet_predecessor = packet;
    }

    if (packet)
    {
        if (packet == transmit_window->packets_head)
        {
            transmit_window->packets_head = packet->window_next;
        }
        else
        {
            packet_predecessor->window_next = packet->window_next;
        }

        if (packet == transmit_window->packets_tail)
        {
            transmit_window->packets_tail = packet_predecessor;
        }
    }

    return packet;
}


/*
  Acknowledge given message id to transmit window. This is to be
  called after a response is considered authentic. If a request with
  the same message_id is found within the window it will be removed
  from the window and true is returned. If the message_id acknowledge
  was the smallest message_id in the window the window can accept more
  packets after the call.

  If no request packet with the message_id is found function returns
  false denoting that the request had already been acknowledged with a
  valid response and any new response is likely to be a fast
  retransmit and should not be processed any further.
*/
bool
ikev2_transmit_window_acknowledge(
        SshIkev2TransmitWindow transmit_window,
        uint32_t message_id)
{
    bool result = false;
    SshIkev2Packet packet;

    packet = ikev2_transmit_window_remove_request(transmit_window, message_id);

    if (packet)
    {
        ikev2_window_packet_done(packet);
        result = true;
    }

    SSH_DEBUG(
            SSH_D_LOWOK,
            ("Transmit window %p: "
             "Acknowledging message_id %u: %s.",
                     transmit_window,
                     message_id,
                     result ? "success" : "no such request"));

    return result;
}


/*
  Removes all packets from the window and finishes them.
 */
void
ikev2_transmit_window_flush(
        SshIkev2TransmitWindow transmit_window)
{

    SSH_DEBUG(
            SSH_D_LOWOK,
            ("Transmit window %p: "
             "Flushing.",
                     transmit_window));

    ikev2_window_packet_list_done(transmit_window->packets_head);

    transmit_window->packets_head = NULL;
    transmit_window->packets_tail = NULL;
}


/*
   Frees all memory allocated by the window first flushing all packets
   from the window.
 */
void
ikev2_transmit_window_uninit(SshIkev2TransmitWindow transmit_window)
{
    SSH_DEBUG(SSH_D_LOWOK,
              ("Uninitialising transmit window %p", transmit_window));
    ikev2_transmit_window_flush(transmit_window);
}


/*
  Set new size for transmit window.
 */
SshIkev2Error
ikev2_transmit_window_set_size(
        SshIkev2TransmitWindow transmit_window,
        unsigned int newsize)
{
    if (newsize > SSH_IKEV2_MAX_WINDOW_SIZE)
    {
        newsize = SSH_IKEV2_MAX_WINDOW_SIZE;
    }

    if (newsize < transmit_window->window_size)
    {
        SSH_DEBUG(
                SSH_D_FAIL,
                ("Transmit window %p: "
                 "Failed to set window size from %u to %u.",
                         transmit_window,
                         transmit_window->window_size,
                         newsize));

        return SSH_IKEV2_ERROR_INVALID_ARGUMENT;
    }

    if (transmit_window->window_size == newsize)
    {
        /* Silently ignore setting to current value. */
        return SSH_IKEV2_ERROR_OK;
    }

    SSH_DEBUG(
            SSH_D_LOWOK,
            ("Transmit window %p: "
             "Set window size from %u to %u",
                     transmit_window,
                     transmit_window->window_size,
                     newsize));

    transmit_window->window_size = newsize;

    return SSH_IKEV2_ERROR_OK;
}


/*
  Activate reassembly of fragmented packet added to transmit window.
 */
static void
ikev2_transmit_window_activate_reassembly(
        SshIkev2Packet window_packet,
        SshIkev2Packet packet)
{
    SSH_ASSERT(packet->fragments_head == NULL);
    SSH_ASSERT(window_packet->reassemble_packet == NULL);

    /* Move fragment to fragment list. */
    packet->total_fragments = packet->message->total_fragments;
    packet->fragments_count = 1;
    packet->fragments_head = packet->message;
    packet->message = NULL;

    window_packet->reassemble_packet = packet;

    /* Packet now in window. */
    packet->in_window = 1;
}


/*
  Start reassembly of fragmented packet added to transmit window.
 */
static void
ikev2_transmit_window_start_reassembly(
        SshIkev2TransmitWindow transmit_window,
        SshIkev2Packet window_packet,
        SshIkev2Packet packet)
{
    SSH_DEBUG(
            SSH_D_LOWOK,
            ("Transmit window %p: reassembly started: "
             "packet %p message_id %u fragment %u.",
                     transmit_window,
                     packet,
                     packet->message_id,
                     packet->message->fragment_number));

    /* Activate reassembly. */
    ikev2_transmit_window_activate_reassembly(window_packet, packet);
}


/*
  Replaces an existing registered packet from the transmit window with
  a new packet. Thereafter activates reassembly with new packet.

  The function expects that there is a registered packet in the transmit
  window.
 */
static void
ikev2_transmit_window_restart_reassembly(
        SshIkev2TransmitWindow transmit_window,
        SshIkev2Packet window_packet,
        SshIkev2Packet packet)
{
    SSH_DEBUG(
            SSH_D_LOWOK,
            ("Transmit window %p: reassembly re-started: "
             "packet %p replaced with %p message_id %u fragment %u.",
                     transmit_window,
                     window_packet->reassemble_packet,
                     packet,
                     packet->message_id,
                     packet->message->fragment_number));

    /* All done for reassemble packet linked to window packet. */
    ikev2_window_reassemble_packet_done(window_packet);

    /* Activate reassembly for new packet. */
    ikev2_transmit_window_activate_reassembly(window_packet, packet);
}


/*
  End reassembly of fragmented packet stored in transmit window.
 */
static void
ikev2_transmit_window_end_reassembly(
        SshIkev2TransmitWindow transmit_window,
        SshIkev2Packet packet)
{
    SSH_DEBUG(
            SSH_D_LOWOK,
            ("Transmit window %p: reassembly ended: "
             "packet %p.",
             transmit_window,
             packet));

    /* All fragments should be received. */
    SSH_ASSERT(packet->total_fragments == packet->fragments_count);

    packet->all_fragments_received = 1;
}


/*
  Add new fragment to reassembly packet found in transmit window.
*/
static bool
ikev2_transmit_window_insert_fragment(
        SshIkev2TransmitWindow transmit_window,
        SshIkev2Packet packet,
        bool *first_fragment,
        SshIkev2Packet *reassemble_packet_ret)
{
    SshIkev2Message fragment = packet->message;
    uint32_t message_id = packet->message_id;
    SshIkev2Packet window_packet;
    SshIkev2Packet reassemble_packet;
    bool result;

    SSH_ASSERT(fragment != NULL);

    *first_fragment = false;
    *reassemble_packet_ret = NULL;

    /* Search packet from transmit window. */
    window_packet =
        ikev2_window_search(transmit_window->packets_head, message_id);
    if (window_packet == NULL)
    {
        SSH_DEBUG(
                SSH_D_LOWOK,
                ("Transmit window %p: reassembly failure: "
                 "message_id %u not found.",
                         transmit_window,
                         message_id));

        return false;
    }

    /* Get reassembled packet from window packet. */
    reassemble_packet = window_packet->reassemble_packet;

    /* Check if this is the first fragment. */
    if (reassemble_packet == NULL)
    {
        /* Start reassembly with new packet. */
        ikev2_transmit_window_start_reassembly(
                transmit_window,
                window_packet,
                packet);

        *first_fragment = true;

        return true;
    }

    /* RFC 7383, Section 2.6.

       If reassembling is not finished yet and the Total Fragments field
       in the received fragment is greater than the Total Fragments field
       in those fragments that are in the reassembling queue, the
       receiver MUST discard all received fragments and start the
       reassembly process over with just the received IKE Fragment
       message.
    */
    if (fragment->total_fragments > reassemble_packet->total_fragments)
    {
        /* Re-start reassembly with new packet. */
        ikev2_transmit_window_restart_reassembly(
                transmit_window,
                window_packet,
                packet);

        *first_fragment = true;

        return true;
    }

    /* Add new fragment to reassemble packet. */
    result = ikev2_window_continue_reassembly(reassemble_packet, packet);
    if (result == false)
    {
        return false;
    }

    /* End reassembly if this is the last fragment. */
    if (reassemble_packet->fragments_count
        >= reassemble_packet->total_fragments)
    {
        ikev2_transmit_window_end_reassembly(
                transmit_window, reassemble_packet);

        *reassemble_packet_ret = reassemble_packet;
    }

    return true;
}


/*
  Acknowledge reassembled packet to transmit window.
 */
static bool
ikev2_transmit_window_acknowledge_fragment(
        SshIkev2TransmitWindow transmit_window,
        SshIkev2Packet packet)
{
    SshIkev2Packet window_packet;
    uint32_t message_id = packet->message_id;

    /* Remove packet from transmit window. */
    window_packet =
        ikev2_transmit_window_remove_request(
                transmit_window,
                message_id);
    if (window_packet == NULL)
    {
        SSH_DEBUG(
                SSH_D_LOWOK,
                ("Transmit window %p: "
                 "Acknowledging reassembled packet %p message_id %u: "
                 "no such request.",
                         transmit_window,
                         packet,
                         message_id));

        return false;
    }

    /* Found window packet should always contain same reassembled packet
       than given in argument. */
    SSH_ASSERT(window_packet->reassemble_packet == packet);

    /* Remove reassembled packet from window packet.
       Thereafter packet is not in window anymore. */
    window_packet->reassemble_packet = NULL;
    packet->in_window = 0;

    /* Free fragments. */
    ikev2_message_free(&packet->fragments_head);

    /* All done for window packet. */
    ikev2_window_packet_done(window_packet);

    SSH_DEBUG(
            SSH_D_LOWOK,
            ("Transmit window %p: "
             "Acknowledging reassembled packet %p message_id %u: success.",
                     transmit_window,
                     packet,
                     message_id));

    return true;
}


/*
  Initialise a receive window.
 */
void
ikev2_receive_window_init(SshIkev2ReceiveWindow receive_window)
{
    receive_window->window_size = 1;
    receive_window->expected_id = 0;
    receive_window->packets_head = NULL;
    receive_window->packets_tail = NULL;
    SSH_DEBUG(SSH_D_LOWOK, ("Receive window %p initialised", receive_window));
}

/*
  Re-transmit response.
 */
static void
ikev2_receive_window_retransmit_response(
        SshIkev2ReceiveWindow receive_window,
        SshIkev2Packet window_packet,
        SshIkev2Packet request_packet)
{
    /*
      If we have a queue packet it is not a response yes, then
      the request packet is so fast retransmit that we are
      processing the originally received request i.e. the
      "window_packet".
    */

    ssh_log_event(
            window_packet->log_facility,
            SSH_LOG_INFORMATIONAL,
            "IKEv2 packet R(%@:%d <- %@:%d): mID=%u",
            ssh_ipaddr_render, request_packet->server->ip_address,
            (request_packet->use_natt ?
             request_packet->server->nat_t_local_port :
             request_packet->server->normal_local_port),
            ssh_ipaddr_render, request_packet->remote_ip,
            request_packet->remote_port,
            request_packet->message_id);

   if ((window_packet->flags & SSH_IKEV2_PACKET_FLAG_RESPONSE) == 0)
   {
       SSH_DEBUG(
               SSH_D_LOWOK,
               ("Receive window %p: "
                "packet %p message_id %u matched packet %p: "
                "no response ready yet.",
                receive_window,
                request_packet,
                request_packet->message_id,
                window_packet));
   }
   else if (window_packet->sent != 1)
   {
       SSH_DEBUG(
               SSH_D_LOWOK,
               ("Receive window %p: "
                "packet %p message_id %u matched packet %p: "
                "response not yet sent.",
                receive_window,
                request_packet,
                request_packet->message_id,
                window_packet));
   }
   else if (window_packet->last_retransmit_response ==
            monotonic_time_get())
   {
       SSH_DEBUG(
               SSH_D_NETGARB,
               ("Receive window %p: "
                "packet %p message_id %u matched packet %p: "
                "response not sent due to rate-limit.",
                receive_window,
                request_packet,
                request_packet->message_id,
                window_packet));
   }
   else
   {
       /* There is a response here already retransmit it */
       SSH_DEBUG(
               SSH_D_LOWOK,
               ("Receive window %p: "
                "packet %p message_id %u matched response %p: "
                "retransmitting.",
                receive_window,
                request_packet,
                request_packet->message_id,
                window_packet));

       window_packet->last_retransmit_response = monotonic_time_get();

       ikev2_udp_retransmit_response_packet(
               window_packet,
               request_packet->server,
               request_packet->remote_ip,
               request_packet->remote_port);

       ikev2_debug_message_out(request_packet->ike_sa, window_packet);
   }
}


/*
  Check if retransmit is required for a fragment and return true if it is
  true; false otherwise
 */
static bool
ikev2_receive_window_is_retransmit_required(
        SshIkev2Packet window_packet,
        SshIkev2Packet packet)
{
    SSH_ASSERT(packet->fragment == 1);

    /* Re-transmit is required only for fragments with fragment number 1. */
    if (packet->message->fragment_number == 1)
    {
        /* Check if all fragments are already received or window packet is
           not fragment. */
        if (window_packet->all_fragments_received == 1 ||
            window_packet->fragment == 0)
        {
            return true;
        }
    }

    return false;
}


/*
  Computes and stores a hash value of the encoded packet into the
  packet structure.

  Check request against current receive window. Return true, denoting
  new request, if packets message_id is within the window and no
  packet with the message_id is stored within the window.

  If a response packet with same message_id and same stored hash value
  is found the response is retransmitted and false is returned.

  If a request packet with same message_id and same stored hash value
  is found, false is returned. This case means that the request is
  being processed already and a response should be sent soon anyway.

  When false is returned the caller should drop the packet without
  further processing.
 */
bool
ikev2_receive_window_check_request(
        SshIkev2ReceiveWindow receive_window,
        SshIkev2Packet request_packet)
{
    SshIkev2Packet packet;

    SSH_ASSERT((request_packet->flags & SSH_IKEV2_PACKET_FLAG_RESPONSE) == 0);

    SSH_DEBUG(
            SSH_D_LOWOK,
            ("Receive window %p: "
             "Checking request packet %p message_id %u.",
                     receive_window,
                     request_packet,
                     request_packet->message_id));

    ikev2_window_packet_hash_compute(request_packet);

    for (packet = receive_window->packets_head;
         packet && packet->message_id != request_packet->message_id;
         packet = packet->window_next)
      ;

    if (packet)
    {
        bool pass = false;

        if (request_packet->fragment == 1)
        {
            if (ikev2_window_is_new_fragment(packet, request_packet))
            {
                SSH_DEBUG(
                        SSH_D_LOWOK,
                        ("Receive window %p: "
                         "packet %p message_id %u fragment %u is new fragment",
                                 receive_window,
                                 request_packet,
                                 request_packet->message_id,
                                 request_packet->message->fragment_number));

                pass = true;
            }
            else if (ikev2_receive_window_is_retransmit_required(
                             packet,
                             request_packet)
                     == false)
            {
                SSH_DEBUG(
                        SSH_D_LOWOK,
                        ("Receive window %p: "
                         "packet %p message_id %u fragment %u "
                         "doesn't require retransmit",
                                 receive_window,
                                 request_packet,
                                 request_packet->message_id,
                                 request_packet->message->fragment_number));
            }
            else
            {
                ikev2_receive_window_retransmit_response(
                        receive_window,
                        packet,
                        request_packet);
            }
        }
        else
        {
            /* Check if retransmit is required by checking equality of
               hash value. */
            if (ikev2_window_packet_hash_equal(packet, request_packet)
                == false)
            {
                SSH_DEBUG(
                        SSH_D_LOWOK,
                        ("Receive window %p: "
                         "packet %p message_id %u matched packet %p: "
                         "packet hash mismatch.",
                                 receive_window,
                                 request_packet,
                                 request_packet->message_id,
                                 packet));
            }
            else
            {
                ikev2_receive_window_retransmit_response(
                        receive_window,
                        packet,
                        request_packet);
            }

        }

        return pass;
    }

    if (request_packet->message_id < receive_window->expected_id)
    {
        SSH_DEBUG(
                SSH_D_LOWOK,
                ("Receive window %p: "
                 "packet %p message_id %u out of window: "
                 "old retransmit.",
                         receive_window,
                         request_packet,
                         request_packet->message_id));

        return false;
    }

    if (request_packet->message_id >=
        (receive_window->expected_id + receive_window->window_size))
    {
        SSH_DEBUG(
                SSH_D_LOWOK,
                ("Receive window %p: "
                 "packet %p message_id %u out of window: "
                 "future packet.",
                         receive_window,
                         request_packet,
                         request_packet->message_id));

        return false;
    }

    SSH_DEBUG(
            SSH_D_LOWOK,
            ("Receive window %p: "
             "packet %p message_id %u in window: new request.",
                     receive_window,
                     request_packet,
                     request_packet->message_id));

    return true;
}

/*
  Update expected id of receive window.
 */
static void
ikev2_receive_window_update_expected_id(
        SshIkev2ReceiveWindow receive_window)
{
    SshIkev2Packet packet;

    /*
       Find out what is the message id that we are expecting to receive
       next. The search will find either the top or the next "hole" in
       the window.
    */
    packet = receive_window->packets_head;
    while (packet)
    {
        if (packet->message_id == receive_window->expected_id)
        {
            /* We have the expected id start expecting next one */
            ++receive_window->expected_id;

            /* restart search; the packets are not ordered */
            packet = receive_window->packets_head;

            SSH_DEBUG(
                    SSH_D_LOWOK,
                    ("Receive window %p: "
                     "expected id now %u.",
                             receive_window,
                             receive_window->expected_id));
        }
        else
        {
            packet = packet->window_next;
        }
    }
}


/*
  Insert request to receive window.
 */
static void
ikev2_receive_window_insert_request(
        SshIkev2ReceiveWindow receive_window,
        SshIkev2Packet packet)
{
    /* Go through packets and drop response that now fall outside the window */
    if (receive_window->packets_head)
    {
        SshIkev2Packet *remove_p = &receive_window->packets_head;
        SshIkev2Packet tail = NULL;
        SshIkev2Packet packet;

        packet = *remove_p;
        while (packet)
        {
            if ((packet->message_id + receive_window->window_size) <
                packet->message_id)
            {
                *remove_p = packet->window_next;

                SSH_DEBUG(
                        SSH_D_LOWOK,
                        ("Receive window %p: "
                         "packet %p fell out of window.",
                                 receive_window,
                                 packet));

                ikev2_window_packet_done(packet);
            }
            else
            {
                tail = packet;
                remove_p = &packet->window_next;
            }

            packet = *remove_p;
        }

        receive_window->packets_tail = tail;
    }


    /* Add the registered request to tail of the window queue */
    if (receive_window->packets_head)
    {
        SSH_ASSERT(receive_window->packets_tail != NULL);

        receive_window->packets_tail->window_next = packet;
    }
    else
    {
        receive_window->packets_head = packet;
    }

    receive_window->packets_tail = packet;
    packet->window_next = NULL;

    /* Packet now in window. */
    packet->in_window = 1;
}

/*
   Called after the request has been verified as to be an authentic
   request and shall produce a response. This registration will cause
   ikev2_receive_window_check_request() to return false for possible
   fast retransmits of the packet thus getting them to be silently
   ignored until a response is inserted.

   As a side-effect the receive window moves and responses left
   outside are removed and freed.

   Returns true if registration was successful.

   Returns false if registration failed. A request with the same
   message_id already in the receive window. This can happen if two
   copies of the same request are received so closely that they both
   get through the ikev2_receive_window_check_request() call.
 */
bool
ikev2_receive_window_register_request(
        SshIkev2ReceiveWindow receive_window,
        SshIkev2Packet request_packet)
{
    SshIkev2Packet packet;

    SSH_ASSERT(request_packet->fragment == 0);

    /* check for existing packet with same message_id */
    for (packet = receive_window->packets_head;
         packet && packet->message_id != request_packet->message_id;
         packet = packet->window_next)
      ;

    if (packet)
    {
        SSH_DEBUG(
                SSH_D_LOWOK,
                ("Receive window %p: "
                 "request %p message_id %u registration failed: "
                 "a %s packet %p exists.",
                         receive_window,
                         request_packet,
                         request_packet->message_id,
                         ((packet->flags & SSH_IKEV2_PACKET_FLAG_RESPONSE)
                          != 0 ?
                          "response" : "request"),
                          packet));

        return false;
    }

    /* Insert request to receive window. */
    ikev2_receive_window_insert_request(receive_window, request_packet);

    /* Update the message id that we are expecting to receive next. */
    ikev2_receive_window_update_expected_id(receive_window);

    SSH_DEBUG(
            SSH_D_LOWOK,
            ("Receive window %p: "
             "request %p message_id %u %s registered successfully.",
                     receive_window,
                     request_packet,
                     request_packet->message_id,
                     (request_packet->fragment == 1) ? "first fragment" : ""));

    return true;
}



/*
  Replaces an existing registered request from the receive window with
  a response to the request.

  The packet hash from the request packet is copied to the response
  packet structure for comparison with possible retransmissions of the
  request.

  The function expects that there is a registered request packet in
  the receive window.
 */
void
ikev2_receive_window_insert_response(
        SshIkev2ReceiveWindow receive_window,
        SshIkev2Packet response_packet)
{
    SshIkev2Packet packet;
    SshIkev2Packet *replace_p;

    SSH_DEBUG(
            SSH_D_LOWOK,
            ("Receive window %p: "
             "inserting response %p message_id %u.",
                     receive_window,
                     response_packet,
                     response_packet->message_id));

    SSH_ASSERT(receive_window->packets_head != NULL);

    replace_p = &receive_window->packets_head;
    for (packet = receive_window->packets_head;
         packet->message_id != response_packet->message_id;
         packet = packet->window_next)
    {
        replace_p = &packet->window_next;
    }

    SSH_ASSERT(packet != NULL);

    ikev2_window_packet_hash_copy(response_packet, packet);

    *replace_p = response_packet;
    response_packet->window_next = packet->window_next;
    if (receive_window->packets_tail == packet)
    {
        receive_window->packets_tail = response_packet;
    }

    response_packet->in_window = 1;

    SSH_DEBUG(
            SSH_D_LOWOK,
            ("Receive window %p: "
             "request packet %p message_id %u done.",
                     receive_window,
                     packet,
                     packet->message_id));

    ikev2_window_packet_done(packet);
}


/*
  Set new size for receive window.
 */
SshIkev2Error
ikev2_receive_window_set_size(
        SshIkev2ReceiveWindow receive_window,
        unsigned int newsize)
{
    if (newsize > SSH_IKEV2_MAX_WINDOW_SIZE)
    {
        SSH_DEBUG(
                SSH_D_FAIL,
                ("Receive window %p: "
                 "Denying request to grow window "
                 "beyond hard limit of %d to %u",
                         receive_window,
                         SSH_IKEV2_MAX_WINDOW_SIZE,
                         newsize));

        return SSH_IKEV2_ERROR_INVALID_ARGUMENT;
    }

    if (newsize < receive_window->window_size)
    {
        SSH_DEBUG(
                SSH_D_FAIL,
                ("Receive window %p: "
                 "Denying request to reduce window from %u to %u.",
                         receive_window,
                         receive_window->window_size,
                         newsize));

        return SSH_IKEV2_ERROR_INVALID_ARGUMENT;
    }

    if (receive_window->window_size == newsize)
    {
        /* Silently ignore setting to current value. */
        return SSH_IKEV2_ERROR_OK;
    }

    SSH_DEBUG(
            SSH_D_LOWOK,
            ("Receive window %p: "
             "Setting window size from %u to %u.",
                     receive_window,
                     receive_window->window_size,
                     newsize));

    receive_window->window_size = newsize;

    return SSH_IKEV2_ERROR_OK;
}


/*
  Removes all fragmented packets from the window and finishes them.
 */
void
ikev2_receive_window_flush_fragments(
        SshIkev2ReceiveWindow receive_window)
{
    SshIkev2Packet packet;
    SshIkev2Packet *list_p;

    SSH_DEBUG(
            SSH_D_LOWOK,
            ("Receive window %p: "
             "Flushing fragments.",
                     receive_window));

    list_p = &receive_window->packets_head;
    for (packet = *list_p;
         packet != NULL;
         packet = *list_p)
    {
        if (packet->fragments_head != NULL)
        {
            *list_p = packet->window_next;
            packet->window_next = NULL;

            ikev2_window_packet_done(packet);
        }
        else
        {
            list_p = &packet->window_next;
        }
    }
}


/*
  Free receive window and it's packets.
 */
void
ikev2_receive_window_uninit(
        SshIkev2ReceiveWindow receive_window)
{
    SSH_DEBUG(SSH_D_LOWOK,
              ("Uninitialising receive window %p", receive_window));
    ikev2_window_packet_list_done(receive_window->packets_head);
}


/*
  Activate reassembly of fragmented packet added to receive window.
 */
static void
ikev2_receive_window_activate_reassembly(
        SshIkev2Packet packet)
{
    SSH_ASSERT(packet->fragments_head == NULL);

    /* Move message to fragment list. */
    packet->total_fragments = packet->message->total_fragments;
    packet->fragments_count = 1;
    packet->fragments_head = packet->message;
    packet->message = NULL;
}


/*
  Start reassembly of fragmented packet added to receive window.
 */
static void
ikev2_receive_window_start_reassembly(
        SshIkev2ReceiveWindow receive_window,
        SshIkev2Packet packet)
{
    SSH_DEBUG(
            SSH_D_LOWOK,
            ("Receive window %p: reassembly started: "
             "packet %p message_id %u fragment %u.",
                     receive_window,
                     packet,
                     packet->message_id,
                     packet->message->fragment_number));


    /* Insert packet containing first fragment to receive window and
       activate reassembly. */
    ikev2_receive_window_insert_request(receive_window, packet);
    ikev2_receive_window_activate_reassembly(packet);
}

/*
  Replaces an existing registered request from the receive window with
  a new request. Thereafter activates reassembly with new packet.

  The function expects that there is a registered request packet in
  the receive window.
 */
static void
ikev2_receive_window_restart_reassembly(
        SshIkev2ReceiveWindow receive_window,
        SshIkev2Packet packet)
{
    SshIkev2Packet reassemble_packet;
    SshIkev2Packet *replace_p;

    SSH_ASSERT(receive_window->packets_head != NULL);

    replace_p = &receive_window->packets_head;
    for (reassemble_packet = receive_window->packets_head;
         reassemble_packet->message_id != packet->message_id;
         reassemble_packet = reassemble_packet->window_next)
    {
        replace_p = &reassemble_packet->window_next;
    }

    SSH_ASSERT(reassemble_packet != NULL);

    *replace_p = packet;
    packet->window_next = reassemble_packet->window_next;
    if (receive_window->packets_tail == reassemble_packet)
    {
        receive_window->packets_tail = packet;
    }

    SSH_DEBUG(
            SSH_D_LOWOK,
            ("Receive window %p: reassembly re-started: "
             "packet %p replaced with %p message_id %u fragment %u.",
                     receive_window,
                     reassemble_packet,
                     packet,
                     packet->message_id,
                     packet->message->fragment_number));

    /* All done for previously reassembled packet. */
    ikev2_window_packet_done(reassemble_packet);

    /* Activate reassembly for new packet. */
    ikev2_receive_window_activate_reassembly(packet);

    /* New packet now in window. */
    packet->in_window = 1;
}


/*
  End reassembly of fragmented packet stored in receive window.
 */
static void
ikev2_receive_window_end_reassembly(
        SshIkev2ReceiveWindow receive_window,
        SshIkev2Packet packet)
{
    SSH_DEBUG(
            SSH_D_LOWOK,
            ("Receive window %p: reassembly ended: "
             "packet %p message_id %u.",
                     receive_window,
                     packet,
                     packet->message_id));

    /* All fragments should be received. */
    SSH_ASSERT(packet->total_fragments == packet->total_fragments);

    packet->all_fragments_received = 1;

    /* Update the message id that we are expecting to receive
       next when all fragments belonging to this message id are
       received. */
    ikev2_receive_window_update_expected_id(receive_window);
}


/*
  Add new fragment to reassembly packet found in receive window.
 */
static bool
ikev2_receive_window_insert_fragment(
        SshIkev2ReceiveWindow receive_window,
        SshIkev2Packet packet,
        bool *first_fragment,
        SshIkev2Packet *reassemble_packet_ret)
{
    SshIkev2Message fragment = packet->message;
    uint32_t message_id = packet->message_id;
    SshIkev2Packet reassemble_packet;
    bool result;

    SSH_ASSERT(fragment != NULL);
    SSH_ASSERT(packet->fragment == 1);

    *first_fragment = false;
    *reassemble_packet_ret = NULL;

    /* Check if reassemble packet can be found from receive window. */
    reassemble_packet =
        ikev2_window_search(receive_window->packets_head, message_id);
    if (reassemble_packet == NULL)
    {
        /* Reassemble packet not found so this must be the first fragment.
           Therefore start reassembly. */
        ikev2_receive_window_start_reassembly(receive_window, packet);

        *first_fragment = true;

        return true;
    }

    SSH_ASSERT(reassemble_packet->fragments_head != NULL);

    /* RFC 7383, Section 2.6.

       If reassembling is not finished yet and the Total Fragments field
       in the received fragment is greater than the Total Fragments field
       in those fragments that are in the reassembling queue, the
       receiver MUST discard all received fragments and start the
       reassembly process over with just the received IKE Fragment
       message.
    */
    if (fragment->total_fragments > reassemble_packet->total_fragments)
    {
        /* Re-start reassembly with new packet. */
        ikev2_receive_window_restart_reassembly(receive_window, packet);

        *first_fragment = true;

        return true;
    }

    /* Add new fragment to receive window. */
    result = ikev2_window_continue_reassembly(reassemble_packet, packet);
    if (result == false)
    {
        return false;
    }

    /* Check if this is the last fragment. */
    if (reassemble_packet->fragments_count >=
        reassemble_packet->total_fragments)
    {
        ikev2_receive_window_end_reassembly(receive_window, reassemble_packet);

        *reassemble_packet_ret = reassemble_packet;
    }

    return true;
}


/*
  Acknowledge reassembled packet from receive window.
 */
static bool
ikev2_receive_window_acknowledge_fragment(
        SshIkev2ReceiveWindow receive_window,
        SshIkev2Packet packet)
{
    /* Free fragments. */
    ikev2_message_free(&packet->fragments_head);

    return true;
}


/*
  Function will insert new fragment to receive or transmit window.

  If fragment is the first one 'first_fragment' is set to true and
  otherwise it will be false. If fragment is the last one function
  will return reassembled packet in 'reassemble_packet_ret' and
  otherwise it will be NULL.
 */
bool
ikev2_window_insert_fragment(
        SshIkev2Packet packet,
        bool *first_fragment,
        SshIkev2Packet *reassemble_packet_ret)
{
    SshIkev2Sa ike_sa = packet->ike_sa;
    bool result;

    SSH_ASSERT(packet->fragment == 1);

    if ((packet->flags & SSH_IKEV2_PACKET_FLAG_RESPONSE) != 0)
    {
        SshIkev2TransmitWindow transmit_window = ike_sa->transmit_window;

        result =
            ikev2_transmit_window_insert_fragment(
                    transmit_window,
                    packet,
                    first_fragment,
                    reassemble_packet_ret);
    }
    else
    {
        SshIkev2ReceiveWindow receive_window = ike_sa->receive_window;

        result =
            ikev2_receive_window_insert_fragment(
                    receive_window,
                    packet,
                    first_fragment,
                    reassemble_packet_ret);
    }

    return result;
}


/*
  Function wil acknowledge reassembled packet from receive or transmit window.
 */
bool
ikev2_window_acknowledge_fragment(
        SshIkev2Packet packet)
{
    SshIkev2Sa ike_sa = packet->ike_sa;
    bool result;

    SSH_ASSERT(packet->fragment == 1);

    if ((packet->flags & SSH_IKEV2_PACKET_FLAG_RESPONSE) != 0)
    {
        SshIkev2TransmitWindow transmit_window = ike_sa->transmit_window;

        result =
            ikev2_transmit_window_acknowledge_fragment(
                    transmit_window,
                    packet);
    }
    else
    {
        SshIkev2ReceiveWindow receive_window = ike_sa->receive_window;

        result =
            ikev2_receive_window_acknowledge_fragment(
                    receive_window,
                    packet);
    }

    return result;
}


#ifdef SSHDIST_IKE_MOBIKE

/*
  Change server of the packet.
*/
static void
ikev2_window_packet_change_server(
        SshIkev2Packet packet,
        SshIkev2Server server)
{
    if (packet->server != server)
    {
        packet->server = server;
        if (packet->ed)
        {
            packet->ed->multiple_addresses_used = 1;
        }
    }
}


/*
  Change server of all packets in transmit and receive windows of
  given ike_sa.
 */
void
ikev2_window_change_server(
        SshIkev2Sa ike_sa,
        SshIkev2Server server)
{
    SshIkev2Packet packet;

    for (packet = ike_sa->transmit_window->packets_head;
         packet != NULL;
         packet = packet->window_next)
    {
        SSH_DEBUG(
                SSH_D_NICETOKNOW,
                ("Transmit window %p: "
                 "Packet %p from server %p to server %p",
                         ike_sa->transmit_window,
                         packet,
                         packet->server,
                         server));

        ikev2_window_packet_change_server(packet, server);
    }

    for (packet = ike_sa->receive_window->packets_head;
         packet != NULL;
         packet = packet->window_next)
    {
        SSH_DEBUG(
                SSH_D_NICETOKNOW,
                ("Receive window %p: "
                 "Packet %p from server %p to server %p",
                         ike_sa->receive_window,
                         packet,
                         packet->server,
                         server));

        ikev2_window_packet_change_server(packet, server);
    }
}

#endif /* SSHDIST_IKE_MOBIKE */


/*
  Set retransmit counter of all packet in the transmit window of a
  given ike_sa.
 */
void
ikev2_window_set_retransmit_count(
        SshIkev2Sa ike_sa,
        uint16_t retransmit_counter)
{
    SshIkev2Packet packet;

    SSH_DEBUG(
            SSH_D_NICETOKNOW,
            ("Transmit window %p: "
             "Setting retransmit count to %d on IKE SA %p",
                     ike_sa->transmit_window,
                     (int) retransmit_counter,
                     ike_sa));


    for (packet = ike_sa->transmit_window->packets_head;
         packet != NULL;
         packet = packet->window_next)
    {
        if (packet->retransmit_counter < retransmit_counter)
        {
            packet->retransmit_counter = retransmit_counter;
        }
    }
}

/* eof */
