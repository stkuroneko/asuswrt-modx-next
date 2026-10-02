/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   Peer information database.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"

#include "ipsec_sa.h"

#define SSH_DEBUG_MODULE "SshPmPeer"

/************************* Definitions **************************************/

#define SSH_PM_PEER_HANDLE_HASH(peer_handle) \
((peer_handle) % SSH_PM_PEER_HANDLE_HASH_TABLE_SIZE)

#define SSH_PM_PEER_IKE_SA_HASH(ike_sa_handle) \
((ike_sa_handle) % SSH_PM_PEER_IKE_SA_HASH_TABLE_SIZE)

#define SSH_PM_PEER_LOCAL_ADDR_HASH(local_ip) \
(SSH_IP_HASH((local_ip)) % SSH_PM_PEER_ADDR_HASH_TABLE_SIZE)

#define SSH_PM_PEER_REMOTE_ADDR_HASH(remote_ip) \
(SSH_IP_HASH((remote_ip)) % SSH_PM_PEER_ADDR_HASH_TABLE_SIZE)

#define SSH_PM_PEER_TUNNEL_ID_HASH(tunnel_id) \
    ((tunnel_id) % SSH_PM_PEER_TUNNEL_ID_HASH_TABLE_SIZE)

#define SSH_PM_PEER_DEBUG_CONNECTION_SHOWN 1
#define SSH_PM_PEER_DEBUG_IKE_SA_CHANGED 2

/************************* Peer hashtable handling **************************/

static void
pm_peer_handle_hash_insert(SshPm pm, SshPmPeer peer)
{
    uint32_t hash;

    SSH_ASSERT(peer != NULL);
    SSH_ASSERT(peer->peer_handle != SSH_IPSEC_INVALID_INDEX);

    hash = SSH_PM_PEER_HANDLE_HASH(peer->peer_handle);

    peer->next_peer_handle = pm->peer_handle_hash[hash];
    if (peer->next_peer_handle)
      peer->next_peer_handle->prev_peer_handle = peer;
    pm->peer_handle_hash[hash] = peer;
}

static void
pm_peer_handle_hash_remove(SshPm pm, SshPmPeer peer)
{
    uint32_t hash;

    SSH_ASSERT(peer != NULL);
    SSH_ASSERT(peer->peer_handle != SSH_IPSEC_INVALID_INDEX);

    if (peer->next_peer_handle)
      peer->next_peer_handle->prev_peer_handle = peer->prev_peer_handle;
    if (peer->prev_peer_handle)
      peer->prev_peer_handle->next_peer_handle = peer->next_peer_handle;
    else
    {
        hash = SSH_PM_PEER_HANDLE_HASH(peer->peer_handle);
        SSH_ASSERT(pm->peer_handle_hash[hash] == peer);
        pm->peer_handle_hash[hash] = peer->next_peer_handle;
    }

    peer->next_peer_handle = NULL;
    peer->prev_peer_handle = NULL;
}

static void
pm_peer_sa_hash_insert(SshPm pm, SshPmPeer peer)
{
    uint32_t hash;

    SSH_ASSERT(peer != NULL);

    hash = SSH_PM_PEER_IKE_SA_HASH(peer->ike_sa_handle);

    peer->next_sa_handle = pm->peer_sa_hash[hash];
    if (peer->next_sa_handle)
      peer->next_sa_handle->prev_sa_handle = peer;
    pm->peer_sa_hash[hash] = peer;
}

static void
pm_peer_sa_hash_remove(SshPm pm, SshPmPeer peer)
{
    uint32_t hash;

    SSH_ASSERT(peer != NULL);

    if (peer->next_sa_handle)
      peer->next_sa_handle->prev_sa_handle = peer->prev_sa_handle;
    if (peer->prev_sa_handle)
      peer->prev_sa_handle->next_sa_handle = peer->next_sa_handle;
    else
    {
        hash = SSH_PM_PEER_IKE_SA_HASH(peer->ike_sa_handle);
        SSH_ASSERT(pm->peer_sa_hash[hash] == peer);
        pm->peer_sa_hash[hash] = peer->next_sa_handle;
    }

    peer->next_sa_handle = NULL;
    peer->prev_sa_handle = NULL;
}

static void
pm_peer_local_addr_hash_insert(SshPm pm, SshPmPeer peer)
{
    uint32_t hash;

    SSH_ASSERT(peer != NULL);

    hash = SSH_PM_PEER_LOCAL_ADDR_HASH(peer->local_ip);

    peer->next_local_addr = pm->peer_local_addr_hash[hash];
    if (peer->next_local_addr)
      peer->next_local_addr->prev_local_addr = peer;
    pm->peer_local_addr_hash[hash] = peer;
}

static void
pm_peer_local_addr_hash_remove(SshPm pm, SshPmPeer peer)
{
    uint32_t hash;

    SSH_ASSERT(peer != NULL);

    if (peer->next_local_addr)
      peer->next_local_addr->prev_local_addr = peer->prev_local_addr;
    if (peer->prev_local_addr)
      peer->prev_local_addr->next_local_addr = peer->next_local_addr;
    else
    {
        hash = SSH_PM_PEER_LOCAL_ADDR_HASH(peer->local_ip);
        SSH_ASSERT(pm->peer_local_addr_hash[hash] == peer);
        pm->peer_local_addr_hash[hash] = peer->next_local_addr;
    }

    peer->next_local_addr = NULL;
    peer->prev_local_addr = NULL;
}

static void
pm_peer_remote_addr_hash_insert(SshPm pm, SshPmPeer peer)
{
    uint32_t hash;

    SSH_ASSERT(peer != NULL);

    hash = SSH_PM_PEER_REMOTE_ADDR_HASH(peer->remote_ip);

    peer->next_remote_addr = pm->peer_remote_addr_hash[hash];
    if (peer->next_remote_addr)
      peer->next_remote_addr->prev_remote_addr = peer;
    pm->peer_remote_addr_hash[hash] = peer;
}

static void
pm_peer_remote_addr_hash_remove(SshPm pm, SshPmPeer peer)
{
    uint32_t hash;

    SSH_ASSERT(peer != NULL);

    if (peer->next_remote_addr)
      peer->next_remote_addr->prev_remote_addr = peer->prev_remote_addr;
    if (peer->prev_remote_addr)
      peer->prev_remote_addr->next_remote_addr = peer->next_remote_addr;
    else
    {
        hash = SSH_PM_PEER_REMOTE_ADDR_HASH(peer->remote_ip);
        SSH_ASSERT(pm->peer_remote_addr_hash[hash] == peer);
        pm->peer_remote_addr_hash[hash] = peer->next_remote_addr;
    }

    peer->next_remote_addr = NULL;
    peer->prev_remote_addr = NULL;
}

static void
pm_peer_tunnel_id_hash_insert(SshPm pm, SshPmPeer peer)
{
    uint32_t hash;

    SSH_ASSERT(peer != NULL);
    SSH_ASSERT(peer->peer_handle != SSH_IPSEC_INVALID_INDEX);

    hash = SSH_PM_PEER_HANDLE_HASH(peer->tunnel_id);

    peer->next_tunnel_id = pm->peer_tunnel_id_hash[hash];
    if (peer->next_tunnel_id)
      peer->next_tunnel_id->prev_tunnel_id = peer;
    pm->peer_tunnel_id_hash[hash] = peer;
}

static void
pm_peer_tunnel_id_hash_remove(SshPm pm, SshPmPeer peer)
{
    uint32_t hash;

    SSH_ASSERT(peer != NULL);
    SSH_ASSERT(peer->peer_handle != SSH_IPSEC_INVALID_INDEX);

    if (peer->next_tunnel_id)
      peer->next_tunnel_id->prev_tunnel_id = peer->prev_tunnel_id;
    if (peer->prev_tunnel_id)
      peer->prev_tunnel_id->next_tunnel_id = peer->next_tunnel_id;
    else
    {
        hash = SSH_PM_PEER_TUNNEL_ID_HASH(peer->tunnel_id);
        SSH_ASSERT(pm->peer_tunnel_id_hash[hash] == peer);
        pm->peer_tunnel_id_hash[hash] = peer->next_tunnel_id;
    }

    peer->next_tunnel_id = NULL;
    peer->prev_tunnel_id = NULL;
}

/************************* Peer reference counting ***************************/

static void
pm_peer_take_ref(SshPmPeer peer)
{
    SSH_ASSERT(peer != NULL);
    peer->refcnt++;
    SSH_DEBUG(SSH_D_LOWOK, ("Taking reference to peer 0x%lx, refcnt %d",
                            (unsigned long) peer->peer_handle, peer->refcnt));
}

/**************************** Peer lookup ***********************************/

SshPmPeer
ssh_pm_peer_by_handle(SshPm pm, uint32_t peer_handle)
{
    SshPmPeer peer;
    uint32_t hash;

    if (peer_handle == SSH_IPSEC_INVALID_INDEX)
      return NULL;

    hash = SSH_PM_PEER_HANDLE_HASH(peer_handle);
    for (peer = pm->peer_handle_hash[hash];
         peer != NULL;
         peer = peer->next_peer_handle)
    {
        if (peer->peer_handle == peer_handle)
          return peer;
    }

    return NULL;
}

/** Iterating through peers that use IKE SA `ike_sa_handle'. */

SshPmPeer
ssh_pm_peer_by_ike_sa_handle(SshPm pm, uint32_t ike_sa_handle)
{
    SshPmPeer peer;
    uint32_t hash;

    hash = SSH_PM_PEER_IKE_SA_HASH(ike_sa_handle);
    for (peer = pm->peer_sa_hash[hash];
         peer != NULL;
         peer = peer->next_sa_handle)
    {
        if (peer->ike_sa_handle == ike_sa_handle)
          return peer;
    }

    return NULL;
}

SshPmPeer
ssh_pm_peer_next_by_ike_sa_handle(SshPm pm, SshPmPeer peer)
{
    SshPmPeer next_peer;

    if (peer == NULL)
      return NULL;

    for (next_peer = peer->next_sa_handle;
         next_peer != NULL;
         next_peer = next_peer->next_sa_handle)
    {
        if (next_peer->ike_sa_handle == peer->ike_sa_handle)
          return next_peer;
    }

    return NULL;
}

SshPmPeer
ssh_pm_peer_by_p1(SshPm pm, SshPmP1 p1)
{
    SSH_ASSERT(p1 != NULL);
    return ssh_pm_peer_by_ike_sa_handle(pm, SSH_PM_IKE_SA_INDEX(p1));
}

uint32_t
ssh_pm_peer_handle_by_p1(SshPm pm, SshPmP1 p1)
{
    SshPmPeer peer;

    SSH_ASSERT(p1 != NULL);
    peer = ssh_pm_peer_by_p1(pm, p1);
    if (peer)
      return peer->peer_handle;

    return SSH_IPSEC_INVALID_INDEX;
}

static SshPmPeer
pm_peer_next_by_tunnel_id(SshPm pm, SshPmPeer peer, uint32_t tunnel_id)
{
    SshPmPeer next;

    if (peer == NULL)
    {
        uint32_t hash;

        hash = SSH_PM_PEER_TUNNEL_ID_HASH(tunnel_id);

        next = pm->peer_tunnel_id_hash[hash];
    }
    else
    {
        next = peer->next_tunnel_id;
    }

    while (next != NULL)
    {
        if (next->tunnel_id == tunnel_id)
        {
            break;
        }

        next = next->next_tunnel_id;
    }

    return next;
}

SshPmPeer
ssh_pm_peer_next_by_tunnel_id(SshPm pm, SshPmPeer peer)
{
    return pm_peer_next_by_tunnel_id(pm, peer, peer->tunnel_id);
}

SshPmPeer
ssh_pm_peer_first_by_tunnel_id(SshPm pm, uint32_t tunnel_id)
{
    return pm_peer_next_by_tunnel_id(pm, NULL, tunnel_id);
}

SshPmPeer
ssh_pm_peer_first_by_remote_address(SshPm pm, SshIpAddr remote_ip)
{
    uint32_t hash;
    SshPmPeer peer;

    hash = SSH_PM_PEER_REMOTE_ADDR_HASH(remote_ip);

    peer = pm->peer_remote_addr_hash[hash];
    while (peer != NULL)
    {
        if (SSH_IP_CMP(peer->remote_ip, remote_ip) == 0)
        {
            break;
        }

        peer = peer->next_remote_addr;
    }

    return peer;
}

SshPmP1
ssh_pm_p1_by_peer_handle(SshPm pm, uint32_t peer_handle)
{
    SshPmPeer peer;

    peer = ssh_pm_peer_by_handle(pm, peer_handle);
    if (peer == NULL)
      return NULL;

    return ssh_pm_p1_from_ike_handle(pm, peer->ike_sa_handle, false);
}

SshPmPeer
ssh_pm_peer_lookup(SshPm pm,
                          SshIpAddr remote_ip, uint16_t remote_port,
                          SshIpAddr local_ip, uint16_t local_port,
                          SshIkev2PayloadID remote_id,
                          SshIkev2PayloadID local_id,
                          SshVriId routing_instance_id,
                          bool use_ikev1)
{
    SshPmPeer peer;
    uint32_t hash;

    /* Addresses are mandatory, ports and identities are optional. */
    SSH_ASSERT(remote_ip != NULL);
    SSH_ASSERT(local_ip != NULL);

    hash = SSH_PM_PEER_REMOTE_ADDR_HASH(remote_ip);
    for (peer = pm->peer_remote_addr_hash[hash];
         peer != NULL;
         peer = peer->next_remote_addr)
    {
        /* Match routing instance id. */
        if (routing_instance_id != peer->routing_instance_id)
          continue;

        /* Match remote address. */
        if (SSH_IP_EQUAL(peer->remote_ip, remote_ip) == false
            || (remote_port != 0 && peer->remote_port != remote_port))
          continue;

        /* Match local address. */
        if (SSH_IP_EQUAL(peer->local_ip, local_ip) == false
            || (local_port != 0 && peer->local_port != local_port))
          continue;

        /* Match identities. */
        if (remote_id != NULL
            && ssh_pm_ikev2_id_compare(remote_id, peer->remote_id) == false)
          continue;

        if (local_id != NULL
            && ssh_pm_ikev2_id_compare(local_id, peer->local_id) == false)
          continue;

        /* Match rest. */
        if (peer->use_ikev1 != use_ikev1)
          continue;

        /* We have a match. */
        return peer;
    }

    return NULL;
}

uint32_t
ssh_pm_peer_handle_lookup(SshPm pm,
                          SshIpAddr remote_ip, uint16_t remote_port,
                          SshIpAddr local_ip, uint16_t local_port,
                          SshIkev2PayloadID remote_id,
                          SshIkev2PayloadID local_id,
                          SshVriId routing_instance_id,
                          bool use_ikev1)
{
    SshPmPeer peer;

    peer =
        ssh_pm_peer_lookup(
                pm,
                remote_ip,
                remote_port,
                local_ip,
                local_port,
                remote_id,
                local_id,
                routing_instance_id,
                use_ikev1);

    if (peer != NULL)
    {
        return peer->peer_handle;
    }
    else
    {
        return SSH_IPSEC_INVALID_INDEX;
    }
}


uint32_t
ssh_pm_peer_handle_by_address(SshPm pm,
                              SshIpAddr remote_ip, uint16_t remote_port,
                              SshIpAddr local_ip, uint16_t local_port,
                              bool use_ikev1,
                              SshVriId routing_instance_id)
{
    return ssh_pm_peer_handle_lookup(pm, remote_ip, remote_port,
                                     local_ip, local_port, NULL, NULL,
                                     routing_instance_id,
                                     use_ikev1);
}

/** Iterating through peers that use `local_ip'. */

SshPmPeer
ssh_pm_peer_by_local_address(SshPm pm, SshIpAddr local_ip)
{
    SshPmPeer peer;

    for (peer =
             pm->peer_local_addr_hash[
                     SSH_PM_PEER_LOCAL_ADDR_HASH(local_ip)];
         peer != NULL;
         peer = peer->next_local_addr)
    {
        if (SSH_IP_EQUAL(peer->local_ip, local_ip))
          return peer;
    }

    return NULL;
}

SshPmPeer
ssh_pm_peer_next_by_local_address(SshPm pm, SshPmPeer peer)
{
    SshPmPeer next_peer;

    if (peer == NULL)
      return NULL;

    for (next_peer = peer->next_local_addr;
         next_peer != NULL;
         next_peer = next_peer->next_local_addr)
    {
        if (SSH_IP_EQUAL(next_peer->local_ip, peer->local_ip))
          return next_peer;
    }

    return NULL;
}

uint32_t
ssh_pm_peer_num_child_sas_by_p1(SshPm pm, SshPmP1 p1)
{
    uint32_t num_child_sas = 0;
    SshPmPeer peer = NULL;

    /* Count child SAs of all the peers having the given p1. */
    for (peer = ssh_pm_peer_by_p1(pm, p1);
         peer != NULL;
         peer = ssh_pm_peer_next_by_ike_sa_handle(pm, peer))
    {
        num_child_sas += peer->num_child_sas;
    }

    return num_child_sas;
}

static void
ssh_pm_peer_dpd_new_ikesa(
        SshPm pm,
        SshPmPeer peer,
        SshPmTunnel tunnel,
        const struct IPsecSaParams *sa_params)
{
    SshPmQm qm = NULL;
    SshPmRule pm_rule = NULL;
    const struct IPsecSaEndpoints *endpoints;

    qm = ssh_pm_qm_alloc(pm, true);
    if (qm == NULL)
    {
        ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_WARNING,
                "The maximum number of active Quick-Mode "
                "negotiations reached.  DPD not done");
        return;
    }

    /* Find the rule and endpoints to use in QM */
    pm_rule = ssh_pm_rule_lookup(pm, sa_params->rule_id);
    if (pm_rule == NULL)
    {
        SSH_DEBUG(
                SSH_D_FAIL,
                ("No rule found for peer %@",
                 ssh_ipaddr_render,
                 peer->remote_ip));
        return;
    }

    endpoints = ipsec_sa_get_endpoints(
            pm->ipsec_control,
            sa_params->inbound_spi);

    /* Fill up the QM */
    qm->peer_handle = peer->peer_handle;

    /* Take a reference to peer handle for protecting qm->peer_handle. */
    if (qm->peer_handle != SSH_IPSEC_INVALID_INDEX)
        ssh_pm_peer_handle_take_ref(pm, qm->peer_handle);

    qm->sa_handler_done = 1; /* No SA handler for empty INFO */
    qm->initiator = 1;
    qm->forward = 1;
    qm->rule = pm_rule;
    SSH_PM_RULE_LOCK(qm->rule);

    qm->tunnel = tunnel;
    SSH_PM_TUNNEL_TAKE_REF(qm->tunnel);

    qm->transform = tunnel->transform;

    in_addr_convert_to_sshipaddr(&endpoints->local_address, &qm->sel_src);
    in_addr_convert_to_sshipaddr(&endpoints->remote_address, &qm->sel_dst);

    qm->dpd = 1;
    qm->packet = NULL;

    /* Store SPI values and old SPI's, these will be used for marking
       the negotiation finished. */
    qm->old_inbound_spi = sa_params->inbound_spi;
    qm->old_outbound_spi = sa_params->outbound_spi;

    SSH_DEBUG(SSH_D_HIGHOK, ("DPD: Creating new IKEv1 SA"));

    /* Mark the SPI having a active negotiation. */
    if (ssh_pm_spi_mark_neg_started(
                pm, sa_params->outbound_spi,
                sa_params->inbound_spi) == true)
        qm->spi_neg_started = 1;
    else
        SSH_DEBUG(SSH_D_ERROR,
                ("Outbound SPI %08lx disappeared from spi table",
                 (unsigned long) sa_params->outbound_spi));

    /* Start a Quick-Mode initator thread from the initiator state
       after trigger processing. */
    ssh_fsm_thread_init(&pm->fsm, &qm->thread,
            ssh_pm_st_qm_i_start_negotiation,
            NULL_FNPTR,
            pm_qm_thread_destructor,
            qm);

    SSH_APE_MARK(1, ("IKEv1 SA has disappeared"));

    ssh_fsm_set_thread_name(&qm->thread, "DPD IKE create");
}


static void
ssh_pm_peer_send_dpd(
        void *context)
{
    SshPmPeer peer = (SshPmPeer) context;

    SshPm pm = peer->pm;
    SshPmP1 p1;
    SshIkev2ExchangeData ed;
    SshPmTunnel tunnel;
    int slot;
    MonotonicTime lastike;
    MonotonicTime now;

    SSH_ASSERT(peer != NULL);

    SSH_DEBUG(SSH_D_MIDOK,
            ("DPD for remote %@", ssh_ipaddr_render, peer->remote_ip));

    tunnel = ssh_pm_tunnel_get_by_id(pm, peer->tunnel_id);

    if (tunnel == NULL)
    {
        SSH_DEBUG(SSH_D_ERROR, ("No tunnel specified"));
        return;
    }

    ssh_register_timeout(
            &peer->idle_timeout,
            tunnel->u.ike.dpd_timeout,
            0,
            ssh_pm_peer_send_dpd,
            peer);


    p1 = ssh_pm_p1_by_peer_handle(pm, peer->peer_handle);

    /* Check Phase 1 state */
    if (p1 == NULL || p1->unusable == true)
    {
        /* IKEv1 expired SA case */
        const struct IPsecSaParams *sa_params;

        sa_params = ipsec_sa_first_by_peer_handle(
                pm->ipsec_control,
                peer->peer_handle);

        if (sa_params->ikev1_sa == false)
        {
            SSH_DEBUG(SSH_D_FAIL, ("IKEv2 SA not valid: cannot send DPD"));
            return;
        }

        /* Check if SPI has already an active negotiation going on. */
        if (ssh_pm_spi_neg_ongoing(pm, sa_params->outbound_spi,
                    sa_params->inbound_spi))
        {
            SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Outbound SPI %08lx already has an ongoing "
                     "negotiation, not sending DPD.",
                     (unsigned long) sa_params->outbound_spi));
            return;
        }
        /* Do blacklist check */
        if (peer && peer->enable_blacklist_check)
        {
            SshPmBlacklistCheckCode check_code
                = SSH_PM_BLACKLIST_CHECK_IKEV1_I_DPD_SA_CREATION;

            if (!ssh_pm_blacklist_check(pm,
                        peer->remote_id,
                        check_code))
            {
                /* IKE ID is in the blacklist. Don't do DPD. */
                return;
            }
        }

        SSH_DEBUG(
                SSH_D_HIGHOK,
                ("IKE SA phase 1 not found or unusable for peer %@",
                 ssh_ipaddr_render, peer->remote_ip));

        ssh_pm_peer_dpd_new_ikesa(pm, peer, tunnel, sa_params);
        return;
    }

    /* IKE SA is ok */
    now = monotonic_time_get();
    lastike = ssh_ikev2_sa_last_input_packet_time(p1->ike_sa);

    SSH_DEBUG(
            SSH_D_HIGHOK,
            ("DPD: Last IKE time: %d now: %d",
             monotonic_time_value(lastike),
             monotonic_time_value(now)));

    if ((now - lastike) < tunnel->u.ike.dpd_timeout)
    {
        SSH_DEBUG(
                SSH_D_HIGHOK,
                ("DPD: Recent IKE packet proofs remote being alive"));
        return;
    }

    if (ssh_pm_servers_select(
            pm,
            p1->ike_sa->server->ip_address,
            SSH_PM_SERVERS_MATCH_IKE_SERVER,
            p1->ike_sa->server,
            SSH_INVALID_IFNUM,
            p1->ike_sa->server->routing_instance_id) == NULL)
    {
        SSH_DEBUG(SSH_D_HIGHOK,
                    ("DPD: IKE server deletion is pending, "
                    "ignoring idle event"));
        return;
    }

    if (pm_ike_async_call_pending(p1->ike_sa))
    {
        SSH_DEBUG(SSH_D_HIGHOK, ("DPD not needed; IKE is active."));
        return;
    }

    if (!pm_ike_async_call_possible(p1->ike_sa, &slot))
    {
        SSH_DEBUG(SSH_D_HIGHOK, ("DPD not possible; IKE is busy."));
        return;
    }

    ed = ssh_ikev2_info_create(p1->ike_sa, 0);
    if (ed != NULL)
    {
        SshPmInfo info =
            ssh_pm_info_alloc(
                pm,
                ed,
                SSH_PM_ED_DATA_INFO_DPD);
        if (info == NULL)
        {
            SSH_DEBUG(SSH_D_FAIL, ("Cannot allocate PmInfo"));
            ssh_ikev2_info_destroy(ed);
            return;
        }
        SSH_APE_MARK(2, ("DPD started"));

        /* Failure to transmit informational exchange will result
            into deletion of IKE SA. Therefore we do not need to
            worry about it. */
        ed->application_context = info;
        PM_IKE_ASYNC_CALL(
                p1->ike_sa,
                ed,
                slot,
                ssh_ikev2_info_send(
                    ed,
                    pm_ike_info_done_callback));
    }
    else
    {
        SSH_DEBUG(
                SSH_D_FAIL,
                ("Cannot create Exchange Data for SA %p. DPD not sent.",
                 p1->ike_sa));
    }
}


/********************* Peer creation / destruction **************************/

uint32_t
ssh_pm_peer_create_internal(
        SshPm pm,
        uint32_t tunnel_id,
        SshIpAddr remote_ip,
        uint16_t remote_port,
        SshIpAddr local_ip,
        uint16_t local_port,
        SshIkev2PayloadID local_id,
        SshIkev2PayloadID remote_id,
        uint32_t ike_sa_handle,
        SshVriId routing_instance_id,
        uint32_t flags,
        bool force_ikev1_natt_draft_02)
{
    uint32_t peer_handle, i;
    SshPmPeer peer;
    SshPmTunnel tunnel;

    SSH_ASSERT(remote_ip != NULL);
    SSH_ASSERT(SSH_IP_DEFINED(remote_ip));
    SSH_ASSERT(remote_port != 0);

    for (i = 0; i < SSH_PM_MAX_PEER_HANDLES; i++)
    {
        /* Select the next free peer_handle. */
        peer_handle = ++pm->next_peer_handle;
        if (pm->next_peer_handle >= SSH_PM_MAX_PEER_HANDLES)
          pm->next_peer_handle = 1;

        if (ssh_pm_peer_by_handle(pm, peer_handle))
          continue;

        /* Free peer_handle found, allocate a SshPmPeer. */
        peer = ssh_pm_peer_alloc(pm);
        if (!peer)
        {
            SSH_DEBUG(SSH_D_FAIL, ("Could not allocate peer object"));
            return SSH_IPSEC_INVALID_INDEX;
        }
        peer->peer_handle = peer_handle;
        peer->pm = pm;

        /* Take one reference for the caller. */
        peer->refcnt = 1;

        *peer->remote_ip = *remote_ip;
        peer->remote_port = remote_port;
        *peer->local_ip = *local_ip;
        peer->local_port = local_port;

        peer->tunnel_id = tunnel_id;
        peer->routing_instance_id = routing_instance_id;

        /* Take one reference for p1. */
        peer->ike_sa_handle = ike_sa_handle;
        if (peer->ike_sa_handle != SSH_IPSEC_INVALID_INDEX)
          peer->refcnt++;
        peer->debug_object.flags |= SSH_PM_PEER_DEBUG_IKE_SA_CHANGED;

        if (local_id)
          peer->local_id = ssh_pm_ikev2_payload_id_dup(local_id);
        if (remote_id)
          peer->remote_id = ssh_pm_ikev2_payload_id_dup(remote_id);

        if (flags & SSH_PM_PEER_CREATE_FLAGS_USE_IKEV1)
          peer->use_ikev1 = 1;

        if (force_ikev1_natt_draft_02 == true)
          peer->ikev1_force_natt_draft_02 = 1;

#ifdef SSH_PM_BLACKLIST_ENABLED
        if (flags & SSH_PM_PEER_CREATE_FLAGS_ENABLE_BLACKLIST_CHECK)
          peer->enable_blacklist_check = 1;
#endif /* SSH_PM_BLACKLIST_ENABLED */

        peer->num_child_sas = 0;

        tunnel = ssh_pm_tunnel_get_by_id(pm, tunnel_id);

        ssh_register_timeout(
                &peer->idle_timeout,
                tunnel->u.ike.dpd_timeout,
                0,
                ssh_pm_peer_send_dpd,
                peer);

        SSH_DEBUG(SSH_D_MIDOK,
                  ("Allocating peer 0x%lx remote %@;%d local %@;%d "
                   "remote ID %@ local ID %@ ike_sa_handle 0x%lx %s "
                   "routing instance %d",
                   (unsigned long) peer->peer_handle,
                   ssh_ipaddr_render, remote_ip, (int) remote_port,
                   ssh_ipaddr_render, local_ip, (int) local_port,
                   ssh_pm_ike_id_render, peer->remote_id,
                   ssh_pm_ike_id_render, peer->local_id,
                   (unsigned long) peer->ike_sa_handle,
                   (peer->use_ikev1 ? "ikev1" : ""),
                   peer->routing_instance_id));

        /* Insert into peer_handle_hash. */
        pm_peer_handle_hash_insert(pm, peer);

        /* Insert into peer_sa_hash. */
        pm_peer_sa_hash_insert(pm, peer);

        /* Insert into peer_addr_hash. */
        pm_peer_local_addr_hash_insert(pm, peer);
        pm_peer_remote_addr_hash_insert(pm, peer);

        pm_peer_tunnel_id_hash_insert(pm, peer);

        return peer->peer_handle;
    }

    /* No free peer_handles available. */
    SSH_DEBUG(SSH_D_FAIL, ("Out of peer handles"));
    return SSH_IPSEC_INVALID_INDEX;
}

uint32_t
ssh_pm_peer_create(
        SshPm pm,
        uint32_t tunnel_id,
        SshIpAddr remote_ip,
        uint16_t remote_port,
        SshIpAddr local_ip,
        uint16_t local_port,
        SshPmP1 p1,
        SshVriId routing_instance_id)
{
    uint32_t flags = 0;
    bool force_ikev1_natt_draft_02 = false;

    if (p1 != NULL)
    {
#ifdef SSHDIST_IKEV1
        if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
        {
            flags |= SSH_PM_PEER_CREATE_FLAGS_USE_IKEV1;

            if (((p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR) != 0
                 && (p1->compat_flags & SSH_PM_COMPAT_NAT_T_DRAFT_02) != 0)
                || (p1->compat_flags &
                    SSH_PM_COMPAT_FORCE_NAT_T_DRAFT_02) != 0)
              force_ikev1_natt_draft_02 = true;
        }
#endif /* SSHDIST_IKEV1 */

#ifdef SSH_PM_BLACKLIST_ENABLED
        if (p1->enable_blacklist_check)
          flags |= SSH_PM_PEER_CREATE_FLAGS_ENABLE_BLACKLIST_CHECK;
#endif /* SSH_PM_BLACKLIST_ENABLED */

        return
            ssh_pm_peer_create_internal(
                    pm,
                    tunnel_id,
                    remote_ip,
                    remote_port,
                    local_ip,
                    local_port,
                    p1->local_id,
                    p1->remote_id,
                    SSH_PM_IKE_SA_INDEX(p1),
                    routing_instance_id,
                    flags,
                    force_ikev1_natt_draft_02);
    }
    else
    {
        return
            ssh_pm_peer_create_internal(
                    pm,
                    tunnel_id,
                    remote_ip,
                    remote_port,
                    local_ip,
                    local_port,
                    NULL,
                    NULL,
                    SSH_IPSEC_INVALID_INDEX,
                    routing_instance_id,
                    flags,
                    force_ikev1_natt_draft_02);
    }
}

static void
pm_peer_destroy(SshPm pm, SshPmPeer peer)
{
    SSH_ASSERT(peer != NULL);
    SSH_ASSERT(peer->refcnt > 0);

    peer->refcnt--;
    if (peer->refcnt > 0)
    {
        SSH_DEBUG(SSH_D_LOWOK,
                  ("Freeing reference to peer 0x%lx, %d references left.",
                   (unsigned long) peer->peer_handle,
                   (int) peer->refcnt));
        return;
    }

    SSH_DEBUG(SSH_D_MIDOK,
              ("Destroying peer 0x%lx remote %@;%d local %@;%d "
               "ike_sa_handle 0x%lx num_child_sas %d",
               (unsigned long) peer->peer_handle,
               ssh_ipaddr_render, peer->remote_ip, (int) peer->remote_port,
               ssh_ipaddr_render, peer->local_ip, (int) peer->local_port,
               (unsigned long) peer->ike_sa_handle,
               (int) peer->num_child_sas));

    ssh_cancel_timeout(&peer->idle_timeout);

    /* Remove from peer_handle_hash. */
    pm_peer_handle_hash_remove(pm, peer);

    /* Remove from peer_sa_hash. */
    pm_peer_sa_hash_remove(pm, peer);

    /* Remove from peer_addr_hash. */
    pm_peer_local_addr_hash_remove(pm, peer);
    pm_peer_remote_addr_hash_remove(pm, peer);
    pm_peer_tunnel_id_hash_remove(pm, peer);

    /* Put peer back to freelist. */
    ssh_pm_peer_free(pm, peer);
}

void
ssh_pm_peer_handle_take_ref(SshPm pm, uint32_t peer_handle)
{
    SSH_ASSERT(peer_handle != SSH_IPSEC_INVALID_INDEX);
    pm_peer_take_ref(ssh_pm_peer_by_handle(pm, peer_handle));
}

void
ssh_pm_peer_handle_destroy(SshPm pm, uint32_t peer_handle)
{
    SSH_ASSERT(peer_handle != SSH_IPSEC_INVALID_INDEX);
    pm_peer_destroy(pm, ssh_pm_peer_by_handle(pm, peer_handle));
}

/************************** Peer updating ***********************************/

static bool pm_peer_update_address(SshPm pm,
                                      SshPmPeer peer,
                                      SshIpAddr new_remote_ip,
                                      uint16_t new_remote_port,
                                      SshIpAddr new_local_ip,
                                      uint16_t new_local_port)
{
    SSH_ASSERT(peer != NULL);
    SSH_ASSERT(new_remote_ip != NULL);
    SSH_ASSERT(new_remote_port != 0);

    if (!SSH_IP_EQUAL(peer->remote_ip, new_remote_ip)
        || peer->remote_port != new_remote_port
        || !SSH_IP_EQUAL(peer->local_ip, new_local_ip)
        || peer->local_port != new_local_port)
    {
        SSH_DEBUG(SSH_D_MIDOK,
                  ("Updating peer 0x%lx address remote %@;%d local %@;%d "
                   "to remote %@;%d local %@;%d",
                   (unsigned long) peer->peer_handle,
                   ssh_ipaddr_render, peer->remote_ip, (int) peer->remote_port,
                   ssh_ipaddr_render, peer->local_ip, (int) peer->local_port,
                   ssh_ipaddr_render, new_remote_ip, (int) new_remote_port,
                   ssh_ipaddr_render, new_local_ip, (int) new_local_port));

        /* Remove from peer_addr_hash. */
        pm_peer_local_addr_hash_remove(pm, peer);
        pm_peer_remote_addr_hash_remove(pm, peer);

        /* Update addresses and ports. */
        *peer->remote_ip = *new_remote_ip;
        peer->remote_port = new_remote_port;
        *peer->local_ip = *new_local_ip;
        peer->local_port = new_local_port;

        /* Insert into peer_addr_hash. */
        pm_peer_local_addr_hash_insert(pm, peer);
        pm_peer_remote_addr_hash_insert(pm, peer);
    }

    return true;
}

bool
ssh_pm_peer_p1_update_address(SshPm pm,
                              SshPmP1 p1,
                              SshIpAddr new_remote_ip,
                              uint16_t new_remote_port,
                              SshIpAddr new_local_ip,
                              uint16_t new_local_port)
{
    SshPmPeer peer;

    SSH_ASSERT(p1 != NULL);

    /* There might be multiple IKE peers pointing to same IKE SA.
       It is also ok not to have any peers for p1. This means just
       that there are no IPsec SAs with this peer. */
    peer = ssh_pm_peer_by_p1(pm, p1);
    while (peer != NULL)
    {
        if (pm_peer_update_address(pm, peer, new_remote_ip, new_remote_port,
                                   new_local_ip, new_local_port) == false)
        {
            SSH_DEBUG(SSH_D_FAIL, ("Failed to update addresses of peer %p",
                                   peer));
            return false;
        }

        peer = ssh_pm_peer_next_by_ike_sa_handle(pm, peer);
    }

    return true;
}

bool
ssh_pm_peer_update_p1(SshPm pm, SshPmPeer peer, SshPmP1 new_p1)
{
    uint32_t new_ike_sa_handle = SSH_IPSEC_INVALID_INDEX;
    uint32_t old_ike_sa_handle = SSH_IPSEC_INVALID_INDEX;

    if (peer == NULL)
      return false;

    if (new_p1 != NULL)
    {
        /* Fill in local and remote identities if they are not set. This may
           happen when importing IPsec SAs without a valid IKEv1 SA. */
        if (peer->local_id == NULL)
          peer->local_id = ssh_pm_ikev2_payload_id_dup(new_p1->local_id);
        if (peer->remote_id == NULL)
          peer->remote_id = ssh_pm_ikev2_payload_id_dup(new_p1->remote_id);

#ifdef SSH_PM_BLACKLIST_ENABLED
        /* Set peer's enable blacklist check flag if blacklist check is
           enabled for the new p1. */
        if (new_p1->enable_blacklist_check)
          peer->enable_blacklist_check = 1;
#endif /* SSH_PM_BLACKLIST_ENABLED */

        new_ike_sa_handle =  SSH_PM_IKE_SA_INDEX(new_p1);
    }

    old_ike_sa_handle = peer->ike_sa_handle;

    if (old_ike_sa_handle == new_ike_sa_handle)
      return true;

    SSH_DEBUG(SSH_D_MIDOK,
              ("Updating peer 0x%lx ike_sa_handle from 0x%lx to 0x%lx",
               (unsigned long) peer->peer_handle,
               (unsigned long) peer->ike_sa_handle,
               (unsigned long) new_ike_sa_handle));

    /* Update ike_sa_handle and peer_sa_hash. */
    pm_peer_sa_hash_remove(pm, peer);
    peer->ike_sa_handle = new_ike_sa_handle;
    peer->debug_object.flags |= SSH_PM_PEER_DEBUG_IKE_SA_CHANGED;
    pm_peer_sa_hash_insert(pm, peer);

    /* Take one reference for the new IKE SA. */
    if (new_ike_sa_handle != SSH_IPSEC_INVALID_INDEX)
      pm_peer_take_ref(peer);

    /* Release the old IKE SA's reference. */
    if (old_ike_sa_handle != SSH_IPSEC_INVALID_INDEX)
      pm_peer_destroy(pm, peer);

    if (new_p1)
      pm_peer_update_address(pm, peer,
                             new_p1->ike_sa->remote_ip,
                             new_p1->ike_sa->remote_port,
                             new_p1->ike_sa->server->ip_address,
                             SSH_PM_IKE_SA_LOCAL_PORT(new_p1->ike_sa));

    return true;
}

/**************************** Module cleanup ********************************/

void
ssh_pm_peers_uninit(SshPm pm)
{
    uint32_t hash;
    SshPmPeer peer;

    for (hash = 0; hash < SSH_PM_PEER_IKE_SA_HASH_TABLE_SIZE; hash++)
    {
        do
        {
            peer = pm->peer_handle_hash[hash];
            if (peer)
            {











                pm_peer_destroy(pm, peer);
            }
        }
        while (peer != NULL);
        SSH_ASSERT(pm->peer_handle_hash[hash] == NULL);
    }
}

/**************************** Selective debug *******************************/

static void
pm_peer_debug_identify(SshPm pm, SshPmPeer peer)
{
    SshPdbgObject o = &peer->debug_object;
    unsigned char *l, *r;
    SshPmP1 p1;

    /* Show connection parameters only once. */
    if ((o->flags & SSH_PM_PEER_DEBUG_CONNECTION_SHOWN) == 0)
    {
        o->flags |= SSH_PM_PEER_DEBUG_CONNECTION_SHOWN;
        ssh_pdbg_output_connection(
          peer->local_ip, peer->local_port,
          peer->remote_ip, peer->remote_port);
    }

    /* Show IKE SPIs if they have changed since last shown. */
    if ((o->flags & SSH_PM_PEER_DEBUG_IKE_SA_CHANGED) != 0)
    {
        o->flags &= ~SSH_PM_PEER_DEBUG_IKE_SA_CHANGED;

        p1 = ssh_pm_p1_from_ike_handle(pm, peer->ike_sa_handle, false);

        if (p1)
        {
            if ((p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR) != 0)
            {
                l = p1->ike_sa->ike_spi_i;
                r = p1->ike_sa->ike_spi_r;
            }
            else
            {
                l = p1->ike_sa->ike_spi_r;
                r = p1->ike_sa->ike_spi_i;
            }

            ssh_pdbg_output_information(
              "Local-IKE-SPI: %.*@ Remote-IKE-SPI: %.*@",
              8, ssh_hex_render, l, 8, ssh_hex_render, r);
        }
    }
}

static void
pm_peer_debug_general(SshPm pm, SshPmPeer peer, const char *text)
{
    ssh_pdbg_output_event("IPSEC-CONN", &peer->debug_object, "%s", text);

    pm_peer_debug_identify(pm, peer);
}

static bool
pm_peer_debug_enabled(SshPm pm, SshPmPeer peer, uint32_t level)
{
    SshPdbgConfig c = &pm->debug_config;
    SshPdbgObject o = &peer->debug_object;

    SshIpAddr l, r;

    if (peer == NULL)
      return false;

    if (o->generation != c->generation)
    {
        if (o->level == 0)
        {
            l = peer->local_ip;
            r = peer->remote_ip;
            ssh_pdbg_object_update(c, o, l, r);
            if (o->level > 0)
            {
                *peer->debug_local = *l;
                *peer->debug_remote = *r;
            }
        }
        else
        {
            l = peer->debug_local;
            r = peer->debug_remote;
            ssh_pdbg_object_update(c, o, l, r);
        }
    }

    return o->level >= level;
}

void
ssh_pm_peer_debug_error_local(SshPm pm, SshPmPeer peer, const char *text)
{
    if (!pm_peer_debug_enabled(pm, peer, 1))
      return;

    pm_peer_debug_general(pm, peer, "local error");

    ssh_pdbg_output_information("Error:\"%s\"", text);
}

void
ssh_pm_peer_debug_error_remote(SshPm pm, SshPmPeer peer, const char *text)
{
    if (!pm_peer_debug_enabled(pm, peer, 1))
      return;

    pm_peer_debug_general(pm, peer, "remote error");

    ssh_pdbg_output_information("Error:\"%s\"", text);
}

