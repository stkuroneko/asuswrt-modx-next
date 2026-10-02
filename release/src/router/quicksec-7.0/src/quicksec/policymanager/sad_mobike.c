/**
   @copyright
   Copyright (c) 2006 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   Policy manager Mobike SAD module.
*/

#include "sshincludes.h"

#include "sshadt.h"
#include "quicksecpm_internal.h"

#define SSH_DEBUG_MODULE "SshPmSadMobIke"

#ifdef SSHDIST_IPSEC_MOBIKE


/******************* Definitions and Forward Declarations ********************/

void
pm_mobike_send_additional_addresses(SshPm pm,
                                    SshPmP1 p1,
                                    SshPmTunnel tunnel);


/****************************** Utilities ***********************************/

/* Extract the NAT-T flags from the NAT-T status of the current exchange
   or from the IKE SA if no exchange data is present. Returns true if
   the NAT-T flags are different in the exchange to those currently
   in the IKE SA. */
bool ssh_pm_mobike_get_exchange_natt_flags(SshPmP1 p1,
                                              SshIkev2ExchangeData ed,
                                              uint32_t *natt_flags)
{
    bool natt_flags_changed = false;
    *natt_flags = 0;

    if (ed == NULL || ed->info_ed == NULL)
    {
        if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_THIS_END_BEHIND_NAT)
          *natt_flags |=
            SSH_IKEV2_IKE_SA_CHANGE_ADDRESSES_FLAGS_LOCAL_BEHIND_NAT;

        if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_OTHER_END_BEHIND_NAT)
          *natt_flags |=
            SSH_IKEV2_IKE_SA_CHANGE_ADDRESSES_FLAGS_REMOTE_BEHIND_NAT;
        return false;
    }

    /* Check if NAT-T status has changed. */
    if (ed->info_ed->local_end_behind_nat)
    {
        *natt_flags |=
          SSH_IKEV2_IKE_SA_CHANGE_ADDRESSES_FLAGS_LOCAL_BEHIND_NAT;

        if (!(p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_THIS_END_BEHIND_NAT))
          natt_flags_changed = true;
    }
    else
    {
        if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_THIS_END_BEHIND_NAT)
          natt_flags_changed = true;
    }

    if (ed->info_ed->remote_end_behind_nat)
    {
        *natt_flags |=
          SSH_IKEV2_IKE_SA_CHANGE_ADDRESSES_FLAGS_REMOTE_BEHIND_NAT;

        if (!(p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_OTHER_END_BEHIND_NAT))
          natt_flags_changed = true;
    }
    else
    {
        if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_OTHER_END_BEHIND_NAT)
          natt_flags_changed = true;
    }

    SSH_DEBUG(SSH_D_LOWOK, ("NAT-T flags for ed=%p, IKE SA=%p are %x",
                            ed, p1->ike_sa, *natt_flags));

    return natt_flags_changed;
}


bool
ssh_pm_mobike_valid_address(SshIpAddr ip)
{
    if (SSH_IP6_IS_LINK_LOCAL(ip) || SSH_IP_IS_NULLADDR(ip) ||
        SSH_IP_IS_BROADCAST(ip) || SSH_IP_IS_MULTICAST(ip) ||
        SSH_IP_IS_LOOPBACK(ip) || !SSH_IP_DEFINED(ip))
      return false;

    return true;
}

SshIkev2Server
ssh_pm_mobike_get_ike_server(SshPm pm,
                             SshPmTunnel tunnel,
                             SshIpAddr local_ip,
                             uint16_t local_port)
{
    SshIkev2Server server;
    uint32_t server_flags = 0;

    if (local_port)
      server_flags |= SSH_PM_SERVERS_MATCH_PORT;

    server = ssh_pm_servers_select_ike(pm, local_ip,
                                       server_flags,
                                       SSH_INVALID_IFNUM,
                                       local_port,
                                       tunnel->routing_instance_id);

    if (server == NULL)
    {
        SSH_DEBUG(SSH_D_FAIL, ("No IKE server running on local address %@",
                               ssh_ipaddr_render, local_ip));
    }

    return server;
}


static bool pm_mobike_update_p1(SshPm pm, SshPmP1 p1,
                                   SshIkev2ExchangeData ed,
                                   SshPmTunnel tunnel)
{
    SshPmTunnelLocalIp local_ip;
    SshIkev2Server server = NULL;
    SshIpAddr remote_ip = NULL;
    uint16_t remote_port = 0;
    uint32_t natt_flags, i;

    /* This should be called only for MobIKE enabled IKE SAs. */
    SSH_ASSERT(p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_MOBIKE_ENABLED);

    /* Get the NAT-T status of the current exchange (or existing the
       IKE SA if no exchange data is present) . */
    (void)ssh_pm_mobike_get_exchange_natt_flags(p1, ed, &natt_flags);

    /* If an exchange data is present use it to update the IKE
       SA addresses */
    if (ed != NULL)
    {
        server = ed->server;
        remote_ip = ed->remote_ip;
        remote_port = ed->remote_port;
    }
    else
    {
        SSH_ASSERT(tunnel != NULL);

        /* Lookup suitable address pair. */
        for (local_ip = tunnel->local_ip;
             local_ip != NULL;
             local_ip = local_ip->next)
        {
            /* Skip non-existent statically configured addresses. */
            if (local_ip->unavailable)
              continue;

            /* Select remote IP. The remote IP used in the exchange
               where the most recent additional address list was
               received is always the first element in the addional
               address list. This may equal to the current IKE SA
               remote IP, or not if the current remote IP has
               disappeared from the peer. Anyway we start the remote
               IP lookup using the last known valid remote IP. If that
               remote IP is equal to the current remote IP in the IKE
               SA then we also use the remote port from the IKE
               SA. Otherwise we set the remote port to 0 and select it
               later according to the NAT-T status of the IKE SA. */
            remote_port = 0;
            for (i = 0; i < p1->ike_sa->num_additional_ip_addresses; i++)
            {
                remote_ip = &p1->ike_sa->additional_ip_addresses[i];
                if (!ssh_pm_mobike_valid_address(remote_ip))
                  continue;

                if ((SSH_IP_IS4(&local_ip->ip) && SSH_IP_IS4(remote_ip))
                    || (SSH_IP_IS6(&local_ip->ip) && SSH_IP_IS6(remote_ip)))
                {
                    if (SSH_IP_EQUAL(remote_ip, p1->ike_sa->remote_ip))
                      remote_port = p1->ike_sa->remote_port;
                    goto out;
                }
            }
            remote_ip = NULL;
        }
      out:
        if (local_ip == NULL || remote_ip == NULL)
        {
            SSH_DEBUG(SSH_D_FAIL, ("No usable address pairs for IKE SA %p",
                                   p1->ike_sa));
            return false;
        }

        server = ssh_pm_mobike_get_ike_server(pm, tunnel, &local_ip->ip,
                                              tunnel->local_port);
        if (server == NULL)
        {
            SSH_DEBUG(SSH_D_FAIL, ("No IKE server running on %@:%d",
                                   ssh_ipaddr_render, &local_ip->ip,
                                   tunnel->local_port));
            return false;
        }

        if (remote_port == 0)
        {
            if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_NAT_T_FLOAT_DONE)
              remote_port = server->nat_t_remote_port;
            else
              remote_port = server->normal_remote_port;
        }
    }

    if (!ssh_pm_mobike_update_p1_addresses(pm, p1, server,
                                           remote_ip, remote_port,
                                           natt_flags))
      return false;

    return true;
}


/************************** Updating p1 addresses ****************************/

bool
ssh_pm_mobike_update_p1_addresses(SshPm pm,
                                  SshPmP1 p1,
                                  SshIkev2Server ike_server,
                                  SshIpAddr remote_ip,
                                  uint16_t remote_port,
                                  uint32_t natt_flags)
{
    SshIkev2Error error;

    SSH_DEBUG(
            SSH_D_MIDOK,
            ("Updating IKE SA %p addresses (natt flags 0x%x) from local %@:%d "
             "remote %@:%d to local %@:%d remote %@:%d",
             p1->ike_sa, natt_flags,
             ssh_ipaddr_render, &p1->ike_sa->server->ip_address,
             (int) SSH_PM_IKE_SA_LOCAL_PORT(p1->ike_sa),
             ssh_ipaddr_render, p1->ike_sa->remote_ip,
             (int) p1->ike_sa->remote_port,
             ssh_ipaddr_render, &ike_server->ip_address,
             (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_NAT_T_FLOAT_DONE ?
              (int) ike_server->nat_t_local_port :
              (int) ike_server->normal_local_port),
             ssh_ipaddr_render, remote_ip,
             (int) remote_port));

    /* Remove p1 from IKE SA hashtable. */
    if (p1->done)
      ssh_pm_ike_sa_hash_remove(pm, p1);

    /* Update IKE SA addresses. */
    error = ssh_ikev2_ike_sa_change_addresses(p1->ike_sa, ike_server,
                                              remote_ip, remote_port,
                                              natt_flags);

    /* Update IKE peer information. */
    if (p1->done && error == SSH_IKEV2_ERROR_OK)
      ssh_pm_peer_p1_update_address(pm, p1, remote_ip, remote_port,
                                    p1->ike_sa->server->ip_address,
                                    SSH_PM_IKE_SA_LOCAL_PORT(p1->ike_sa));

    /* Add p1 back to IKE SA hashtable. */
    if (p1->done)
      ssh_pm_ike_sa_hash_insert(pm, p1);

    if (error != SSH_IKEV2_ERROR_OK)
      SSH_DEBUG(SSH_D_FAIL, ("Could not update IKE SA %p addresses",
                             p1->ike_sa));

    return (error == SSH_IKEV2_ERROR_OK) ? true : false;
}


/************************* Completion Callbacks ******************************/

static void pm_mobike_operation_done_cb(SshPm pm,
                                        SshPmP1 p1,
                                        bool status,
                                        void *context)
{
    SSH_DEBUG(SSH_D_MIDOK, ("Mobike operation for IKE SA %p %s",
                            p1->ike_sa, (status ? "succeeded" : "failed")));

    /* Clear operation handle. */
    p1->initiator_ops[PM_IKE_INITIATOR_OP_ADDRESS_UPDATE] = NULL;

    /* Send any delayed delete notifications. */
    if (status == true)
      ssh_pm_send_ipsec_delete_notification_requests(pm, p1);
}


static void pm_mobike_forced_address_update_cb(SshPm pm,
                                               SshPmP1 p1,
                                               bool status,
                                               void *context)
{
    SshPmTunnel tunnel;

    SSH_DEBUG(SSH_D_LOWOK, ("Forced address update callback done status '%s'",
                            status ? "successful" : "failed"));

    /* Clear operation handle. */
    p1->initiator_ops[PM_IKE_INITIATOR_OP_ADDRESS_UPDATE] = NULL;

    if (status)
    {
        /* Send additional addresses if the remote end is not behind
           NAT. If the peer is behind NAT, do not bother with this as the
           operation will most likely fail. Leave it to the initiator to fix
           the problem . */
        if (!(p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_OTHER_END_BEHIND_NAT))
        {
            SSH_DEBUG(
                    SSH_D_MIDOK,
                    ("Send additional addresses to IKE peer for "
                     "IKE SA %p", p1->ike_sa));

            /* Lookup tunnel. */
            tunnel = ssh_pm_p1_get_tunnel(pm, p1);
            if (tunnel != NULL)
              pm_mobike_send_additional_addresses(pm, p1, tunnel);
            else
              SSH_DEBUG(SSH_D_ERROR,
                        ("Could not find tunnel for IKE SA %p, tunnel_id %d",
                         p1->ike_sa, p1->tunnel_id));

            return;
        }
        else
        {
            SSH_DEBUG(SSH_D_MIDOK, ("Remote end behind NAT, not attempting to "
                                    "send additional address notify"));
        }
        return;
    }
}


/************************** Address update **********************************/

static void pm_mobike_start_address_update(SshPm pm, SshPmP1 p1,
                                           SshIkev2ExchangeData ed,
                                           SshPmTunnel tunnel,
                                           bool force_ike_update)
{
    uint32_t update_flags = 0;

    /* This should be called only for MobIKE enabled IKE SAs. */
    SSH_ASSERT(p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_MOBIKE_ENABLED);
    SSH_PM_ASSERT_P1(p1);
    SSH_ASSERT(tunnel != NULL);

    SSH_DEBUG(SSH_D_MIDOK, ("IKE SA reevaluation causes address update"));

    /* IKE SA is mobike enabled and it is not using preferred local IP,
       or the current local IP has disappeared. Now initiate address update. */
    if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_MOBIKE_INITIATOR)
    {
        /* Start a new address update if there is no ongoing operation */
        if (!p1->initiator_ops[PM_IKE_INITIATOR_OP_ADDRESS_UPDATE])
        {
            if (force_ike_update)
              update_flags |= SSH_PM_MOBIKE_FLAGS_PROBE;

            p1->address_update_pending = 0;
            p1->initiator_ops[PM_IKE_INITIATOR_OP_ADDRESS_UPDATE] =
                ssh_pm_mobike_initiator_address_update(
                        pm, p1, ed,
                        tunnel, update_flags,
                        pm_mobike_operation_done_cb,
                        NULL);
        }
        else
        {
            SSH_DEBUG(SSH_D_HIGHOK,
                      ("Initiator address update currently in progress. "
                       "Will redo address update on completion"));

            if (force_ike_update)
              pm_mobike_update_p1(pm, p1, ed, tunnel);

            p1->address_update_pending = 1;
        }
        return;
    }
    else
    {
        /* Responders only force address update if the currently used
           address in the IKE SA can no longer be used. Forcing of
           address update is achieved by sending an additional
           address notify where the IP address in the notify
           packet is different to the old IKE SA address and the
           old IKE SA address is not one of the additional addresses in
           the notify payload. */
        if (!p1->initiator_ops[PM_IKE_INITIATOR_OP_ADDRESS_UPDATE])
        {
            p1->initiator_ops[PM_IKE_INITIATOR_OP_ADDRESS_UPDATE] =
              ssh_pm_mobike_responder_forced_address_update(
                      pm, p1, tunnel,
                      pm_mobike_forced_address_update_cb,
                      NULL);
        }
        else
        {
            if (force_ike_update)
              pm_mobike_update_p1(pm, p1, ed, tunnel);
        }
    }
}


/************************** Add additional addresses to VIP *****************/

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
/* This function is called when additional address notifies (or a no
   additional address notify) is received from the peer. Tunnel may
   have VIP enabled and the additional addresses need to be added to
   VIP and updated to the host routes. */
static void
ssh_pm_mobike_add_additional_addresses_to_vip(SshPm pm, SshPmP1 p1)
{
    bool sgw_ip_was_in_additional_ads = false;
    SshPmTunnel tunnel;
    uint32_t i;

    tunnel = ssh_pm_p1_get_tunnel(pm, p1);
    if (tunnel == NULL || tunnel->vip == NULL)
    {
        SSH_DEBUG(SSH_D_MIDOK,
                  ("The tunnel did not have VIP enabled."));
        return;
    }

    /* Mark all the existing routes as removed. */
    ssh_pm_vip_flush_sgw_routes(tunnel->vip);

    /* Check if the additional addresses include the current IKE
       remote address.*/
    for (i = 0; i < p1->ike_sa->num_additional_ip_addresses; i++)
    {
        if (!ssh_pm_mobike_valid_address(&p1->ike_sa->
                                         additional_ip_addresses[i]))
          continue;

        if (SSH_IP_EQUAL(&p1->ike_sa->additional_ip_addresses[i],
                         p1->ike_sa->remote_ip))
          sgw_ip_was_in_additional_ads = true;

        ssh_pm_vip_create_sgw_route(tunnel->vip,
                                    &p1->ike_sa->additional_ip_addresses[i]);
    }

    /* If the remote ip was not in addional addresses, add it to the
       sgw ips. */
    if (sgw_ip_was_in_additional_ads == false)
      ssh_pm_vip_create_sgw_route(tunnel->vip, p1->ike_sa->remote_ip);

    tunnel->vip->reconfigure_routes = 1;
    ssh_fsm_condition_broadcast(&pm->fsm, &tunnel->vip->cond);
}
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

/************************** Additional addresses received *******************/

/* This function is called when additional address notifies (or a no
   additional address notify) is received from the peer. MobIKE initiators
   need to check if the responder has indicated its current address is
   no longer valid. The responder does this by not including its current
   address in the additional address notifies and using a different
   address to send the notify message. If the responder's current address
   is not longer valid, then perform address update immediately. Otherwise
   reevaluate the IKE SA (reevaluation is performed to see if a new
   address pair of higher precedence has become available). */
void
ssh_pm_mobike_additional_addresses_received(SshPm pm, SshPmP1 p1,
                                            SshIkev2ExchangeData ed)
{
    int i;
    SshPmTunnel tunnel;

    /* Only MobIKE enabled IKE SAs need to react on this. */
    if ((p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_MOBIKE_ENABLED) == 0)
      return;

    /* Only MOBIKE initiators need to react on this. */
    if ((p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_MOBIKE_INITIATOR) == 0)
      return;

    SSH_DEBUG(SSH_D_LOWOK, ("Processing additional address notifies"));

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
    ssh_pm_mobike_add_additional_addresses_to_vip(pm, p1);
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

    /* Check if the current remote address has changed. */
    if (SSH_IP_EQUAL(ed->remote_ip, p1->ike_sa->remote_ip))
    {
        SSH_DEBUG(SSH_D_MIDOK, ("Reevaluating IKE SA %p as a result of "
                                "additional address notify", p1->ike_sa));
        ssh_pm_mobike_reevaluate_ike_sa(pm, p1);
        return;
    }

    /* Check if the additional addresses include the current IKE
       remote address.*/
    for (i = 0; i < p1->ike_sa->num_additional_ip_addresses; i++)
    {
        if (!ssh_pm_mobike_valid_address(&p1->ike_sa->
                                         additional_ip_addresses[i]))
          continue;

        /* Yes, remote address is in additional addresses. Reevaluate IKE SA
           to check if any address pair with higher precedence is available. */
        if (SSH_IP_EQUAL(&p1->ike_sa->additional_ip_addresses[i],
                         p1->ike_sa->remote_ip))
        {
            SSH_DEBUG(SSH_D_MIDOK, ("Reevaluating IKE SA %p as a result "
                                    "of additional address notify",
                                    p1->ike_sa));
            ssh_pm_mobike_reevaluate_ike_sa(pm, p1);
            return;
        }
    }

    /* If we get here, the responder's remote IP address in the IKE SA
       is no longer valid. Start address update. */
    SSH_DEBUG(SSH_D_HIGHOK, ("Responder has sent additional addresses notify "
                             "that does not include the current remote address"
                             " and remote IP address has changed, starting "
                             "address update"));
    tunnel = ssh_pm_p1_get_tunnel(pm, p1);
    if (tunnel == NULL)
    {
        SSH_DEBUG(SSH_D_FAIL,
                  ("Could not find tunnel for IKE SA %p, tunnel_id %d",
                   p1->ike_sa, p1->tunnel_id));
        return;
    }

    pm_mobike_start_address_update(pm, p1, ed, tunnel, true);
    return;
}


/******************** Re-evaluating mobike enabled IKE SAs  ******************/

/* Reevaluate a single IKE SA. */
void ssh_pm_mobike_reevaluate_ike_sa(SshPm pm, SshPmP1 p1)
{
    SshPmTunnel tunnel;
    SshPmTunnelLocalIp local_ip;
    uint32_t current_precedence;
    SshIpAddr remote_ip;
    uint32_t i;

    /* Skip non-mobike IKE SAs. */
    if ((p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_MOBIKE_ENABLED) == 0)
      return;

    /* Skip unusable IKE SAs. */
    if (p1->unusable)
      return;

    SSH_DEBUG(SSH_D_LOWOK,
              ("Reevaluate MobIKE enabled IKE SA %p", p1->ike_sa));

    /* Lookup tunnel. */
    tunnel = ssh_pm_p1_get_tunnel(pm, p1);
    if (tunnel == NULL)
    {
        SSH_DEBUG(SSH_D_ERROR,
                  ("Could not find tunnel for IKE SA %p, tunnel_id %d",
                   p1->ike_sa, p1->tunnel_id));
        return;
    }

    /* Check if current IKE SA local IP has disappeared.
       Iterate through local IP entries and try to find the current
       address. If address is not found, then the IKE SA must be moved
       to another IKE server and an address update must be performed. */
    for (local_ip = tunnel->local_ip;
         local_ip != NULL;
         local_ip = local_ip->next)
    {
        if (SSH_IP_EQUAL(&local_ip->ip, p1->ike_sa->server->ip_address))
        {
            /* Check the current address is available. */
            if (local_ip->unavailable)
              local_ip = NULL;
            break;
        }
    }
    if (local_ip == NULL)
    {
        SSH_DEBUG(SSH_D_HIGHOK,
                  ("Current IKE SA local IP address has disappeared."));
        pm_mobike_start_address_update(pm, p1, NULL, tunnel, true);
        return;
    }

    SSH_DEBUG(SSH_D_MIDOK,
              ("Current local IP is %@, precedence %d. Now check for "
               "higher precedence local addresses",
               ssh_ipaddr_render, &local_ip->ip,
               local_ip->precedence));

    /* Check if IKE SA is using the preferred local IP. If the address
       is found, but there is a suitable local addresses with higher
       precedence then an address update is started. */
    if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_MOBIKE_INITIATOR)
    {
        current_precedence = local_ip->precedence;

        for (local_ip = tunnel->local_ip;
             local_ip != NULL;
             local_ip = local_ip->next)
        {
            if (local_ip->unavailable)
              continue;

            for (i = 0; i < p1->ike_sa->num_additional_ip_addresses; i++)
            {
                remote_ip = &p1->ike_sa->additional_ip_addresses[i];

                if (!ssh_pm_mobike_valid_address(remote_ip))
                  continue;

                if ((SSH_IP_IS4(&local_ip->ip) && SSH_IP_IS4(remote_ip))
                    || (SSH_IP_IS6(&local_ip->ip) && SSH_IP_IS6(remote_ip)))
                {
                    if (current_precedence < local_ip->precedence)
                    {
                        SSH_DEBUG(
                                SSH_D_HIGHOK,
                                ("Found local IP %@ with higher precedence %d",
                                 ssh_ipaddr_render, &local_ip->ip,
                                 local_ip->precedence));
                        pm_mobike_start_address_update(
                                pm, p1, NULL, tunnel,
                                true);
                        return;
                    }
                }
            }
        }
    }

    SSH_DEBUG(SSH_D_MIDOK, ("Current local IP has highest precedence"));

    /* The IKE SA is using the preferred local IP, but local IPs have
       changed, send additional addresses notification to peer. */
    if (tunnel->local_ip_changed)
    {
        SSH_DEBUG(SSH_D_NICETOKNOW,
                  ("Additional local IP addresses have changed"));

        pm_mobike_send_additional_addresses(pm, p1, tunnel);
    }

    return;
}

/* Reevaluate all IKE SAs. */
void
ssh_pm_mobike_reevaluate(SshPm pm,
                         SshPmStatusCB callback,
                         void *context)
{
    SshADTHandle handle;
    SshPmP1 p1;
    SshPmTunnel tunnel;

    SSH_DEBUG(SSH_D_MIDOK, ("Reevaluating mobike enabled IKE SAs."));

    /* Loop through all IKE SAs . */
    for (handle = ssh_adt_enumerate_start(pm->sad_handle->ike_sa_by_spi);
         handle != SSH_ADT_INVALID;
         handle = ssh_adt_enumerate_next(
                 pm->sad_handle->ike_sa_by_spi, handle))
    {
        p1 = (SshPmP1) ssh_adt_get(pm->sad_handle->ike_sa_by_spi, handle);
        SSH_ASSERT(p1 != NULL);

        /* Evaluate only completed IKEv2 SAs. */
        if (!p1->done)
          continue;
#ifdef SSHDIST_IKEV1
        if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
          continue;
#endif /* SSHDIST_IKEV1 */

        ssh_pm_mobike_reevaluate_ike_sa(pm, p1);
    }

    /* Clear local_ip_changed flag from all tunnels. */
    for (handle = ssh_adt_enumerate_start(pm->tunnels);
         handle != SSH_ADT_INVALID;
         handle = ssh_adt_enumerate_next(pm->tunnels, handle))
    {
        tunnel = (SshPmTunnel) ssh_adt_get(pm->tunnels, handle);
        SSH_ASSERT(tunnel != NULL);
        tunnel->local_ip_changed = false;
    }

    if (callback)
      (*callback)(pm, true, context);
    return;
}


/************************* Sending additional addresses **********************/

static void pm_mobike_additional_addrs_done_cb(SshSADHandle sad_handle,
                                               SshIkev2Sa ike_sa,
                                               SshIkev2ExchangeData ed,
                                               SshIkev2Error error)
{
    SshPmP1 p1 = (SshPmP1) ike_sa;
    SshPm pm = sad_handle->pm;

    SSH_PM_ASSERT_P1(p1);
    SSH_PM_ASSERT_ED(ed);

#ifdef DEBUG_LIGHT
    {
        SshPmInfo info = (SshPmInfo) ed->application_context;
        SSH_ASSERT(info != NULL);
        SSH_ASSERT(info->type == SSH_PM_ED_DATA_INFO_MOBIKE);
    }
#endif /* DEBUG_LIGHT */

    PM_IKE_ASYNC_CALL_COMPLETE(ike_sa, ed);

    /* Clear application context. */
    ed->application_context = NULL;

    SSH_DEBUG(SSH_D_MIDOK,
              ("Sending additional addresses for IKE SA %p %s (error %d)",
               ike_sa, (error == SSH_IKEV2_ERROR_OK ? "succeeded" : "failed"),
               error));

    /* Call common information exchange completion callback. */
    pm_ike_info_done_common(pm, p1, ed, error);
}

void
pm_mobike_send_additional_addresses(SshPm pm,
                                   SshPmP1 p1,
                                   SshPmTunnel tunnel)
{
    SshIkev2ExchangeData ed = NULL;
    SshPmInfo info = NULL;
    uint32_t flags;
    int slot;

    /* This should be called only for MobIKE enabled IKE SAs. */
    SSH_ASSERT(p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_MOBIKE_ENABLED);

    SSH_DEBUG(SSH_D_MIDOK, ("Sending additional addresses for IKE SA %p",
                            p1->ike_sa));

    if (p1->unusable)
    {
        SSH_DEBUG(
                SSH_D_FAIL,
                ("Cannot use this IKE SA for sending additional addresses."));
        return;
    }

    if (!pm_ike_async_call_possible(p1->ike_sa, &slot))
    {
        SSH_DEBUG(
                SSH_D_FAIL,
                ("Window full, cannot send additional addresses"));

        if (p1->mobike_suspended_op_type == SSH_PM_MOBIKE_OP_NOT_SUSPENDED)
        {
            SSH_ASSERT(p1->mobike_suspended_operation == NULL);
            p1->mobike_suspended_op_type =
                SSH_PM_MOBIKE_OP_ADDITIONAL_ADDRESSES;
            p1->mobike_suspended_operation = NULL;
        }
        return;
    }

    flags = SSH_IKEV2_INFO_CREATE_FLAGS_REQUEST_ADDRESSES;
    ed = ssh_ikev2_info_create(p1->ike_sa, flags);
    if (ed == NULL)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Could not allocate exchange data for "
                               "sending additional addresses"));
        return;
    }

    info = ssh_pm_info_alloc(pm, ed, SSH_PM_ED_DATA_INFO_MOBIKE);
    if (info == NULL)
    {
        ssh_ikev2_info_destroy(ed);
        SSH_DEBUG(SSH_D_FAIL, ("Could not allocate info exchange context."));
        return;
    }

    ed->application_context = info;

    PM_IKE_ASYNC_CALL(p1->ike_sa, ed, slot,
                      ssh_ikev2_info_send(ed,
                                          pm_mobike_additional_addrs_done_cb));
    return;
}


/************* Check MobIKE status after exchange completion ****************/

/* Check if an address update needs to be performed.  This is called
   when initiator exchange `ed' has successfully completed for IKE SA
   `p1->ike_sa'. This function must not be called if the exchange failed. */
void ssh_pm_mobike_check_exchange(SshPm pm,
                                  SshIkev2Error error,
                                  SshPmP1 p1,
                                  SshIkev2ExchangeData ed)
{
    SshPmTunnel tunnel;
    bool natt_status_changed;
    uint32_t natt_flags;
    SshPmMobike ctx;
    SshIkev2PayloadNotify notify;

    /* Only MOBIKE enabled IKE SAs need checking. */
    if ((p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_MOBIKE_ENABLED) == 0)
      return;

    /* Only successfull or temporarily failed exchanges can trigger
       MOBIKE actions. */
    if (error != SSH_IKEV2_ERROR_OK
        && error != SSH_IKEV2_ERROR_TEMPORARY_FAILURE
        && error != SSH_IKEV2_ERROR_CHILD_SA_NOT_FOUND)
      return;

    switch (p1->mobike_suspended_op_type)
    {
      case SSH_PM_MOBIKE_OP_NOT_SUSPENDED:
        break;

      case SSH_PM_MOBIKE_OP_ADDITIONAL_ADDRESSES:
        SSH_DEBUG(SSH_D_MIDOK,
                  ("Continuing suspended MOBIKE additional address sending"));

        p1->mobike_suspended_op_type = SSH_PM_MOBIKE_OP_NOT_SUSPENDED;
        p1->mobike_suspended_operation = NULL;

        tunnel = ssh_pm_p1_get_tunnel(pm, p1);
        if (tunnel != NULL)
          pm_mobike_send_additional_addresses(pm, p1, tunnel);
        else
          SSH_DEBUG(SSH_D_FAIL,
                    ("Could not find tunnel for IKE SA %p, tunnel_id %d",
                     p1->ike_sa, p1->tunnel_id));

        return;

      case SSH_PM_MOBIKE_OP_INITIATOR_ADDRESS_UPDATE:
        SSH_DEBUG(SSH_D_MIDOK,
                  ("Continuing suspended MOBIKE initiator address update"));

        ctx = p1->mobike_suspended_operation;
        p1->mobike_suspended_op_type = SSH_PM_MOBIKE_OP_NOT_SUSPENDED;
        p1->mobike_suspended_operation = NULL;

        ssh_pm_mobike_initiator_continue_address_update(pm, ctx);
        return;

      case SSH_PM_MOBIKE_OP_RESPONDER_ADDRESS_UPDATE:
        SSH_DEBUG(SSH_D_MIDOK,
                  ("Continuing suspended MOBIKE responder address update"));

        ctx = p1->mobike_suspended_operation;
        p1->mobike_suspended_op_type = SSH_PM_MOBIKE_OP_NOT_SUSPENDED;
        p1->mobike_suspended_operation = NULL;

        ssh_pm_mobike_responder_continue_address_update(pm, ctx);
        return;
    }

    /* MOBIKE responder does not need to do anything more. */
    if ((p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_MOBIKE_INITIATOR) == 0)
      return;

    SSH_DEBUG(SSH_D_NICETOKNOW, ("Checking MobIKE status of exchange "
                                 "IKE SA=%p, ED=%p", p1->ike_sa, ed));

    /* Check if NAT-T status has changed. */
    natt_status_changed = ssh_pm_mobike_get_exchange_natt_flags(p1, ed,
                                                                &natt_flags);

    if (natt_status_changed)
      SSH_DEBUG(SSH_D_MIDOK, ("NAT-T changed detected natt_flags=%x",
                              natt_flags));

    if (ed->multiple_addresses_used ||
        p1->address_update_pending ||
        natt_status_changed)
    {
        tunnel = ssh_pm_p1_get_tunnel(pm, p1);
        if (tunnel == NULL)
        {
            SSH_DEBUG(SSH_D_FAIL,
                      ("Could not find tunnel for IKE SA %p, tunnel_id %d",
                       p1->ike_sa, p1->tunnel_id));
            return;
        }
        pm_mobike_start_address_update(pm, p1, ed, tunnel, false);
        return;
    }

    /* Check if responder sent fresh additional address list. */
    for (notify = ed->notify; notify != NULL; notify = notify->next_notify)
    {
        switch (notify->notify_message_type)
        {
          case SSH_IKEV2_NOTIFY_ADDITIONAL_IP4_ADDRESS:
          case SSH_IKEV2_NOTIFY_ADDITIONAL_IP6_ADDRESS:
          case SSH_IKEV2_NOTIFY_NO_ADDITIONAL_ADDRESSES:
            ssh_pm_mobike_additional_addresses_received(pm, p1, ed);
            return;

          default:
            break;
        }
    }

    /* All done, no actions taken. */
}

/**************************** Receiving address updates **********************/

void
ssh_pm_mobike_address_update_received(SshPm pm,
                                      SshPmP1 p1,
                                      SshIkev2ExchangeData ed)
{
    uint32_t natt_flags = 0;

    /* Only MobIKE enabled IKE SAs need to react on this. */
    if ((p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_MOBIKE_ENABLED) == 0)
      return;

    /* MOBIKE initiator does not react on address updates. */
    if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_MOBIKE_INITIATOR)
      return;

    SSH_DEBUG(SSH_D_LOWOK, ("Address update received for IKE SA %p",
                            p1->ike_sa));







    if (p1->initiator_ops[PM_IKE_INITIATOR_OP_ADDRESS_UPDATE] == NULL)
    {
        SSH_DEBUG(SSH_D_LOWOK, ("Starting responder address update operation "
                                "for IKE SA %p", p1->ike_sa));

        p1->initiator_ops[PM_IKE_INITIATOR_OP_ADDRESS_UPDATE] =
          ssh_pm_mobike_responder_address_update(pm, p1, ed,
                                                 pm_mobike_operation_done_cb,
                                                 NULL);
    }
    else
    {
        /* Update IKE SA with fresh address information. */
        SSH_DEBUG(SSH_D_MIDOK,
                  ("Ongoing address update, updating IKE SA %p addresses.",
                   p1->ike_sa));

        (void)ssh_pm_mobike_get_exchange_natt_flags(p1, ed, &natt_flags);

        (void) ssh_pm_mobike_update_p1_addresses(pm, p1, ed->server,
                                                 ed->remote_ip,
                                                 ed->remote_port, natt_flags);

        p1->rrc_pending = 1;
    }
}


/*************************** Selecting Address Pairs *************************/

typedef struct SshPmAddressPairRec
{
    SshPmTunnelLocalIp local_ip;
    int remote_index;
} *SshPmAddressPair;


SshIkev2Error ssh_pm_mobike_get_address_pair(SshPm pm, SshPmP1 p1,
                                             uint32_t address_index,
                                             SshIkev2Server *server_ret,
                                             SshIpAddr remote_ip_ret)
{
    SshPmTunnel tunnel;
    uint32_t index, remote_index, num_address_pairs, num_remote_addrs;
    SshPmAddressPair address_pairs = NULL;
    SshPmTunnelLocalIp local_ip;
    SshIpAddr remote_ip;
    SshIkev2Server server;
    uint32_t server_flags;
    SshIkev2Error status = SSH_IKEV2_ERROR_OK;

    SSH_DEBUG(SSH_D_LOWSTART, ("Get address pair IKE SA %p index %d",
                               p1, (int) address_index));

    SSH_ASSERT(server_ret != NULL);
    SSH_ASSERT(remote_ip_ret != NULL);

    /* Lookup tunnel. */
    tunnel = ssh_pm_p1_get_tunnel(pm, p1);
    if (tunnel == NULL)
    {
        SSH_DEBUG(SSH_D_FAIL,
                  ("Could not find tunnel for IKE SA %p, tunnel_id %d",
                   p1->ike_sa, p1->tunnel_id));
        status = SSH_IKEV2_ERROR_INVALID_ARGUMENT;
        goto error;
    }

    /* Count maximum number of address pairs. */
    num_address_pairs = 0;
    for (local_ip = tunnel->local_ip;
         local_ip != NULL;
         local_ip = local_ip->next)
      num_address_pairs++;

    /* Count the valid remote addresses. */
    num_remote_addrs = 0;

    /* During initial exchange the peer has not yet sent the additional
       addresses. Thus we have just the peer address. */
    if (p1->ike_sa->num_additional_ip_addresses == 0)
      num_remote_addrs = 1;

    /* Else utilize the additional addresses from peer. Note that if we have
       received additional addresses then the first element is always the
       most recently used peer address (which may not be the IKE SA remote
       address in case the remote peer has done a forced address update). */
    else
    {
        for (index = 0;
             index < p1->ike_sa->num_additional_ip_addresses;
             index++)
        {
            if (!ssh_pm_mobike_valid_address(&p1->ike_sa->
                                             additional_ip_addresses[index]))
              continue;

            num_remote_addrs++;
        }
    }

    num_address_pairs *= num_remote_addrs;
    if (num_address_pairs == 0)
    {
        SSH_DEBUG(SSH_D_FAIL, ("No valid address pairs"));
        status = SSH_IKEV2_ERROR_INVALID_ARGUMENT;
        goto error;
    }

    /* Build a table of valid address pairs. */
    address_pairs = ssh_calloc(num_address_pairs, sizeof(*address_pairs));
    if (address_pairs == NULL)
    {
        status = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
        goto error;
    }

    /* Check that address families of local and remote addresses match. */
    num_address_pairs = 0;
    if (tunnel->local_port)
      server_flags = SSH_PM_SERVERS_MATCH_PORT;
    else
      server_flags = 0;
    for (local_ip = tunnel->local_ip;
         local_ip != NULL && num_address_pairs <= address_index;
         local_ip = local_ip->next)
    {
        /* Skip configured addresses that are not available. */
        if (local_ip->unavailable)
        {
            SSH_DEBUG(SSH_D_MIDOK, ("Skipping unavailable local ip"));
            continue;
        }

        SSH_DEBUG(SSH_D_NICETOKNOW,
                  ("Constructing address pairs from local IP %@",
                   ssh_ipaddr_render, &local_ip->ip));

        /* Check that there is an IKE server running on the local IP address
           on the tunnel local port. */
        server = ssh_pm_servers_select_ike(pm, &local_ip->ip, server_flags,
                                           SSH_INVALID_IFNUM,
                                           tunnel->local_port,
                                           tunnel->routing_instance_id);
        if (server == NULL)
        {
            SSH_DEBUG(SSH_D_NICETOKNOW, ("No IKE server running on address %@",
                                         ssh_ipaddr_render, &local_ip->ip));
            continue;
        }

        /* Additional addresses not yet received, check IKE SA remote
           address. */
        if (p1->ike_sa->num_additional_ip_addresses == 0)
        {
            remote_ip = p1->ike_sa->remote_ip;
            if (!ssh_pm_mobike_valid_address(remote_ip))
            {
                SSH_DEBUG(SSH_D_NICETOKNOW,
                          ("Skipping invalid IKE SA remote address '%@'",
                           ssh_ipaddr_render, remote_ip));
            }
            else
            {
                if ((SSH_IP_IS4(&local_ip->ip) && SSH_IP_IS4(remote_ip))
                    || (SSH_IP_IS6(&local_ip->ip) && SSH_IP_IS6(remote_ip)))
                {
                    address_pairs[num_address_pairs].local_ip = local_ip;
                    address_pairs[num_address_pairs].remote_index = -1;
                    num_address_pairs++;
                }
            }
        }

        /* Check additional remote addresses. The first element in the
           additional address list is the most recently used and
           known-to-work remote address. */
        else
        {
            for (remote_index = 0;
                 remote_index < p1->ike_sa->num_additional_ip_addresses &&
                   num_address_pairs <= address_index;
                 remote_index++)
            {
                remote_ip = &p1->ike_sa->additional_ip_addresses[remote_index];
                if (!ssh_pm_mobike_valid_address(remote_ip))
                {
                    SSH_DEBUG(SSH_D_NICETOKNOW,
                              ("Remote end send unusable additional address "
                               "'%@'. Address ignored.",
                               ssh_ipaddr_render, remote_ip));
                    continue;
                }

                if ((SSH_IP_IS4(&local_ip->ip) && SSH_IP_IS4(remote_ip))
                    || (SSH_IP_IS6(&local_ip->ip) && SSH_IP_IS6(remote_ip)))
                {
                    address_pairs[num_address_pairs].local_ip = local_ip;
                    address_pairs[num_address_pairs].remote_index =
                        remote_index;
                    num_address_pairs++;
                }
            }
        }
    }

    if (num_address_pairs == 0)
    {
        SSH_DEBUG(SSH_D_FAIL, ("No valid address pairs"));
        status = SSH_IKEV2_ERROR_INVALID_ARGUMENT;
        goto error;
    }

    /* Select the address pair indexed by address_index. */
    index = address_index % num_address_pairs;
    local_ip = address_pairs[index].local_ip;

    if (address_pairs[index].remote_index == -1)
    {
        *remote_ip_ret = *p1->ike_sa->remote_ip;
    }
    else
    {
        SSH_ASSERT(address_pairs[index].remote_index <
                   p1->ike_sa->num_additional_ip_addresses);
        *remote_ip_ret =
            p1->ike_sa->additional_ip_addresses[
                    address_pairs[index].remote_index];
    }

    /* Fetch the IKE server. */
    *server_ret = ssh_pm_servers_select_ike(pm, &local_ip->ip,
                                            server_flags,
                                            SSH_INVALID_IFNUM,
                                            tunnel->local_port,
                                            tunnel->routing_instance_id);

    SSH_DEBUG(SSH_D_MIDOK, ("Returning address pair %@ - %@",
                            ssh_ipaddr_render, (*server_ret)->ip_address,
                            ssh_ipaddr_render, remote_ip_ret));

    /* Cleanup. */
    ssh_free(address_pairs);

    SSH_ASSERT(*server_ret != NULL);
    SSH_ASSERT(SSH_IP_DEFINED(remote_ip_ret));
    SSH_ASSERT(status == SSH_IKEV2_ERROR_OK);

    return SSH_IKEV2_ERROR_OK;

    /* Error handling. */
   error:
    SSH_DEBUG(SSH_D_FAIL, ("Error: %s (%d)",
                           ssh_ikev2_error_to_string(status), (int) status));
    SSH_ASSERT(status != SSH_IKEV2_ERROR_OK);
    ssh_free(address_pairs);
    *server_ret = NULL;
    SSH_IP_UNDEFINE(remote_ip_ret);

    return status;
}

#endif /* SSHDIST_IPSEC_MOBIKE */
