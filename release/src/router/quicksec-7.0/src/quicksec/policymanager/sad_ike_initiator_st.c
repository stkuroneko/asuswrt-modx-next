/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   Quick-Mode initiator.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"

#define SSH_DEBUG_MODULE "SshPmStQmInitiator"

/********************************** States **********************************/

SSH_FSM_STEP(ssh_pm_st_qm_i_trigger)
{
    SshPmQm qm = (SshPmQm) thread_context;

    SSH_DEBUG(SSH_D_MIDOK, ("Starting auto-start rule"));

    /* Store transform properties. */
    qm->transform = qm->tunnel->transform;

    SSH_ASSERT(qm->local_ts != NULL);
    SSH_ASSERT(qm->remote_ts != NULL);
    SSH_ASSERT(qm->dpd == 0); /* DPD should never end up here. */

    SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_start_negotiation);
    return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_qm_i_start_negotiation)
{
#ifdef WITH_IKE
    SshPmQm qm = (SshPmQm) thread_context;

    /* Negotiate SA by calling our `Quick-Mode Negotiation' sub
       state-machine. */
    qm->fsm_qm_i_n_success = ssh_pm_st_qm_i_negotiation_done;
    qm->fsm_qm_i_n_failed = ssh_pm_st_qm_i_failed;

    SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_n_start);
#else /* WITH_IKE */

    SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_failed);
#endif /* WITH_IKE */

    return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_qm_i_negotiation_done)
{
    SshPmQm qm = (SshPmQm) thread_context;

    /* Mark that the trigger rule is no longer being used for a Quick-Mode
       negotiation. */
    if (qm->rule)
    {
        qm->rule->ike_in_progress = 0;
    }
    else
    {
        /* DPD intiator */
        SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_success);
        return SSH_FSM_CONTINUE;
    }

    /* The SA handler has created our rule. */
    SSH_DEBUG(SSH_D_NICETOKNOW, ("SA handler implemented SA"));
    SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_success);

    return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_qm_i_rekey)
{
#ifdef DEBUG_LIGHT
    SshPmQm qm = (SshPmQm) thread_context;
#endif /* DEBUG_LIGHT */
    /* The transform properties are already set. */
    SSH_ASSERT(qm->transform != 0);
    SSH_ASSERT(qm->tunnel != NULL);

    /* Negotiate. */
    SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_start_negotiation);
    return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(ssh_pm_st_qm_i_auto_start)
{
    SshPm pm = (SshPm) fsm_context;
    SshPmQm qm = (SshPmQm) thread_context;
    uint32_t ifnum = SSH_INVALID_IFNUM;
    SshIpAddr peer_ip;
    SshIpAddrStruct local_ip;

    if (ssh_pm_check_qm_error(qm, thread, ssh_pm_st_qm_i_failed))
      return SSH_FSM_CONTINUE;

    if (SSH_IP6_IS_LINK_LOCAL(&qm->sel_dst)
        && qm->tunnel->local_ip == NULL)
    {
        ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_WARNING,
                      "Tunnel end-point %@ is a link-local address, but "
                      "tunnel local-ip is undefined. This is a "
                      "configuration error!",
                      ssh_ipaddr_render, &qm->sel_dst);
    }

    peer_ip = &qm->sel_dst;
    if (qm->tunnel->num_peers && SSH_IP_DEFINED(&qm->tunnel->peers[0]))
      peer_ip = &qm->tunnel->peers[0];

    /* Does the tunnel specify a local IP address to use? */
    ssh_pm_tunnel_select_local_ip(qm->tunnel, peer_ip, &local_ip);
    if (SSH_IP_DEFINED(&local_ip))
    {
        /* Yes.  Let's resolve the interface number by the local IP
           address.  Note that the interface number is only used if the
           destination address is a multicast or a broadcast address. */
        (void) ssh_pm_find_interface_by_address_prefix(
                                              pm,
                                              &qm->tunnel->local_ip->ip,
                                              qm->tunnel->routing_instance_id,
                                              &ifnum);
        SSH_DEBUG(SSH_D_NICETOKNOW,
                  ("Setting ifnum hint %u for address %@",
                   (unsigned int) ifnum, ssh_ipaddr_render, &local_ip));
    }

    SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_trigger);
    return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_qm_i_success)
{
    SshPm pm = (SshPm) fsm_context;
    SshPmQm qm = (SshPmQm) thread_context;
    SshIkev2PayloadTS packet_src = NULL, packet_dst = NULL;

    /* The negotiation was successful. */
    SSH_FSM_SET_NEXT(ssh_pm_st_qm_terminate);

    SSH_ASSERT(qm->sa_handler_done);
    SSH_ASSERT(qm->error == 0);

    if (qm->packet)
    {
        SshIpAddrStruct src;
        SshIpAddrStruct dst;
        /* Check if the trigger packet fits into the negotiated traffic
           selectors. */
        packet_src = ssh_ikev2_ts_allocate(pm->sad_handle);
        packet_dst = ssh_ikev2_ts_allocate(pm->sad_handle);
        if (packet_src == NULL || packet_dst == NULL)
        {
            SSH_DEBUG(SSH_D_FAIL, ("Unable to reprocess trigger packet"));
            goto out;
        }

        if (qm->packet_protocol == SSH_PROTOCOL_IP4)
        {
            if (qm->packet_len < SSH_IPH4_HDRLEN)
            {
                SSH_DEBUG(SSH_D_FAIL, ("Unable to reprocess trigger packet"));
                goto out;
            }
            SSH_IPH4_SRC(&src, qm->packet);
            SSH_IPH4_DST(&dst, qm->packet);
        }
        else if (qm->packet_protocol == SSH_PROTOCOL_IP6)
        {
            if (qm->packet_len < SSH_IPH6_HDRLEN)
            {
                SSH_DEBUG(SSH_D_FAIL, ("Unable to reprocess trigger packet"));
                goto out;
            }
            SSH_IPH6_SRC(&src, qm->packet);
            SSH_IPH6_DST(&dst, qm->packet);
        }
        else
        {
            SSH_DEBUG(SSH_D_FAIL, ("Unable to reprocess trigger packet"));
            goto out;
        }
        if (ssh_ikev2_ts_item_add(packet_src, qm->sel_ipproto,
                                  &src, &src,
                                  qm->sel_src_port, qm->sel_src_port)
            != SSH_IKEV2_ERROR_OK)
        {
            SSH_DEBUG(SSH_D_FAIL, ("Unable to reprocess trigger packet"));
            goto out;
        }

        if (ssh_ikev2_ts_item_add(packet_dst, qm->sel_ipproto,
                                  &dst, &dst,
                                  qm->sel_dst_port, qm->sel_dst_port)
            != SSH_IKEV2_ERROR_OK)
        {
            SSH_DEBUG(SSH_D_FAIL, ("Unable to reprocess trigger packet"));
            goto out;
        }

        if (ssh_ikev2_ts_match(qm->local_ts, packet_src)
            && ssh_ikev2_ts_match(qm->remote_ts, packet_dst))
        {
            /* Yes, trigger packet fits into SA traffic selectors,
               reprocess trigger packet. */
            ssh_ikev2_ts_free(pm->sad_handle, packet_src);
            ssh_ikev2_ts_free(pm->sad_handle, packet_dst);

            /* Let's reprocess the triggered packet after a short timeout,
               if possible. This same timeout container is used also during
               rekey. */
            SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_reprocess_trigger);
            SSH_FSM_ASYNC_CALL({
              ssh_register_timeout(qm->timeout,
                                   0, SSH_PM_TRIGGER_REPROCESS_DELAY,
                                   ssh_pm_timeout_cb, thread);
            });
            SSH_NOTREACHED;
        }
        else
        {
            /* No, trigger packet does not fit into SA traffic selectors.
               Drop trigger packet. */
            SSH_DEBUG(SSH_D_NICETOKNOW,
                      ("Trigger packet does not fit into negotiated "
                       "traffic selectors, dropping trigger packet"));
        }
    }

   out:
    if (packet_src)
      ssh_ikev2_ts_free(pm->sad_handle, packet_src);
    if (packet_dst)
      ssh_ikev2_ts_free(pm->sad_handle, packet_dst);

    return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_qm_i_reprocess_trigger)
{
    SshPmQm qm = (SshPmQm) thread_context;

    SSH_ASSERT(qm->packet != NULL);

    SSH_FSM_SET_NEXT(ssh_pm_st_qm_terminate);
    return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_qm_i_failed)
{
    SshPmQm qm = (SshPmQm) thread_context;

#ifdef SSHDIST_IKEV1
    if (qm->error == SSH_IKEV2_ERROR_USE_IKEV1)
    {
        if (qm->tunnel->u.ike.versions & SSH_PM_IKE_VERSION_1)
        {
            qm->ike_done = 0;
            SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_n_alloc_ike_sa);
            return SSH_FSM_CONTINUE;
        }

        ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_WARNING,
                      "Policy denied fallback to IKEv1 for peer %@",
                      ssh_ipaddr_render, &qm->initial_remote_addr);
    }
#endif /* SSHDIST_IKEV1 */

    /* Mark that the rule is no longer being used for a Quick-Mode
       negotiation. */
    if (qm->rule)
      qm->rule->ike_in_progress = 0;

    SSH_ASSERT(qm->error != SSH_IKEV2_ERROR_OK);

    SSH_FSM_SET_NEXT(ssh_pm_st_qm_terminate);

    return SSH_FSM_CONTINUE;
}
