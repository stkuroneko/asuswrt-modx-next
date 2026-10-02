/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Quick-Mode initiator.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"

#define SSH_DEBUG_MODULE "SshPmStQmInitiator"

/************************** Static help functions ***************************/

#ifdef SSHDIST_IPSEC_NAT
#ifdef SSHDIST_IPSEC_FIREWALL
static void
ssh_pm_qm_appgw_auto_get_rule_cb(SshPm pm,
                                 const SshEnginePolicyRule rule,
                                 void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshPmQm qm = (SshPmQm) ssh_fsm_get_tdata(thread);

  if (rule != NULL)
    {
      SSH_ASSERT(rule->type != SSH_ENGINE_RULE_NONEXISTENT);
      qm->appgw_trigger_rule = *rule;
    }
  else
    qm->error = SSH_PM_QM_ERROR_INTERNAL_PM;

 SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}
#endif /* SSHDIST_IPSEC_FIREWALL */
#endif /* SSHDIST_IPSEC_NAT */


/********************************** States **********************************/


SSH_FSM_STEP(ssh_pm_st_qm_i_trigger)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmQm qm = (SshPmQm) thread_context;

  /* Store transform properties. */
  qm->transform = qm->tunnel->transform;

  /* Check manually keyed tunnels. */
  if (qm->tunnel->manual_tn)
    {
      if (qm->tunnel->u.manual.trd_index != SSH_IPSEC_INVALID_INDEX)
        {
          /* The transform is already created. */
          SSH_DEBUG(SSH_D_NICETOKNOW, ("Manual tunnel already up"));
          qm->trd_index = qm->tunnel->u.manual.trd_index;

          SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_sa_lookup_result);
          return SSH_FSM_CONTINUE;
        }

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
      /* Check outer tunnel VIP status. */
      if (qm->tunnel->outer_tunnel != NULL)
        {
          if (SSH_PM_TUNNEL_IS_VIRTUAL_IP(qm->tunnel->outer_tunnel)
              && !SSH_PM_VIP_READY(qm->tunnel->outer_tunnel))
            {
              SSH_DEBUG(SSH_D_FAIL,
                    ("Outer tunnel virtual IP setup is not ready."));
              qm->error = SSH_PM_QM_ERROR_NETWORK_UNAVAILABLE;
              SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_failed);
              return SSH_FSM_CONTINUE;
            }
        }
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

      /* Start our SA handler thread. */
      if (!ssh_pm_manual_sa_handler(pm, qm))
        {
          /* Immediate error. Mark SA handler done. */
          qm->error = SSH_PM_QM_ERROR_INTERNAL_PM;
          qm->sa_handler_done = 1;
        }

      /* And wait that SA handler terminates. */
      SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_manual_sa_handler_result);
      return SSH_FSM_CONTINUE;
    }

  SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_check_apply_rule);
  return SSH_FSM_CONTINUE;
}


/* Determine if we really need to perform a Quick-Mode negotiation. A
   new SA should not be negotiated if a suitable transform already exists
   in the engine, doing so for IKEv1 SA's will cause problems since multiple
   SA's with the same traffic selectors is not supported.

   This check is necessary for both auto-start rules and for trigger rules.
   For trigger rules there are race conditions between the engine and policy
   manager, a trigger may be received at the policy manager just after a
   suitable apply rule is installed to the engine. Auto-start negotiations
   are triggered from the transform destroy notification. If a transform
   is destroyed (for example because of simultanuous IPsec negotiations) it
   is not always needed to start a new negotiation.
*/
SSH_FSM_STEP(ssh_pm_st_qm_i_check_apply_rule)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmQm qm = (SshPmQm) thread_context;

  SSH_DEBUG(SSH_D_MIDOK, ("Checking if a apply rule exists before starting "
                          "auto-start rule"));

  SSH_ASSERT(qm->local_ts != NULL);
  SSH_ASSERT(qm->remote_ts != NULL);
  SSH_ASSERT(qm->dpd == 0); /* DPD should never end up here. */

  /* Create an outbound rule from the first pair of traffic selectors from
     the auto-start rule. */
  if (!ssh_pm_make_sa_outbound_rule(pm, qm, TRUE, qm->rule,
                                    qm->local_ts, 0,
                                    qm->remote_ts, 0,
                                    &qm->sa_outbound_rule))
    {
      /** Rule creation failed. */
      SSH_DEBUG(SSH_D_ERROR, ("Could not create outbound SA rule"));
      qm->error = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
      SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_failed);
      return SSH_FSM_CONTINUE;
    }

  /* Consult the rule database in the engine to check if a matching apply
     rule exists in the engine. We do not care about the exact transform
     algorithms. */
  SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_check_apply_rule_result);
  SSH_FSM_ASYNC_CALL({
    ssh_pme_find_matching_transform_rule(pm->engine,
                                         &qm->sa_outbound_rule,
                                         0, 0, NULL, NULL, 0, 0, NULL,
                                         SSH_PME_RULE_MATCH_ANY_IFNUM,
                                         ssh_pm_sa_index_cb,
                                         thread);
  });

}

SSH_FSM_STEP(ssh_pm_st_qm_i_check_apply_rule_result)
{
  SshPmQm qm = (SshPmQm) thread_context;

 if (ssh_pm_check_qm_error(qm, thread, ssh_pm_st_qm_i_failed))
    return SSH_FSM_CONTINUE;

 if (qm->trd_index != SSH_IPSEC_INVALID_INDEX)
   {
     SSH_DEBUG(SSH_D_LOWOK, ("Apply rule already present in the engine, "
                             "not doing Quick-Mode negotiation"));

     SSH_ASSERT(qm->rule != NULL);
     qm->rule->ike_in_progress = 0;

     SSH_FSM_SET_NEXT(ssh_pm_st_qm_terminate);
     return SSH_FSM_CONTINUE;
   }

 SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_start_negotiation);
 return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(ssh_pm_st_qm_i_sa_lookup_result)
{
  SshPmQm qm = (SshPmQm) thread_context;

  if (qm->trd_index == SSH_IPSEC_INVALID_INDEX)
    {
      /* We added a rule/trd below, which we came here to find, and
         we did not find it. Fail. */
      if (qm->sa_index != SSH_IPSEC_INVALID_INDEX)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Failed to find previously added rule %d!",
                     (int) qm->sa_index));



          qm->error = SSH_IKEV2_ERROR_INVALID_SYNTAX;
          SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_failed);
          return SSH_FSM_CONTINUE;
        }
      /* Negotiate. */
      SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_start_negotiation);
      return SSH_FSM_CONTINUE;
    }

  /* We have an applicable SA. */
  SSH_DEBUG(SSH_D_NICETOKNOW, ("Found an applicable SA: trd_index=0x%x",
                               (unsigned int) qm->trd_index));

  SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_make_sa_rule);
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

  if (qm->is_sa_rule_modified && !qm->rekey)
    {
      /* Yes we did.  We must create another rule applying the trigger
         rule's SA selectors. */
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Proxy ID rule not sufficient: "
                 "need another SA rule: trd_index=0x%x",
                 (unsigned int) qm->trd_index));
      SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_make_sa_rule);
    }
  else
    {
      /* No we did not.  The SA handler has already created our
         rule. */
      SSH_DEBUG(SSH_D_NICETOKNOW, ("SA handler implemented SA"));
      SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_success);
    }

  return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(ssh_pm_st_qm_i_make_sa_rule)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmQm qm = (SshPmQm) thread_context;
  SshPmRule rule;
  SshUInt32 local_ind = 0, remote_ind = 0;

  if (ssh_pm_check_qm_error(qm, thread, ssh_pm_st_qm_i_failed))
    return SSH_FSM_CONTINUE;

  /* Create an outbound rule for the SA. */
  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Creating SA rule: local TS=%@, remote TS=%@",
             ssh_ikev2_ts_render, qm->local_trigger_ts,
             ssh_ikev2_ts_render, qm->remote_trigger_ts));

  SSH_ASSERT(qm->rule != NULL);
  rule = qm->rule;

  if (qm->tunnel && qm->tunnel->manual_tn)
    {
      local_ind = qm->local_ts_item_index;
      remote_ind = qm->remote_ts_item_index;
    }

  /* The trigger rule applies the rule in the 'forward' direction
     if qm->forward is set. APPGW dynamic ports may apply a rule
     in the reverse direction when dynamic ports are opened. */
  if (!ssh_pm_make_sa_outbound_rule(pm, qm, qm->forward, rule,
                                    qm->local_trigger_ts, local_ind,
                                    qm->remote_trigger_ts, remote_ind,
                                    &qm->sa_outbound_rule))
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not create outbound SA rule"));
      qm->error = SSH_IKEV2_ERROR_NO_PROPOSAL_CHOSEN;
      SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_failed);
      return SSH_FSM_CONTINUE;
    }

#ifdef SSHDIST_IPSEC_NAT
#ifdef SSHDIST_IPSEC_FIREWALL
  /* Because this is not a master rule for the transform (already created),
     we can safely make an APPLY/TRIGGER rule with pre-NAT selectors. */
  if ((!SSH_IP_EQUAL(&qm->packet_orig_src_ip, &qm->sel_src))
      || qm->packet_orig_src_port != qm->sel_src_port
      || (!SSH_IP_EQUAL(&qm->packet_orig_dst_ip, &qm->sel_dst))
      || qm->packet_orig_dst_port != qm->sel_dst_port)
    {
      size_t ip_len;
      SshEnginePolicyRule engine_rule = &qm->sa_outbound_rule;

      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Changing APPLY rule source selectors to pre-NAT "
                 "configuration."));

      if (SSH_IP_IS4(&qm->sel_src) == SSH_IP_IS4(&qm->packet_orig_src_ip))
        {
          SSH_IP_ENCODE(&qm->packet_orig_src_ip, engine_rule->src_ip_low,
                        ip_len);
          SSH_IP_ENCODE(&qm->packet_orig_src_ip, engine_rule->src_ip_high,
                        ip_len);
        }

      if (SSH_IP_IS4(&qm->sel_dst) == SSH_IP_IS4(&qm->packet_orig_dst_ip))
        {
          SSH_IP_ENCODE(&qm->packet_orig_dst_ip, engine_rule->dst_ip_low,
                        ip_len);
          SSH_IP_ENCODE(&qm->packet_orig_dst_ip, engine_rule->dst_ip_high,
                        ip_len);
        }

      engine_rule->src_port_low = qm->packet_orig_src_port;
      engine_rule->src_port_high = qm->packet_orig_src_port;
      engine_rule->dst_port_low = qm->packet_orig_dst_port;
      engine_rule->dst_port_high = qm->packet_orig_dst_port;
    }

  if (qm->rule->service != NULL
      && qm->rule->service->appgw_ident != NULL)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Creating IPSec'd appgw to-tunnel rule for trd 0x%08lx!",
                 (unsigned long) qm->trd_index));

      /* For auto-start rule we need to fetch the engine rule previously
         installed from the trigger rule and set qm->appgw_trigger_rule
         from that. */
      if (qm->appgw_trigger_rule.type == SSH_ENGINE_RULE_NONEXISTENT)
        {
          SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_make_sa_rule);
          SSH_FSM_ASYNC_CALL(ssh_pme_get_rule(pm->engine,
                                              qm->rule->rules[0],
                                              ssh_pm_qm_appgw_auto_get_rule_cb,
                                              thread));
        }






     SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_add_rule_result);
     SSH_FSM_ASYNC_CALL(ssh_appgw_create_totunnel_rule(pm,
                                                       &qm->appgw_trigger_rule,
                                                       qm->trd_index,
                                                       qm->is_appgw_new_session
                                                       ? TRUE : FALSE,
                                                       ssh_pm_add_sa_rule_cb,
                                                       thread));
     SSH_NOTREACHED;
    }

#endif /* SSHDIST_IPSEC_FIREWALL */
#endif /* SSHDIST_IPSEC_NAT */

  qm->sa_outbound_rule.transform_index = qm->trd_index;

  SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_add_rule_result);
  SSH_FSM_ASYNC_CALL(ssh_pme_add_rule(pm->engine, qm->rekey,
                                      &qm->sa_outbound_rule,
                                      ssh_pm_add_sa_rule_cb, thread));
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_pm_st_qm_i_add_rule_result)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmQm qm = (SshPmQm) thread_context;

  if (qm->sa_index == SSH_IPSEC_INVALID_INDEX)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not create outbound SA rule"));
      qm->error = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
    }

  if (qm->error != SSH_IKEV2_ERROR_OK)
    {
      SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_failed);
      return SSH_FSM_CONTINUE;
    }

  if (qm->tunnel->manual_tn)
    {
      if (++qm->remote_ts_item_index == qm->remote_ts->number_of_items_used)
        {
          if (++qm->local_ts_item_index == qm->local_ts->number_of_items_used)
            {
              ssh_pm_log_manual_sa_event(pm, qm, FALSE, "completed");

              /* Rule added successfully.  Let's fake a successful SA handler
                 termination. */
              qm->sa_handler_done = 1;
              SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_success);

              return SSH_FSM_CONTINUE;
            }
          qm->remote_ts_item_index = 0;
        }

      SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_make_sa_rule);
      return SSH_FSM_CONTINUE;
    }

  /* Rule added successfully.  Let's fake a successful SA handler
     termination. */
  qm->sa_handler_done = 1;
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
  SshUInt32 ifnum = SSH_INVALID_IFNUM;
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
      (void) ssh_pm_find_interface_by_address_prefix(pm,
                                                     &qm->tunnel->local_ip->ip,
                                                     &ifnum);
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Setting ifnum hint %u for address %@",
                 (unsigned int) ifnum, ssh_ipaddr_render, &local_ip));
    }

  qm->packet_ifnum = SSH_INVALID_IFNUM;

  SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_trigger);
  return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(ssh_pm_st_qm_i_manual_sa_handler_result)
{
  SshPmQm qm = (SshPmQm) thread_context;

  /* Wait until the transform is installed. */
  if (!qm->sa_handler_done)
    {
      SSH_DEBUG(SSH_D_LOWSTART, ("Suspending until SA handler completes"));
      return SSH_FSM_SUSPENDED;
    }

  if (qm->error)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Manual SA handler failed"));
      SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_failed);
      return SSH_FSM_CONTINUE;
    }

  /* Store transform index in the tunnel. */
  SSH_ASSERT(qm->trd_index != SSH_IPSEC_INVALID_INDEX);
  SSH_ASSERT(qm->tunnel != NULL);
  SSH_DEBUG(SSH_D_LOWOK, ("Transform %u implements manual tunnel",
                          (unsigned int) qm->trd_index));
  qm->tunnel->u.manual.trd_index = qm->trd_index;

  /* The manually keyed tunnel is now up.  We do not clear or free the
     key since it is needed in possible reconfiguration.  However, the
     key will be freed when the tunnel object is freed. */

  SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_negotiation_done);
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

#ifdef SSHDIST_IPSEC_NAT
#ifdef SSHDIST_IPSEC_FIREWALL
  /* Check if we need application gateway processing after IPSec. */
  if (qm->rule
      && qm->rule->service
      && qm->rule->service->appgw_ident)
    {
      SshIpAddr new_dst_ip = NULL;
      SshUInt16 new_dst_port = 0;

      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Application gateway `%s' with IPSec: "
                 "new session=%u slave=%u",
                 qm->rule->service->appgw_ident,
                 qm->is_appgw_new_session,
                 qm->is_appgw_slave));

      /* Assert that the tunnel we are negotiating is in the
         forward direction */
#ifdef DEBUG_LIGHT
      if (qm->forward)
        SSH_ASSERT(qm->tunnel == qm->rule->side_to.tunnel);
      else
        SSH_ASSERT(qm->tunnel == qm->rule->side_from.tunnel);
#endif /* DEBUG_LIGHT */

      if (qm->is_appgw_new_session
          && (qm->appgw_trigger_rule.flags & SSH_PM_ENGINE_RULE_APPGW))
        {
          if ((!SSH_IP_EQUAL(&qm->packet_orig_dst_ip, &qm->sel_dst))
              || qm->packet_orig_dst_port != qm->sel_dst_port)
            {
              new_dst_ip = &qm->sel_dst;
              new_dst_port = qm->sel_dst_port;
            }

          ssh_pm_appgw_request(pm, qm->rule, qm->rule->service,
                               qm->master_connection,
                               qm->appgw_trigger_rule.rule_index,
                               qm->flow_index,
                               qm->packet_protocol,
                               qm->packet_ifnum, qm->packet_flags,
                               qm->appgw_trigger_rule.rule_index,
                               qm->packet_tunnel_id,
                               qm->tunnel->tunnel_id,
                               qm->trd_index,
                               qm->packet_prev_transform_index,
                               &qm->packet_orig_src_ip,
                               &qm->packet_orig_dst_ip,
                               qm->sel_ipproto,
                               qm->packet_orig_src_port,
                               qm->packet_orig_dst_port,
                               new_dst_ip, new_dst_port,
                               qm->packet, qm->packet_len);

          /* A possible packet belongs now to the application gateway
             module. */
          qm->packet = NULL;
          qm->packet_len = 0;
        }
    }
#endif /* SSHDIST_IPSEC_FIREWALL */
#endif /* SSHDIST_IPSEC_NAT */

  if (qm->packet)
    {
      /* Check if the trigger packet fits into the negotiated traffic
         selectors. */
      packet_src = ssh_ikev2_ts_allocate(pm->sad_handle);
      packet_dst = ssh_ikev2_ts_allocate(pm->sad_handle);
      if (packet_src == NULL || packet_dst == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Unable to reprocess trigger packet"));
          goto out;
        }

      if (ssh_ikev2_ts_item_add(packet_src, qm->sel_ipproto,
                                &qm->sel_src, &qm->sel_src,
                                qm->sel_src_port, qm->sel_src_port)
          != SSH_IKEV2_ERROR_OK)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Unable to reprocess trigger packet"));
          goto out;
        }

      if (ssh_ikev2_ts_item_add(packet_dst, qm->sel_ipproto,
                                &qm->sel_dst, &qm->sel_dst,
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
             Drop trigger packet and set trigger flow status to drop mode.
             New triggers are generated for the flow after the current
             trigger flow expires in near future. */
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Trigger packet does not fit into negotiated "
                     "traffic selectors, dropping trigger packet"));
          if (qm->flow_index != SSH_IPSEC_INVALID_INDEX)
            {
              SSH_DEBUG(SSH_D_NICETOKNOW,
                        ("Disabling trigger events for trigger flow %d",
                         (int) qm->flow_index));
              ssh_pme_flow_set_status(pm->engine,
                                      qm->flow_index,
                                      SSH_PME_FLOW_DROP_EXPIRE,
                                      NULL_FNPTR, NULL);
            }
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
  SshPm pm = (SshPm) fsm_context;
  SshPmQm qm = (SshPmQm) thread_context;

  SSH_ASSERT(qm->packet != NULL);

  /* This does not free `qm->packet'. */
  ssh_pme_process_packet(pm->engine, qm->packet_tunnel_id,
                         qm->packet_protocol, qm->packet_ifnum,
                         qm->packet_flags | SSH_PME_PACKET_NOTRIGGER,
                         qm->packet_prev_transform_index,
                         qm->packet, qm->packet_len);

  SSH_FSM_SET_NEXT(ssh_pm_st_qm_terminate);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_qm_i_failed)
{
  SshPm pm = (SshPm) fsm_context;
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

  if (qm->flow_index != SSH_IPSEC_INVALID_INDEX
      && (qm->error == SSH_IKEV2_ERROR_NO_PROPOSAL_CHOSEN
          || qm->error == SSH_IKEV2_ERROR_TS_UNACCEPTABLE
          || qm->error == SSH_IKEV2_NOTIFY_FAILED_CP_REQUIRED
          || qm->error == SSH_IKEV2_NOTIFY_NO_ADDITIONAL_SAS))
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Disabling trigger events for trigger flow %d",
                 (int) qm->flow_index));
      ssh_pme_flow_set_status(pm->engine,
                              qm->flow_index,
                              SSH_PME_FLOW_DROP_EXPIRE,
                              NULL_FNPTR, NULL);
    }

  if (qm->tunnel->manual_tn)
    {
      ssh_pm_log_manual_sa_event(pm, qm, FALSE, "failed");
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                    "  Message: %s (%d)",
                    ssh_pm_qm_error_to_string(qm->error), qm->error);
    }

  /* Mark that the rule is no longer being used for a Quick-Mode
     negotiation. */
  if (qm->rule)
    qm->rule->ike_in_progress = 0;

  SSH_ASSERT(qm->error != SSH_IKEV2_ERROR_OK);

  SSH_FSM_SET_NEXT(ssh_pm_st_qm_terminate);

  return SSH_FSM_CONTINUE;
}
