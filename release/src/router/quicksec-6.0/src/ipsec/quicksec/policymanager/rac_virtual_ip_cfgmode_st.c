/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Virtual IP with IKE configuration mode.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
#ifdef SSHDIST_ISAKMP_CFG_MODE

#define SSH_DEBUG_MODULE "SshPmStVirtualIpCfgmode"

/************************** Static help functions ***************************/

#ifdef SSHDIST_IPSEC_NAT
#ifdef SSHDIST_IPSEC_FIREWALL
static void
ssh_pm_qm_appgw_vip_auto_get_rule_cb(SshPm pm,
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


/************************** Types and definitions ***************************/

SSH_FSM_STEP(ssh_pm_st_vip_start_qm_negotiation)
{
  SshPmQm qm = (SshPmQm) thread_context;

  SSH_ASSERT(qm->transform != 0);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Virtual IP CFGMODE QM thread starting"));

  /* Set the final states which will continue the VIP thread. */
  qm->fsm_qm_i_n_success = ssh_pm_st_vip_qm_negotiation_done;
  qm->fsm_qm_i_n_failed = ssh_pm_st_vip_qm_failed;

  /* Negotiate the SA by calling our `Quick-Mode Negotiation' sub
     state-machine. */
  SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_n_start);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_vip_qm_negotiation_done)
{
  SshPmQm qm = (SshPmQm) thread_context;
  SshPmVip vip = qm->vip;
  SshPmP1 p1;

  SSH_PM_ASSERT_QM(qm);
  SSH_ASSERT(qm->p1 != NULL);

  vip->t.cfgmode.done = 1;

  /* Check for errors in case the Phase-I has been freed */
  if (qm->error != SSH_IKEV2_ERROR_OK)
    {
      vip->t.cfgmode.ike_error = qm->error;
      vip->p1 = NULL;

      /* Delete IKE SA if it was negotiated successfully, otherwise the next
         trigger will cause qm negotiation and vip will never be set up. */
      if (qm->p1 && !SSH_PM_P1_DELETED(qm->p1))
        {
          p1 = qm->p1;
          SSH_PM_IKEV2_IKE_SA_DELETE(p1, 0,
                                  pm_ike_sa_delete_notification_done_callback);
        }
    }
  else
    {
      vip->t.cfgmode.ike_error = SSH_IKEV2_ERROR_OK;

      SSH_ASSERT(qm->p1 != NULL);
      vip->p1 = qm->p1;

      /* The Quick-Mode and Phase-1 successfully completed.
         Record the SGW IP address. */
      ssh_pm_vip_flush_sgw_routes(vip);
      ssh_pm_vip_create_sgw_route(vip, vip->p1->ike_sa->remote_ip);

      if (qm->is_sa_rule_modified && !qm->rekey)
        {
          /* Yes we did.  We must create another rule applying the trigger
             rule's SA selectors. */
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Proxy ID rule not sufficient: "
                     "need another SA rule: trd_index=0x%x",
                     (unsigned int) qm->trd_index));

          SSH_FSM_SET_NEXT(ssh_pm_st_vip_i_make_sa_rule);
          return SSH_FSM_CONTINUE;
        }
    }

  /* Wake up the VIP thread. */
  ssh_fsm_continue(&vip->thread);

  /* Terminate the Quick-Mode thread */
  SSH_DEBUG(SSH_D_NICETOKNOW, ("Virtual IP CFGMODE QM thread terminating"));
  SSH_FSM_SET_NEXT(ssh_pm_st_qm_terminate);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_vip_i_make_sa_rule)
{
  SshPm     pm   = (SshPm) fsm_context;
  SshPmQm   qm   = (SshPmQm) thread_context;
  SshPmVip  vip  = qm->vip;
  SshPmRule rule;

  /* Create an outbound rule for the SA. */
  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Creating SA rule: local TS=%@, remote TS=%@",
             ssh_ikev2_ts_render, qm->local_trigger_ts,
             ssh_ikev2_ts_render, qm->remote_trigger_ts));

  SSH_ASSERT(qm->rule != NULL);
  rule = qm->rule;

  /* The trigger rule applies the rule in the 'forward' direction
     if qm->forward is set. APPGW dynamic ports may apply a rule
     in the reverse direction when dynamic ports are opened. */
  if (!ssh_pm_make_sa_outbound_rule(pm, qm, qm->forward, rule,
                                    qm->local_trigger_ts, 0,
                                    qm->remote_trigger_ts, 0,
                                    &qm->sa_outbound_rule))
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not create outbound SA rule"));
      qm->error = SSH_IKEV2_ERROR_NO_PROPOSAL_CHOSEN;
      vip->t.cfgmode.ike_error = qm->error;
      vip->p1 = NULL;

      /* Wake up the VIP thread. */
      ssh_fsm_continue(&vip->thread);

      /* Terminate the Quick-Mode thread */
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Virtual IP CFGMODE QM thread terminating"));
      SSH_FSM_SET_NEXT(ssh_pm_st_qm_terminate);
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
          SSH_FSM_SET_NEXT(ssh_pm_st_vip_i_make_sa_rule);
          SSH_FSM_ASYNC_CALL(ssh_pme_get_rule(pm->engine,
                                         qm->rule->rules[0],
                                         ssh_pm_qm_appgw_vip_auto_get_rule_cb,
                                         thread));
        }




      SSH_FSM_SET_NEXT(ssh_pm_st_vip_qm_i_add_rule_result);
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

SSH_FSM_STEP(ssh_pm_st_vip_qm_i_add_rule_result)
{
  SshPmQm qm = (SshPmQm) thread_context;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("vip add rule result"));

  if (qm->sa_index == SSH_IPSEC_INVALID_INDEX)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not create outbound SA rule"));
      qm->error = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
      qm->vip->t.cfgmode.ike_error = qm->error;
      qm->vip->p1 = NULL;

    }

  ssh_fsm_continue(&qm->vip->thread);

  /* Terminate the Quick-Mode thread */
  SSH_DEBUG(SSH_D_NICETOKNOW, ("Virtual IP CFGMODE QM thread terminating"));
  SSH_FSM_SET_NEXT(ssh_pm_st_qm_terminate);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_vip_qm_failed)
{
  SshPmQm qm = (SshPmQm) thread_context;
  SshPmVip vip = qm->vip;
  SshPmP1 p1;

  SSH_PM_ASSERT_QM(qm);

  SSH_DEBUG(SSH_D_FAIL, ("Virtual IP CFGMODE qm failed error %u", qm->error));

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

  /* If IPsec SA negotiation was restarted due to INVALID_KE_PAYLOAD then
     the ownership of the vip object has been moved to the new qm object,
     and thus we do not need to worry about the vip thread here. */
  if (vip != NULL)
    {
      vip->t.cfgmode.done = 1;
      if (qm->error == SSH_IKEV2_ERROR_OK)
        vip->t.cfgmode.ike_error = SSH_IKEV2_ERROR_INVALID_ARGUMENT;
      else
        {
          vip->t.cfgmode.ike_error = qm->error;

          /* Delete IKE SA if it was negotiated successfully, otherwise the
             next trigger will cause qm negotiation and vip will never be set
             up. */
          if (qm->p1 && !SSH_PM_P1_DELETED(qm->p1))
            {
              p1 = qm->p1;
              SSH_PM_IKEV2_IKE_SA_DELETE(p1, 0,
                                  pm_ike_sa_delete_notification_done_callback);
            }
        }

      /* Wake up the VIP thread. */
      ssh_fsm_continue(&vip->thread);
    }

  /* Terminate the Quick-Mode thread */
  SSH_FSM_SET_NEXT(ssh_pm_st_qm_terminate);
  return SSH_FSM_CONTINUE;
}

/* Start a Quick-Mode negotiation for remote access clients. This
   Quick-Mode will take care of processing the Configuration payloads. */
Boolean
ssh_pm_start_ike_vip(SshPm pm, SshPmVip vip)
{
  SshPmRule rule = vip->rules->rule;
  SshPmTunnel tunnel = vip->tunnel;
  SshPmQm qm;

  SSH_ASSERT(rule != NULL);

  qm = ssh_pm_qm_alloc(pm, FALSE);
  if (qm == NULL)
    {
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_WARNING,
                    "The maximum number of active Quick-Mode negotiations "
                    "reached.");
      return FALSE;
    }
  /* Store a reference to the VIP object. */
  if (!ssh_pm_virtual_ip_take_ref(pm, vip->tunnel))
    goto error;
  qm->vip = vip;

  qm->initiator = 1;
  qm->forward = 1;

  qm->tunnel = tunnel;
  SSH_PM_TUNNEL_TAKE_REF(qm->tunnel);

  qm->rule = rule;
  SSH_PM_RULE_LOCK(qm->rule);

  if ((tunnel->flags & SSH_PM_TI_DELAYED_OPEN) == 0
      || tunnel->as_active)
    qm->auto_start = 1;

  if (!ssh_pm_resolve_policy_rule_traffic_selectors(pm, qm))
    goto error;

  qm->transform = qm->tunnel->transform;

  /* The transform properties are already set. */
  SSH_ASSERT(qm->transform != 0);


  /* Start a Quick-Mode initator thread. */
  ssh_fsm_thread_init(&pm->fsm, &qm->thread,
                      ssh_pm_st_vip_start_qm_negotiation,
                      NULL_FNPTR,
                      pm_qm_thread_destructor, qm);
  ssh_fsm_set_thread_name(&qm->thread, "QM VIP CFGMODE");
  return TRUE;

 error:
  if (qm->vip != NULL)
    ssh_pm_virtual_ip_free(pm, SSH_IPSEC_INVALID_INDEX, qm->vip->tunnel);
  qm->vip = NULL;
  ssh_pm_qm_free(pm, qm);
  return FALSE;
}

/************* States for the VIP configuration mode **********************/

/* This state starts acquiring an IP address for the virtual IP
   interface and possibly other tunneling attributes. It is entered
   from state `ssh_pm_st_vip_get_attrs' of the generic part of the
   FSM. After attribute retrieval is completed (or failed), the FSM
   should return to the `ssh_pm_st_vip_get_attrs_result' state of the
   generic part. */

SSH_FSM_STEP(ssh_pm_st_vip_get_attrs_cfgmode)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmVip vip = (SshPmVip) thread_context;

  /* Init our negotiation state. */
  vip->t.cfgmode.done = 0;

  if (vip->rules->rule->side_to.tunnel->num_peers == 0)
    {
      /** Phase-1 cannot proceed. */
      SSH_DEBUG(SSH_D_FAIL, ("Phase-1 unsuccessful, no tunnel peers "
                             "specified"));
      SSH_FSM_SET_NEXT(ssh_pm_st_vip_get_attrs_cfgmode_failed);
      return SSH_FSM_CONTINUE;
    }

  /* Start a new IKE negotiation. This will take care of
     handling the configuration mode processing. */
  if (!ssh_pm_start_ike_vip(pm, vip))
    {
      /** Phase-1 negotiation failed. */
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Phase-1 failed"));
      SSH_FSM_SET_NEXT(ssh_pm_st_vip_get_attrs_cfgmode_failed);
      return SSH_FSM_CONTINUE;
    }

  /* Wait for the config mode to complete. */
  SSH_FSM_SET_NEXT(ssh_pm_st_vip_get_attrs_cfgmode_wait_cfgmode);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_vip_get_attrs_cfgmode_wait_cfgmode)
{
  SshPmVip vip = (SshPmVip) thread_context;

  /* Wait until IKE completes. */
  if (!vip->t.cfgmode.done)
    {
      /* Sleep until the operation is copmlete. */
      SSH_DEBUG(SSH_D_LOWOK, ("Suspending until IKE completes"));
      return SSH_FSM_SUSPENDED;
    }

  if (vip->t.cfgmode.ike_error == SSH_IKEV2_ERROR_OK)
    {
      ssh_pm_log_cfgmode_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                               vip->p1,  SSH_IKEV2_CFG_REQUEST,
                               "completed");

      if (vip->p1->remote_access_attrs &&
          vip->p1->remote_access_attrs->num_addresses &&
          SSH_IP_DEFINED(&vip->p1->remote_access_attrs->addresses[0]))
        {
          /** Attributes received. */
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                        "  Configuration data received:");
          ssh_pm_log_remote_access_attributes(SSH_LOGFACILITY_AUTH,
                                              SSH_LOG_INFORMATIONAL,
                                             vip->p1->remote_access_attrs);

          /* Copy the remote access attributes to the VIP context. */
          vip->attrs = *vip->p1->remote_access_attrs;

          SSH_FSM_SET_NEXT(ssh_pm_st_vip_get_attrs_cfgmode_done);
          return SSH_FSM_CONTINUE;
        }
      else
        {
          /** No attributes. */
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                        "  No configuration data received");
          /* No attributes (or mandatory virtual IP address was
             missing). */
          SSH_FSM_SET_NEXT(ssh_pm_st_vip_get_attrs_cfgmode_failed);
          return SSH_FSM_CONTINUE;
        }
    }
  else
    {
      char *error_string;

      error_string =
        (char *)ssh_ikev2_error_to_string(vip->t.cfgmode.ike_error);
      if (!strcmp(error_string, "unknown"))
        error_string = "Internal error";

      /** IKE negotiation failed. */
      if (vip->p1)
        ssh_pm_log_cfgmode_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                                 vip->p1, SSH_IKEV2_CFG_REQUEST,
                                 "failed");
      else
        ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                      "Phase-I negotiation failed");

      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                    "  Message: %s (%d)", error_string,
                    vip->t.cfgmode.ike_error);
      SSH_FSM_SET_NEXT(ssh_pm_st_vip_get_attrs_cfgmode_failed);
      return SSH_FSM_CONTINUE;
    }

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_vip_get_attrs_cfgmode_done)
{
  SshPmVip vip = (SshPmVip) thread_context;

  SSH_ASSERT(vip->attrs.num_addresses > 0);

  /* Method finished successfully. */
  vip->successful = 1;

  /* We do not need our Phase-1 pointer anymore. */
  vip->p1 = NULL;

  SSH_FSM_SET_NEXT(ssh_pm_st_vip_get_attrs_result);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_vip_get_attrs_cfgmode_failed)
{
  SshPmVip vip = (SshPmVip) thread_context;

  /* Release our Phase-1 pointer if it exists. */
  if (vip->p1)
    {
      vip->p1 = NULL;
    }

  SSH_FSM_SET_NEXT(ssh_pm_st_vip_get_attrs_result);
  return SSH_FSM_CONTINUE;
}
#endif /* SSHDIST_ISAKMP_CFG_MODE */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */
