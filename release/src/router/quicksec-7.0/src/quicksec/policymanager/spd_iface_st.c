/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   The main thread controlling PM interface changes.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"

#define SSH_DEBUG_MODULE "SshPmStIface"


/* The interval (in microseconds) after an interface change to wait until
   restarting servers and their failure TTLs are decremented. */
#define SSH_PM_IFACE_CHANGE_TIMER_INTERVAL      250000

/* The maximum number of times to try restarting the servers after an
   interface change. */
#define SSH_PM_IFACE_CHANGE_RETRY_LIMIT      20

/*********************** Processing interface changes ***********************/

static void
ssh_pm_interface_timeout_cb(void *ctx)
{
    SshFSMThread thread = (SshFSMThread) ctx;
    SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

static void
ssh_pm_servers_interface_change_done_cb(SshPm pm, bool success,
                                        void *context)
{
    SshFSMThread thread = (SshFSMThread) context;

    pm->iface_change_ok = success ? 1 : 0;

    SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

SSH_FSM_STEP(ssh_pm_st_main_iface_change)
{
    SshPm pm = (SshPm) fsm_context;

    SSH_ASSERT(pm->iface_change);
    SSH_ASSERT(pm->batch_active);

    pm->iface_change = 0;
    pm->iface_change_ok = 0;

    /* On some platforms, we can actually end up here before the host
       operating system has managed to get all its state in synch, so
       we allow this operation to fail up to 'pm->interface_change_retry'
       times, with a timeout inbetween each attempt. */
    pm->interface_change_retry = SSH_PM_IFACE_CHANGE_RETRY_LIMIT;

    SSH_FSM_SET_NEXT(ssh_pm_st_main_iface_change_update_tunnels);
    SSH_FSM_ASYNC_CALL(ssh_register_timeout(&pm->interface_change_timeout,
                                            0,
                                            SSH_PM_IFACE_CHANGE_TIMER_INTERVAL,
                                            ssh_pm_interface_timeout_cb,
                                            thread));
    SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_pm_st_main_iface_change_update_tunnels)
{
#ifdef SSHDIST_IPSEC_MOBIKE
    SshPm pm = (SshPm) fsm_context;
    SshADTHandle handle;
    SshPmTunnel tunnel;

    SSH_DEBUG(SSH_D_LOWSTART, ("Updating tunnel local IP addresses"));

    /* Iterate through tunnels and update local interface addresses. */
    for (handle = ssh_adt_enumerate_start(pm->tunnels);
         handle != SSH_ADT_INVALID;
         handle = ssh_adt_enumerate_next(pm->tunnels, handle))
    {
        tunnel = (SshPmTunnel) ssh_adt_get(pm->tunnels, handle);
        if (tunnel != NULL)
          ssh_pm_tunnel_update_local_interface_addresses(tunnel);
    }
#endif /* SSHDIST_IPSEC_MOBIKE */

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
    SSH_DEBUG(SSH_D_NICETOKNOW, ("Reiterating all tunnels for VIP"));

    for (handle = ssh_adt_enumerate_start(pm->tunnels);
         handle != SSH_ADT_INVALID;
         handle = ssh_adt_enumerate_next(pm->tunnels, handle))
    {
        tunnel = (SshPmTunnel) ssh_adt_get(pm->tunnels, handle);

        if (tunnel != NULL && tunnel->vip != NULL)
        {
            SSH_DEBUG(SSH_D_LOWOK,
                      ("Tunnel 0x%p VIP marked for reconfiguration", tunnel));

            tunnel->vip->reconfigure_routes = 1;
            ssh_fsm_condition_broadcast(&pm->fsm, &tunnel->vip->cond);
        }
    }
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

    SSH_DEBUG(SSH_D_LOWSTART, ("Updating tunnel routing instance ids."));
    /* Iterate through tunnels and update routing instance id. */
    for (handle = ssh_adt_enumerate_start(pm->tunnels);
         handle != SSH_ADT_INVALID;
         handle = ssh_adt_enumerate_next(pm->tunnels, handle))
    {
        tunnel = (SshPmTunnel) ssh_adt_get(pm->tunnels, handle);
        if (tunnel != NULL)
          tunnel->routing_instance_id = ssh_ip_get_interface_vri_id(
                                                &pm->ifs,
                                                tunnel->routing_instance_name);
    }

    SSH_FSM_SET_NEXT(ssh_pm_st_main_iface_change_servers);
    return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_main_iface_change_servers)
{
    SshPm pm = (SshPm) fsm_context;

    /* Notify servers about updated interface listing. If starting some new
       server has failed, reschedule a timeout to try again. */
    if (pm->interface_change_retry && !pm->iface_change_ok)
    {
        pm->interface_change_retry--;

        SSH_FSM_SET_NEXT(ssh_pm_st_main_iface_change_servers_check_done);
        SSH_FSM_ASYNC_CALL(
                ssh_pm_servers_interface_change(
                        pm,
                        ssh_pm_servers_interface_change_done_cb,
                        thread));
        SSH_NOTREACHED;

    }

#ifdef SSHDIST_IPSEC_MOBIKE
    /* Re-evaluate MOBIKE SAs if policy manager is active and there is no
       ongoing policy configuration. */
    if ((ssh_pm_get_status(pm) == SSH_PM_STATUS_ACTIVE) && !pm->config_active)
      ssh_pm_mobike_reevaluate(pm, NULL_FNPTR, NULL);
#endif /* SSHDIST_IPSEC_MOBIKE */

    /* Start processing rules. */
    pm->mt_current.container = pm->rule_by_id;
    pm->mt_current.handle = ssh_adt_enumerate_start(pm->rule_by_id);

    SSH_FSM_SET_NEXT(ssh_pm_st_main_iface_change_rules);

    return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_main_iface_change_servers_check_done)
{
    SshPm pm = (SshPm) fsm_context;

    SSH_FSM_SET_NEXT(ssh_pm_st_main_iface_change_servers);

    if (pm->iface_change_ok)
    {
        SSH_DEBUG(SSH_D_LOWOK, ("Servers Interface changes OK"));

        SSH_APE_MARK(1, ("Interface change event complete"));

        return SSH_FSM_CONTINUE;
    }
    else
    {
        SSH_DEBUG(SSH_D_HIGHOK, ("Servers Interface changes failed, "
                                 "rescheduling for another attempt"));

        SSH_FSM_ASYNC_CALL(
                ssh_register_timeout(
                        &pm->interface_change_timeout,
                        0,
                        SSH_PM_IFACE_CHANGE_TIMER_INTERVAL,
                        ssh_pm_interface_timeout_cb,
                        thread));

        SSH_NOTREACHED;
    }
}

SSH_FSM_STEP(ssh_pm_st_main_iface_change_rules)
{
    SshPm pm = (SshPm) fsm_context;
    SshPmRule rule;

    if (pm->mt_current.handle == SSH_ADT_INVALID)
    {
        /* All rules processed. */
        SSH_FSM_SET_NEXT(ssh_pm_st_main_iface_change_pending_iface);

        return SSH_FSM_CONTINUE;
    }

    rule = ssh_adt_get(pm->mt_current.container, pm->mt_current.handle);

    /* Nothing to do for this rule. */
    SSH_DEBUG(
            SSH_D_NICETOKNOW,
            ("Skipping rule `%@'",
             ssh_pm_rule_render, rule));

    pm->mt_current.handle =
        ssh_adt_enumerate_next(
                pm->mt_current.container,
                pm->mt_current.handle);

    return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_main_iface_change_pending_iface)
{
    SshPm pm = (SshPm) fsm_context;
    SshPmRule rule;
    bool batch_active = false;
    bool interface_not_up = false;
    SshADTHandle handle, next;

    /* Check the pending interface rules. For any rules that are now valid
       add them to the batch additions. When finished, signal a policy
       reconfiguration.*/

    for (handle = ssh_adt_enumerate_start(pm->iface_pending_additions);
         handle != SSH_ADT_INVALID;
         handle = next)
    {
        next = ssh_adt_enumerate_next(pm->iface_pending_additions, handle);
        rule = ssh_adt_get(pm->iface_pending_additions, handle);

#ifdef SSHDIST_IPSEC_DNSPOLICY
        if (pm_rule_get_dns_status(pm, rule) == SSH_PM_DNS_STATUS_ERROR)
        {
            SSH_DEBUG(SSH_D_MIDOK, ("DNS selectors for rule not yet resolved; "
                                    "pending interface can't be processed "
                                    "for rule %@.",
                                    ssh_pm_rule_render, rule));
            continue;
        }
#endif /* SSHDIST_IPSEC_DNSPOLICY */

        SSH_ASSERT(rule->side_from.ts != NULL && rule->side_to.ts != NULL);

        if (!interface_not_up)
        {
            /* Remove this from the list of pending interface rules */
            ssh_adt_detach(pm->iface_pending_additions, handle);

            /* If this happens when batch is not active, we need to
               react properly */
            if (pm->batch.additions != NULL)
              ssh_adt_insert(pm->batch.additions, rule);
            else
              if ((pm->batch.additions =
                   ssh_adt_create_generic(SSH_ADT_BAG,
                                  SSH_ADT_HEADER,
                                  SSH_ADT_OFFSET_OF(SshPmRuleStruct,
                                                    rule_by_index_add_hdr),
                                  SSH_ADT_HASH, ssh_pm_rule_hash_adt,
                                  SSH_ADT_COMPARE, ssh_pm_rule_compare_adt,
                                  SSH_ADT_DESTROY, ssh_pm_rule_destroy_adt,
                                  SSH_ADT_CONTEXT, pm,
                                  SSH_ADT_ARGS_END))
                  != NULL)
              {
                  ssh_adt_insert(pm->batch.additions, rule);
                  batch_active = true;
              }
        }
    }

    /* Clear batch_active that was set in
       ssh_pm_st_main_run to disable reconfigurations. */
    pm->batch_active = 0;

    /* Reconfiguration if necessary */
    if (batch_active)
    {
        pm->batch_active = 1;
        pm->batch.status_cb = NULL_FNPTR;
        pm->batch.status_cb_context = NULL;
    }

    SSH_FSM_SET_NEXT(ssh_pm_st_main_iface_change_done);
    return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(ssh_pm_st_main_iface_change_done)
{
    SshPm pm = (SshPm) fsm_context;

    /* Check auto-start rules after rule changes. */
    pm->auto_start = 1;

    /* Notify the top level policy manager interface callback
       that the interface information has changed. */
    if (pm->interface_callback != NULL_FNPTR)
      (*pm->interface_callback)(pm, pm->interface_callback_context);

    SSH_FSM_SET_NEXT(ssh_pm_st_main_run);
    return SSH_FSM_CONTINUE;
}
