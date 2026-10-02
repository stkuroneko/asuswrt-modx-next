/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   The main thread controlling PM start and event waiting.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"
#include "sshnetconfig.h"
#include "util_netconfig.h"
#include "ipsec_base_policy.h"
/************************** Types and definitions ***************************/

#define SSH_DEBUG_MODULE "SshPmStMain"

/* The interval how often failed auto-start rules are checked and
   their failure TTLs are decremented. */
#define SSH_PM_AUTO_START_TIMER_INTERVAL        5

static void ssh_pm_auto_start_timer(void *context);


/**************************** Main thread states ****************************/

SSH_FSM_STEP(ssh_pm_st_main_initialize)
{
    SshPm pm = (SshPm) fsm_context;
    SshCryptoLibraryStatus crypto_status;

    /* Check crypto library status before continuing initialization. */
    crypto_status = ssh_crypto_library_get_status();

    /* Everything ok, safe to continue pm initialization. */
    if (crypto_status == SSH_CRYPTO_LIBRARY_STATUS_OK)
    {
        SSH_FSM_SET_NEXT(ssh_pm_st_main_send_random_salt);
        return SSH_FSM_CONTINUE;
    }

    /* Crypto library is still busy with self tests, wait for a while. */
    else if (crypto_status == SSH_CRYPTO_LIBRARY_STATUS_SELF_TEST)
    {
        SSH_DEBUG(SSH_D_LOWOK,
                  ("Waiting for crypto library initialization to complete"));
        SSH_FSM_ASYNC_CALL(ssh_register_timeout(&pm->main_thread_timeout,
                                                0, 200000,
                                                ssh_pm_timeout_cb, thread));
        SSH_NOTREACHED;
    }

    /* Crypto library failure is a fatal error. */
    ssh_fatal("Crypto library initialization failed!");
    return SSH_FSM_FINISH;
}

SSH_FSM_STEP(ssh_pm_st_main_send_random_salt)
{
    SSH_FSM_SET_NEXT(ssh_pm_st_main_start);
    return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(ssh_pm_st_main_start)
{
    SshPm pm = (SshPm) fsm_context;

    /* Start auto-start rule timer. */
    ssh_pm_auto_start_timer(pm);

    /* And wait for interesting events. */
    SSH_FSM_SET_NEXT(ssh_pm_st_main_start_wait_interfaces);
    return SSH_FSM_CONTINUE;
}

/* This timeout is called if the interface notification is not sent within
   5 seconds of starting the policy manager. It continues execution of the
   policy manager's main thread (another option here would be to shutdown
   the policymanager if this expiry timeout is delivered). */
static void pm_interface_change_expire_timer(void *context)
{
    SshPm pm = (SshPm) context;

    SSH_DEBUG(SSH_D_HIGHOK, ("In interface change expire timeout"));

    /* Retry fetching the interfaces. */
    if (ssh_pm_interface_change(pm) == false)
    {
        /* XXX Just fake the event for now, if no interfaces found */
        pm->iface_change = 1;
    }

    ssh_fsm_condition_broadcast(&pm->fsm, &pm->main_thread_cond);

    /* Clear the structure so it is safe to call ssh_cancel_timeout on it */
    memset(&pm->interface_change_timeout, 0,
           sizeof(pm->interface_change_timeout));
}

SSH_FSM_STEP(ssh_pm_st_main_start_wait_interfaces)
{
    SshPm pm = (SshPm) fsm_context;

    if (ssh_pm_interface_change(pm) == false)
    {
        /* Wait until we receive the initial interface notification. */
        SSH_DEBUG(SSH_D_LOWSTART, ("Waiting for interface information"));

        ssh_register_timeout(&pm->interface_change_timeout, 5, 0,
                             pm_interface_change_expire_timer, pm);

        SSH_FSM_CONDITION_WAIT(&pm->main_thread_cond);
    }
    /* Notify the main thread that the interface information has
       changed. */
    pm->iface_change = 1;

    ssh_cancel_timeout(&pm->interface_change_timeout);

    /* Perform any interface information dependent initialization. */
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
    /* Get virtual adapters. */
    SSH_DEBUG(SSH_D_LOWSTART, ("Getting virtual adapters"));
    SSH_FSM_SET_NEXT(ssh_pm_st_main_start_get_virtual_adapters);
    return SSH_FSM_CONTINUE;
#else /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */
    /* Create default rules. */
    SSH_DEBUG(SSH_D_LOWSTART, ("Creating default rules"));
    SSH_FSM_SET_NEXT(ssh_pm_st_main_start_default_rules);
    return SSH_FSM_CONTINUE;
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */
}

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
SSH_FSM_STEP(ssh_pm_st_main_start_get_virtual_adapters)
{
    SSH_FSM_SET_NEXT(ssh_pm_st_main_start_get_virtual_adapters_result);
    return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(ssh_pm_st_main_start_get_virtual_adapters_result)
{
    /* Create default rules. */
    SSH_DEBUG(SSH_D_LOWSTART, ("Creating default rules"));
    SSH_FSM_SET_NEXT(ssh_pm_st_main_start_default_rules);
    return SSH_FSM_CONTINUE;
}
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */


/** Add base policy */
SSH_FSM_STEP(ssh_pm_st_main_start_default_rules)
{
    SshPm pm = (SshPm) fsm_context;
    bool ok = true;

    ok = ipsec_system_policy_set(pm->ipsec_control, true);

    if (ok == true)
    {
        ipsec_base_policy_set(pm->ipsec_control, true);
    }

    SSH_FSM_SET_NEXT(ssh_pm_st_main_start_complete);
    return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(ssh_pm_st_main_start_complete)
{
    SshPm pm = (SshPm) fsm_context;

    /* The policy manager is not fully functional. */
    SSH_DEBUG(SSH_D_LOWOK, ("Policy manager started"));

    /* Let's call the user-provided completion callback. */
    SSH_ASSERT(pm->create_cb != NULL_FNPTR);
    (*pm->create_cb)(pm, pm->create_cb_context);

    /* And enter the main loop. */
    SSH_FSM_SET_NEXT(ssh_pm_st_main_run);
    return SSH_FSM_CONTINUE;
}

/************************ Handling auto-start rules *************************/

/* Try to establish IPSec tunnel of rule `rule'.  If the operation is
   successful, the function starts a Quick-Mode thread that negotiates
   the tunnel. */
static void ssh_pm_rule_auto_start(SshPm pm, SshPmRule rule, bool forward)
{
    SshPmQm qm;
    SshPmRuleSideSpecification src, dst;

    if (forward)
    {
        src = &rule->side_from;
        dst = &rule->side_to;
    }
    else
    {
        src = &rule->side_to;
        dst = &rule->side_from;
    }

    SSH_ASSERT(dst->tunnel != NULL);

    if (dst->as_up)
    {
        SSH_DEBUG(SSH_D_NICETOKNOW, ("Rule already up"));
        return;
    }
    if (dst->as_active)
    {
        SSH_DEBUG(SSH_D_NICETOKNOW, ("Auto-start already active for rule"));
        return;
    }
    if (dst->as_fail_retry > 0)
    {
        SSH_DEBUG(SSH_D_NICETOKNOW, ("Auto-start rule has failed: timeout %d",
                                     dst->as_fail_retry));
        return;
    }

    /* This tunnel is currently being used for auto-start rule. */
    if (dst->as_active == 0 && dst->tunnel->as_active != 0)
    {
        SSH_DEBUG(SSH_D_NICETOKNOW, ("Auto-start already active for tunnel"));
        /* Mark that another rule is waiting for the auto-start tunnel to
           come up. */
        dst->tunnel->as_rule_pending = 1;
        return;
    }

    /* Check if the rule is already being used for a Quick-Mode negotiation. */
    if (rule->ike_in_progress)
    {
        SSH_DEBUG(SSH_D_FAIL, ("The rule already has an ongoing IKE "
                               "negotiation. Dropping auto-start request."));
        return;
    }

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
    if (SSH_PM_RULE_IS_VIRTUAL_IP(rule))
    {
        if (!ssh_pm_use_virtual_ip(pm, dst->tunnel, rule))
        {
            SSH_DEBUG(SSH_D_ERROR, ("Could not get virtual IP interface"));
            dst->as_active = 0;
            dst->tunnel->as_active = 0;

            goto fail;
        }
        if (dst->tunnel->vip->unusable)
        {
           /* VIP interface was just started, no nothing else. */
            goto end;
        }
        /* Otherwise continue with QM negotiation unless... */
#ifdef SSHDIST_L2TP
        /* ... this is an L2TP tunnel. */
        if (dst->tunnel->flags & SSH_PM_TI_L2TP)
          goto end;
#endif /* SSHDIST_L2TP */
#ifdef SSHDIST_ISAKMP_CFG_MODE_RULES
        if (rule->flags & SSH_PM_RULE_CFGMODE_RULES)
        {
            SSH_DEBUG(
                    SSH_D_ERROR,
                    ("Invalid attempt to start QM with config "
                     "mode placeholder rule"));
            goto fail;
        }
#endif /* SSHDIST_ISAKMP_CFG_MODE_RULES */
    }

#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

    /* Allocate and init Quick-Mode context for this negotiation. */
    qm = ssh_pm_qm_alloc(pm, false);
    if (qm == NULL)
    {
        SSH_DEBUG(SSH_D_FAIL, ("No more Quick-Mode structures left"));
        goto fail;
    }

    qm->initiator = 1;
    if (forward)
      qm->forward = 1;
    qm->auto_start = 1;

    rule->ike_in_progress = 1;
    qm->rule = rule;
    SSH_PM_RULE_LOCK(qm->rule);

    qm->tunnel = dst->tunnel;
    SSH_PM_TUNNEL_TAKE_REF(qm->tunnel);

    /* Packet ifnum is needed later at the trigger processing and we
       will resolve it before entering the normal trigger processing. */

    /* Create hand-crafted packet attributes. */

    SSH_ASSERT(src->ts->number_of_items_used > 0);
    SSH_ASSERT(dst->ts->number_of_items_used > 0);

    if (SSH_IP_DEFINED(dst->ts->items[0].start_address))
    {
        qm->sel_dst = *dst->ts->items[0].start_address;
    }
    else
    {
        if (SSH_IP_DEFINED(src->ts->items[0].start_address))
        {
            if (SSH_IP_IS4(src->ts->items[0].start_address))
              ssh_ipaddr_parse(&qm->sel_dst, "0.0.0.0");
            else
              ssh_ipaddr_parse(&qm->sel_dst, "::");
        }
        else
        {
            SSH_DEBUG(
                    SSH_D_ERROR,
                    ("Selectors undefined in auto-start rule!"));
            rule->ike_in_progress = 0;
            ssh_pm_qm_free(pm, qm);
            goto fail;
        }
    }

    /* Source address. */
    if (SSH_IP_DEFINED(src->ts->items[0].start_address))
    {
        qm->sel_src = *src->ts->items[0].start_address;
    }
    else
    {
        if (SSH_IP_IS4(&qm->sel_dst))
          ssh_ipaddr_parse(&qm->sel_src, "0.0.0.0");
        else
          ssh_ipaddr_parse(&qm->sel_src, "::");
    }

    SSH_ASSERT((SSH_IP_IS4(&qm->sel_dst) && SSH_IP_IS4(&qm->sel_src)) ||
               (SSH_IP_IS6(&qm->sel_dst) && SSH_IP_IS6(&qm->sel_src)));

    /* Protocol and port numbers. */
    qm->sel_ipproto = SSH_IPPROTO_ANY;
    if (src->ts->items[0].proto)
      qm->sel_ipproto = src->ts->items[0].proto;

    qm->sel_src_port = src->ts->items[0].start_port;
    qm->sel_dst_port = dst->ts->items[0].start_port;

    /* Create SA traffic selectors for this negotiation from the
       policy rule. */
    if (!ssh_pm_resolve_policy_rule_traffic_selectors(pm, qm))
    {
        rule->ike_in_progress = 0;
        ssh_pm_qm_free(pm, qm);
        goto fail;
    }

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
    /* Take a vip reference for the duration of the qm negotiation. */
    if (SSH_PM_RULE_IS_VIRTUAL_IP(qm->rule))
    {
        SSH_ASSERT(qm->tunnel->vip != NULL);
        if (!ssh_pm_virtual_ip_take_ref(pm, qm->tunnel))
        {
            rule->ike_in_progress = 0;
            ssh_pm_qm_free(pm, qm);
            goto fail;
        }
        qm->vip = qm->tunnel->vip;
    }
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

    /* Start a Quick-Mode initiator thread. */
    ssh_fsm_thread_init(&pm->fsm, &qm->thread,
                        ssh_pm_st_qm_i_auto_start,
                        NULL_FNPTR, pm_qm_thread_destructor, qm);
    ssh_fsm_set_thread_name(&qm->thread, "QM auto start");

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
   end:
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */
    /* Mark rule and tunnel having already an auto-start thread. */
    dst->as_active = 1;
    dst->tunnel->as_active = 1;
    return;

   fail:
    /* Mark auto-start failed. */
    if (dst->as_fail_limit < 16)
      dst->as_fail_limit++;
    dst->as_fail_retry = dst->as_fail_limit;
    return;
}

/* A function for scheduling the ssh_pm_auto_start_timer. */
static void pm_schedule_auto_start_timer(SshPm pm)
{
    SshADTHandle handle;
    SshPmRule rule;
    unsigned long timeout = SSH_PM_AUTO_START_TIMER_INTERVAL;
    bool start_timer = false;

    for (handle = ssh_adt_enumerate_start(pm->rule_by_autostart);
         handle != SSH_ADT_INVALID;
         handle = ssh_adt_enumerate_next(pm->rule_by_autostart, handle))
    {
        rule = ssh_adt_get(pm->rule_by_autostart, handle);

        if (SSH_PM_RULE_INACTIVE(pm, rule))
          continue;

        SSH_ASSERT(rule->side_to.auto_start &&
                   rule->side_from.auto_start == 0);

        /* Check forward direction. */
        if (rule->side_to.auto_start)
        {
            SSH_ASSERT(rule->side_to.tunnel != NULL);
            if (rule->side_to.as_fail_retry)
            {
                /* Register timer to update as_fail_retry */
                start_timer = true;
            }
            else if (rule->side_to.as_fail_retry == 0
                     && rule->side_to.as_up == 0)
            {
                /* Register timer to auto-start rule as soon as possible. */
                start_timer = true;
            }
            else if (rule->side_to.tunnel->as_active)
            {
                /* Register timer to check the status of currently active
                   auto-starts. */
                start_timer = true;
            }

            if (rule->side_to.tunnel->as_rule_pending)
            {
                /* Handle pending auto-starts immediately. */
                timeout = 0;
                start_timer = true;
                break;
            }
        }
    }

    if (start_timer == false)
    {
        ssh_cancel_timeout(pm->auto_start_timeout);
        pm->auto_start_timeout_registered = false;
        SSH_DEBUG(SSH_D_LOWOK, ("No auto-start timer scheduled"));
    }
    else if (pm->auto_start_timeout_registered == false)
    {
        /* Add some jitter to the auto start timeout interval to help
           avoiding simultaneous IPsec negotiations. */
        unsigned long usec = ssh_random_get_byte();
        usec *= 1000;

        SSH_DEBUG(SSH_D_LOWOK, ("Rescheduling auto-start timer to %d.%06d",
                                timeout, usec));

        pm->auto_start_timeout_registered = true;
        ssh_register_timeout(pm->auto_start_timeout,
                             timeout, usec,
                             ssh_pm_auto_start_timer, pm);
    }
}

/* A timer for aging failed auto-start rules. */
static void ssh_pm_auto_start_timer(void *context)
{
    SshPm pm = (SshPm) context;
    SshPmRule rule;
    uint32_t count = 0;
    SshADTHandle handle;

    SSH_DEBUG(SSH_D_LOWOK, ("Auto-start timer triggered"));
    pm->auto_start_timeout_registered = false;

    for (handle = ssh_adt_enumerate_start(pm->rule_by_autostart);
         handle != SSH_ADT_INVALID;
         handle = ssh_adt_enumerate_next(pm->rule_by_autostart, handle))
    {
        rule = ssh_adt_get(pm->rule_by_autostart, handle);

        if (SSH_PM_RULE_INACTIVE(pm, rule))
          continue;

        SSH_ASSERT(rule->side_to.auto_start &&
                   rule->side_from.auto_start == 0);

        if (rule->side_to.auto_start)
        {
            SSH_ASSERT(rule->side_to.tunnel != NULL);

            if (rule->side_to.as_fail_retry)
              rule->side_to.as_fail_retry--;

            if (rule->side_to.as_fail_retry == 0)
            {
                SSH_DEBUG(SSH_D_LOWOK,
                          ("Activating auto-start rule `%@'",
                           ssh_pm_rule_render, rule));
                count++;
            }
            else if (rule->side_to.tunnel->as_rule_pending)
            {
                count++;
            }
        }
    }

    if (count > 0)
    {
        SSH_DEBUG(SSH_D_LOWOK, ("Activated %u rules: notifying main thread",
                                (unsigned int) count));
        pm->auto_start = 1;
        ssh_fsm_condition_broadcast(&pm->fsm, &pm->main_thread_cond);
    }

    pm_schedule_auto_start_timer(pm);
}

#ifdef SSHDIST_ISAKMP_CFG_MODE_RULES
SSH_FSM_STEP(ssh_pm_st_main_cfgmode_rules)
{
    SshPm pm = (SshPm) fsm_context;
    SshPmTunnel tunnel;
    bool rules_changed = false;
    SshADTHandle handle;

    SSH_ASSERT(pm->cfgmode_rules);

    pm->cfgmode_rules = 0;
    SSH_FSM_SET_NEXT(ssh_pm_st_main_run);

    /* Do not attempt anything if policy manager is suspended. */
    if (ssh_pm_get_status(pm) != SSH_PM_STATUS_ACTIVE)
    {
        SSH_DEBUG(SSH_D_LOWOK,
                  ("Policy manager is not active, ignoring cfgmode-rules"));
        return SSH_FSM_CONTINUE;
    }

    /* Add policy rules based on config mode associated with a virtual
       adapter that has come up, or delete previously added rules
       associated with a virtual adapter going down. */
    for (handle = ssh_adt_enumerate_start(pm->tunnels);
         handle != SSH_ADT_INVALID;
         handle = ssh_adt_enumerate_next(pm->tunnels, handle))
    {
        tunnel = ssh_adt_get(pm->tunnels,  handle);

        if (tunnel->vip != NULL &&
            ssh_pm_virtual_ip_update_cfgmode_rules(pm, tunnel->vip))
          rules_changed = true;
    }

    /* If no  rules were added or deleted then do nothing more. */
    if (!rules_changed)
      return SSH_FSM_CONTINUE;

    /* Makefile additions/deletions pending. */
    ssh_pm_config_make_pending(pm);

    /* Transfer pending changes to batch. */
    ssh_pm_config_pending_to_batch(pm);

    /* Direct this thread to do the batch. */
    pm->batch_active = 1;

    return SSH_FSM_CONTINUE;
}
#endif /* SSHDIST_ISAKMP_CFG_MODE_RULES */

SSH_FSM_STEP(ssh_pm_st_main_auto_start)
{
    SshPm pm = (SshPm) fsm_context;
    SshPmRule rule;
    SshADTHandle handle;

    SSH_ASSERT(pm->auto_start);

    /* Do not attempt auto-start if policy manager is suspended. */
    if (ssh_pm_get_status(pm) != SSH_PM_STATUS_ACTIVE)
    {
        SSH_DEBUG(SSH_D_LOWOK,
                  ("Policy manager is not active, ignoring auto-start"));
        pm->auto_start = 0;
        SSH_FSM_SET_NEXT(ssh_pm_st_main_run);
        return SSH_FSM_CONTINUE;
    }

    /* Check if there are any auto-start rules which need some
       actions. */
    for (handle = ssh_adt_enumerate_start(pm->rule_by_autostart);
         handle != SSH_ADT_INVALID;
         handle = ssh_adt_enumerate_next(pm->rule_by_autostart, handle))
    {
        rule = ssh_adt_get(pm->rule_by_autostart, handle);

        SSH_DEBUG(SSH_D_LOWSTART, ("Checking rule `%@'",
                                   ssh_pm_rule_render, rule));

        if (SSH_PM_RULE_INACTIVE(pm, rule))
        {
            SSH_DEBUG(
                    SSH_D_LOWOK,
                    ("Rule is not in the active configuration"));
            continue;
        }

        SSH_ASSERT(rule->side_to.auto_start
                   && rule->side_from.auto_start == 0);

        /* Check the forward direction of the rule. */
        if (rule->side_to.auto_start)
        {
            SSH_ASSERT(rule->side_to.tunnel != NULL);
            if ((rule->side_to.tunnel->flags & SSH_PM_TI_DELAYED_OPEN) == 0
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
                || ((rule->side_to.tunnel->flags & SSH_PM_TI_INTERFACE_TRIGGER)
                    && ssh_pm_vip_rule_interface_trigger(pm, rule))
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */
                )
            {
                ssh_pm_rule_auto_start(pm, rule, true);
            }
        }
    }

    pm->auto_start = 0;

    pm_schedule_auto_start_timer(pm);

    SSH_FSM_SET_NEXT(ssh_pm_st_main_run);
    return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_main_run)
{
    SshPm pm = (SshPm) fsm_context;

    /* The policy manager is now fully  */

    /* Wait until something interesting happens. */
    if ((ssh_pm_get_status(pm) != SSH_PM_STATUS_DESTROYED)
        && !pm->iface_change
        && !pm->batch_active
#ifdef SSHDIST_ISAKMP_CFG_MODE_RULES
        && !pm->cfgmode_rules
#endif /* SSHDIST_ISAKMP_CFG_MODE_RULES */
        && !pm->auto_start)
    {
        /* Nothing to do.  Signal our condition variable since the
           modification waiters wait on it. */
        SSH_FSM_CONDITION_BROADCAST(&pm->main_thread_cond);

        /* And wait that someone schedules us some work. */
        SSH_DEBUG(SSH_D_LOWSTART, ("Waiting for events"));
        SSH_FSM_CONDITION_WAIT(&pm->main_thread_cond);
    }

    if (ssh_pm_get_status(pm) == SSH_PM_STATUS_DESTROYED)
    {
        SSH_DEBUG(SSH_D_LOWOK, ("Policy manager destroyed"));
        SSH_FSM_SET_NEXT(ssh_pm_st_main_shutdown);
        return SSH_FSM_CONTINUE;
    }

    if (pm->batch_active)
    {
        SSH_DEBUG(SSH_D_LOWOK, ("Policy modification"));
        SSH_FSM_SET_NEXT(ssh_pm_st_main_batch_start);
        return SSH_FSM_CONTINUE;
    }

    if (pm->iface_change)
    {
        SSH_DEBUG(SSH_D_LOWOK, ("Interface change"));

        /* Set batch_active to disable reconfigurations */
        pm->batch_active = 1;

        SSH_FSM_SET_NEXT(ssh_pm_st_main_iface_change);
        return SSH_FSM_CONTINUE;
    }

#ifdef SSHDIST_ISAKMP_CFG_MODE_RULES
    if (pm->cfgmode_rules)
    {
        SSH_DEBUG(SSH_D_LOWOK, ("Config mode rules update"));
        SSH_FSM_SET_NEXT(ssh_pm_st_main_cfgmode_rules);
        return SSH_FSM_CONTINUE;
    }
#endif /* SSHDIST_ISAKMP_CFG_MODE_RULES */

    if (pm->auto_start)
    {
        SSH_DEBUG(SSH_D_LOWOK, ("Auto-start"));
        SSH_FSM_SET_NEXT(ssh_pm_st_main_auto_start);
        return SSH_FSM_CONTINUE;
    }

    /* One of the cases above must have been true. */
    SSH_NOTREACHED;
    return SSH_FSM_FINISH;
}
