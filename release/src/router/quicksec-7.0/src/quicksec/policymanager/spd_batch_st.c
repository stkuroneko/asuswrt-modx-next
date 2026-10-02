/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   The main thread controlling PM start and event waiting.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"

#define SSH_DEBUG_MODULE "SshPmStBatch"


static void
pm_delete_ipsec_sas_by_peer_handle(
        SshPm pm,
        uint32_t peer_handle)
{
    struct IPsecControl *ipsec_control = pm->ipsec_control;
    const struct IPsecSaParams *ipsec_sa_params;

    ipsec_sa_params =
        ipsec_sa_first_by_peer_handle(
                ipsec_control,
                peer_handle);

    while (ipsec_sa_params != NULL)
    {
        uint32_t inbound_spi = ipsec_sa_params->inbound_spi;

        ipsec_sa_delete(
                ipsec_control, inbound_spi);

        ipsec_sa_params =
            ipsec_sa_next_by_peer_handle(
                    ipsec_control,
                    peer_handle,
                    inbound_spi);
    }
}

static void
pm_delete_all_by_tunnel(
        SshPm pm,
        SshPmTunnel tunnel)
{
    SshPmPeer peer = NULL;

    if (tunnel != NULL)
    {
        SSH_DEBUG(
                SSH_D_NICETOKNOW,
                ("Deleting all IPsec SAs by tunnel %d %s",
                 tunnel->tunnel_id,
                 tunnel->tunnel_name));

        peer = ssh_pm_peer_first_by_tunnel_id(pm, tunnel->tunnel_id);
    }

    while (peer != NULL)
    {
        SshPmPeer next;

        next = ssh_pm_peer_next_by_tunnel_id(pm, peer);

        pm_delete_ipsec_sas_by_peer_handle(pm, peer->peer_handle);

        peer = next;
    }
}

static void
pm_delete_all_by_rule(
        SshPm pm,
        SshPmRule rule)
{
    SSH_DEBUG(
            SSH_D_NICETOKNOW,
            ("Deleting all IPsec SAs by rule_id=%d: start.",
             rule->rule_id));

    pm_delete_all_by_tunnel(pm, rule->side_to.tunnel);

    pm_delete_all_by_tunnel(pm, rule->side_from.tunnel);

    SSH_DEBUG(
            SSH_D_NICETOKNOW,
            ("Deleting all IPsec SAs by rule_id=%d: finished.",
             rule->rule_id));
}

/***************** Callbacks, etc... utility functions     ******************/
/* A callback function that is called to notify that the policy manager has
   been suspended. */
static void
pm_batch_policy_suspend_cb(SshPm pm, bool status, void *context)
{
    SshFSMThread thread = (SshFSMThread) context;

    if (status == true)
    {
        SSH_DEBUG(SSH_D_NICETOKNOW, ("Policy manager suspended."));
    }
    else
    {
        pm->batch_failed = 1;
        SSH_DEBUG(SSH_D_NICETOKNOW,
                  ("Policy manager could not be suspended, batch failed."));
    }

    SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

/***************** Processing rule additions and deletions ******************/

SSH_FSM_STEP(ssh_pm_st_main_batch_start)
{
    SshPm pm = (SshPm) fsm_context;

    SSH_FSM_SET_NEXT(ssh_pm_st_main_batch);

    SSH_ASSERT(pm->batch_active);

    /* Continue batch by disabling ike library for a while. */
    SSH_FSM_ASYNC_CALL(ssh_pm_policy_suspend(pm, pm_batch_policy_suspend_cb,
                                             thread));

    SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_pm_st_main_batch)
{
    SshPm pm = (SshPm) fsm_context;
    SshADTHandle handle;
    SshADTHandle next;

    /* Did we fail suspend operation? */
    if (pm->batch_failed)
    {
        /* We need to take care of the batch additions and deletions here. */
        if (pm->batch.deletions)
        {
            SSH_DEBUG(SSH_D_NICETOKNOW, ("Removing batch deletions."));

            for (handle = ssh_adt_enumerate_start(pm->batch.deletions);
                 handle != SSH_ADT_INVALID;
                 handle = next)
            {
                next = ssh_adt_enumerate_next(pm->batch.deletions, handle);
                ssh_adt_detach(pm->batch.deletions, handle);
            }

            SSH_ASSERT(ssh_adt_num_objects(pm->batch.deletions) == 0);
            ssh_adt_destroy(pm->batch.deletions);
            pm->batch.deletions = NULL;
        }

        if (pm->batch.additions)
        {
            SSH_DEBUG(SSH_D_NICETOKNOW, ("Removing batch additions."));

            for (handle = ssh_adt_enumerate_start(pm->batch.additions);
                 handle != SSH_ADT_INVALID;
                 handle = next)
            {
                next = ssh_adt_enumerate_next(pm->batch.additions, handle);
                ssh_adt_detach(pm->batch.additions, handle);
            }

            SSH_ASSERT(ssh_adt_num_objects(pm->batch.additions) == 0);
            ssh_adt_destroy(pm->batch.additions);
            pm->batch.additions = NULL;
        }

        SSH_FSM_SET_NEXT(ssh_pm_st_main_batch_done);
        return SSH_FSM_CONTINUE;
    }

    pm->mt_current.container = NULL;
    pm->mt_current.handle = SSH_ADT_INVALID;

    /* Then, move to rule additions. */
    SSH_FSM_SET_NEXT(ssh_pm_st_main_batch_additions);
    return SSH_FSM_CONTINUE;
}

/* Process entries on batch.additions container */
SSH_FSM_STEP(ssh_pm_st_main_batch_additions)
{
    SshPm pm = (SshPm) fsm_context;
    SshPmRule rule;

    if (pm->mt_current.container == NULL)
    {
        /* Add the first rule from the additions list. */
        pm->mt_current.container = pm->batch.additions;
        if (pm->batch.additions)
          pm->mt_current.handle = ssh_adt_enumerate_start(pm->batch.additions);
        else
          pm->mt_current.handle = SSH_ADT_INVALID;
    }
    else
    {
        /* advance and detach the old rule */
        pm->mt_current.handle =
          ssh_adt_enumerate_next(pm->mt_current.container,
                                 pm->mt_current.handle);
    }

    /* All additions done, next sanity check added rules. */
    if (pm->mt_current.handle == SSH_ADT_INVALID)
    {
        pm->mt_current.container = pm->batch.deletions;
        if (pm->batch.deletions)
          pm->mt_current.handle = ssh_adt_enumerate_start(pm->batch.deletions);
        else
          pm->mt_current.handle = SSH_ADT_INVALID;

        /* All additions are done.  Move on to deletions. */
        SSH_FSM_SET_NEXT(ssh_pm_st_main_batch_deletions);
        return SSH_FSM_CONTINUE;
    }

    /* Insert it into rule by precedence and rule by id containers. */
    rule = ssh_adt_get(pm->mt_current.container, pm->mt_current.handle);
    ssh_adt_insert(pm->rule_by_precedence, rule);
    ssh_adt_insert(pm->rule_by_id, rule);

    /* Insert auto start rules to rule by autostart container. */
    if (rule->side_to.auto_start)
    {
        ssh_adt_insert(pm->rule_by_autostart, rule);
        rule->in_auto_start_adt = 1;
    }

    SSH_FSM_SET_NEXT(ssh_pm_st_main_batch_addition);
    return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_main_batch_addition)
{
    SshPm pm = (SshPm) fsm_context;
    SshPmRule rule;

    rule = ssh_adt_get(pm->mt_current.container, pm->mt_current.handle);
    SSH_ASSERT(rule != NULL);

#ifdef SSHDIST_ISAKMP_CFG_MODE_RULES
    if (rule->flags & SSH_PM_RULE_CFGMODE_RULES)
    {
        SSH_DEBUG(
                SSH_D_NICETOKNOW,
                ("Not creating filter rules for cfgmode placeholder rule `%@'",
                 ssh_pm_rule_render, rule));

        SSH_FSM_SET_NEXT(ssh_pm_st_main_batch_additions);
        return SSH_FSM_CONTINUE;
    }
#endif /* SSHDIST_ISAKMP_CFG_MODE_RULES */

    SSH_DEBUG(
            SSH_D_NICETOKNOW,
            ("Creating filter rules for rule `%@'", ssh_pm_rule_render, rule));

#ifdef SSHDIST_IPSEC_DNSPOLICY
    if (pm_rule_get_dns_status(pm, rule) == SSH_PM_DNS_STATUS_ERROR)
    {
        SSH_DEBUG(SSH_D_MIDOK, ("DNS selectors for rule not yet resolved; "
                                "can't create rules for rule %@.",
                                ssh_pm_rule_render, rule));
    }
    else
#endif /* SSHDIST_IPSEC_DNSPOLICY */
    {
        if (ssh_pm_ipsec_rule_add(pm, rule) == false)
        {
            SSH_DEBUG(SSH_D_NICETOKNOW,
                      ("Unable to create rule `%@'",
                       ssh_pm_rule_render, rule));
        }
    }

    /** Move ahead. */
    SSH_FSM_SET_NEXT(ssh_pm_st_main_batch_additions);
    return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_main_batch_deletions)
{
    SshPm pm = (SshPm) fsm_context;
    SshADTHandle handle, next;
    SshPmRule rule;

    if (pm->mt_current.handle != SSH_ADT_INVALID)
    {
        rule = ssh_adt_get(pm->mt_current.container, pm->mt_current.handle);
        SSH_ASSERT(rule->flags & SSH_PM_RULE_I_DELETED);

        pm->batch_deleted_rules = 1;

        /* Delete this rule's low-level rules. */
        SSH_FSM_SET_NEXT(ssh_pm_st_main_batch_deletions_delete);
        return SSH_FSM_CONTINUE;
    }

    /* All deletions done.  As the final step we must remove the deleted
       rules from the SPD and recycle the rule objects. */
    if (pm->batch.deletions)
    {
        for (handle = ssh_adt_enumerate_start(pm->batch.deletions);
             handle != SSH_ADT_INVALID;
             handle = next)
        {
            next = ssh_adt_enumerate_next(pm->batch.deletions, handle);
            rule = ssh_adt_get(pm->batch.deletions, handle);

            SSH_ASSERT(rule->flags & SSH_PM_RULE_I_DELETED);

            /* Remove this rule from the sub-rule chain (double-linked
               by the master_rule and sub_rule fields). */
            if (rule->master_rule)
              rule->master_rule->sub_rule = rule->sub_rule;
            if (rule->sub_rule)
              rule->sub_rule->master_rule = rule->master_rule;
            rule->master_rule = NULL;
            rule->sub_rule = NULL;

            /* Remove the rule from its containers */
            ssh_adt_detach(
                    pm->rule_by_precedence,
                    &rule->rule_by_precedence_hdr);

            if (rule->in_auto_start_adt)
            {
                ssh_adt_detach(
                        pm->rule_by_autostart,
                        &rule->rule_by_autostart_hdr);
                rule->in_auto_start_adt = 0;
            }

            ssh_adt_detach(pm->batch.deletions, handle);
            ssh_adt_detach(pm->rule_by_id, &rule->rule_by_index_hdr);

            /* Finally delete the rule */
            ssh_pm_rule_free(pm, rule);
        }
    }

    /* Now we have successfully added new rules and removed the
       deleted ones.  As the final pass we must clear
       SSH_PM_RULE_I_IN_BATCH flags from the new rules. */
    if (pm->batch.additions)
    {
        for (handle = ssh_adt_enumerate_start(pm->batch.additions);
             handle != SSH_ADT_INVALID;
             handle = next)
        {
            next = ssh_adt_enumerate_next(pm->batch.additions, handle);
            rule = ssh_adt_get(pm->batch.additions, handle);

            /* Remove the rule for the batch additions container */
            ssh_adt_detach(pm->batch.additions, handle);

            SSH_ASSERT((rule->flags & SSH_PM_RULE_I_DELETED) == 0);
            if (rule->flags & SSH_PM_RULE_I_IN_BATCH)
            {
                rule->flags &= ~SSH_PM_RULE_I_IN_BATCH;
                /* And wake up possible threads waiting for the batch to
                   complete. */
                SSH_FSM_CONDITION_BROADCAST(&rule->cond);
            }
        }
    }

    pm->batch_failed = 0;

    if (pm->batch.additions != NULL)
    {
        SSH_ASSERT(ssh_adt_num_objects(pm->batch.additions) == 0);
        ssh_adt_destroy(pm->batch.additions);
        pm->batch.additions = NULL;
   }
    if (pm->batch.deletions != NULL)
    {
        SSH_ASSERT(ssh_adt_num_objects(pm->batch.deletions) == 0);
        ssh_adt_destroy(pm->batch.deletions);
        pm->batch.deletions = NULL;
    }

    SSH_FSM_SET_NEXT(ssh_pm_st_main_batch_done_resume);
    return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_main_batch_deletions_delete)
{
    SshPm pm = (SshPm) fsm_context;
    SshPmRule rule;

    rule = ssh_adt_get(pm->mt_current.container, pm->mt_current.handle);

    /* Wait until the rule has no references. In addition, delete possible
       active p1 negotiation references. */
    if (rule->refcount > 0)
    {
        SSH_DEBUG(SSH_D_LOWOK,
                  ("Waiting until rule `%@' has no references: refcount=%d",
                   ssh_pm_rule_render, rule, (int) rule->refcount));

#ifdef WITH_IKE
        /* Abort negotiations */
        if (!(rule->flags & SSH_PM_RULE_I_IKE_ABORT))
          ssh_pm_delete_rule_negotiations(pm, rule);
#endif /* WITH_IKE */

        rule->flags |= SSH_PM_RULE_I_IKE_ABORT;

        /* Wake up all users of this thread.  Note that this does not
           wake up IKE negotiations.  They will continue when their IKE
           negotiation is completed. */
        SSH_FSM_CONDITION_BROADCAST(&rule->cond);
        SSH_FSM_CONDITION_BROADCAST(&pm->resume_cond);
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
        if (rule->side_to.tunnel && rule->side_to.tunnel->vip)
        {
            rule->side_to.tunnel->vip->rule_deleted = 1;
            SSH_FSM_CONDITION_BROADCAST(&rule->side_to.tunnel->vip->cond);
        }
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

        /* And wait that some of the threads are finished. */
        if (rule->refcount > 0)
        {
            SSH_DEBUG(
                    SSH_D_LOWOK,
                    ("Waiting until rule `%@' has no references: refcount=%d",
                     ssh_pm_rule_render, rule, (int) rule->refcount));
            SSH_FSM_CONDITION_WAIT(&pm->main_thread_cond);
        }
    }

    pm_delete_all_by_rule(pm, rule);

    SSH_DEBUG(SSH_D_NICETOKNOW,
              ("Deleting rule `%@'", ssh_pm_rule_render, rule));

    /* Move ahead in the delete batch. */
    pm->mt_current.handle =
        ssh_adt_enumerate_next(
                pm->mt_current.container,
                pm->mt_current.handle);
    SSH_FSM_SET_NEXT(ssh_pm_st_main_batch_deletions);
    return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_main_batch_abort)
{
    SshPm pm = (SshPm) fsm_context;
    SshPmRule rule, *rulep;
    SshADTHandle handle, next;

    /* The abort operation is potentially expensive, it iterates through
       all rules on the pm->rule_by_id container. */
    if (pm->mt_current.handle != SSH_ADT_INVALID)
    {
        rule = ssh_adt_get(pm->rule_by_id, pm->mt_current.handle);
        SSH_ASSERT(rule != NULL);

        if ((rule->flags & (SSH_PM_RULE_I_IN_BATCH | SSH_PM_RULE_I_DELETED))
            == SSH_PM_RULE_I_IN_BATCH)
        {
            /* This rule was successfully added in this batch.  Let's delete
               it. */
            SSH_FSM_SET_NEXT(ssh_pm_st_main_batch_abort_delete);
            return SSH_FSM_CONTINUE;
        }

        /* Move ahead. */
        pm->mt_current.handle =
          ssh_adt_enumerate_next(pm->rule_by_id, pm->mt_current.handle);
        return SSH_FSM_CONTINUE;
    }

    /* All additions of this batch have been removed.  Now we are
       ready for final cleanup. */
    for (handle = ssh_adt_enumerate_start(pm->rule_by_id);
         handle != SSH_ADT_INVALID;
         handle = next)
    {
        next = ssh_adt_enumerate_next(pm->rule_by_id, handle);
        rule = ssh_adt_get(pm->rule_by_id, handle);
        SSH_ASSERT(rule != NULL);

        /* Break all `sub_rule' relations from the added rules. */
        for (rulep = &rule->sub_rule; *rulep; )
        {
            if (((*rulep)->flags & (SSH_PM_RULE_I_DELETED
                                    | SSH_PM_RULE_I_IN_BATCH))
                == SSH_PM_RULE_I_IN_BATCH)
            {
                /* The rule was added in this batch.  Break the sub-rule
                   relation. */
                (*rulep)->master_rule = NULL;
                *rulep = (*rulep)->sub_rule;
            }
            else
            {
                rulep = &(*rulep)->sub_rule;
            }
        }
        if (rule->flags & SSH_PM_RULE_I_DELETED)
        {
            /* The rule was to be deleted in this batch.  Just clear
               the deletion flag, so it will not get deleted.  */
            rule->flags &=
                  ~(SSH_PM_RULE_I_DELETED | SSH_PM_RULE_I_IN_BATCH);

            /* Remove the rule from the deletions container. */
            ssh_adt_detach(pm->batch.deletions, &rule->rule_by_index_del_hdr);
        }
        else if (rule->flags & SSH_PM_RULE_I_IN_BATCH)
        {
            SSH_ASSERT((rule->flags & SSH_PM_RULE_I_DELETED) == 0);

            /* The rule was to be added in this batch. */

            /* Remove the rule from its containers. */
            ssh_adt_detach(
                    pm->rule_by_precedence,
                    &rule->rule_by_precedence_hdr);
            ssh_adt_detach(
                    pm->batch.additions,
                    &rule->rule_by_index_add_hdr);

            if (rule->in_auto_start_adt)
            {
                ssh_adt_detach(
                        pm->rule_by_autostart,
                        &rule->rule_by_autostart_hdr);
                rule->in_auto_start_adt = 0;
            }

            ssh_adt_detach(pm->rule_by_id, &rule->rule_by_index_hdr);

            /* Remove this sub-rule from the master-rule's subrule list. */
            if (rule->master_rule != NULL)
            {
                SSH_ASSERT(rule->flags & SSH_PM_RULE_I_SYSTEM);
                for (rulep = &rule->master_rule->sub_rule; *rulep;)
                {
                    if (*rulep == rule)
                      *rulep = (*rulep)->sub_rule;
                    else
                      rulep = &(*rulep)->sub_rule;
                }
            }

            /* Finally free the rule. */
            ssh_pm_rule_free(pm, rule);
        }
    }

    /* Free all pending additions and deletions. */
    ssh_adt_destroy(pm->batch.additions);
    pm->batch.additions = NULL;

    ssh_adt_destroy(pm->batch.deletions);
    pm->batch.deletions = NULL;

    /* And notify user. */
    pm->batch_failed = 1;
    SSH_FSM_SET_NEXT(ssh_pm_st_main_batch_done_resume);

    return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_main_batch_abort_delete)
{
    SshPm pm = (SshPm) fsm_context;
    SshPmRule rule;

    rule = ssh_adt_get(pm->mt_current.container, pm->mt_current.handle);

    /* Wait that all sub-threads go away from the rule. */
    if (rule->refcount > 0)
    {
        rule->flags |= SSH_PM_RULE_I_BATCH_F;
        SSH_FSM_CONDITION_BROADCAST(&rule->cond);
        SSH_FSM_CONDITION_WAIT(&pm->main_thread_cond);
    }

    /* Let's move ahead. */
    pm->mt_current.handle =
        ssh_adt_enumerate_next(
                pm->mt_current.container,
                pm->mt_current.handle);

    SSH_FSM_SET_NEXT(ssh_pm_st_main_batch_abort);
    return SSH_FSM_CONTINUE;
}

static void
ssh_pm_st_main_batch_check_sa_validity(SshPm pm)
{
    SshPmP1 p1 = NULL;
    SshPmP1 next_p1 = NULL;
    uint32_t hash = 0;
    SshPmTunnel tunnel = NULL;

    /* Clear resume queue. This is safe to do since we are looping through
       the whole IKE SA hash table. */
    pm->resume_queue = NULL;

    SSH_DEBUG(SSH_D_NICETOKNOW, ("Going through IKE SA table. "));

    for (hash = 0; hash < SSH_PM_IKE_SA_HASH_TABLE_SIZE; hash++)
    {
        p1 = pm->ike_sa_hash[hash];

        while (p1)
        {
            bool is_ikev1 = false;
            uint32_t flags = 0;

            next_p1 = p1->hash_next;

            /* Clear resume queue pointer. */
            p1->resume_queue_next = NULL;
            p1->in_resume_queue = 0;

            /* Do the delayed IPsec delete notifications. */
            tunnel = ssh_pm_tunnel_get_by_id(pm, p1->tunnel_id);

            /* Invalidate p1's tunnel_id if tunnel is not part of the
               active configuration. PM IKE SA timer will handle IKE SA
               deletion in a delayed fashion. */
            if (tunnel == NULL || tunnel->referring_rule_count == 0)
            {
                SSH_DEBUG(SSH_D_LOWOK,
                          ("IKE SA %p was negotiated from a tunnel that does "
                           "not belong to the active policy, "
                           "marking for deletion",
                           p1->ike_sa));
                p1->tunnel_id = SSH_IPSEC_INVALID_INDEX;
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
                if (tunnel && tunnel->vip)
                  ssh_pm_virtual_ip_free(pm, tunnel);
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */
            }

#ifdef SSHDIST_IKEV1
            if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
              is_ikev1 = true;
            flags = SSH_IKEV2_IKE_DELETE_FLAGS_FORCE_DELETE_NOW;
#endif /* SSHDIST_IKEV1 */

            /* Send delayed IPsec notification in following cases:
               1. This is IKEv1 SA
               2. IKEv2 and only rules reconfigured. */
            if (p1->delete_notification_requests &&
                (is_ikev1 || (tunnel && tunnel->referring_rule_count > 0)))
            {
                SSH_DEBUG(SSH_D_NICETOKNOW,
                          ("Sending delayed IPsec delete notifications for "
                           "P1 %p",
                           p1));

                ssh_pm_send_ipsec_delete_notification_requests(pm, p1);
            }

            /* Otherwise free any pending delete notification
               requests, as IKEv2 SA is going to get deleted soon
               anyway. */
            else
            {
                ssh_pm_free_ipsec_delete_notification_requests(p1);

                /* Delete P1 with no child SA's or vanished tunnel
                   ID's.  I.e. tunnel is removed or all the IPsec SA's
                   has been removed for some reason... */
                if ((ssh_pm_peer_num_child_sas_by_p1(pm, p1) == 0
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
#ifdef SSHDIST_ISAKMP_CFG_MODE_RULES
                     /* ... but don't delete a P1 that is waiting for
                        some cfgmode-based child SA's to appear. */
                     && !(tunnel != NULL && tunnel->vip != NULL &&
                          tunnel->vip->rules != NULL &&
                          (tunnel->vip->rules->rule->flags &
                           SSH_PM_RULE_CFGMODE_RULES) != 0)
#endif /* SSHDIST_ISAKMP_CFG_MODE_RULES */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */
                     ) || tunnel == NULL || tunnel->referring_rule_count == 0)
                {
                    if (!SSH_PM_P1_DELETED(p1))
                    {
                        int i;

                        /* Aborting all ongoing operations. Not sure
                           if this is really necessary, but playing safe. */
                        for (i = 0; i < PM_IKE_NUM_INITIATOR_OPS; i++)
                        {
                            SshOperationHandle op = p1->initiator_ops[i];

                            /* Clear the operation handle from the p1 to avoid
                               recursive calls aborting the operations. */
                            p1->initiator_ops[i] = NULL;
                            if (op)
                              ssh_operation_abort(op);
                        }

                        SSH_DEBUG(SSH_D_LOWOK,
                                  ("Deleting IKE SA %p", p1->ike_sa));
                        SSH_PM_IKEV2_IKE_SA_DELETE(
                                p1, flags,
                                pm_ike_sa_delete_notification_done_callback);
                    }
                }
            }

            p1 = next_p1;
        }
    }
}

SSH_FSM_STEP(ssh_pm_st_main_batch_done_resume)
{
    SshPm pm = (SshPm) fsm_context;

    /* Resume policy manager */
    if (!ssh_pm_policy_resume(pm))
      SSH_DEBUG(SSH_D_FAIL, ("Policy manager resume failed."));
    else
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Policy manager resumed."));

    /* Now loop all the IKE SAs. do all pending IPsec SA delete
       notifications, remove childless IKE SAs and IKE SAs with
       removed tunnels. */
    if (pm->batch_deleted_rules)
      ssh_pm_st_main_batch_check_sa_validity(pm);

    SSH_FSM_SET_NEXT(ssh_pm_st_main_batch_done);
    return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_main_batch_done)
{
    SshPm pm = (SshPm) fsm_context;
    bool success;
    SshPmStatusCB status_cb;
    void *status_cb_context;

    /* Signal that the main batch has ended and the
       suspended threads continue. */
    SSH_FSM_CONDITION_BROADCAST(&pm->resume_cond);

    success = pm->batch_failed ? false : true;
    status_cb = pm->batch.status_cb;
    status_cb_context = pm->batch.status_cb_context;

    /* Notify submodules interested on policy changes. */
    if (pm->batch_changes)
      ssh_pm_dpd_policy_change_notify(pm);

#ifdef SSH_PM_BLACKLIST_ENABLED
    /* In successful case commit blacklist changes and otherwise abort them. */
    if (success)
      ssh_pm_blacklist_commit(pm);
    else
      ssh_pm_blacklist_abort(pm);
#endif /* SSH_PM_BLACKLIST_ENABLED */

    /* The batch is completed, cleanup. */
    pm->batch_deleted_rules = 0;
    pm->batch_active = 0;
    pm->batch_failed = 0;
    pm->batch_changes = 0;
    pm->batch.status_cb = NULL_FNPTR;
    pm->batch.status_cb_context = NULL;

    /* Call user callback. */
    if (status_cb)
      (*status_cb)(pm, success, status_cb_context);

    /* Check auto-start rules after policy modifications. */
    pm->auto_start = 1;

    SSH_FSM_CONDITION_BROADCAST(&pm->main_thread_cond);
    SSH_FSM_SET_NEXT(ssh_pm_st_main_run);

    SSH_APE_MARK(1, ("Policy manager resumed"));

    return SSH_FSM_CONTINUE;
}
