/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   IPsec related utility functions that are independent of the keying
   method. No IKE specific code must be included in this file.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"

#define SSH_DEBUG_MODULE "PmUtilIPSec"


/**************** Help functions for Quick mode threads ********************/

void
pm_qm_thread_destructor(
        SshFSM fsm,
        void *context)
{
    SshPm pm = (SshPm) ssh_fsm_get_gdata_fsm(fsm);
    SshPmQm qm = (SshPmQm) context;

    SSH_PM_ASSERT_QM(qm);
    SSH_DEBUG(
            SSH_D_NICETOKNOW,
            ("In Quick-Mode thread destructor for QM %p",
             qm));

    /* Release the QM negotiation context for the initiator unless they
       are running the sub thread. If sub-thread is run, then then free
       is delayed to its destructor (if qm->ed == NULL) there. See
       pm_qm_sub_thread_destructor function above. */
    if (!SSH_FSM_THREAD_EXISTS(&qm->sub_thread))
    {
        ssh_pm_qm_free(pm, qm);
    }
}

bool
ssh_pm_check_qm_error(
        SshPmQm qm,
        SshFSMThread thread,
        SshFSMStepCB error_state)
{
    if (qm->error != SSH_IKEV2_ERROR_OK)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Setting QM %p thread to error state", qm));
        ssh_fsm_set_next(thread, error_state);
        return true;
    }
    return false;
}

void
ssh_pm_rule_auto_start_remove(
        SshPm pm,
        SshPmRule rule)
{
    SSH_ASSERT(rule->side_from.auto_start == 0);

    if ((rule->side_to.auto_start == 0 || rule->side_to.as_up == 1)
        || rule->side_from.as_up == 1)
    {
        if (rule->in_auto_start_adt)
        {
            ssh_adt_detach(
                    pm->rule_by_autostart,
                    &rule->rule_by_autostart_hdr);
            rule->in_auto_start_adt = 0;
        }
    }
}

void
ssh_pm_rule_auto_start_insert(
        SshPm pm,
        SshPmRule rule)
{
    if (rule->in_auto_start_adt == 0)
    {
        ssh_adt_insert(pm->rule_by_autostart, rule);
        rule->in_auto_start_adt = 1;
    }
}

/* Update success status about auto-start tunnels. */
void
ssh_pm_qm_update_auto_start_status(
        SshPm pm,
        SshPmQm qm)
{
    SshPmRuleSideSpecification side;

    if (qm->auto_start)
    {
        SSH_ASSERT(qm->tunnel != NULL);
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
        SSH_ASSERT((qm->tunnel->flags & SSH_PM_TI_DELAYED_OPEN) == 0
                   ||(qm->tunnel->flags & SSH_PM_TI_INTERFACE_TRIGGER) != 0);
#else /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */
        SSH_ASSERT((qm->tunnel->flags & SSH_PM_TI_DELAYED_OPEN) == 0);
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

        if (qm->rule == NULL)
        {
            return;
        }
        else if (qm->forward)
        {
            side = &qm->rule->side_to;
        }
        else
        {
            side = &qm->rule->side_from;
        }

        if (qm->error)
        {
            SSH_DEBUG(SSH_D_FAIL, ("Auto-start rule failed"));

            /* If qm failed locally because of no usable IKE server was
               found, then clear the auto start failure counter so that
               the IKE negotiation is started as soon as possible after
               a valid IKE server has been started. */
            if (qm->error == SSH_PM_QM_ERROR_NO_IKE_PEERS)
            {
                side->as_fail_retry = 0;
            }
            else
            {
                if (side->as_fail_limit < 16)
                {
                    side->as_fail_limit++;
                }

                side->as_fail_retry = side->as_fail_limit;
            }

            side->as_up = 0;
        }
        else
        {
            SSH_DEBUG(SSH_D_NICETOKNOW, ("Auto-start tunnel up"));
            side->as_up = 1;
            side->as_fail_limit = 0;

            /* Check if another rule is waiting for this auto-start tunnel to
               come up, if so signal to the main thread to reconsider the
               auto-start rules. */
            if (qm->tunnel->as_rule_pending)
            {
                qm->tunnel->as_rule_pending = 0;
                pm->auto_start = 1;
                ssh_fsm_condition_broadcast(&pm->fsm, &pm->main_thread_cond);
            }
        }

        /* Mark rule and tunnel not having an auto-start negotiation active. */
        side->as_active = 0;
        qm->tunnel->as_active = 0;
    }
    else if (qm->error == 0)
    {
        /* Update success status about auto-start tunnels also for trigger
           and responder negotiations. */
        if (qm->rule == NULL)
        {
            return;
        }
        else if (qm->forward)
        {
            side = &qm->rule->side_to;
        }
        else
        {
            side = &qm->rule->side_from;
        }

        if (side->auto_start)
        {
            side->as_up = 1;
            side->as_fail_limit = 0;
        }
    }

    /* If the autostart status of rule's both directions is ok,
       then detach the rule from autostart ADT. */
    if (qm->rule != NULL)
    {
        ssh_pm_rule_auto_start_remove(pm, qm->rule);
    }
}


/* ************************** IPsec SA events *******************************/

void
ssh_pm_ipsec_sa_event_created(
        SshPm pm,
        SshPmQm qm)
{
    SshPmIPsecSAEventHandleStruct ipsec_sa;

    SSH_PM_ASSERT_QM(qm);

    SSH_DEBUG(SSH_D_LOWOK, ("IPsec SA created"));

    if (pm->ipsec_sa_callback)
    {
        memset(&ipsec_sa, 0, sizeof(ipsec_sa));
        ipsec_sa.event = SSH_PM_SA_EVENT_CREATED;
        ipsec_sa.qm = qm;

        (*pm->ipsec_sa_callback)(
                pm,
                ipsec_sa.event,
                &ipsec_sa,
                pm->ipsec_sa_callback_context);
    }
}

void
ssh_pm_ipsec_sa_event_rekeyed(
        SshPm pm,
        SshPmQm qm)
{
    SshPmIPsecSAEventHandleStruct ipsec_sa;

    SSH_PM_ASSERT_QM(qm);

    SSH_DEBUG(SSH_D_LOWOK, ("IPsec SA rekeyed"));

    if (pm->ipsec_sa_callback)
    {
        struct IPsecSaParams *ipsec_sa_params;

        /* Generate rekeyed event for the new SPI values. */
        memset(&ipsec_sa, 0, sizeof(ipsec_sa));
        ipsec_sa.event = SSH_PM_SA_EVENT_REKEYED;
        ipsec_sa.qm = qm;

        (*pm->ipsec_sa_callback)(
                pm,
                ipsec_sa.event,
                &ipsec_sa,
                pm->ipsec_sa_callback_context);

        /* Generate updated event for the old SPI values. */
        memset(&ipsec_sa, 0, sizeof(ipsec_sa));
        ipsec_sa.event = SSH_PM_SA_EVENT_UPDATED;
        ipsec_sa.update_type = SSH_PM_IPSEC_SA_UPDATE_OLD_SPI_INVALIDATED;
        ipsec_sa.outbound_spi = qm->old_outbound_spi;
        ipsec_sa.inbound_spi = qm->old_inbound_spi;

        ipsec_sa_params = &qm->ipsec_sa_params;

        if (ipsec_sa_params->ipproto == SSH_IPPROTO_ESP ||
            ipsec_sa_params->ipproto == SSH_IPPROTO_AH)
        {
            ipsec_sa.ipproto = ipsec_sa_params->ipproto;
        }
        else
        {
            SSH_NOTREACHED;
        }

        /* P1 to peer mapping may change if there are multiple simultaneous
           IKE/IPsec negotiations going on. */
        ipsec_sa.peer = ssh_pm_peer_by_p1(pm, qm->p1);
        if (ipsec_sa.peer == NULL)
        {
            ipsec_sa.peer = ssh_pm_peer_by_handle(pm, qm->peer_handle);
        }
        SSH_ASSERT(ipsec_sa.peer != NULL);

        (*pm->ipsec_sa_callback)(
                pm,
                ipsec_sa.event,
                &ipsec_sa,
                pm->ipsec_sa_callback_context);
    }
}

void
ssh_pm_ipsec_sa_event_deleted(
        SshPm pm,
        uint32_t outbound_spi,
        uint32_t inbound_spi,
        uint8_t ipproto)
{
    SshPmIPsecSAEventHandleStruct ipsec_sa;

    SSH_DEBUG(SSH_D_LOWOK, ("IPsec SA deleted"));

    if (pm->ipsec_sa_callback)
    {
        memset(&ipsec_sa, 0, sizeof(ipsec_sa));
        ipsec_sa.event = SSH_PM_SA_EVENT_DELETED;
        ipsec_sa.outbound_spi = outbound_spi;
        ipsec_sa.inbound_spi = inbound_spi;
        ipsec_sa.ipproto = ipproto;

        (*pm->ipsec_sa_callback)(
                pm,
                ipsec_sa.event,
                &ipsec_sa,
                pm->ipsec_sa_callback_context);
    }
}

void
ssh_pm_ipsec_sa_event_peer_updated(
        SshPm pm,
        SshPmPeer peer,
        bool enable_natt,
        bool enable_tcpencap)
{
    SshPmIPsecSAEventHandleStruct ipsec_sa;
    SshPmSpiOut spi_out;

    SSH_DEBUG(SSH_D_LOWOK, ("IPsec SA updated"));

    if (pm->ipsec_sa_callback)
    {
        if (peer == NULL)
        {
            SSH_DEBUG(SSH_D_FAIL, ("No peer found"));
            return;
        }

        memset(&ipsec_sa, 0, sizeof(ipsec_sa));
        ipsec_sa.event = SSH_PM_SA_EVENT_UPDATED;
        ipsec_sa.update_type = SSH_PM_IPSEC_SA_UPDATE_PEER_UPDATED;

        for (spi_out = peer->spi_out;
             spi_out != NULL;
             spi_out = spi_out->peer_spi_next)
        {
            /* Skip old SPIs that are marked as rekeyed. */
            if (spi_out->rekeyed)
            {
                continue;
            }

            ipsec_sa.spi_out = spi_out;
            ipsec_sa.peer = peer;
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
            ipsec_sa.enable_natt = enable_natt;
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
            (*pm->ipsec_sa_callback)(
                    pm,
                    ipsec_sa.event,
                    &ipsec_sa,
                    pm->ipsec_sa_callback_context);
        }
    }
}

/* ********************** Other utility functions ****************************/

void
ssh_pm_tunnel_select_local_ip(
        SshPmTunnel tunnel,
        SshIpAddr peer,
        SshIpAddr local_ip_ret)
{
    SshPmTunnelLocalIp local_ip;

    SSH_ASSERT(tunnel != NULL);
    SSH_ASSERT(local_ip_ret != NULL);
    SSH_ASSERT(peer != NULL);

    SSH_IP_UNDEFINE(local_ip_ret);
    for (local_ip = tunnel->local_ip;
         local_ip != NULL;
         local_ip = local_ip->next)
    {
        if (SSH_IP_IS4(peer) && SSH_IP_IS4(&local_ip->ip))
        {
            break;
        }

        if (SSH_IP_IS6(peer) && SSH_IP_IS6(&local_ip->ip))
        {
            /* Found link-local local address for link-local peer. */
            if (SSH_IP6_IS_LINK_LOCAL(peer)
                && SSH_IP6_IS_LINK_LOCAL(&local_ip->ip))
            {
                break;
            }

            /* Found global local address for global peer. */
            if (!SSH_IP6_IS_LINK_LOCAL(peer)
                && !SSH_IP6_IS_LINK_LOCAL(&local_ip->ip))
            {
                break;
            }

            /* Found non-optimal link-local/global address pair.
               Continue searching for a better pair. */
            if (!SSH_IP_DEFINED(local_ip_ret))
            {
                *local_ip_ret = local_ip->ip;
            }
        }
    }

    if (local_ip != NULL)
    {
        *local_ip_ret = local_ip->ip;
    }
}


/* **** Utility functions for accessing information from IPsec SA's *********/

SshInetIPProtocolID
ssh_pm_ipsec_sa_get_protocol(
        SshPm pm,
        SshPmIPsecSAEventHandle ipsec_sa)
{
    struct IPsecSaParams *ipsec_sa_params;
    SSH_ASSERT(ipsec_sa != NULL);

    switch (ipsec_sa->event)
    {
    case SSH_PM_SA_EVENT_CREATED:
    case SSH_PM_SA_EVENT_REKEYED:
        SSH_PM_ASSERT_QM(ipsec_sa->qm);
        ipsec_sa_params = &ipsec_sa->qm->ipsec_sa_params;

        if (ipsec_sa_params->ipproto == SSH_IPPROTO_ESP ||
            ipsec_sa_params->ipproto == SSH_IPPROTO_AH)
        {
            return ipsec_sa_params->ipproto;
        }

        SSH_NOTREACHED;
        return SSH_IPPROTO_ANY;

    case SSH_PM_SA_EVENT_DELETED:
        return ipsec_sa->ipproto;

    case SSH_PM_SA_EVENT_UPDATED:
        if (ipsec_sa->update_type == SSH_PM_IPSEC_SA_UPDATE_PEER_UPDATED)
        {
            SSH_ASSERT(ipsec_sa->spi_out != NULL);
            return ipsec_sa->spi_out->ipproto;
        }
        else if (ipsec_sa->update_type
                 == SSH_PM_IPSEC_SA_UPDATE_OLD_SPI_INVALIDATED)
        {
            return ipsec_sa->ipproto;
        }
        else
        {
            SSH_NOTREACHED;
        }
        break;
    }

    SSH_NOTREACHED;
    return SSH_IPPROTO_ANY;
}

uint32_t
ssh_pm_ipsec_sa_get_inbound_spi(
        SshPm pm,
        SshPmIPsecSAEventHandle ipsec_sa)
{
    struct IPsecSaParams *ipsec_sa_params;
    uint32_t spi = 0;

    SSH_ASSERT(ipsec_sa != NULL);
    switch (ipsec_sa->event)
    {
    case SSH_PM_SA_EVENT_CREATED:
    case SSH_PM_SA_EVENT_REKEYED:
          SSH_PM_ASSERT_QM(ipsec_sa->qm);
          ipsec_sa_params = &ipsec_sa->qm->ipsec_sa_params;

          return ipsec_sa_params->inbound_spi;

    case SSH_PM_SA_EVENT_DELETED:
        return ipsec_sa->inbound_spi;

    case SSH_PM_SA_EVENT_UPDATED:
        if (ipsec_sa->update_type == SSH_PM_IPSEC_SA_UPDATE_PEER_UPDATED)
        {
            SSH_ASSERT(ipsec_sa->spi_out != NULL);
            return ipsec_sa->spi_out->inbound_spi;
        }
        else if (ipsec_sa->update_type
                 == SSH_PM_IPSEC_SA_UPDATE_OLD_SPI_INVALIDATED)
        {
            return ipsec_sa->inbound_spi;
        }
        else
        {
            SSH_NOTREACHED;
        }
        break;
    }

    SSH_NOTREACHED;
    return spi;
}

uint32_t
ssh_pm_ipsec_sa_get_outbound_spi(
        SshPm pm,
        SshPmIPsecSAEventHandle ipsec_sa)
{
    struct IPsecSaParams *ipsec_sa_params;
    uint32_t spi = 0;

    SSH_ASSERT(ipsec_sa != NULL);
    switch (ipsec_sa->event)
    {
    case SSH_PM_SA_EVENT_CREATED:
    case SSH_PM_SA_EVENT_REKEYED:
         SSH_PM_ASSERT_QM(ipsec_sa->qm);
         ipsec_sa_params = &ipsec_sa->qm->ipsec_sa_params;

         return ipsec_sa_params->outbound_spi;

    case SSH_PM_SA_EVENT_DELETED:
        return ipsec_sa->outbound_spi;

    case SSH_PM_SA_EVENT_UPDATED:
        if (ipsec_sa->update_type == SSH_PM_IPSEC_SA_UPDATE_PEER_UPDATED)
        {
            SSH_ASSERT(ipsec_sa->spi_out != NULL);
            return ipsec_sa->spi_out->outbound_spi;
        }
        else if (ipsec_sa->update_type
                 == SSH_PM_IPSEC_SA_UPDATE_OLD_SPI_INVALIDATED)
        {
            return ipsec_sa->outbound_spi;
        }
        else
        {
            SSH_NOTREACHED;
        }
        break;
    }

    SSH_NOTREACHED;
    return spi;
}

uint32_t
ssh_pm_ipsec_sa_get_old_inbound_spi(
        SshPm pm,
        SshPmIPsecSAEventHandle ipsec_sa)
{
    SSH_ASSERT(ipsec_sa != NULL);
    switch (ipsec_sa->event)
    {
    case SSH_PM_SA_EVENT_CREATED:
    case SSH_PM_SA_EVENT_REKEYED:
        SSH_PM_ASSERT_QM(ipsec_sa->qm);
        return ipsec_sa->qm->old_inbound_spi;

    default:
        break;
    }

    SSH_DEBUG(
            SSH_D_FAIL,
            ("Cannot get old outbound SPI for SA event other than "
             "SSH_PM_SA_EVENT_CREATED or SSH_PM_SA_EVENT_REKEYED"));
    return 0;
}

uint32_t
ssh_pm_ipsec_sa_get_life_seconds(
        SshPm pm,
        SshPmIPsecSAEventHandle ipsec_sa)
{
    struct IPsecSaParams *ipsec_sa_params;

    switch (ipsec_sa->event)
    {
    case SSH_PM_SA_EVENT_CREATED:
    case SSH_PM_SA_EVENT_REKEYED:
        if (ipsec_sa->life_seconds > 0)
          return ipsec_sa->life_seconds;

        SSH_PM_ASSERT_QM(ipsec_sa->qm);
        ipsec_sa_params = &ipsec_sa->qm->ipsec_sa_params;

        return ipsec_sa_params->life_seconds;

    default:
        break;
    }

    SSH_DEBUG(
            SSH_D_FAIL,
            ("Cannot get SA lifetime for SA event other than "
             "SSH_PM_SA_EVENT_CREATED or SSH_PM_SA_EVENT_REKEYED"));
    return 0;
}

uint32_t
ssh_pm_ipsec_sa_get_remaining_life_seconds(
        SshPm pm,
        SshPmIPsecSAEventHandle ipsec_sa)
{
    struct IPsecSaParams *ipsec_sa_params;

    switch (ipsec_sa->event)
    {
    case SSH_PM_SA_EVENT_CREATED:
    case SSH_PM_SA_EVENT_REKEYED:
        SSH_PM_ASSERT_QM(ipsec_sa->qm);
        ipsec_sa_params = &ipsec_sa->qm->ipsec_sa_params;

        return ipsec_sa_params->life_seconds;

    default:
        break;
    }

    SSH_DEBUG(
            SSH_D_FAIL,
            ("Cannot get remaining SA lifetime for SA event other than "
             "SSH_PM_SA_EVENT_CREATED or SSH_PM_SA_EVENT_REKEYED"));
    return 0;
}

void
ssh_pm_ipsec_sa_get_outbound_sequence_number(
        SshPm pm,
        SshPmIPsecSAEventHandle ipsec_sa,
        uint32_t *seq_low,
        uint32_t *seq_high,
        bool *esn)
{
    struct IPsecSaParams *ipsec_sa_params;

    SSH_ASSERT(ipsec_sa != NULL);
    switch (ipsec_sa->event)
    {
    case SSH_PM_SA_EVENT_CREATED:
    case SSH_PM_SA_EVENT_REKEYED:
        SSH_PM_ASSERT_QM(ipsec_sa->qm);
        ipsec_sa_params = &ipsec_sa->qm->ipsec_sa_params;

        *seq_low = ipsec_sa_params->seq_low;
        *seq_high = ipsec_sa_params->seq_high;
        *esn = ipsec_sa_params->esn;
        return;

    default:
        break;
    }

    *seq_low = 0;
    *seq_high = 0;
    *esn = false;

    SSH_DEBUG(
            SSH_D_FAIL,
            ("Cannot get outbound sequence for SA event other than "
             "SSH_PM_SA_EVENT_CREATED or SSH_PM_SA_EVENT_REKEYED"));
}

#ifdef SSHDIST_IPSEC_SA_EXPORT

/* Sets the outbound sequence numbers for 'ipsec_sa' to 'seq_high' and
   'seq_low'. */
void
ssh_pm_ipsec_sa_set_outbound_sequence_number(
        SshPm pm,
        SshPmIPsecSAEventHandle ipsec_sa,
        uint32_t seq_low,
        uint32_t seq_high)
{
    struct IPsecSaParams *ipsec_sa_params;

    SSH_ASSERT(ipsec_sa != NULL);
    switch (ipsec_sa->event)
    {
    case SSH_PM_SA_EVENT_CREATED:
    case SSH_PM_SA_EVENT_REKEYED:
        SSH_PM_ASSERT_QM(ipsec_sa->qm);
        SSH_DEBUG(
                SSH_D_LOWOK,
                ("Setting outbound IPsec sequence to 0x%lx 0x%lx for qm %p",
                 (unsigned long) seq_high,
                 (unsigned long) seq_low,
                 ipsec_sa->qm));
        ipsec_sa_params = &ipsec_sa->qm->ipsec_sa_params;
        if (ipsec_sa_params->esn == true)
        {
            ipsec_sa_params->seq_low = seq_low;
            ipsec_sa_params->seq_high = seq_high;
        }
        else
        {
            ipsec_sa_params->seq_low = seq_low;
            ipsec_sa_params->seq_high = 0;
        }
        return;

    default:
        break;
    }

    SSH_DEBUG(
            SSH_D_FAIL,
            ("Cannot set outbound sequence for SA event other than "
             "SSH_PM_SA_EVENT_CREATED or SSH_PM_SA_EVENT_REKEYED"));
}

/* Return IPsec SA's tunnel application identifier. */
bool
ssh_pm_ipsec_sa_get_tunnel_application_identifier(
        SshPm pm,
        SshPmIPsecSAEventHandle ipsec_sa,
        char *id,
        size_t *id_len)
{
    SSH_ASSERT(ipsec_sa != NULL);
    SSH_ASSERT(id != NULL);
    SSH_ASSERT(id_len != NULL);

    if (ipsec_sa->event == SSH_PM_SA_EVENT_CREATED)
    {
        if (*id_len < ipsec_sa->tunnel_application_identifier_len)
        {
            return false;
        }

        memcpy(
                id,
                ipsec_sa->tunnel_application_identifier,
                ipsec_sa->tunnel_application_identifier_len);
        *id_len = ipsec_sa->tunnel_application_identifier_len;

        return true;
    }

    SSH_DEBUG(
            SSH_D_FAIL,
            ("Cannot get tunnel application identifier for SA event other "
             "than SSH_PM_SA_EVENT_CREATED"));

    return false;
}

/* Sets the 'tunnel' for IPsec SA 'ipsec_sa'. */
void
ssh_pm_ipsec_sa_set_tunnel(
        SshPm pm,
        SshPmIPsecSAEventHandle ipsec_sa,
        SshPmTunnel tunnel)
{
    SSH_ASSERT(ipsec_sa != NULL);
    SSH_ASSERT(tunnel != NULL);

    if (ipsec_sa->event == SSH_PM_SA_EVENT_CREATED)
    {
        SSH_PM_ASSERT_QM(ipsec_sa->qm);

        SSH_DEBUG(
                SSH_D_LOWOK,
                ("Setting tunnel_id %d for qm %p",
                 (int) tunnel->tunnel_id,
                 ipsec_sa->qm));

        SSH_PM_TUNNEL_TAKE_REF(tunnel);
        if (ipsec_sa->qm->tunnel)
        {
            SSH_PM_TUNNEL_DESTROY(pm, ipsec_sa->qm->tunnel);
        }
        ipsec_sa->qm->tunnel = tunnel;
        return;
    }

    SSH_DEBUG(
            SSH_D_FAIL,
            ("Cannot set tunnel id for SA event other than "
             "SSH_PM_SA_EVENT_CREATED"));
}

/* Returns the IPsec SA's rule application identifier. */
bool
ssh_pm_ipsec_sa_get_rule_application_identifier(
        SshPm pm,
        SshPmIPsecSAEventHandle ipsec_sa,
        char *id,
        size_t *id_len)
{
    SSH_ASSERT(ipsec_sa != NULL);
    SSH_ASSERT(id != NULL);
    SSH_ASSERT(id_len != NULL);

    if (ipsec_sa->event == SSH_PM_SA_EVENT_CREATED)
    {
        if (*id_len < ipsec_sa->rule_application_identifier_len)
        {
            return false;
        }

        memcpy(
                id,
                ipsec_sa->rule_application_identifier,
                ipsec_sa->rule_application_identifier_len);
        *id_len = ipsec_sa->rule_application_identifier_len;

        return true;
    }

    SSH_DEBUG(
            SSH_D_FAIL,
            ("Cannot get rule application identifier for SA event other than "
             "SSH_PM_SA_EVENT_CREATED"));

    return false;
}

/* Sets the 'rule' for IPsec SA 'ipsec_sa'. */
void
ssh_pm_ipsec_sa_set_rule(
        SshPm pm,
        SshPmIPsecSAEventHandle ipsec_sa,
        SshPmRule rule)
{
    SSH_ASSERT(ipsec_sa != NULL);
    SSH_ASSERT(rule != NULL);

    if (ipsec_sa->event == SSH_PM_SA_EVENT_CREATED)
    {
        SSH_PM_ASSERT_QM(ipsec_sa->qm);

        SSH_DEBUG(
                SSH_D_LOWOK,
                ("Setting rule_id %d for qm %p",
                 (int) rule->rule_id,
                 ipsec_sa->qm));

        SSH_PM_RULE_LOCK(rule);
        if (ipsec_sa->qm->rule)
        {
            SSH_PM_RULE_UNLOCK(pm, ipsec_sa->qm->rule);
        }
        ipsec_sa->qm->rule = rule;
        return;
    }

    SSH_DEBUG(
            SSH_D_FAIL,
            ("Cannot set rule id for SA event other than "
             "SSH_PM_SA_EVENT_CREATED"));
}

#endif /* SSHDIST_IPSEC_SA_EXPORT */
