/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   Utility functions related to deletion of IKE/IPSec SA's.
   Initial contact notification processing is also handled here.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"
#include "sshadt.h"
#include "sshadt_bag.h"

#define SSH_DEBUG_MODULE "SshPmUtilIke"

/*-----------------------------------------------------------------------*/
/* Notify callbacks for ssh_ikev2_ike_sa_delete().                       */
/*-----------------------------------------------------------------------*/

void pm_ike_sa_delete_done_callback(SshSADHandle sad_handle,
                                    SshIkev2Sa sa,
                                    SshIkev2ExchangeData ed,
                                    SshIkev2Error error)
{
    SshPmP1 p1 = (SshPmP1) sa;

    if (p1 != NULL)
      p1->initiator_ops[PM_IKE_INITIATOR_OP_DELETE] = NULL;




    if (ed != NULL)
    {
        if (p1 && p1->n && (error == SSH_IKEV2_ERROR_OK))
        {
            /* Wake up the thread controlling this negotiation.  We do this
               both for initiator and responder case. */
            SSH_DEBUG(SSH_D_LOWOK, ("Waking up Phase-1 thread"));
            p1->done = 1;
            p1->failed = 1;
            ssh_fsm_continue(&p1->n->thread);
        }
    }

    SSH_DEBUG(SSH_D_LOWSTART,  ("IKE SA delete done callback, ike error %s",
                                ssh_ikev2_error_to_string(error)));
}

/* Notify callback for ssh_ikev2_ike_sa_delete(). If 'error' indicates that
   the sending of delete notification failed, then this function will call
   ssh_ikev2_ike_sa_delete() with SSH_IKEV2_IKE_DELETE_FLAGS_NO_NOTIFICATION
   to delete the IKE SA. */
void pm_ike_sa_delete_notification_done_callback(SshSADHandle sad_handle,
                                                 SshIkev2Sa sa,
                                                 SshIkev2ExchangeData ed,
                                                 SshIkev2Error error)
{
    SshPmP1 p1 = (SshPmP1) sa;

    if (p1 != NULL)
      p1->initiator_ops[PM_IKE_INITIATOR_OP_DELETE] = NULL;

    switch (error)
    {
      case SSH_IKEV2_ERROR_WINDOW_FULL:
        /* IKE SA was not deleted because sending of SA delete
           notification failed. Redelete IKE SA with
           SSH_IKEV2_IKE_DELETE_FLAGS_NO_NOTIFICATION */

        if (p1)
        {
            SSH_PM_IKEV2_IKE_SA_DELETE(
                    p1,
                    SSH_IKEV2_IKE_DELETE_FLAGS_NO_NOTIFICATION,
                    pm_ike_sa_delete_done_callback);
        }
        break;

      default:
        /* Complete SA deletion */
        pm_ike_sa_delete_done_callback(sad_handle, sa, ed, error);
        break;
    }
}


/*-----------------------------------------------------------------------*/
/* Sending delete notifications                                          */
/*-----------------------------------------------------------------------*/

/* Internal utility function for sending out IPsec delete notifications.
   This returns the success of the operation using SshIkev2Error (for
   conviniency). */
static SshIkev2Error
pm_p1_send_ipsec_delete_notifications(SshPm pm,
                                      SshPmP1 p1,
                                      uint32_t num_esp_spis,
                                      uint32_t *esp_spis,
                                      uint32_t num_ah_spis,
                                      uint32_t *ah_spis,
                                      SshIkev2NotifyCB callback,
                                      void *ed_application_context)
{
    SshIkev2ExchangeData ed = NULL;
    int slot;

    SSH_PM_ASSERT_P1(p1);

    SSH_DEBUG(SSH_D_LOWOK,
              ("Sending delete notification for %d ESP, %d AH SPIs",
               (int) num_esp_spis, (int) num_ah_spis));

    if ((num_esp_spis + num_ah_spis) == 0)
      return SSH_IKEV2_ERROR_INVALID_ARGUMENT;

    if (!pm_ike_async_call_possible(p1->ike_sa, &slot))
    {
        SSH_DEBUG(SSH_D_NICETOKNOW,
                  ("Cannot use this IKE SA for sending delete notify"));
        return SSH_IKEV2_ERROR_WINDOW_FULL;
    }

    ed = ssh_ikev2_info_create(p1->ike_sa, 0);
    if (ed == NULL)
    {
        SSH_DEBUG(SSH_D_NICETOKNOW,
                  ("Could not allocate exchange data for sending delete "
                   "notifications"));
        goto error;
    }

    ed->application_context = ed_application_context;

    if (num_esp_spis > 0)
    {
        if (ssh_ikev2_info_add_delete(ed, SSH_IKEV2_PROTOCOL_ID_ESP,
                                      num_esp_spis, esp_spis, 0)
            != SSH_IKEV2_ERROR_OK)
          goto error;
    }

    if (num_ah_spis > 0)
    {
        if (ssh_ikev2_info_add_delete(ed, SSH_IKEV2_PROTOCOL_ID_AH,
                                      num_ah_spis, ah_spis, 0)
            != SSH_IKEV2_ERROR_OK)
          goto error;
    }

    PM_IKE_ASYNC_CALL(p1->ike_sa, ed, slot, ssh_ikev2_info_send(ed, callback));

    return SSH_IKEV2_ERROR_OK;

   error:
    SSH_DEBUG(SSH_D_NICETOKNOW, ("failed"));
    if (ed != NULL)
      ssh_ikev2_info_destroy(ed);
    return SSH_IKEV2_ERROR_OUT_OF_MEMORY;
}

/* Either p1 or tunnel, rule, dst and port. Note that p1 may be unusable.
   If p1 is not given, then p1 lookup (using tunnel, rule and dst) will
   ignore unusable p1's. This expects that PM is not suspended. */
void
ssh_pm_send_ipsec_delete_notification(
        SshPm pm,
        uint32_t peer_handle,
        SshPmTunnel tunnel,
        SshPmRule rule,
        SshInetIPProtocolID ipproto,
        uint32_t inbound_spi)
{
    SshPmPeer peer;
    SshPmP1 p1;
    int slot;
    SshPmStatus pm_status;

    if (ipproto != SSH_IPPROTO_AH && ipproto != SSH_IPPROTO_ESP)
    {
        SSH_DEBUG(SSH_D_NICETOKNOW,
                  ("Cannot send delete notification for IP protocol %d",
                   (int) ipproto));
        return;
    }

    /* Lookup peer. */
    peer = ssh_pm_peer_by_handle(pm, peer_handle);
    if (peer == NULL)
    {
        SSH_DEBUG(SSH_D_NICETOKNOW,
                  ("No peer object found for peer handle 0x%lx",
                   (unsigned long) peer_handle));
        return;
    }

    /* Fetch IKE SA for peer. */
    p1 = ssh_pm_p1_by_peer_handle(pm, peer_handle);

    /* Check PM status. When PM is shutting down there is no need to send
       delete notifications for IKEv2 SAs because the IKEv2 SA is going to
       be deleted very soon. However for IKEv1 we want to send the IPsec
       delete notification. */
    pm_status = ssh_pm_get_status(pm);
    if (pm_status == SSH_PM_STATUS_DESTROYED
#ifdef SSHDIST_IKEV1
        && (p1 == NULL
            || (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1) ==
            0)
#endif /* SSHDIST_IKEV1 */
        )
    {
        SSH_DEBUG(SSH_D_NICETOKNOW,
                  ("Cannot send delete notification, pm shutting down"));
        return;
    }

    /* If there is no IKE SA or IKE SA is marked unusable, try to find
       a more usable IKE SA. */
    if (p1 == NULL || p1->unusable)
    {
        if (rule != NULL && tunnel != NULL && peer != NULL)
        {
            /* Lookup a matching usable IKE SA. */
            p1 = ssh_pm_lookup_p1(pm, rule, tunnel, peer_handle, NULL, NULL,
                                  true);
            if (p1 == NULL || p1->unusable)
            {
                /* Fallback to using the possibly unusable IKE SA. */
                p1 = ssh_pm_p1_by_peer_handle(pm, peer_handle);
            }
        }
    }

    if (p1 == NULL)
    {
        SSH_DEBUG(SSH_D_NICETOKNOW,
                  ("No IKE SA to protect IPsec SPI delete notify"));
        return;
    }
    SSH_PM_ASSERT_P1(p1);

    /* Check if IKE window is full and request delayed delete notification
       if so. Also if we are suspended or suspending, request delayed delete
       notification. */
    if (!pm_ike_async_call_possible(p1->ike_sa, &slot)
        || pm_status == SSH_PM_STATUS_SUSPENDING
        || pm_status == SSH_PM_STATUS_SUSPENDED)
    {
        SSH_DEBUG(
                SSH_D_NICETOKNOW,
                ("Cannot use this IKE SA for sending IPsec SPI delete notify, "
                 "requesting delayed IPsec delete notification."));

        ssh_pm_request_ipsec_delete_notification(pm, p1, ipproto, inbound_spi);
        return;
    }

    if (ipproto == SSH_IPPROTO_ESP)
    {
        pm_p1_send_ipsec_delete_notifications(pm, p1, 1, &inbound_spi, 0, NULL,
                                              pm_ike_info_done_callback, NULL);
    }
    else if (ipproto == SSH_IPPROTO_AH)
    {
        pm_p1_send_ipsec_delete_notifications(pm, p1, 0, NULL, 1, &inbound_spi,
                                              pm_ike_info_done_callback, NULL);
    }
}


/****************** Delayed delete notification requests ********************/

static void
pm_free_ipsec_delete_notification_reqs(SshPmIPsecDeleteNotificationRequest n)
{
    SshPmIPsecDeleteNotificationRequest n_next;

    while (n != NULL)
    {
        n_next = n->next;
        ssh_free(n);
        n = n_next;
    }
}

void
ssh_pm_free_ipsec_delete_notification_requests(SshPmP1 p1)
{
    SSH_PM_ASSERT_P1(p1);
    pm_free_ipsec_delete_notification_reqs(p1->delete_notification_requests);
    p1->delete_notification_requests = NULL;
}

/* Internal utility function for sending the delayed delete notification
   requests from a zero timeout. */
static void
pm_send_ipsec_delete_notification_requests(void *context)
{
    SshPmP1 p1 = context;
    SshPmIPsecDeleteNotificationRequest delete_notification_requests;
    SshPmIPsecDeleteNotificationRequest n;
    SshPmIPsecDeleteNotificationRequest n_next;
    uint32_t esp_spis[10];
    uint32_t ah_spis[10];
    uint8_t num_esp_spis = 0;
    uint8_t num_ah_spis = 0;
    SshPmStatus status;

    SSH_PM_ASSERT_P1(p1);

    /* If the pm is suspended / suspending, these
       messages will be handled after suspend ends. */
    status = ssh_pm_get_status(p1->pm);
    if (status == SSH_PM_STATUS_SUSPENDING ||
        status == SSH_PM_STATUS_SUSPENDED)
      goto out;

    /* If there are no delete notification requests then check if the IKE SA
       is childless and delete the SA if necessary. */
    if (p1->delete_notification_requests == NULL
        && p1->delete_childless_sa == 1)
    {
        pm_ike_delete_childless_p1(p1->pm, p1);
        goto out;
    }

    delete_notification_requests = p1->delete_notification_requests;
    for (n = delete_notification_requests; n != NULL; n = n_next)
    {
        n_next = n->next;

        if (n->ipproto == SSH_IPPROTO_ESP)
          esp_spis[num_esp_spis++] = n->spi;
        else if (n->ipproto == SSH_IPPROTO_AH)
          ah_spis[num_ah_spis++] = n->spi;
        else
          SSH_NOTREACHED;

        /* Send delete notification if maximum number of SPIs per delete
           notification is reached, or if this is the last SPI delete
           request. */
        if (n->next == NULL || ((num_esp_spis + num_ah_spis) == 10))
        {
            p1->delete_notification_requests = n_next;

            if (pm_p1_send_ipsec_delete_notifications(
                        p1->pm, p1,
                        num_esp_spis, esp_spis,
                        num_ah_spis, ah_spis,
                        pm_ike_info_done_callback,
                        NULL)

                == SSH_IKEV2_ERROR_WINDOW_FULL)
            {
                /* Put requests back in the list for later processing. */
                p1->delete_notification_requests =
                    delete_notification_requests;
                goto out;
            }

            /* Free processed requests. */
            n->next = NULL;
            pm_free_ipsec_delete_notification_reqs(
                    delete_notification_requests);

            if (p1->delete_notification_requests == NULL)
            {
                /* Break immediately since pm_ike_info_done_callback() may
                   have been directly called on failure case and rest
                   delete_notification_requests may have been freed from p1
                   making n and n_next invalid. */
                break;
            }

            num_esp_spis = 0;
            num_ah_spis = 0;
            delete_notification_requests = p1->delete_notification_requests;
        }
    }

    /* Assert that all requests were processed. */
    SSH_ASSERT(p1->delete_notification_requests == NULL);

   out:
    SSH_PM_IKE_SA_FREE_REF(p1->pm->sad_handle, p1->ike_sa);
}

void
ssh_pm_send_ipsec_delete_notification_requests(SshPm pm, SshPmP1 p1)
{
    SSH_PM_ASSERT_P1(p1);

    /* Send delete notifications from a zero timeout. Take a reference to
       protect the p1 from disappearing. */
    SSH_PM_IKE_SA_TAKE_REF(p1->ike_sa);
    if (ssh_register_timeout(NULL, 0, 0,
                             pm_send_ipsec_delete_notification_requests, p1)
        == NULL)
    {
        /* Could not send delete notifications. Free any pending delete
           notification requests and let ike_sa_timer() take care of
           deleting childless IKE SAs. */
        SSH_DEBUG(
                SSH_D_FAIL,
                ("Failed to send delayed delete notifications for p1 %p",
                 p1));

        ssh_pm_free_ipsec_delete_notification_requests(p1);
        SSH_PM_IKE_SA_FREE_REF(pm->sad_handle, p1->ike_sa);
    }
}

/* Register a delayed delete notification request. */
bool
ssh_pm_request_ipsec_delete_notification(SshPm pm,
                                         SshPmP1 p1,
                                         SshInetIPProtocolID ipproto,
                                         uint32_t spi)
{
    SshPmIPsecDeleteNotificationRequest n;

    SSH_PM_ASSERT_P1(p1);

    if (ipproto != SSH_IPPROTO_AH && ipproto != SSH_IPPROTO_ESP)
    {
        SSH_DEBUG(SSH_D_NICETOKNOW,
                  ("Cannot send delete notification for IP protocol '%@' (%d)",
                   ssh_ipproto_render, (uint32_t) ipproto,
                   (int) ipproto));
        return false;
    }

    /* Allocate a delayed delete notification request. */
    n = ssh_calloc(1, sizeof(*n));
    if (n == NULL)
    {
        SSH_DEBUG(SSH_D_NICETOKNOW,
                  ("Failed to allocate delete notification request for SPI "
                   "%@-%08lx",
                   ssh_ipproto_render, (uint32_t) ipproto,
                   (unsigned long) spi));
        return false;
    }

    n->ike_sa_handle = SSH_PM_IKE_SA_INDEX(p1);
    n->spi = spi;
    n->ipproto = ipproto;

    /* Add request to p1. */
    n->next = p1->delete_notification_requests;
    p1->delete_notification_requests = n;

    /* If policymanager is suspended, then add IKE SA to resume queue so that
       delete notifications will get sent on policymanager resume. */
    if (!p1->in_resume_queue
        && (ssh_pm_get_status(pm) == SSH_PM_STATUS_SUSPENDED
            || ssh_pm_get_status(pm) == SSH_PM_STATUS_SUSPENDING))
    {
        p1->resume_queue_next = pm->resume_queue;
        p1->in_resume_queue = 1;
        pm->resume_queue = p1;
    }

    SSH_DEBUG(SSH_D_NICETOKNOW,
              ("Added delayed delete notification for p1 %p for SPI %@-%08lx",
               p1,
               ssh_ipproto_render, (uint32_t) ipproto,
               (unsigned long) spi));

    return true;
}


/************************** Invalidating old inbound SPIs ********************/

/* This internal utility function deletes all IPsec SAs and IKE SAs with
   peer identified by `peer_handle'. On immediate error this returns false.
   Otherwise this starts deleting the IPsec SAs and returns true. Note that
   the deletion completes asynchronously sometime after this function call
   has returned. */
static bool
pm_delete_sas_by_peer_handle(SshPm pm, uint32_t peer_handle)
{

  MonotonicTime expire_time;
  SshPmP1 p1;
  SshPmPeer peer;
  SshPmStatus pm_status;

  expire_time =
      monotonic_time_get() +
      SSH_PM_IKE_EXPIRE_TIMER_SECONDS;

  /* We have a reference to the IKE peer to make sure it does not disappear. */
  peer = ssh_pm_peer_by_handle(pm, peer_handle);
  SSH_ASSERT(peer != NULL);

  peer->deleting = 1;

  SSH_DEBUG(SSH_D_LOWOK, ("Deleting IPsec SAs by peer handle 0x%lx",
                          (unsigned long) peer_handle));

  /* The IKE SA is deleted in the callback. */
  ipsec_sa_destroy_all_by_peer_handle(pm->ipsec_control, peer_handle);

  /* Check if the IKE SA has been freed */
  p1 = ssh_pm_p1_from_ike_handle(pm, peer->ike_sa_handle, false);
  if (p1 == NULL || SSH_PM_P1_DELETED(p1))
    {
      SSH_DEBUG(SSH_D_HIGHOK, ("IKE SA is already deleted"));
      return true;
    }

  /* Mark that the childless IKE SA should be freed. */
  p1->delete_childless_sa = 1;

  /* Send out pending IPsec delete notification requests. */
  pm_status = ssh_pm_get_status(pm);
  if (pm_status == SSH_PM_STATUS_ACTIVE
      || pm_status == SSH_PM_STATUS_DESTROYED)
    {
      ssh_pm_send_ipsec_delete_notification_requests(pm, p1);
    }

  /* In suspended / suspending pm status, just make sure IKE SA
     won't live too long. */
  else
    {
      /* Manually set the expire_time, so that the IKE SA gets
         deleted in near future in case the sending of IPsec SPI delete
         notification fails. */
      if ((p1->expire_time > expire_time) && !SSH_PM_P1_DELETED(p1))
        {
          SSH_DEBUG(SSH_D_MIDOK,
                    ("Marking IKE SA %p for deletion", p1->ike_sa));

          p1->expire_time = expire_time;
        }
    }

  return true;
}

/************ Deleting IPsec SAs due to notification from other end *********/

uint32_t
ssh_pm_delete_by_spi(
        SshPm pm,
        uint32_t spi,
        SshVriId routing_instance_id,
        uint8_t ipproto,
        const SshIpAddr remote_ip,
        uint16_t remote_ike_port)
{
    uint32_t inbound_spi = 0;
    struct InAddr remote_ip_inaddr;

    in_addr_convert_from_sshipaddr(
            &remote_ip_inaddr,
            remote_ip);

    /* Lookup inbound SPI. */
    inbound_spi =
        ipsec_sa_find_by_outbound_spi(
                pm->ipsec_control,
                true,
                spi,
                ipproto,
                &remote_ip_inaddr,
                remote_ike_port);

    if (inbound_spi != 0)
    {
        SSH_DEBUG(
                SSH_D_HIGHOK,
                ("Deleting IPsec SA "
                 "SPI %@-%08lx inbound SPI %@-%08lx",
                 ssh_ipproto_render,
                 (uint32_t) ipproto,
                 (unsigned long) spi,
                 ssh_ipproto_render,
                 (uint32_t) ipproto,
                 (unsigned long) inbound_spi));

        ipsec_sa_delete(pm->ipsec_control, inbound_spi);


        /* Indicate that this IPsec SA has been destroyed. */
        /* XXX check disable_sa_events */
        ssh_pm_ipsec_sa_event_deleted(
                pm,
                spi,
                inbound_spi,
                ipproto);
    }

    return inbound_spi;
}

/****************** Initial contact notification processing *****************/

/* The number of seconds an IKE SA is considered to be recently negotiated */
#define SSH_PM_IKE_SA_NEW_LIFETIME 3

/* Process initial contact notification from peer.
   This function is called before SA installation on the responder */
void
ssh_pm_process_initial_contact_notification(SshPm pm, SshPmP1 peer_p1)
{
    SshPmP1 p1, next_p1;
    SshPmPeer peer, next_peer;
    uint32_t hash, peer_handle;
    MonotonicTime current_time;
    uint32_t flags = 0;

    if (ssh_pm_get_status(pm) == SSH_PM_STATUS_DESTROYED)
      return;

    SSH_PM_ASSERT_P1(peer_p1);

    SSH_DEBUG(SSH_D_NICETOKNOW,
              ("Initial contact notification from %@:%d ID %@ "
               "routing instance id %d",
               ssh_ipaddr_render, peer_p1->ike_sa->remote_ip,
               peer_p1->ike_sa->remote_port,
               ssh_pm_ike_id_render, peer_p1->remote_id,
               peer_p1->ike_sa->server->routing_instance_id));

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
    if (peer_p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_THIS_END_BEHIND_NAT ||
        peer_p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_OTHER_END_BEHIND_NAT)
    {
        if (peer_p1->remote_id->id_type == SSH_IKEV2_ID_TYPE_IPV4_ADDR ||
            peer_p1->remote_id->id_type == SSH_IKEV2_ID_TYPE_IPV6_ADDR)
        {
            ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_WARNING,
                          "NAT-T initial contact notification with IP "
                          "identity %@",
                          ssh_pm_ike_id_render, peer_p1->remote_id);
            ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_WARNING,
                          "It is recommended to use non-IP identities with "
                          "NAT-T to avoid ID collisions");
        }
    }
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

    /* Delete all IKE SA's (except for `peer_p1') that have the same local
       and remote identities as `peer_p1'.

       Send delete notification to remote end only if the deleted SA is
       reasonably new, and we suspect that the other end might end up
       being out of sync. */
    current_time = monotonic_time_get();

    /* Compute the hash value from IKE remote ID. */
    hash = SSH_PM_IKE_ID_HASH(peer_p1->remote_id);

    for (p1 = pm->ike_sa_id_hash[hash]; p1; p1 = next_p1)
    {
        next_p1 = p1->hash_id_next;

        /* Do not delete 'p1' */
        if (peer_p1 == p1)
          continue;

        /* Do not delete SAs from different VRF. */
        if (peer_p1->ike_sa->server->routing_instance_id !=
            p1->ike_sa->server->routing_instance_id)
          continue;

        /* The local identities must agree */
        if (!ssh_pm_ikev2_id_compare(peer_p1->local_id, p1->local_id))
          continue;

        /* The remote identities must agree */
        if (!ssh_pm_ikev2_id_compare(peer_p1->remote_id, p1->remote_id))
          continue;

        /* Deletion is already ongoing. */
        if (SSH_PM_P1_DELETED(p1))
          continue;

        /* Delete immediately all IPsec SA's belonging to this Phase-I. */

        /* If the SA has been negotiated recently, then send a delete
           notification to ensure that both ends are in sync.
           The SA we are deleting might have been negotiated simultaneously
           with the SA that included the initial contact notification. If so,
           then we should make sure that the SA we are deleting does not exist
           in the other end. */
        if ((p1->expire_time - p1->lifetime + SSH_PM_IKE_SA_NEW_LIFETIME) >
            current_time)
        {
            peer_handle = ssh_pm_peer_handle_by_p1(pm, p1);

            /* This IKE SA has no associated IPsec SAs, continue with IKE SA
               deletion. */
            if (peer_handle == SSH_IPSEC_INVALID_INDEX)
              goto delete_ike_sa;

            /* Do not use p1 for new negotiations. */
            p1->unusable = 1;

            /* Start deleting all IPsec SAs and the IKE SA. */
            if (pm_delete_sas_by_peer_handle(pm, peer_handle) == false)
              goto delete_ike_sa;
        }

        /* Old SA, assume the other end has rebooted, and do not bother
           to send a delete notification. */
        else
        {
            flags = SSH_IKEV2_IKE_DELETE_FLAGS_NO_NOTIFICATION;

          delete_ike_sa:
            /* Now delete the IKE SA and child SAs. */
            SSH_DEBUG(SSH_D_MIDOK, ("Deleting the IKE SA %p", p1->ike_sa));

#ifdef SSHDIST_IKEV1
            flags |= SSH_IKEV2_IKE_DELETE_FLAGS_FORCE_DELETE_NOW;
#endif /* SSHDIST_IKEV1 */

            /* Request child SA deletion. */
            p1->delete_child_sas = 1;

            SSH_ASSERT(p1->initiator_ops[PM_IKE_INITIATOR_OP_DELETE] == NULL);
            SSH_PM_IKEV2_IKE_SA_DELETE(p1, flags,
                                       pm_ike_sa_delete_done_callback);
        }
    }

    /* Delete IPsec SAs, that have no parent IKEv1 SA. */
    for (peer = ssh_pm_peer_by_ike_sa_handle(pm, SSH_IPSEC_INVALID_INDEX);
         peer != NULL;
         peer = next_peer)
    {
        SSH_ASSERT(peer->ike_sa_handle == SSH_IPSEC_INVALID_INDEX);
        next_peer = ssh_pm_peer_next_by_ike_sa_handle(pm, peer);

        /* Do not delete SAs from different VRF. */
        if (peer_p1->ike_sa->server->routing_instance_id !=
            peer->routing_instance_id)
          continue;


        /* Use IP addresses if no identity information is present in
           the peer */
        if (!peer->local_id || !peer->remote_id)
        {
            if (SSH_IP_CMP(peer->remote_ip, peer_p1->ike_sa->remote_ip)
                || peer->remote_port != peer_p1->ike_sa->remote_port)
              continue;

            if (SSH_IP_CMP(peer->local_ip, peer_p1->ike_sa->server->ip_address)
                || peer->local_port !=
                SSH_PM_IKE_SA_LOCAL_PORT(peer_p1->ike_sa))
              continue;
        }
        else
        {
            /* The local identities must agree */
            if (!ssh_pm_ikev2_id_compare(peer->local_id, peer_p1->local_id))
              continue;

            /* The remote identities must agree */
            if (!ssh_pm_ikev2_id_compare(peer->remote_id, peer_p1->remote_id))
              continue;
        }

        /* Do not send delete notifications, as there is no IKE SA. */
        ipsec_sa_destroy_all_by_peer_handle(
                pm->ipsec_control,
                peer->peer_handle);
    }
}

/******************  Deletion of SAs by remote ID ***************************/

void
ssh_pm_delete_by_remote_id(SshPm pm,
                           SshIkev2PayloadID remote_id,
                           uint32_t flags)
{
    SshPmP1 p1;
    SshPmP1 next_p1;
    SshPmPeer peer;
    SshPmPeer next_peer;
    uint32_t hash;

    if (ssh_pm_get_status(pm) == SSH_PM_STATUS_DESTROYED)
      return;

    SSH_DEBUG(SSH_D_NICETOKNOW,
              ("Deleting SAs by remote ID %@",
               ssh_pm_ike_id_render, remote_id));

    /* Check ongoing IKE SA negotiations. */
    for (p1 = pm->active_p1_negotiations; p1 != NULL; p1 = next_p1)
    {
        SshIkev2PayloadID p1_remote_id;

        next_p1 = p1->n->next;

        /* Dig out the remote IKE ID from the exchange data. */
        if (p1->n->ed == NULL || p1->n->ed->ike_ed == NULL)
          continue;

        if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR)
          p1_remote_id = p1->n->ed->ike_ed->id_r;
        else
          p1_remote_id = p1->n->ed->ike_ed->id_i;

        /* If remote IKE ID has been received then check if it matches
          the given remote IKE ID. */
        if (p1_remote_id != NULL
            && ssh_pm_ikev2_id_compare(remote_id, p1_remote_id))
        {
            SSH_DEBUG(SSH_D_NICETOKNOW, ("Marking IKE SA %p unusable",
                                         p1->ike_sa));

            /* Mark p1 unusable and request child SA deletion. The IKE SA
               will be deleted right after the negotiation completes.
               See ssh_pm_ike_sa_done(). */
            p1->unusable = 1;
            p1->delete_child_sas = 1;
        }
    }

    /* Delete all IKE SA's that have the same remote identities as
       `remote_id'. */

    /* Compute the hash value from IKE remote ID. */
    hash = SSH_PM_IKE_ID_HASH(remote_id);

    for (p1 = pm->ike_sa_id_hash[hash]; p1; p1 = next_p1)
    {
        uint32_t tmp_flags;

        next_p1 = p1->hash_id_next;

        /* The remote identities must agree */
        if (!ssh_pm_ikev2_id_compare(remote_id, p1->remote_id))
          continue;

        /* Deletion is already ongoing. */
        if (SSH_PM_P1_DELETED(p1))
          continue;

        /* Delete immediately all IPsec SA's belonging to this Phase-I. */

        /* Copy flags */
        tmp_flags = flags;

#ifdef SSHDIST_IKEV1
        /* Send a delete notification if caller requests it.
           Otherwise make deletion silently. */
        if ((p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1) != 0
            && (tmp_flags & SSH_IKEV2_IKE_DELETE_FLAGS_NO_NOTIFICATION) == 0)
        {
            uint32_t peer_handle;

            peer_handle = ssh_pm_peer_handle_by_p1(pm, p1);

            /* This IKE SA has no associated IPsec SAs, continue with IKE SA
               deletion. */
            if (peer_handle == SSH_IPSEC_INVALID_INDEX)
              goto delete_ike_sa;

            /* Do not use p1 for new negotiations. */
            p1->unusable = 1;

            /* Start deleting all IPsec SAs and the IKE SA. */
            if (pm_delete_sas_by_peer_handle(pm, peer_handle) == false)
            {
                /* Don't send notification in failure case. */
                tmp_flags |= SSH_IKEV2_IKE_DELETE_FLAGS_NO_NOTIFICATION;
                goto delete_ike_sa;
            }
        }
        else
#endif /* SSHDIST_IKEV1 */
        {
#ifdef SSHDIST_IKEV1
          delete_ike_sa:
#endif /* SSHDIST_IKEV1 */
            /* Now delete the IKE SA and child SAs. */
            SSH_DEBUG(SSH_D_MIDOK, ("Deleting the IKE SA %p", p1->ike_sa));

#ifdef SSHDIST_IKEV1
            tmp_flags |= SSH_IKEV2_IKE_DELETE_FLAGS_FORCE_DELETE_NOW;
#endif /* SSHDIST_IKEV1 */

            /* Request child SA deletion. */
            p1->delete_child_sas = 1;

            SSH_ASSERT(p1->initiator_ops[PM_IKE_INITIATOR_OP_DELETE] == NULL);
            SSH_PM_IKEV2_IKE_SA_DELETE(p1, tmp_flags,
                                       pm_ike_sa_delete_done_callback);
        }
    }

    /* Delete IPsec SAs, that have no parent IKEv1 SA. */
    for (peer = ssh_pm_peer_by_ike_sa_handle(pm, SSH_IPSEC_INVALID_INDEX);
         peer != NULL;
         peer = next_peer)
    {
        SSH_ASSERT(peer->ike_sa_handle == SSH_IPSEC_INVALID_INDEX);
        next_peer = ssh_pm_peer_next_by_ike_sa_handle(pm, peer);

        /* The remote identities must agree */
        if (!ssh_pm_ikev2_id_compare(remote_id, peer->remote_id))
          continue;

        /* Do not send delete notifications, as there is no IKE SA. */
        ipsec_sa_destroy_all_by_peer_handle(
                pm->ipsec_control,
                peer->peer_handle);
    }
}


/********************** Deletion of SAs by IKE peer handle ******************/















/* Delete all IKE and IPsec SAs with IKE peer `peer_handle'. */
void
ssh_pm_delete_by_peer_handle(SshPm pm, uint32_t peer_handle, uint32_t flags,
                             SshPmStatusCB callback, void *context)
{
    SshPmP1 p1;
    SshPmPeer peer;
    bool sa_deletion_started = false;

    SSH_DEBUG(SSH_D_MIDOK, ("Deleting SAs by peer handle 0x%lx", peer_handle));

    if (peer_handle == SSH_IPSEC_INVALID_INDEX)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Failed: Invalid peer_handle"));
        goto error;
    }

    peer = ssh_pm_peer_by_handle(pm, peer_handle);
    if (peer == NULL)
      goto out;

    p1 = ssh_pm_p1_from_ike_handle(pm, peer->ike_sa_handle, false);
    if (p1 && !SSH_PM_P1_DELETED(p1))
    {
        /* Delete IKE SAs, the child SAs will be deleted automatically */
        p1->delete_child_sas = 1;

        sa_deletion_started = true;

#ifdef SSHDIST_IKEV1
        /* IKEv1 SA needs special handling. */
        if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
        {
            /* Do not use p1 for new negotiations. */
            p1->unusable = 1;

            if (flags & SSH_IKEV2_IKE_DELETE_FLAGS_NO_NOTIFICATION)
            {
                /* Do not send delete notifications. */
              ipsec_sa_destroy_all_by_peer_handle(
                      pm->ipsec_control,
                      peer_handle);
              goto delete_ike_sa;
            }
            else
            {
                /* Start deleting the IPsec SAs and the IKE SA. */
                if (pm_delete_sas_by_peer_handle(pm, peer_handle) == false)
                  goto delete_ike_sa;
            }
        }
        else /* IKEv2 SA's can just be deleted. */
#endif /* SSHDIST_IKEV1 */
        {
#ifdef SSHDIST_IKEV1
          delete_ike_sa:
#endif /* SSHDIST_IKEV1 */
            SSH_DEBUG(SSH_D_LOWOK, ("Deleting the IKE SA %p", p1->ike_sa));

#ifdef SSHDIST_IKEV1
            flags |= SSH_IKEV2_IKE_DELETE_FLAGS_FORCE_DELETE_NOW;
#endif /* SSHDIST_IKEV1 */

            SSH_ASSERT(p1->initiator_ops[PM_IKE_INITIATOR_OP_DELETE] == NULL);
            SSH_PM_IKEV2_IKE_SA_DELETE(
                    p1, flags,
                    ((flags & SSH_IKEV2_IKE_DELETE_FLAGS_NO_NOTIFICATION) ?
                     pm_ike_sa_delete_done_callback :
                     pm_ike_sa_delete_notification_done_callback));
        }
    }

    /* Delete IPsec SAs, that have no usable parent IKE SA. */
    else
    {
        sa_deletion_started = true;

        /* Do not send delete notifications, as there is no usable IKE SA. */
        ipsec_sa_destroy_all_by_peer_handle(pm->ipsec_control, peer_handle);
    }

   out:
    if (callback)
      (*callback)(pm, sa_deletion_started, context);
    return;

   error:
    if (callback)
      (*callback)(pm, false, context);
}

/********************** Deletion of IPsec SAs on interface change ************/

void
ssh_pm_delete_by_local_address(SshPm pm, SshIpAddr local_ip,
                               SshVriId routing_instance_id)
{
    SshPmPeer peer, next_peer;

    if (local_ip == NULL || !SSH_IP_DEFINED(local_ip))
      return;

    /* Delete IPsec SAs, that have no parent IKE SA */
    for (peer = ssh_pm_peer_by_local_address(pm, local_ip);
         peer != NULL;
         peer = next_peer)
    {
        SSH_ASSERT(SSH_IP_EQUAL(local_ip, peer->local_ip));
        next_peer = ssh_pm_peer_next_by_local_address(pm, peer);

        /* Delete only SAs that belong to the specified VRF. */
        if (peer->routing_instance_id != routing_instance_id)
          continue;

        /* Delete only IKEv1 SA's. IKEv2 keyed child SA's
           are deleted with the IKEv2 SA. */
        if (peer->use_ikev1 == false)
          continue;

        /* Do not send delete notifications, as there is no IKE SA. */
        ipsec_sa_destroy_all_by_peer_handle(
                pm->ipsec_control,
                peer->peer_handle);
    }
}

/********************** Deletion of SAs on PM shutdown ***********************/

/* Delete all IKE and IPsec SAs with peer whose address matches `ip'. */
void
ssh_pm_delete_by_peer(SshPm pm, SshIpAddr ip, uint32_t flags,
                      SshPmStatusCB callback, void *context)
{
    SshPmP1 p1, next_p1;
    uint32_t i;
    SshPmPeer peer, next_peer;
#ifdef SSHDIST_IKEV1
    uint32_t peer_handle;
#endif /* SSHDIST_IKEV1 */
    bool sa_deletion_started = false;
    uint32_t ike_sa_delete_flags;

    SSH_DEBUG(SSH_D_MIDOK, ("Deleting SAs by peer %@", ssh_ipaddr_render, ip));

    if (ip && !SSH_IP_DEFINED(ip))
    {
        SSH_DEBUG(SSH_D_FAIL, ("Failed: Invalid peer ip"));
        goto error;
    }

    /* Delete IKE SAs, the child SAs will be deleted automatically */
    for (i = 0; i < SSH_PM_IKE_SA_HASH_TABLE_SIZE; i++)
    {
        for (p1 = pm->ike_sa_hash[i]; p1; p1 = next_p1)
        {
            next_p1 = p1->hash_next;

            /* IKE peer address does not match. */
            if (ip != NULL && !SSH_IP_EQUAL(p1->ike_sa->remote_ip, ip))
              continue;

            sa_deletion_started = true;

            /* IKE SA is already deleted. */
            if (SSH_PM_P1_DELETED(p1))
              continue;

            /* Request child SA deletion also. */
            p1->delete_child_sas = 1;

#ifdef SSHDIST_IKEV1
            /* IKEv1 SA needs special handling. */
            if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
            {
                peer_handle = ssh_pm_peer_handle_by_p1(pm, p1);

                /* This IKE SA has no associated IPsec SAs, continue with
                   IKE SA deletion. */
                if (peer_handle == SSH_IPSEC_INVALID_INDEX)
                  goto delete_ike_sa;

                /* Do not use p1 for new negotiations. */
                p1->unusable = 1;

                if (flags & SSH_IKEV2_IKE_DELETE_FLAGS_NO_NOTIFICATION)
                {
                    /* Do not send delete notifications. */
                    ipsec_sa_destroy_all_by_peer_handle(
                            pm->ipsec_control,
                            peer_handle);
                    goto delete_ike_sa;
                }
                else
                {
                    /* Start deleting all IPsec SAs and the IKE SA. */
                    if (pm_delete_sas_by_peer_handle(pm, peer_handle) == false)
                      goto delete_ike_sa;
                }
            }

            /* IKEv2 SA's can just be deleted. */
            else
#endif /* SSHDIST_IKEV1 */
            {
#ifdef SSHDIST_IKEV1
              delete_ike_sa:
#endif /* SSHDIST_IKEV1 */
                SSH_DEBUG(SSH_D_LOWOK, ("Deleting the IKE SA %p", p1->ike_sa));

                ike_sa_delete_flags = flags;
#ifdef SSHDIST_IKEV1
                ike_sa_delete_flags |=
                  SSH_IKEV2_IKE_DELETE_FLAGS_FORCE_DELETE_NOW;
#endif /* SSHDIST_IKEV1 */
                SSH_ASSERT(p1->initiator_ops[PM_IKE_INITIATOR_OP_DELETE]
                           == NULL);
                SSH_PM_IKEV2_IKE_SA_DELETE(
                        p1, ike_sa_delete_flags,
                        ((flags & SSH_IKEV2_IKE_DELETE_FLAGS_NO_NOTIFICATION) ?
                         pm_ike_sa_delete_done_callback :
                         pm_ike_sa_delete_notification_done_callback));
            }
        }
    }

    /* Delete IPsec SAs, that have no parent IKEv1 SA. */
    for (peer = ssh_pm_peer_by_ike_sa_handle(pm, SSH_IPSEC_INVALID_INDEX);
         peer != NULL;
         peer = next_peer)
    {
        SSH_ASSERT(peer->ike_sa_handle == SSH_IPSEC_INVALID_INDEX);
        next_peer = ssh_pm_peer_next_by_ike_sa_handle(pm, peer);

        /* IKE peer address does not match. */
        if (ip != NULL && !SSH_IP_EQUAL(peer->remote_ip, ip))
          continue;

        sa_deletion_started = true;

        /* Do not send delete notifications, as there is no IKE SA. */
        ipsec_sa_destroy_all_by_peer_handle(
                pm->ipsec_control,
                peer->peer_handle);
    }

    if (callback)
      (*callback)(pm, sa_deletion_started, context);

    return;

   error:
    if (callback)
      (*callback)(pm, false, context);
}























