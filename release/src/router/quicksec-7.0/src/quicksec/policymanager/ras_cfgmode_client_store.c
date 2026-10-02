/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   Storage for active IKE configuration mode clients.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"

#define SSH_DEBUG_MODULE "SshPmCfgmodeClientStore"

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
#ifdef SSHDIST_ISAKMP_CFG_MODE


#define SSH_PM_CFGMODE_CLIENT_HASH(peer_handle) \
  ((peer_handle) % SSH_PM_CFGMODE_CLIENT_HASH_TABLE_SIZE)

static void
pm_cfgmode_client_store_timed_renew(void *context);

/************ Public function to manipulate CFGMODE client store ************/

bool
ssh_pm_cfgmode_client_store_init(SshPm pm)
{
    int i;

    for (i = 0; i < SSH_PM_MAX_CONFIG_MODE_CLIENTS; i++)
    {
        SshPmActiveCfgModeClient client = ssh_malloc(sizeof(*client));

        if (client == NULL)
        {
            SSH_DEBUG(SSH_D_ERROR, ("Could not allocate client structures"));
            ssh_pm_cfgmode_client_store_uninit(pm);
            return false;
        }
        client->peer_handle = SSH_IPSEC_INVALID_INDEX;
        client->next = pm->cfgmode_clients_freelist;
        pm->cfgmode_clients_freelist = client;
    }

    return true;
}


void
ssh_pm_cfgmode_client_store_uninit(SshPm pm)
{
    int i, j;
    SshPmActiveCfgModeClient client;

    /* Free hash table. */
    for (i = 0; i < SSH_PM_CFGMODE_CLIENT_HASH_TABLE_SIZE; i++)
    {
        while (pm->cfgmode_clients_hash[i])
        {
            client = pm->cfgmode_clients_hash[i];

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
#ifdef SSHDIST_RADIUS
            /* Call radius accounting to stop if it was on. */
            pm_ras_radius_acct_stop(pm, client);
#endif /* SSHDIST_RADIUS */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */

            pm->cfgmode_clients_hash[i] = client->next;

            ssh_cancel_timeout(&client->lease_renewal_timer);

            /* Release IP address. */
            for (j = 0; j < client->num_addresses; j++)
            {
                if (client->addresses[j])
                {
                    (*client->free_cb)(pm, client->addresses[j],
                                       client->address_context,
                                       client->ras_cb_context);
                    ssh_free(client->addresses[j]);
                }
            }

            ssh_free(client);
        }
    }

    /* Free freelist. */
    while (pm->cfgmode_clients_freelist)
    {
        client = pm->cfgmode_clients_freelist;
        pm->cfgmode_clients_freelist = client->next;

        ssh_free(client);
    }
}

SshPmActiveCfgModeClient
ssh_pm_cfgmode_client_store_alloc(SshPm pm, SshPmP1 p1)
{
    SshPmActiveCfgModeClient client;
    uint32_t hash, peer_handle;

    /* Check if there are free cfgmode_clients left. */
    if (pm->cfgmode_clients_freelist == NULL)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Out of cgmode_clients"));
        return NULL;
    }

    /* Lookup IKE peer entry. */
    peer_handle = ssh_pm_peer_handle_by_p1(pm, p1);
    if (peer_handle == SSH_IPSEC_INVALID_INDEX)
    {
        /* On success the created peer has been initialized with one
           reference for the p1 (if there was one) and one reference for
           the caller of the function. Use the latter reference to protect
           client->peer_handle. */
        peer_handle =
            ssh_pm_peer_create(
                    pm,
                    p1->tunnel_id,
                    p1->ike_sa->remote_ip,
                    p1->ike_sa->remote_port,
                    p1->ike_sa->server->ip_address,
                    SSH_PM_IKE_SA_LOCAL_PORT(p1->ike_sa),
                    p1,
                    p1->ike_sa->server->routing_instance_id);
        if (peer_handle == SSH_IPSEC_INVALID_INDEX)
        {
            SSH_DEBUG(SSH_D_FAIL, ("Could not create IKE peer for p1 %p", p1));
            return NULL;
        }
    }
    else
    {
        /* Take a reference to protect client->peer_handle. */
        ssh_pm_peer_handle_take_ref(pm, peer_handle);
    }

    /* Allocate client. */
    client = pm->cfgmode_clients_freelist;
    pm->cfgmode_clients_freelist = client->next;

    /* Initialize the client */
    memset(client, 0, sizeof(*client));
    client->pm = pm;
    client->peer_handle = peer_handle;
    client->refcount = 1;
    client->status_cb = NULL_FNPTR;

    /* Link it to the hash table. */
    hash = SSH_PM_CFGMODE_CLIENT_HASH(client->peer_handle);
    client->next = pm->cfgmode_clients_hash[hash];
    pm->cfgmode_clients_hash[hash] = client;

    return client;
}

SshPmActiveCfgModeClient
ssh_pm_cfgmode_client_store_lookup(SshPm pm, uint32_t peer_handle)
{
    uint32_t hash;
    SshPmActiveCfgModeClient c;

    SSH_ASSERT(peer_handle != SSH_IPSEC_INVALID_INDEX);
    hash = SSH_PM_CFGMODE_CLIENT_HASH(peer_handle);
    for (c = pm->cfgmode_clients_hash[hash]; c != NULL; c = c->next)
    {
        if (c->peer_handle == peer_handle)
          return c;
    }
    return NULL;
}

/************** Registering addresses to cfgmode client store ***************/

SshOperationHandle
ssh_pm_cfgmode_client_store_register(SshPm pm,
                                     SshPmTunnel tunnel,
                                     SshPmActiveCfgModeClient client,
                                     SshPmRemoteAccessAttrs attributes,
                                     SshPmRemoteAccessAttrsAllocCB renew_cb,
                                     SshPmRemoteAccessAttrsFreeCB free_cb,
                                     void *ras_cb_context,
                                     SshPmStatusCB status_cb,
                                     void *status_cb_context)
{
    int i = 0;

    SSH_ASSERT(client != NULL);
    SSH_ASSERT(client->status_cb == NULL_FNPTR);

    if (client->state != SSH_PM_CFGMODE_CLIENT_STATE_IDLE)
      goto error;

    client->num_addresses = attributes->num_addresses;
    for (i = 0; i < attributes->num_addresses; i++)
    {
        if (!SSH_IP_DEFINED(&attributes->addresses[i]))
          goto error;

        SSH_DEBUG(SSH_D_LOWOK, ("Registering address `%@'",
                                ssh_ipaddr_render, &attributes->addresses[i]));
        client->addresses[i] = ssh_memdup(&attributes->addresses[i],
                                          sizeof(SshIpAddrStruct));
        if (client->addresses[i] == NULL)
          goto error;
    }
    client->address_context = attributes->address_context;

    client->renew_cb = renew_cb;
    client->free_cb = free_cb;
    client->ras_cb_context = ras_cb_context;
    client->lease_time = attributes->lease_renewal;

    if (client->lease_time > 0)
      ssh_register_timeout(&client->lease_renewal_timer, client->lease_time, 0,
                           pm_cfgmode_client_store_timed_renew, client);

    if (status_cb != NULL_FNPTR)
      (*status_cb)(pm, true, status_cb_context);

    return NULL;

   error:
    for (i = 0; i < client->num_addresses; i++)
    {
        ssh_free(client->addresses[i]);
        client->addresses[i] = NULL;
    }

    if (status_cb != NULL_FNPTR)
      (*status_cb)(pm, false, status_cb_context);

    return NULL;
}


/*************************** Address renewal ********************************/
static void
pm_cfgmode_client_store_timed_renew_status_cb(SshPm pm, bool success,
                                                  void *context)
{
    SshPmActiveCfgModeClient client = (SshPmActiveCfgModeClient) context;

    SSH_DEBUG(SSH_D_LOWOK, ("Client address renewal %s",
                            (success ? "succeeded" : "failed")));

    /* If DHCP lease renewal failed delete IKE and IPsec SAs, otherwise do
       nothing. */
    if (success == false)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Client address renewal failed, releasing"));
        ssh_cancel_timeout(&client->lease_renewal_timer);
        ssh_pm_delete_by_peer_handle(client->pm, client->peer_handle,
                                     0, NULL_FNPTR, NULL);
    }
}

static void
pm_cfgmode_client_store_timed_renew(void *context)
{
    SshPmActiveCfgModeClient client = (SshPmActiveCfgModeClient) context;

    SSH_DEBUG(SSH_D_LOWOK, ("Launching timer invoked address lease renewal."));
    ssh_pm_cfgmode_client_store_renew(
                             client->pm, client,
                             pm_cfgmode_client_store_timed_renew_status_cb,
                             client);

}

static void
pm_cfgmode_client_store_renew_abort(void *context)
{
    SshPmActiveCfgModeClient client = (SshPmActiveCfgModeClient) context;

    SSH_DEBUG(SSH_D_LOWOK, ("Aborting cfgmode client address renewal"));
    SSH_ASSERT(client->state == SSH_PM_CFGMODE_CLIENT_STATE_RENEWING);

    /* Abort the renewal sub operation, mark operation aborted and clear
       status_cb. */
    if (client->sub_operation != NULL)
      ssh_operation_abort(client->sub_operation);
    client->sub_operation = NULL;

    client->status_cb = NULL_FNPTR;
    client->flags |= SSH_PM_CFGMODE_CLIENT_ABORTED;

    /* Release the reference to cfgmode client. */
    SSH_PM_CFGMODE_CLIENT_FREE_REF(client->pm, client);
}

static void
pm_cfgmode_client_store_renew_cb(SshPmRemoteAccessAttrs attributes,
                                 void *context)
{
    SshPmActiveCfgModeClient client = (SshPmActiveCfgModeClient) context;

    /* Renewal sub operation has completed, clear sub operation handle
       and unregister our operation handle. */
    SSH_ASSERT(client->state == SSH_PM_CFGMODE_CLIENT_STATE_RENEWING);

    if (client->sub_operation != NULL
        && (client->flags & SSH_PM_CFGMODE_CLIENT_ABORTED) == 0)
      ssh_operation_unregister_no_free(&client->operation);

    client->sub_operation = NULL;
    client->state = SSH_PM_CFGMODE_CLIENT_STATE_IDLE;

    if (attributes == NULL)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Cfgmode client address renewal failed"));
        if (client->status_cb != NULL_FNPTR)
          (*client->status_cb)(client->pm, false, client->status_cb_context);
        client->status_cb = NULL_FNPTR;
    }
    else
    {
        SSH_DEBUG(SSH_D_NICETOKNOW,
                  ("Cfgmode client address renewal succeeded"));
        client->lease_time = attributes->lease_renewal;
        if (client->status_cb != NULL_FNPTR)
          (*client->status_cb)(client->pm, true, client->status_cb_context);
        client->status_cb = NULL_FNPTR;

        /* Set up a new timeout for lease renewal. */
        if (client->lease_time > 0)
          ssh_register_timeout(&client->lease_renewal_timer,
                               client->lease_time, 0,
                               pm_cfgmode_client_store_timed_renew, client);
    }

    /* Release the reference to cfgmode client. */
    SSH_PM_CFGMODE_CLIENT_FREE_REF(client->pm, client);
}

SshOperationHandle
ssh_pm_cfgmode_client_store_renew(SshPm pm,
                                  SshPmActiveCfgModeClient client,
                                  SshPmStatusCB status_cb,
                                  void *status_cb_context)
{
    SshPmAuthDataStruct ad[1];
    SshPmRemoteAccessAttrsStruct attrs[1];
    SshOperationHandle sub_operation;
    int i;

    if (client->state != SSH_PM_CFGMODE_CLIENT_STATE_IDLE)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Cfgmode client address renewal in progress"));
        if (status_cb != NULL_FNPTR)
          (*status_cb)(pm, false, status_cb_context);
        return NULL;
    }

    if (client->num_addresses == 0)
    {
        SSH_DEBUG(SSH_D_LOWOK, ("No cfgmode client addresses to renew"));
        if (status_cb != NULL_FNPTR)
          (*status_cb)(pm, true, status_cb_context);
        return NULL;
    }

    if (client->renew_cb == NULL_FNPTR)
    {
        SSH_DEBUG(SSH_D_LOWOK, ("No cfgmode client renew callback specified"));
        if (status_cb != NULL_FNPTR)
          (*status_cb)(pm, true, status_cb_context);
        return NULL;
    }

    /* Cancel possible renewal timeouts, the renewal may be invoked by
       IKE rekey as well. */
    ssh_cancel_timeout(&client->lease_renewal_timer);

    /* Lookup p1 for authentication data. */
    memset(ad, 0x0, sizeof(*ad));
    ad->pm = pm;
    ad->p1 = ssh_pm_p1_by_peer_handle(pm, client->peer_handle);
    if (ad->p1 == NULL)
    {
        SSH_DEBUG(SSH_D_FAIL,("No IKE SA found for peer 0x%lx",
                              client->peer_handle));
    }

    /* Create remote access attributes from cfgmode client store
       addresses. */
    memset(&attrs, 0, sizeof(attrs));
    for (i = 0; i < client->num_addresses; i++)
    {
        if (client->addresses[i] != NULL)
        {
            memcpy(
                    &attrs->addresses[attrs->num_addresses],
                    client->addresses[i],
                    sizeof(SshIpAddrStruct));
            attrs->num_addresses++;
        }
    }
    attrs->address_context = client->address_context;

    SSH_ASSERT(attrs->num_addresses > 0);

    /* Take a reference to the client. */
    SSH_PM_CFGMODE_CLIENT_TAKE_REF(pm, client);

    client->status_cb = status_cb;
    client->status_cb_context = status_cb_context;
    client->state = SSH_PM_CFGMODE_CLIENT_STATE_RENEWING;

    /* Call remote access address alloc callback to renew attributes. */
    sub_operation =
      (*client->renew_cb)(pm, ad, SSH_PM_REMOTE_ACCESS_ALLOC_FLAG_RENEW,
                          attrs, pm_cfgmode_client_store_renew_cb, client,
                          client->ras_cb_context);

    /* Renew operation completed synchronously. */
    if (sub_operation == NULL)
      return NULL;

    /* Register an abort callback for the renewal operation. */
    SSH_ASSERT(client->sub_operation == NULL);
    client->sub_operation = sub_operation;

    ssh_operation_register_no_alloc(&client->operation,
                                    pm_cfgmode_client_store_renew_abort,
                                    client);

    return &client->operation;
}


/*********************** Freeing cgfmode client store addresses **************/

static void
pm_cfgmode_client_store_free(SshPm pm, SshPmActiveCfgModeClient client)
{
    int i;

    for (i = 0; i < client->num_addresses; i++)
    {
        if (client->addresses[i] != NULL)
        {
            ssh_free(client->addresses[i]);
            client->addresses[i] = NULL;
        }
    }

    if (client->peer_handle != SSH_IPSEC_INVALID_INDEX)
      ssh_pm_peer_handle_destroy(pm, client->peer_handle);
    client->peer_handle = SSH_IPSEC_INVALID_INDEX;

    client->next = pm->cfgmode_clients_freelist;
    pm->cfgmode_clients_freelist = client;
}

void
ssh_pm_cfgmode_client_store_unreference(SshPm pm,
                                        SshPmActiveCfgModeClient client)
{
    uint32_t hash;
    SshPmActiveCfgModeClient *clientp;
    int j;

    /* Lookup the client. */
    SSH_ASSERT(client != NULL);
    SSH_ASSERT(client->peer_handle != SSH_IPSEC_INVALID_INDEX);
    hash = SSH_PM_CFGMODE_CLIENT_HASH(client->peer_handle);
    for (clientp = &pm->cfgmode_clients_hash[hash];
         *clientp;
         clientp = &(*clientp)->next)
    {
        if (*clientp == client)
        {
            if (--client->refcount > 0)
              /* This was not the last reference. */
              return;

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
#ifdef SSHDIST_RADIUS
            /* Call radius accounting to stop if it was on. */
            pm_ras_radius_acct_stop(pm, client);
#endif /* SSHDIST_RADIUS */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */

            /* Remove it from the hash table. */
            *clientp = client->next;

            /* Cancel renewal timeout */
            ssh_cancel_timeout(&client->lease_renewal_timer);

            /* Release the IP address. */
            for (j = 0; j < client->num_addresses; j++)
            {
                SSH_DEBUG(SSH_D_LOWOK, ("Releasing addresses `%@'",
                                        ssh_ipaddr_render,
                                        client->addresses[j]));
                if (client->free_cb != NULL_FNPTR)
                {
                    if (client->addresses[j] != NULL)
                      (*client->free_cb)(pm, client->addresses[j],
                                         client->address_context,
                                         client->ras_cb_context);
                }
            }

            /* And recycle the registry structure. */
            pm_cfgmode_client_store_free(pm, client);
            return;
        }
    }
}

void
ssh_pm_cfgmode_client_store_take_reference(SshPm pm,
                                           SshPmActiveCfgModeClient client)
{
    client->refcount++;
}
#endif /* SSHDIST_ISAKMP_CFG_MODE */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
