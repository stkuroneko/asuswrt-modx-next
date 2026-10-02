/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   Tunnel object handling.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"
#include "util_dnsresolver.h"

#define SSH_DEBUG_MODULE "SshPmTunnels"

/***************************** Public functions *****************************/

SshPmTunnel
ssh_pm_tunnel_create(SshPm pm, SshPmTransform transform, uint32_t flags,
                     const char *tunnel_name)
{
    SshPmTunnel tunnel;
    uint32_t i;
    uint32_t num_ciphers;
    uint32_t num_macs;
    uint32_t num_compressions;
    bool algorithms_defined;

    SSH_DEBUG(
            SSH_D_LOWOK,
            ("Creating tunnel %s with transform %x and flags %x",
             tunnel_name,
             (unsigned int) transform,
             (unsigned int) flags));

    /* Sanity check transform and flags. */
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
    if (flags & SSH_PM_TI_L2TP)
    {
        if ((transform & SSH_PM_IPSEC_TUNNEL) ||
            !(flags & SSH_PM_T_TRANSPORT_MODE))
        {
            ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                          "L2TP can only be used in transport mode.");
            return NULL;
        }

        ssh_log_event(
                SSH_LOGFACILITY_AUTH,
                SSH_LOG_ERROR,
                "L2TP is not supported");
        return NULL;
    }

    if (flags & SSH_PM_TI_CFGMODE)
    {
        if (flags & SSH_PM_T_PER_PORT_SA)
        {
            ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                          "The 'per-port' SA flag cannot be "
                          "specified for remote access client tunnels");
            return NULL;
        }
        if (flags & SSH_PM_TI_DONT_INITIATE)
        {
            ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                          "The 'dont-initiate' SA flag cannot be "
                          "specified for remote access client tunnels");
            return NULL;
        }
        if (flags & SSH_PM_T_TRANSPORT_MODE)
        {
            ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                          "The 'transport' flag cannot be "
                          "combined with 'cfgmode' flag.");
            return NULL;
        }

        ssh_log_event(
                SSH_LOGFACILITY_AUTH,
                SSH_LOG_ERROR,
                "CFGMode is not supported");
        return NULL;
    }
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
    if (flags & SSH_PM_TR_ALLOW_L2TP)
    {
        if ((transform & SSH_PM_IPSEC_TUNNEL) ||
            (flags & SSH_PM_T_TRANSPORT_MODE) == 0)
        {
            ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                          "L2TP can only be used in transport mode.");
            return NULL;
        }

        ssh_log_event(
                SSH_LOGFACILITY_AUTH,
                SSH_LOG_ERROR,
                "L2TP is not supported");
        return NULL;
    }

    if ((flags & SSH_PM_TR_ALLOW_CFGMODE) == 0
        && (flags & SSH_PM_TR_REQUIRE_CFGMODE))
    {
        ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                      "'require-cfgmode' flag cannot be used without "
                      "'allow-cfgmode'.");
        return NULL;
    }

    if ((flags & SSH_PM_TR_ALLOW_CFGMODE)
        && (flags & SSH_PM_T_TRANSPORT_MODE))
    {
        ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                      "'allow-cfgmode' flag cannot be used with "
                      "transport mode.");
        return NULL;
    }
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */

#ifdef SSHDIST_IPSEC_MOBIKE
    if (flags & SSH_PM_T_MOBIKE)
    {
        if (flags & SSH_PM_T_TRANSPORT_MODE)
        {
            ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                          "Mobike can only be used in tunnel mode.");
            return NULL;
        }
        if (transform & SSH_PM_IPSEC_AH)
        {
            SSH_DEBUG(SSH_D_NICETOKNOW,
                      ("Disabling NAT-T for Mobike AH tunnel."));
            flags |= SSH_PM_T_DISABLE_NATT;
        }
    }
#endif /* SSHDIST_IPSEC_MOBIKE */

    /* IPSec SA. */

    algorithms_defined = ssh_pm_ipsec_num_algorithms(pm, transform, 0,
                                                     &num_ciphers, &num_macs,
                                                     &num_compressions, NULL);
    if (algorithms_defined == false)
    {
        ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                      "Tunnel proposes algorithms that have not been included "
                      "in the compilation.");
        return NULL;
    }

    /* ESP. */
    if (transform & SSH_PM_IPSEC_ESP)
    {
        if (num_ciphers == 0 && num_macs == 0)
        {
            ssh_log_event(
                    SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                    "ESP tunnel is missing encryption and authentication "
                    "algorithms");
            return NULL;
        }
        else if (num_ciphers == 0)
        {
            ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                          "ESP tunnel is missing encryption algorithm "
                          "(the NULL encryption algorithm must be specified "
                          "if no encryption is required)");
            return NULL;
        }

        /* Check that ESP null-null is not proposed */
        if ((transform & SSH_PM_MAC_MASK) == 0 &&
            (transform & SSH_PM_CRYPT_NULL) != 0)
        {
            ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                          "ESP NULL-NULL is proposed for this tunnel. "
                          "This is forbidden by RFC 4301.");
            return NULL;
        }

        if ((transform & SSH_PM_CRYPT_NULL) != 0 &&
            (transform & SSH_PM_CRYPT_NULL_AUTH_AES_GMAC) != 0)
        {
            ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                          "ESP configuration results in NULL encryption and "
                          "NULL authentication. "
                          "This is forbidden by RFC 4301. "
                          "Don't use NULL encryption with gmac-aes!");
            return NULL;
        }

        if (num_macs != 0 &&
            (transform & (SSH_PM_CRYPT_MASK & ~SSH_PM_COMBINED_MASK)) == 0)
        {
            ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                          "ESP with authentication algorithm must be "
                          "used together with a non-combined mode cipher "
                          "or the null cipher.");
            return NULL;
        }
    }

    /* AH. */
    if (transform & SSH_PM_IPSEC_AH)
    {
#ifdef SSH_IPSEC_AH

















#endif /* SSH_IPSEC_AH */

        ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                      "AH is not supported");
        return NULL;
    }

    /* IPComp. */
#ifdef SSHDIST_IPSEC_IPCOMP
    if (transform & SSH_PM_IPSEC_IPCOMP)
    {
        if (num_compressions == 0)
        {
            ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                          "IPComp tunnel is missing compression algorithm");
            return NULL;
        }

        ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                      "IPComp is not supported");
        return NULL;
    }
#endif /* SSHDIST_IPSEC_IPCOMP */

    for (i = 0; i < num_ciphers; i++)
    {
        SshPmCipher cipher;

        cipher = ssh_pm_ipsec_cipher(pm, i, transform);

        /* Check that the key limits are within our compile time maximum
           values. */
        if (cipher->max_key_size + cipher->nonce_size >
            SSH_IPSEC_MAX_ESP_KEY_BITS)
        {
            ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                          "The maximum cipher key size %u is bigger than "
                          "the built-in maximum %u",
                          (unsigned int) (cipher->max_key_size
                                          + cipher->nonce_size),
                          SSH_IPSEC_MAX_ESP_KEY_BITS);
            return NULL;
        }
    }
    for (i = 0; i < num_macs; i++)
    {
        SshPmMac mac;

        mac = ssh_pm_ipsec_mac(pm, i, transform);

        /* Check that the key limits are within our compile time maximum
           values. */
        if (mac->max_key_size > SSH_IPSEC_MAX_MAC_KEY_BITS)
        {
            ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                          "The maximum MAC key size %u is bigger than "
                          "the built-in maximum %u",
                          (unsigned int) mac->max_key_size,
                          SSH_IPSEC_MAX_MAC_KEY_BITS);
            return NULL;
        }
    }

    /* An IPSec transform must be selected. */
    if ((transform & (SSH_PM_IPSEC_ESP | SSH_PM_IPSEC_AH)) == 0)
    {
        ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                      "No IPsec transform (AH or ESP) specified for tunnel");
        return NULL;
    }

    /* Auto-start rules must not have per-host or per-port flags. */
    if ((flags & SSH_PM_TI_DELAYED_OPEN) == 0
        && (flags & (SSH_PM_T_PER_HOST_SA | SSH_PM_T_PER_PORT_SA)))
    {
        ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                      "The `per-port' or `per-host' SA flags can not be "
                      "specified for `auto-start' tunnels");
        return NULL;
    }

    /* Both auto-start and dont-initiated can not be specified. */
    if ((flags & SSH_PM_TI_DELAYED_OPEN) == 0
        && (flags & SSH_PM_TI_DONT_INITIATE))
    {
        ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                      "Both `auto-start' and `dont-initiate' specified "
                      "for a tunnel");
        return NULL;
    }

    tunnel = ssh_pm_tunnel_alloc(pm);
    if (tunnel == NULL)
    {
        SSH_DEBUG(
                SSH_D_ERROR,
                ("Could not allocate memory for tunnel object"));
        return NULL;
    }

    tunnel->ike_window_size = 1;
    tunnel->num_peers = 0;
    tunnel->local_port = pm->params.local_ike_ports[0];
    tunnel->tunnel_name = NULL;
    if (tunnel_name != NULL)
    {
        tunnel->tunnel_name = ssh_strdup(tunnel_name);
        if (tunnel->tunnel_name == NULL)
        {
            ssh_pm_tunnel_free(pm, tunnel);

            ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                          "Out of memory. Could not allocate memory for "
                          "tunnel name!");
            return NULL;
        }
    }

    tunnel->pm = pm;
    tunnel->tunnel_id = pm->next_tunnel_id++;
    tunnel->refcount = 1;

    tunnel->ike_fragment_size = pm->ike_fragment_size;

    tunnel->transform = transform;
    tunnel->flags = flags;
    tunnel->routing_instance_id = SSH_VRI_ID_GLOBAL;
    ssh_strncpy(tunnel->routing_instance_name, SSH_VRI_NAME_GLOBAL,
                SSH_VRI_NAMESIZE);

    /* Tunnel mode is default if transport mode was not specified. */
    if ((tunnel->flags & SSH_PM_T_TRANSPORT_MODE) == 0)
      tunnel->transform |= SSH_PM_IPSEC_TUNNEL;

    tunnel->u.ike.versions = SSH_PM_IKE_VERSION_2;

    /* Init Diffie-Hellman groups and properties to our default values. */
    tunnel->u.ike.ike_groups = SSH_PM_DEFAULT_DH_GROUPS;

    tunnel->u.ike.dpd_timeout = SSH_PM_DEFAULT_DPD_TIMEOUT;

    /* As a default, no PFS. */

    /* Init default IKE SA lifetime. */
    tunnel->u.ike.ike_sa_life_seconds = SSH_PM_DEFAULT_IKE_SA_LIFE_SECONDS;

    /* Resolve IKE algorithms. */
    if (tunnel->u.ike.algorithms == 0)
    {
        /* Take the algorithms from the tunnel's transform. Account for
           algorithms which are not used in IKE. */
        tunnel->u.ike.algorithms
          = (tunnel->transform
             & ~(SSH_PM_COMBINED_MASK)
             & (SSH_PM_CRYPT_MASK | SSH_PM_MAC_MASK));

        /* And extend the missing algorithms from the global default
           IKE algorithms.*/
        if ((tunnel->u.ike.algorithms
             & (SSH_PM_CRYPT_MASK & ~SSH_PM_CRYPT_NULL)) == 0)
          tunnel->u.ike.algorithms |= (pm->default_ike_algorithms
                                       & SSH_PM_CRYPT_MASK);
        if ((tunnel->u.ike.algorithms & SSH_PM_MAC_MASK) == 0)
          tunnel->u.ike.algorithms |= (pm->default_ike_algorithms
                                       & SSH_PM_MAC_MASK);
    }

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
    tunnel->num_address_pool_ids = 0;
    if ((tunnel->flags & SSH_PM_TR_ALLOW_CFGMODE)
        || (tunnel->flags & SSH_PM_TR_ALLOW_L2TP))
    {
        /* Add the default address pool to the tunnel. This may be later
           overridden by calling ssh_pm_tunnel_add_address_pool(). */
        SshPmAddressPoolId id;

        if (ssh_pm_address_pool_get_default_id(pm, &id))
          tunnel->address_pool_ids[tunnel->num_address_pool_ids++] = id;

        /* Set the default remote access callbacks. This may be later
           overridden by ssh_pm_tunnel_set_remote_access(). */
        if (pm->remote_access_alloc_cb != NULL_FNPTR)
          ssh_pm_tunnel_set_remote_access(tunnel,
                                          pm->remote_access_alloc_cb,
                                          pm->remote_access_free_cb,
                                          pm->remote_access_cb_context);

        else
          ssh_pm_tunnel_set_remote_access(
                  tunnel,
                  ssh_pm_ras_alloc_address,
                  ssh_pm_ras_free_address,
                  SSH_PM_UINT32_TO_PTR(tunnel->tunnel_id));

    }
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */

    /* Add it to tunnel_id map */
    ssh_adt_insert(pm->tunnels, tunnel);

    return tunnel;
}

void
ssh_pm_tunnel_destroy(SshPm pm, SshPmTunnel tunnel)
{
    SshADTHandle h;

    if (tunnel == NULL)
      return;

    if (--tunnel->refcount > 0)
      /* This was not the last reference. */
      return;

    SSH_DEBUG(SSH_D_LOWOK, ("Destroying tunnel '%s' (id %d)",
                            tunnel->tunnel_name, tunnel->tunnel_id));

    /* Remove it from map */
    h = ssh_adt_get_handle_to(pm->tunnels, tunnel);
    SSH_ASSERT(h != SSH_ADT_INVALID);

    /* Delete will free the tunnel via ADT */
    ssh_adt_delete(pm->tunnels, h);
}

SshPmTunnel
ssh_pm_tunnel_get_next(SshPm pm, SshPmTunnel previous_tunnel)
{
    SshADTHandle h;

    if (previous_tunnel == NULL)
      h = ssh_adt_enumerate_start(pm->tunnels);
    else
      h = ssh_adt_enumerate_next(pm->tunnels,
                                 (SshADTHandle)&previous_tunnel->adt_header);

    if (h != SSH_ADT_INVALID)
      return (SshPmTunnel)ssh_adt_get(pm->tunnels, h);
    else
      return NULL;
}

uint32_t
ssh_pm_tunnel_get_flags(SshPmTunnel tunnel)
{
    return tunnel->flags;
}

static uint32_t
pm_tunnel_add_peer_ip(SshPmTunnel tunnel, SshIpAddr ip, uint32_t peer_index)
{
    SshIpAddr peers;
    uint32_t i, num_peers;

    SSH_DEBUG(SSH_D_LOWOK, ("Adding tunnel peer %@ at index %d",
                            ssh_ipaddr_render, ip, (int) peer_index));

    if (ssh_pm_find_interface_by_address(tunnel->pm, ip,
                                         tunnel->routing_instance_id, NULL)
                                         != NULL)
    {
        SSH_DEBUG(SSH_D_ERROR, ("Peer IP address is a local address"));
        return SSH_IPSEC_INVALID_INDEX;
    }

#ifdef SSH_IPSEC_MULTICAST
      /*  Multicast Peer not supported. */
      if (SSH_IP_IS_MULTICAST(ip))
    {
        SSH_DEBUG(SSH_D_ERROR,
                  ("Multicast Peer not supported"));
        return SSH_IPSEC_INVALID_INDEX;
    }
#endif /* SSH_IPSEC_MULTICAST */

#if defined (WITH_IPV6)
#ifdef SSHDIST_IPSEC_MOBIKE
      if ((tunnel->flags & SSH_PM_T_MOBIKE) &&
          !ssh_pm_mobike_valid_address(ip))
      {
          SSH_DEBUG(SSH_D_ERROR,
                    ("Cannot add link local peer with MobIKE enabled tunnel"));
          return SSH_IPSEC_INVALID_INDEX;
      }
#endif /* SSHDIST_IPSEC_MOBIKE */
#else /* WITH_IPV6 */
    /* Check that no IPv6 addresses were specified. */
    if (SSH_IP_IS6(ip))
    {
        SSH_DEBUG(SSH_D_ERROR, ("IPv6 support not compiled in"));
        return SSH_IPSEC_INVALID_INDEX;
    }
#endif /* WITH_IPV6 */

    /* Allocate memory for the new peer IP. */
    peers = ssh_calloc(tunnel->num_peers + 1, sizeof(SshIpAddrStruct));
    if (peers == NULL)
    {
        SSH_DEBUG(SSH_D_ERROR,
                  ("Could not allocate memory for a new IKE peer"));
        return SSH_IPSEC_INVALID_INDEX;
    }

    if (peer_index > tunnel->num_peers)
      peer_index = tunnel->num_peers;

    /* Copy existing peer IPs to tunnel peers. */
    num_peers = 0;
    for (i = 0; i < peer_index; i++)
      peers[num_peers++] = tunnel->peers[i];

    /* Insert new peer IP to tunnel peers. */
    peer_index = num_peers;
    peers[num_peers++] = *ip;

    /* Copy the rest of existing peer IPs to tunnel peers. */
    for (; i < tunnel->num_peers; i++)
      peers[num_peers++] = tunnel->peers[i];

    tunnel->num_peers = num_peers;

    ssh_free(tunnel->peers);
    tunnel->peers = peers;

    return peer_index;
}

#ifdef SSHDIST_IPSEC_DNSPOLICY
bool
ssh_pm_tunnel_add_dns_peer_ip(SshPmTunnel tunnel, SshIpAddr ip,
                              SshPmDnsReference ref)
{
    uint32_t i, peer_index;
    SshPmDnsPeer dns_peer = NULL;

    if (ip == NULL || !SSH_IP_DEFINED(ip))
      return false;

    /* Lookup DNS peer reference. */
    for (i = 0; i < tunnel->num_dns_peers; i++)
    {
        if (ref == tunnel->dns_peer_ip_ref_array[i].ref)
        {
            dns_peer = &tunnel->dns_peer_ip_ref_array[i];
            break;
        }
    }

    if (dns_peer == NULL)
      return false;

    /* Add peer IP address. */
    peer_index = pm_tunnel_add_peer_ip(tunnel, ip, dns_peer->peer_index);
    if (peer_index == SSH_IPSEC_INVALID_INDEX)
      return false;

    /* Fix peer indexes for other DNS peer references. */
    for (i++; i < tunnel->num_dns_peers; i++)
    {
        SSH_ASSERT(tunnel->dns_peer_ip_ref_array[i].peer_index >= peer_index);
        tunnel->dns_peer_ip_ref_array[i].peer_index++;
    }

    dns_peer->peer_index = peer_index;
    dns_peer->num_peers++;

    SSH_DEBUG(SSH_D_LOWOK,
              ("Added DNS resolved peer IP %@ at index %d (num_peers %d)",
               ssh_ipaddr_render, ip, (int) dns_peer->peer_index,
               (int) dns_peer->num_peers));

    return true;
}
#endif /* SSHDIST_IPSEC_DNSPOLICY */

bool
ssh_pm_tunnel_add_peer(SshPmTunnel tunnel, const char *address)
{
    SshIpAddrStruct ip_struct;
    bool ok;

    SSH_DEBUG(SSH_D_LOWOK, ("Adding tunnel peer %s", address));

    ok = ssh_ipaddr_parse(&ip_struct, address);

#ifdef SSHDIST_IPSEC_DNSPOLICY
    /* If the input is domain name make a reference... We'll possibly
       come here again when the name has been resolved and do the actual
       trick then. */
    if (!ok)
    {
        SshPmDnsReference ref;
        SshPmDnsPeer dns_peers;

        ref = ssh_pm_dns_cache_insert(tunnel->pm->dnscache, address,
                                      SSH_PM_DNS_OC_T_PEER, tunnel);
        if (ref == NULL)
        {
            SSH_DEBUG(SSH_D_ERROR, ("Malformed gateway IP address `%s'",
                                    address));
            return false;
        }

        dns_peers = ssh_realloc(tunnel->dns_peer_ip_ref_array,
                                tunnel->num_dns_peers *
                                sizeof(SshPmDnsPeerStruct),
                                (tunnel->num_dns_peers + 1) *
                                sizeof(SshPmDnsPeerStruct));
        if (dns_peers == NULL)
        {
            ssh_pm_dns_cache_remove(tunnel->pm->dnscache, ref);
            return false;
        }

        dns_peers[tunnel->num_dns_peers].ref = ref;
        dns_peers[tunnel->num_dns_peers].peer_index = tunnel->num_peers;
        dns_peers[tunnel->num_dns_peers].num_peers = 0;

        tunnel->num_dns_peers++;
        tunnel->dns_peer_ip_ref_array = dns_peers;
        return true;
    }
#endif /* SSHDIST_IPSEC_DNSPOLICY */

    if (pm_tunnel_add_peer_ip(tunnel, &ip_struct, tunnel->num_peers)
        == SSH_IPSEC_INVALID_INDEX)
      return false;

    return true;
}

#ifdef SSHDIST_IPSEC_SA_EXPORT
bool ssh_pm_tunnel_set_application_identifier(SshPmTunnel tunnel,
                                                 const char *id,
                                                 size_t id_len)
{
    char *app_id = NULL;

    if (id_len > SSH_PM_APPLICATION_IDENTIFIER_MAX_LENGTH)
      return false;

    if (id_len > 0)
    {
        app_id = ssh_malloc(id_len);
        if (app_id == NULL)
          return false;

        memcpy(app_id, id, id_len);
        SSH_DEBUG_HEXDUMP(
                SSH_D_LOWOK,
                ("Setting application identifier to tunnel '%s' (%d):",
                 tunnel->tunnel_name, tunnel->tunnel_id), id, id_len);
    }
    else
      SSH_DEBUG(SSH_D_LOWOK,
                ("Clearing application identifier fro tunnel '%s' (%d)",
                 tunnel->tunnel_name, tunnel->tunnel_id));

    if (tunnel->application_identifier != NULL)
      ssh_free(tunnel->application_identifier);
    tunnel->application_identifier = app_id;
    tunnel->application_identifier_len = id_len;

    return true;
}

bool ssh_pm_tunnel_get_application_identifier(SshPmTunnel tunnel,
                                                 char *id,
                                                 size_t *id_len)
{
    if (tunnel->application_identifier_len > *id_len)
      return false;

    if (tunnel->application_identifier_len > 0)
      memcpy(id, tunnel->application_identifier,
             tunnel->application_identifier_len);

    *id_len = tunnel->application_identifier_len;

    return true;
}
#endif /* SSHDIST_IPSEC_SA_EXPORT */

/* A predicate to compare two algorithm property lists for equality.
   The comparison is done element by element and they must match
   exatly to be equal. */
static bool
ssh_pm_algorithm_properties_compare(SshPmAlgorithmProperties p1,
                                    SshPmAlgorithmProperties p2)
{
    /* Check whether either p1 or p2 (but not both) is NULL */
    if ((p1 != p2) && ((p1 == NULL) || (p2 == NULL)))
      return false;

    while (p1 && p2)
    {
        /* Compare this item. */
        if (p1->algorithm != p2->algorithm
            || p1->min_key_size != p2->min_key_size
            || p1->max_key_size != p2->max_key_size
            || p1->default_key_size != p2->default_key_size)
          /* This item differs. */
          return false;

        /* Move forward. */
        p1 = p1->next;
        p2 = p2->next;

        if ((p1 == NULL && p2 != NULL) ||
            (p1 != NULL && p2 == NULL))
          /* List lengths differ. */
          return false;
    }

    /* All elements were equal. */
    return true;
}

/* A predicate to compare two Difie Hellman group objects for equality.
   They must match exactly to be equal. */
static bool
pm_compare_dh_groups(SshPmDHGroup g1, SshPmDHGroup g2)
{
    /* Check whether either g1 or g2 (but not both) is NULL */
    if ((g1 != g2) && ((g1 == NULL) || (g2 == NULL)))
      return false;

    if (g1->mask_bits != g2->mask_bits)
      return false;
    if (g1->group_desc != g2->group_desc)
      return false;
    if (g1->group_size != g2->group_size)
      return false;
    if (g1->preference != g2->preference)
      return false;

    return true;
}

bool
ssh_pm_tunnel_compare(SshPm pm, SshPmTunnel tunnel1, SshPmTunnel tunnel2)
{
    uint32_t i;

    if (!tunnel1 || !tunnel2)
      return false;

    if (tunnel1->transform != tunnel2->transform)
      return false;
    if (tunnel1->flags != tunnel2->flags)
      return false;

    /* Local identity */
    if (tunnel1->local_identity && !tunnel2->local_identity)
      return false;
    if (tunnel2->local_identity && !tunnel1->local_identity)
      return false;

    if (tunnel1->local_port != tunnel2->local_port)
      return false;

    if (tunnel1->local_identity && tunnel2->local_identity)
    {
        if (tunnel1->local_identity->id_type !=
            tunnel2->local_identity->id_type)
          return false;
        if (tunnel1->local_identity->id_data_size !=
            tunnel2->local_identity->id_data_size)
          return false;
        if (memcmp(tunnel1->local_identity->id_data,
                   tunnel2->local_identity->id_data,
                   tunnel2->local_identity->id_data_size) != 0)
          return false;
    }

    /* Remote identity */
    if (tunnel1->remote_identity && !tunnel2->remote_identity)
      return false;
    if (tunnel2->remote_identity && !tunnel1->remote_identity)
      return false;

    if (tunnel1->remote_identity && tunnel2->remote_identity)
    {
        if (tunnel1->remote_identity->id_type !=
            tunnel2->remote_identity->id_type)
          return false;
        if (tunnel1->remote_identity->id_data_size !=
            tunnel2->remote_identity->id_data_size)
          return false;
        if (memcmp(tunnel1->remote_identity->id_data,
                   tunnel2->remote_identity->id_data,
                   tunnel2->remote_identity->id_data_size) != 0)
          return false;
    }

    if (tunnel1->auth_domain_name || tunnel2->auth_domain_name)
    {
        if (!tunnel1->auth_domain_name || !tunnel2->auth_domain_name)
          return false;
        if (strcmp(tunnel1->auth_domain_name,
                   tunnel2->auth_domain_name))
        {
            SSH_DEBUG(SSH_D_NICETOKNOW, ("Authentication domains differ"));
            return false;
        }
    }

#ifdef SSH_IKEV2_MULTIPLE_AUTH
    if (tunnel1->second_local_identity && tunnel2->second_local_identity)
    {
        if (tunnel1->second_local_identity->id_type !=
            tunnel2->second_local_identity->id_type)
          return false;
        if (tunnel1->second_local_identity->id_data_size !=
            tunnel2->second_local_identity->id_data_size)
          return false;
        if (memcmp(tunnel1->second_local_identity->id_data,
                   tunnel2->second_local_identity->id_data,
                   tunnel2->second_local_identity->id_data_size) != 0)
          return false;
    }


    if (tunnel1->second_auth_domain_name ||
        tunnel2->second_auth_domain_name)
    {
        if (!tunnel1->second_auth_domain_name ||
            !tunnel2->second_auth_domain_name)
          return false;
        if (strcmp(tunnel1->second_auth_domain_name,
                   tunnel2->second_auth_domain_name))
        {
            SSH_DEBUG(SSH_D_NICETOKNOW,
                      ("Second authentication domains differ"));
            return false;
        }
    }
#endif /* SSH_IKEV2_MULTIPLE_AUTH */

#ifdef SSHDIST_IPSEC_DNSPOLICY
    if (tunnel1->num_dns_peers || tunnel2->num_dns_peers)
    {
        if (tunnel1->num_dns_peers != tunnel2->num_dns_peers)
          return false;
        for (i = 0; i < tunnel1->num_dns_peers; i++)
          if (!ssh_pm_dns_cache_compare(tunnel1->dns_peer_ip_ref_array[i].ref,
                                        tunnel2->dns_peer_ip_ref_array[i].ref))
            return false;
    }
    else
#endif /* SSHDIST_IPSEC_DNSPOLICY */
    {
        if (tunnel1->num_peers != tunnel2->num_peers)
          return false;
        for (i = 0; i < tunnel1->num_peers; i++)
          if (!SSH_IP_EQUAL(&tunnel1->peers[i], &tunnel2->peers[i]))
            return false;
    }

#ifdef SSHDIST_IPSEC_DNSPOLICY
    if (tunnel1->num_local_dns_addresses || tunnel2->num_local_dns_addresses)
    {
        SshPmTunnelLocalDnsAddress local_dns1, local_dns2;

        if (tunnel1->num_local_dns_addresses !=
            tunnel2->num_local_dns_addresses)
          return false;

        for (local_dns1 = tunnel1->local_dns_address;
             local_dns1 != NULL;
             local_dns1 = local_dns1->next)
        {
            for (local_dns2 = tunnel2->local_dns_address;
                 local_dns2 != NULL;
                 local_dns2 = local_dns2->next)
            {
                if (ssh_pm_dns_cache_compare(local_dns1->ref, local_dns2->ref))
                  break;
            }
            if (local_dns2 == NULL)
              return false;
        }
    }
#endif /* SSHDIST_IPSEC_DNSPOLICY */

    if (tunnel1->num_local_interfaces || tunnel2->num_local_interfaces)
    {
        SshPmTunnelLocalInterface local_iface1, local_iface2;

        if (tunnel1->num_local_interfaces != tunnel2->num_local_interfaces)
          return false;

        for (local_iface1 = tunnel1->local_interface;
             local_iface1 != NULL;
             local_iface1 = local_iface1->next)
        {
            for (local_iface2 = tunnel2->local_interface;
                 local_iface2 != NULL;
                 local_iface2 = local_iface2->next)
            {
                if (strcmp(local_iface1->name, local_iface2->name) == 0)
                  break;
            }
            if (local_iface2 == NULL)
              return false;
        }
    }

    if (tunnel1->num_local_ips || tunnel2->num_local_ips)
    {
        SshPmTunnelLocalIp local_ip1, local_ip2;

        if (tunnel1->num_local_ips != tunnel2->num_local_ips)
          return false;

        for (local_ip1 = tunnel1->local_ip;
             local_ip1 != NULL;
             local_ip1 = local_ip1->next)
        {
            if (!local_ip1->static_ip)
              continue;

            for (local_ip2 = tunnel2->local_ip;
                 local_ip2 != NULL;
                 local_ip2 = local_ip2->next)
            {
                if (!local_ip2->static_ip)
                  continue;

                if (SSH_IP_EQUAL(&local_ip1->ip, &local_ip2->ip))
                  break;
            }
            if (local_ip2 == NULL)
              return false;
        }
    }

    if (tunnel1->routing_instance_id != tunnel2->routing_instance_id)
    {
        SSH_DEBUG(SSH_D_NICETOKNOW, ("Routing instance id mismatch"));
        return false;
    }

    /* Algorithm properties. */
    if (!ssh_pm_algorithm_properties_compare(tunnel1->algorithm_properties,
                                             tunnel2->algorithm_properties))
      return false;

    /* IKE keyed tunnels. */
    {
        if (tunnel1->u.ike.versions != tunnel2->u.ike.versions)
          return false;
        if (tunnel1->u.ike.algorithms != tunnel2->u.ike.algorithms)
          return false;
        if (tunnel1->u.ike.ike_groups != tunnel2->u.ike.ike_groups)
          return false;
        if (tunnel1->u.ike.pfs_groups != tunnel2->u.ike.pfs_groups)
          return false;
        if (tunnel1->u.ike.ipsec_sa_life_seconds
            != tunnel2->u.ike.ipsec_sa_life_seconds)
          return false;
        if (tunnel1->u.ike.ipsec_sa_life_kb != tunnel2->u.ike.ipsec_sa_life_kb)
          return false;
        if (tunnel1->u.ike.ike_sa_life_seconds
            != tunnel2->u.ike.ike_sa_life_seconds)
          return false;

        if (tunnel1->u.ike.num_tunnel_ike_groups
            != tunnel2->u.ike.num_tunnel_ike_groups)
          return false;
        for (i = 0; i < tunnel1->u.ike.num_tunnel_ike_groups; i++)
        {
            if (!pm_compare_dh_groups(&tunnel1->u.ike.tunnel_ike_groups[i],
                                      &tunnel2->u.ike.tunnel_ike_groups[i]))
              return false;
        }

        if (tunnel1->u.ike.num_tunnel_pfs_groups
            != tunnel2->u.ike.num_tunnel_pfs_groups)
          return false;
        for (i = 0; i < tunnel1->u.ike.num_tunnel_pfs_groups; i++)
        {
            if (!pm_compare_dh_groups(&tunnel1->u.ike.tunnel_pfs_groups[i],
                                      &tunnel2->u.ike.tunnel_pfs_groups[i]))
              return false;
        }

        /* Pre-shared keys. */
        if (tunnel1->u.ike.num_secrets != tunnel2->u.ike.num_secrets)
          return false;

        for (i = 0; i < tunnel1->u.ike.num_secrets; i++)
        {
            if (!ssh_pm_psk_compare(&tunnel1->u.ike.secrets[i],
                                    &tunnel2->u.ike.secrets[i]))
              return false;

            if (tunnel1->u.ike.secrets[i].flags !=
                tunnel2->u.ike.secrets[i].flags)
              return false;
        }

#ifdef SSHDIST_IKE_CERT_AUTH
        /* Local certificate */
        if ((tunnel1->u.ike.local_cert_kid &&
             !tunnel2->u.ike.local_cert_kid) ||
            (!tunnel1->u.ike.local_cert_kid &&
             tunnel2->u.ike.local_cert_kid) ||
            (tunnel1->u.ike.local_cert_kid_len !=
             tunnel2->u.ike.local_cert_kid_len))
          return false;

#ifdef SSHDIST_CERT
        if (tunnel1->u.ike.local_cert_kid)
        {
            if (memcmp(tunnel1->u.ike.local_cert_kid,
                       tunnel2->u.ike.local_cert_kid,
                       tunnel1->u.ike.local_cert_kid_len))
              return false;
        }
#endif /* SSHDIST_CERT */
#endif /* SSHDIST_IKE_CERT_AUTH */

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
        /* Compare the address pool ids. */
        if (tunnel1->num_address_pool_ids != tunnel2->num_address_pool_ids)
        {
            SSH_DEBUG(SSH_D_NICETOKNOW, ("Address pool id's differ"));
            return false;
        }
        for (i = 0; i < tunnel1->num_address_pool_ids; i++)
        {
            if (tunnel1->address_pool_ids[i] != tunnel2->address_pool_ids[i])
            {
                SSH_DEBUG(SSH_D_NICETOKNOW, ("Address pool id's differ"));
                return false;
            }
        }
        if ((tunnel1->u.ike.remote_access_alloc_cb
             != tunnel2->u.ike.remote_access_alloc_cb)
            || (tunnel1->u.ike.remote_access_free_cb
                != tunnel2->u.ike.remote_access_free_cb))
        {
            SSH_DEBUG(SSH_D_NICETOKNOW, ("Remote access callbacks differ"));
            return false;
        }
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
        if (strcmp(tunnel1->vip_name, tunnel2->vip_name))
          return false;

        if (tunnel1->u.ike.num_irac_addresses !=
            tunnel2->u.ike.num_irac_addresses)
          return false;

        for (i = 0; i < tunnel1->u.ike.num_irac_addresses; i++)
          if (SSH_IP_CMP(&tunnel1->u.ike.irac_address[i],
                         &tunnel2->u.ike.irac_address[i]))
            return false;
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */
    }

    /* They are equal. */
    return true;
}

static uint32_t
ssh_pm_tunnel_hash_adt(void *ptr, void *ctx)
{
    SshPmTunnel tunnel = (SshPmTunnel) ptr;

    return tunnel->tunnel_id;
}

static int
ssh_pm_tunnel_compare_adt(void *ptr1, void *ptr2, void *ctx)
{
    SshPmTunnel t1 = (SshPmTunnel) ptr1;
    SshPmTunnel t2 = (SshPmTunnel) ptr2;

    return t2->tunnel_id - t1->tunnel_id;
}

static void
ssh_pm_tunnel_destroy_adt(void *ptr, void *ctx)
{
    SshPmTunnel tunnel = (SshPmTunnel) ptr;
    SshPm pm = (SshPm) ctx;

    ssh_pm_tunnel_free(pm, tunnel);
}

bool
ssh_pm_tunnels_init(SshPm pm)
{
    pm->tunnels
      = ssh_adt_create_generic(SSH_ADT_BAG,

                               SSH_ADT_HEADER,
                               SSH_ADT_OFFSET_OF(SshPmTunnelStruct,
                                                 adt_header),

                               SSH_ADT_HASH,      ssh_pm_tunnel_hash_adt,
                               SSH_ADT_COMPARE,   ssh_pm_tunnel_compare_adt,
                               SSH_ADT_DESTROY,   ssh_pm_tunnel_destroy_adt,
                               SSH_ADT_CONTEXT,   pm,

                               SSH_ADT_ARGS_END);

    if (pm->tunnels == NULL)
      return false;

    return true;
}

void
ssh_pm_tunnels_uninit(SshPm pm)
{
    if (pm->tunnels != NULL)
    {
        ssh_adt_destroy(pm->tunnels);
        pm->tunnels = NULL;
    }
}
