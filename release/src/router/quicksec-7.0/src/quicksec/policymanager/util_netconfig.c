/**
   @copyright
   Copyright (c) 2015 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   The main thread controlling PM start and event waiting.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"
#include "sshnetconfig.h"

/************************** Types and definitions ***************************/

#define SSH_DEBUG_MODULE "SshPmUtilNetlink"

#define SSH_PM_NETEVENT_MAX_IFACES 128
#define SSH_PM_NETEVENT_MAX_IFACE_ADDRS 128
#define SSH_PM_NETCONFIG_MAX_ROUTES 128

void
ssh_pm_qm_route(
        SshPm pm,
        uint32_t flags,
        uint32_t ifnum,
        const SshIpAddr next_hop,
        void *context)
{
    SshFSMThread thread = (SshFSMThread) context;
    SshPmQm qm = (SshPmQm) ssh_fsm_get_tdata(thread);
    SshIpAddr ip;

    if (qm->aborted)
    {
        SSH_DEBUG(SSH_D_MIDOK,
                  ("QM thread aborted, advancing to terminal state"));
        ssh_fsm_set_next(thread, ssh_pm_st_qm_i_n_failed);
        return;
    }

    if ((flags & SSH_PM_ROUTE_REACHABLE) == 0)
    {
        SSH_DEBUG(SSH_D_NICETOKNOW,
                  ("Destination `%@' is unreachable",
                   ssh_ipaddr_render, &qm->initial_remote_addr));
        qm->error = SSH_IKEV2_ERROR_XMIT_ERROR;
    }
    else if (flags & SSH_PM_ROUTE_LINKBROADCAST)
    {
        SSH_DEBUG(SSH_D_NICETOKNOW,
                  ("Destination `%@' is a link-local broadcast address",
                   ssh_ipaddr_render, &qm->initial_remote_addr));
        qm->error = SSH_IKEV2_ERROR_XMIT_ERROR;
    }
    else
    {
        if (flags & SSH_PM_ROUTE_LOCAL)
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Destination `%@' is our local address",
                     ssh_ipaddr_render, &qm->initial_remote_addr));

        SSH_DEBUG(SSH_D_NICETOKNOW,
                  ("Destination `%@' is reachable using "
                   "interface %u: next_hop=%@",
                   ssh_ipaddr_render, &qm->initial_remote_addr,
                   (int) ifnum,
                   ssh_ipaddr_render, next_hop));

        /* If the local IP address is undefined, lookup it now. */
        if (!SSH_IP_DEFINED(&qm->initial_local_addr))
        {
            ip =
                ssh_pm_find_interface_address(
                        pm, ifnum,
                        (SSH_IP_IS6(&qm->initial_remote_addr)
                         ? true : false),
                        &qm->initial_remote_addr);
            if (ip == NULL)
            {
                SSH_DEBUG(SSH_D_NICETOKNOW,
                          ("Interface %d does not have an usable address",
                           (int) ifnum));
                qm->error = SSH_IKEV2_ERROR_XMIT_ERROR;
            }
            else
            {
                SSH_DEBUG(SSH_D_NICETOKNOW, ("Using local IP address `%@'",
                                             ssh_ipaddr_render, ip));
                qm->initial_local_addr = *ip;
            }
        }
    }
}

static void
log_removed_interfaces(
        SshPm pm,
        const struct SshIpInterfacesRec *new_ifs)
{
    SshInterface *ifp1, *ifp2;
    bool seen;
    int i, j;

    /* Log any removed interfaces */
    for (i = 0; i < pm->ifs.nifs; i++)
    {
        ifp1 = &pm->ifs.ifs[i];

        for (j = 0, seen = false; j < new_ifs->nifs; j++)
        {
            ifp2 = &new_ifs->ifs[j];

            /* Skip interfaces that have link down. */
            if (ifp2->flags & SSH_INTERFACE_FLAG_LINK_DOWN)
                continue;

            if (ssh_ip_interface_compare(ifp1, ifp2))
            {
                seen = true;
                break;
            }
        }

        if (!seen)
        {
            ssh_log_event(
                    SSH_LOGFACILITY_AUTH,
                    SSH_LOG_INFORMATIONAL,
                    "Removed interface: %d",
                    (int) ifp1->ifnum);

            ssh_pm_log_interface(ifp1);
        }
    }
}


static void
log_new_interface(
        SshPm pm,
        SshInterface *iface)
{
    SshInterface *if_tmp;
    bool seen;
    int j;

    /* Check if this is a new interface. */
    for (j = 0, seen = false; j < pm->ifs.nifs; j++)
    {
        if_tmp = &pm->ifs.ifs[j];

        if (ssh_ip_interface_compare(iface, if_tmp))
        {
          seen = true;
          break;
        }
    }

    if (!seen)
    {
        ssh_log_event(
                SSH_LOGFACILITY_AUTH,
                SSH_LOG_INFORMATIONAL,
                "Added new interface: %d",
                (int) iface->ifnum);

         ssh_pm_log_interface(iface);
    }
}

static bool
pm_netcofing_interface_address_add(
        uint32_t ifnum,
        SshInterfaceAddress iface_addr,
        SshNetconfigInterfaceAddr net_iface_addr)
{
    if (net_iface_addr->address.type != SSH_IP_TYPE_IPV6 &&
        net_iface_addr->address.type != SSH_IP_TYPE_IPV4)
      return false;

    if (SSH_IP_IS4(&net_iface_addr->address))
        iface_addr->protocol = SSH_PROTOCOL_IP4;
    else if (SSH_IP_IS6(&net_iface_addr->address))
        iface_addr->protocol = SSH_PROTOCOL_IP6;
    else
        iface_addr->protocol = SSH_PROTOCOL_OTHER;

    memcpy(
            &iface_addr->addr.ip.ip,
            &net_iface_addr->address,
            sizeof(SshIpAddrStruct));
    SSH_IP_MASK_LEN(&iface_addr->addr.ip.ip) =
        8 * SSH_IP_ADDR_LEN(&iface_addr->addr.ip.ip);

    if (net_iface_addr->address.type == SSH_IP_TYPE_IPV6)
        iface_addr->addr.ip.ip.scope_id.scope_id_union.ui32 = ifnum;

    ssh_ipaddr_set_mask_bits(
            &iface_addr->addr.ip.mask,
            net_iface_addr->address.type,
            net_iface_addr->address.mask_len);

    /** Undefine bcast address if interface does not support bcast */
    if ((net_iface_addr->flags & SSH_NETCONFIG_ADDR_BROADCAST) == 0)
    {
        SSH_IP_UNDEFINE(&net_iface_addr->broadcast);
    }
    else
    {
        memcpy(
                &iface_addr->addr.ip.broadcast,
                &net_iface_addr->broadcast,
                sizeof(SshIpAddrStruct));
        SSH_IP_MASK_LEN(&iface_addr->addr.ip.broadcast) =
            8 * SSH_IP_ADDR_LEN(&net_iface_addr->broadcast);
    }

    return true;
}

bool
ssh_pm_interface_change(SshPm pm)
{
    SshIpInterfacesStruct ifs_struct;
    SshInterface ifp1;
    SshNetconfigError error;
    uint32_t ifnum[SSH_PM_NETEVENT_MAX_IFACES];
    uint32_t num_ifaces;
    int i, j, k;
    SshNetconfigLinkStruct link;
    char ifname[SSH_INTERFACE_IFNAME_SIZE + 1];
    SshNetconfigInterfaceAddrStruct ifaddr[SSH_PM_NETEVENT_MAX_IFACE_ADDRS];
    uint32_t num_ifaddrs;
    SshInterfaceAddress addrs = NULL;

    if (ssh_pm_get_status(pm) == SSH_PM_STATUS_DESTROYED)
    {
        /* The policy manager is shutting down. */
        SSH_DEBUG(SSH_D_NICETOKNOW,
                  ("Policy manager shutting down: ignoring interface change"));
        return false;
    }

    /* Initialize new interface table. */
    if (ssh_ip_init_interfaces(&ifs_struct) == false)
      goto error;

    num_ifaces = SSH_PM_NETEVENT_MAX_IFACE_ADDRS;
    error = ssh_netconfig_get_links(ifnum, &num_ifaces);
    if (error == SSH_NETCONFIG_ERROR_OUT_OF_MEMORY)
    {
        SSH_DEBUG(SSH_D_FAIL,
                  ("Out of memory while fetching interface information, "
                   "some interfaces might be not updated to pm"));
    }
    else if (error != SSH_NETCONFIG_ERROR_OK)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Could not fetch interface information: %d",
                               (int) error));
        goto error;
    }

    SSH_DEBUG(SSH_D_LOWOK, ("Received interface information for %d links",
                            (int) num_ifaces));

   /** Iterate interfaces */
    for (i = 0; i < num_ifaces; i++)
    {
        /** Fetch interface status */
        error = ssh_netconfig_get_link(ifnum[i], &link);
        if (error != SSH_NETCONFIG_ERROR_OK)
        {
            SSH_DEBUG(SSH_D_NICETOKNOW,
                      ("Could not fetch interface status for ifnum %d: %d",
                       (int) ifnum[i], (int) error));
            continue;
        }

        /** Skip interfaces that are down */
        if ((link.flags & SSH_NETCONFIG_LINK_UP) == 0)
        {
            SSH_DEBUG(SSH_D_NICETOKNOW, ("Interface %d is down",
                                         (int) ifnum[i]));
            continue;
        }

        /** Skip loopback interfaces */
        if ((link.flags & SSH_NETCONFIG_LINK_LOOPBACK) != 0)
        {
            SSH_DEBUG(SSH_D_NICETOKNOW, ("Skipping loopback interface %d",
                                         (int) ifnum[i]));
            continue;
        }

        /** Fetch interface name */
        error = ssh_netconfig_resolve_ifnum(ifnum[i], ifname,
                                            SSH_INTERFACE_IFNAME_SIZE);
        if (error != SSH_NETCONFIG_ERROR_OK)
        {
            SSH_DEBUG(SSH_D_FAIL,
                      ("Could not fetch interface name for ifnum %d: %d",
                       (int) ifnum[i], (int) error));
            continue;
        }
        ifname[SSH_INTERFACE_IFNAME_SIZE] = '\0';

        memset(&ifp1, 0, sizeof(ifp1));
        ifp1.ifnum = ifnum[i];
        ssh_snprintf(ifp1.name, sizeof(ifp1.name), "%s", ifname);
        ifp1.flags = link.flags;

       /** Fetch addresses */
        num_ifaddrs = SSH_PM_NETEVENT_MAX_IFACE_ADDRS;
        error = ssh_netconfig_get_addresses(ifnum[i], &num_ifaddrs, ifaddr);
        if (error == SSH_NETCONFIG_ERROR_OUT_OF_MEMORY)
        {
            SSH_DEBUG(SSH_D_FAIL,
                      ("Out of memory while fetching interface addresses, "
                       "some addresses might be not updated to pm"));
        }
        else if (error != SSH_NETCONFIG_ERROR_OK)
        {
            SSH_DEBUG(SSH_D_FAIL,
                      ("Could not fetch addresses for interface '%s' %d: %d",
                       ifname, (int) ifnum[i], (int) error));
            continue;
        }

        addrs = NULL;
        if (num_ifaddrs)
        {
            if ((addrs = ssh_calloc(1, sizeof(ifp1.addrs[0]) * num_ifaddrs))
                == NULL)
              goto error;
        }
        k = 0;
        /** Iterate interface addresses */
        for (j = 0; j < num_ifaddrs; j++)
        {
            bool status = true;

            if ((ifaddr[j].flags & SSH_NETCONFIG_ADDR_TENTATIVE) != 0)
            {
                SSH_DEBUG(
                        SSH_D_HIGHOK,
                        ("Ignoring tentative address %@ [%@] on interface "
                         "'%s' (%d): %d",
                         ssh_ipaddr_render, &ifaddr[j].address,
                         ssh_ipaddr_render, &ifaddr[j].broadcast,
                         ifname,
                         (int) ifnum[i],
                         (int) error));
                continue;
            }
            status = pm_netcofing_interface_address_add(
                             ifnum[i],
                             &addrs[k],
                             &ifaddr[j]);
            if (status == true)
            {
                SSH_DEBUG(SSH_D_HIGHOK,
                          ("Added address %@ [%@] on interface "
                           "'%s' (%d)",
                           ssh_ipaddr_render, &addrs[j].addr.ip.ip,
                           ssh_ipaddr_render, &addrs[j].addr.ip.broadcast,
                           ifname,
                           (int) ifnum[i]));
                k++;
            }
        }
        ifp1.addrs = addrs;
        ifp1.num_addrs = k;
        ifp1.routing_instance_id = link.routing_instance_id;
        {
          char *name;

          if (link.routing_instance_id != SSH_VRI_ID_GLOBAL)
            name="";
          else
            name = SSH_VRI_NAME_GLOBAL;
          strncpy(
                  ifp1.routing_instance_name,
                  name,
                  SSH_VRI_NAMESIZE - 1);
        }

        memcpy(ifp1.media_addr, link.media_addr, sizeof(ifp1.media_addr));
        ifp1.media_addr_len = SSH_NETCONFIG_MEDIA_ADDRLEN;

        /* XXX Are IPv4 and IPv6 MTUs supposed to be the same ?*/
        ifp1.to_adapter.mtu_ipv4 = link.mtu;
        ifp1.to_protocol.mtu_ipv4 = link.mtu;
#ifdef WITH_IPV6
        ifp1.to_adapter.mtu_ipv6 = link.mtu;
        ifp1.to_protocol.mtu_ipv6 = link.mtu;
#endif /* WITH_IPV6 */

        SSH_DEBUG(SSH_D_NICETOKNOW, ("Adding interface %d",
                                     (int) ifnum[i]));

        /* Add interface to new interface table. */
        if (ssh_ip_init_interfaces_add(&ifs_struct, &ifp1) == false)
        {
            SSH_DEBUG(SSH_D_FAIL,
                      ("Could not add interface to interface table"));
            goto error;
        }

        log_new_interface(pm, &ifp1);

        ssh_free(addrs);
        addrs = NULL;
    }

    log_removed_interfaces(pm, &ifs_struct);

    /* Finalize interface table initialization. */
    if (ssh_ip_init_interfaces_done(&ifs_struct) == false)
      goto error;

    /* Replace existing interface table with the new interface table. */
    ssh_ip_uninit_interfaces(&pm->ifs);
    pm->ifs = ifs_struct;

    return true;

   error:
    SSH_DEBUG(SSH_D_FAIL, ("Failed to initialize interface table"));
    if (addrs != NULL)
        ssh_free(addrs);
    ssh_ip_uninit_interfaces(&ifs_struct);
    return false;
}

int
ssh_pm_route(
        SshPm pm,
        SshIpAddr preferred_src,
        SshRouteKey key,
        uint32_t *flags,
        uint32_t *ifnum,
        SshIpAddr next_hop)
{
    SshIpAddrStruct filter;
    SshNetconfigError error;
    int i;
    int best_match = 0;
    bool match_found =  false;
    SshNetconfigRouteStruct routes[SSH_PM_NETCONFIG_MAX_ROUTES];
    uint32_t num_routes = SSH_PM_NETCONFIG_MAX_ROUTES;
    uint32_t preferred_ifnum;
    *flags = *ifnum = 0;

    SSH_DEBUG(SSH_D_LOWOK, ("Routing remote %@ preferred source %@",
                            ssh_ipaddr_render, &key->dst,
                            ssh_ipaddr_render, preferred_src));

    /** Create filter for fetching only routes that match address family
        of remote_ip */
    if (SSH_IP_IS4(&key->dst))
      ssh_ipaddr_parse_with_mask(&filter, SSH_IPADDR_ANY_IPV4,
                                 SSH_IPADDR_ANY_IPV4);
    else if (SSH_IP_IS6(&key->dst))
      ssh_ipaddr_parse_with_mask(&filter, SSH_IPADDR_ANY_IPV6,
                                 SSH_IPADDR_ANY_IPV6);
    else
    {
        SSH_DEBUG(SSH_D_FAIL, ("Invalid remote ip"));
        return -1;
    }

    /** Resolve ifnum for preferred source ip, if it is specified */
    if (preferred_src != NULL && SSH_IP_DEFINED(preferred_src))
    {
        if (ssh_pm_find_interface_by_address(pm, preferred_src,
                                             key->routing_instance_id,
                                             &preferred_ifnum) == false)
        {
            SSH_DEBUG(SSH_D_LOWOK,
                      ("Failed to find local interface for preferred src %@",
                       ssh_ipaddr_render, preferred_src));
            return -1;
        }
    }
    else
    {
        preferred_ifnum = SSH_INVALID_IFNUM;
    }

    /** Fetch routes */
    error = ssh_netconfig_get_route(&filter, &num_routes, routes);
    if (error != SSH_NETCONFIG_ERROR_OK)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Failed to fetch routing table: error %d",
                               (int) error));
        return -1;
    }

    /** Select route with longest matching prefix and lowest metric */
    for (i = 0; i < num_routes; i++)
    {
        SSH_DEBUG(SSH_D_LOWOK,
                  (" Route to %@ via %@ dev %d metric %d.",
                   ssh_ipaddr_render, &routes[i].prefix,
                   ssh_ipaddr_render, &routes[i].gateway,
                   routes[i].ifnum, routes[i].metric));

        /** Skip routes that go out via unknown interfaces. This takes care
            of virtual ip routes, loopback routes and routes via interfaces
            that the PM does not listen to. */
        if (ssh_ip_get_interface_by_ifnum(&pm->ifs, routes[i].ifnum) == NULL)
          continue;

        /** Skip route prefixes that do not contain remote destination */
        if (!SSH_IP_MASK_EQUAL(&key->dst, &routes[i].prefix))
          continue;

        /** Skip routes that go out via non-preferred interface */
        if (preferred_ifnum != SSH_INVALID_IFNUM
            && preferred_ifnum != routes[i].ifnum)
            continue;

        /** Skip routes that have a shorter prefix than the current best
            match candidate */
        if (match_found == true &&
                SSH_IP_MASK_LEN(&routes[best_match].prefix) >
                SSH_IP_MASK_LEN(&routes[i].prefix))
            continue;

        /* First hit is always initial best match. */
        if (match_found == false)
        {
            best_match = i;
            match_found = true;
            continue;
        }

        /** Check if this is so far the best match and remember it */
        if (SSH_IP_MASK_LEN(&routes[best_match].prefix) <
                SSH_IP_MASK_LEN(&routes[i].prefix))
        {
            /** Longest found prefix */
            best_match = i;
        }
        else if (routes[best_match].metric > routes[i].metric)
        {
            /** Longest found prefix with lowest metric */
            SSH_ASSERT(SSH_IP_MASK_LEN(&routes[best_match].prefix)
                       == SSH_IP_MASK_LEN(&routes[i].prefix));
            best_match = i;
        }
    }

    if (match_found == false)
    {
        SSH_DEBUG(
                SSH_D_NICETOKNOW,
                ("No route to remote %@ preferred src %@",
                ssh_ipaddr_render, &key->dst,
                ssh_ipaddr_render, &key->src));
        return 1;
    }

    SSH_DEBUG(
            SSH_D_LOWOK,
            ("Returning route %@",
            ssh_netconfig_route_render, &routes[best_match]));
    /* Set return values */
    *flags |= SSH_PM_ROUTE_REACHABLE;
    *ifnum = routes[best_match].ifnum;
    memcpy(next_hop, &routes[best_match].gateway, sizeof(*next_hop));
    return 0;
}



