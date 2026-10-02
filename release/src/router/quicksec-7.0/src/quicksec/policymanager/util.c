/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   General utility functions.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"

#define SSH_DEBUG_MODULE "SshPmUtil"

/*  Selector values for 'selector' bitmap */

/** Source address */
#define SSH_ROUTE_KEY_SRC                    0x0001
/** IP protocol identifier */
#define SSH_ROUTE_KEY_IPPROTO                0x0002
/** Inbound interface number */
#define SSH_ROUTE_KEY_IN_IFNUM               0x0004
/** Outbound interface number */
#define SSH_ROUTE_KEY_OUT_IFNUM              0x0008

/** Source address belongs to one of the local interfaces. */
#define SSH_ROUTE_KEY_FLAG_LOCAL_SRC         0x4000
/** Destination address belongs to one of the local interfaces. */
#define SSH_ROUTE_KEY_FLAG_LOCAL_DST         0x8000

/** Platform dependent VRI information. */
#define SSH_ROUTE_KEY_RIID                   0x10000

/*  Macros for setting fields in SshRouteKey */

/** Clear all fields from the SshRouteKeyRec */
#define SSH_ROUTE_KEY_INIT(KEY)                                 \
do                                                              \
{                                                               \
    (KEY)->selector = 0;                                        \
} while (0)

/** Set destination address */
#define SSH_ROUTE_KEY_SET_DST(KEY, DSTPTR)                      \
do                                                              \
{                                                               \
    (KEY)->dst = *(DSTPTR);                                     \
} while (0)

/** Set source address */
#define SSH_ROUTE_KEY_SET_SRC(KEY, SRCPTR)                      \
do                                                              \
{                                                               \
    (KEY)->src = *(SRCPTR);                                     \
    (KEY)->selector |= SSH_ROUTE_KEY_SRC;                       \
} while (0)

/** Set IP protocol identifier */
#define SSH_ROUTE_KEY_SET_IPPROTO(KEY, IPPROTO)                 \
do                                                              \
{                                                               \
    (KEY)->ipproto = (IPPROTO);                                 \
    (KEY)->selector |= SSH_ROUTE_KEY_IPPROTO;                   \
} while (0)

/** Set outbound interface number */
#define SSH_ROUTE_KEY_SET_OUT_IFNUM(KEY, IFNUM)                 \
do                                                              \
{                                                               \
    SSH_ASSERT(((uint32_t) (IFNUM))                             \
               !=((uint32_t) SSH_INTERFACE_INVALID_IFNUM));   \
    SSH_ASSERT(((uint32_t) (IFNUM))                             \
               < ((uint32_t) SSH_INTERFACE_MAX_IFNUM));         \
    (KEY)->ifnum = (IFNUM);                                     \
    (KEY)->selector |= SSH_ROUTE_KEY_OUT_IFNUM;                 \
    (KEY)->selector &= ~SSH_ROUTE_KEY_IN_IFNUM;                 \
} while (0)

/** Set platform specific routing instance id */
#define SSH_ROUTE_KEY_SET_RIID(KEY, RIID)                       \
do                                                              \
{                                                               \
    (KEY)->selector |= SSH_ROUTE_KEY_RIID;                      \
    (KEY)->routing_instance_id = (RIID);                        \
} while (0)


int
ssh_pm_rule_render(char *buf, int buf_size,
                   int precision, void *datum)
{
    SshPmRule rule = (SshPmRule) datum;
    int wrote;
    char flags[128];

    /* Format flags. */
    flags[0] = '\0';
    if (rule->flags & SSH_PM_RULE_PASS)
      strcat(flags, ", pass");
    if (rule->flags & SSH_PM_RULE_REJECT)
      strcat(flags, ", reject");
    if (rule->flags & SSH_PM_RULE_LOG)
      strcat(flags, ", log-flows");
    if (rule->flags & SSH_PM_RULE_RATE_LIMIT)
      strcat(flags, ", rate-limit");

    wrote = ssh_snprintf(buf, buf_size,
                         "Rule ID %u: prec=%u, flags=[%s], ft=%u, tt=%u, "
                         "ttflags=0x%x",
                         (unsigned int) rule->rule_id,
                         (unsigned int) rule->precedence,
                         flags[0] ? flags + 2 : flags,
                         (unsigned int)
                         (rule->side_from.tunnel
                          ? rule->side_from.tunnel->tunnel_id : 0),
                         (unsigned int)
                         (rule->side_to.tunnel
                          ? rule->side_to.tunnel->tunnel_id : 0),
                         (unsigned int)
                         (rule->side_to.tunnel
                          ? rule->side_to.tunnel->flags : 0));


    if (wrote >= buf_size - 1)
      return buf_size + 1;

    if (precision >= 0)
      if (wrote > precision)
        wrote = precision;

    return wrote;
}


void
ssh_pm_destructor_timeout(void *context)
{
    SshPm pm = (SshPm) context;
    SshPmDestroyCB callback = pm->destroy_callback;
    void *callback_context = pm->destroy_callback_context;

    SSH_PM_ASSERT_PM(pm);

    SSH_DEBUG(SSH_D_HIGHOK, ("Freeing policy manager %p", pm));
    ssh_pm_free(pm);

#ifdef SSHDIST_IPSEC_DNSPOLICY
    /* Shut down domain name services */
    ssh_name_server_shutdown();
#endif /* SSHDIST_IPSEC_DNSPOLICY */

    if (callback)
      (*callback)(callback_context);
}

/* Fills in the SshRouteKey `key' from the given information. */
void
ssh_pm_create_route_key(
        SshPm pm,
        SshRouteKey key,
        SshIpAddr src,
        SshIpAddr dst,
        uint8_t ipproto,
        uint32_t ifnum,
        SshVriId routing_instance_id)
{
    /* Assert that destination is valid. */
    SSH_ASSERT(dst != NULL);
    SSH_ASSERT(SSH_IP_DEFINED(dst));

    /* Initialize key and set destination address selector */
    SSH_ROUTE_KEY_INIT(key);

    SSH_ROUTE_KEY_SET_DST(key, dst);
    if (ssh_pm_find_interface_by_address(pm, dst, routing_instance_id,
                                         NULL) != NULL)
      key->selector |= SSH_ROUTE_KEY_FLAG_LOCAL_DST;

    SSH_ROUTE_KEY_SET_RIID(key, routing_instance_id);

    /* Set the source address if applicable. */
    if (src && SSH_IP_DEFINED(src)
        && ssh_pm_find_interface_by_address(pm, src, routing_instance_id,
                                            NULL) != NULL)
    {
        key->selector |= SSH_ROUTE_KEY_FLAG_LOCAL_SRC;
        SSH_ROUTE_KEY_SET_SRC(key, src);
    }

    /* Interface number is also put, note that the src ip
       and ifnum might be in diffrent interfaces. */
    if (ifnum != SSH_INVALID_IFNUM)
      SSH_ROUTE_KEY_SET_OUT_IFNUM(key, ifnum);

    /* Set transport layer selectors if possible.
       Only couple of protocols supported. */
    switch (ipproto)
    {
      case SSH_IPPROTO_TCP:
      case SSH_IPPROTO_UDP:
      case SSH_IPPROTO_UDPLITE:
      case SSH_IPPROTO_SCTP:
        SSH_ROUTE_KEY_SET_IPPROTO(key, ipproto);
        break;

      default:
        /* Do nothing, can't set anything reasonable infomation. */
        break;
    }

    SSH_DEBUG(SSH_D_NICETOKNOW,
              ("route key: selector 0x%04x "
               "dst %@ src %@ ifnum %d ipproto %d "
               "routing instance id %d",
               key->selector,
               ssh_ipaddr_render, &key->dst,
               ssh_ipaddr_render,
               ((key->selector & SSH_ROUTE_KEY_SRC) ?
                &key->src : NULL),
               (int)
               ((key->selector & (SSH_ROUTE_KEY_IN_IFNUM |
                                  SSH_ROUTE_KEY_OUT_IFNUM)) ?
                key->ifnum : -1),
               ((key->selector & SSH_ROUTE_KEY_IPPROTO) ?
                key->ipproto : -1),
                routing_instance_id));
}

void
ssh_pm_create_dst_route_key(
        SshRouteKey key,
        SshIpAddr dst,
        SshVriId routing_instance_id)
{
    SSH_ROUTE_KEY_INIT(key);
    SSH_ROUTE_KEY_SET_DST(key, dst);
    SSH_ROUTE_KEY_SET_RIID(key, routing_instance_id);
}

SshInterface *
ssh_pm_find_interface(SshPm pm, const char *ifname, uint32_t *ifnum_return)
{
    uint32_t ifnum;
    bool retval;

    for (retval = ssh_pm_interface_enumerate_start(pm, &ifnum);
         retval;
         retval = ssh_pm_interface_enumerate_next(pm, ifnum, &ifnum))
    {
        SshInterface *ifp =
            ssh_pm_find_interface_by_ifnum(pm, ifnum);

        if (ifp != NULL && strcmp(ifp->name, ifname) == 0)
      {
          /* Found it. */
          if (ifnum_return)
            *ifnum_return = ifnum;

          return ifp;
      }
    }

    return NULL;
}


SshInterface *
ssh_pm_find_interface_by_ifnum(SshPm pm, uint32_t ifnum)
{
    return ssh_ip_get_interface_by_ifnum(&pm->ifs, ifnum);
}

const char *
ssh_pm_find_interface_vri_name(int routing_instance_id,
                               void * context)
{
    SshPm pm = (SshPm) context;

    return ssh_ip_get_interface_vri_name(&pm->ifs, routing_instance_id);
}

int
ssh_pm_find_interface_vri_id(const char * routing_instance_name,
                             void * context)
{
    SshPm pm = (SshPm) context;

    return ssh_ip_get_interface_vri_id(&pm->ifs, routing_instance_name);
}

int
ssh_pm_find_interface_vri_id_by_ifnum(uint32_t ifnum, void * context)
{
    SshPm pm = (SshPm) context;
    SshInterface *iface = NULL;

    iface = ssh_ip_get_interface_by_ifnum(&pm->ifs, ifnum);
    if (iface != NULL)
      return iface->routing_instance_id;
    else
      return SSH_VRI_ID_ANY;
}

SshInterface *
ssh_pm_find_interface_by_address(SshPm pm, SshIpAddr addr,
                                     int routing_instance_id,
                                     uint32_t *ifnum_return)
{
    SshInterface *ifp;

    ifp = ssh_ip_get_interface_by_ip(&pm->ifs, addr, routing_instance_id);
    if (ifp != NULL && ifnum_return != NULL)
      *ifnum_return = ifp->ifnum;

    return ifp;
}

SshInterface *
ssh_pm_find_interface_by_address_prefix(SshPm pm, SshIpAddr addr,
                                        SshVriId routing_instance_id,
                                        uint32_t *ifnum_return)
{
    SshInterface *ifp;

    ifp = ssh_ip_get_interface_by_ip(&pm->ifs, addr, routing_instance_id);
    if (ifp != NULL)
    {
        if (ifnum_return)
          *ifnum_return = ifp->ifnum;
        return ifp;
    }

    ifp = ssh_ip_get_interface_by_subnet(&pm->ifs, addr, routing_instance_id);
    if (ifp != NULL)
    {
        SSH_DEBUG(SSH_D_NICETOKNOW,
                  ("Could not find interface by exact address, using "
                   "interface based on masked address"));
        if (ifnum_return)
          *ifnum_return = ifp->ifnum;
        return ifp;
    }

    return NULL;
}

/* Return IP address (either of family IPv6 or IPv4 for interface
   'ifnum', or NULL if interface is unknown. Prefer addresses we
   are bound to (in order of appgw, ike) */
SshIpAddr
ssh_pm_find_interface_address(SshPm pm, uint32_t ifnum, bool ipv6,
                              const SshIpAddr dst)
{
    SshInterface *ifp;
    uint32_t i;
    SshIpAddr first = NULL;
    uint32_t j;

    ifp = ssh_ip_get_interface_by_ifnum(&pm->ifs, ifnum);
    if (ifp == NULL)
      return NULL;

    /* If our IKE is bound to certain addresses, prefer those. */
    for (j = 0; j < pm->params.ike_addrs_count; j++)
    {
        for (i = 0; i < ifp->num_addrs; i++)
        {
            SshInterfaceAddress addr = &ifp->addrs[i];

            if (SSH_IP_EQUAL(&pm->params.ike_addrs[j], &addr->addr.ip.ip))
              return &addr->addr.ip.ip;
        }
    }

    /* Select the local address.  If the destination address is given,
       check if the interface has direct connection to the same network
       with the destination.  If the direct connection is not found, or
       the destination address was not given, return the first IP
       address of the given IP version. */
    for (i = 0; i < ifp->num_addrs; i++)
    {
        SshInterfaceAddress addr = &ifp->addrs[i];

        if ((addr->protocol == SSH_PROTOCOL_IP4 && ipv6)
            || (addr->protocol == SSH_PROTOCOL_IP6 && !ipv6))
          /* Wrong IP address version. */
          continue;

        /* The IP version matches. */

        if (first == NULL)
        {
            /* Record the first address of the given type. */
            first = &addr->addr.ip.ip;
        }
        else if (ipv6
                 && SSH_IP6_IS_LINK_LOCAL(first)
                 && !SSH_IP6_IS_LINK_LOCAL(&addr->addr.ip.ip))
        {
            /* Prefer non-local (or non-link local) addresses. */
            first = &addr->addr.ip.ip;
        }

        if (dst)
        {
            /* Check if address belongs to the same network with the
               destination. */

            SSH_ASSERT(SSH_IP_DEFINED(dst));

            if (SSH_IP_IS4(dst))
            {
                uint32_t ip_int = SSH_IP4_TO_INT(&addr->addr.ip.ip);
                uint32_t dst_int = SSH_IP4_TO_INT(dst);
                uint32_t mask_int = SSH_IP4_TO_INT(&addr->addr.ip.mask);

                if ((ip_int & mask_int) == (dst_int & mask_int))
                  /* They both belong to the same network. */
                  return &addr->addr.ip.ip;
            }
            else
            {
                unsigned char ipbuf[16];
                unsigned char dstbuf[16];
                unsigned char maskbuf[16];
                uint32_t indx;

                SSH_IP6_ENCODE(&addr->addr.ip.ip, ipbuf);
                SSH_IP6_ENCODE(dst, dstbuf);
                SSH_IP6_ENCODE(&addr->addr.ip.mask, maskbuf);

                /* Check all words. */
                for (indx = 0; indx < 4; indx++)
                {
                    uint32_t ip_int = SSH_GET_32BIT(ipbuf + indx * 4);
                    uint32_t dst_int = SSH_GET_32BIT(dstbuf + indx * 4);
                    uint32_t mask_int = SSH_GET_32BIT(maskbuf + indx * 4);

                    if ((ip_int & mask_int) != (dst_int & mask_int))
                      /* The address does not match. */
                      break;
                }

                if (indx < 4)
                  /* It did not match.  Continue searching. */
                  continue;

                /* The both belong to the same network. */
                return &addr->addr.ip.ip;
            }
        }
    }

    /* Return the first address of the given type or NULL if no
       addresses could be found. */
    return first;
}

char *
ssh_pm_util_data_to_hex(char *buf, size_t buflen,
                        const unsigned char *data, size_t datalen)
{
    int i;
    size_t nprint;

    nprint = datalen;
    if (buflen / 3 < nprint)
      nprint = buflen / 3;

    if (nprint)
    {
        for (i = 0; i < nprint; i++)
          ssh_snprintf(buf + i * 3, buflen - i * 3, "%02x ", data[i]);
        buf[nprint * 3 - 1] = '\000';
    }
    else
    {
        SSH_ASSERT(buflen >= 1);
        buf[0] = '\000';
    }

    return buf;
}

/********************** General thread help functions ***********************/

void
ssh_pm_timeout_cb(void *context)
{
    SshFSMThread thread = (SshFSMThread) context;
    SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

/* Check if authorization of p1 allows access to the rule. */
bool ssh_pm_check_rule_authorization(SshPmP1 p1, SshPmRule rule)
{
    uint32_t i, j;

    if (rule->num_access_groups == 0)
      return true;

    SSH_DEBUG(SSH_D_LOWSTART, ("Matching authorization group IDS"));

    for (i = 0; i < rule->num_access_groups; i++)
    {
        for (j = 0; j < p1->num_authorization_group_ids; j++)
        {
            if (p1->authorization_group_ids[j] == rule->access_groups[i])
            {
                return true;
            }
        }
        for (j = 0; j < p1->num_xauth_authorization_group_ids; j++)
        {
            if (p1->xauth_authorization_group_ids[j] == rule->access_groups[i])
            {
                return true;
            }
        }
    }

    SSH_DEBUG(
            SSH_D_FAIL,
            ("Authorization failed; access groups did not match"));
    return false;
}
