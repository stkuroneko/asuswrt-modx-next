/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   Rule object handling.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"
#include "util_dnsresolver.h"
#include "sshicmp-util.h"
#include "ipsec_policy.h"

#define SSH_DEBUG_MODULE "SshPmRules"

/* Flag to check valid Multicast traffic selectors */
#define SSH_PM_RULE_TS_CHECK_MULTICAST_SRC 0x00000001

/* Create SA selectors for the negotiation `qm' that was started from
   a trigger (or from hand-constructed trigger in the non-delayed open
   case).  The SA selectors are taken from the high-level policy rule,
   or from the triggered packet if the tunnel specifies per-port or
   per-host SAs. The parameter 'forward' states in which direction
   the negotiation is proceeding. It is false only for hand-constructed
   triggers. */
static bool
pm_make_traffic_selectors(SshPm pm,
                          SshPmQm qm, SshPmRule rule,
                          bool forward,
                          SshIkev2PayloadTS *local_ts,
                          SshIkev2PayloadTS *remote_ts)
{
    SshPmRuleSideSpecification src;
    SshPmRuleSideSpecification dst;
    SshPmTunnel tunnel;
    int i;

    *local_ts = *remote_ts = NULL;

    /* Take the traffic selectors from the rule. */
    if (forward)
    {
        src = &rule->side_from;
        dst = &rule->side_to;
    }
    else
    {
        dst = &rule->side_from;
        src = &rule->side_to;
    }

    tunnel = dst->tunnel;
    SSH_ASSERT(tunnel != NULL);

    /* Here we process everything related to PER_HOST_SA or PER_PORT_SA
       or all transport mode stuff. */
    if ((!(tunnel->transform & SSH_PM_IPSEC_TUNNEL) ||
         (tunnel->flags & SSH_PM_T_PER_HOST_SA) ||
         (tunnel->flags & SSH_PM_T_PER_PORT_SA)))
    {
        /* Allocate local and remote traffic selectors. */
        *local_ts = ssh_ikev2_ts_allocate(pm->sad_handle);
        if (*local_ts == NULL)
          return false;

        *remote_ts = ssh_ikev2_ts_allocate(pm->sad_handle);
        if (*remote_ts == NULL)
        {
            ssh_ikev2_ts_free(pm->sad_handle, *local_ts);
            *local_ts = NULL;
            return false;
        }

        if (tunnel->flags & SSH_PM_T_PER_PORT_SA)
        {
            /* Add a local traffic selector item from the trigger packet. */
            if (ssh_ikev2_ts_item_add(*local_ts,
                                      qm->sel_ipproto,
                                      &qm->sel_src,
                                      &qm->sel_src,
                                      qm->sel_src_port,
                                      qm->sel_src_port)
                != SSH_IKEV2_ERROR_OK)
            {
                SSH_DEBUG(SSH_D_FAIL, ("Cannot add a TS item to local TS"));
                ssh_ikev2_ts_free(pm->sad_handle, *local_ts);
                ssh_ikev2_ts_free(pm->sad_handle, *remote_ts);
                *local_ts = *remote_ts = NULL;
                return false;
            }

            /* Add a remote traffic selector item from the trigger packet. */
            if (ssh_ikev2_ts_item_add(*remote_ts,
                                      qm->sel_ipproto,
                                      &qm->sel_dst,
                                      &qm->sel_dst,
                                      qm->sel_dst_port,
                                      qm->sel_dst_port)
                != SSH_IKEV2_ERROR_OK)
            {
                SSH_DEBUG(SSH_D_FAIL, ("Cannot add a TS item to remote TS"));
                ssh_ikev2_ts_free(pm->sad_handle, *local_ts);
                ssh_ikev2_ts_free(pm->sad_handle, *remote_ts);
                *local_ts = *remote_ts = NULL;
                return false;
            }

            /* Do not bother sending trigger traffic selectors. */
            qm->send_trigger_ts = 0;
        }

        /* PER_HOST and transport mode */
        else
        {
            /* Loop through source traffic selector items and take protocol
               and port selectors, use source IP from trigger packet. */
            for (i = 0;
                 rule->side_from.ts != NULL
                   && i < rule->side_from.ts->number_of_items_used;
                 i++)
            {
                /* Assert that IP address families match. Traffic selectors
                   have already been checked for mixed IP address families
                   in ssh_pm_rule_add(). */
                SSH_ASSERT((SSH_IP_IS4(&qm->sel_src)
                            && SSH_IP_IS4(rule->side_from.ts->items[i].
                                          start_address))
                           ||
                           (SSH_IP_IS6(&qm->sel_src)
                            && SSH_IP_IS6(rule->side_from.ts->items[i].
                                          start_address)));

                if (ssh_ikev2_ts_item_add(
                            *local_ts,
                            rule->side_from.ts->items[i].proto,
                            &qm->sel_src,
                            &qm->sel_src,
                            rule->side_from.ts->items[i].start_port,
                            rule->side_from.ts->items[i].end_port)
                    != SSH_IKEV2_ERROR_OK)
                {
                    SSH_DEBUG(
                            SSH_D_FAIL, ("Cannot add a TS item to local TS"));
                    ssh_ikev2_ts_free(pm->sad_handle, *local_ts);
                    ssh_ikev2_ts_free(pm->sad_handle, *remote_ts);
                    *local_ts = *remote_ts = NULL;
                    return false;
                }
            }

            /* Loop through destination traffic selector items and
               take protocol and port selectors, use destination IP
               from trigger packet. */
            for (i = 0;
                 rule->side_to.ts != NULL
                   && i < rule->side_to.ts->number_of_items_used;
                 i++)
            {
                /* Assert that IP address families match. Traffic selectors
                   have already been checked for mixed IP address families
                   in ssh_pm_rule_add(). */
                SSH_ASSERT((SSH_IP_IS4(&qm->sel_dst)
                            && SSH_IP_IS4(rule->side_to.ts->items[i].
                                          start_address))
                           ||
                           (SSH_IP_IS6(&qm->sel_dst)
                            && SSH_IP_IS6(rule->side_to.ts->items[i].
                                          start_address)));

                if (ssh_ikev2_ts_item_add(
                            *remote_ts,
                            rule->side_to.ts->items[i].proto,
                            &qm->sel_dst,
                            &qm->sel_dst,
                            rule->side_to.ts->items[i].start_port,
                            rule->side_to.ts->items[i].end_port)
                    != SSH_IKEV2_ERROR_OK)
                {
                    SSH_DEBUG(
                            SSH_D_FAIL, ("Cannot add a TS item to remote TS"));
                    ssh_ikev2_ts_free(pm->sad_handle, *local_ts);
                    ssh_ikev2_ts_free(pm->sad_handle, *remote_ts);
                    *local_ts = *remote_ts = NULL;
                    return false;
                }
            }

            /* Assert that local and remote traffic selectors each have
               atleast one item. */
            SSH_ASSERT((*local_ts)->number_of_items_used > 0);
            SSH_ASSERT((*remote_ts)->number_of_items_used > 0);
        }
    }
    else
    {
#ifdef SSHDIST_ISAKMP_CFG_MODE
        /* If rekeying an IPSec SA established using IKE CFG mode we need to
           narrow the rule's traffic selectors with the remote access
           attributes that we assigned during the IKE negotiation. */
        SshPmP1 p1 = ssh_pm_p1_by_peer_handle(pm, qm->peer_handle);
        bool client;

        /* Are we the remote access client or server? */
        client = SSH_PM_RULE_IS_VIRTUAL_IP(rule) ? true : false;

        if (!client && p1 && p1->remote_access_attrs)
        {

            if (ssh_pm_narrow_remote_access_attrs(pm, client,
                                                  p1->remote_access_attrs,
                                                  src->ts, dst->ts,
                                                  local_ts, remote_ts)
                != SSH_IKEV2_ERROR_OK)
              return false;
        }
        else
#endif /* SSHDIST_ISAKMP_CFG_MODE */
        {
            /* Otherwise just take the traffic selectors from the
               policy rule */
            *local_ts = ssh_ikev2_ts_dup(pm->sad_handle, src->ts);
            if (*local_ts == NULL)
              return false;

            *remote_ts = ssh_ikev2_ts_dup(pm->sad_handle, dst->ts);
            if (*remote_ts == NULL)
            {
                ssh_ikev2_ts_free(pm->sad_handle, *local_ts);
                *local_ts = NULL;
                return false;
            }
        }
    }

    SSH_DEBUG(SSH_D_MIDOK,
              ("SA traffic selectors for %s direction of the rule: "
               "local=%@, remote=%@",
               forward ? "FORWARD" : "REVERSE",
               ssh_ikev2_ts_render, *local_ts,
               ssh_ikev2_ts_render, *remote_ts));
    return true;
}


bool
ssh_pm_resolve_policy_rule_traffic_selectors(SshPm pm, SshPmQm qm)
{
    /* Create traffic selectors for this negotiation. */
    if (!pm_make_traffic_selectors(pm,
                                   qm, qm->rule,
                                   qm->forward,
                                   &qm->local_trigger_ts,
                                   &qm->remote_trigger_ts))
      return false;

#ifdef SSHDIST_ISAKMP_CFG_MODE_RULES
    if (qm->rule->flags & SSH_PM_RULE_CFGMODE_RULES)
    {
        /* Prevent a cfgmode placeholder rule from creating an IPsec SA. */
        qm->local_ts = NULL;
        qm->remote_ts = NULL;
    }
    else
#endif /* SSHDIST_ISAKMP_CFG_MODE_RULES */
    {
        /* The SA selectors are also the default values for traffic selectors.
           Therefore, the trigger rule is also our default value for `rule'. */
        qm->local_ts = qm->local_trigger_ts;
        qm->remote_ts = qm->remote_trigger_ts;
        ssh_ikev2_ts_take_ref(pm->sad_handle, qm->local_ts);
        ssh_ikev2_ts_take_ref(pm->sad_handle, qm->remote_ts);

        SSH_DEBUG(SSH_D_NICETOKNOW,
                  ("Selectors from triggered packet: local=%@, remote=%@",
                   ssh_ikev2_ts_render, qm->local_trigger_ts,
                   ssh_ikev2_ts_render, qm->remote_trigger_ts));
    }

    return true;
}

/* Internal function for setting traffic selectors.
   Parameters test_flags has extra flags like
   SSH_PM_RULE_TS_CHECK_MULTICAST_SRC
 */
static bool ssh_pm_rule_set_ts_internal(SshPmRule rule,
                           SshPmRuleSide side,
                           SshIkev2PayloadTS ts,
                           uint32_t test_flags);

/************************** Static help functions ***************************/

/* Sanity check for rule's tunnels.  This verifies that the tunnel
   `tunnel' has all necessary settings.  The function returns true if
   the tunnel is valid and false otherwise. */
static bool
pm_verify_tunnel(SshPmTunnel tunnel)
{
    SshPmTunnel p1_tunnel;
#ifdef WITH_IPV6
    uint16_t link_local_peer_cnt = 0;
    uint16_t i;
#endif /* WITH_IPV6 */

    if (tunnel == NULL)
      return true;

    /* Select the tunnel used for p1 negotiations and check IKE configuration
       from that tunnel. */
    SSH_PM_TUNNEL_GET_P1_TUNNEL(p1_tunnel, tunnel);
    SSH_ASSERT(p1_tunnel != NULL);

    {
#ifdef SSHDIST_IPSEC_MOBIKE
        if (p1_tunnel->flags & SSH_PM_T_MOBIKE
            && SSH_PM_TUNNEL_NUM_LOCAL_ADDRS(p1_tunnel) == 0)
        {
            ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                          "No local addresses or interfaces specified for "
                          "a MobIKE enabled tunnel");
            return false;
        }
#endif /* SSHDIST_IPSEC_MOBIKE */

#ifdef SSHDIST_IKEV1
        if (tunnel->u.ike.versions & SSH_PM_IKE_VERSION_1 &&
            tunnel->auth_domain_name != NULL)
        {
            ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                          "Setting non-default authentication domain for "
                          "IKEv1-tunnel is not allowed.");
            return false;
        }
#endif /* SSHDIST_IKEV1 */
    }

    {
        /* If using AES counter mode, we must also use authentication */
        if ((tunnel->transform & SSH_PM_CRYPT_AES_CTR) &&
            ((tunnel->transform & SSH_PM_MAC_MASK) == 0))
        {
            ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                          "AES counter mode cannot be used without an "
                          "authentication algorithm");
            return false;
        }
    }

#ifdef SSHDIST_IKE_CERT_AUTH
#ifdef SSHDIST_CERT
    if (tunnel->local_identity != NULL &&
        tunnel->u.ike.local_cert_kid != NULL)
    {
        ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                      "Cannot specify local identity and local certificate "
                      "together.");
        return false;
    }

#endif /* SSHDIST_CERT */
#endif /* SSHDIST_IKE_CERT_AUTH */

    if (tunnel->local_identity == NULL &&
#ifdef SSHDIST_IKE_CERT_AUTH
#ifdef SSHDIST_CERT
        tunnel->u.ike.local_cert_kid == NULL &&
#endif /* SSHDIST_CERT */
#endif /* SSHDIST_IKE_CERT_AUTH */
        tunnel->id_type != SSH_PM_IDENTITY_ANY)
    {
        ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                      "Tunnel has identity type set without an identity "
                      "specified");
        return false;
    }

#ifdef SSHDIST_IKE_ID_LIST
    if (p1_tunnel->u.ike.versions & SSH_PM_IKE_VERSION_2)
    {
        if ((p1_tunnel->local_identity && p1_tunnel->local_identity->id_type ==
             (int) IPSEC_ID_LIST) ||
            (p1_tunnel->remote_identity &&
             p1_tunnel->remote_identity->id_type ==
             (int) IPSEC_ID_LIST))
        {
            ssh_log_event(
                    SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                    "The ID_LIST identity type cannot be used with IKEv2 "
                    "tunnels");
            return false;
        }
    }
#endif /* SSHDIST_IKE_ID_LIST */

#ifdef WITH_IPV6
    /* Little bit sanity checking for ipv6 link-local addresses. */
    for (i = 0; i < tunnel->num_peers; i++)
    {
        if (SSH_IP6_IS_LINK_LOCAL(&tunnel->peers[i]))
          link_local_peer_cnt++;
    }

    /* All of the peers are not friends of link-local. */
    if (link_local_peer_cnt &&
        (link_local_peer_cnt != tunnel->num_peers))
    {
        ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                      "Some of the peers specified for a tunnel are link-local"
                      " and some are global addresses.");
        return false;
    }

    if (link_local_peer_cnt && tunnel->num_local_interfaces == 0)
    {
        ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                      "Link-local peers configured, but no local interfaces "
                      "are specified.");
        return false;
    }
#endif /* WITH_IPV6 */

#ifdef SSH_IKEV2_MULTIPLE_AUTH
    if (tunnel->second_auth_domain_name &&
        !tunnel->second_local_identity &&
        !(tunnel->flags & SSH_PM_TI_DONT_INITIATE))
    {
        ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                      "If second authentication domain is set for a tunnel "
                      "second identity or SSH_PM_TI_DONT_INITIATE must also "
                      "be set.");
        return false;
    }

    if (!tunnel->second_auth_domain_name &&
        tunnel->second_local_identity)
    {
        ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                      "If second identity is set for a tunnel second "
                      "authentication domain must also be set.");
        return false;
    }
#endif /* SSH_IKEV2_MULTIPLE_AUTH */

    return true;
}

/* Post check for auto-start rule `rule'.  This verifies that the user
   did provide enough information (remote IKE peer IP address) that we
   can establish this rule automatically.  The function returns true
   if all required information is given and false otherwise. */
static bool
pm_rule_post_check_auto_start(SshPmRule rule, SshPmTunnel tunnel,
                              SshPmRuleSideSpecification side)
{
    SSH_ASSERT(tunnel != NULL);

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
    SSH_ASSERT((tunnel->flags & SSH_PM_TI_DELAYED_OPEN) == 0
               || (tunnel->flags & SSH_PM_TI_INTERFACE_TRIGGER) != 0);
#else /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */
    SSH_ASSERT((tunnel->flags & SSH_PM_TI_DELAYED_OPEN) == 0);
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

    /* For tunnel mode it is sufficient that an IKE peer is specified. For
       transport mode the following checks below are also required */
    if (tunnel->transform & SSH_PM_IPSEC_TUNNEL)
    {
        if (tunnel->num_peers
#ifdef SSHDIST_IPSEC_DNSPOLICY
            || tunnel->num_dns_peers
#endif /* SSHDIST_IPSEC_DNSPOLICY */
            )
          /* Explicit IKE peers specified. */
          return true;
    }

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
    /* For L2TP tunnels the following checks below on the traffic selector item
       are not required. This is because the SA protecting L2TP traffic takes
       its selectors from the IKE peer addresses and L2TP ports, it does not
       use the selectors from the policy rule that is input to this routine. */
    if (tunnel->flags & SSH_PM_TI_L2TP)
      return true;
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */


    /* Enforce that there is exactly one traffic selector item. */
    if (!side->ts || side->ts->number_of_items_used != 1)
    {
        if (tunnel->transform & SSH_PM_IPSEC_TUNNEL)
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                        "Auto-start rule specifies zero or more than one "
                        "traffic selector item and no IKE peer is specified.");
        else
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                        "Auto-start rule specifies zero or more than one "
                        "traffic selector item with transport mode.");
        return false;
    }


    /* Now check that IP addresses in the traffic slector item specify
       a single IP address. */
    if ((!SSH_IP_DEFINED(side->ts->items[0].start_address)
         || !SSH_IP_EQUAL(side->ts->items[0].start_address,
                          side->ts->items[0].end_address))
#ifdef SSHDIST_IPSEC_DNSPOLICY
        && !side->dns_addr_sel_ref
#endif /* SSHDIST_IPSEC_DNSPOLICY */
        )
    {
        ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                      "Auto-start rule does not specify single IP address "
                      "or domain name for its remote peer.");
        return false;
    }

    return true;
}

/* Check if the rule's side specification `side' has any selectors. */
static bool
pm_rule_has_selectors(SshPmRuleSideSpecification side)
{
    if (side->ts
#ifdef SSHDIST_IPSEC_DNSPOLICY
        || side->dns_addr_sel_ref
#endif /* SSHDIST_IPSEC_DNSPOLICY */
        )
      return true;

    /* No selectors set. */
    return false;
}

int ssh_pm_rule_hash_adt(void *ptr, void *context)
{
    SshPmRule r = ptr;

    return r->rule_id;
}

int ssh_pm_rule_compare_adt(void *ptr1, void *ptr2, void *context)
{
    SshPmRule r1 = ptr1;
    SshPmRule r2 = ptr2;

    if (r1->rule_id == r2->rule_id)
      return 0;
    else if (r1->rule_id < r2->rule_id)
      return -1;
    else
      return 1;
}

int ssh_pm_rule_prec_compare_adt(void *ptr1, void *ptr2, void *context)
{
    SshPmRule r1 = ptr1;
    SshPmRule r2 = ptr2;

    if (r1->precedence == r2->precedence)
      return 0;
    else if (r1->precedence < r2->precedence)
      return 1;
    else
      return -1;
}

void ssh_pm_rule_destroy_adt(void *ptr, void *context)
{
    SshPm pm = context;
    SshPmRule rule = ptr;

    ssh_pm_rule_free(pm, rule);
}

/* Verify the user has given a sane traffic selector. The IKE library
   takes care of sanity checking the individual TS items, here we just
   check that the different traffic selector items will combine to
   form rules that make sense. */
static bool pm_rule_verify_ts_sane(SshPm pm, SshPmRule rule)
{
    SshIkev2PayloadTSItem from, to;
    bool ikev1_tunnel = false;
    uint32_t i, j;

    /* For simplicity restrict rules with per-host/perport tunnels to
       have at most one traffic selector item. */
    if (rule->side_to.tunnel &&
        ((rule->side_to.tunnel->flags & SSH_PM_T_PER_HOST_SA) ||
         (rule->side_to.tunnel->flags & SSH_PM_T_PER_PORT_SA)))
    {
        if ((rule->side_to.ts != NULL &&
             (rule->side_to.ts->number_of_items_used > 1)) ||
            (rule->side_from.ts != NULL &&
             (rule->side_from.ts->number_of_items_used > 1)))
        {
            ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                          "Per-host or per-port rules cannot be used with "
                          "multiple traffic selector items");
            return false;
        }
    }
    if (rule->side_from.tunnel &&
        ((rule->side_from.tunnel->flags & SSH_PM_T_PER_HOST_SA) ||
         (rule->side_from.tunnel->flags & SSH_PM_T_PER_PORT_SA)))
    {
        if ((rule->side_from.ts != NULL &&
             (rule->side_from.ts->number_of_items_used > 1)) ||
            (rule->side_to.ts != NULL &&
             (rule->side_to.ts->number_of_items_used > 1)))
        {
            ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                          "Per-host or per-port rules cannot be used with "
                          "multiple traffic selector items");
            return false;
        }
    }

    if ((rule->side_to.tunnel &&
         (rule->side_to.tunnel->u.ike.versions & SSH_PM_IKE_VERSION_1)) ||
        (rule->side_from.tunnel &&
         (rule->side_from.tunnel->u.ike.versions & SSH_PM_IKE_VERSION_1)))
      ikev1_tunnel = true;
    else
      ikev1_tunnel = false;

    if (rule->side_to.ts != NULL)
    {
        for (i = 0; i < rule->side_to.ts->number_of_items_used; i++)
        {
            to = &rule->side_to.ts->items[i];

            /* No port ranges allowed in IKEv1 */
            if (ikev1_tunnel && (to->start_port != to->end_port)
                && (to->start_port != 0 && to->end_port != 0xffff))
            {
                ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                              "IKEv1 does not support negotiation of "
                              "port ranges");
                return false;
            }
        }
    }

    if (rule->side_from.ts != NULL)
    {
        for (i = 0; i < rule->side_from.ts->number_of_items_used; i++)
        {
            from = &rule->side_from.ts->items[i];

            /* No port ranges allowed in IKEv1 */
            if (ikev1_tunnel && (from->start_port != from->end_port)
                && (from->start_port != 0 && from->end_port != 0xffff))
            {
                ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                              "IKEv1 does not support negotiation of "
                              "port ranges");
                return false;
            }

            if (rule->side_to.ts != NULL)
            {
                for (j = 0; j < rule->side_to.ts->number_of_items_used; j++)
                {
                    to = &rule->side_to.ts->items[j];

                    /* Check the types agree */
                    if (from->ts_type != to->ts_type)
                    {
                        ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                                      "Mixed IP address families are not "
                                      "supported");
                        return false;
                    }

#ifdef WITH_IPV6
                    /* Check that the IPv6 addresses are of same kind.
                       So no mixing link-local and global addresses. */
                    if (from->ts_type == SSH_IKEV2_TS_IPV6_ADDR_RANGE &&
                        (SSH_IP6_IS_LINK_LOCAL(from->start_address) !=
                         SSH_IP6_IS_LINK_LOCAL(to->start_address)))
                    {
                        ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                                      "Mixed IPv6 address types are not "
                                      "supported");
                        return false;
                    }
#endif /* WITH_IPV6 */

                    /* Check the IP protocols agree */
                    if (from->proto && to->proto && from->proto != to->proto)
                    {
                        ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                                      "Mixed IP protocols are not supported");
                        return false;
                    }

                    /* Check that ports for ICMP are the same for the
                       from and to side. The ICMP type/code selectors
                       are encoded as ports.
                    */
                    if (from->proto == SSH_IPPROTO_ICMP ||
                        from->proto == SSH_IPPROTO_IPV6ICMP)
                    {
                        if (from->start_port &&
                            to->start_port &&
                            from->start_port != to->start_port)
                        {
                            ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                                          "Inconsistent ICMP selectors");
                            return false;
                        }

                        if (from->end_port != 0xffff &&
                            to->end_port != 0xffff &&
                            from->end_port != to->end_port)
                        {
                            ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                                          "Inconsistent ICMP selectors");
                            return false;
                        }
                    }
                }
            }
        }
    }

    /* Checks if the 'to' tunnel specifies transport mode */
    if (rule->side_to.tunnel &&
        (((rule->side_to.tunnel->flags & SSH_PM_T_TRANSPORT_MODE)
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
          && !(rule->side_to.tunnel->flags & SSH_PM_TI_L2TP)
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */
          )))
    {
        for (i = 0;
             rule->side_from.ts != NULL
               && i < rule->side_from.ts->number_of_items_used;
             i++)
        {
            /* If the tunnel specifies a local IP address, it must agree with
               that in the traffic selector. */
            if (rule->side_to.tunnel->local_ip != NULL
                && ((SSH_IP_CMP(
                             &rule->side_to.tunnel->local_ip->ip,
                             rule->side_from.ts->items[i].start_address) < 0)
                    || (SSH_IP_CMP(
                                &rule->side_to.tunnel->local_ip->ip,
                                rule->side_from.ts->items[i].end_address)
                        > 0)))
            {
                ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                              "Local IP tunnel attribute does not match the "
                              "source selector given in the rule, this is not "
                              "allowed for transport mode");
                return false;
            }
        }

        for (i = 0;
             rule->side_to.ts != NULL
             && i < rule->side_to.ts->number_of_items_used;
             i++)
        {
            /* If the tunnel specifies peer IP addresses, they must agree with
               that in the traffic selector. */
            for (j = 0; j < rule->side_to.tunnel->num_peers; j++)
            {
                if (SSH_IP_CMP(&rule->side_to.tunnel->peers[j],
                               rule->side_to.ts->items[i].start_address)
                    || SSH_IP_CMP(&rule->side_to.tunnel->peers[j],
                                  rule->side_to.ts->items[i].end_address))
                {
                    ssh_log_event(
                            SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                            "Peer IP tunnel attribute does not match the "
                            "destination selector given in rule, this is "
                            "not allowed for transport mode");
                    return false;
                }
            }
        }
    }

    /* Checks if the 'from' tunnel specifies transport mode */
    if (rule->side_from.tunnel &&
        (((rule->side_from.tunnel->flags & SSH_PM_T_TRANSPORT_MODE)
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
          && !(rule->side_from.tunnel->flags & SSH_PM_TI_L2TP)
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */
          )))
    {
        for (i = 0;
             rule->side_to.ts != NULL
               && i < rule->side_to.ts->number_of_items_used;
             i++)
        {
            /* If the tunnel specifies a local IP address, it must agree with
               that in the traffic selector. */
            if (rule->side_from.tunnel->local_ip != NULL
                && ((SSH_IP_CMP(&rule->side_from.tunnel->local_ip->ip,
                                rule->side_to.ts->items[i].start_address) < 0)
                    || (SSH_IP_CMP(
                                &rule->side_from.tunnel->local_ip->ip,
                                rule->side_to.ts->items[i].end_address) > 0)))
            {
                ssh_log_event(
                        SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                        "Local IP tunnel attribute does not match the "
                        "destination selector given in the rule, this is "
                        "not allowed for transport mode");
                return false;
            }
        }

        for (i = 0;
             rule->side_from.ts != NULL
             && i < rule->side_from.ts->number_of_items_used;
             i++)
        {
            /* If the tunnel specifies peer IP addresses, they must agree with
               that in the traffic selector. */
            for (j = 0; j < rule->side_from.tunnel->num_peers; j++)
              if (SSH_IP_CMP(&rule->side_from.tunnel->peers[j],
                             rule->side_from.ts->items[i].start_address)
                  || SSH_IP_CMP(&rule->side_from.tunnel->peers[j],
                                rule->side_from.ts->items[i].end_address))
            {
                ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                              "Peer IP tunnel attribute does not match the "
                              "source selector given in rule, this is not "
                              "allowed for transport mode");
                return false;
            }

        }
    }

    return true;
}

/* Lookup the rule by its ID. */
SshPmRule
ssh_pm_rule_lookup(SshPm pm, uint32_t id)
{
    SshADTHandle handle;
    SshPmRuleStruct probe;

    probe.rule_id = id;

    if (pm->config_additions == NULL
        || (handle =
            ssh_adt_get_handle_to_equal(pm->config_additions, &probe))
        == SSH_ADT_INVALID)
    {
        if (pm->iface_pending_additions == NULL
            || (handle =
                ssh_adt_get_handle_to_equal(
                        pm->iface_pending_additions, &probe))
            == SSH_ADT_INVALID)
        {
            if ((handle =
                 ssh_adt_get_handle_to_equal(pm->rule_by_id, &probe))
                == SSH_ADT_INVALID)
            {
                return NULL;
            }
            return ssh_adt_get(pm->rule_by_id, handle);
        }
        return ssh_adt_get(pm->iface_pending_additions, handle);
    }
    return ssh_adt_get(pm->config_additions, handle);
}

SshPmRule
ssh_pm_rule_get_next(SshPm pm, SshPmRule previous_rule)
{
    SshADTHandle h;

    if (!previous_rule)
      h = ssh_adt_enumerate_start(pm->rule_by_id);
    else
      h = ssh_adt_enumerate_next(
              pm->rule_by_id,
              (SshADTHandle)&previous_rule->rule_by_index_hdr);

    if (h != SSH_ADT_INVALID)
      return (SshPmRule) ssh_adt_get(pm->rule_by_id, h);
    else
      return NULL;
}


/* Compare rule side specifications for equality. */
static bool
pm_rule_side_specification_compare(SshPm pm,
                                   SshPmRuleSideSpecification side1,
                                   SshPmRuleSideSpecification side2)
{
#ifdef SSHDIST_IPSEC_DNSPOLICY
    if (side1->dns_addr_sel_ref && !side2->dns_addr_sel_ref)
      return false;
    if (side2->dns_addr_sel_ref && !side1->dns_addr_sel_ref)
      return false;

    if (!side1->dns_addr_sel_ref)
    {
#endif /* SSHDIST_IPSEC_DNSPOLICY */
        /* Two traffic selectors t1, t2 are considered equal iff t1 is
           a subrange of t2 and t2 is a subrange of t1. */
        if (!ssh_ikev2_ts_match(side1->ts, side2->ts) ||
            !ssh_ikev2_ts_match(side2->ts, side1->ts))
          return false;
#ifdef SSHDIST_IPSEC_DNSPOLICY
    }
    else
      if (!ssh_pm_dns_cache_compare(side1->dns_addr_sel_ref,
                                    side2->dns_addr_sel_ref))
        return false;
#endif /* SSHDIST_IPSEC_DNSPOLICY */

    if ((side1->auto_start && !side2->auto_start)
        || (!side1->auto_start && side2->auto_start))
      return false;

    if (side1->tunnel && side2->tunnel)
    {
        if (!ssh_pm_tunnel_compare(pm, side1->tunnel, side2->tunnel))
          return false;
    }
    else if (side1->tunnel && !side2->tunnel)
      return false;
    else if (!side1->tunnel && side2->tunnel)
      return false;

    /* They are equal. */
    return true;
}

/* Create default match all traffic selectors, if no traffic selectors
   have been set to the rule side specification. */
static bool
pm_rule_make_default_traffic_selector(SshPm pm,
                                      bool ipv6,
                                      SshPmRuleSideSpecification side)
{
    SshIpAddrStruct start_address, end_address;

    if (side->ts
#ifdef SSHDIST_IPSEC_DNSPOLICY
        || side->dns_addr_sel_ref
#endif /* SSHDIST_IPSEC_DNSPOLICY */
        )
      return true;

    side->ts = ssh_ikev2_ts_allocate(pm->sad_handle);
    if (side->ts == NULL)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Cannot allocate a traffic selector"));
        return false;
    }

    if (ipv6)
    {
#if defined (WITH_IPV6)
        SSH_VERIFY(ssh_ipaddr_parse(&start_address, "0:0:0:0:0:0:0:0"));
        SSH_VERIFY(ssh_ipaddr_parse(&end_address,
                                    "ffff:ffff:ffff:ffff:"
                                    "ffff:ffff:ffff:ffff"));

        if (ssh_ikev2_ts_item_add(side->ts, 0,
                                  &start_address, &end_address,
                                  0, 0xffff) != SSH_IKEV2_ERROR_OK)
          return false;

#endif /* WITH_IPV6 */
    }
    else
    {
        SSH_VERIFY(ssh_ipaddr_parse(&start_address, "0.0.0.0"));
        SSH_VERIFY(ssh_ipaddr_parse(&end_address, "255.255.255.255"));

        if (ssh_ikev2_ts_item_add(side->ts, 0,
                                  &start_address, &end_address,
                                  0, 0xffff) != SSH_IKEV2_ERROR_OK)
          return false;
    }

    side->default_ts = 1;

    return true;
}

static bool
pm_rule_make_default_traffic_selectors(SshPm pm, SshPmRule rule)
{
    bool is6 = false;

#ifdef WITH_IPV6
#ifdef SSHDIST_IPSEC_DNSPOLICY
    /* We cannot set default traffic selectors yet, if we do not know
       address families traffic selectors get resolved to. */
    if ((rule->side_from.dns_addr_sel_ref != NULL
         && rule->side_from.ts == NULL)
        ||
        (rule->side_to.dns_addr_sel_ref != NULL
         && rule->side_to.ts == NULL))
    {
        SSH_DEBUG(SSH_D_NICETOKNOW,
                  ("At least one rule traffic selector remains unresolved, "
                   "not setting default selectors yet for rule id %d",
                   rule->rule_id));
        return true;
    }
#endif /* SSHDIST_IPSEC_DNSPOLICY */
#endif /* WITH_IPV6 */

    if (rule->side_to.ts &&
        rule->side_to.ts->number_of_items_used > 0)
      if (SSH_IP_IS6(rule->side_to.ts->items[0].start_address))
        is6 = true;

    if (!is6 &&
        rule->side_from.ts &&
        rule->side_from.ts->number_of_items_used > 0)
      if (SSH_IP_IS6(rule->side_from.ts->items[0].start_address))
        is6 = true;

    if (!pm_rule_make_default_traffic_selector(pm,
                                               is6,
                                               &rule->side_to))
      return false;

    if (!pm_rule_make_default_traffic_selector(pm,
                                               is6,
                                               &rule->side_from))
      return false;

    return true;
}

/* Return traffic selectors from rule (not copied, do not free) */
bool
ssh_pm_rule_get_traffic_selectors(SshPm pm, SshPmRule rule,
                                  bool forward,
                                  SshIkev2PayloadTS *local,
                                  SshIkev2PayloadTS *remote)
{
    SshPmRuleSideSpecification src;
    SshPmRuleSideSpecification dst;

    *local = *remote = NULL;

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
    *local = src->ts;
    *remote = dst->ts;

    SSH_DEBUG(SSH_D_MIDOK, ("SA traffic selectors: local=%@, remote=%@",
                            ssh_ikev2_ts_render, *local,
                            ssh_ikev2_ts_render, *remote));
    return true;
}

/************************ Public interface functions ************************/

static SshPmRule
ssh_pm_rule_create_internal(
        SshPm pm,
        uint32_t precedence,
        uint32_t flags,
        SshPmTunnel from_tunnel,
        SshPmTunnel to_tunnel)
{
    SshPmRule rule;

    /* Check flags validity. */
    if ((flags & SSH_PM_RULE_REJECT) && (flags & SSH_PM_RULE_PASS))
    {
        ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                      "Both REJECT and PASS defined for a rule");
        return NULL;
    }

    if ((flags & SSH_PM_RULE_REJECT) && to_tunnel)
    {
        ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                      "To-tunnel specified for a REJECT rule");
        return NULL;
    }

    /* Check tunnels. */
    if (!pm_verify_tunnel(from_tunnel))
      return NULL;
    if (!pm_verify_tunnel(to_tunnel))
      return NULL;

    /* Currently set-df and clear-df cannot be specified. */
    if ((flags & SSH_PM_RULE_DF_SET) != 0
        || (flags & SSH_PM_RULE_DF_CLEAR) != 0)
    {
        ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                      "`set-df' or `clear-df' cannot be specified "
                      "for a rule");
        return NULL;
    }

    /* The adjust-local-address flag needs a remote access client to-tunnel. */
    if (flags & SSH_PM_RULE_ADJUST_LOCAL_ADDRESS)
    {
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
        if (to_tunnel == NULL)
        {
            ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                          "`adjust-local-address' specified for a rule "
                          "without to-tunnel");
            return NULL;
        }
        else if ((to_tunnel->flags &
                  (SSH_PM_TI_CFGMODE | SSH_PM_TI_L2TP)) == 0)
        {
            ssh_log_event(
                    SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                    "`adjust-local-address' specified for a rule with a "
                    "to-tunnel that is not a remote access client tunnel");
            return NULL;
        }
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */
        ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                      "Unsupported flag `adjust-local-address' specified for "
                      "a rule");
        return NULL;
    }

#ifdef SSHDIST_ISAKMP_CFG_MODE_RULES
    if (flags & SSH_PM_RULE_CFGMODE_RULES)
    {
        if (!(flags & SSH_PM_RULE_ADJUST_LOCAL_ADDRESS))
        {
            ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                          "`adjust-local-address' must be used with "
                          "`cfgmode-rules'");
            return NULL;
        }
        if (from_tunnel != NULL)
        {
            ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                          "`cfgmode-rules' specified for a rule "
                          "with from-tunnel");
            return NULL;
        }
        if (to_tunnel->u.ike.versions & SSH_PM_IKE_VERSION_2)
        {
            ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                          "`cfgmode-rules' specified for an IKEv2 rule");
            return NULL;
        }
        if ((to_tunnel->flags & SSH_PM_TI_CFGMODE) == 0)
        {
            ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                          "`cfgmode-rules' specified for a rule with a "
                          "to-tunnel without config mode client capability");
            return NULL;
        }
    }
#endif /* SSHDIST_ISAKMP_CFG_MODE_RULES */

    rule = ssh_pm_rule_alloc(pm);
    if (rule == NULL)
    {
        ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                      "The maximum number of policy rules reached");
        return NULL;
    }

    ssh_fsm_condition_init(&pm->fsm, &rule->cond);

    rule->precedence = precedence;
    rule->flags = flags;

    if (from_tunnel != NULL)
    {
        ssh_strncpy(rule->routing_instance_name,
                    from_tunnel->routing_instance_name,
                    SSH_VRI_NAMESIZE);
        rule->routing_instance_id = from_tunnel->routing_instance_id;
    }
    else if (to_tunnel != NULL)
    {
        ssh_strncpy(rule->routing_instance_name,
                    to_tunnel->routing_instance_name,
                    SSH_VRI_NAMESIZE);
        rule->routing_instance_id = to_tunnel->routing_instance_id;
    }
    else
    {
        ssh_strncpy(rule->routing_instance_name,
                    SSH_VRI_NAME_GLOBAL,
                    SSH_VRI_NAMESIZE);
        rule->routing_instance_id = SSH_VRI_ID_GLOBAL;
    }

    /* The rule will belong to one future commit batch.  This is just
       the cheapest way to set the flag. */
    rule->flags |= SSH_PM_RULE_I_IN_BATCH;

    if (from_tunnel)
    {
        rule->side_from.tunnel = from_tunnel;
        SSH_PM_TUNNEL_TAKE_REF(rule->side_from.tunnel);
        SSH_PM_TUNNEL_ATTACH_RULE(rule->side_from.tunnel, rule, false);
    }

    if (to_tunnel)
    {
        rule->side_to.tunnel = to_tunnel;
        SSH_PM_TUNNEL_TAKE_REF(rule->side_to.tunnel);
        SSH_PM_TUNNEL_ATTACH_RULE(rule->side_to.tunnel, rule, true);
    }

    rule->pm = pm;
    return rule;
}


SshPmRule
ssh_pm_rule_create(
        SshPm pm,
        uint32_t precedence,
        uint32_t flags,
        SshPmTunnel from_tunnel,
        SshPmTunnel to_tunnel)
{
    SshPmRule rule;

    SSH_ASSERT(precedence < 100000000);

    /* Assert that no internal rule flags are set. */
    SSH_ASSERT((flags & 0xfff00000) == 0);

    rule =
        ssh_pm_rule_create_internal(
                pm,
                precedence,
                flags,
                from_tunnel,
                to_tunnel);

    return rule;
}

SshPmRule
ssh_pm_rule_copy(
        SshPm pm,
        SshPmRule rule)
{
    SshPmRule copy = NULL;
#ifdef SSHDIST_IPSEC_DNSPOLICY
    SshPmDnsReference from_dns_asr = NULL, to_dns_asr = NULL;
#endif /* SSHDIST_IPSEC_DNSPOLICY */
    uint32_t *agroups = NULL;

    copy =
        ssh_pm_rule_create(
                pm,
                rule->precedence,
                rule->flags & 0x000fffff,
                rule->side_from.tunnel,
                rule->side_to.tunnel);
    if (copy == NULL)
    {
        SSH_DEBUG(SSH_D_ERROR, ("Cannot create rule"));
        goto fail;
    }

    if (
#ifdef SSHDIST_IPSEC_DNSPOLICY
        (rule->side_from.dns_addr_sel_ref &&
         !(from_dns_asr = ssh_pm_dns_cache_copy(
                   rule->pm->dnscache,
                   rule->side_from.dns_addr_sel_ref,
                   rule))) ||
        (rule->side_to.dns_addr_sel_ref &&
         !(to_dns_asr = ssh_pm_dns_cache_copy(
                   rule->pm->dnscache,
                   rule->side_to.dns_addr_sel_ref,
                   rule))) ||
#endif /* SSHDIST_IPSEC_DNSPOLICY */
        (rule->access_groups &&
         !(agroups = ssh_calloc(sizeof *agroups, rule->num_access_groups))))
    {
        SSH_DEBUG(SSH_D_ERROR, ("Out of memory when copying rule"));
        goto fail;
    }

#ifdef SSHDIST_IPSEC_SA_EXPORT
    if (rule->application_identifier_len > 0)
    {
        copy->application_identifier =
          ssh_malloc(rule->application_identifier_len);
        if (copy->application_identifier == NULL)
        {
            SSH_DEBUG(SSH_D_ERROR,
                      ("Out of memory when copying rule's application "
                       "identifier"));
            goto fail;
        }
        memcpy(copy->application_identifier, rule->application_identifier,
               rule->application_identifier_len);
        copy->application_identifier_len = rule->application_identifier_len;
    }
#endif /* SSHDIST_IPSEC_SA_EXPORT */

    copy->side_from.ts = rule->side_from.ts;
    if (copy->side_from.ts)
      ssh_ikev2_ts_take_ref(pm->sad_handle, copy->side_from.ts);
#ifdef SSHDIST_IPSEC_DNSPOLICY
    copy->side_from.dns_addr_sel_ref = from_dns_asr;
#endif /* SSHDIST_IPSEC_DNSPOLICY */

    copy->side_to.ts = rule->side_to.ts;
    if (copy->side_to.ts)
      ssh_ikev2_ts_take_ref(pm->sad_handle, copy->side_to.ts);
#ifdef SSHDIST_IPSEC_DNSPOLICY
    copy->side_to.dns_addr_sel_ref = to_dns_asr;
#endif /* SSHDIST_IPSEC_DNSPOLICY */
    copy->routing_instance_id = rule->routing_instance_id;

    copy->num_access_groups = rule->num_access_groups;
    if (rule->access_groups)
    {
        copy->access_groups = agroups;
        if (copy->access_groups != NULL)
        {
            memcpy(copy->access_groups, rule->access_groups,
               copy->num_access_groups * sizeof *copy->access_groups);
        }
    }

    return copy;

  fail:
    if (agroups)
      ssh_free(agroups);
#ifdef SSHDIST_IPSEC_DNSPOLICY
    if (to_dns_asr)
      ssh_pm_dns_cache_remove(rule->pm->dnscache, to_dns_asr);
    if (from_dns_asr)
      ssh_pm_dns_cache_remove(rule->pm->dnscache, from_dns_asr);
#endif /* SSHDIST_IPSEC_DNSPOLICY */
    if (copy)
      ssh_pm_rule_free(rule->pm, copy);
    return NULL;
}

#ifdef SSHDIST_IPSEC_DNSPOLICY

#define CLONE_SIDE(r, c, side)                                                \
do {                                                                          \
  (c)->side.dns_addr_sel_ref = (r)->side.dns_addr_sel_ref;                    \
  (c)->side.auto_start = (r)->side.auto_start;                                \
  (c)->side.as_up = (r)->side.as_up;                                          \
  (c)->side.as_fail_retry = (r)->side.as_fail_retry;                          \
} while (0)

/* Clone the given rule. */
SshPmRule
ssh_pm_rule_clone(
        SshPm pm,
        SshPmRule rule)
{
    SshPmRule clone;

    clone =
        ssh_pm_rule_create_internal(
                pm,
                rule->precedence, rule->flags,
                rule->side_from.tunnel,
                rule->side_to.tunnel);
    if (clone == NULL)
    {
        return NULL;
    }

    CLONE_SIDE(rule, clone, side_to);
    CLONE_SIDE(rule, clone, side_from);

    clone->side_from.ts = rule->side_from.ts;
    clone->side_to.ts = rule->side_to.ts;
    if (rule->side_from.ts)
      ssh_ikev2_ts_take_ref(pm->sad_handle, rule->side_from.ts);
    if (rule->side_to.ts)
      ssh_ikev2_ts_take_ref(pm->sad_handle, rule->side_to.ts);

    clone->rule_id = rule->rule_id;
    clone->flags |= SSH_PM_RULE_I_CLONE;
    ssh_strncpy(clone->routing_instance_name, rule->routing_instance_name,
                SSH_VRI_NAMESIZE);
    clone->routing_instance_id = rule->routing_instance_id;

    return clone;
}

#endif /* SSHDIST_IPSEC_DNSPOLICY */

#ifdef SSHDIST_IPSEC_DNSPOLICY
bool
ssh_pm_rule_set_dns(SshPmRule rule, SshPmRuleSide side,
                    const char *address)
{
    SshPmRuleSideSpecification side_spec;
    SshPmDnsObjectClass oc;

    if (address == NULL)
      return false;

    if (side == SSH_PM_FROM)
    {
        side_spec = &rule->side_from;
        oc = SSH_PM_DNS_OC_R_LOCAL;
    }
    else
    {
        side_spec = &rule->side_to;
        oc = SSH_PM_DNS_OC_R_REMOTE;
    }

    /* Check that there are no port or protocol traffic selectors encoded
       in the 'address' parameter */
    if (strchr((const char *)address, ','))
      return false;

    side_spec->dns_addr_sel_ref =
        ssh_pm_dns_cache_insert(rule->pm->dnscache, address, oc, rule);

    return side_spec->dns_addr_sel_ref != NULL;
}
#endif /* SSHDIST_IPSEC_DNSPOLICY */

/* Adds a traffic selector constraint to the given rule.  This constrains
   which packets the rule applies to. Only one traffic selector can be
   specified for each side of the rule (it is a fatal error to try to
   add more). This function returns true on success and
   false if the traffic selector could not be parsed. */
bool ssh_pm_rule_set_traffic_selector(SshPmRule rule,
                                         SshPmRuleSide side,
                                         const char *traffic_selector)
{
    SshPm pm = rule->pm;
    SshIkev2PayloadTS ts;
    int items;
    char *ts_string;

    ts = ssh_ikev2_ts_allocate(pm->sad_handle);
    if (ts == NULL)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Cannot allocate a traffic selector"));
        return false;
    }

    ts_string = ssh_icmputil_string_to_tsstring(traffic_selector);
    if (ts_string != NULL)
    {
        items = ssh_ikev2_string_to_ts(ts_string, ts);
        ssh_free(ts_string);
    }
    else
      items = ssh_ikev2_string_to_ts(traffic_selector, ts);

    if (items == -1)
    {
        ssh_ikev2_ts_free(pm->sad_handle, ts);
        ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                      "Input traffic selector is corrupt.");
        SSH_DEBUG(SSH_D_FAIL, ("Cannot parse the input traffic selector"));
        return false;
    }

    SSH_DEBUG(SSH_D_LOWOK, ("Traffic selector %s parsed into %d items",
                            traffic_selector, items));

    return ssh_pm_rule_set_ts(rule, side, ts);
}

bool ssh_pm_rule_set_ts(SshPmRule rule,
                           SshPmRuleSide side,
                           SshIkev2PayloadTS ts)
{
    return ssh_pm_rule_set_ts_internal(rule, side, ts,
                                     SSH_PM_RULE_TS_CHECK_MULTICAST_SRC);
}

bool ssh_pm_rule_set_ts_internal(SshPmRule rule,
                                    SshPmRuleSide side,
                                    SshIkev2PayloadTS ts,
                                    uint32_t test_flags)
{
    SshPmRuleSideSpecification side_spec;
    SshPm pm = rule->pm;
    SshIkev2PayloadTSItem to;
    int i = 0;

    if (ts == NULL)
      return false;

#ifdef SSHDIST_ISAKMP_CFG_MODE_RULES
    if (rule->flags & SSH_PM_RULE_CFGMODE_RULES)
    {
        ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                      "attempt to specify traffic selector for a "
                      "rule with `cfgmode-rules' set");
        ssh_ikev2_ts_free(pm->sad_handle, ts);
        return false;
    }
#endif /* SSHDIST_ISAKMP_CFG_MODE_RULES */

    if (side == SSH_PM_FROM)
      side_spec = &rule->side_from;
    else
      side_spec = &rule->side_to;

    if (side_spec->ts)
    {
        SSH_DEBUG(SSH_D_FAIL, ("This rule side already has a configured "
                               "traffic selector"));
        ssh_ikev2_ts_free(pm->sad_handle, ts);
        return false;
    }

    /* Sanity check the number of items in the supplied traffic selector */
    if (ts->number_of_items_used > SSH_MAX_RULE_TRAFFIC_SELECTORS_ITEMS)
    {
        ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                      "Input traffic selector contains more than the built in "
                      "maximum number of items. "
                      "Increase the value of "
                      "SSH_MAX_RULE_TRAFFIC_SELECTORS_ITEMS");
        SSH_DEBUG(SSH_D_FAIL, ("Input traffic selector contains %d items",
                               ts->number_of_items_used));
        ssh_ikev2_ts_free(pm->sad_handle, ts);
        return false;
    }

    /* Multicast address is not allowed in source traffic selector.
       This check is skipped for dummy "to-tunnel" multicast rules.
     */
    if ((side == SSH_PM_FROM) &&
        (test_flags & SSH_PM_RULE_TS_CHECK_MULTICAST_SRC))
    {
        for (i = 0; i < ts->number_of_items_used; i++)
        {
            to = &(ts->items[i]);
            if (SSH_IP_IS_MULTICAST(to->start_address)) {
              ssh_ikev2_ts_free(pm->sad_handle, ts);
              ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                            "Multicast address is not allowed as source in "
                            "traffic selectors.");
              return false;
          }
        }
    }

    if (ts->number_of_items_used != 1 &&
        ((rule->side_to.tunnel &&
          rule->side_to.tunnel->u.ike.versions & SSH_PM_IKE_VERSION_1)
         ||
         (rule->side_from.tunnel &&
          rule->side_from.tunnel->u.ike.versions & SSH_PM_IKE_VERSION_1)))
    {
        ssh_ikev2_ts_free(pm->sad_handle, ts);
        ssh_log_event(
                SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                "IKEv1 tunnels only has traffic selectors with one item.");
        SSH_DEBUG(SSH_D_FAIL, ("Cannot parse the input traffic selector"));
        return false;
    }

    side_spec->ts = ts;
    return true;
}

bool
ssh_pm_rule_set_routing_instance(SshPmRule rule,
                                 const char *routing_instance_name)
{
    if (routing_instance_name == NULL)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Routing instance name not valid for rule."));
        return false;
    }

    /* The set name should match the routing instance name of the tunnel
       it is attached to, if any. */
    if (rule->side_from.tunnel != NULL)
    {
        if (strcmp(rule->side_from.tunnel->routing_instance_name,
                   routing_instance_name) != 0)
        {
            SSH_DEBUG(SSH_D_FAIL, ("Rule routing instance name '%s' does not "
                           "match the tunnel with routing instance name '%s'",
                           routing_instance_name,
                           rule->side_from.tunnel->routing_instance_name));
            return false;
        }
    }
    else if (rule->side_to.tunnel != NULL)
    {
        if (strcmp(rule->side_to.tunnel->routing_instance_name,
                   routing_instance_name) != 0)
        {
            SSH_DEBUG(SSH_D_FAIL, ("Rule routing instance name '%s' does not "
                           "match the tunnel with routing instance name '%s'",
                           routing_instance_name,
                           rule->side_to.tunnel->routing_instance_name));
            return false;
        }
    }
    /* Not attached to a tunnel. Set the given name. */
    else
    {
        ssh_strncpy(rule->routing_instance_name, routing_instance_name,
                    SSH_VRI_NAMESIZE);

        rule->routing_instance_id =
            ssh_ip_get_interface_vri_id(
                    &rule->pm->ifs,
                    rule->routing_instance_name);
    }

    return true;
}

bool
ssh_pm_rule_set_ip(SshPmRule rule, SshPmRuleSide side,
                   const char *ip_low, const char *ip_high)
{
    SshPmRuleSideSpecification side_spec;
    SshIpAddrStruct low, high;

    if (side == SSH_PM_FROM)
      side_spec = &rule->side_from;
    else
      side_spec = &rule->side_to;

    if (side_spec->ts)
    {
        SSH_DEBUG(SSH_D_FAIL, ("This rule side already has a configured "
                               "traffic selector"));
        return false;
    }

    side_spec->ts = ssh_ikev2_ts_allocate(rule->pm->sad_handle);
    if (side_spec->ts == NULL)
      return false;

    if (!ssh_ipaddr_parse(&low, ip_low) || !ssh_ipaddr_parse(&high, ip_high))
    {
        SSH_DEBUG(SSH_D_ERROR, ("Malformed IP address range `%s-%s'",
                                ip_low, ip_high));
        return false;
    }

    if (ssh_ikev2_ts_item_add(side_spec->ts, 0, &low, &high, 0, 0xffff)
        != SSH_IKEV2_ERROR_OK)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Cannot create traffic selector."));
        side_spec->ts = NULL;
        return false;
    }

    return true;
}

bool
ssh_pm_rule_add_authorization_group_id(SshPm pm, SshPmRule rule,
                                       uint32_t group_id)
{
    uint32_t *tmp;

    SSH_DEBUG(SSH_D_NICETOKNOW, ("Adding group id %d to the rule %p",
                                 (int) group_id, rule));

    tmp = ssh_realloc(rule->access_groups,
                      rule->num_access_groups * sizeof(*tmp),
                      (rule->num_access_groups + 1) * sizeof(*tmp));
    if (tmp == NULL)
      return false;

    rule->access_groups = tmp;
    rule->access_groups[rule->num_access_groups++] = group_id;

    return true;
}

#ifdef SSH_IPSEC_MULTICAST
/* For a to-tunnel rule having destination traffic selector
   as multicast address, make sure that local ip/interface is
   given.
   For a from-tunnel rule having destination traffic selector
   as multicast address, create a dummy to-tunnel rule with
   source traffic selector as the same multicast address. This
   dummy rule is drop rule.
*/
bool ssh_pm_multicast_check_and_add_to_tunnel(SshPm pm, SshPmRule rule)
{
    SshPmRule nrule;
    SshIkev2PayloadTSItem to,from;
    SshIkev2PayloadTS to_ts, from_ts;
    int i = 0;
    bool existing_rule = false;
    uint32_t index;

    /* All to-tunnel rule with multicast traffic selector
       should have local ip/interface. */
    if (rule->side_to.tunnel && rule->side_to.ts)
    {
        SSH_DEBUG(SSH_D_NICETOKNOW,
                  ("Validating Multicast Tunnel for local ip/interface"));
        /* Search for Multicast destination address in this rule */
        for (i = 0; i < rule->side_to.ts->number_of_items_used; i++)
       {
           to = &(rule->side_to.ts->items[i]);
           if (SSH_IP_IS_MULTICAST(to->start_address))
           {
               if (rule->side_to.tunnel->num_local_ips == 0
                   && rule->side_to.tunnel->num_local_interfaces == 0)
               {
                   ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                                 "Tunnel should have local ip/interface for"
                                 " having Multicast traffic selector");
                   return false;
               }
               else
                 break;
           }
       }
    }

    if (rule->side_from.tunnel && rule->side_to.ts)
    {
        to_ts = ssh_ikev2_ts_allocate(pm->sad_handle);
        if (to_ts == NULL)
       {
           ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                         "Cannot allocate a traffic selector");
           return false;
       }

        /* Search for Multicast destination address in this rule */
        for (i = 0; i < rule->side_to.ts->number_of_items_used; i++)
       {
           to = &(rule->side_to.ts->items[i]);
           if (SSH_IP_IS_MULTICAST(to->start_address))
           {
               ssh_ikev2_ts_item_add(to_ts, to->proto, to->start_address,
                             to->end_address, to->start_port, to->end_port);
           }
       }
        if (to_ts->number_of_items_used == 0)
       {
           ssh_ikev2_ts_free(pm->sad_handle, to_ts);
           return true;
       }

        from_ts = ssh_ikev2_ts_allocate(pm->sad_handle);
        if (from_ts == NULL)
       {
           ssh_ikev2_ts_free(pm->sad_handle, to_ts);
           ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                         "Cannot allocate a traffic selector");
           return false;
       }

        for (i = 0; i < rule->side_from.ts->number_of_items_used; i++)
       {
           from = &(rule->side_from.ts->items[i]);
           ssh_ikev2_ts_item_add(from_ts, from->proto, from->start_address,
                                 from->end_address, from->start_port,
                                 from->end_port);
       }

        nrule =
            ssh_pm_rule_create(
                    pm,
                    rule->precedence,
                    0 /*DROP*/,
                    NULL,
                    rule->side_from.tunnel);
        if (nrule == NULL)
       {
           ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                         "Could not create dummy multicast to-tunnel rule.");
           goto error;
       }

        /* We add this special to tunnel rule with source Multicast address,
          so we skip the source Multicast check for this rule by passing
          zero as last parameter*/
        ssh_pm_rule_set_ts_internal(nrule, SSH_PM_FROM, to_ts, 0);

        ssh_pm_rule_set_ts_internal(nrule, SSH_PM_TO, from_ts, 1);
        nrule->routing_instance_id = rule->routing_instance_id;

        index = ssh_pm_rule_add(pm, nrule);
        if (index == SSH_IPSEC_INVALID_INDEX)
       {
           ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                         "Could not add dummy multicast to-tunnel rule.");
           goto error;
       }

      /* check for the already existing rules. */
      {
          SshPmRule temp_rule;
          SshADTHandle handle;

          for (handle = ssh_adt_enumerate_start(pm->rule_by_id);
                                    handle != SSH_ADT_INVALID;
               handle = ssh_adt_enumerate_next(pm->rule_by_id, handle))
         {
             temp_rule = ssh_adt_get(pm->rule_by_id, handle);
             if (ssh_pm_rule_compare(pm, temp_rule->rule_id, index))
             {
                 ssh_pm_rule_delete(pm, index);
                 existing_rule = true;
                 break;
             }
         }
      }
        if (!existing_rule)
        {
            nrule->flags |= SSH_PM_RULE_I_SYSTEM;
            nrule->master_rule = rule;
            rule->sub_rule = nrule;
            SSH_DEBUG(SSH_D_NICETOKNOW,("Created dummy multicast to-tunnel "
                                   "rule (id=%d) for from-tunnel rule (id=%d)",
                                   nrule->rule_id, rule->rule_id ));
        }
    }
    return true;

    error:
    ssh_ikev2_ts_free(pm->sad_handle, to_ts);
    ssh_ikev2_ts_free(pm->sad_handle, from_ts);
    return false;
}
#endif /* SSH_IPSEC_MULTICAST */

#ifdef SSHDIST_IPSEC_SA_EXPORT
bool ssh_pm_rule_set_application_identifier(SshPmRule rule,
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
        SSH_DEBUG_HEXDUMP(SSH_D_LOWOK,
                          ("Setting application identifier to rule '%@':",
                           ssh_pm_rule_render, rule), id, id_len);
    }
    else
      SSH_DEBUG(SSH_D_LOWOK,
                ("Clearing application identifier from rule '%@'",
                 ssh_pm_rule_render, rule));

    if (rule->application_identifier)
      ssh_free(rule->application_identifier);
    rule->application_identifier = app_id;
    rule->application_identifier_len = id_len;

    return true;
}

bool ssh_pm_rule_get_application_identifier(SshPmRule rule,
                                               char *id,
                                               size_t *id_len)
{
    if (rule->application_identifier_len > *id_len)
      return false;

    if (rule->application_identifier_len > 0)
      memcpy(
              id,
              rule->application_identifier,
              rule->application_identifier_len);

    *id_len = rule->application_identifier_len;

    return true;
}
#endif /* SSHDIST_IPSEC_SA_EXPORT */


uint32_t
ssh_pm_rule_add(SshPm pm, SshPmRule rule)
{
    /* Sanity check for the rule's traffic selectors. */
    if (!pm_rule_verify_ts_sane(pm, rule))
    {
        ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                      "The rule's traffic selectors are invalid.");
        return SSH_IPSEC_INVALID_INDEX;
    }

    if (rule->flags & SSH_PM_RULE_PASS_UNMODIFIED)
    {
        ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                      "The rule's flags are invalid.");





        return SSH_IPSEC_INVALID_INDEX;
    }

    /* Check outbound IPSec rules (with to-tunnel set) but which has no
       selectors.  The policy enforcement rule of these rules will
       shadow the outbound trigger and this can create very weird
       problems. */
    if (rule->side_to.tunnel
        && (rule->flags & SSH_PM_RULE_PASS)
        && !SSH_PM_RULE_IS_VIRTUAL_IP(rule)
        && (!pm_rule_has_selectors(&rule->side_to)
            && !pm_rule_has_selectors(&rule->side_from)))
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_WARNING,
                    "Suspicious outbound IPsec rule without any selectors: "
                    "the rule might not work at all");

    /* Auto-start rules. */
    if (rule->side_to.tunnel != NULL
        && ((rule->side_to.tunnel->flags & SSH_PM_TI_DELAYED_OPEN) == 0
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
            || (rule->side_to.tunnel->flags & SSH_PM_TI_INTERFACE_TRIGGER) != 0
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */
            ))
    {
        rule->side_to.auto_start = 1;

        /* Install inactive trigger rule for auto-start rule. */
        rule->flags |= SSH_PM_RULE_I_NO_TRIGGER;

        if (!pm_rule_post_check_auto_start(rule, rule->side_to.tunnel,
                                           &rule->side_to))
          return SSH_IPSEC_INVALID_INDEX;
    }
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
    /* Virtual IP. */
    if (SSH_PM_RULE_IS_VIRTUAL_IP(rule))
    {
        /* The tunnels must specify IKE peer. */
        if (rule->side_to.tunnel->num_peers == 0
#ifdef SSHDIST_IPSEC_DNSPOLICY
            && rule->side_to.tunnel->num_dns_peers == 0
#endif /* SSHDIST_IPSEC_DNSPOLICY */
            )
          /* Explicit IKE peers specified. */
        {
            ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                          "No IKE peers specified for virtual IP rule");
            return SSH_IPSEC_INVALID_INDEX;
        }
        /* Install inactive trigger rule for interface-trigger rule. */
        if (rule->side_to.tunnel->flags & SSH_PM_TI_INTERFACE_TRIGGER)
          rule->flags |= SSH_PM_RULE_I_NO_TRIGGER;
    }
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

    /* Create default match all traffic selectors if no traffic selector
       has been set for the rule sides. */
    if (!pm_rule_make_default_traffic_selectors(pm, rule))
      return SSH_IPSEC_INVALID_INDEX;

#ifdef SSHDIST_IPSEC_DNSPOLICY
    SSH_ASSERT((rule->side_from.ts != NULL ||
                rule->side_from.dns_addr_sel_ref != NULL)
               ||
               (rule->side_to.ts != NULL ||
                rule->side_to.dns_addr_sel_ref != NULL));
#endif /* SSHDIST_IPSEC_DNSPOLICY */

#ifdef SSH_IPSEC_MULTICAST
    if (!ssh_pm_multicast_check_and_add_to_tunnel(pm, rule))
      return SSH_IPSEC_INVALID_INDEX;
#endif /* SSH_IPSEC_MULTICAST */

    if (!(rule->flags & SSH_PM_RULE_I_CLONE))
      rule->rule_id = pm->next_rule_id++;
    else
      rule->flags &= ~SSH_PM_RULE_I_CLONE;

    /* Add this rule to the list of configuration's rule
       additions. When doing this, create container if it does not
       exist. */
    if (pm->config_additions == NULL)
        if ((pm->config_additions =
             ssh_adt_create_generic(SSH_ADT_BAG,
                                    SSH_ADT_HEADER,
                                    SSH_ADT_OFFSET_OF(SshPmRuleStruct,
                                                      rule_by_index_add_hdr),
                                    SSH_ADT_HASH, ssh_pm_rule_hash_adt,
                                    SSH_ADT_COMPARE, ssh_pm_rule_compare_adt,
                                    SSH_ADT_DESTROY, ssh_pm_rule_destroy_adt,
                                    SSH_ADT_CONTEXT, pm,
                                    SSH_ADT_ARGS_END))
            == NULL)
            return SSH_IPSEC_INVALID_INDEX;

    ssh_adt_insert(pm->config_additions, rule);

    SSH_DEBUG(SSH_D_NICETOKNOW, ("Add rule with rule_id=%d", rule->rule_id));
    return rule->rule_id;
}

static bool
ssh_pm_ipsec_policy_add(
        SshPm pm,
        SshIkev2PayloadTS from_ts,
        SshIkev2PayloadTS to_ts,
        IPsecPolicyRole role,
        IPsecPolicyAction action,
        int priority,
        int *return_id)
{
    struct IPSelectorGroup *selector_group = NULL;
    bool rv = false;

    /* Create a selector group for the rule */
    selector_group =
        ssh_pm_create_ip_selector_group(
                from_ts,
                to_ts);

    if (selector_group == NULL)
    {
        SSH_DEBUG(
                SSH_D_FAIL,
                ("IPsec rule add failed, "
                 "IPSelectorGroup allocation failed"));
    }
    else
    {
        rv =
            ipsec_policy_add_entry(
                    pm->ipsec_control,
                    role,
                    action,
                    priority,
                    selector_group,
                    return_id);

        ssh_free(selector_group);
    }

    return rv;
}

static bool
ssh_pm_ipsec_inbound_and_outbound_rule_add(
        SshPm pm,
        SshPmRule rule)
{
    SshIkev2PayloadTS from_ts = rule->side_from.ts;
    SshIkev2PayloadTS to_ts = rule->side_to.ts;
    IPsecPolicyRole role;
    IPsecPolicyAction action = IPSEC_POLICY_DISCARD;
    int priority;
    bool ok = true;

    /* Is this a pass or a drop rule */
    if (rule->flags & SSH_PM_RULE_PASS)
    {
        action = IPSEC_POLICY_BYPASS;
        pm->policy_stats.pass_rule_cnt++;
    }
    else
    {
        pm->policy_stats.drop_rule_cnt++;
    }

    role = IPSEC_POLICY_O;

    priority = 100000000 + IPSEC_PRIORITY_O_USER - rule->precedence;

    ok =
        ssh_pm_ipsec_policy_add(
                pm,
                from_ts,
                to_ts,
                role,
                action,
                priority,
                &rule->ipsec_policy_id[0]);

    if (ok == true)
    {
        ok =
            ssh_pm_ipsec_policy_add(
                    pm,
                    to_ts,
                    from_ts,
                    role,
                    action,
                    priority,
                    &rule->ipsec_policy_id[1]);
    }

        role = IPSEC_POLICY_I;

        priority = 100000000 + IPSEC_PRIORITY_I_USER - rule->precedence;

    if (ok == true)
    {
        ok =
            ssh_pm_ipsec_policy_add(
                    pm,
                    to_ts,
                    from_ts,
                    role,
                    action,
                    priority,
                    &rule->ipsec_policy_id[2]);
    }

    if (ok == true)
    {
        ok =
            ssh_pm_ipsec_policy_add(
                    pm,
                    from_ts,
                    to_ts,
                    role,
                    action,
                    priority,
                    &rule->ipsec_policy_id[3]);
    }

    return ok;
}


bool
ssh_pm_ipsec_rule_add(
        SshPm pm,
        SshPmRule rule)
{
    SshPmRuleSideSpecification src = &rule->side_from;
    SshPmRuleSideSpecification dst = &rule->side_to;
    bool ok = true;
    bool outbound = false, inbound = false;

    /* Determine the direction for the rule */
    if (src->tunnel == NULL && dst->tunnel == NULL)
    {
        outbound = true;
        inbound = true;
    }

    /* Add the policy for appropriate direction */
    if (inbound == true && outbound == true)
    {
        ok =
            ssh_pm_ipsec_inbound_and_outbound_rule_add(
                    pm,
                    rule);

    }

    /* If adding any of the rules fail, remove the rule */
    if (ok == false)
    {
        ssh_pm_ipsec_rule_delete(pm, rule);
    }

    return ok;
}

void
ssh_pm_ipsec_rule_delete(
        SshPm pm,
        SshPmRule rule)
{
    int i;

    /* Remove rules to both directions if present */
    for (i = 0; i < 4; ++i)
    {
        if (rule->ipsec_policy_id[i] != 0)
        {
            ipsec_policy_remove_entry(
                    pm->ipsec_control,
                    rule->ipsec_policy_id[i]);
            rule->ipsec_policy_id[i] = 0;
        }
    }
}

void
ssh_pm_rule_delete(SshPm pm, uint32_t rule_id)
{
    SshPmRule rule;
    SshPmRuleStruct probe;
    SshADTHandle handle;

    SSH_DEBUG(SSH_D_NICETOKNOW, ("Deleting rule with rule_id=%d", rule_id));

    /* Check if this is a rule that was added in the current
       configuration batch. */

    probe.rule_id = rule_id;

    if (pm->config_additions)
    {
        if ((handle =
             ssh_adt_get_handle_to_equal(pm->config_additions, &probe))
            != SSH_ADT_INVALID)
        {
            SSH_DEBUG(SSH_D_MIDOK, ("Deleting rule %d from newly added rules",
                                    (int) rule_id));
            ssh_adt_delete(pm->config_additions, handle);
            return;
        }
    }

    if (pm->iface_pending_additions)
    {
        if ((handle =
             ssh_adt_get_handle_to_equal(pm->iface_pending_additions, &probe))
            != SSH_ADT_INVALID)
        {
            SSH_DEBUG(SSH_D_MIDOK, ("Deleting rule %d from if-pending rules",
                                    (int) rule_id));
            ssh_adt_delete(pm->iface_pending_additions, handle);
            return;
        }
    }

    handle = ssh_adt_get_handle_to_equal(pm->rule_by_id, &probe);
    if (handle == SSH_ADT_INVALID)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Rule ID %d is unknown",
                               (int) rule_id));
        return;
    }
    rule = ssh_adt_get(pm->rule_by_id, handle);

    /* Add this rule to the list of configuration's rule
       deletions. When doing this, create container if it does not
       exist. */
    if (pm->config_deletions == NULL)
    {
        pm->config_deletions = ssh_adt_create_generic(SSH_ADT_BAG,
                                    SSH_ADT_HEADER,
                                    SSH_ADT_OFFSET_OF(SshPmRuleStruct,
                                                      rule_by_index_del_hdr),
                                    SSH_ADT_HASH, ssh_pm_rule_hash_adt,
                                    SSH_ADT_COMPARE, ssh_pm_rule_compare_adt,
                                    SSH_ADT_CONTEXT, pm,
                                    SSH_ADT_ARGS_END);
        if (pm->config_deletions == NULL)
          return;
    }

    if (ssh_adt_get_handle_to_equal(pm->config_deletions, rule)
        != SSH_ADT_INVALID)
    {
        SSH_DEBUG(SSH_D_NICETOKNOW,
                  ("Rule ID %d is already about to be deleted.",
                   (int) rule_id));
        return;
    }

    ssh_adt_insert(pm->config_deletions, rule);
}


bool
ssh_pm_rule_compare(SshPm pm, uint32_t id1, uint32_t id2)
{
    SshPmRule rule1 = ssh_pm_rule_lookup(pm, id1);
    SshPmRule rule2 = ssh_pm_rule_lookup(pm, id2);
    uint32_t i;

    if (rule1 == NULL)
    {
        SSH_DEBUG(SSH_D_ERROR, ("Trying to compare an unknown rule %d",
                                (int) id1));
        return false;
    }
    if (rule2 == NULL)
    {
        SSH_DEBUG(SSH_D_ERROR, ("Trying to compare an unknown rule %d",
                                (int) id2));
        return false;
    }

    /* Compare the rules. */

    if (rule1->precedence != rule2->precedence)
      return false;
    if ((rule1->flags & 0x0000ffff) != (rule2->flags & 0x0000ffff))
      return false;

    /* Access groups. */
    if (rule1->num_access_groups != rule2->num_access_groups)
      return false;
    for (i = 0; i < rule1->num_access_groups; i++)
      if (rule1->access_groups[i] != rule2->access_groups[i])
        return false;

    if (!pm_rule_side_specification_compare(pm, &rule1->side_from,
                                            &rule2->side_from))
      return false;
    if (!pm_rule_side_specification_compare(pm, &rule1->side_to,
                                            &rule2->side_to))
      return false;

    /* Check VRF routing instance identifier. */
    if (rule1->routing_instance_id != rule2->routing_instance_id)
      return false;

    /* They are equal. */
    return true;
}

#ifdef SSHDIST_IPSEC_DNSPOLICY
SshPmDnsStatus
pm_rule_get_dns_status(SshPm pm, SshPmRule rule)
{
    SshPmDnsStatus dnsstat = SSH_PM_DNS_STATUS_OK;
    SshPmDnsStatus status = SSH_PM_DNS_STATUS_OK;
    SshPmDnsStatus peer_dnsstat, tmp_stat;
    SshPmTunnelLocalDnsAddress local_dns;
    int i;

    SSH_ASSERT(rule != NULL);

    /* Require all rule DNS names to be valid */
    status = ssh_pm_dns_cache_status(rule->side_from.dns_addr_sel_ref);
    if (status != SSH_PM_DNS_STATUS_ERROR && rule->side_from.ts == NULL)
      status = SSH_PM_DNS_STATUS_ERROR;
    dnsstat |= status;

    status = ssh_pm_dns_cache_status(rule->side_to.dns_addr_sel_ref);
    if (status != SSH_PM_DNS_STATUS_ERROR && rule->side_to.ts == NULL)
      status = SSH_PM_DNS_STATUS_ERROR;
    dnsstat |= status;

    if (rule->side_to.tunnel)
    {
        /* Require tunnel local DNS names to be valid */
        for (local_dns = rule->side_to.tunnel->local_dns_address;
             local_dns != NULL;
             local_dns = local_dns->next)
        {
            status = ssh_pm_dns_cache_status(local_dns->ref);
            if (status != SSH_PM_DNS_STATUS_ERROR
                && !SSH_IP_DEFINED(&local_dns->ip->ip))
              status = SSH_PM_DNS_STATUS_ERROR;
            dnsstat |= status;
        }

        /* Require atleast one tunnel peer DNS name to be valid */
        peer_dnsstat = SSH_PM_DNS_STATUS_ERROR;
        for (i = 0; i < rule->side_to.tunnel->num_dns_peers; i++)
        {
            tmp_stat =
              ssh_pm_dns_cache_status(rule->side_to.tunnel->
                                      dns_peer_ip_ref_array[i].ref);
            if (peer_dnsstat > tmp_stat)
              peer_dnsstat = tmp_stat;
        }
        if (i != 0)
        {
            for (i = 0; i < rule->side_to.tunnel->num_peers; i++)
              if (SSH_IP_DEFINED(&rule->side_to.tunnel->peers[i]))
                break;
            if (i == rule->side_to.tunnel->num_peers)
              peer_dnsstat = SSH_PM_DNS_STATUS_ERROR;
            dnsstat |= peer_dnsstat;
        }
    }

    if (rule->side_from.tunnel)
    {
        /* Require tunnel local DNS names to be valid */
        for (local_dns = rule->side_from.tunnel->local_dns_address;
             local_dns != NULL;
             local_dns = local_dns->next)
        {
            status = ssh_pm_dns_cache_status(local_dns->ref);
            if (status != SSH_PM_DNS_STATUS_ERROR
                && !SSH_IP_DEFINED(&local_dns->ip->ip))
              status = SSH_PM_DNS_STATUS_ERROR;
            dnsstat |= status;
        }

        /* Require atleast one tunnel peer DNS name to be valid */
        peer_dnsstat = SSH_PM_DNS_STATUS_ERROR;
        for (i = 0; i < rule->side_from.tunnel->num_dns_peers; i++)
        {
            tmp_stat =
              ssh_pm_dns_cache_status(rule->side_from.tunnel->
                                      dns_peer_ip_ref_array[i].ref);
            if (peer_dnsstat > tmp_stat)
              peer_dnsstat = tmp_stat;
        }
        if (i != 0)
        {
            for (i = 0; i < rule->side_from.tunnel->num_peers; i++)
              if (SSH_IP_DEFINED(&rule->side_from.tunnel->peers[i]))
                break;
            if (i == rule->side_from.tunnel->num_peers)
              peer_dnsstat = SSH_PM_DNS_STATUS_ERROR;
            dnsstat |= peer_dnsstat;
        }
    }

    /* Function returns either SSH_PM_DNS_STATUS_ERROR,
       SSH_PM_DNS_STATUS_STALE, or SSH_PM_DNS_STATUS_OK. */

    if (dnsstat & SSH_PM_DNS_STATUS_ERROR)
      return SSH_PM_DNS_STATUS_ERROR;
    else if (dnsstat & SSH_PM_DNS_STATUS_STALE)
      return SSH_PM_DNS_STATUS_STALE;
    return dnsstat;
}

SshPmDnsStatus
ssh_pm_rule_get_dns_status(SshPm pm, uint32_t rule_id)
{
    SshPmRule rule = NULL;
    SshPmRuleStruct probe;
    SshADTHandle handle;

    memset(&probe, 0, sizeof(probe));
    probe.rule_id = rule_id;

    handle = ssh_adt_get_handle_to_equal(pm->rule_by_id, &probe);
    if (handle != SSH_ADT_INVALID)
    {
        rule = ssh_adt_get(pm->rule_by_id, handle);
    }
    else
    {
        handle = ssh_adt_get_handle_to_equal(pm->iface_pending_additions,
                                             &probe);
        if (handle != SSH_ADT_INVALID)
          rule = ssh_adt_get(pm->iface_pending_additions, handle);
    }

    if (rule != NULL)
      return pm_rule_get_dns_status(pm, rule);
    else
      return SSH_PM_DNS_STATUS_ERROR;
}
#endif /* SSHDIST_IPSEC_DNSPOLICY */

void
ssh_pm_commit(SshPm pm, SshPmStatusCB callback, void *context)
{
    SSH_ASSERT(!pm->config_active);

    /* Make additions/deletions `pending'. */
    ssh_pm_config_make_pending(pm);

    /* Start configuration thread.  It waits until the main thread has
       finished its current commit batch and schedules this batch for
       processing. */
    pm->config_active = 1;
    pm->config_callback = callback;
    pm->config_callback_context = context;

    ssh_fsm_thread_init(&pm->fsm, &pm->config_thread,
                        ssh_pm_st_config_start, NULL_FNPTR, NULL_FNPTR, pm);
    ssh_fsm_set_thread_name(&pm->config_thread, "Config");
}


void
ssh_pm_abort(SshPm pm)
{
    SSH_ASSERT(!pm->config_active);

    SSH_DEBUG(SSH_D_LOWOK, ("PM abort entered"));

    /* Free additions and deletions . */
    if (pm->config_additions)
      ssh_adt_clear(pm->config_additions);

    if (pm->config_deletions)
      ssh_adt_clear(pm->config_deletions);

    ssh_adt_clear(pm->iface_pending_additions);

#ifdef SSH_PM_BLACKLIST_ENABLED
    ssh_pm_blacklist_abort(pm);
#endif /* SSH_PM_BLACKLIST_ENABLED */
}

void
ssh_pm_config_make_pending(SshPm pm)
{
    /* Steal current additions and deletions. */
    pm->config_pending_additions = pm->config_additions;
    pm->config_additions = NULL;
    pm->config_pending_deletions = pm->config_deletions;
    pm->config_deletions = NULL;
}

void
ssh_pm_config_pending_to_batch(SshPm pm)
{
    SshADTHandle handle;
    SshPmRule rule;

    SSH_ASSERT(pm->batch.additions == NULL);
    SSH_ASSERT(pm->batch.deletions == NULL);

    /* Schedule additions, this is done by stealing the configuration
       additions container. */
    pm->batch.additions = pm->config_pending_additions;
    pm->config_pending_additions = NULL;

    /* Convert delete requests into real delete flags.  Also mark that
       the rule belongs to the active batch. */
    if (pm->config_pending_deletions)
    {
        for (handle = ssh_adt_enumerate_start(pm->config_pending_deletions);
             handle != SSH_ADT_INVALID;
             handle = ssh_adt_enumerate_next(pm->config_pending_deletions,
                                             handle))
        {
            rule = ssh_adt_get(pm->config_pending_deletions, handle);
            rule->flags |= (SSH_PM_RULE_I_IN_BATCH | SSH_PM_RULE_I_DELETED);
            SSH_DEBUG(SSH_D_MIDOK, ("Mark rule (id=%d) as deleted",
                                    rule->rule_id));
        }

        /* Mark subrules to be deleted. */
        for (handle = ssh_adt_enumerate_start(pm->config_pending_deletions);
             handle != SSH_ADT_INVALID;
             handle = ssh_adt_enumerate_next(pm->config_pending_deletions,
                                             handle))
        {
            rule = ssh_adt_get(pm->config_pending_deletions, handle);
            for (rule = rule->sub_rule; rule != NULL; rule = rule->sub_rule)
            {
                /* Skip rules already inserted and then encountered by
                   ssh_adt_enumerate_next() above. */
                if (rule->flags & SSH_PM_RULE_I_DELETED)
                  continue;
                SSH_ASSERT(rule->flags & SSH_PM_RULE_I_SYSTEM);
                SSH_DEBUG(SSH_D_MIDOK,
                          ("Mark sub rule (id=%d) as deleted",
                           rule->rule_id));
                rule->flags |=
                  (SSH_PM_RULE_I_IN_BATCH | SSH_PM_RULE_I_DELETED);
                ssh_adt_insert(pm->config_pending_deletions, rule);
            }
        }
    }

    pm->batch.deletions = pm->config_pending_deletions;
    pm->config_pending_deletions = NULL;
}

void
ssh_pm_rule_ipsec_sa_down(
        SshPm pm,
        uint32_t rule_id)
{
    bool reset = true;
    SshPmRule pm_rule;

    pm_rule = ssh_pm_rule_lookup(pm, rule_id);
    if (pm_rule == NULL)
    {
        SSH_DEBUG(
                SSH_D_FAIL,
                ("IPsec SA down on non-existent rule_id %u",
                 (unsigned int) rule_id));
        return;
    }

    if (pm_rule->side_to.tunnel == NULL)
    {
        reset = false;
    }

    /* Check auto-start rules if not shutting down */
    if (ssh_pm_get_status(pm) == SSH_PM_STATUS_DESTROYED)
    {
        reset = false;
    }

    if (SSH_PM_RULE_INACTIVE(pm, pm_rule) == true)
    {
        reset = false;
    }

    /* Clear any cached transform information from
       auto-start rules. */
    if (pm_rule->side_to.as_up == 0)
    {
        reset = false;
    }

    if (reset == true)
    {
        SSH_DEBUG(
                SSH_D_NICETOKNOW,
                ("Clearing cached transform information for "
                 "SshPmRule id %u",
                 (unsigned int) rule_id));

        /* Clear auto-start information from the rule. */
        pm_rule->side_to.as_up = 0;
        pm_rule->side_to.as_fail_retry = 0;
        pm_rule->side_to.as_fail_limit = 0;

        /* Add rule to auto start ADT. */
        ssh_pm_rule_auto_start_insert(pm, pm_rule);

        /* And notify main thread that the auto-start
           rules should be rechecked. */
        pm->auto_start = 1;
        ssh_fsm_condition_broadcast(&pm->fsm, &pm->main_thread_cond);
    }
}
