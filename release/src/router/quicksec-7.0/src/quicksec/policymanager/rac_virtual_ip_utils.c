/**
   @copyright
   Copyright (c) 2015 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   The virtual IP thread handling obtaining, using, and releasing
   virtual IP addresses.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT

#define SSH_DEBUG_MODULE "SshPmStVirtualIp"

/************************** Static help functions ***************************/


static SshPmVirtualAdapter
ssh_pm_virtual_adapter_find_byname(SshPm pm, char *name)
{
    uint32_t i;

    for (i = 0; i < pm->num_virtual_adapters; i++)
      if (strcmp(name, pm->virtual_adapters[i].adapter_name) == 0)
        return &pm->virtual_adapters[i];

    return NULL;
}

static SshPmVirtualAdapter
ssh_pm_virtual_adapter_find_unused(SshPm pm)
{
    uint32_t i;

    for (i = 0; i < pm->num_virtual_adapters; i++)
      if (!pm->virtual_adapters[i].reserved
          && !pm->virtual_adapters[i].in_use)
        return &pm->virtual_adapters[i];

    return NULL;
}

#ifdef SSHDIST_L2TP
/* This function looks up the companion l2tp rule for the virtual IP
   rule `rule', creates a SshPmVipRule out of the l2tp rule and locks
   the l2tp rule. The l2tp rule is unlocked like other virtual IP rules
   in ssh_pm_vip_remove_deleted_rules(). On error no rules are locked
   and this function returns false. */
static bool
ssh_pm_vip_lock_l2tp_rule(SshPm pm, SshPmVip vip, SshPmRule rule)
{
    SshPmRule l2tp_rule = NULL;
    SshPmVipRule l2tp_vrule;
    SshADTHandle h;

    /* Lookup vip rule's companion l2tp rule. */
    for (h = ssh_adt_enumerate_start(pm->rule_by_precedence);
         h != SSH_ADT_INVALID;
         h = ssh_adt_enumerate_next(pm->rule_by_precedence, h))
    {
        l2tp_rule = ssh_adt_get(pm->rule_by_precedence, h);
        SSH_ASSERT(l2tp_rule != NULL);

        if (l2tp_rule->side_to.tunnel == rule->side_to.tunnel
            && (l2tp_rule->flags & SSH_PM_RULE_I_DELETED) == 0
            && SSH_PM_RULE_IS_L2TP(l2tp_rule)
            && (!l2tp_rule->side_to.auto_start || l2tp_rule->side_to.as_up))
          break;

        /* The l2tp rule must have a higher or equal precedence
           than the virtual IP rule. */
        if (l2tp_rule->precedence > rule->precedence)
        {
            h = SSH_ADT_INVALID;
            break;
        }
    }
    if (h == SSH_ADT_INVALID)
    {
        SSH_DEBUG(SSH_D_FAIL,
                  ("Could not find l2tp rule for virtual IP rule %u",
                   (unsigned int) rule->rule_id));
        return false;
    }

    l2tp_vrule = ssh_calloc(1, sizeof(*l2tp_vrule));
    if (l2tp_vrule == NULL)
    {
        SSH_DEBUG(SSH_D_FAIL,
                  ("Out of memory adding l2tp rule to virtual IP"));
        return false;
    }

    /* Lock l2tp PM rule and add it to the vip rule list. */
    SSH_PM_RULE_LOCK(l2tp_rule);
    l2tp_vrule->rule = l2tp_rule;
    l2tp_vrule->next = vip->rules;
    vip->rules = l2tp_vrule;

    SSH_DEBUG(SSH_D_LOWOK,
              ("L2tp rule %u added to VIP", (unsigned)l2tp_rule->rule_id));

    return true;
}
#endif /* SSHDIST_L2TP */

/* Adds the rule to the list of rules maintained by the Vip record.
   Returns true if the rule was not in the list and was sucessfully
   added. In all other conditions returns false. */
static bool
ssh_pm_vip_add_rule(SshPm pm, SshPmVip vip, SshPmRule rule)
{
    SshPmVipRule vrule;
#ifdef SSHDIST_L2TP
    SshIkev2PayloadTS ts;
    uint32_t i;
#endif /* SSHDIST_L2TP */

    for (vrule = vip->rules; vrule != NULL; vrule = vrule->next)
    {
        if (vrule->rule == rule)
        {
            SSH_DEBUG(SSH_D_FAIL, ("Rule already added to virtual IP object"));
            return false;
        }
    }

    vrule = ssh_calloc(1, sizeof (*vrule));
    if (vrule == NULL)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Out of memory adding rule to virtual IP"));
        return false;
    }
    vrule->rule = rule;

#ifdef SSHDIST_L2TP
    if (vrule->rule->side_to.tunnel->flags & SSH_PM_TI_L2TP)
    {
        /* Lock the companion l2tp rule. This is done to ensure that the
           l2tp tunnel is shutdown properly regardless of which of the
           virtual IP rules is deleted first (see spd_batch_st.c for
           how the virtual IP thread is notified when virtual IP rules
           or l2tp rules are deleted. */
        if (!ssh_pm_vip_lock_l2tp_rule(pm, vip, rule))
        {
            SSH_DEBUG(SSH_D_FAIL,
                      ("Could not lock l2tp rule for virtual IP rule"));
            ssh_free(vrule);
            return false;
        }

        /* Create VIP route entries from rule destinations. */
        ts = vrule->rule->side_to.ts;
        for (i = 0; i < ts->number_of_items_used; i++)
          ssh_pm_vip_create_rule_route(vip, &ts->items[i], rule);

        /* Signal the VIP thread to update the routing table. */
        vip->add_routes = 1;
    }
#endif /* SSHDIST_L2TP */

    /* Lock PM rule and add to the vip rule list. */
    SSH_PM_RULE_LOCK(rule);
    vrule->next = vip->rules;
    vip->rules = vrule;

    SSH_DEBUG(SSH_D_LOWOK, ("Rule %u added to VIP", (unsigned)rule->rule_id));
    return true;
}

/************************* Thread startup/shutdown **************************/

/* Destructor callback for virtual IP thread. */
static void
ssh_pm_vip_thread_destructor(SshFSM fsm, void *context)
{
    SshPmVip vip = (SshPmVip) context;
    SshPm pm = (SshPm) ssh_fsm_get_gdata_fsm(fsm);

    ssh_pm_vip_free(pm, vip);
}

bool
ssh_pm_use_virtual_ip(SshPm pm, SshPmTunnel tunnel, SshPmRule rule)
{
    SshPmVip vip;
    SshPmVirtualAdapter adapter;

    if (!tunnel || !SSH_PM_TUNNEL_IS_VIRTUAL_IP(tunnel))
    {
        SSH_DEBUG(SSH_D_ERROR, ("Bad tunnel for virtual IP"));
        return false;
    }

    if (!rule || !SSH_PM_RULE_IS_VIRTUAL_IP(rule))
    {
        SSH_DEBUG(SSH_D_ERROR, ("Bad rule for virtual IP"));
        return false;
    }

    if (tunnel->vip)
    {
        if (tunnel->vip->unusable)
        {
            SSH_DEBUG(SSH_D_ERROR, ("Virtual IP is unusable"));
            return false;
        }
        else
        {
            if (!ssh_pm_vip_add_rule(pm, tunnel->vip, rule))
              return false;

            /* If routes were added, wake up the VIP thread. */
            if (tunnel->vip->add_routes)
              ssh_fsm_condition_broadcast(&pm->fsm, &tunnel->vip->cond);

            return true;
        }
    }

    /* Find a virtual adapter. */
    if (strlen(tunnel->vip_name) > 0)
    {
        adapter = ssh_pm_virtual_adapter_find_byname(pm, tunnel->vip_name);
        if (adapter == NULL)
        {
            SSH_DEBUG(SSH_D_FAIL, ("Virtual adapter '%s' not available",
                                   tunnel->vip_name));
            return false;
        }
        else if (adapter->in_use)
        {
            SSH_DEBUG(SSH_D_FAIL, ("Virtual adapter '%s' is in use",
                                   tunnel->vip_name));
            return false;
        }
    }
    else
    {
        adapter = ssh_pm_virtual_adapter_find_unused(pm);
        if (adapter == NULL)
        {
            SSH_DEBUG(SSH_D_FAIL, ("No virtual adapters available for use"));
            return false;
        }
    }

    SSH_DEBUG(SSH_D_LOWSTART, ("Starting virtual IP thread for rule `%@'",
                               ssh_pm_rule_render, rule));

    /* Allocate vip object. */
    vip = ssh_pm_vip_alloc(pm);
    if (vip == NULL)
    {
        SSH_DEBUG(SSH_D_ERROR,
                  ("Could not allocate memory for Virtual IP thread"));
        return false;
    }

    vip->pm = pm;

    /* Mark VIP initially unusable. */
    vip->unusable = 1;
    vip->successful = 0;

#ifdef SSHDIST_ISAKMP_CFG_MODE
    if (tunnel->flags & SSH_PM_TI_CFGMODE)
      vip->t_cfgmode = 1;
#endif /* SSHDIST_ISAKMP_CFG_MODE */

#ifdef SSHDIST_L2TP
    if (tunnel->flags & SSH_PM_TI_L2TP)
      vip->t_l2tp = 1;
#endif /* SSHDIST_L2TP */

    if (!ssh_pm_vip_add_rule(pm, vip, rule))
    {
        ssh_pm_vip_free(pm, vip);
        return false;
    }

    /* Attach virtual adapter to vip object. */
    vip->adapter_ifnum = adapter->adapter_ifnum;
    adapter->in_use = true;

    /* Attach vip object to tunnel. */
    tunnel->vip = vip;

    /* Initialize VIP condition */
    ssh_fsm_condition_init(&pm->fsm, &vip->cond);

    /* Start a new PM subthread to handle virtual adapter lifecycle. */
    pm->mt_num_sub_threads++;
    ssh_fsm_thread_init(&pm->fsm, &vip->thread, ssh_pm_st_vip_start,
                        NULL_FNPTR, ssh_pm_vip_thread_destructor, vip);
    ssh_fsm_set_thread_name(&vip->thread, "VIP");
    return true;
}

void
ssh_pm_stop_virtual_ip(SshPm pm, SshPmTunnel tunnel)
{
    SSH_ASSERT(tunnel->vip->refcnt == 0);

    SSH_DEBUG(SSH_D_LOWSTART, ("Stopping virtual IP thread for tunnel %p",
                               (void *)tunnel));

    /* Mark vip unusable. */
    tunnel->vip->unusable = 1;

    /* Signal vip thread to start shutdown. */
    tunnel->vip->shutdown = 1;
    ssh_fsm_condition_broadcast(&pm->fsm, &tunnel->vip->cond);
}

#ifdef SSHDIST_ISAKMP_CFG_MODE_RULES
static bool
pm_cfgmode_rules_add_direction(
  SshPm pm, SshPmRule rule, SshPmRuleSide direction, char *traffic)
{
    uint32_t flags, precedence, index;
    SshPmTunnel from_tunnel, to_tunnel;
    SshPmRule sub_rule;

    if (direction == SSH_PM_TO)
    {
        precedence = rule->precedence;
        flags = SSH_PM_RULE_PASS | SSH_PM_RULE_ADJUST_LOCAL_ADDRESS;
        from_tunnel = NULL;
        to_tunnel = rule->side_to.tunnel;
    }
    else
    {
        precedence = rule->precedence - 1;
        flags = SSH_PM_RULE_PASS;
        from_tunnel = rule->side_to.tunnel;
        to_tunnel = NULL;
    }

    sub_rule =
        ssh_pm_rule_create(
                pm, precedence, flags, from_tunnel, to_tunnel);
    if (sub_rule == NULL)
    {
        SSH_DEBUG(SSH_D_ERROR, ("Cannot create policy rule"));
        return false;
    }

    ssh_strncpy(sub_rule->routing_instance_name, rule->routing_instance_name,
                SSH_VRI_NAMESIZE);
    sub_rule->routing_instance_id = rule->routing_instance_id;

    if (!ssh_pm_rule_set_traffic_selector(sub_rule, direction, traffic))
    {
        SSH_DEBUG(SSH_D_ERROR, ("Cannot set policy rule traffic selector"));
        ssh_pm_rule_free(pm, sub_rule);
        return false;
    }

    index = ssh_pm_rule_add(pm, sub_rule);
    if (index == SSH_IPSEC_INVALID_INDEX)
    {
        SSH_DEBUG(SSH_D_ERROR, ("Cannot add policy rule"));
        ssh_pm_rule_free(pm, sub_rule);
        return false;
    }

    sub_rule->flags |= SSH_PM_RULE_I_SYSTEM;
    sub_rule->master_rule = rule;
    sub_rule->sub_rule = rule->sub_rule;
    if (rule->sub_rule)
      rule->sub_rule->master_rule = sub_rule;
    rule->sub_rule = sub_rule;

    SSH_DEBUG(
      SSH_D_MIDOK, ("Added policy rule `%@'", ssh_pm_rule_render, sub_rule));
    return true;
}

static bool
pm_cfgmode_rules_add_subnet(SshPm pm, SshPmRule rule, SshIpAddr subnet)
{
    char addrstr[64];
    char tsstr[64];

    ssh_ipaddr_print_with_mask(subnet, addrstr, sizeof addrstr);
    ssh_snprintf(
      tsstr, sizeof tsstr, "%s(%s)",
      SSH_IP_IS6(subnet) ? "ipv6" : "ipv4", addrstr);

    if (!pm_cfgmode_rules_add_direction(pm, rule, SSH_PM_TO, tsstr) ||
        !pm_cfgmode_rules_add_direction(pm, rule, SSH_PM_FROM, tsstr))
      return false;

    return true;
}

bool
pm_cfgmode_rules_add(SshPm pm, SshPmVip vip)
{
    SshPmVipRule vrule;
    bool rules_changed = false;
    int i;

    /* Process config mode placeholder rules. */
    for (vrule = vip->rules; vrule; vrule = vrule->next)
    {
        if ((vrule->rule->flags & SSH_PM_RULE_CFGMODE_RULES) == 0)
          continue;

        /* Sub-rules already created? */
        if (vrule->rule->sub_rule)
          continue;

        for (i = 0; i < vip->attrs.num_subnets; i++)
          if (pm_cfgmode_rules_add_subnet(
                pm, vrule->rule, &vip->attrs.subnets[i]))
            rules_changed = true;
    }

    return rules_changed;
}

bool
pm_cfgmode_rules_remove(SshPm pm, SshPmVip vip)
{
    SshPmVipRule vrule;
    SshPmRule sub_rule;
    bool rules_changed = false;

    /* Process config mode placeholder rules. */
    for (vrule = vip->rules; vrule; vrule = vrule->next)
    {
        if ((vrule->rule->flags & SSH_PM_RULE_CFGMODE_RULES) == 0)
          continue;

        for (sub_rule = vrule->rule->sub_rule;
             sub_rule;
             sub_rule = sub_rule->sub_rule)
        {
            SSH_DEBUG(SSH_D_MIDOK,
              ("Removing policy rule `%@'", ssh_pm_rule_render, sub_rule));
            ssh_pm_rule_delete(pm, sub_rule->rule_id);
            rules_changed = true;
        }
    }

    return rules_changed;
}

bool
ssh_pm_virtual_ip_update_cfgmode_rules(SshPm pm, SshPmVip vip)
{
    if (!vip->unusable && vip->successful)
      return pm_cfgmode_rules_add(pm, vip);
    else
      return pm_cfgmode_rules_remove(pm, vip);
}
#endif /* SSHDIST_ISAKMP_CFG_MODE_RULES */



#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */
