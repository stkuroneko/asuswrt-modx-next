/**
   @copyright
   Copyright (c) 2012 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   IPsec policy interface.
*/


#ifndef IPSEC_POLICY_H
#define IPSEC_POLICY_H

#include "ipsec_control.h"
#include "ipsec_policy_params.h"

/** Structure for base parameters when adding an IPsec policy entry. */
struct IPsecPolicyBaseEntry
{
    /** IP version */
    int ip_version;

    /** IP protocol */
    int ip_protocol;

    /** Source port */
    int source_port;

    /** Destination port */
    int destination_port;
};

/** Structure for ICMP parameters when adding an IPsec policy entry. */
struct IPsecPolicyIcmpId
{
    /** ICMP type */
    int type;
    /** ICMP code */
    int code;
};

/* Function to add new IPsec policy entry to IPsec SPD. */
bool
ipsec_policy_add_entry(
        struct IPsecControl *ipsec_control,
        IPsecPolicyRole role,
        IPsecPolicyAction action,
        int priority,
        struct IPSelectorGroup *selector_group,
        int *ipsec_policy_id_ret);

bool
ipsec_policy_add_base_entry(
        struct IPsecControl *ipsec_control,
        IPsecPolicyRole role,
        IPsecPolicyAction action,
        int priority,
        const struct IPsecPolicyBaseEntry *entries,
        int entries_count,
        int *ipsec_policy_id_ret);

bool
ipsec_policy_add_network_entry(
        struct IPsecControl *ipsec_control,
        IPsecPolicyRole role,
        IPsecPolicyAction action,
        int priority,
        const struct InAddr *networks,
        const int *net_masks,
        int networks_count,
        int *ipsec_policy_id_ret);

bool
ipsec_policy_add_5tuple_entry(
        struct IPsecControl *ipsec_control,
        IPsecPolicyRole role,
        IPsecPolicyAction action,
        int priority,
        const struct InAddr *source_address,
        const struct InAddr *destination_address,
        int in_protocol,
        int local_port,
        int remote_port,
        int *ipsec_policy_id_ret);

bool
ipsec_policy_add_icmp_entry(
        struct IPsecControl *ipsec_control,
        IPsecPolicyRole role,
        IPsecPolicyAction action,
        int priority,
        const struct IPsecPolicyIcmpId *icmp_ids,
        int icmp_id_count,
        const struct IPsecPolicyIcmpId *icmpv6_ids,
        int icmpv6_id_count,
        int *ipsec_policy_id_ret);

bool
ipsec_policy_add_5tuple_bypass_entry(
        struct IPsecControl *ipsec_control,
        const struct InAddr *local_address,
        const struct InAddr *remote_address,
        int in_protocol,
        int local_port,
        int remote_port,
        int *ipsec_policy_id_ret);

void
ipsec_policy_remove_entry(
        struct IPsecControl *ipsec_control,
        int ipsec_policy_id);

void
ipsec_policy_remove_entry_with_delay(
        struct IPsecControl *ipsec_control,
        int ipsec_policy_id,
        int delay_seconds);

#endif /* IPSEC_POLICY_H */
