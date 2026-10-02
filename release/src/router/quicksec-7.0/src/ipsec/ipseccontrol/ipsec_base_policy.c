/**
   @copyright
   Copyright (c) 2016, INSIDE Secure Oy. All rights reserved.
*/


/**
   The SPD base policy functionality.
*/

#include "ipsec_policy.h"
#include "ipsec_base_policy.h"
#include "ipsec_sa.h"
#include "ipsec_control_internal.h"

#define SSH_DEBUG_MODULE "IpsecBasePolicy"


static struct IPsecPolicyBaseEntry ipsec_system_ike_o_policy[] =
{
    /* IKE */
    { 4, SSH_IPPROTO_UDP, -1, 500 },
    { 6, SSH_IPPROTO_UDP, -1, 500 },

    /* IKE NAT-T */
    { 4, SSH_IPPROTO_UDP, -1, 4500 },
    { 6, SSH_IPPROTO_UDP, -1, 4500 },
};


static const uint32_t ipsec_num_system_ike_o_entries =
  (sizeof(ipsec_system_ike_o_policy) / sizeof(ipsec_system_ike_o_policy[0]));


static struct IPsecPolicyBaseEntry ipsec_system_ike_i_policy[] =
{
    /* IKE */
    { 4, SSH_IPPROTO_UDP, 500, -1 },
    { 6, SSH_IPPROTO_UDP, 500, -1 },

    /* IKE NAT-T */
    { 4, SSH_IPPROTO_UDP, 4500, -1 },
    { 6, SSH_IPPROTO_UDP, 4500, -1 },
};

static const uint32_t ipsec_num_system_ike_i_entries =
  (sizeof(ipsec_system_ike_i_policy) / sizeof(ipsec_system_ike_i_policy[0]));

static struct IPsecPolicyBaseEntry ipsec_system_spd_o_policy[] =
{
    /* ESP */
    { 4, SSH_IPPROTO_ESP, -1 , -1 },
    { 6, SSH_IPPROTO_ESP, -1 , -1 },

    /* DNS */
    { 4, SSH_IPPROTO_UDP, -1, 53 },
    { 4, SSH_IPPROTO_TCP, -1, 53 },
    { 6, SSH_IPPROTO_UDP, -1, 53 },
    { 6, SSH_IPPROTO_TCP, -1, 53 },

    /* DHCP for IPv4  */
    { 4, SSH_IPPROTO_UDP, 68, 67 },

    /* DHCP for IPv6  */
    { 6, SSH_IPPROTO_UDP, 546, 547 }
};

static const uint32_t ipsec_num_system_spd_o_entries =
  (sizeof(ipsec_system_spd_o_policy) / sizeof(ipsec_system_spd_o_policy[0]));


static struct IPsecPolicyBaseEntry ipsec_system_spd_i_policy[] =
{
    /* ESP */
    { 4, SSH_IPPROTO_ESP, -1 , -1 },
    { 6, SSH_IPPROTO_ESP, -1 , -1 },

    /* DNS */
    { 4, SSH_IPPROTO_UDP, 53, -1 },
    { 4, SSH_IPPROTO_TCP, 53, -1 },
    { 6, SSH_IPPROTO_UDP, 53, -1 },
    { 6, SSH_IPPROTO_TCP, 53, -1 },

    /* DHCP for IPv4  */
    { 4, SSH_IPPROTO_UDP, 67, 68 },

    /* DHCP for IPv6  */
    { 6, SSH_IPPROTO_UDP, 547, 546 }
};

static const uint32_t ipsec_num_system_spd_i_entries =
  (sizeof(ipsec_system_spd_i_policy) / sizeof(ipsec_system_spd_i_policy[0]));


static const struct IPsecPolicyIcmpId ipsec_icmp_policy[] =
{
    {   3, -1 }, /* Destination Unreachable, all codes. */
    {  11, -1 }  /* Time Exceeded, all codes. */
};


static const uint32_t ipsec_num_icmp_entries =
  (sizeof(ipsec_icmp_policy) / sizeof(ipsec_icmp_policy[0]));


static const struct IPsecPolicyIcmpId ipsec_icmpv6_policy[] =
{
    {   1, -1 }, /* Destination Unreachable        [RFC4443] */
    {   2, -1 }, /* Packet Too Big                 [RFC4443] */
    {   3, -1 }, /* Time Exceeded                  [RFC4443] */
    {   4, -1 }, /* Parameter Problem              [RFC4443] */
    { 130, -1 }, /* Multicast Listener Query        [RFC2710] */
    { 131, -1 }, /* Multicast Listener Report       [RFC2710] */
    { 132, -1 }, /* Multicast Listener Done         [RFC2710] */
    { 133, -1 }, /* Router Solicitation             [RFC4861] */
    { 134, -1 }, /* Router Advertisement            [RFC4861] */
    { 135, -1 }, /* Neighbor Solicitation           [RFC4861] */
    { 136, -1 }, /* Neighbor Advertisement          [RFC4861] */
    { 137, -1 }, /* Redirect Message                [RFC4861] */
    { 138, -1 }, /* Router Renumbering              [Matt_Crawford] */
    { 141, -1 }, /* Inverse Neighbor Discovery Solicitation Message
                    [RFC3122] */
    { 142, -1 }, /* Inverse Neighbor Discovery Advertisement Message
                    [RFC3122] */
    { 143, -1 }, /* Version 2 Multicast Listener Report [RFC3810] */
    { 144, -1 }, /* Home Agent Address Discovery Request Message
                    [RFC6275] */
    { 145, -1 }, /* Home Agent Address Discovery Reply Message
                    [RFC6275] */
    { 146, -1 }, /* Mobile Prefix Solicitation [RFC6275] */
    { 147, -1 }, /* Mobile Prefix Advertisement [RFC6275] */
    { 148, -1 }, /* Certification Path Solicitation Message
                    [RFC3971] */
    { 149, -1 }, /* Certification Path Advertisement Message
                    [RFC3971] */
    { 151, -1 }, /* Multicast Router Advertisement  [RFC4286] */
    { 152, -1 }, /* Multicast Router Solicitation   [RFC4286] */
    { 153, -1 }, /* Multicast Router Termination    [RFC4286] */
    { 154, -1 }, /* FMIPv6 Messages                 [RFC5568] */
    { 155, -1 }, /* RPL Control Message             [RFC6550] */
    { 156, -1 }, /* ILNPv6 Locator Update Message   [RFC6743] */
    { 157, -1 }, /* Duplicate Address Request       [RFC-ietf-6lowpan-nd-21] */
    { 158, -1 }  /* Duplicate Address Confirmation  [RFC-ietf-6lowpan-nd-21] */
};

static const uint32_t ipsec_num_icmpv6_entries =
  (sizeof(ipsec_icmpv6_policy) / sizeof(ipsec_icmpv6_policy[0]));

static struct IPsecPolicyBaseEntry ipsec_base_spd_o_policy[] =
{
    /* All traffic */
    { 4, 0, -1 , -1 },
    { 6, 0, -1 , -1 }
};

static const uint32_t ipsec_num_base_spd_o_entries =
  (sizeof(ipsec_base_spd_o_policy) / sizeof(ipsec_base_spd_o_policy[0]));


static struct IPsecPolicyBaseEntry ipsec_base_spd_i_policy[] =
{
    /* All traffic  */
    { 4, 0, -1 , -1 },
    { 6, 0, -1 , -1 }
};

static const uint32_t ipsec_num_base_spd_i_entries =
  (sizeof(ipsec_base_spd_i_policy) / sizeof(ipsec_base_spd_i_policy[0]));

bool
ipsec_system_policy_set(struct IPsecControl *ipsec_control, bool is_responder)
{
    bool ok = true;
    struct IPsecPolicyBaseEntry* ike_out_policies;
    struct IPsecPolicyBaseEntry* ike_in_policies;
    uint32_t ike_out_entries;
    uint32_t ike_in_entries;

    /* flip the IKE and NAT-T entries for responder */
    if (is_responder == true)
    {
        ike_out_policies = &ipsec_system_ike_i_policy[0];
        ike_out_entries = ipsec_num_system_ike_i_entries;
        ike_in_policies = &ipsec_system_ike_o_policy[0];
        ike_in_entries = ipsec_num_system_ike_o_entries;
    }
    else
    {
        ike_out_policies = &ipsec_system_ike_o_policy[0];
        ike_out_entries = ipsec_num_system_ike_o_entries;
        ike_in_policies = &ipsec_system_ike_i_policy[0];
        ike_in_entries = ipsec_num_system_ike_i_entries;
    }

    /* Base policies */
    if (ok == true)
    {
        ok =
            ipsec_policy_add_base_entry(
                    ipsec_control,
                    IPSEC_POLICY_O,
                    IPSEC_POLICY_BYPASS,
                    IPSEC_PRIORITY_O_BASE_BYPASS,
                    &ipsec_system_spd_o_policy[0],
                    ipsec_num_system_spd_o_entries,
                    &ipsec_control->system_spd_o_entry_id);
    }

    if (ok == true)
    {
        ok =
            ipsec_policy_add_base_entry(
                    ipsec_control,
                    IPSEC_POLICY_I,
                    IPSEC_POLICY_BYPASS,
                    IPSEC_PRIORITY_I_BASE_BYPASS,
                    &ipsec_system_spd_i_policy[0],
                    ipsec_num_system_spd_i_entries,
                    &ipsec_control->system_spd_i_entry_id);
    }

    /* IKE and NAT-T */
    if (ok == true)
    {
        ok =
            ipsec_policy_add_base_entry(
                    ipsec_control,
                    IPSEC_POLICY_O,
                    IPSEC_POLICY_BYPASS,
                    IPSEC_PRIORITY_O_BASE_BYPASS,
                    ike_out_policies,
                    ike_out_entries,
                    &ipsec_control->ike_spd_o_entry_id);
    }

    if (ok == true)
    {
        ok =
            ipsec_policy_add_base_entry(
                    ipsec_control,
                    IPSEC_POLICY_I,
                    IPSEC_POLICY_BYPASS,
                    IPSEC_PRIORITY_I_BASE_BYPASS,
                    ike_in_policies,
                    ike_in_entries,
                    &ipsec_control->ike_spd_i_entry_id);
    }

    if (ok == false)
    {
        ipsec_system_policy_clear(ipsec_control);
    }

    return ok;
}

void
ipsec_system_policy_clear(struct IPsecControl *ipsec_control)
{
    if (ipsec_control != NULL)
    {
        if (ipsec_control->system_spd_o_entry_id != 0)
        {
            ipsec_policy_remove_entry(
                    ipsec_control,
                    ipsec_control->system_spd_o_entry_id);
        }

        if (ipsec_control->system_spd_i_entry_id != 0)
        {
            ipsec_policy_remove_entry(
                    ipsec_control,
                    ipsec_control->system_spd_i_entry_id);
        }

        if (ipsec_control->ike_spd_o_entry_id != 0)
        {
            ipsec_policy_remove_entry(
                    ipsec_control,
                    ipsec_control->ike_spd_o_entry_id);
        }

        if (ipsec_control->ike_spd_i_entry_id != 0)
        {
            ipsec_policy_remove_entry(
                    ipsec_control,
                    ipsec_control->ike_spd_i_entry_id);
        }

        ipsec_control->system_spd_o_entry_id = 0;
        ipsec_control->system_spd_i_entry_id = 0;
        ipsec_control->ike_spd_o_entry_id = 0;
        ipsec_control->ike_spd_i_entry_id = 0;
    }
}

bool
ipsec_base_policy_set(struct IPsecControl *ipsec_control, bool discard)
{
    IPsecPolicyAction action;
    bool ok = true;

    /* Resolve action. */
    action = (discard == true) ? IPSEC_POLICY_DISCARD : IPSEC_POLICY_BYPASS;

    if (ok == true)
    {
        ok =
            ipsec_policy_add_icmp_entry(
                    ipsec_control,
                    IPSEC_POLICY_O,
                    IPSEC_POLICY_BYPASS,
                    IPSEC_PRIORITY_O_BASE_BYPASS,
                    &ipsec_icmp_policy[0],
                    ipsec_num_icmp_entries,
                    &ipsec_icmpv6_policy[0],
                    ipsec_num_icmpv6_entries,
                    &ipsec_control->icmp_spd_o_entry_id);
    }

    if (ok == true)
    {
        ok =
            ipsec_policy_add_icmp_entry(
                    ipsec_control,
                    IPSEC_POLICY_I,
                    IPSEC_POLICY_BYPASS,
                    IPSEC_PRIORITY_I_BASE_BYPASS,
                    &ipsec_icmp_policy[0],
                    ipsec_num_icmp_entries,
                    &ipsec_icmpv6_policy[0],
                    ipsec_num_icmpv6_entries,
                    &ipsec_control->icmp_spd_i_entry_id);
    }

    if (ok == true)
    {
        ok =
            ipsec_policy_add_base_entry(
                    ipsec_control,
                    IPSEC_POLICY_O,
                    action,
                    IPSEC_PRIORITY_O_BASE_INITIAL,
                    &ipsec_base_spd_o_policy[0],
                    ipsec_num_base_spd_o_entries,
                    &ipsec_control->base_spd_o_entry_id);
    }

    if (ok == true)
    {
        ok =
            ipsec_policy_add_base_entry(
                    ipsec_control,
                    IPSEC_POLICY_I,
                    action,
                    IPSEC_PRIORITY_I_BASE_INITIAL,
                    &ipsec_base_spd_i_policy[0],
                    ipsec_num_base_spd_i_entries,
                    &ipsec_control->base_spd_i_entry_id);
    }

    if (ok == false)
    {
        ipsec_base_policy_clear(ipsec_control);
    }

    return ok;
}

void
ipsec_base_policy_clear(struct IPsecControl *ipsec_control)
{
    if (ipsec_control != NULL)
    {
        if (ipsec_control->base_spd_o_entry_id != 0)
        {
            ipsec_policy_remove_entry(
                    ipsec_control,
                    ipsec_control->base_spd_o_entry_id);
        }

        if (ipsec_control->base_spd_i_entry_id != 0)
        {
            ipsec_policy_remove_entry(
                    ipsec_control,
                    ipsec_control->base_spd_i_entry_id);
        }

        if (ipsec_control->icmp_spd_o_entry_id != 0)
        {
            ipsec_policy_remove_entry(
                    ipsec_control,
                    ipsec_control->icmp_spd_o_entry_id);
        }

        if (ipsec_control->icmp_spd_i_entry_id != 0)
        {
            ipsec_policy_remove_entry(
                    ipsec_control,
                    ipsec_control->icmp_spd_i_entry_id);
        }

        ipsec_control->base_spd_o_entry_id = 0;
        ipsec_control->base_spd_i_entry_id = 0;
        ipsec_control->icmp_spd_o_entry_id = 0;
        ipsec_control->icmp_spd_i_entry_id = 0;
    }
}


