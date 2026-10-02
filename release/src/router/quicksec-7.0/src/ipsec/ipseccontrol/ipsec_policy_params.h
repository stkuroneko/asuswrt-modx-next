/**
   @copyright
   Copyright (c) 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   Header for IPsec policy structures.
*/

#ifndef IPSEC_POLICY_PARAMS_H
#define IPSEC_POLICY_PARAMS_H

#include "in_addr.h"

/** IPsec priorities (outbound direction). */
enum
{
    IPSEC_PRIORITY_SA = 1000,
    IPSEC_PRIORITY_S = 2000,
    IPSEC_PRIORITY_O_BASE_DROP = 3000,
    IPSEC_PRIORITY_O_DNS_DROP = 4000,
    IPSEC_PRIORITY_O_BASE_BYPASS = 5000,
    IPSEC_PRIORITY_O_INTERFACE_ADDRESS = 6000,
    IPSEC_PRIORITY_O_SUBNET = 7000,
    IPSEC_PRIORITY_SA_LOW = 8000,
    IPSEC_PRIORITY_O_USER = 100000,
    IPSEC_PRIORITY_O_SPLIT_TUNNELING = 2000000000,
    IPSEC_PRIORITY_O_BASE_INITIAL = 2000001000
};

/** IPsec priorities (inbound direction). */
enum
{
    IPSEC_PRIORITY_I_BASE_DROP = 3000,
    IPSEC_PRIORITY_I_DNS_DROP = 4000,
    IPSEC_PRIORITY_I_BASE_BYPASS = 5000,
    IPSEC_PRIORITY_I_INTERFACE_ADDRESS = 6000,
    IPSEC_PRIORITY_I_SUBNET = 7000,
    IPSEC_PRIORITY_I_USER = 100000,
    IPSEC_PRIORITY_I_SPLIT_TUNNELING = 2000000000,
    IPSEC_PRIORITY_I_BASE_INITIAL = 2000001000
};

/** IPsec policy roles. */
typedef enum
{
    /** Security Association. */
    IPSEC_POLICY_SA,

    /** Secure. */
    IPSEC_POLICY_S,

    /** Inbound. */
    IPSEC_POLICY_I,

    /** Outbound. */
    IPSEC_POLICY_O,


    /** This must be the last value. */
    IPSEC_POLICY_COUNT
}
IPsecPolicyRole;

/** IPsec policy actions. */
typedef enum
{
    /** Packet must be discarded. */
    IPSEC_POLICY_DISCARD,

    /** Packet must be forwarded without protection. */
    IPSEC_POLICY_BYPASS,

    /** Packet must be protected. */
    IPSEC_POLICY_PROTECT
}
IPsecPolicyAction;

/** Structure for parameters for IPsec policy callbacks. */
struct IPsecPolicyParams
{
    int policy_id;
    IPsecPolicyRole role;
    IPsecPolicyAction action;
    int priority;
    struct IPSelectorGroup *selector_group;
};

#endif /* IPSEC_POLICY_PARAMS_H */
