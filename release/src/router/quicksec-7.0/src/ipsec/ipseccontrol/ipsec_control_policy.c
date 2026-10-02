/**
   @copyright
   Copyright (c) 2013 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   IPsec Control Policy module.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"


#include "ipsec_control.h"
#include "ipsec_control_internal.h"
#include "ip_selector_encode.h"
#include "ipsec_policy.h"


#define SSH_DEBUG_MODULE "IPsecControlPolicy"
#define __DEBUG_MODULE__ IPsecControlPolicy

#define IPSEC_CONTROL_MAX_BYPASS_ENTRIES 32


/* Function to convert SSH IP address format to format used by IP selector. */
static int
ipsec_policy_encode_selector_addresses(
        const struct InAddr *start_address,
        const struct InAddr *end_address,
        unsigned char *selector_address_begin,
        unsigned char *selector_address_end)
{
    int ip_version;

    if (in_addr_version(start_address) == IN_ADDR_FOUR)
    {
        memset(selector_address_begin, 0, 12);
        memcpy(&selector_address_begin[12], in_addr_ip_data(start_address), 4);

        memset(selector_address_end, 0, 12);
        memcpy(&selector_address_end[12], in_addr_ip_data(end_address), 4);

        ip_version = 4;
    }
    else
    {
        memcpy(selector_address_begin, in_addr_ip_data(start_address), 16);
        memcpy(selector_address_end, in_addr_ip_data(end_address), 16);

        ip_version = 6;
    }

    return ip_version;
}


/* Function to convert SSH IP network address to IP selector's begin and
   end address. */
static void
ipsec_policy_encode_network_to_selector_addresses(
        const struct InAddr *network,
        unsigned int mask_len,
        unsigned char *selector_address_begin,
        unsigned char *selector_address_end,
        int *ip_version)
{
    struct InAddr start_address_st;
    struct InAddr end_address_st;

    /* Make start and end addresses.
       Mask length not fixed because its not relevant in this case. */
    in_addr_copy(&start_address_st, network, IN_ADDR_BIT_COUNT);
    in_addr_copy(&end_address_st, network, IN_ADDR_BIT_COUNT);
    in_addr_host_bits_clear(&start_address_st, mask_len);
    in_addr_host_bits_set(&end_address_st, mask_len);

    /* Convert addresses to format used by selector. */
    *ip_version =
        ipsec_policy_encode_selector_addresses(
                &start_address_st,
                &end_address_st,
                selector_address_begin,
                selector_address_end);
}

/* Function to remove IPSec Policy entry from database and free it. */
static void
ipsec_control_policy_free(
        struct IPsecPolicy *ipsec_policy)
{
    if (ipsec_policy != NULL)
    {
        ipsec_control_db_policy_remove(
                ipsec_policy->ipsec_control,
                ipsec_policy);

        IPSEC_POLICY_DEBUG(
                LOW,
                ipsec_policy,
                "Freed.");

        if (ipsec_policy->params.selector_group != NULL)
        {
            ssh_free(ipsec_policy->params.selector_group);
        }

        if (SSH_TIMEOUT_IS_REGISTERED(
                    &ipsec_policy->remove_timeout)
            == true)
        {
            ssh_cancel_timeout(&ipsec_policy->remove_timeout);
        }

        ssh_free(ipsec_policy);
    }
}

/* Function to allocate IPsec Policy entry and insert it to database. */
static bool
ipsec_control_policy_allocate(
        struct IPsecControl *ipsec_control,
        struct IPsecPolicy **ipsec_policy_p,
        IPsecPolicyRole role,
        IPsecPolicyAction action,
        int priority,
        struct IPSelectorGroup *selector_group)
{
    struct IPsecPolicy *ipsec_policy = NULL;
    bool status = true;

    if (status == true)
    {
        ipsec_policy = ssh_calloc(1, sizeof *ipsec_policy);
        if (ipsec_policy == NULL)
        {
            IPSEC_CONTROL_DEBUG(
                    FAIL,
                    ipsec_control,
                    "Out of memory while allocating IPsec Policy");

            status = false;
        }
    }

    if (status == true)
    {
        ipsec_policy->sibling_policy_id = -1;
        ipsec_policy->params.selector_group =
            ssh_malloc(
                    selector_group->bytecount);

        if (ipsec_policy->params.selector_group == NULL)
        {
            IPSEC_CONTROL_DEBUG(
                    FAIL,
                    ipsec_control,
                    "selector allocation failed while allocating "
                    "IPsec Policy");
            status = false;
        }
    }

    if (status == true)
    {
        int policy_id = ++ipsec_control->ipsec_policy_ids;

        ipsec_policy->params.role = role;
        ipsec_policy->params.action = action;
        ipsec_policy->params.priority = priority;

        memcpy(
                ipsec_policy->params.selector_group,
                selector_group,
                selector_group->bytecount);

        ipsec_policy->params.policy_id = policy_id;
        ipsec_policy->policy_id = policy_id;
        ipsec_policy->ipsec_control = ipsec_control;

        IPSEC_POLICY_DEBUG(
                LOW,
                ipsec_policy,
                "Allocated.");

        ipsec_control_db_policy_insert(
                ipsec_control,
                ipsec_policy);
    }
    else
    {
        if (ipsec_policy != NULL)
        {
            if (ipsec_policy->params.selector_group != NULL)
            {
                ssh_free(ipsec_policy->params.selector_group);
            }

            ssh_free(ipsec_policy);
            ipsec_policy = NULL;
        }
    }

    if (ipsec_policy_p != NULL)
    {
        *ipsec_policy_p = ipsec_policy;
    }

    return status;
}


/* Function to add new IPsec policy entry to IPsec SPD. */
bool
ipsec_policy_add_entry(
        struct IPsecControl *ipsec_control,
        IPsecPolicyRole role,
        IPsecPolicyAction action,
        int priority,
        struct IPSelectorGroup *selector_group,
        int *ipsec_policy_id_ret)
{
    struct IPsecPolicy *ipsec_policy = NULL;
    bool ok;

    ok =
        ipsec_control_policy_allocate(
                ipsec_control,
                &ipsec_policy,
                role,
                action,
                priority,
                selector_group);

    if (ok == true)
    {
        if (ipsec_control->control_callbacks != NULL &&
            ipsec_control->control_callbacks->install_policy_cb != NULL)
        {
            void *control_policy;

            ok =
                ipsec_control->control_callbacks->install_policy_cb(
                        ipsec_control->control_param,
                        &ipsec_policy->params,
                        &control_policy);

            if (ok == true)
            {
                ipsec_policy->control_policy = control_policy;

                IPSEC_POLICY_DEBUG(
                        LOW,
                        ipsec_policy,
                        "Installed.");
            }
            else
            {
                IPSEC_POLICY_DEBUG(
                        FAIL,
                        ipsec_policy,
                        "Install failed.");
            }
        }
    }

    if (ok == true)
    {
        *ipsec_policy_id_ret = ipsec_policy->policy_id;
    }
    else
    {
        ipsec_control_policy_free(ipsec_policy);
    }

    return ok;
}


/* Function to init encoding of IP selector. */
static struct IPSelectorGroup *
ipsec_policy_init_ip_selector_encoding(
        struct IPSelectorEncode *encoder,
        int selector_count,
        int endpoint_count,
        int port_count,
        int address_count)
{
    struct IPSelectorGroup *selector_group;
    int selector_group_size;

    /* Get size of selector group, allocate memory for it and init encoding. */
    selector_group_size =
        ip_selector_encode_selector_group_bytecount(
                selector_count,
                endpoint_count,
                port_count,
                address_count);
    selector_group = ssh_malloc(selector_group_size);
    if (selector_group != NULL)
    {
        ip_selector_encode_init(encoder, selector_group, selector_group_size);
    }
    else
    {
        SSH_DEBUG(SSH_D_FAIL, ("Cannot allocate memory for selector group."));
    }

    return selector_group;
}


/* Public function; documented in the ipsec_policy.h header file. */
bool
ipsec_policy_add_base_entry(
        struct IPsecControl *ipsec_control,
        IPsecPolicyRole role,
        IPsecPolicyAction action,
        int priority,
        const struct IPsecPolicyBaseEntry *entries,
        int entries_count,
        int *ipsec_policy_id_ret)
{
    struct IPSelectorGroup *selector_group;
    struct IPSelectorEncode encoder_st;
    bool ok = true;
    int port_count = 0;
    int i;

    /* Calculate number of ports. */
    for (i = 0; i < entries_count; i++)
    {
        const struct IPsecPolicyBaseEntry *entry = &entries[i];

        if (entry->source_port >= 0)
        {
            port_count++;
        }

        if (entry->destination_port >= 0)
        {
            port_count++;
        }
    }

    /* Init IP selector encoding. */
    selector_group =
        ipsec_policy_init_ip_selector_encoding(
                &encoder_st,
                entries_count,
                0,
                port_count,
                0);
    if (selector_group == NULL)
    {
        ok = false;
    }

    /* Go through all base entries and encode them. */
    if (ok == true)
    {
        for (i = 0; i < entries_count; i++)
        {
            const struct IPsecPolicyBaseEntry *entry = &entries[i];

            ip_selector_encode_add_selector(
                    &encoder_st,
                    entry->ip_version,
                    entry->ip_protocol);

            if (entry->source_port >= 0)
            {
                ip_selector_encode_add_source_port(
                        &encoder_st,
                        entry->source_port,
                        entry->source_port);
            }

            if (entry->destination_port >= 0)
            {
                ip_selector_encode_add_destination_port(
                        &encoder_st,
                        entry->destination_port,
                        entry->destination_port);
            }
        }
    }

    /* Add new IPsec policy entry. */
    if (ok == true)
    {
        ok =
            ipsec_policy_add_entry(
                    ipsec_control,
                    role,
                    action,
                    priority,
                    selector_group,
                    ipsec_policy_id_ret);
    }

    if (selector_group != NULL)
    {
        ssh_free(selector_group);
    }

    return ok;
}

/* Public function; documented in the ipsec_policy.h header file. */
bool
ipsec_policy_add_network_entry(
        struct IPsecControl *ipsec_control,
        IPsecPolicyRole role,
        IPsecPolicyAction action,
        int priority,
        const struct InAddr *networks,
        const int *net_masks,
        int networks_count,
        int *ipsec_policy_id_ret)
{
    struct IPSelectorGroup *selector_group;
    struct IPSelectorEncode encoder_st;
    bool ok = true;

    /* Init IP selector encoding. */
    selector_group =
        ipsec_policy_init_ip_selector_encoding(
                &encoder_st,
                1,
                networks_count,
                0,
                0);
    if (selector_group == NULL)
    {
        ok = false;
    }

    /* Go through all networks and add them to IP selector group. */
    if (ok == true)
    {
        int i;

        ip_selector_encode_add_selector(&encoder_st, 0, 0);

        for (i = 0; i < networks_count; i++)
        {
            unsigned char address_begin[16];
            unsigned char address_end[16];
            int ip_version;

            ipsec_policy_encode_network_to_selector_addresses(
                    &networks[i],
                    net_masks[i],
                    address_begin,
                    address_end,
                    &ip_version);

            /* In inbound direction network address is set to
               source address field. */
            if (role == IPSEC_POLICY_I)
            {
                ip_selector_encode_add_source_endpoint(
                        &encoder_st,
                        address_begin,
                        address_end,
                        IP_SELECTOR_PORT_MIN,
                        IP_SELECTOR_PORT_MAX,
                        ip_version,
                        0);
            }
            else
            {
                ip_selector_encode_add_destination_endpoint(
                        &encoder_st,
                        address_begin,
                        address_end,
                        IP_SELECTOR_PORT_MIN,
                        IP_SELECTOR_PORT_MAX,
                        ip_version,
                        0);
            }
        }
    }

    /* Add new IPsec policy entry. */
    if (ok == true)
    {
        ok =
            ipsec_policy_add_entry(
                    ipsec_control,
                    role,
                    action,
                    priority,
                    selector_group,
                    ipsec_policy_id_ret);
    }

    if (selector_group != NULL)
    {
        ssh_free(selector_group);
    }

    return ok;
}

static struct IPSelectorGroup *
ipsec_policy_create_5tuple_selector_group(
        const struct InAddr *source_address,
        const struct InAddr *destination_address,
        int in_protocol,
        int local_port,
        int remote_port)
{
    struct IPSelectorGroup *selector_group;
    struct IPSelectorEncode encoder_st;

    /* Init IP selector encoding. */
    selector_group =
        ipsec_policy_init_ip_selector_encoding(
                &encoder_st,
                1,
                0,
                2,
                2);

    /* Go through all networks and add them to IP selector group. */
    if (selector_group != NULL)
    {
        unsigned char address_begin[16];
        unsigned char address_end[16];
        int ip_version = 0;

        if (source_address != NULL)
        {
            ip_version =
                in_addr_version(source_address) == IN_ADDR_FOUR ? 4 : 6;
        }
        else
        if (destination_address != NULL)
        {
            ip_version =
                in_addr_version(destination_address) == IN_ADDR_FOUR ? 4 : 6;
        }

        ip_selector_encode_add_selector(&encoder_st, ip_version, in_protocol);

        if (source_address != NULL)
        {
            (void)
                ipsec_policy_encode_selector_addresses(
                        source_address,
                        source_address,
                        address_begin,
                        address_end);

            ip_selector_encode_add_source_address(
                    &encoder_st,
                    address_begin,
                    address_end);
        }

        if (destination_address != NULL)
        {
            (void)
                ipsec_policy_encode_selector_addresses(
                        destination_address,
                        destination_address,
                        address_begin,
                        address_end);

            ip_selector_encode_add_destination_address(
                    &encoder_st,
                    address_begin,
                    address_end);
        }

        if (local_port != -1)
        {
            ip_selector_encode_add_source_port(
                    &encoder_st,
                    local_port,
                    local_port);
        }

        if (remote_port != -1)
        {
            ip_selector_encode_add_destination_port(
                    &encoder_st,
                    remote_port,
                    remote_port);
        }
    }

    return selector_group;
}


/* Public function; documented in the ipsec_policy.h header file. */
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
        int *ipsec_policy_id_ret)
{
    struct IPSelectorGroup *selector_group;
    bool ok = true;

    selector_group =
        ipsec_policy_create_5tuple_selector_group(
                source_address,
                destination_address,
                in_protocol,
                local_port,
                remote_port);

    if (selector_group == NULL)
    {
        ok = false;
    }

    /* Add new IPsec policy entry. */
    if (ok == true)
    {
        ok =
            ipsec_policy_add_entry(
                    ipsec_control,
                    role,
                    action,
                    priority,
                    selector_group,
                    ipsec_policy_id_ret);
    }

    if (selector_group != NULL)
    {
        ssh_free(selector_group);
    }

    return ok;
}


static void
ipsec_policy_add_icmp_ids(
        struct IPSelectorEncode *encoder,
        const struct IPsecPolicyIcmpId *icmp_ids,
        int icmp_id_count)
{
    int i;

    for (i = 0; i < icmp_id_count; i++)
    {
        const int type = icmp_ids[i].type;
        const int code = icmp_ids[i].code;
        int port_start;
        int port_end;

        if (type == -1)
        {
            port_start = IP_SELECTOR_PORT_MIN;
            port_end = IP_SELECTOR_PORT_MAX;
        }
        else
        {
            port_start = 0xff00 & (type << 8);

            if (code == -1)
            {
                port_end = port_start | 0xff;
            }
            else
            {
                port_start |= code;
                port_end = port_start;
            }
        }

        ip_selector_encode_add_destination_port(
                encoder,
                port_start,
                port_end);
    }
}


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
        int *ipsec_policy_id_ret)
{
    struct IPSelectorGroup *selector_group;
    struct IPSelectorEncode encoder_st;
    bool ok = true;

    /* Init IP selector encoding. */
    selector_group =
        ipsec_policy_init_ip_selector_encoding(
                &encoder_st,
                2,
                0,
                0,
                icmp_id_count + icmpv6_id_count);

    if (selector_group == NULL)
    {
        ok = false;
    }

    /* Go through all networks and add them to IP selector group. */
    if (ok == true)
    {
        ip_selector_encode_add_selector(&encoder_st, 4, SSH_IPPROTO_ICMP);

        ipsec_policy_add_icmp_ids(
                &encoder_st,
                icmp_ids,
                icmp_id_count);

        ip_selector_encode_add_selector(&encoder_st, 6, SSH_IPPROTO_IPV6ICMP);

        ipsec_policy_add_icmp_ids(
                &encoder_st,
                icmpv6_ids,
                icmpv6_id_count);
    }

    /* Add new IPsec policy entry. */
    if (ok == true)
    {
        ok =
            ipsec_policy_add_entry(
                    ipsec_control,
                    role,
                    action,
                    priority,
                    selector_group,
                    ipsec_policy_id_ret);
    }

    if (selector_group != NULL)
    {
        ssh_free(selector_group);
    }

    return ok;
}

static void
ipsec_policy_5tuple_log_event(
        const char *what,
        int policy_id,
        const struct InAddr *local_address,
        const struct InAddr *remote_address,
        int in_protocol,
        int local_port,
        int remote_port)
{
    char local_str[100] = "<any>";
    char remote_str[100] = "<any>";

    if (local_address != NULL)
    {
        in_addr_str(
                local_address,
                local_str,
                sizeof local_str);
    }

    if (remote_address != NULL)
    {
        in_addr_str(
                remote_address,
                remote_str,
                sizeof remote_str);
    }

    ssh_log_event(
            SSH_LOGFACILITY_DAEMON,
            SSH_LOG_INFORMATIONAL,
            "%s: Entry id %d %s %s:%d -> %s:%d.",
            what,
            policy_id,
            ssh_ipproto_str(in_protocol),
            local_str,
            local_port,
            remote_str,
            remote_port);
}

bool
ipsec_policy_add_5tuple_bypass_entry(
        struct IPsecControl *ipsec_control,
        const struct InAddr *local_address,
        const struct InAddr *remote_address,
        int in_protocol,
        int local_port,
        int remote_port,
        int *ipsec_policy_id_ret)
{
    int outbound_policy_id = -1;
    int inbound_policy_id = -1;
    bool ok = true;

    if (ipsec_control->bypass_entry_count >= IPSEC_CONTROL_MAX_BYPASS_ENTRIES)
    {
        ipsec_policy_5tuple_log_event(
                "Maximum entries created. Not creating new BYPASS entry",
                -1,
                local_address,
                remote_address,
                in_protocol,
                local_port,
                remote_port);

        ok = false;
    }

    if (ok == true)
    {
        ok =
            ipsec_policy_add_5tuple_entry(
                    ipsec_control,
                    IPSEC_POLICY_O,
                    IPSEC_POLICY_BYPASS,
                    IPSEC_PRIORITY_O_BASE_BYPASS,
                    local_address,
                    remote_address,
                    in_protocol,
                    local_port,
                    remote_port,
                    &outbound_policy_id);
    }

    if (ok == true)
    {
        ok =
            ipsec_policy_add_5tuple_entry(
                    ipsec_control,
                    IPSEC_POLICY_I,
                    IPSEC_POLICY_BYPASS,
                    IPSEC_PRIORITY_I_BASE_BYPASS,
                    remote_address,
                    local_address,
                    in_protocol,
                    remote_port,
                    local_port,
                    &inbound_policy_id);
    }

    if (ok == true)
    {
        struct IPsecPolicy *outbound_policy;
        struct IPsecPolicy *inbound_policy;

        outbound_policy =
            ipsec_control_db_policy_lookup(
                    ipsec_control,
                    outbound_policy_id);

        ASSERT(outbound_policy != NULL);

        inbound_policy =
            ipsec_control_db_policy_lookup(
                    ipsec_control,
                    inbound_policy_id);

        ASSERT(inbound_policy != NULL);

        outbound_policy->sibling_policy_id = inbound_policy_id;

        *ipsec_policy_id_ret = outbound_policy_id;

        outbound_policy->bypass_entry = true;
        ++ipsec_control->bypass_entry_count;

        inbound_policy->bypass_entry = true;
        ++ipsec_control->bypass_entry_count;

        ipsec_policy_5tuple_log_event(
                "Creating outbound BYPASS entry",
                outbound_policy_id,
                local_address,
                remote_address,
                in_protocol,
                local_port,
                remote_port);

        ipsec_policy_5tuple_log_event(
                "Creating inbound BYPASS entry",
                inbound_policy_id,
                remote_address,
                local_address,
                in_protocol,
                remote_port,
                local_port);
    }
    else
    {
        if (outbound_policy_id != -1)
        {
            ipsec_policy_remove_entry(
                    ipsec_control,
                    outbound_policy_id);
        }
    }

    return ok;
}


/* Public function; documented in the ipsec_policy.h header file. */
void
ipsec_policy_remove_entry(
        struct IPsecControl *ipsec_control,
        int ipsec_policy_id)
{
    struct IPsecPolicy *ipsec_policy;
    int sibling_policy_id = -1;

    /* Find IPsec Policy from database. */
    ipsec_policy =
        ipsec_control_db_policy_lookup(
                ipsec_control,
                ipsec_policy_id);

    if (ipsec_policy != NULL)
    {
        sibling_policy_id = ipsec_policy->sibling_policy_id;

        if (ipsec_control->control_callbacks != NULL &&
            ipsec_control->control_callbacks->delete_policy_cb != NULL)
        {
            ipsec_control->control_callbacks->delete_policy_cb(
                    ipsec_control->control_param,
                    &ipsec_policy->params,
                    &ipsec_policy->control_policy);

            IPSEC_POLICY_DEBUG(
                    LOW,
                    ipsec_policy,
                    "Deleted.");
        }

        if (ipsec_policy->bypass_entry == true)
        {
            --ipsec_control->bypass_entry_count;

            ssh_log_event(
                    SSH_LOGFACILITY_DAEMON,
                    SSH_LOG_INFORMATIONAL,
                    "Removing BYPASS entry: Entry id %d.",
                    ipsec_policy->policy_id);
        }

        /* Free IPsec Policy. */
        ipsec_control_policy_free(ipsec_policy);
    }
    else
    {
        IPSEC_CONTROL_DEBUG(
                FAIL,
                ipsec_control,
                "Delete failed: policy not found with id %d.",
                ipsec_policy_id);
    }

    if (sibling_policy_id != -1)
    {
        ipsec_policy_remove_entry(
                ipsec_control,
                sibling_policy_id);
    }
}


static void
ipsec_policy_remove_timeout_callback(
        void *param)
{
    struct IPsecPolicy *ipsec_policy = param;

    /* if sibling has its own remove timeout registered, let the
       timeout remote it */
    if (ipsec_policy->sibling_policy_id != -1)
    {
        struct IPsecPolicy *sibling_policy;

        sibling_policy =
            ipsec_control_db_policy_lookup(
                    ipsec_policy->ipsec_control,
                    ipsec_policy->sibling_policy_id);

        if (sibling_policy != NULL &&
            SSH_TIMEOUT_IS_REGISTERED(
                    &sibling_policy->remove_timeout)
            == true)
        {
            ipsec_policy->sibling_policy_id = -1;
        }
    }

    ipsec_policy_remove_entry(
            ipsec_policy->ipsec_control,
            ipsec_policy->policy_id);
}

void
ipsec_policy_remove_entry_with_delay(
        struct IPsecControl *ipsec_control,
        int ipsec_policy_id,
        int delay_seconds)
{
    struct IPsecPolicy *ipsec_policy;
    int sibling_policy_id = -1;

    /* Find IPsec Policy from database. */
    ipsec_policy =
        ipsec_control_db_policy_lookup(
                ipsec_control,
                ipsec_policy_id);

    if (ipsec_policy != NULL)
    {
        sibling_policy_id = ipsec_policy->sibling_policy_id;

        ssh_register_timeout(
                &ipsec_policy->remove_timeout,
                delay_seconds,
                /* microseconds */ 0,
                ipsec_policy_remove_timeout_callback,
                ipsec_policy);
    }

    if (sibling_policy_id != -1)
    {
        ipsec_policy_remove_entry_with_delay(
                ipsec_control,
                sibling_policy_id,
                delay_seconds + 10);
    }
}

void
ipsec_policy_flush(
        struct IPsecControl *ipsec_control)
{
    struct IPsecPolicy *ipsec_policy;

    ipsec_policy = ipsec_control_db_policy_first(ipsec_control);

    while (ipsec_policy != NULL)
    {
        /* Only dynamic entries are allowed to exists when flush is called */
        ASSERT(ipsec_policy->bypass_entry == true);

        ipsec_policy_remove_entry(ipsec_control, ipsec_policy->policy_id);
        ipsec_policy = ipsec_control_db_policy_first(ipsec_control);
    }
}
