/**
   @copyright
   Copyright (c) 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   Data Plane Policy - Policy handling API for Linux data plane.
*/

#define SSH_ALLOW_SYSTEM_SPRINTFS

#include "data_plane_internal.h"
#include "netlink_xfrm.h"

#include "sshadt.h"
#include "sshadt_bag.h"


#define SSH_DEBUG_MODULE "DataPlaneLinux"
#define __DEBUG_MODULE__ DataPlaneLinux

struct PolicyEntry
{
    SshADTBagHeaderStruct adt_header_policy_id;

    int action;
    bool has_template;
    struct PolicyParams params;
    struct PolicyTmplParams template;

    struct PolicyEntry *next;
};

struct DPPolicyDB
{
    DataPlane data_plane;

    SshADTContainer dp_policies;
};

static bool
data_plane_policy_db_entry_equal(
        const struct PolicyEntry *first_entry,
        const struct PolicyEntry *second_entry);

static bool
data_plane_policy_entry_netlink_install(
        DataPlane data_plane,
        const struct PolicyEntry *policy_entry,
        bool update)
{
    struct NetlinkXfrm *netlink_xfrm = data_plane->netlink_xfrm;
    struct NetlinkRequest *request = NULL;
    const struct PolicyParams *params = &policy_entry->params;
    const struct PolicyTmplParams *tmpl_params = &policy_entry->template;
    bool ok = true;

    DEBUG_DUMP(
            dataplane,
            debug_dump_data_plane_policy_entry,
            policy_entry,
            sizeof *policy_entry,
            "Netlink xfrm policy entry %p %s:",
            policy_entry,
            update == true ? "update" : "install");

    if (ok == true)
    {
        request = netlink_xfrm_request_alloc(netlink_xfrm);
        if (request == NULL)
        {
            ok = false;
        }
    }

    if (ok == true)
    {
        netlink_xfrm_newpolicy_init(
                request,
                update,
                params->direction,
                policy_entry->action,
                params->priority);

        netlink_xfrm_encode_selector(
                request,
                &params->src_sel.address,
                params->src_sel.address_mask,
                params->src_sel.port,
                params->src_sel.port_mask,
                &params->dst_sel.address,
                params->dst_sel.address_mask,
                params->dst_sel.port,
                params->dst_sel.port_mask,
                params->protocol);

        if (policy_entry->has_template == true)
        {
            netlink_xfrm_newpolicy_encode_tmpl(
                    request,
                    &tmpl_params->src_address,
                    &tmpl_params->dst_address,
                    tmpl_params->protocol,
                    tmpl_params->tunnel_mode,
                    tmpl_params->req_id);
        }

        ok = netlink_xfrm_request_send(&request);
    }

    return ok;
}

static bool
data_plane_policy_entry_netlink_new(
        DataPlane data_plane,
        const struct PolicyEntry *policy_entry)
{
    return
        data_plane_policy_entry_netlink_install(
                data_plane,
                policy_entry,
                /* update: */ false);
}

static bool
data_plane_policy_entry_netlink_update(
        DataPlane data_plane,
        const struct PolicyEntry *old_entry,
        const struct PolicyEntry *new_entry)
{
    bool ok = true;

    /* Update the entry to new values only if entries differ. */
    if (data_plane_policy_db_entry_equal(old_entry, new_entry)
        == false)
    {
        ok =
            data_plane_policy_entry_netlink_install(
                    data_plane,
                    new_entry,
                    /* update: */ true);
    }

    return ok;
}

static bool
data_plane_policy_entry_netlink_delete(
        DataPlane data_plane,
        const struct PolicyEntry *policy_entry)
{
    struct NetlinkXfrm *netlink_xfrm = data_plane->netlink_xfrm;
    struct NetlinkRequest *request = NULL;
    const struct PolicyParams *params = &policy_entry->params;
    bool ok = true;

    DEBUG_DUMP(
            dataplane,
            debug_dump_data_plane_policy_entry,
            policy_entry,
            sizeof *policy_entry,
            "Netlink xfrm policy entry %p deleted:",
            policy_entry);

    if (ok == true)
    {
        request = netlink_xfrm_request_alloc(netlink_xfrm);
        if (request == NULL)
        {
            ok = false;
        }
    }

    if (ok == true)
    {
        netlink_xfrm_delpolicy_init(
                request,
                params->direction);

        netlink_xfrm_encode_selector(
                request,
                &params->src_sel.address,
                params->src_sel.address_mask,
                params->src_sel.port,
                params->src_sel.port_mask,
                &params->dst_sel.address,
                params->dst_sel.address_mask,
                params->dst_sel.port,
                params->dst_sel.port_mask,
                params->protocol);

        ok = netlink_xfrm_request_send(&request);
    }

    return ok;
}

static int
data_plane_policy_db_compare_entries(
        const struct PolicyEntry *first_policy,
        const struct PolicyEntry *second_policy)
{
    const struct PolicyParams *first_params = &first_policy->params;
    const struct PolicyParams *second_params = &second_policy->params;
    int difference = 0;

    if (difference == 0)
    {
        if (first_params->direction < second_params->direction)
        {
            difference = -1;
        }
    }

    if (difference == 0)
    {
        if (first_params->direction > second_params->direction)
        {
            difference = 1;
        }
    }

    if (difference == 0)
    {
        if (first_params->protocol < second_params->protocol)
        {
            difference = -1;
        }
    }

    if (difference == 0)
    {
        if (first_params->protocol > second_params->protocol)
        {
            difference = 1;
        }
    }

    if (difference == 0)
    {
        difference =
            memcmp(
                    &first_params->src_sel,
                    &second_params->src_sel,
                    sizeof first_params->src_sel);
    }

    if (difference == 0)
    {
        difference =
            memcmp(
                    &first_params->dst_sel,
                    &second_params->dst_sel,
                    sizeof first_params->dst_sel);
    }

    return difference;
}

static int
data_plane_policy_db_compare(
        void *first,
        void *second,
        void *context)
{
    return data_plane_policy_db_compare_entries(first, second);
}

static uint32_t
data_plane_policy_db_hash_bytes(
        uint32_t hash,
        const void *byte_p,
        int byte_count)
{
    const uint8_t *bytes = byte_p;
    int i;

    for (i = 0; i < byte_count; i++)
    {
        int c = bytes[i] * i;

        hash = c + (hash << 6) + (hash << 16) - hash;
    }

    return hash;

}


static uint32_t
data_plane_policy_db_hash(
        void *item,
        void *context)
{
    const struct PolicyEntry *policy = item;
    uint32_t hash = 0;

    hash =
        data_plane_policy_db_hash_bytes(
                hash,
                &policy->params.src_sel,
                sizeof policy->params.src_sel);

    hash =
        data_plane_policy_db_hash_bytes(
                hash,
                &policy->params.dst_sel,
                sizeof policy->params.dst_sel);

    hash =
        data_plane_policy_db_hash_bytes(
                hash,
                &policy->params.direction,
                sizeof policy->params.direction);

    hash =
        data_plane_policy_db_hash_bytes(
                hash,
                &policy->params.protocol,
                sizeof policy->params.protocol);

    return hash;
}

static void
data_plane_policy_db_free(
        struct DPPolicyDB **policy_db_p)
{
    struct DPPolicyDB *policy_db = *policy_db_p;

    if (policy_db != NULL)
    {
        if (policy_db->dp_policies != NULL)
        {
            SSH_ASSERT(
                    ssh_adt_num_objects(
                            policy_db->dp_policies) == 0);

            ssh_adt_destroy(policy_db->dp_policies);

            policy_db->dp_policies = NULL;
        }

        ssh_free(policy_db);
    }

    *policy_db_p = NULL;
}

void
data_plane_policy_db_uninit(
        DataPlane data_plane)
{
    data_plane_policy_db_free(&data_plane->policy_db);
}

bool
data_plane_policy_db_init(
        DataPlane data_plane)
{
    struct DPPolicyDB *policy_db = NULL;

    policy_db = ssh_calloc(1, sizeof(struct DPPolicyDB));
    if (policy_db == NULL)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Out of memory!"));
        goto error;
    }

    policy_db->dp_policies =
        ssh_adt_create_generic(
                SSH_ADT_BAG,
                SSH_ADT_HEADER,
                SSH_ADT_OFFSET_OF(
                        struct PolicyEntry,
                        adt_header_policy_id),
                SSH_ADT_HASH,      data_plane_policy_db_hash,
                SSH_ADT_COMPARE,   data_plane_policy_db_compare,
                SSH_ADT_CONTEXT,   data_plane->policy_db,
                SSH_ADT_ARGS_END);

    if (policy_db->dp_policies == NULL)
    {
        SSH_DEBUG(
                SSH_D_FAIL,
                ("Initializing ADT bag for Data Plane Policies failed."));
        goto error;
    }

    policy_db->data_plane = data_plane;
    data_plane->policy_db = policy_db;

    return true;

error:
    data_plane_policy_db_free(&policy_db);

    return false;
}

static SshADTHandle
data_plane_policy_db_lookup_handle(
        DataPlane data_plane,
        const struct PolicyParams *policy_params)
{
    struct DPPolicyDB *policy_db = data_plane->policy_db;
    struct PolicyEntry policy_entry;

    policy_entry.params = *policy_params;
    SshADTHandle adt_handle;

    adt_handle =
        ssh_adt_get_handle_to_equal(
                policy_db->dp_policies,
                &policy_entry);

    return adt_handle;
}


static struct PolicyEntry *
data_plane_policy_db_lookup(
        DataPlane data_plane,
        const struct PolicyParams *policy_params)
{
    struct DPPolicyDB *policy_db = data_plane->policy_db;
    struct PolicyEntry *matching_entry = NULL;
    SshADTHandle adt_handle;

    adt_handle =
        data_plane_policy_db_lookup_handle(
                data_plane,
                policy_params);

    if (adt_handle != NULL)
    {
        matching_entry = ssh_adt_get(policy_db->dp_policies, adt_handle);
    }

    return matching_entry;
}


static void
data_plane_policy_db_remove(
        DataPlane data_plane,
        struct PolicyEntry *policy_entry)
{
    struct DPPolicyDB *policy_db = data_plane->policy_db;
    SshADTHandle adt_handle;

    adt_handle =
        data_plane_policy_db_lookup_handle(
                data_plane,
                &policy_entry->params);

    ASSERT(adt_handle != NULL);

    ASSERT(policy_entry == ssh_adt_get(policy_db->dp_policies, adt_handle));

    ssh_adt_detach(policy_db->dp_policies, adt_handle);
}


static void
data_plane_policy_db_insert(
        DataPlane data_plane,
        struct PolicyEntry *policy_entry)
{
    struct DPPolicyDB *policy_db = data_plane->policy_db;

    ASSERT(data_plane_policy_db_lookup_handle(
                data_plane,
                &policy_entry->params)
           == NULL);

    ssh_adt_insert(policy_db->dp_policies, policy_entry);
}

static bool
data_plane_policy_db_entry_equal(
        const struct PolicyEntry *first_entry,
        const struct PolicyEntry *second_entry)
{
    int comparison = 0;
    bool equal = true;

    if (comparison == 0)
    {
        comparison =
            (int) first_entry->action -
            (int) second_entry->action;
    }

    if (comparison == 0)
    {
        comparison =
            (int) first_entry->has_template -
            (int) second_entry->has_template;
    }

    if (comparison == 0)
    {
        comparison =
            memcmp(
                    &first_entry->template,
                    &second_entry->template,
                    sizeof second_entry->template);
    }

    if (comparison == 0)
    {
        comparison =
            data_plane_policy_db_compare_entries(
                    first_entry,
                    second_entry);
    }

    if (comparison != 0)
    {
        equal = false;
    }

    return equal;
}


static bool
data_plane_policy_db_install_entry(
        DataPlane data_plane,
        struct PolicyEntry *policy_entry)
{
    bool ok = true;
    struct PolicyEntry *older_entry;

    DEBUG_DUMP(
            dataplane,
            debug_dump_data_plane_policy_entry,
            policy_entry,
            sizeof *policy_entry,
            "Installing data plane policy entry %p:",
            policy_entry);

    older_entry =
        data_plane_policy_db_lookup(
                data_plane,
                &policy_entry->params);

    if (older_entry != NULL)
    {
        if (older_entry->params.priority > policy_entry->params.priority)
        {
            data_plane_policy_db_remove(data_plane, older_entry);
            policy_entry->next = older_entry;
            data_plane_policy_db_insert(data_plane, policy_entry);

            ok =
                data_plane_policy_entry_netlink_update(
                        data_plane,
                        older_entry,
                        policy_entry);
        }
        else
        {
            struct PolicyEntry *insert_after;

            insert_after = older_entry;

            while (insert_after->next != NULL &&
                   insert_after->next->params.priority <=
                   policy_entry->params.priority)
            {
                insert_after = insert_after->next;
            }

            policy_entry->next = insert_after->next;
            insert_after->next = policy_entry;
        }
    }
    else
    {
        data_plane_policy_db_insert(data_plane, policy_entry);

        ok =
            data_plane_policy_entry_netlink_new(
                    data_plane,
                    policy_entry);
    }

    return ok;
}

static bool
data_plane_install_policy_entry(
        DataPlane data_plane,
        const struct PolicyParams *params,
        int action,
        const struct PolicyTmplParams *tmpl_params)
{
    struct PolicyEntry *policy_entry = NULL;
    bool ok = true;

    policy_entry = ssh_calloc(1, sizeof(struct PolicyEntry));
    if (policy_entry == NULL)
    {
        SSH_DEBUG(
                SSH_D_FAIL,
                ("Allocating PolicyEntry failed."));

        ok = false;
    }

    if (ok == true)
    {
        policy_entry->params = *params;
        policy_entry->action = action;

        if (tmpl_params != NULL)
        {
            policy_entry->template = *tmpl_params;
            policy_entry->has_template = true;
        }

        ok = data_plane_policy_db_install_entry(data_plane, policy_entry);
    }

    if (ok == false)
    {
        if (policy_entry != NULL)
        {
            ssh_free(policy_entry);
        }
    }

    return ok;
}

static bool
data_plane_update_policy_entry(
        DataPlane data_plane,
        const struct PolicyParams *params,
        int action,
        const struct PolicyTmplParams *tmpl_params)
{
    bool ok = true;
    struct PolicyEntry *first_entry;
    struct PolicyEntry *policy_entry;

    first_entry =
        data_plane_policy_db_lookup(
                data_plane,
                params);

    if (first_entry == NULL)
    {
        ok = false;
    }

    if (ok == true)
    {
        policy_entry = first_entry;

        while (policy_entry != NULL &&
               policy_entry->params.policy_id != params->policy_id)
        {
            policy_entry = policy_entry->next;
        }

        if (policy_entry == NULL)
        {
            ok = false;
        }
    }

    if (ok == true)
    {
        policy_entry->params = *params;
        policy_entry->action = action;

        if (tmpl_params != NULL)
        {
            policy_entry->template = *tmpl_params;
            policy_entry->has_template = true;
        }
        else
        {
            policy_entry->has_template = false;
        }

        DEBUG_DUMP(
                dataplane,
                debug_dump_data_plane_policy_entry,
                policy_entry,
                sizeof *policy_entry,
                "Updated data plane policy entry %p:",
                policy_entry);

        if (policy_entry == first_entry)
        {
            ok =
                data_plane_policy_entry_netlink_install(
                        data_plane,
                        policy_entry,
                        true);
        }
    }

    return ok;
}

bool
data_plane_install_policy(
        DataPlane data_plane,
        bool update,
        const struct PolicyParams *params,
        int action)
{
    bool ok;

    if (update == true)
    {
        ok =
            data_plane_update_policy_entry(
                    data_plane,
                    params,
                    action,
                    NULL);
    }
    else
    {
        ok =
            data_plane_install_policy_entry(
                    data_plane,
                    params,
                    action,
                    NULL);
    }

    return ok;
}

bool
data_plane_install_policy_with_tmpl(
        DataPlane data_plane,
        bool update,
        const struct PolicyParams *params,
        const struct PolicyTmplParams *tmpl_params)
{
    bool ok;

    if (update == true)
    {
        ok =
            data_plane_update_policy_entry(
                    data_plane,
                    params,
                    NETLINK_XFRM_POLICY_ALLOW,
                    tmpl_params);
    }
    else
    {
        ok =
            data_plane_install_policy_entry(
                    data_plane,
                    params,
                    NETLINK_XFRM_POLICY_ALLOW,
                    tmpl_params);
    }

    return ok;
}


bool
data_plane_delete_policy(
        DataPlane data_plane,
        const struct PolicyParams *params)
{
    bool ok = true;
    struct PolicyEntry *first_entry;
    struct PolicyEntry *policy_entry;
    struct PolicyEntry *previous_entry = NULL;

    first_entry =
        data_plane_policy_db_lookup(
                data_plane,
                params);

    if (first_entry == NULL)
    {
        ok = false;
    }

    if (ok == true)
    {
        policy_entry = first_entry;

        while (policy_entry != NULL &&
               policy_entry->params.policy_id != params->policy_id)
        {
            previous_entry = policy_entry;
            policy_entry = policy_entry->next;
        }

        if (policy_entry == NULL)
        {
            ok = false;
        }
    }

    if (ok == true)
    {
        if (previous_entry != NULL)
        {
            previous_entry->next = policy_entry->next;
        }
        else
        {
            ASSERT(first_entry == policy_entry);

            data_plane_policy_db_remove(data_plane, policy_entry);

            if (policy_entry->next != NULL)
            {
                data_plane_policy_db_insert(data_plane, policy_entry->next);

                ok =
                    data_plane_policy_entry_netlink_update(
                            data_plane,
                            policy_entry,
                            policy_entry->next);

                policy_entry->next = NULL;
            }
            else
            {
                ok =
                    data_plane_policy_entry_netlink_delete(
                            data_plane,
                            policy_entry);
            }
        }

        DEBUG_DUMP(
                dataplane,
                debug_dump_data_plane_policy_entry,
                policy_entry,
                sizeof *policy_entry,
                "Deleted data plane policy entry %p:",
                policy_entry);

        ssh_free(policy_entry);
    }

    return ok;
}


void
debug_dump_data_plane_policy_entry(
        void *context,
        const void *data,
        unsigned bytecount)
{
    const struct PolicyEntry *policy_entry = data;
    const struct PolicyParams *policy_params = &policy_entry->params;
    const struct SelectorEnd *source = &policy_params->src_sel;
    const struct SelectorEnd *destination = &policy_params->dst_sel;
    const struct PolicyTmplParams *template = &policy_entry->template;

    ASSERT(bytecount == sizeof *policy_entry);

    DEBUG_DUMP_LINE(
            context,
            "%p: policy_id %u ipproto %d priority %d direction %d",
            policy_entry,
            policy_params->policy_id,
            policy_params->protocol,
            policy_params->priority,
            policy_params->direction);

    DEBUG_DUMP_LINE(
            context,
            "%p: %s/%d %d/%x -> %s/%d %d/%x%s",
            policy_entry,
            debug_strbuf_in_addr(DEBUG_STRBUF_GET(), &source->address),
            source->address_mask,
            source->port,
            source->port_mask,
            debug_strbuf_in_addr(DEBUG_STRBUF_GET(), &destination->address),
            destination->address_mask,
            destination->port,
            destination->port_mask,
            policy_entry->action != NETLINK_XFRM_POLICY_ALLOW ? " drop" : "");

    if (policy_entry->has_template == true)
    {
        DEBUG_DUMP_LINE(
                context,
                "%p: protocol %u request_id %u %s -> %s %s",
                policy_entry,
                template->protocol,
                template->req_id,
                debug_strbuf_in_addr(
                        DEBUG_STRBUF_GET(),
                        &template->src_address),
                debug_strbuf_in_addr(
                        DEBUG_STRBUF_GET(),
                        &template->dst_address),
                template->tunnel_mode == true ? "tunnel" : "transport");
    }
}
