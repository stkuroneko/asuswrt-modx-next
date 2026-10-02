/**
   @copyright
   Copyright (c) 2016, INSIDE Secure Oy. All rights reserved.
*/

#include "ipsec_keepalive.h"

#include "in_addr.h"

#include "sshtimeouts.h"

#define SSH_DEBUG_MODULE "IPsecKeepalive"
#define __DEBUG_MODULE__ IPsecKeepalive


/** IPsec UDP encapsulation NAT-T keepalive packet UDP payload,
    as specified in RFC 3948 */
#define IPSEC_UDP_ENCAP_NATT_KEEPALIVE_DATA 0xff

/**
   The default interval (in seconds) how often NAT-T keepalive
   packets are sent. Zero not allowed here.
*/
#define IPSEC_NATT_KEEPALIVE_INTERVAL_DEFAULT 20

/**
   Maximum allowed timeout for dpd and natt keepalive. One week.
*/
#define IPSEC_MAX_DPD_KEEPALIVE_TIMEOUT (60*60*24*7)


struct IPsecKeepalive
{
    SshADTContainer keepalive_adt;

    IPsecKeepaliveSendCB *ipsec_keepalive_send_cb;
    void *control_param;
};

struct IPsecKeepaliveEntry
{
    struct InAddr local_ip;
    struct InAddr remote_ip;
    uint16_t local_port;
    uint16_t remote_port;

    /** Keepalive timeout, seconds */
    SshTimeoutStruct timeout;
    int keepalive_timeout;

    /** Timestamp of last sent packet with this 5-tuple */
    MonotonicTime last_send;

    /** Reference count */
    uint32_t ref_count;

    struct IPsecKeepalive *ipsec_keepalive;
    SshADTHeaderStruct adt_hdr;
};

static int
ipsec_keepalive_adt_cmp(
        void *obj1,
        void *obj2,
        void *context)
{
    struct IPsecKeepaliveEntry *keepalive1 = obj1;
    struct IPsecKeepaliveEntry *keepalive2 = obj2;
    int ret;

    ret = in_addr_compare(&keepalive1->local_ip, &keepalive2->local_ip);
    if (ret != 0)
      return ret;

    if (keepalive1->local_port < keepalive2->local_port)
      return -1;
    else if (keepalive1->local_port > keepalive2->local_port)
      return 1;

    ret = in_addr_compare(&keepalive1->remote_ip, &keepalive2->remote_ip);
    if (ret != 0)
      return ret;

    if (keepalive1->remote_port < keepalive2->remote_port)
      return -1;
    else if (keepalive1->remote_port > keepalive2->remote_port)
      return 1;

    return 0;
}

static uint32_t
ipsec_keepalive_in_addr_hash(struct InAddr *ip)
{
    uint32_t value;
    size_t len;
    unsigned int i;

    SSH_ASSERT(ip != NULL);

    InAddrVersion version = in_addr_version(ip);
    len = version == IN_ADDR_FOUR ? 4 : 16;

    for (i = 0, value = len; i < len; i++)
      value = 257 * value + ip->addr[i] + 3 * (value >> 23);

    return value;
}

static uint32_t
ipsec_keepalive_adt_hash(
        void *obj,
        void *context)
{
    struct IPsecKeepaliveEntry *keepalive = obj;

    return
        ipsec_keepalive_in_addr_hash(&keepalive->local_ip) ^
        ipsec_keepalive_in_addr_hash(&keepalive->remote_ip) ^
        ((keepalive->local_port << 16 | keepalive->remote_port));
}

static struct IPsecKeepaliveEntry*
ipsec_adt_keepalive_lookup(
        SshADTContainer keepalive_adt,
        const struct InAddr *local_ip,
        uint16_t local_port,
        const struct InAddr *remote_ip,
        uint16_t remote_port)
{
    struct IPsecKeepaliveEntry *keepalive = NULL;
    struct IPsecKeepaliveEntry probe;
    SshADTHandle handle;

    /** Lookup matching keepalive entry */
    memset(&probe, 0, sizeof(probe));
    probe.local_ip = *local_ip;
    probe.local_port = local_port;
    probe.remote_ip = *remote_ip;
    probe.remote_port = remote_port;

    handle = ssh_adt_get_handle_to_equal(keepalive_adt, &probe);
    if (handle != SSH_ADT_INVALID)
    {
        keepalive = ssh_adt_get(keepalive_adt, handle);
        SSH_ASSERT(keepalive != NULL);
    }

    return keepalive;
}


void
ipsec_keepalive_update(
        struct IPsecKeepalive *ipsec_keepalive,
        const struct InAddr *local_addr,
        uint16_t local_port,
        const struct InAddr *remote_addr,
        uint16_t remote_port)
{
    struct IPsecKeepaliveEntry *keepalive;

    SSH_ASSERT(ipsec_keepalive != NULL);

    /** Update last_send timestamp for matching keepalive entries */
    keepalive =
        ipsec_adt_keepalive_lookup(
                ipsec_keepalive->keepalive_adt,
                local_addr,
                local_port,
                remote_addr,
                remote_port);
    if (keepalive != NULL)
    {
        keepalive->last_send = monotonic_time_get();
    }
}


static void
ipsec_keepalive_check(
        struct IPsecKeepaliveEntry *keepalive,
        MonotonicTime now)
{
    keepalive->ipsec_keepalive->ipsec_keepalive_send_cb(
            keepalive->ipsec_keepalive->control_param,
            &keepalive->local_ip,
            keepalive->local_port,
            &keepalive->remote_ip,
            keepalive->remote_port);
    keepalive->last_send = now;
}


void
ipsec_keepalive_requested(
        struct IPsecKeepalive *ipsec_keepalive,
        const struct InAddr *local_addr,
        uint16_t local_port,
        const struct InAddr *remote_addr,
        uint16_t remote_port)
{
    struct IPsecKeepaliveEntry *keepalive;
    MonotonicTime now;

    SSH_DEBUG(
            SSH_D_MIDOK,
            ("UDP NAT-T keepalive requested"));

    now = monotonic_time_get();

    keepalive =
        ipsec_adt_keepalive_lookup(
                ipsec_keepalive->keepalive_adt,
                local_addr,
                local_port,
                remote_addr,
                remote_port);

    if (keepalive != NULL)
    {
        ipsec_keepalive_check(keepalive, now);
    }
    else
    {
        ipsec_keepalive->ipsec_keepalive_send_cb(
                ipsec_keepalive->control_param,
                local_addr,
                local_port,
                remote_addr,
                remote_port);
    }
}

static void
ipsec_keepalive_timeout(
        void *context)
{
    struct IPsecKeepaliveEntry *keepalive = context;
    MonotonicTime now;
    long timeout;

    SSH_DEBUG(
            SSH_D_MIDOK,
            ("UDP NAT-T keepalive timeout local %@:%d remote %@:%d",
             ssh_in_addr_render, &keepalive->local_ip,
             keepalive->local_port,
             ssh_in_addr_render, &keepalive->remote_ip,
             keepalive->remote_port));

    now = monotonic_time_get();
    if (now >= keepalive->last_send + keepalive->keepalive_timeout)
        ipsec_keepalive_check(keepalive, now);

    timeout = keepalive->last_send + keepalive->keepalive_timeout - now;

    SSH_DEBUG(
            SSH_D_MIDOK,
            ("Registering UDP NAT-T keepalive timeout to %ds "
             "local %@:%d remote %@:%d",
             timeout,
             ssh_in_addr_render, &keepalive->local_ip,
             keepalive->local_port,
             ssh_in_addr_render, &keepalive->remote_ip,
             keepalive->remote_port));

    ssh_register_timeout(
            &keepalive->timeout,
            timeout,
            0,
            ipsec_keepalive_timeout,
            keepalive);
}

void
ipsec_keepalive_start(
        struct IPsecKeepalive *ipsec_keepalive,
        const struct InAddr *local_addr,
        uint16_t local_port,
        const struct InAddr *remote_addr,
        uint16_t remote_port,
        int keepalive_timeout)
{
    struct IPsecKeepaliveEntry *keepalive;

    SSH_ASSERT(ipsec_keepalive != NULL);

    /* Check the timout value */
    if (keepalive_timeout > IPSEC_MAX_DPD_KEEPALIVE_TIMEOUT)
    {
        SSH_DEBUG(SSH_D_HIGHOK,
                ("NAT-T keepalive timeout too long %ds, using %ds",
                 keepalive_timeout,
                 IPSEC_MAX_DPD_KEEPALIVE_TIMEOUT));
        keepalive_timeout = IPSEC_MAX_DPD_KEEPALIVE_TIMEOUT;
    }
    else if (keepalive_timeout <= 0)
    {
        keepalive_timeout = IPSEC_NATT_KEEPALIVE_INTERVAL_DEFAULT;
    }

    SSH_DEBUG(
            SSH_D_HIGHOK,
            ("Enabling UDP NAT-T keepalive for local %@:%d remote %@:%d "
             "timeout %ds",
             ssh_in_addr_render, local_addr,
             local_port,
             ssh_in_addr_render, remote_addr,
             remote_port,
             keepalive_timeout));

    /** Lookup matching keepalive entry */
    keepalive =
        ipsec_adt_keepalive_lookup(
                ipsec_keepalive->keepalive_adt,
                local_addr,
                local_port,
                remote_addr,
                remote_port);
    if (keepalive != NULL)
    {
        if (keepalive_timeout < keepalive->keepalive_timeout)
        {
            keepalive->keepalive_timeout = keepalive_timeout;
        }

        keepalive->ref_count++;
        return;
    }

    /** Allocate a new keepalive entry */
    keepalive = ssh_calloc(1, sizeof(*keepalive));
    if (keepalive == NULL)
    {
        SSH_DEBUG(
                SSH_D_FAIL,
                ("Failed to allocate memory for UDP NAT-T keepalive entry"));
        return;
    }

    keepalive->local_ip = *local_addr;
    keepalive->local_port = local_port;
    keepalive->remote_ip = *remote_addr;
    keepalive->remote_port = remote_port;
    keepalive->keepalive_timeout = keepalive_timeout;
    keepalive->last_send = monotonic_time_get();
    keepalive->ref_count = 1;
    keepalive->ipsec_keepalive = ipsec_keepalive;

    SSH_VERIFY(ssh_adt_insert(ipsec_keepalive->keepalive_adt, keepalive)
               != SSH_ADT_INVALID);

    /** Trigger keepalive timeout to register next real timeout */
    ipsec_keepalive_timeout(keepalive);
}

void
ipsec_keepalive_stop(
        struct IPsecKeepalive *ipsec_keepalive,
        const struct InAddr *local_addr,
        uint16_t local_port,
        const struct InAddr *remote_addr,
        uint16_t remote_port)
{
    struct IPsecKeepaliveEntry *keepalive;

    SSH_ASSERT(ipsec_keepalive != NULL);

    SSH_DEBUG(
            SSH_D_HIGHOK,
            ("Disabling UDP NAT-T keepalive for local %@:%d remote %@:%d",
             ssh_in_addr_render, local_addr,
             local_port,
             ssh_in_addr_render, remote_addr,
             remote_port));

    /** Lookup matching keepalive entry */
    keepalive =
        ipsec_adt_keepalive_lookup(
                ipsec_keepalive->keepalive_adt,
                local_addr,
                local_port,
                remote_addr,
                remote_port);
    if (keepalive == NULL)
    {
        SSH_DEBUG(
                SSH_D_FAIL,
                ("No keepalive entry found for local %@:%d remote %@:%d",
                 ssh_in_addr_render, local_addr,
                 local_port,
                 ssh_in_addr_render, remote_addr,
                 remote_port));
    }
    else
    {
        SSH_ASSERT(keepalive->ref_count > 0);
        keepalive->ref_count--;
        if (keepalive->ref_count == 0)
        {
            /** Cancel keepalive timeout */
            ssh_cancel_timeout(&keepalive->timeout);

            /** Remove from keepalive adt and free */
            SSH_VERIFY(ssh_adt_detach_object(
                               ipsec_keepalive->keepalive_adt,
                               keepalive) == keepalive);
            ssh_free(keepalive);
        }
    }
}

bool
ipsec_keepalive_init(
        struct IPsecKeepalive **ipsec_keepalive_p,
        IPsecKeepaliveSendCB *send_cb,
        void *control_param)
{
    struct IPsecKeepalive *ipsec_keepalive = NULL;
    bool ok = true;

    SSH_ASSERT(send_cb != NULL);
    SSH_ASSERT(control_param != NULL);

    *ipsec_keepalive_p = NULL;

    if (ok == true)
    {
        ipsec_keepalive = ssh_calloc(1, sizeof(*ipsec_keepalive));
        if (ipsec_keepalive == NULL)
        {
            SSH_DEBUG(SSH_D_FAIL, ("Failed to allocate IPsec UDP handler"));
            ok = false;
        }
    }

    if (ok == true)
    {
        ipsec_keepalive->ipsec_keepalive_send_cb = send_cb;
        ipsec_keepalive->control_param = control_param;

        ipsec_keepalive->keepalive_adt = ssh_adt_create_generic(
                    SSH_ADT_BAG,
                    SSH_ADT_HEADER,
                    SSH_ADT_OFFSET_OF(struct IPsecKeepaliveEntry, adt_hdr),
                    SSH_ADT_HASH, ipsec_keepalive_adt_hash,
                    SSH_ADT_COMPARE, ipsec_keepalive_adt_cmp,
                    SSH_ADT_ARGS_END);
        if (ipsec_keepalive->keepalive_adt == NULL)
        {
            ok = false;
        }
    }

    if (ok == false)
    {
        ipsec_keepalive_uninit(&ipsec_keepalive);
        return false;
    }

    *ipsec_keepalive_p = ipsec_keepalive;

    return true;
}


void
ipsec_keepalive_uninit(
        struct IPsecKeepalive **ipsec_keepalive_p)
{
    if (*ipsec_keepalive_p != NULL)
    {
        struct IPsecKeepalive *ipsec_keepalive = *ipsec_keepalive_p;

        if (ipsec_keepalive->keepalive_adt != NULL)
        {
            /** Assert that all keepalive entries have been destroyed */
            SSH_ASSERT(
                    ssh_adt_num_objects(ipsec_keepalive->keepalive_adt) == 0);
            ssh_adt_destroy(ipsec_keepalive->keepalive_adt);
        }

        ssh_free(ipsec_keepalive);
        *ipsec_keepalive_p = NULL;
    }
}
