/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   IPsec Control DB module.
*/
#include "sshincludes.h"
#include "sshinet.h"
#include "sshadt_list.h"
#include "sshadt.h"
#include "sshadt_bag.h"
#include "sshadt_avltree.h"

#include "ipsec_sa.h"
#include "ipsec_control.h"
#include "ipsec_control_internal.h"

#define SSH_DEBUG_MODULE "IPsecControlDb"
#define __DEBUG_MODULE__ IPsecControlDb

#define IPSEC_CONTROL_PEER_MAX 250

struct IPsecDbSa
{
    /** ADT header for IPsec SA. */
    SshADTBagHeaderStruct adt_header_inbound;

    /** ADT header for IPsec SA by outbound SPI. */
    SshADTBagHeaderStruct adt_header_outbound;

    /** ADT header for IPsec SA by chain id. */
    SshADTBagHeaderStruct adt_header_chain_id;

    uint32_t inbound_spi;
    uint32_t chain_id;

    struct IPsecSa *ipsec_sa;
    struct IPsecDbSa *next;
};

struct IPsecSaDbControl
{
    struct IPsecControl *ipsec_control;

    /** ADT bags for active SAs. */
    SshADTContainer ipsec_sas;
    SshADTContainer ipsec_sas_by_outbound_spi;
    SshADTContainer ipsec_sas_by_chain_id;

    SshADTContainer ipsec_peer_by_handle;
};

struct IPsecDbPolicy
{
    SshADTHeaderStruct adt_header_policy_id;

    uint32_t id;

    struct IPsecPolicy *ipsec_policy;
    struct IPsecDbPolicy *next;
};

struct IPsecPolicyDbControl
{
    struct IPsecControl *ipsec_control;

    SshADTContainer ipsec_policies;
};

struct IPsecDbPeer
{
    SshADTBagHeaderStruct adt_header_peer_handle;
    SshADTBagHeaderStruct adt_header_peer_addr;

    struct InAddr peer_addr;

    uint32_t peer_handle;

    /* List of IPsec SAs for this peer */
    struct IPsecDbSa *ipsec_db_sa;
};

/* Hash function for SPI values. */
static uint32_t
ipsec_control_db_hash(uint32_t id)
{
    return (id + 3 * (id >> 8) + 7 * (id >> 16) + 11 * (id >> 24));
}

/* Return relative order of two ints. */
static int
ipsec_control_db_compare_int(
        uint32_t a,
        uint32_t b)
{
    if (a > b)
        return 1;
    if (a < b)
        return -1;
    return 0;
}


static uint32_t
ipsec_control_db_sa_hash(
        void *ptr,
        void *ctx)
{
    struct IPsecDbSa *ipsec_db_sa = (struct IPsecDbSa *)ptr;

    return ipsec_control_db_hash(ipsec_db_sa->inbound_spi);
}

static uint32_t
ipsec_control_db_sa_hash_chain_id(
        void *ptr,
        void *ctx)
{
    struct IPsecDbSa *ipsec_db_sa = ptr;

    return ipsec_control_db_hash(ipsec_db_sa->chain_id);
}

static uint32_t
ipsec_control_db_sa_outbound_hash(
        void *ptr,
        void *ctx)
{
    struct IPsecSa *ipsec_sa = ((struct IPsecDbSa *)ptr)->ipsec_sa;

    return ipsec_control_db_hash(ipsec_sa->params.outbound_spi);
}

static int
ipsec_control_db_sa_compare(
        void *ptr1,
        void *ptr2,
        void *ctx)
{
    struct IPsecDbSa *ipsec_db_sa1 = (struct IPsecDbSa *)ptr1;
    struct IPsecDbSa *ipsec_db_sa2 = (struct IPsecDbSa *)ptr2;

    return
        ipsec_control_db_compare_int(
                ipsec_db_sa1->inbound_spi,
                ipsec_db_sa2->inbound_spi);
}

static int
ipsec_control_db_policy_compare(
        void *ptr1,
        void *ptr2,
        void *ctx)
{
    struct IPsecDbPolicy *ipsec_db_policy1 = (struct IPsecDbPolicy *)ptr1;
    struct IPsecDbPolicy *ipsec_db_policy2 = (struct IPsecDbPolicy *)ptr2;

    return
        ipsec_control_db_compare_int(
                ipsec_db_policy1->id,
                ipsec_db_policy2->id);
}

static int
ipsec_control_db_sa_compare_chain_id(
        void *ptr1,
        void *ptr2,
        void *ctx)
{
    struct IPsecDbSa *ipsec_db_sa1 = ptr1;
    struct IPsecDbSa *ipsec_db_sa2 = ptr2;

    return
        ipsec_control_db_compare_int(
                ipsec_db_sa1->chain_id,
                ipsec_db_sa2->chain_id);
}

static int
ipsec_control_db_sa_outbound_compare(
        void *ptr1,
        void *ptr2,
        void *ctx)
{
    struct IPsecSa *ipsec_sa1 = ((struct IPsecDbSa *)ptr1)->ipsec_sa;
    struct IPsecSa *ipsec_sa2 = ((struct IPsecDbSa *)ptr2)->ipsec_sa;
    int ret = 0;

    ret =
        ipsec_control_db_compare_int(
                ipsec_sa1->params.outbound_spi,
                ipsec_sa2->params.outbound_spi);
    if (ret != 0)
    {
        return ret;
    }

    ret =
        ipsec_control_db_compare_int(
                ipsec_sa1->params.ipproto,
                ipsec_sa2->params.ipproto);
    if (ret != 0)
    {
        return ret;
    }
    ret =
        in_addr_compare(
                &ipsec_sa1->endpoints.remote_address,
                &ipsec_sa2->endpoints.remote_address);
    if (ret != 0)
    {
        return ret;
    }

    if (ipsec_sa1->endpoints.remote_port > ipsec_sa2->endpoints.remote_port)
        return 1;

    if (ipsec_sa1->endpoints.remote_port < ipsec_sa2->endpoints.remote_port)
        return -1;

    return 0;
}

static uint32_t
ipsec_control_db_peer_handle_hash(
        void *ptr,
        void *ctx)
{
    struct IPsecDbPeer *ipsec_db_peer = (struct IPsecDbPeer *)ptr;

    return ipsec_control_db_hash(ipsec_db_peer->peer_handle);
}

static int
ipsec_control_db_peer_handle_compare(
        void *ptr1,
        void *ptr2,
        void *ctx)
{
    struct IPsecDbPeer *ipsec_db_peer1 = (struct IPsecDbPeer *)ptr1;
    struct IPsecDbPeer *ipsec_db_peer2 = (struct IPsecDbPeer *)ptr2;

    if (ipsec_db_peer1->peer_handle > ipsec_db_peer2->peer_handle)
        return 1;

    if (ipsec_db_peer1->peer_handle < ipsec_db_peer2->peer_handle)
        return -1;

    return 0;
}

static void
ipsec_control_sa_db_uninit(
        struct IPsecSaDbControl **ipsec_sa_db_p)
{
    if (*ipsec_sa_db_p != NULL)
    {
        struct IPsecSaDbControl *ipsec_sa_db = *ipsec_sa_db_p;

        if (ipsec_sa_db->ipsec_peer_by_handle != NULL)
        {
            SSH_ASSERT(
                    ssh_adt_num_objects(
                            ipsec_sa_db->ipsec_peer_by_handle) == 0);

            ssh_adt_destroy(ipsec_sa_db->ipsec_peer_by_handle);

            ipsec_sa_db->ipsec_peer_by_handle = NULL;
        }

        if (ipsec_sa_db->ipsec_sas_by_outbound_spi != NULL)
        {
            SSH_ASSERT(
                    ssh_adt_num_objects(
                            ipsec_sa_db->ipsec_sas_by_outbound_spi) == 0);

            ssh_adt_destroy(ipsec_sa_db->ipsec_sas_by_outbound_spi);

            ipsec_sa_db->ipsec_sas_by_outbound_spi = NULL;
        }

        if (ipsec_sa_db->ipsec_sas_by_chain_id != NULL)
        {
            SSH_ASSERT(
                    ssh_adt_num_objects(
                            ipsec_sa_db->ipsec_sas_by_chain_id) == 0);

            ssh_adt_destroy(ipsec_sa_db->ipsec_sas_by_chain_id);

            ipsec_sa_db->ipsec_sas_by_chain_id = NULL;
        }

        if (ipsec_sa_db->ipsec_sas != NULL)
        {
            SSH_ASSERT(ssh_adt_num_objects(ipsec_sa_db->ipsec_sas) == 0);

            ssh_adt_destroy(ipsec_sa_db->ipsec_sas);

            ipsec_sa_db->ipsec_sas = NULL;
        }

        ssh_free(ipsec_sa_db);
        *ipsec_sa_db_p = NULL;
    }
}

static bool
ipsec_control_sa_db_init(
        struct IPsecControl *ipsec_control)
{
    struct IPsecSaDbControl *ipsec_sa_db = NULL;

    ipsec_sa_db = ssh_calloc(1, sizeof(struct IPsecSaDbControl));
    if (ipsec_sa_db == NULL)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Out of memory!"));
        goto error;
    }

    ipsec_sa_db->ipsec_sas =
        ssh_adt_create_generic(
                SSH_ADT_BAG,
                SSH_ADT_HEADER,
                SSH_ADT_OFFSET_OF(
                        struct IPsecDbSa,
                        adt_header_inbound),
                SSH_ADT_HASH,      ipsec_control_db_sa_hash,
                SSH_ADT_COMPARE,   ipsec_control_db_sa_compare,
                SSH_ADT_CONTEXT,   ipsec_sa_db,
                SSH_ADT_ARGS_END);

    if (ipsec_sa_db->ipsec_sas == NULL)
    {
        SSH_DEBUG(
                SSH_D_FAIL,
                ("Initializing ADT bag for SAs failed."));
        goto error;
    }

    ipsec_sa_db->ipsec_sas_by_outbound_spi =
        ssh_adt_create_generic(
                SSH_ADT_BAG,
                SSH_ADT_HEADER,
                SSH_ADT_OFFSET_OF(
                        struct IPsecDbSa,
                        adt_header_outbound),
                SSH_ADT_HASH,      ipsec_control_db_sa_outbound_hash,
                SSH_ADT_COMPARE,   ipsec_control_db_sa_outbound_compare,
                SSH_ADT_CONTEXT,   ipsec_sa_db,
                SSH_ADT_ARGS_END);

    if (ipsec_sa_db->ipsec_sas_by_outbound_spi == NULL)
    {
        SSH_DEBUG(
                SSH_D_FAIL,
                ("Initializing ADT bag for SAs by outbound SPI failed."));
        goto error;
    }

    ipsec_sa_db->ipsec_sas_by_chain_id =
        ssh_adt_create_generic(
                SSH_ADT_BAG,
                SSH_ADT_HEADER,
                SSH_ADT_OFFSET_OF(
                        struct IPsecDbSa,
                        adt_header_chain_id),
                SSH_ADT_HASH,      ipsec_control_db_sa_hash_chain_id,
                SSH_ADT_COMPARE,   ipsec_control_db_sa_compare_chain_id,
                SSH_ADT_CONTEXT,   ipsec_sa_db,
                SSH_ADT_ARGS_END);

    if (ipsec_sa_db->ipsec_sas_by_chain_id == NULL)
    {
        SSH_DEBUG(
                SSH_D_FAIL,
                ("Initializing ADT bag for SAs by chain_id failed."));
        goto error;
    }

    ipsec_sa_db->ipsec_peer_by_handle =
        ssh_adt_create_generic(
                SSH_ADT_BAG,
                SSH_ADT_HEADER,
                SSH_ADT_OFFSET_OF(
                        struct IPsecDbPeer,
                        adt_header_peer_handle),
                SSH_ADT_HASH,      ipsec_control_db_peer_handle_hash,
                SSH_ADT_COMPARE,   ipsec_control_db_peer_handle_compare,
                SSH_ADT_CONTEXT,   ipsec_sa_db,
                SSH_ADT_ARGS_END);

    if (ipsec_sa_db->ipsec_peer_by_handle == NULL)
    {
        SSH_DEBUG(
                SSH_D_FAIL,
                ("Initializing ADT bag for peers by handle failed."));
        goto error;
    }

    ipsec_sa_db->ipsec_control = ipsec_control;
    ipsec_control->ipsec_sa_db = ipsec_sa_db;

    return true;

error:
    ipsec_control_sa_db_uninit(&ipsec_sa_db);
    return false;
}

static SshADTHandle
ipsec_control_db_sa_retrieve_handle(
        struct IPsecSaDbControl *ipsec_sa_db,
        uint32_t inbound_spi)
{

    SshADTHandle h = NULL;
    struct IPsecDbSa probe;
    struct IPsecSa ipsec_sa;

    memset(&probe, 0, sizeof(probe));
    memset(&ipsec_sa, 0, sizeof(ipsec_sa));
    probe.ipsec_sa = &ipsec_sa;
    probe.inbound_spi = inbound_spi;

    h = ssh_adt_get_handle_to_equal(ipsec_sa_db->ipsec_sas, &probe);

    return h;
}

static struct IPsecDbSa *
ipsec_control_db_sa_retrieve(
        struct IPsecSaDbControl *ipsec_sa_db,
        uint32_t inbound_spi)
{
    SshADTHandle h;
    struct IPsecDbSa *ipsec_db_sa = NULL;

    h =
        ipsec_control_db_sa_retrieve_handle(
                ipsec_sa_db,
                inbound_spi);

    if (h != SSH_ADT_INVALID)
    {
        ipsec_db_sa = ssh_adt_get(ipsec_sa_db->ipsec_sas, h);
    }

    return ipsec_db_sa;
}

static struct IPsecDbPeer *
ipsec_control_db_peer_retrieve(
        struct IPsecSaDbControl *ipsec_sa_db,
        uint32_t peer_handle)
{
    struct IPsecDbPeer *ipsec_db_peer = NULL;
    struct IPsecDbPeer probe;
    SshADTHandle h;


    memset(&probe, 0, sizeof(probe));
    probe.peer_handle = peer_handle;

    h =
        ssh_adt_get_handle_to_equal(
                ipsec_sa_db->ipsec_peer_by_handle,
                &probe);

    if (h != SSH_ADT_INVALID)
    {
        ipsec_db_peer =
            ssh_adt_get(
                    ipsec_sa_db->ipsec_peer_by_handle,
                    h);
    }
    return ipsec_db_peer;
}

static bool
ipsec_control_db_peer_insert(
        struct IPsecSaDbControl *ipsec_sa_db,
        struct IPsecDbSa *ipsec_db_sa)
{
    struct IPsecDbPeer *ipsec_db_peer;
    struct IPsecDbSa *curr;
    struct IPsecDbSa *prev = NULL;

    ipsec_db_peer =
        ipsec_control_db_peer_retrieve(
                ipsec_sa_db,
                ipsec_db_sa->ipsec_sa->params.peer_handle);
    if (ipsec_db_peer == NULL)
    {
        ipsec_db_peer = ssh_calloc(1, sizeof(struct IPsecDbPeer));
        if (ipsec_db_peer == NULL)
            return false;

        in_addr_copy(
                &ipsec_db_peer->peer_addr,
                &ipsec_db_sa->ipsec_sa->endpoints.remote_address,
                IN_ADDR_BIT_COUNT);

        ipsec_db_peer->peer_handle =
            ipsec_db_sa->ipsec_sa->params.peer_handle;

        ssh_adt_insert(ipsec_sa_db->ipsec_peer_by_handle, ipsec_db_peer);
    }

    curr = ipsec_db_peer->ipsec_db_sa;
    while (curr)
    {
        if (curr->inbound_spi > ipsec_db_sa->inbound_spi)
            break;
        prev = curr;
        curr = curr->next;
    }

    if (prev != NULL)
    {
        ipsec_db_sa->next = prev->next;
        prev->next = ipsec_db_sa;
    }
    else
    {
        ipsec_db_sa->next = ipsec_db_peer->ipsec_db_sa;
        ipsec_db_peer->ipsec_db_sa = ipsec_db_sa;
    }

    return true;
}

bool
ipsec_control_db_sa_insert(
        struct IPsecControl *ipsec_control,
        struct IPsecSa *ipsec_sa)
{
    struct IPsecSaDbControl *ipsec_sa_db = ipsec_control->ipsec_sa_db;
    struct IPsecDbSa *ipsec_db_sa = NULL;

    ipsec_db_sa = ssh_calloc(1, sizeof(struct IPsecDbSa));
    if (ipsec_db_sa == NULL)
        return false;

    ipsec_db_sa->ipsec_sa = ipsec_sa;
    ipsec_db_sa->inbound_spi = ipsec_sa->params.inbound_spi;

    SSH_ASSERT(ssh_adt_get_handle_to_equal(
                       ipsec_sa_db->ipsec_sas,
                       ipsec_db_sa)
               == SSH_ADT_INVALID);

    SSH_DEBUG(
            SSH_D_MY,
            ("Inserting %p to active SA bag.",
             ipsec_sa));

    ssh_adt_insert(ipsec_sa_db->ipsec_sas, ipsec_db_sa);

    return true;
}

void
ipsec_control_db_sa_insert_chain_id(
        struct IPsecControl *ipsec_control,
        struct IPsecSa *ipsec_sa)
{
    struct IPsecSaDbControl *ipsec_sa_db = ipsec_control->ipsec_sa_db;
    struct IPsecDbSa *ipsec_db_sa = NULL;

    ipsec_db_sa =
        ipsec_control_db_sa_retrieve(
                ipsec_sa_db,
                ipsec_sa->params.inbound_spi);

    SSH_ASSERT(ipsec_db_sa != NULL);

    ipsec_db_sa->chain_id = ipsec_sa->chain_id;

    SSH_ASSERT(ssh_adt_get_handle_to_equal(
                       ipsec_sa_db->ipsec_sas_by_chain_id,
                       ipsec_db_sa)
               == SSH_ADT_INVALID);

    SSH_DEBUG(
            SSH_D_MY,
            ("Inserting %p to chain_id SA bag.",
             ipsec_sa));

    ssh_adt_insert(ipsec_sa_db->ipsec_sas_by_chain_id, ipsec_db_sa);
}

void
ipsec_control_db_sa_remove_chain_id(
        struct IPsecControl *ipsec_control,
        struct IPsecSa *ipsec_sa)
{
    struct IPsecSaDbControl *ipsec_sa_db = ipsec_control->ipsec_sa_db;
    struct IPsecDbSa probe;
    SshADTHandle adt_handle;

    probe.chain_id = ipsec_sa->chain_id;

    adt_handle =
        ssh_adt_get_handle_to_equal(
                ipsec_sa_db->ipsec_sas_by_chain_id,
                &probe);

    SSH_ASSERT(adt_handle != SSH_ADT_INVALID);

    ssh_adt_detach(ipsec_sa_db->ipsec_sas_by_chain_id, adt_handle);
}

/**
   Function to return a pointer to active IPsec SA with the given
   inbound SPI.
 */
struct IPsecSa *
ipsec_control_db_sa_lookup_by_chain_id(
        struct IPsecControl *ipsec_control,
        uint32_t chain_id)
{
    struct IPsecSaDbControl *ipsec_sa_db = ipsec_control->ipsec_sa_db;
    struct IPsecDbSa *ipsec_db_sa = NULL;
    SshADTHandle adt_handle;
    struct IPsecDbSa probe;
    struct IPsecSa *ipsec_sa = NULL;

    probe.chain_id = chain_id;

    adt_handle =
        ssh_adt_get_handle_to_equal(
                ipsec_sa_db->ipsec_sas_by_chain_id,
                &probe);

    if (adt_handle != SSH_ADT_INVALID)
    {
        ipsec_db_sa =
            ssh_adt_get(
                    ipsec_sa_db->ipsec_sas_by_chain_id,
                    adt_handle);
    }

    if (ipsec_db_sa != NULL)
    {
        ipsec_sa = ipsec_db_sa->ipsec_sa;
    }

    return ipsec_sa;
}


void
ipsec_control_db_sa_insert_active(
        struct IPsecControl *ipsec_control,
        struct IPsecSa *ipsec_sa)
{
    struct IPsecSaDbControl *ipsec_sa_db = ipsec_control->ipsec_sa_db;
    struct IPsecDbSa *ipsec_db_sa = NULL;

    ipsec_db_sa =
        ipsec_control_db_sa_retrieve(
                ipsec_sa_db,
                ipsec_sa->params.inbound_spi);

    SSH_ASSERT(ssh_adt_get_handle_to_equal(
                       ipsec_sa_db->ipsec_sas_by_outbound_spi,
                       ipsec_db_sa)
               == SSH_ADT_INVALID);

    SSH_DEBUG(
            SSH_D_MY,
            ("Inserting %p to active SA bag by outbound SPI.",
              ipsec_sa));

    ssh_adt_insert(ipsec_sa_db->ipsec_sas_by_outbound_spi, ipsec_db_sa);

    ipsec_control_db_peer_insert(ipsec_sa_db, ipsec_db_sa);
}


static void
ipsec_control_db_remove_from_peer(
        struct IPsecSaDbControl *ipsec_sa_db,
        struct IPsecDbSa *ipsec_db_sa)
{
    SshADTHandle h;
    struct IPsecDbPeer *ipsec_db_peer;

    ipsec_db_peer =
        ipsec_control_db_peer_retrieve(
                ipsec_sa_db,
                ipsec_db_sa->ipsec_sa->params.peer_handle);

    SSH_ASSERT(ipsec_db_peer != NULL);

    {
        struct IPsecDbSa *prev = NULL;
        struct IPsecDbSa *curr = ipsec_db_peer->ipsec_db_sa;

        while (curr)
        {
            if (curr == ipsec_db_sa)
                break;
            prev = curr;
            curr = curr->next;
        }
        if (curr != NULL)
        {
            if (prev != NULL)
                prev->next = curr->next;
            else
                ipsec_db_peer->ipsec_db_sa = curr->next;
        }
    }

    if (ipsec_db_peer->ipsec_db_sa == NULL)
    {
        h =
            ssh_adt_get_handle_to_equal(
                    ipsec_sa_db->ipsec_peer_by_handle,
                    ipsec_db_peer);
        SSH_ASSERT(h != SSH_ADT_INVALID);
        ssh_adt_detach(ipsec_sa_db->ipsec_peer_by_handle, h);

        ssh_free(ipsec_db_peer);
    }
}

void
ipsec_control_db_sa_remove(
        struct IPsecControl *ipsec_control,
        struct IPsecSa *ipsec_sa)
{
    SshADTHandle h;
    struct IPsecSaDbControl *ipsec_sa_db = ipsec_control->ipsec_sa_db;
    struct IPsecDbSa probe;
    struct IPsecDbSa *ipsec_db_sa;

    memset(&probe, 0, sizeof(probe));
    probe.ipsec_sa = ipsec_sa;

    if (ipsec_sa->pending == false)
    {
        h =
            ssh_adt_get_handle_to_equal(
                    ipsec_sa_db->ipsec_sas_by_outbound_spi,
                    &probe);
        SSH_ASSERT(h != SSH_ADT_INVALID);

        SSH_DEBUG(
                SSH_D_MY,
                ("Removing %p from active SA bag by outbound SPI 0x%.8x",
                 ipsec_sa, ipsec_sa->params.outbound_spi));

        ipsec_db_sa = ssh_adt_get(ipsec_sa_db->ipsec_sas_by_outbound_spi, h);
        SSH_ASSERT(ipsec_db_sa->ipsec_sa == ipsec_sa);

        ssh_adt_detach(ipsec_sa_db->ipsec_sas_by_outbound_spi, h);

        ipsec_control_db_remove_from_peer(
                ipsec_sa_db,
                ipsec_db_sa);

    }

    h = ipsec_control_db_sa_retrieve_handle(
            ipsec_sa_db,
            ipsec_sa->params.inbound_spi);

    SSH_ASSERT(h != SSH_ADT_INVALID);

    SSH_DEBUG(
            SSH_D_MY,
            ("Removing %p with SPI 0x%.8x from active SA bag",
             ipsec_sa, ipsec_sa->params.inbound_spi));

    ipsec_db_sa = ssh_adt_get(ipsec_sa_db->ipsec_sas, h);
    SSH_ASSERT(ipsec_db_sa->ipsec_sa == ipsec_sa);

    ssh_adt_detach(ipsec_sa_db->ipsec_sas, h);

    ssh_free(ipsec_db_sa);
}

/**
   Function to return a pointer to active IPsec SA with the given
   inbound SPI.
 */
struct IPsecSa *
ipsec_control_db_sa_lookup(
        struct IPsecControl *ipsec_control,
        uint32_t inbound_spi)
{
    struct IPsecSaDbControl *ipsec_sa_db = ipsec_control->ipsec_sa_db;
    struct IPsecDbSa *ipsec_db_sa = NULL;

    ipsec_db_sa =
        ipsec_control_db_sa_retrieve(
                ipsec_sa_db,
                inbound_spi);

    if (ipsec_db_sa != NULL)
        return ipsec_db_sa->ipsec_sa;

    SSH_DEBUG(
            SSH_D_LOWOK,
            ("Could not find IPsec SA with SPI 0x%.8x from active SA bag.",
             inbound_spi));
    return NULL;
}

struct IPsecSa *
ipsec_control_db_sa_lookup_by_outbound_spi(
        struct IPsecControl *ipsec_control,
        uint32_t spi,
        uint8_t ipproto,
        const struct InAddr *remote_ip,
        uint16_t remote_ike_port)
{
    struct IPsecDbSa probe;
    struct IPsecSa ipsec_sa;
    SshADTHandle h;
    struct IPsecSaDbControl *ipsec_sa_db = ipsec_control->ipsec_sa_db;
    struct IPsecDbSa *ipsec_db_sa = NULL;

    memset(&probe, 0, sizeof(probe));
    memset(&ipsec_sa, 0, sizeof(ipsec_sa));
    probe.ipsec_sa = &ipsec_sa;

    probe.ipsec_sa->params.outbound_spi = spi;
    probe.ipsec_sa->params.ipproto = ipproto;
    probe.ipsec_sa->endpoints.remote_address = *remote_ip;
    probe.ipsec_sa->endpoints.remote_port = remote_ike_port;

    h =
        ssh_adt_get_handle_to_equal(
                ipsec_sa_db->ipsec_sas_by_outbound_spi,
                &probe);

    if (h != SSH_ADT_INVALID)
    {
        ipsec_db_sa =
            ssh_adt_get(
                    ipsec_sa_db->ipsec_sas_by_outbound_spi,
                    h);
    }

    if (ipsec_db_sa != NULL)
        return ipsec_db_sa->ipsec_sa;

    SSH_DEBUG(
            SSH_D_LOWOK,
            ("Could not find IPsec SA with outbound SPI 0x%.8x from ADT bag.",
             spi));

    return NULL;
}

struct IPsecSa *
ipsec_control_db_sa_lookup_first_by_peer_handle(
        struct IPsecControl *ipsec_control,
        uint32_t peer_handle)
{
    struct IPsecSaDbControl *ipsec_sa_db = ipsec_control->ipsec_sa_db;
    struct IPsecDbPeer *ipsec_db_peer = NULL;

    ipsec_db_peer =
        ipsec_control_db_peer_retrieve(
                ipsec_sa_db,
                peer_handle);

    if (ipsec_db_peer != NULL)
        return ipsec_db_peer->ipsec_db_sa->ipsec_sa;

    SSH_DEBUG(
            SSH_D_LOWOK,
            ("Could not find peer with handle 0x%.8x from ADT bag.",
             peer_handle));

    return NULL;
}

struct IPsecSa *
ipsec_control_db_sa_lookup_next_by_peer_handle(
        struct IPsecControl *ipsec_control,
        uint32_t peer_handle,
        uint32_t inbound_spi)
{
    struct IPsecDbPeer *ipsec_db_peer = NULL;
    struct IPsecSaDbControl *ipsec_sa_db = ipsec_control->ipsec_sa_db;

    ipsec_db_peer =
        ipsec_control_db_peer_retrieve(
                ipsec_sa_db,
                peer_handle);

    if (ipsec_db_peer != NULL)
    {
        struct IPsecDbSa *curr = ipsec_db_peer->ipsec_db_sa;

        while (curr)
        {
            if (curr->inbound_spi > inbound_spi)
                break;
            curr = curr->next;
        }
        if (curr != NULL)
            return curr->ipsec_sa;
    }

    SSH_DEBUG(
            SSH_D_LOWOK,
            ("Could not find peer with handle 0x%.8x from ADT bag.",
             peer_handle));

    return NULL;
}

static void
ipsec_control_policy_db_uninit(
        struct IPsecPolicyDbControl **ipsec_policy_db_p)
{
    if (*ipsec_policy_db_p != NULL)
    {
        struct IPsecPolicyDbControl *ipsec_policy_db = *ipsec_policy_db_p;

        if (ipsec_policy_db->ipsec_policies != NULL)
        {
            SSH_ASSERT(
                    ssh_adt_num_objects(
                            ipsec_policy_db->ipsec_policies) == 0);

            ssh_adt_destroy(ipsec_policy_db->ipsec_policies);

            ipsec_policy_db->ipsec_policies = NULL;
        }

        ssh_free(ipsec_policy_db);
        *ipsec_policy_db_p = NULL;
    }
}

static bool
ipsec_control_policy_db_init(
        struct IPsecControl *ipsec_control)
{

    struct IPsecPolicyDbControl *ipsec_policy_db = NULL;

    ipsec_policy_db = ssh_calloc(1, sizeof(struct IPsecPolicyDbControl));
    if (ipsec_policy_db == NULL)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Out of memory!"));
        goto error;
    }

    ipsec_policy_db->ipsec_policies =
        ssh_adt_create_generic(
                SSH_ADT_AVLTREE,
                SSH_ADT_HEADER,
                SSH_ADT_OFFSET_OF(
                        struct IPsecDbPolicy,
                        adt_header_policy_id),
                SSH_ADT_COMPARE,   ipsec_control_db_policy_compare,
                SSH_ADT_CONTEXT,   ipsec_policy_db,
                SSH_ADT_ARGS_END);

    if (ipsec_policy_db->ipsec_policies == NULL)
    {
        SSH_DEBUG(
                SSH_D_FAIL,
                ("Initializing ADT bag for Policies failed."));
        goto error;
    }

    ipsec_policy_db->ipsec_control = ipsec_control;
    ipsec_control->ipsec_policy_db = ipsec_policy_db;

    return true;

error:
    ipsec_control_policy_db_uninit(&ipsec_policy_db);
    return false;
}

bool
ipsec_control_db_policy_insert(
        struct IPsecControl *ipsec_control,
        struct IPsecPolicy *ipsec_policy)
{
    struct IPsecPolicyDbControl *ipsec_policy_db =
            ipsec_control->ipsec_policy_db;
    struct IPsecDbPolicy *ipsec_db_policy = NULL;

    ipsec_db_policy = ssh_calloc(1, sizeof(struct IPsecDbPolicy));
    if (ipsec_db_policy == NULL)
        return false;

    ipsec_db_policy->ipsec_policy = ipsec_policy;
    ipsec_db_policy->id = ipsec_policy->policy_id;

    SSH_ASSERT(ssh_adt_get_handle_to_equal(
                       ipsec_policy_db->ipsec_policies,
                       ipsec_db_policy)
               == SSH_ADT_INVALID);

    SSH_DEBUG(
            SSH_D_MY,
            ("Inserting policy %p to database.",
             ipsec_policy));

    ssh_adt_insert(ipsec_policy_db->ipsec_policies, ipsec_db_policy);

    return true;
}


static struct IPsecDbPolicy *
ipsec_control_db_policy_retrieve_handle(
        struct IPsecPolicyDbControl *ipsec_policy_db,
        uint32_t id)
{

    SshADTHandle h = NULL;
    struct IPsecDbPolicy probe;
    struct IPsecPolicy ipsec_policy;

    memset(&probe, 0, sizeof(probe));
    memset(&ipsec_policy, 0, sizeof(ipsec_policy));
    probe.ipsec_policy = &ipsec_policy;
    probe.id = id;

    h = ssh_adt_get_handle_to_equal(ipsec_policy_db->ipsec_policies,
                                    &probe);

    return h;
}

void
ipsec_control_db_policy_remove(
        struct IPsecControl *ipsec_control,
        struct IPsecPolicy *ipsec_policy)
{
    SshADTHandle adt_handle;
    struct IPsecPolicyDbControl *ipsec_policy_db_control =
            ipsec_control->ipsec_policy_db;

    struct IPsecDbPolicy *ipsec_db_policy;

    adt_handle =
        ipsec_control_db_policy_retrieve_handle(
                ipsec_policy_db_control,
                ipsec_policy->policy_id);

    SSH_ASSERT(adt_handle != SSH_ADT_INVALID);

    SSH_DEBUG(
            SSH_D_MY,
            ("Removing policy %p from database.",
             ipsec_policy));

    ipsec_db_policy =
        ssh_adt_get(
                ipsec_policy_db_control->ipsec_policies,
                adt_handle);

    SSH_ASSERT(ipsec_db_policy->ipsec_policy == ipsec_policy);

    ssh_adt_detach(ipsec_policy_db_control->ipsec_policies, adt_handle);

    ssh_free(ipsec_db_policy);
}

struct IPsecPolicy *
ipsec_control_db_policy_lookup(
        struct IPsecControl *ipsec_control,
        int policy_id)
{
    SshADTHandle adt_handle;
    struct IPsecPolicyDbControl *ipsec_policy_db_control =
        ipsec_control->ipsec_policy_db;
    struct IPsecDbPolicy *ipsec_db_policy;
    struct IPsecPolicy *ipsec_policy = NULL;

    adt_handle =
        ipsec_control_db_policy_retrieve_handle(
                ipsec_policy_db_control,
                policy_id);

    ipsec_db_policy =
        ssh_adt_get(
                ipsec_policy_db_control->ipsec_policies,
                adt_handle);

    if (adt_handle != SSH_ADT_INVALID)
    {
        ipsec_db_policy =
            ssh_adt_get(
                    ipsec_policy_db_control->ipsec_policies,
                    adt_handle);
    }

    if (ipsec_db_policy != NULL)
    {
        ipsec_policy = ipsec_db_policy->ipsec_policy;
    }

    return ipsec_policy;
}

struct IPsecPolicy *
ipsec_control_db_policy_first(
        struct IPsecControl *ipsec_control)
{
    struct IPsecPolicyDbControl *ipsec_policy_db_control =
        ipsec_control->ipsec_policy_db;

    struct IPsecDbPolicy *ipsec_db_policy = NULL;
    struct IPsecPolicy *ipsec_policy = NULL;

    if (ssh_adt_num_objects(ipsec_policy_db_control->ipsec_policies) != 0)
    {
        ipsec_db_policy =
            ssh_adt_get_object_from_location(
                    ipsec_policy_db_control->ipsec_policies,
                    SSH_ADT_BEGINNING);
    }

    if (ipsec_db_policy != NULL)
    {
        ipsec_policy = ipsec_db_policy->ipsec_policy;
    }

    return ipsec_policy;
}

bool
ipsec_control_db_init(
        struct IPsecControl *ipsec_control)
{
    bool success = false;

    success = ipsec_control_sa_db_init(ipsec_control);

    if (success == true)
    {
        success = ipsec_control_policy_db_init(ipsec_control);
    }

    if (success == false)
    {
        ipsec_control_db_uninit(ipsec_control);
    }

    return success;
}

void
ipsec_control_db_uninit(
        struct IPsecControl *ipsec_control)
{
    if (ipsec_control != NULL)
    {
        ipsec_control_sa_db_uninit(&ipsec_control->ipsec_sa_db);

        ipsec_control_policy_db_uninit(&ipsec_control->ipsec_policy_db);
    }
}
