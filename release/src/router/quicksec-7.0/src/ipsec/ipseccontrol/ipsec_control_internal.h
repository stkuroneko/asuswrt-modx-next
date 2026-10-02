/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   IPsec Control SA module.
*/
#ifndef IPSEC_CONTROL_INTERNAL_H
#define IPSEC_CONTROL_INTERNAL_H

#include "sshincludes.h"
#include "sshinet.h"
#include "implementation_defs.h"

#include "ipsec_control.h"

#define FIRST(f, ...) f
#define REST(f, ...) __VA_ARGS__

/* Internal debug macro to get IPsec SA prefix for debug log
   message. */
#define IPSEC_SA_DEBUG(level, ipsec_sa, ...)                            \
    DEBUG_ ## level(                                                    \
            control,                                                    \
            "IPsecControl %p: IPsecSa SPI 0x%.8x: "                     \
            FIRST(__VA_ARGS__) "%s",                                    \
            (ipsec_sa)->ipsec_control,                                  \
            (ipsec_sa)->params.inbound_spi,                             \
            REST(__VA_ARGS__, ""))

/* Internal debug macro to get IPsec Policy prefix for debug log
   message. */
#define IPSEC_POLICY_DEBUG(level, ipsec_policy, ...)                    \
    DEBUG_ ## level(                                                    \
            control,                                                    \
            "IPsecPolicy %p: ID %d: "                                   \
            FIRST(__VA_ARGS__) "%s",                                    \
            (ipsec_policy),                                             \
            (ipsec_policy)->policy_id,                                  \
            REST(__VA_ARGS__, ""))

/* Internal debug macro to get IPsec Control prefix for debug log
   message. */
#define IPSEC_CONTROL_DEBUG(level, ipsec_control, ...)                  \
    DEBUG_ ## level(                                                    \
            control,                                                    \
            "IPsecControl %p: "  FIRST(__VA_ARGS__) "%s",               \
            (ipsec_control),                                            \
            REST(__VA_ARGS__, ""))

#define IPSEC_CONTROL_POLICY_ID_MAX 0x01000000

struct IPsecSaDbControl;
struct IPsecPolicyDbControl;

/** Enumerated IPsec SA events. */
typedef enum IPsecControlSaEventsEnum
{
    /** No event. */
    IPSEC_CONTROL_SA_NONE,

    /** IPsec SA is installed. */
    IPSEC_CONTROL_SA_INSTALLED,

    /** IPsec SA has received first packet successfully. */
    IPSEC_CONTROL_SA_FIRST_PACKET_RECEIVED,

    /** IPsec SA has detected idle peer. */
    IPSEC_CONTROL_SA_IDLE_TIMEOUT,

    /** IPsec SA must be rekeyed. */
    IPSEC_CONTROL_SA_REKEY,

    /** IPsec SA must be deleted. */
    IPSEC_CONTROL_SA_DELETE,

    /** IPsec SA has been rekeyed and must be deleted. */
    IPSEC_CONTROL_SA_REKEY_DELETE,

    /** IPsec SA life expired without being rekeyed. */
    IPSEC_CONTROL_SA_EXPIRE,

    /** IPsec SA has overflown outbound sequence numbers. */
    IPSEC_CONTROL_SA_SEQUENCE_NUMBER_OVERFLOW,

    /** IPsec SA is destroyed. */
    IPSEC_CONTROL_SA_DESTROY,

    /** Count of defined IPsec SA events. */
    IPSEC_CONTROL_SA_COUNT
}
IPsecControlSaEvents;

/* Enumerated IKEv2 IPsec SA simultaneous rekey states. */
typedef enum IPsecControlIkev2RekeyStateEnum
{
    /** IPsec SA has not done an IKEv2 simultaneous rekey. */
    IPSEC_CONTROL_IKEV2_REKEY_NONE,

    /** IPsec SA has ongoing IKEv2 simultaneous rekey. */
    IPSEC_CONTROL_IKEV2_REKEY_ONGOING,

    /** IPsec SA has lost an IKEv2 simultaneous rekey. */
    IPSEC_CONTROL_IKEV2_REKEY_LOSER,

    /** IPsec SA has won an IKEv2 simultaneous rekey. */
    IPSEC_CONTROL_IKEV2_REKEY_WINNER,
}
IPsecControlIkev2RekeyState;


/** Structure maintaining state of an IPsec SA. */
struct IPsecSa
{
    /** The configured  parameters of an IPsec SA. */
    struct IPsecSaParams params;

    /** The configured parameters of an IPsec SA endpoints. */
    struct IPsecSaEndpoints endpoints;

    /** Copy of key material until outbound has been installed as well. */
    struct IPsecSaKeyMaterial *ipsec_sa_keymaterial;

    /** Pending flag: when set to true, the inbound SPI is allocated,
        but SA not installed to data plane yet. */
    bool pending;

    /** Deleted flag: when set to true, the SA is deleted but it still
        waits that delete threshold timer expires. In this state events from
        the data plane should be ignored. */
    bool deleted;

    /** IPsec SA has received a delete notification. e.g. from IKE */
    bool delete_received;

    /** IPsec SA has sent a delete notification. */
    bool delete_sent;

    /** Set to true when first IPsec packet has been successfully
        received on the IPsec SA. */
    bool first_packet_received;

    /** Set to true when outbound SA is installed. Inbound is always
        installed.
     */
    bool outbound_installed;

    /** Set to IPSEC_CONTROL_IKEV2_REKEY_WINNER if this SA has won an
        IKEv2 simultaneous rekey and
        set to IPSEC_CONTROL_IKEV2_REKEY_LOSER if this SA has lost an
        IKEv2 simultaneous rekey. */
    IPsecControlIkev2RekeyState ikev2_simultaneous_rekey;

    /** SPI for IPsec SA participating to IKEv2 simultaneous rekey. */
    uint32_t ikev2_simultaneous_inbound_spi;

    /** The timeout structure of the IPsec SA. When SA is not pending a
        timeout is always registered. */
    SshTimeoutStruct timeout;

    /** The event the timeout is registered for.  */
    IPsecControlSaEvents timeout_event;

    /** Set to true, when timeout is registered and to false when
        timeout is not registered. */
    bool timeout_registered;

    /** The remaining life time of the IPsec SA in seconds left after
        the timeout . */
    int life_to_live;

    /** Count of rekey attempt for this IPsec SA. */
    int rekey_attempt;

    /** Rekey retry timeout. */
    int rekey_retry_timeout;

    /** Return pointer from data plane when SA installed via IPsec
        Control API. */
    void *control_sa;

    /** Back pointer to the IPsec Control. */
    struct IPsecControl *ipsec_control;

    struct IPsecSa *circle_next;

    /** Identifier of the rekey chain of IPsec SAs. */
    uint32_t chain_id;
};

/** Structure maintaining state of an IPsec Policy. */
struct IPsecPolicy
{
    /** Policy entry identifier for the database. */
    int policy_id;

    /** Identifier of a sibling entry. */
    int sibling_policy_id;

    /** If this is a "bypass" entry. */
    bool bypass_entry;

    /** Timeout after which the entry is removed. */
    SshTimeoutStruct remove_timeout;

    /** The configured  parameters of an IPsec Policy. */
    struct IPsecPolicyParams params;

    /** Return pointer from data plane when policy installed via
        IPsec Control API. */
    void *control_policy;

    /** Back pointer to the IPsec Control. */
    struct IPsecControl *ipsec_control;
};

/**
   The root structure of a IPsec Control context.
 */
struct IPsecControl
{
    /** Back Pointer to the controlling entity (Policy Manager). */
    void *param;

    /** Longer delay, in seconds, after rekey before deleting IPsec SA. Used
        for IKEv2 responder and for IKEv1 responder and IKEv1 initiator
        until first inbound packet has been received. */
    uint32_t ipsec_life_rekey_delete_long_delay;

    /** Short delay, in seconds, after rekey before deleting IPsec SA. User
        for IKEv2 initiator, and for IKEv1 initiator after first packet
        has been received on the SA. */
    uint32_t ipsec_life_rekey_delete_short_delay;

    /** Callback for events in policy manager. */
    IPsecSaEventCb *event_callback;
    IPsecSaEventUnknownSpiCb *unknown_spi_callback;

    const struct IPsecControlCallbacks *control_callbacks;
    void *control_param;

    /* seed for internal random number generator (for generating jitter) */
    uint64_t seed;

    /** Counter for IPSec Policy identifiers. */
    int ipsec_policy_ids;

    struct IPsecSaDbControl *ipsec_sa_db;
    struct IPsecPolicyDbControl *ipsec_policy_db;

    int bypass_entry_count;

    /* Base policy entry ids. */
    int icmp_spd_o_entry_id;
    int icmp_spd_i_entry_id;
    int base_spd_o_entry_id;
    int base_spd_i_entry_id;
    int system_spd_o_entry_id;
    int system_spd_i_entry_id;
    int ike_spd_o_entry_id;
    int ike_spd_i_entry_id;
};

bool
ipsec_control_db_init(
        struct IPsecControl *ipsec_control);


void
ipsec_control_db_uninit(
        struct IPsecControl *ipsec_control);


bool
ipsec_control_db_sa_insert(
        struct IPsecControl *ipsec_control,
        struct IPsecSa *ipsec_sa);

void
ipsec_control_db_sa_insert_active(
        struct IPsecControl *ipsec_control,
        struct IPsecSa *ipsec_sa);

void
ipsec_control_db_sa_remove(
        struct IPsecControl *ipsec_control,
        struct IPsecSa *ipsec_sa);


bool
ipsec_control_db_policy_insert(
        struct IPsecControl *ipsec_control,
        struct IPsecPolicy *ipsec_policy);

void
ipsec_control_db_policy_remove(
        struct IPsecControl *ipsec_control,
        struct IPsecPolicy *ipsec_policy);

struct IPsecPolicy *
ipsec_control_db_policy_first(
        struct IPsecControl *ipsec_control);

void
ipsec_policy_flush(
        struct IPsecControl *ipsec_control);

/**
   Function to return a pointer to IPsec Policy with the given
   policy id.
 */
struct IPsecPolicy *
ipsec_control_db_policy_lookup(
        struct IPsecControl *ipsec_control,
        int policy_id);

/**
   Function to return a pointer to active IPsec SA with the given
   inbound SPI.
 */
struct IPsecSa *
ipsec_control_db_sa_lookup(
        struct IPsecControl *ipsec_control,
        uint32_t inbound_spi);

struct IPsecSa *
ipsec_control_db_sa_lookup_by_outbound_spi(
        struct IPsecControl *ipsec_control,
        uint32_t spi, uint8_t ipproto,
        const struct InAddr *remote_ip,
        uint16_t remote_ike_port);

void
ipsec_control_db_sa_remove_chain_id(
        struct IPsecControl *ipsec_control,
        struct IPsecSa *ipsec_sa);

struct IPsecSa *
ipsec_control_db_sa_lookup_by_chain_id(
        struct IPsecControl *ipsec_control,
        uint32_t chain_id);

void
ipsec_control_db_sa_insert_chain_id(
        struct IPsecControl *ipsec_control,
        struct IPsecSa *ipsec_sa);

uint32_t
ipsec_control_db_sa_find_peer(
        struct IPsecControl *ipsec_control,
        const struct InAddr *remote_ip);

struct IPsecSa *
ipsec_control_db_sa_lookup_first_by_peer_handle(
        struct IPsecControl *ipsec_control,
        uint32_t peer_handle);

struct IPsecSa *
ipsec_control_db_sa_lookup_next_by_peer_handle(
        struct IPsecControl *ipsec_control,
        uint32_t peer_handle,
        uint32_t inbound_spi);

#endif /* IPSEC_CONTROL_INTERNAL_H */
