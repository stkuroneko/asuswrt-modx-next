/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   Header for IPsec SA module.
*/

#ifndef IPSEC_SA_H
#define IPSEC_SA_H

#include "sshincludes.h"
#include "sshinet.h"
#include "sshtimeouts.h"

#include "sshikev2-initiator.h"
#include "sshsad.h"

#include "public_defs.h"
#include "ipsec_sa_params.h"
#include "ipsec_control.h"

/** Enumerated IPsec SA events. */
typedef enum IPsecSaEventEnum
{
    /** Idle */
    IPSEC_SA_EVENT_IDLE,

    /** Install */
    IPSEC_SA_EVENT_INSTALL,

    /** Uninstall */
    IPSEC_SA_EVENT_UNINSTALL,

    /** Deleted */
    IPSEC_SA_EVENT_DELETE,

    /** Expired */
    IPSEC_SA_EVENT_EXPIRE,

    /** Rekey */
    IPSEC_SA_EVENT_REKEY

} IPsecSaEvent;

typedef void
IPsecSaEventCb(
        void *param,
        const struct IPsecSaParams *ipsec_sa_params,
        const struct IPsecSaEndpoints *ipsec_sa_endpoints,
        IPsecSaEvent event);

typedef void
IPsecSaEventUnknownSpiCb(
        void *param,
        const struct InAddr *local_ip,
        const struct InAddr *remote_ip,
        uint16_t local_port,
        uint16_t remote_port,
        SshInetIPProtocolID ipproto,
        uint32_t spi,
        int routing_instance_id);

bool
ipsec_sa_configure(
        struct IPsecControl *ipsec_control,
        void *callback_param,
        IPsecSaEventCb *event_callback,
        IPsecSaEventUnknownSpiCb *unknown_spi_callback);

void
ipsec_sa_unconfigure(
        struct IPsecControl *ipsec_control);

bool
ipsec_sa_allocate(
        struct IPsecControl *ipsec_control,
        uint32_t *inbound_spi);

bool
ipsec_sa_allocate_rekey(
        struct IPsecControl *ipsec_control,
        uint32_t rekeyed_spi,
        uint32_t *rekey_spi);

void
ipsec_sa_free(
        struct IPsecControl *ipsec_control,
        uint32_t inbound_spi);

uint32_t
ipsec_sa_find_by_outbound_spi(
        struct IPsecControl *ipsec_control,
        bool match_address,
        uint32_t spi,
        uint8_t ipproto,
        const struct InAddr *remote_ip,
        uint16_t remote_ike_port);

const struct IPsecSaParams *
ipsec_sa_get_params(
        struct IPsecControl *ipsec_control,
        uint32_t inbound_spi);

const struct IPsecSaEndpoints *
ipsec_sa_get_endpoints(
        struct IPsecControl *ipsec_control,
        uint32_t inbound_spi);

bool
ipsec_sa_get_traffic_selectors(
        struct IPsecControl *ipsec_control,
        uint32_t inbound_spi,
        const struct IPSelectorGroup **selector_group_p);

bool
ipsec_sa_is_rekeyed(
        struct IPsecControl *ipsec_control,
        uint32_t inbound_spi);

bool
ipsec_sa_is_rekey_possible(
        struct IPsecControl *ipsec_control,
        uint32_t inbound_spi,
        int *time_left_seconds);

bool
ipsec_sa_install(
        struct IPsecControl *ipsec_control,
        struct IPsecSaParams *ipsec_sa_params,
        struct IPsecSaEndpoints *ipsec_sa_endpoints,
        struct IPsecSaKeyMaterial *ipsec_sa_keymaterial,
        const struct IPSelectorGroup *selector_group);

bool
ipsec_sa_import(
        struct IPsecControl *ipsec_control,
        struct IPsecSaParams *ipsec_sa_params,
        struct IPsecSaEndpoints *ipsec_sa_endpoints,
        struct IPsecSaKeyMaterial *ipsec_sa_keymaterial,
        const struct IPSelectorGroup *selector_group);

int
ipsec_sa_delete_all_by_peer_handle(
        struct IPsecControl *ipsec_control,
        uint32_t peer_handle);

int
ipsec_sa_destroy_all_by_peer_handle(
        struct IPsecControl *ipsec_control,
        uint32_t peer_handle);

void
ipsec_sa_delete(
        struct IPsecControl *ipsec_control,
        uint32_t inbound_spi);

bool
ipsec_sa_update_by_peer_handle(
        struct IPsecControl *ipsec_control,
        uint32_t peer_handle,
        int path_id,
        struct IPsecSaEndpoints *ipsec_sa_endpoints);

uint32_t
ipsec_sa_find_matching_sa(
        struct IPsecControl *ipsec_control,
        uint32_t peer_handle,
        const struct IPSelectorGroup *selector_group);

void
ipsec_sa_responder_set_simultaneous_rekey(
        struct IPsecControl *ipsec_control,
        uint32_t inbound_spi,
        uint32_t simultaneous_inbound_spi);

void
ipsec_sa_initiator_set_simultaneous_won(
        struct IPsecControl *ipsec_control,
        uint32_t inbound_spi);

void
ipsec_sa_initiator_set_simultaneous_lost(
        struct IPsecControl *ipsec_control,
        uint32_t inbound_spi);

const struct IPsecSaParams *
ipsec_sa_first_by_peer_handle(
        struct IPsecControl *ipsec_control,
        uint32_t peer_handle);

const struct IPsecSaParams *
ipsec_sa_next_by_peer_handle(
        struct IPsecControl *ipsec_control,
        uint32_t peer_handle,
        uint32_t inbound_spi);

#endif /* IPSEC_SA_H */
