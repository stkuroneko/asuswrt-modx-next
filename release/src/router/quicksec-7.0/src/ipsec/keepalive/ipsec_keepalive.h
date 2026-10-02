/**
   @copyright
   Copyright (c) 2016, INSIDE Secure Oy. All rights reserved.
*/

#ifndef IPSEC_KEEPALIVE_H
#define IPSEC_KEEPALIVE_H

#include "sshincludes.h"
#include "sshadt.h"
#include "sshadt_bag.h"

#include "in_addr.h"


struct IPsecKeepalive;


typedef bool
IPsecKeepaliveSendCB(
        void *control_param,
        const struct InAddr *local_ip,
        uint16_t local_port,
        const struct InAddr *remote_ip,
        uint16_t remote_port);


/**
   Enable UDP NAT-T keepalive for specified address pair with given
   keepalive timeout interval.
 */
void
ipsec_keepalive_start(
        struct IPsecKeepalive* ipsec_keepalive,
        const struct InAddr *local_addr,
        uint16_t local_port,
        const struct InAddr *remote_addr,
        uint16_t remote_port,
        int keepalive_timeout);

/**
   Disable UDP NAT-T keepalive for specified address pair.
 */
void
ipsec_keepalive_stop(
        struct IPsecKeepalive* ipsec_keepalive,
        const struct InAddr *local_addr,
        uint16_t local_port,
        const struct InAddr *remote_addr,
        uint16_t remote_port);

void
ipsec_keepalive_update(
        struct IPsecKeepalive* ipsec_keepalive,
        const struct InAddr *local_addr,
        uint16_t local_port,
        const struct InAddr *remote_addr,
        uint16_t remote_port);

 /**
   Request an extra keepalive.
 */
void
ipsec_keepalive_requested(
        struct IPsecKeepalive *ipsec_keepalive,
        const struct InAddr *local_addr,
        uint16_t local_port,
        const struct InAddr *remote_addr,
        uint16_t remote_port);

bool
ipsec_keepalive_init(
        struct IPsecKeepalive **ipsec_keepalive,
        IPsecKeepaliveSendCB *send_cb,
        void *control_param);

void
ipsec_keepalive_uninit(
        struct IPsecKeepalive **ipsec_keepalive);


#endif /* IPSEC_KEEPALIVE_H */
