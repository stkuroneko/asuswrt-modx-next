/*
 * @@-COPYRIGHT-START-@@
 *
 * Copyright (c) 2014 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * @@-COPYRIGHT-END-@@
 */

#include <osdep.h>
#include "osif_private.h"

#ifndef _ATH_BAND_STEERING__
#define _ATH_BAND_STEERING___

#if ATH_BAND_STEERING

#define WLAN_DEFAULT_BSTEER_NETLINK_PID 0xffffff

struct band_steering_netlink {
    struct sock      *bsteer_sock;
    u_int32_t        bsteer_pid;
    atomic_t         bsteer_refcnt;
};

int ath_band_steering_netlink_init(void);
int ath_band_steering_netlink_delete(void);
void ath_band_steering_netlink_send(ath_netlink_bsteering_event_t *event);
#else
#define ath_band_steering_netlink_init() do {} while (0)
#define ath_band_steering_netlink_delete() do {} while (0)
#define ath_band_steering_netlink_send(ev) do {} while (0)
#endif

#endif /* _ATH_BAND_STEERING___*/
