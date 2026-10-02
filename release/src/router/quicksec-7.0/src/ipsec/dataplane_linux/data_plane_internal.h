/**
   @copyright
   Copyright (c) 2015 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   Data Plane - Internal API for Data Plane Linux
*/

#ifndef DATA_PLANE_INTERNAL_H
#define DATA_PLANE_INTERNAL_H

#include "sshincludes.h"
#include "data_plane.h"
#include "implementation_defs.h"

struct SelectorEnd
{
    struct InAddr address;
    int address_mask;
    int port;
    uint16_t port_mask;
};

struct PolicyParams
{
    uint32_t policy_id;
    uint32_t priority;

    uint32_t direction;
    int protocol;
    struct SelectorEnd src_sel;
    struct SelectorEnd dst_sel;
};

struct DPPolicyDb;

struct DataPlaneRec
{
    /** Anti-replay window. */
    uint32_t replay_window;

    struct IPsecControl *ipsec_control;
    struct NetlinkXfrm *netlink_xfrm;

    struct DPPolicyDB *policy_db;

    struct IPsecKeepalive *ipsec_keepalive;
    int udp_sock;
};

struct PolicyTmplParams
{
    bool tunnel_mode;

    struct InAddr src_address;
    struct InAddr dst_address;

    uint32_t protocol;
    uint32_t req_id;
};

bool
data_plane_policy_db_init(
        DataPlane data_plane);

void
data_plane_policy_db_uninit(
        DataPlane data_plane);

bool
data_plane_install_policy(
        DataPlane data_plane,
        bool update,
        const struct PolicyParams *params,
        int action);

bool
data_plane_install_policy_with_tmpl(
        DataPlane data_plane,
        bool update,
        const struct PolicyParams *params,
        const struct PolicyTmplParams *tmpl_params);

bool
data_plane_delete_policy(
        DataPlane data_plane,
        const struct PolicyParams *params);

void
debug_dump_data_plane_policy_entry(
        void *context,
        const void *data,
        unsigned bytecount);

#endif /* DATA_PLANE_INTERNAL_H */

