/**
   @copyright
   Copyright (c) 2015 - 2016, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "data_plane_internal.h"
#include "data_plane.h"
#include "implementation_defs.h"
#include "netlink_xfrm.h"
#include "ipsec_keepalive.h"

#include "ip_selector_parse.h"
#include "ipsec_control.h"

#include "in_addr.h"

#include <netinet/in.h>
#include <arpa/inet.h>

#define SSH_DEBUG_MODULE "DataPlaneLinux"
#define __DEBUG_MODULE__ DataPlaneLinux

/**
   Anti-replay window size.
*/
#define DATAPLANE_ANTIREPLAY_WINDOW_SIZE 128

/** Set upper limit for the number of policies generated from one
      selector group. */
#define DATAPLANE_SELECTOR_POLICY_LIMIT (5 * 5)

/** IPsec UDP encapsulation NAT-T keepalive packet UDP payload,
    as specified in RFC 3948 */
#define IPSEC_UDP_ENCAP_NATT_KEEPALIVE_DATA 0xff

/* Port bit size */
#define PORT_BIT_COUNT 16

/* ICMP code size */
#define ICMP_CODE_BIT_COUNT 8

typedef bool
DataPlanePolicyHandler(
        DataPlane data_plane,
        const struct SelectorEnd *src,
        const struct SelectorEnd *dst,
        int protocol,
        const void *context);

static bool
data_plane_create_udp_socket(
        DataPlane data_plane);

static bool
data_plane_parse_selector(
        DataPlane data_plane,
        const struct IPSelectorGroup *selector_group,
        DataPlanePolicyHandler *policy_handler,
        const void *context);

static void
data_plane_addr_range_to_subnet(
        struct InAddr *subnet_address,
        int *subnet_mask,
        const struct InAddr *begin,
        const struct InAddr *end)
{
    int mask_bit_count;
    struct InAddr subnet_address_max;

    for (mask_bit_count = IN_ADDR_BIT_COUNT;
         mask_bit_count > 0;
         mask_bit_count--)
    {
        if (in_addr_compare_masked(
                    begin,
                    end,
                    mask_bit_count)
            == 0)
        {
            break;
        }
    }

    in_addr_copy(subnet_address, begin, mask_bit_count);

    in_addr_copy(&subnet_address_max, begin, mask_bit_count);
    in_addr_host_bits_set(&subnet_address_max, mask_bit_count);

    if (in_addr_version(subnet_address) == IN_ADDR_FOUR)
    {
        mask_bit_count -= IN_ADDR_FOUR_MASK_OFFSET;
    }

    if (in_addr_compare(begin, subnet_address) != 0 ||
        in_addr_compare(end, &subnet_address_max) != 0)
    {
        ssh_log_event(
                    SSH_LOGFACILITY_DAEMON,
                    SSH_LOG_WARNING,
                    "Requested address range %@ - %@ could not be installed, "
                    "using %@ - %@ instead!",
                    ssh_in_addr_render, begin,
                    ssh_in_addr_render, end,
                    ssh_in_addr_render, subnet_address,
                    ssh_in_addr_render, &subnet_address_max);
    }


    *subnet_mask = mask_bit_count;
}

static bool
data_plane_range_to_mask(
        int *port,
        uint16_t *mask,
        const int len,
        const int begin,
        const int end)
{
    bool ok = true;
    int mask_bit_count;
    int begin_bits;
    int end_bits;

    /* Figure out the mask length. */
    for (mask_bit_count = 0;
         mask_bit_count < len;
         mask_bit_count++)
    {
        begin_bits = begin >> mask_bit_count;
        end_bits = end >> mask_bit_count;

        if (memcmp(&begin_bits, &end_bits, sizeof(int)) == 0)
        {
            break;
        }
    }

    /* Clear the non common bits. */
    *port = begin >> mask_bit_count;
    *port = *port << mask_bit_count;

    /* Clear the non common bits from the mask. */
    *mask = 0xffff >> mask_bit_count;
    *mask = *mask << mask_bit_count;

    /* Check if we have an exact range or not. */
    if (*port != begin ||
        (*port | (~(*mask) & 0xffff)) != end)
    {
        ok = false;
    }

    return ok;
}

static bool
data_plane_port_range_to_mask(
        int *port,
        uint16_t *mask,
        const int begin,
        const int end)
{
    bool ok = true;

    /* Not a range at all. */
    if (begin == end)
    {
        *port = begin;
        if (*port == 0)
        {
            *mask = 0;
        }
        else
        {
            *mask = 0xffff;
        }
    }
    /* The whole available port range. */
    else if (begin == IP_SELECTOR_PORT_MIN &&
             end == IP_SELECTOR_PORT_MAX)
    {
        *port = 0;
        *mask = 0;
    }
    else
    {
        ok =
            data_plane_range_to_mask(
                    port,
                    mask,
                    PORT_BIT_COUNT,
                    begin,
                    end);
    }

    if (ok == false)
    {
        ssh_log_event(
                SSH_LOGFACILITY_DAEMON,
                SSH_LOG_WARNING,
                "Requested port range %d - %d could not be installed, "
                "using %d - %d instead!",
                begin, end,
                *port, *port | (~(*mask) & 0xffff));
    }

    return ok;
}

static bool
data_plane_icmp_code_range_to_mask(
        int *port,
        uint16_t *mask,
        const int begin,
        const int end)
{
    bool ok = true;

    ok = data_plane_range_to_mask(
                    port,
                    mask,
                    ICMP_CODE_BIT_COUNT,
                    begin,
                    end);

    if (ok == false)
    {
        ssh_log_event(
                SSH_LOGFACILITY_DAEMON,
                SSH_LOG_WARNING,
                "Requested ICMP code range %d - %d could not be installed, "
                "using %d - %d instead!",
                begin, end,
                *port, *port | (~(*mask) & 0xffff));
    }

    return ok;
}

typedef struct
{
    int src_endpoint;
    int dst_endpoint;
    int src_address;
    int dst_address;
    int src_port;
    int dst_port;
}
SelectorFieldCounts;

struct SaPolicyContext
{
    bool update;
    struct PolicyTmplParams policy_template;
    const struct IPsecSaParams *sa_params;
};

static bool
data_plane_port_to_icmp_type_and_code(
        bool source,
        int* port,
        uint16_t* port_mask,
        int port_begin,
        int port_end)
{
    bool ok = true;

    /* Check if we're dealing with a range. */
    if (port_begin != port_end)
    {
        /* Support selecting the whole range. */
        if (port_begin == IP_SELECTOR_PORT_MIN &&
            port_end == IP_SELECTOR_PORT_MAX)
        {
            *port = 0;
            *port_mask = 0;
        }
        else
        {
            int type_begin;
            int code_begin;
            int type_end;
            int code_end;

            type_begin = port_begin >> 8;
            code_begin = port_begin & 0xff;
            type_end = port_end >> 8;
            code_end = port_end & 0xff;

            if (type_begin != type_end)
            {
                SSH_DEBUG(SSH_D_FAIL,("ICMP selectors that contain several "
                            "types are not supported."));
                *port = 0;
                *port_mask = 0xffff;
                ok = false;
            }
            else
            {
                SSH_DEBUG(SSH_D_FAIL,("ICMP selectors that contain several "
                            "codes are not properly supported yet."));

                if (source == true)
                {
                    *port = type_begin;
                    *port_mask = 0xffff;
                }
                else
                {
                    data_plane_icmp_code_range_to_mask(
                            port,
                            port_mask,
                            code_begin,
                            code_end);
                }
            }

        }

    }
    /* Not a range. */
    else
    {
        /* Source port becomes type */
        if (source == true)
        {
            *port = port_begin >> 8;
        }
        /* Destination port becomes code */
        else
        {
            *port = port_begin & 0xff;
        }

        *port_mask = 0xffff;
    }

    return ok;
}


static void
data_plane_netlink_get_selector_values(
        struct IPSelectorParse *parser,
        bool source,
        struct InAddr *address,
        int *address_mask,
        int *port,
        uint16_t *port_mask,
        int *ip_protocol)
{
    int field = IP_SELECTOR_DESTINATION_ENDPOINT;
    struct InAddr address_begin;
    struct InAddr address_end;
    int port_begin;
    int port_end;

    if (source == true)
    {
        field = IP_SELECTOR_SOURCE_ENDPOINT;
    }

    ip_selector_parse_next_endpoint(
            parser,
            field,
            &address_begin,
            &address_end,
            ip_protocol,
            &port_begin,
            &port_end);

    data_plane_addr_range_to_subnet(
            address,
            address_mask,
            &address_begin,
            &address_end);

    if (*ip_protocol == SSH_IPPROTO_ICMP ||
        *ip_protocol == SSH_IPPROTO_IPV6ICMP)
    {
        data_plane_port_to_icmp_type_and_code(
                source,
                port,
                port_mask,
                port_begin,
                port_end);
    }
    else
    {
        data_plane_port_range_to_mask(
                port,
                port_mask,
                port_begin,
                port_end);
    }
}


static void
data_plane_policy_params_sa_init_out(
        struct PolicyParams *policy_params,
        const struct SelectorEnd *src,
        const struct SelectorEnd *dst,
        int protocol,
        const struct IPsecSaParams *sa_params)
{
    policy_params->src_sel = *src;
    policy_params->dst_sel = *dst;

    policy_params->priority = sa_params->policy_priority;
    policy_params->protocol = protocol;
    policy_params->policy_id = sa_params->inbound_spi;

    policy_params->direction = NETLINK_XFRM_DIRECTION_OUT;
}

static void
data_plane_policy_params_sa_init_in(
        struct PolicyParams *policy_params,
        const struct SelectorEnd *src,
        const struct SelectorEnd *dst,
        int protocol,
        const struct IPsecSaParams *sa_params)
{
    /* Swap ends */
    policy_params->src_sel = *dst;
    policy_params->dst_sel = *src;

    policy_params->priority = sa_params->policy_priority;
    policy_params->protocol = protocol;
    policy_params->policy_id = sa_params->inbound_spi;

    policy_params->direction = NETLINK_XFRM_DIRECTION_IN;
}


static void
data_plane_policy_params_sa_set_fwd(
        struct PolicyParams *policy_params)
{
    policy_params->direction = NETLINK_XFRM_DIRECTION_FWD;
}

static void
data_plane_template_params_sa_init_outbound(
        struct PolicyTmplParams *template,
        const struct IPsecSaParams *sa_params,
        const struct IPsecSaEndpoints *endpoints)
{
    template->tunnel_mode = sa_params->tunnel_mode;
    template->req_id = sa_params->event_id_outbound;
    template->protocol = sa_params->ipproto;

    memcpy(
            &template->src_address,
            &endpoints->local_address,
            sizeof template->src_address);
    memcpy(
            &template->dst_address,
            &endpoints->remote_address,
            sizeof template->dst_address);
}


static void
data_plane_template_params_sa_init_inbound(
        struct PolicyTmplParams *template,
        const struct IPsecSaParams *sa_params,
        const struct IPsecSaEndpoints *endpoints)
{
    template->tunnel_mode = sa_params->tunnel_mode;
    template->req_id = sa_params->event_id_inbound;
    template->protocol = sa_params->ipproto;

    memcpy(
            &template->src_address,
            &endpoints->remote_address,
            sizeof template->src_address);
    memcpy(
            &template->dst_address,
            &endpoints->local_address,
            sizeof template->dst_address);
}

static bool
data_plane_sa_policy_inbound_handler(
        DataPlane data_plane,
        const struct SelectorEnd *src,
        const struct SelectorEnd *dst,
        int protocol,
        const void *context)
{
    struct SaPolicyContext *sa_context = (struct SaPolicyContext *)context;
    struct PolicyParams policy_params = { 0 };
    bool ok;

    data_plane_policy_params_sa_init_in(
            &policy_params,
            src,
            dst,
            protocol,
            sa_context->sa_params);

    ok =
        data_plane_install_policy_with_tmpl(
                data_plane,
                sa_context->update,
                &policy_params,
                &sa_context->policy_template);

    if (ok == true && sa_context->sa_params->tunnel_mode == true)
    {
        data_plane_policy_params_sa_set_fwd(
                &policy_params);

        ok =
            data_plane_install_policy_with_tmpl(
                    data_plane,
                    sa_context->update,
                    &policy_params,
                    &sa_context->policy_template);
    }

    return ok;
}

static bool
data_plane_install_sa_policy_inbound(
        DataPlane data_plane,
        bool update,
        const struct IPsecSaParams *sa_params,
        const struct IPsecSaEndpoints *endpoints)
{
    struct SaPolicyContext context = { 0 };
    bool ok = true;

    data_plane_template_params_sa_init_inbound(
            &context.policy_template,
            sa_params,
            endpoints);

    context.update = update;
    context.sa_params = sa_params;

    ok =
        data_plane_parse_selector(
                data_plane,
                sa_params->selector_group,
                data_plane_sa_policy_inbound_handler,
                &context);

    return ok;
}

static bool
data_plane_sa_policy_outbound_handler(
        DataPlane data_plane,
        const struct SelectorEnd *src,
        const struct SelectorEnd *dst,
        int protocol,
        const void *context)
{
    struct SaPolicyContext *sa_context = (struct SaPolicyContext *)context;
    struct PolicyParams policy_params = { 0 };
    bool ok;

    data_plane_policy_params_sa_init_out(
            &policy_params,
            src,
            dst,
            protocol,
            sa_context->sa_params);

    ok =
        data_plane_install_policy_with_tmpl(
                data_plane,
                sa_context->update,
                &policy_params,
                &sa_context->policy_template);

    return ok;
}



static bool
data_plane_install_sa_policy_outbound(
        DataPlane data_plane,
        bool update,
        const struct IPsecSaParams *sa_params,
        const struct IPsecSaEndpoints *endpoints)
{
    struct SaPolicyContext context = { 0 };
    bool ok = true;

    data_plane_template_params_sa_init_outbound(
            &context.policy_template,
            sa_params,
            endpoints);

    context.update = update;
    context.sa_params = sa_params;

    ok =
        data_plane_parse_selector(
                data_plane,
                sa_params->selector_group,
                data_plane_sa_policy_outbound_handler,
                &context);

    return ok;
}

static bool
data_plane_install_sa_policy(
        DataPlane data_plane,
        bool update,
        const struct IPsecSaParams *sa_params,
        const struct IPsecSaEndpoints *endpoints)
{
    bool ok = true;

    ok =
        data_plane_install_sa_policy_outbound(
                data_plane,
                update,
                sa_params,
                endpoints);

    if (ok == true)
    {
        ok =
            data_plane_install_sa_policy_inbound(
                    data_plane,
                    update,
                    sa_params,
                    endpoints);
    }
    return ok;
}


static bool
data_plane_install_outbound_sa(
        DataPlane data_plane,
        const struct IPsecSaParams *params,
        const struct IPsecSaEndpoints *endpoints,
        const struct IPsecSaKeyMaterial *key_mat)
{
    struct NetlinkXfrm *netlink_xfrm = data_plane->netlink_xfrm;
    struct NetlinkRequest *request;
    bool ok = false;

    request = netlink_xfrm_request_alloc(netlink_xfrm);
    if (request != NULL)
    {
        netlink_xfrm_newsa_init(request);

        if (endpoints->natt == true)
        {
            int local_port;
            int remote_port;

            local_port = endpoints->local_port;
            remote_port = endpoints->remote_port;

            netlink_xfrm_set_natt(request, local_port, remote_port);
        }

        /* SA data */
        netlink_xfrm_newsa_encode_addresses(
                request,
                &endpoints->local_address,
                &endpoints->remote_address);

        netlink_xfrm_newsa_encode_sa_info(
                request,
                params->ipproto,
                params->outbound_spi,
                params->event_id_outbound,
                params->tunnel_mode,
                params->esn,
                params->life_bytes,
                params->life_bytes_rekey,
                true);

        /* Anti-replay window and ESN */
        netlink_xfrm_newsa_encode_replay_window_esn(
                request,
                data_plane->replay_window,
                params->seq_high,
                params->seq_low,
                true,
                params->esn);

        /* encryption alg */
        netlink_xfrm_newsa_encode_algorithm(
                request,
                params->encryption_algorithm_id,
                key_mat->encryption_keymaterial_len,
                key_mat->outbound_encryption_keymaterial);

        if (params->integrity_algorithm_id != TRANSFORMID_INTEG_NONE)
        {
            netlink_xfrm_newsa_encode_algorithm(
                    request,
                    params->integrity_algorithm_id,
                    key_mat->integrity_keymaterial_len,
                    key_mat->outbound_integrity_keymaterial);
        }

        ok = netlink_xfrm_request_send(&request);
    }
    else
    {
        SSH_DEBUG(SSH_D_ERROR, ("Failed to allocate XFRM request"));
    }

    return ok;
}


static bool
data_plane_install_inbound_sa(
        DataPlane data_plane,
        const struct IPsecSaParams *params,
        const struct IPsecSaEndpoints *endpoints,
        const struct IPsecSaKeyMaterial *key_mat)
{
    struct NetlinkXfrm *netlink_xfrm = data_plane->netlink_xfrm;
    struct NetlinkRequest *request;
    const struct InAddr *src;
    const struct InAddr *dst;
    bool ok = false;

    request = netlink_xfrm_request_alloc(netlink_xfrm);
    if (request != NULL)
    {
        /* In inbound direction remote address is source
           and local address id destination. */
        src = &endpoints->remote_address;
        dst = &endpoints->local_address;

        netlink_xfrm_newsa_init(request);

        if (endpoints->natt == true)
        {
            int local_port;
            int remote_port;

            local_port = endpoints->local_port;
            remote_port = endpoints->remote_port;

            netlink_xfrm_set_natt(request, local_port, remote_port);
        }

        /* SA data */
        netlink_xfrm_newsa_encode_addresses(request, src, dst);

        netlink_xfrm_newsa_encode_sa_info(
                request,
                params->ipproto,
                params->inbound_spi,
                params->event_id_inbound,
                params->tunnel_mode,
                params->esn,
                params->life_bytes,
                params->life_bytes_rekey,
                false);

        /* Anti-replay window and ESN */
        netlink_xfrm_newsa_encode_replay_window_esn(
                request,
                data_plane->replay_window,
                0,
                0,
                false,
                params->esn);

        /* encryption alg */
        netlink_xfrm_newsa_encode_algorithm(
                request,
                params->encryption_algorithm_id,
                key_mat->encryption_keymaterial_len,
                key_mat->inbound_encryption_keymaterial);

        /* authentication alg */
        if (params->integrity_algorithm_id != TRANSFORMID_INTEG_NONE)
        {
            netlink_xfrm_newsa_encode_algorithm(
                    request,
                    params->integrity_algorithm_id,
                    key_mat->integrity_keymaterial_len,
                    key_mat->inbound_integrity_keymaterial);
        }

        ok = netlink_xfrm_request_send(&request);
    }
    else
    {
        SSH_DEBUG(SSH_D_ERROR, ("Failed to allocate XFRM request"));
    }

    return ok;
}


static bool
data_plane_install_sas(
        DataPlane data_plane,
        const struct IPsecSaParams *params,
        const struct IPsecSaEndpoints *endpoints,
        const struct IPsecSaKeyMaterial *key_mat)
{
    bool ok = true;

    if (ok == true)
    {
        ok =
            data_plane_install_outbound_sa(
                    data_plane,
                    params,
                    endpoints,
                    key_mat);
    }

    if (ok == true)
    {
        ok =
            data_plane_install_inbound_sa(
                    data_plane,
                    params,
                    endpoints,
                    key_mat);
    }

    if (ok == true && endpoints->natt_keepalive == true)
    {
        ipsec_keepalive_start(
                data_plane->ipsec_keepalive,
                &endpoints->local_address,
                endpoints->local_port,
                &endpoints->remote_address,
                endpoints->remote_port,
                params->natt_keepalive_timeout);
    }

    return ok;
}


static bool
data_plane_install_sa_cb(
        void *control_param,
        const struct IPsecSaParams *params,
        const struct IPsecSaEndpoints *endpoints,
        void **control_sa_p,
        const struct IPsecSaKeyMaterial *key_mat)
{
    bool ok = true;

    if (ok == true)
    {
        ok =
            data_plane_install_sas(
                    control_param,
                    params,
                    endpoints,
                    key_mat);
    }

    if (ok == true)
    {
        ok =
            data_plane_install_sa_policy(
                    control_param,
                    /* update: */ false,
                    params,
                    endpoints);
    }

    return ok;
}

static bool
data_plane_install_inbound_sa_cb(
        void *control_param,
        const struct IPsecSaParams *sa_params,
        const struct IPsecSaEndpoints *endpoints,
        void **control_sa_p,
        const struct IPsecSaKeyMaterial *key_mat)
{
    DataPlane data_plane = control_param;
    bool ok = true;

    if (ok == true)
    {
        ok =
            data_plane_install_inbound_sa(
                    data_plane,
                    sa_params,
                    endpoints,
                    key_mat);
    }

    if (ok == true)
    {
        ok =
            data_plane_install_sa_policy_inbound(
                    data_plane,
                    /* update: */ false,
                    sa_params,
                    endpoints);
    }

    if (ok == true && endpoints->natt_keepalive == true)
    {
        ipsec_keepalive_start(
                data_plane->ipsec_keepalive,
                &endpoints->local_address,
                endpoints->local_port,
                &endpoints->remote_address,
                endpoints->remote_port,
                sa_params->natt_keepalive_timeout);
    }

    return ok;
}


static bool
data_plane_install_outbound_sa_cb(
        void *control_param,
        const struct IPsecSaParams *sa_params,
        const struct IPsecSaEndpoints *endpoints,
        void *control_sa_p,
        const struct IPsecSaKeyMaterial *key_mat)
{
    DataPlane data_plane = control_param;
    bool ok = true;

    if (ok == true)
    {
        ok =
            data_plane_install_outbound_sa(
                    data_plane,
                    sa_params,
                    endpoints,
                    key_mat);
    }

    if (ok == true)
    {
        ok =
            data_plane_install_sa_policy_outbound(
                    data_plane,
                    /* update: */ false,
                    sa_params,
                    endpoints);
    }

    return ok;
}

static void
data_plane_remove_sa(
        struct NetlinkXfrm *netlink_xfrm,
        const struct InAddr *dst,
        uint8_t proto,
        uint32_t spi)
{
    struct NetlinkRequest *request;
    bool ok = true;

    request = netlink_xfrm_request_alloc(netlink_xfrm);
    if (request == NULL)
    {
        ok = false;
    }

    if (ok == true)
    {
        netlink_xfrm_delsa_init(request);

        netlink_xfrm_delsa_encode_id(request, dst, proto, spi);

        ok = netlink_xfrm_request_send(&request);
    }

    if (ok == false)
    {
        SSH_DEBUG(SSH_D_FAIL, ("SA removal failed."));
    }
}

static void
data_plane_remove_sas(
        DataPlane data_plane,
        const struct IPsecSaParams *params,
        const struct IPsecSaEndpoints *endpoints)
{
    struct NetlinkXfrm *netlink_xfrm = data_plane->netlink_xfrm;

    /* Outbound */
    data_plane_remove_sa(
            netlink_xfrm,
            &endpoints->remote_address,
            params->ipproto,
            params->outbound_spi);

    /* Inbound */
    data_plane_remove_sa(
            netlink_xfrm,
            &endpoints->local_address,
            params->ipproto,
            params->inbound_spi);

    if (endpoints->natt_keepalive == true)
    {
        ipsec_keepalive_stop(
            data_plane->ipsec_keepalive,
            &endpoints->local_address,
            endpoints->local_port,
            &endpoints->remote_address,
            endpoints->remote_port);
    }
}

static void
data_plane_update_outbound_sa(
        DataPlane data_plane,
        const struct IPsecSaParams *params,
        const struct IPsecSaEndpoints *old_endpoints,
        const struct IPsecSaEndpoints *new_endpoints)
{
    struct NetlinkXfrm *netlink_xfrm = data_plane->netlink_xfrm;
    struct NetlinkRequest *request;
    bool ok;

    /* Get the SA information from the existing SA. */
    ok =
        netlink_xfrm_getsa(
                netlink_xfrm,
                &old_endpoints->remote_address,
                params->ipproto,
                params->outbound_spi,
                &request);

    if (ok == true)
    {
        /* Delete the old SA */
        data_plane_remove_sa(
                netlink_xfrm,
                &old_endpoints->remote_address,
                params->ipproto,
                params->outbound_spi);

        /* Add the new SA */
        netlink_xfrm_newsa_init_from_getsa(request);

        if (new_endpoints->natt == true)
        {
            int local_port;
            int remote_port;

            local_port = new_endpoints->local_port;
            remote_port = new_endpoints->remote_port;

            netlink_xfrm_set_natt(request, local_port, remote_port);
        }

        /* change the addresses */
        netlink_xfrm_newsa_encode_addresses(
                request,
                &new_endpoints->local_address,
                &new_endpoints->remote_address);

        netlink_xfrm_request_send(&request);
    }
    else
    {
        SSH_DEBUG(
                SSH_D_FAIL,
                ("Cannot get SA infromation from existing outbound SA."));
    }
}


static void
data_plane_update_inbound_sa(
        DataPlane data_plane,
        const struct IPsecSaParams *params,
        const struct IPsecSaEndpoints *old_endpoints,
        const struct IPsecSaEndpoints *new_endpoints)
{
    struct NetlinkXfrm *netlink_xfrm = data_plane->netlink_xfrm;
    struct NetlinkRequest *request;
    bool ok;

    /* Get the SA information from the existing SA. */
    ok =
        netlink_xfrm_getsa(
                netlink_xfrm,
                &old_endpoints->local_address,
                params->ipproto,
                params->inbound_spi,
                &request);

    if (ok == true)
    {
        /* Delete the old SA */
        data_plane_remove_sa(
                netlink_xfrm,
                &old_endpoints->local_address,
                params->ipproto,
                params->inbound_spi);

        if (old_endpoints->natt_keepalive == true)
        {
            ipsec_keepalive_stop(
                    data_plane->ipsec_keepalive,
                    &old_endpoints->local_address,
                    old_endpoints->local_port,
                    &old_endpoints->remote_address,
                    old_endpoints->remote_port);
        }

        /* Add a new SA */
        netlink_xfrm_newsa_init_from_getsa(request);

        if (new_endpoints->natt == true)
        {
            int local_port;
            int remote_port;

            local_port = new_endpoints->local_port;
            remote_port = new_endpoints->remote_port;

            netlink_xfrm_set_natt(request, local_port, remote_port);
        }

        /* change the addresses */
        netlink_xfrm_newsa_encode_addresses(
                request,
                &new_endpoints->remote_address,
                &new_endpoints->local_address);

        netlink_xfrm_request_send(&request);

        if (new_endpoints->natt_keepalive == true)
        {
            ipsec_keepalive_start(
                    data_plane->ipsec_keepalive,
                    &new_endpoints->local_address,
                    new_endpoints->local_port,
                    &new_endpoints->remote_address,
                    new_endpoints->remote_port,
                    params->natt_keepalive_timeout);
        }
    }
    else
    {
        SSH_DEBUG(
                SSH_D_FAIL,
                ("Cannot get SA infromation from existing inbound SA."));
    }
}

static bool
data_plane_delete_sa_outbound_policy_entry_cb(
        DataPlane data_plane,
        const struct SelectorEnd *src,
        const struct SelectorEnd *dst,
        int protocol,
        const void *context)
{
    const struct IPsecSaParams *sa_params = context;
    struct PolicyParams policy_params = { 0 };
    bool ok;

    data_plane_policy_params_sa_init_out(
            &policy_params,
            src,
            dst,
            protocol,
            sa_params);

    ok =
        data_plane_delete_policy(
                data_plane,
                &policy_params);

    return ok;
}

static void
data_plane_delete_sa_policy_outbound(
        DataPlane data_plane,
        const struct IPsecSaParams *sa_params)
{
    data_plane_parse_selector(
            data_plane,
            sa_params->selector_group,
            data_plane_delete_sa_outbound_policy_entry_cb,
            sa_params);
}

static bool
data_plane_delete_sa_inbound_policy_entry_cb(
        DataPlane data_plane,
        const struct SelectorEnd *src,
        const struct SelectorEnd *dst,
        int protocol,
        const void *context)
{
    const struct IPsecSaParams *sa_params = context;
    struct PolicyParams policy_params = { 0 };

    data_plane_policy_params_sa_init_in(
            &policy_params,
            src,
            dst,
            protocol,
            sa_params);

    data_plane_delete_policy(
            data_plane,
            &policy_params);

    if (sa_params->tunnel_mode == true)
    {
        data_plane_policy_params_sa_set_fwd(
                &policy_params);

        data_plane_delete_policy(
                data_plane,
                &policy_params);
    }

    return true;
}

static void
data_plane_delete_sa_policy_inbound(
        DataPlane data_plane,
        const struct IPsecSaParams *sa_params)
{
    data_plane_parse_selector(
            data_plane,
            sa_params->selector_group,
            data_plane_delete_sa_inbound_policy_entry_cb,
            sa_params);
}

static bool
data_plane_update_sa_cb(
        void *control_param,
        const struct IPsecSaParams *params,
        const struct IPsecSaEndpoints *old_endpoints,
        const struct IPsecSaEndpoints *new_endpoints,
        void *control_sa)
{

    data_plane_install_sa_policy(
            control_param,
            true, /* update */
            params,
            new_endpoints);

    data_plane_update_outbound_sa(
            control_param,
            params,
            old_endpoints,
            new_endpoints);
    data_plane_update_inbound_sa(
            control_param,
            params,
            old_endpoints,
            new_endpoints);

    return true;
}




static void
data_plane_remove_sa_cb(
        void *control_param,
        const struct IPsecSaParams *sa_params,
        const struct IPsecSaEndpoints *endpoints,
        void *control_sa)
{
    DataPlane data_plane = control_param;

    data_plane_remove_sas(
            data_plane,
            sa_params,
            endpoints);

    data_plane_delete_sa_policy_outbound(
            data_plane,
            sa_params);

    data_plane_delete_sa_policy_inbound(
            data_plane,
            sa_params);
}

static void
data_plane_get_field_counts(
        struct IPSelectorParse *parser,
        SelectorFieldCounts *field_counts)
{
    field_counts->src_endpoint =
        ip_selector_parse_field_count(
                parser,
                IP_SELECTOR_SOURCE_ENDPOINT);

    field_counts->dst_endpoint =
        ip_selector_parse_field_count(
                parser,
                IP_SELECTOR_DESTINATION_ENDPOINT);

    field_counts->src_address =
        ip_selector_parse_field_count(
                parser,
                IP_SELECTOR_SOURCE_ADDRESS);

    field_counts->dst_address =
        ip_selector_parse_field_count(
                parser,
                IP_SELECTOR_DESTINATION_ADDRESS);

    field_counts->src_port =
        ip_selector_parse_field_count(
                parser,
                IP_SELECTOR_SOURCE_PORT);

    field_counts->dst_port =
        ip_selector_parse_field_count(
                parser,
                IP_SELECTOR_DESTINATION_PORT);
}

static bool
data_plane_parse_address(
        struct IPSelectorParse *parser,
        bool source,
        struct SelectorEnd *se)
{
    struct InAddr address_begin;
    struct InAddr address_end;
    bool ok;
    int selector_field = IP_SELECTOR_SOURCE_ADDRESS;

    if (source == false)
    {
        selector_field = IP_SELECTOR_DESTINATION_ADDRESS;
    }

    ok =
        ip_selector_parse_next_address(
                parser,
                selector_field,
                &address_begin,
                &address_end);

    if (ok == true)
    {
        data_plane_addr_range_to_subnet(
                &se->address,
                &se->address_mask,
                &address_begin,
                &address_end);
    }

    return ok;
}

static bool
data_plane_parse_port(
        struct IPSelectorParse *parser,
        bool source,
        struct SelectorEnd *se)
{
    int port_begin;
    int port_end;
    bool ok;
    int selector_field = IP_SELECTOR_SOURCE_PORT;

    if (source == false)
    {
        selector_field = IP_SELECTOR_DESTINATION_PORT;
    }

    ok =
        ip_selector_parse_next_port(
                parser,
                selector_field,
                &port_begin,
                &port_end);

    if (ok == true)
    {
        data_plane_port_range_to_mask(
                &se->port,
                &se->port_mask,
                port_begin,
                port_end);
    }

    return ok;
}

static bool
data_plane_parse_icmp(
        struct IPSelectorParse *parser,
        struct SelectorEnd *src,
        struct SelectorEnd *dst)
{
    int port_begin;
    int port_end;
    bool ok;

    ok =
        ip_selector_parse_next_port(
                parser,
                IP_SELECTOR_DESTINATION_PORT,
                &port_begin,
                &port_end);

    if (ok == true)
    {
        if (port_begin == IP_SELECTOR_PORT_MIN &&
            port_end == IP_SELECTOR_PORT_MAX)
        {
            src->port = 0;
            src->port_mask = 0;
            dst->port = 0;
            dst->port_mask = 0;
        }
        else
        {
            src->port = 0xff & (port_begin >> 8);

            if (src->port == 0)
            {
                dst->port = 0;
            }
            else
            {
                dst->port = port_begin & 0xff;
            }

            src->port_mask = 0xffff;
            dst->port_mask = 0;
        }
    }

    return ok;
}

static void
data_plane_clear_selector_end(
        struct SelectorEnd *se,
        int version)
{
    memset(se, 0, sizeof(struct SelectorEnd));

    if (version == 4)
    {
        se->address.addr[10] = 0xff;
        se->address.addr[11] = 0xff;
    }
}

static bool
data_plane_parse_endpoints(
        DataPlane data_plane,
        struct IPSelectorParse *parser,
        SelectorFieldCounts *fc,
        int version,
        DataPlanePolicyHandler *policy_handler,
        const void *context)
{
    struct SelectorEnd src;
    struct SelectorEnd dst;
    int protocol;
    int src_protocol = 0;
    int dst_protocol = 0;
    bool ok = false;
    bool exit = false;
    int src_count;
    int dst_count;
    int i;
    int j;
    int installed_rules = 0;

    /* Iterate for at least one round. */
    src_count = fc->src_endpoint > 0 ? fc->src_endpoint : 1;
    dst_count = fc->dst_endpoint > 0 ? fc->dst_endpoint : 1;

    data_plane_clear_selector_end(
            &src,
            version);
    data_plane_clear_selector_end(
            &dst,
            version);

    for (i = 0; i < src_count && exit == false; ++i)
    {
        if (fc->src_endpoint > 0)
        {
            data_plane_netlink_get_selector_values(
                    parser,
                    true, /* source: */
                    &src.address,
                    &src.address_mask,
                    &src.port,
                    &src.port_mask,
                    &src_protocol);
        }

        for (j = 0; j < dst_count && exit == false; ++j)
        {
            if (fc->dst_endpoint > 0)
            {
                data_plane_netlink_get_selector_values(
                        parser,
                        false, /* source: */
                        &dst.address,
                        &dst.address_mask,
                        &dst.port,
                        &dst.port_mask,
                        &dst_protocol);
            }

            /* Only add rules with compatible protocol selectors. */
            if (src_protocol == dst_protocol ||
                dst_protocol == 0)
            {
                protocol = src_protocol;
            }
            else if (src_protocol == 0)
            {
                protocol = dst_protocol;
            }
            else
            {
                continue;
            }

            ok =
                (*policy_handler)(
                        data_plane,
                        &src,
                        &dst,
                        protocol,
                        context);

            ++installed_rules;
            if (installed_rules >= DATAPLANE_SELECTOR_POLICY_LIMIT)
            {
                exit = true;
            }
        }

        /* Reset destination endpoint counter to enable looping */
        ip_selector_parse_field_reset(
                parser,
                IP_SELECTOR_DESTINATION_ENDPOINT);

    }
    return ok;
}

static bool
data_plane_parse_icmp_selectors(
        DataPlane data_plane,
        struct IPSelectorParse *parser,
        SelectorFieldCounts *field_counts,
        int protocol,
        int version,
        DataPlanePolicyHandler *policy_handler,
        const void *context)
{
    struct SelectorEnd src;
    struct SelectorEnd dst;
    int i;
    bool ok;

    data_plane_clear_selector_end(
            &src,
            version);
    data_plane_clear_selector_end(
            &dst,
            version);

    /* Create rules for all icmp type and code combinations. */
    for (i = 0; i < field_counts->dst_port; ++i)
    {
        data_plane_parse_icmp(
                parser,
                &src,
                &dst);

        ok = (*policy_handler)(
                data_plane,
                &src,
                &dst,
                protocol,
                context);
        if (ok == false)
        {
            ssh_log_event(
                    SSH_LOGFACILITY_DAEMON,
                    SSH_LOG_ERROR,
                    "Creating ICMP rule failed. type %d proto %d",
                    src.port,
                    protocol);
        }
    }

    return true;
}

static bool
data_plane_parse_address_and_port(
        DataPlane data_plane,
        struct IPSelectorParse *parser,
        SelectorFieldCounts *field_counts,
        int protocol,
        int version,
        DataPlanePolicyHandler *policy_handler,
        const void *context)
{
    struct SelectorEnd src;
    struct SelectorEnd dst;
    bool ok = false;

    data_plane_clear_selector_end(
            &src,
            version);
    data_plane_clear_selector_end(
            &dst,
            version);

    if (field_counts->src_address == 1)
    {
        data_plane_parse_address(
                parser,
                true, /* source */
                &src);
    }

    if (field_counts->dst_address == 1)
    {
        data_plane_parse_address(
                parser,
                false, /* source */
                &dst);
    }

    /* Create rules for all port combinations. */
    if (field_counts->src_port == 1)
    {
        data_plane_parse_port(
                parser,
                true, /* source */
                &src);
    }

    if (field_counts->dst_port == 1)
    {
        data_plane_parse_port(
                parser,
                false, /* source */
                &dst);
    }

    ok =
        (*policy_handler)(
                data_plane,
                &src,
                &dst,
                protocol,
                context);

    return ok;
}

static bool
data_plane_parse_selector(
        DataPlane data_plane,
        const struct IPSelectorGroup *selector_group,
        DataPlanePolicyHandler *policy_handler,
        const void *context)
{
    struct IPSelectorParse parser;
    SelectorFieldCounts field_counts = { 0 };
    int protocol;
    int version;
    bool is_icmp = false;

    ip_selector_parse_init(&parser, selector_group);

    while (ip_selector_parse_next_selector(
                    &parser,
                    &version,
                    &protocol) == true)
    {
        data_plane_get_field_counts(&parser, &field_counts);

        if (protocol == SSH_IPPROTO_ICMP ||
            protocol == SSH_IPPROTO_IPV6ICMP)
        {
            is_icmp = true;
        }

        /* Not prepared for more than one address selector.
           Endpoints and addresses not allowed at the same time. */
        if (field_counts.src_address > 1 ||
            field_counts.dst_address > 1 ||
            ((field_counts.src_endpoint > 0 ||
              field_counts.dst_endpoint > 0) &&
             (field_counts.src_address == 1 ||
              field_counts.dst_address == 1)))
        {
            SSH_DEBUG(SSH_D_FAIL,("Unsupported policy"));
            SSH_DEBUG(SSH_D_FAIL,(
                    "Source Endpoints: %d "
                    "Destination Endpoints: %d "
                    "Source Addresses: %d "
                    "Destination Addresses: %d "
                    "Source Ports: %d "
                    "Destination Ports: %d",
                    field_counts.src_endpoint,
                    field_counts.dst_endpoint,
                    field_counts.src_address,
                    field_counts.dst_address,
                    field_counts.src_port,
                    field_counts.dst_port));
            continue;
        }

        /* Match endpoint selectors */
        if (field_counts.src_endpoint > 0 ||
            field_counts.dst_endpoint > 0)
        {
            data_plane_parse_endpoints(
                    data_plane,
                    &parser,
                    &field_counts,
                    version,
                    policy_handler,
                    context);
        }
        /* Match base policy ICMP rules */
        else if (field_counts.src_port == 0 &&
                 field_counts.dst_port > 0 &&
                 is_icmp)
        {
            data_plane_parse_icmp_selectors(
                    data_plane,
                    &parser,
                    &field_counts,
                    protocol,
                    version,
                    policy_handler,
                    context);
        }
        else
        {
            data_plane_parse_address_and_port(
                    data_plane,
                    &parser,
                    &field_counts,
                    protocol,
                    version,
                    policy_handler,
                    context);
        }

    }


    return true;
}

bool
data_plane_install_policy_entry_cb(
        DataPlane data_plane,
        const struct SelectorEnd *src,
        const struct SelectorEnd *dst,
        int protocol,
        const void *context)
{
    const struct IPsecPolicyParams *params = context;
    struct PolicyParams policy_params = { 0 };
    bool ok = false;
    int action;

    policy_params.policy_id = params->policy_id;
    policy_params.priority = params->priority;
    policy_params.protocol = protocol;

    memcpy(&policy_params.src_sel, src, sizeof(*src));
    memcpy(&policy_params.dst_sel, dst, sizeof(*dst));

    if (params->action == IPSEC_POLICY_DISCARD)
    {
        action = NETLINK_XFRM_POLICY_BLOCK;
    }
    else
    {
        action = NETLINK_XFRM_POLICY_ALLOW;
    }


    if (params->role == IPSEC_POLICY_I)
    {
        policy_params.direction = NETLINK_XFRM_DIRECTION_IN;
        ok =
            data_plane_install_policy(
                    data_plane,
                    /* update: */ false,
                    &policy_params,
                    action);
    }
    else if (params->role == IPSEC_POLICY_O)
    {
        policy_params.direction = NETLINK_XFRM_DIRECTION_OUT;

        ok =
            data_plane_install_policy(
                    data_plane,
                    /* update: */ false,
                    &policy_params,
                    action);
    }

    return ok;
}

static bool
data_plane_install_policy_cb(
        void *control_param,
        const struct IPsecPolicyParams *params,
        void **control_policy_p)
{
    DataPlane data_plane = control_param;
    bool ok;

    ok =
        data_plane_parse_selector(
                data_plane,
                params->selector_group,
                data_plane_install_policy_entry_cb,
                (const void*)params);

    return ok;
}


bool
data_plane_delete_policy_entry_cb(
        DataPlane data_plane,
        const struct SelectorEnd *src,
        const struct SelectorEnd *dst,
        int protocol,
        const void *context)
{
    const struct IPsecPolicyParams *params = context;
    struct PolicyParams policy_params;

    policy_params.priority = params->priority;
    policy_params.src_sel = *src;
    policy_params.dst_sel = *dst;
    policy_params.protocol = protocol;
    policy_params.policy_id = params->policy_id;

    if (params->role == IPSEC_POLICY_I)
    {
        policy_params.direction = NETLINK_XFRM_DIRECTION_IN;
    }
    else if (params->role == IPSEC_POLICY_O)
    {
        policy_params.direction = NETLINK_XFRM_DIRECTION_OUT;
    }
    else
    {
        policy_params.direction = NETLINK_XFRM_DIRECTION_FWD;
    }

    data_plane_delete_policy(
            data_plane,
            &policy_params);

    return true;
}

static void
data_plane_delete_policy_cb(
        void *control_p,
        const struct IPsecPolicyParams *params,
        void **control_policy_p)
{
    DataPlane data_plane = control_p;

    data_plane_parse_selector(
            data_plane,
            params->selector_group,
            data_plane_delete_policy_entry_cb,
            (const void*)params);
}

static const struct IPsecControlCallbacks callbacks =
{
    data_plane_install_sa_cb,
    data_plane_install_inbound_sa_cb,
    data_plane_install_outbound_sa_cb,
    data_plane_update_sa_cb,
    data_plane_remove_sa_cb,
    data_plane_install_policy_cb,
    NULL_FNPTR,
    data_plane_delete_policy_cb
};

static void
data_plane_event_cb(
        void *context_p,
        uint32_t event_id,
        uint32_t spi,
        bool overflow,
        bool first_packet,
        bool rekey,
        bool idle_timeout)
{
    DataPlane data_plane = context_p;

    SSH_DEBUG(
            SSH_D_LOWOK,
            ("Event received with id %u"
             "%s%s%s%s",
             event_id,
             overflow == true ? ", overflow " : "",
             first_packet == true ? ", first packet " : "",
             rekey == true ? ", rekey " : "",
             idle_timeout == true ? ", idle timeout" : ""));

    ipsec_control_sa_event(
            data_plane->ipsec_control,
            event_id,
            spi,
            overflow,
            first_packet,
            rekey,
            idle_timeout);
}

static int
data_plane_udp_sendmsg(
        int sock,
        struct sockaddr_in6 addr,
        int tos,
        int ttl,
        struct iovec *iovec,
        int iovec_len)
{
    struct msghdr hdr;
    ssize_t len = -1;

    memset(&hdr, 0, sizeof(hdr));
    hdr.msg_name = &addr;
    hdr.msg_namelen = sizeof(addr);
    hdr.msg_iov = iovec;
    hdr.msg_iovlen = iovec_len;

    len = sendmsg(sock, &hdr, 0);
    if (len < 0)
    {
        SSH_DEBUG(
                SSH_D_FAIL,
                ("sendmsg() failed: %s (%d)",
                 strerror(errno), errno));
    }

    return (int) len;
}

static bool
data_plane_keepalive_send_cb(
        void *control_param,
        const struct InAddr *local_ip,
        uint16_t local_port,
        const struct InAddr *remote_ip,
        uint16_t remote_port)
{
    DataPlane data_plane = (DataPlane) control_param;
    struct iovec iov;
    char msg;
    int len;
    bool ok;

    ok = data_plane_create_udp_socket(data_plane);

    if (ok == true)
    {
        struct sockaddr_in6 local_addr;
        struct sockaddr_in6 remote_addr;

        int rc;

        memset(&local_addr, 0, sizeof(struct sockaddr_in6));
        memset(&remote_addr, 0, sizeof(struct sockaddr_in6));
        local_addr.sin6_family = AF_INET6;
        local_addr.sin6_port = htons(local_port);
        memcpy(
                local_addr.sin6_addr.s6_addr,
                local_ip->addr,
                sizeof(local_ip->addr));

        remote_addr.sin6_family = AF_INET6;
        remote_addr.sin6_port = htons(remote_port);
        memcpy(
                remote_addr.sin6_addr.s6_addr,
                remote_ip->addr,
                sizeof(remote_ip->addr));

        rc =
            bind(
                    data_plane->udp_sock,
                    (struct sockaddr *)&local_addr,
                    sizeof(local_addr));
        if (rc < 0)
        {
            SSH_DEBUG(
                    SSH_D_FAIL,
                    ("bind(%@:%d) failed",
                     ssh_in_addr_render, local_ip,
                     local_port));
            return false;
        }

        rc =
            connect(
                    data_plane->udp_sock,
                    (struct sockaddr *)&remote_addr,
                    sizeof(remote_addr));
        if (rc < 0)
        {
            SSH_DEBUG(
                    SSH_D_FAIL,
                    ("connect(%@:%d) failed",
                     ssh_in_addr_render, remote_ip,
                     remote_port));
            return false;
        }

        /* Generate one 0xff byte and send it. */
        msg = IPSEC_UDP_ENCAP_NATT_KEEPALIVE_DATA;
        iov.iov_base = &msg;
        iov.iov_len = 1;

        len =
            data_plane_udp_sendmsg(
                    data_plane->udp_sock,
                    remote_addr,
                    0,
                    0,
                    &iov,
                    1);

        if (len < 0)
        {
            SSH_DEBUG(
                    SSH_D_NICETOKNOW,
                    ("Failed to send UDP NAT-T keepalive local %@:%d "
                     "remote %@:%d:",
                     ssh_in_addr_render, local_ip,
                     local_port,
                     ssh_in_addr_render, remote_ip,
                     remote_port));
        }
        else
        {
            SSH_DEBUG(
                    SSH_D_MIDOK,
                    ("Sent UDP NAT-T keepalive local %@:%d remote %@:%d ",
                     ssh_in_addr_render, local_ip,
                     local_port,
                     ssh_in_addr_render, remote_ip,
                     remote_port));
        }

         close(data_plane->udp_sock);
    }

    return ok;
}

static bool
data_plane_create_udp_socket(
        DataPlane data_plane)
{
    int sock;
    bool ok = false;

    sock = socket(AF_INET6, SOCK_DGRAM, 0);
    if (sock >= 0)
    {
        int rc;
        int optval = 1;

        ok = true;

        rc =
            setsockopt(
                    sock,
                    SOL_SOCKET,
                    SO_REUSEADDR,
                    &optval,
                    sizeof(optval));
        if (rc < 0)
        {
            SSH_DEBUG(
                    SSH_D_HIGHOK,
                    ("Setting SO_REUSEADDR failed"));
            ok = false;
        }

        if (ok == true)
        {
            rc =
                setsockopt(
                        sock,
                        SOL_SOCKET,
                        SO_NO_CHECK,
                        &optval,
                        sizeof(optval));
            if (rc < 0)
            {
                SSH_DEBUG(
                        SSH_D_HIGHOK,
                        ("Setting SO_NO_CHECK failed"));
                ok = false;
            }
        }

        if (ok == true)
        {
            data_plane->udp_sock = sock;
        }
        else
        {
            close(sock);
        }
    }

    return ok;
}

DataPlane
data_plane_init(
        DataPlaneParams dp_params)
{
    bool success = true;
    DataPlane data_plane = NULL;

    if (success == true)
    {
        data_plane = ssh_calloc(sizeof *data_plane, 1);
        if (data_plane == NULL)
        {
            success = false;
        }
    }

    if (success == true)
    {
        data_plane->replay_window = DATAPLANE_ANTIREPLAY_WINDOW_SIZE;
    }

    if (success == true)
    {
        struct NetlinkXfrmParams netlink_xfrm_params = { 0 };

        netlink_xfrm_params.event_cb = data_plane_event_cb;
        netlink_xfrm_params.event_context = data_plane;

        success =
            netlink_xfrm_init(
                    &netlink_xfrm_params,
                    &data_plane->netlink_xfrm);
    }

    if (success == true)
    {
        success = data_plane_policy_db_init(data_plane);
    }

    if (success == true)
    {
        success =
            ipsec_keepalive_init(
                    &data_plane->ipsec_keepalive,
                    data_plane_keepalive_send_cb,
                    data_plane);
    }

    if (success == false)
    {
        data_plane_uninit(data_plane);
        data_plane = NULL;
    }

    return data_plane;
}

void
data_plane_uninit(
        DataPlane data_plane)
{
    if (data_plane != NULL)
    {
        netlink_xfrm_uninit(&data_plane->netlink_xfrm);

        data_plane_policy_db_uninit(data_plane);

        ipsec_keepalive_uninit(&data_plane->ipsec_keepalive);

        ssh_free(data_plane);

        data_plane = NULL;
    }
}

bool
data_plane_set_ipsec_control_handle(
        DataPlane data_plane,
        struct IPsecControl *ipsec_control)
{
    ipsec_control_register_context_callbacks(
            ipsec_control,
            &callbacks,
            data_plane);

    data_plane->ipsec_control = ipsec_control;

    return true;
}

void
data_plane_remove_ipsec_control_handle(
        DataPlane data_plane)
{
    if (data_plane != NULL)
    {
        ipsec_control_unregister_context_callbacks(
                data_plane->ipsec_control,
                &callbacks,
                data_plane);
    }
}
