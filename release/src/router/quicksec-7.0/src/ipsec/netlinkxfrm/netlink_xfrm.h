/**
   @copyright
   Copyright (c) 2015 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   Interface for netlink xfrm socket.
*/

#ifndef NETLINK_XFRM_H
#define NETLINK_XFRM_H

#include "public_defs.h"
#include "idtransformer.h"

#include "in_addr.h"

/* Anti-replay window limits */
#define XFRM_MIN_ANTIREPLAY_WINDOW_SIZE 32
#define XFRM_MAX_ANTIREPLAY_WINDOW_SIZE 4096

/**
   Netlink XFRM context.
 */
struct NetlinkXfrm;

struct NetlinkRequest;

/**
    Event callback function type. Called when kernel sends a XFRM_MSG_EXPIRE
    message.

    @param context_p
    The event_context given in  NetlinkXfrmParams.

    @param event_id
    Event ID. (same as request ID now)

    @param spi
    SPI

    @param overflow
    True if this is a sequence overflow event.

    @param  first_packet
    True if this is a first packet event.

    @param rekey
    True if this is a rekey event.

    @param idle_timeout
    True if this an idle tiemout event.
 */
typedef void
NetlinkXfrmEventCb(
        void *context_p,
        uint32_t event_id,
        uint32_t spi,
        bool overflow,
        bool first_packet,
        bool rekey,
        bool idle_timeout);

/* Configuration parameters to Netlink XFRM. */
struct NetlinkXfrmParams
{
    NetlinkXfrmEventCb *event_cb;
    void *event_context;
};

/**
    Allocates and initializes the NetlinkXfrm struct.

    @param params
    Configuration parameters.

    @param netlink_xfrm_p
    On return this is holds the pointer to the new NetlinkXfrm struct, or NULL
    in case of failure.

    @return
    True on success.
 */
bool
netlink_xfrm_init(
        struct NetlinkXfrmParams *params,
        struct NetlinkXfrm **netlink_xfrm_p);

/**
    Unintializes and frees the NetlinkXfrm object.

    @param netlink_xfrm_p
    Double pointer to NetlinkXfrm struct. Poiner will be set to NULL.
 */
void
netlink_xfrm_uninit(
        struct NetlinkXfrm **netlink_xfrm_p);


/**
    Allocates a new NetlinkRequest.

    @param netlink_xfrm
    The NetlinkXfrm that the request will use.

    @return
    The newly allocated NetlinkRequest or NULL in case of failure.
 */
struct NetlinkRequest*
netlink_xfrm_request_alloc(
        struct NetlinkXfrm *netlink_xfrm);

/**
    Sends the request to kernel. It is not waiting for a response from
    kernel. After sending the request is freed and pointer set to NULL
    regardless of success or failure.


    @param request_p
    Request to be sent.

    @return
    True if request was sent successfuly, false on failure.
 */
bool
netlink_xfrm_request_send(
        struct NetlinkRequest **request_p);

/**
    Frees the request and sets the pointer to NULL;

    @param request_p
    Request to be freed.
 */
void
netlink_xfrm_request_free(
        struct NetlinkRequest **request_p);

/**
    Initiates the request for sending a new SA message (XFRM_MSG_NEWSA).
    This must be called before any other new SA related functions.

    @param request
    NetlinkRequest pointer.
 */
void
netlink_xfrm_newsa_init(
        struct NetlinkRequest *request);

/**
    Encodes the xfrm_usersa_info part of the NEWSA message except the IP
    addresses. This must be called before other netlink_xfrm_newsa_encode*
    functions.

    @param request
    Request to be encoded.

    @param protocol
    IANA IP protocol identifier, either ESP or AH.

    @param spi
    Security Parameter Index

    @param request_id
    Request ID, must be the same for the SA and corresponding policy.

    @param tunnel_mode
    True for tunnel mode, false for trasnport mode.

    @param esn
    True to enable extended sequence number.

    @param life_bytes
    SA's life byte limit. Infinite if 0.

    @param life_bytes_rekey
    SA's life byte limit before rekey.

    @param is_outbound
    True for outbound SA's, false for inbound.
 */
void
netlink_xfrm_newsa_encode_sa_info(
        struct NetlinkRequest *request,
        uint8_t protocol,
        uint32_t spi,
        uint32_t request_id,
        bool tunnel_mode,
        bool esn,
        uint64_t life_bytes,
        uint64_t life_bytes_rekey,
        bool is_outbound);

/**
    Encodes source and destination IP addresses

    @param request
    Request to be encoded.

    @param src
    Source IP.

    @param dst
    Destination IP.
 */
void
netlink_xfrm_newsa_encode_addresses(
        struct NetlinkRequest *request,
        const struct InAddr *src,
        const struct InAddr *dst);


/**
    Encodes the anti-replay window and ESN (extened sequence numbers) state.

    @param request
    Request to be encoded.

    @param replay_window
    Ani-replay window size in bytes

    @param esn
    If true, ESN will be enabled (sets the XFRM_STATE_ESN flag).
 */
void
netlink_xfrm_newsa_encode_replay_window_esn(
        struct NetlinkRequest *request,
        uint32_t replay_window,
        uint32_t seq_high,
        uint32_t seq_low,
        bool outbound,
        bool esn);

/**
    Adds and encodes an algorithm to the NEWSA request. This must be called
    after netlink_xfrm_newsa_encode_sa_info() and
    netlink_xfrm_newsa_encode_addresses have been called.

    @param request
    Request to add the algorithm to.

    @param alg_id
    The algoritm's TransformId

    @param alg_key_len
    Algorithm key length in bytes

    @param alg_key
    Algorithm key.

    @return
    0 on success.
 */
int
netlink_xfrm_newsa_encode_algorithm(
        struct NetlinkRequest *request,
        TransformId alg_id,
        unsigned int alg_key_len,
        const unsigned char *alg_key);

/**
    Initiates the request for sending a delete SA message (XFRM_MSG_DELSA).
    This must be called before any other SA deletion related functions.

    @param request
    NetlinkRequest pointer.
 */
void
netlink_xfrm_delsa_init(
        struct NetlinkRequest *request);

/**
    Encodes the xfrm_usersa_id struct of the DELSA request.

    @param request
    Request to be encoded.

    @param dst
    IP of the SA's destination.

    @param proto
    IANA protocol number for either ESP or AH.

    @proto spi
    SA's SPI.
 */
void
netlink_xfrm_delsa_encode_id(
        struct NetlinkRequest *request,
        const struct InAddr *dst,
        uint8_t proto,
        uint32_t spi);


enum
{
    NETLINK_XFRM_DIRECTION_IN = 0,
    NETLINK_XFRM_DIRECTION_OUT,
    NETLINK_XFRM_DIRECTION_FWD
};

enum
{
    NETLINK_XFRM_POLICY_ALLOW = 0,
    NETLINK_XFRM_POLICY_BLOCK
};

/**
    Initiates the request for sending a new policy message
    (XFRM_MSG_NEWPOLICY).
    This must be called before any other new policy related functions.

    @param request
    NetlinkRequest pointer.

    @param update
    If true the message type will be XFRM_MSG_UPDPOLICY and a policy will be
    updated.

    @param direction
    Traffic direction: in, out or forward. Use NETLINK_XFRM_DIRECTION_*

    @param action
    Unused. Only allow action is supported now.

    @param priority
    Priority of the policy. 0 is highest.
 */

void
netlink_xfrm_newpolicy_init(
        struct NetlinkRequest* request,
        bool update,
        uint8_t direction,
        uint8_t action,
        uint32_t priority);

/**
    Add NAT-T parameters to request. It uses an XFRMA_ENCAP attribute.

    @param request
    NetlinkRequest pointer.

    @param local_port
    Local (source) port.

    @param remote_port
    Remote (destination) port.
 */
void
netlink_xfrm_set_natt(
        struct NetlinkRequest* request,
        int local_port,
        int remote_port);

/**
    Adds and encodes a template (XFRMA_TMPL) for matching traffic to a
    NEWPOLICY request.

    @param request
    NetlinkRequest pointer.

    @param src
    Source IP.

    @param dst
    Destination IP.

    @param proto
    IANA IP protocol identifier, either ESP or AH.

    @param tunnel_mode
    True for tunnel mode, false for trasnport mode.

    @param request_id
    Request ID, must be the same for the SA and corresponding policy.
 */
void
netlink_xfrm_newpolicy_encode_tmpl(
        struct NetlinkRequest *request,
        const struct InAddr *src,
        const struct InAddr *dst,
        uint8_t proto,
        bool tunnel_mode,
        uint32_t request_id);

/**
    Initiates the request for sending a delete policy message
    (XFRM_MSG_DELPOLICY).
    This must be called before any other policy deletion related functions.

    @param request
    NetlinkRequest pointer.

    @param direction
    Traffic direction: in, out or forward. Use NETLINK_XFRM_DIRECTION_*
 */
void
netlink_xfrm_delpolicy_init(
        struct NetlinkRequest *request,
        uint8_t direction);

/**
    Adds and encodes traffic selectors to policy (new or delete) requests.

    @param request
    NetlinkRequest pointer.

    @param src
    Source IP.

    @param src_prefix
    Source IP prefix (address mask).

    @param src_port
    Source port.

    @param dst
    Destination IP.

    @param dst_prefix
    Destination IP prefix (address mask).

    @param dst_port
    Destination port.

    @param proto
    IANA protocol number either ESP or AH.
 */
void
netlink_xfrm_encode_selector(
        struct NetlinkRequest *request,
        const struct InAddr *src,
        uint8_t src_prefix,
        uint16_t src_port,
        uint16_t src_port_mask,
        const struct InAddr *dst,
        uint8_t dst_prefix,
        uint16_t dst_port,
        uint16_t dst_port_mask,
        uint8_t proto);

/**
    Encodes the xfrm_usersa_id struct of the GETSA request.

    @param netlink_xfrm
    The NetlinkXfrm that the response_p will use.

    @param dst
    Destination IP.

    @param proto
    IANA protocol number for either ESP or AH.

    @proto spi
    SA's SPI.

    @param response_p
    Request structure where response has been encoded.
 */

bool
netlink_xfrm_getsa(
        struct NetlinkXfrm *netlink_xfrm,
        const struct InAddr *dst,
        uint8_t proto,
        uint32_t spi,
        struct NetlinkRequest **response_p);

void
netlink_xfrm_newsa_init_from_getsa(
        struct NetlinkRequest *request);

#endif /* NETLINK_XFRM_H */
