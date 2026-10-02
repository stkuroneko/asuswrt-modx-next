/**
   @copyright
   Copyright (c) 2015 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   Interface for netlink xfrm socket.
*/

#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/xfrm.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/udp.h>

#include "sshincludes.h"
#include "ssheloop.h"

#include "netlink_xfrm.h"
#include "implementation_defs.h"

#define SSH_DEBUG_MODULE "NetlinkXfrm"

#define NETLINK_XFRM_MESSAGE_SIZE 2048


/** Maximum IPsec SA byte limit. */
#ifndef NETLINK_XFRM_BYTE_LIMIT_MAX
#define NETLINK_XFRM_BYTE_LIMIT_MAX (XFRM_INF - 1)
#endif

/** Percentage of hard packet limit to use as soft packet limit for
    IPsec SA. */
#ifndef NETLINK_XFRM_SOFT_PACKET_LIMIT_PERCENTAGE
#define NETLINK_XFRM_SOFT_PACKET_LIMIT_PERCENTAGE 95
#endif

#define NETLINK_XFRM_ATTR_DATA(hdr)                                     \
    ((struct nlattr *) ((char *) (hdr) + NLMSG_ALIGN((hdr)->nlmsg_len)))

#define NETLINK_XFRM_NLA_DATA(attr)             \
    ((void *) (((char *) (attr)) + NLA_HDRLEN))

#define NETLINK_XFRM_NLA_LENGTH(len) (NLA_HDRLEN + (len))

#define NETLINK_XFRM_NLMSG_CALC_LENGTH(hdr, nla_len) \
    (NLMSG_ALIGN((hdr)->nlmsg_len) + NLA_ALIGN(nla_len));

#define NETLINK_XFRM_NLMSG_DEC_LENGTH(hdr, nla_len) \
    (NLMSG_ALIGN((hdr)->nlmsg_len) - NLA_ALIGN(nla_len));


#define NETLINK_XFRM_ATTR_FIRST(hdr, x) \
    ((struct nlattr *) (NLMSG_DATA(hdr) + NLMSG_ALIGN(x)))

#define NETLINK_XFRM_ATTR_OK(attr, len)           \
    ((len) >= (int) sizeof(struct nlattr) &&      \
     (attr)->nla_len >= sizeof(struct nlattr) &&  \
     (attr)->nla_len <= (len))

#define NETLINK_XFRM_ATTR_NEXT(attr, len)                               \
    ((len) -= NLA_ALIGN((attr)->nla_len),                               \
     (struct nlattr *) (((char *) (attr)) + NLA_ALIGN((attr)->nla_len)))


/* Netlink XRFM context. */
struct NetlinkXfrm
{
    /* Socket descriptor for sending requests. */
    int request_sock;

    /* Socket descriptor for receiving events. */
    int event_sock;

    /* Sequence number for netlink messages. */
    int sequence_number;

    /* Event callback function and context. */
    NetlinkXfrmEventCb *event_cb;
    void *event_context;
};


/* Netlink request. */
struct NetlinkRequest
{
    /* Netlink XRFM context. */
    struct NetlinkXfrm* netlink_xfrm;

    /* Netlink message. */
    char message[NETLINK_XFRM_MESSAGE_SIZE];
};

struct netlink_xfrm_alg_properties
{
    char* name;
    TransformId id;
    int xfrm_type;
    int icv_len;
};

const struct netlink_xfrm_alg_properties netlink_xfrm_alg_mapping[] = {
  /* Encryption algorithms */
  {"ecb(cipher_null)", TRANSFORMID_ENCR_NULL, XFRMA_ALG_CRYPT, 0},

  {"cbc(des3_ede)", TRANSFORMID_ENCR_3DES_CBC, XFRMA_ALG_CRYPT, 0},

  {"cbc(aes)", TRANSFORMID_ENCR_AES_128_CBC, XFRMA_ALG_CRYPT, 0},
  {"cbc(aes)", TRANSFORMID_ENCR_AES_192_CBC, XFRMA_ALG_CRYPT, 0},
  {"cbc(aes)", TRANSFORMID_ENCR_AES_256_CBC, XFRMA_ALG_CRYPT, 0},

  {"rfc3686(ctr(aes))", TRANSFORMID_ENCR_AES_128_CTR, XFRMA_ALG_CRYPT, 0},
  {"rfc3686(ctr(aes))", TRANSFORMID_ENCR_AES_192_CTR, XFRMA_ALG_CRYPT, 0},
  {"rfc3686(ctr(aes))", TRANSFORMID_ENCR_AES_256_CTR, XFRMA_ALG_CRYPT, 0},

  {"rfc4309(ccm(aes))", TRANSFORMID_ENCR_AES_128_CCM_8,  XFRMA_ALG_AEAD, 64},
  {"rfc4309(ccm(aes))", TRANSFORMID_ENCR_AES_128_CCM_12, XFRMA_ALG_AEAD, 96},
  {"rfc4309(ccm(aes))", TRANSFORMID_ENCR_AES_128_CCM_16, XFRMA_ALG_AEAD, 128},

  {"rfc4309(ccm(aes))", TRANSFORMID_ENCR_AES_192_CCM_8,  XFRMA_ALG_AEAD, 64},
  {"rfc4309(ccm(aes))", TRANSFORMID_ENCR_AES_192_CCM_12, XFRMA_ALG_AEAD, 96},
  {"rfc4309(ccm(aes))", TRANSFORMID_ENCR_AES_192_CCM_16, XFRMA_ALG_AEAD, 128},

  {"rfc4309(ccm(aes))", TRANSFORMID_ENCR_AES_256_CCM_8,  XFRMA_ALG_AEAD, 64},
  {"rfc4309(ccm(aes))", TRANSFORMID_ENCR_AES_256_CCM_12, XFRMA_ALG_AEAD, 96},
  {"rfc4309(ccm(aes))", TRANSFORMID_ENCR_AES_256_CCM_16, XFRMA_ALG_AEAD, 128},

  {"rfc4106(gcm(aes))", TRANSFORMID_ENCR_AES_128_GCM_8,  XFRMA_ALG_AEAD, 64},
  {"rfc4106(gcm(aes))", TRANSFORMID_ENCR_AES_128_GCM_12, XFRMA_ALG_AEAD, 96},
  {"rfc4106(gcm(aes))", TRANSFORMID_ENCR_AES_128_GCM_16, XFRMA_ALG_AEAD, 128},


  {"rfc4106(gcm(aes))", TRANSFORMID_ENCR_AES_192_GCM_8,  XFRMA_ALG_AEAD, 64},
  {"rfc4106(gcm(aes))", TRANSFORMID_ENCR_AES_192_GCM_12, XFRMA_ALG_AEAD, 96},
  {"rfc4106(gcm(aes))", TRANSFORMID_ENCR_AES_192_GCM_16, XFRMA_ALG_AEAD, 128},


  {"rfc4106(gcm(aes))", TRANSFORMID_ENCR_AES_256_GCM_8,  XFRMA_ALG_AEAD, 64},
  {"rfc4106(gcm(aes))", TRANSFORMID_ENCR_AES_256_GCM_12, XFRMA_ALG_AEAD, 96},
  {"rfc4106(gcm(aes))", TRANSFORMID_ENCR_AES_256_GCM_16, XFRMA_ALG_AEAD, 128},

  {"rfc4543(gcm(aes))", TRANSFORMID_ENCR_AES_128_GMAC, XFRMA_ALG_AEAD, 128},
  {"rfc4543(gcm(aes))", TRANSFORMID_ENCR_AES_192_GMAC, XFRMA_ALG_AEAD, 128},
  {"rfc4543(gcm(aes))", TRANSFORMID_ENCR_AES_256_GMAC, XFRMA_ALG_AEAD, 128},

  /* Integrity algorithms */
  {"digest_null", TRANSFORMID_INTEG_NONE, XFRMA_ALG_AUTH_TRUNC, 0},

  {"hmac(sha1)", TRANSFORMID_INTEG_HMAC_SHA1_96, XFRMA_ALG_AUTH_TRUNC, 0},

  {"hmac(sha256)", TRANSFORMID_INTEG_HMAC_SHA256_128, XFRMA_ALG_AUTH_TRUNC, 0},
  {"hmac(sha384)", TRANSFORMID_INTEG_HMAC_SHA384_192, XFRMA_ALG_AUTH_TRUNC, 0},
  {"hmac(sha512)", TRANSFORMID_INTEG_HMAC_SHA512_256, XFRMA_ALG_AUTH_TRUNC, 0},

  {"xcbc(aes)", TRANSFORMID_INTEG_AES_XCBC_96, XFRMA_ALG_AUTH_TRUNC, 0},

  /* This must be the last element. */
  {NULL, 0, 0, 0}
};


static const struct netlink_xfrm_alg_properties *
netlink_xfrm_get_alg_properties(
        TransformId alg_id)
{
    int i;

    for (i = 0; netlink_xfrm_alg_mapping[i].name; i++)
    {
        if (netlink_xfrm_alg_mapping[i].id == alg_id)
        {
            return &netlink_xfrm_alg_mapping[i];
        }
    }

    return NULL;
}


static int
netlink_xfrm_receive_message(
        int sock,
        unsigned char *buf,
        size_t buf_len)
{
    struct sockaddr_nl sa;
    struct iovec iov;
    struct msghdr msg;
    int len;

    iov.iov_base = buf;
    iov.iov_len = buf_len;

    msg.msg_name = (struct sockaddr *) &sa;
    msg.msg_namelen = sizeof(sa);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;

    len = recvmsg(sock, &msg, 0);
    if (len <= 0)
    {
        SSH_DEBUG(SSH_D_FAIL, ("recvmsg() failed"));
    }
    else
    {
        SSH_DEBUG(SSH_D_LOWOK, ("Read %d bytes from XFRM", len));
    }

    return len;
}

static void
netlink_xfrm_proto_str(
        uint8_t proto,
        char *buf,
        size_t buf_len)
{
    SSH_ASSERT(buf_len >= 16);

    switch(proto)
    {
    case 1:
        ssh_snprintf(buf, buf_len, "icmp");
        return;
    case 6:
        ssh_snprintf(buf, buf_len, "tcp");
        return;
    case 17:
        ssh_snprintf(buf, buf_len, "udp");
        return;
    case 50:
        ssh_snprintf(buf, buf_len, "esp");
        return;
    case 58:
        ssh_snprintf(buf, buf_len, "ipv6-icmp");
        return;
    default:
        ssh_snprintf(buf, buf_len, "%u", proto);
        return;
    }
}

static const char *
netlink_xfrm_direction_str(
        uint8_t direction)
{
    switch(direction)
    {
    case XFRM_POLICY_IN:
        return "in";
    case XFRM_POLICY_OUT:
        return "out";
    case XFRM_POLICY_FWD:
        return "fwd";
    default:
        return "undefined";
    }
}

static const char *
netlink_xfrm_action_str(
        uint8_t action)
{
    switch(action)
    {
    case NETLINK_XFRM_POLICY_ALLOW:
        return "allow";
    case NETLINK_XFRM_POLICY_BLOCK:
        return "block";
    default:
        return "undefined";
    }
}

static const char *
netlink_xfrm_mode_str(
        uint8_t mode)
{
    switch(mode)
    {
    case XFRM_MODE_TRANSPORT:
        return "transport";
    case XFRM_MODE_TUNNEL:
        return "tunnel";
    case XFRM_MODE_ROUTEOPTIMIZATION:
        return "route_optimization";
    case XFRM_MODE_IN_TRIGGER:
        return "in_trigger";
    case XFRM_MODE_BEET:
        return "beet";
    default:
        return "undefined";
    }
}

static const char *
netlink_xfrm_type_str(
        uint16_t type)
{
    switch(type)
    {
    case XFRM_MSG_NEWSA:
        return "newsa";
    case XFRM_MSG_DELSA:
        return "delsa";
    case XFRM_MSG_GETSA:
        return "getsa";
    case XFRM_MSG_NEWPOLICY:
        return "newpolicy";
    case XFRM_MSG_DELPOLICY:
        return "delpolicy";
    case XFRM_MSG_GETPOLICY:
        return "getpolicy";
    case XFRM_MSG_ALLOCSPI:
        return "allocspi";
    case XFRM_MSG_ACQUIRE:
        return "acquire";
    case XFRM_MSG_EXPIRE:
        return "expire";
    case XFRM_MSG_UPDPOLICY:
        return "udppolicy";
    case XFRM_MSG_UPDSA:
        return "updsa";
    case XFRM_MSG_POLEXPIRE:
        return "polexpire";
    case XFRM_MSG_FLUSHSA:
        return "flushsa";
    case XFRM_MSG_FLUSHPOLICY:
        return "flushpolicy";
    case XFRM_MSG_NEWAE:
        return "newae";
    case XFRM_MSG_GETAE:
        return "getae";
    case XFRM_MSG_REPORT:
        return "report";
    case XFRM_MSG_MIGRATE:
        return "migrate";
    case XFRM_MSG_NEWSADINFO:
        return "newsadinfo";
    case XFRM_MSG_GETSADINFO:
        return "getsadinfo";
    case XFRM_MSG_NEWSPDINFO:
        return "newspdinfo";
    case XFRM_MSG_GETSPDINFO:
        return "getspdinfo";
    case XFRM_MSG_MAPPING:
        return "mapping";
    default:
        return "undefined";
    }
}

void
netlink_xfrm_decode_selector(
        struct xfrm_selector *selector,
        struct InAddr *src,
        uint8_t *src_prefix,
        uint16_t *src_port,
        struct InAddr *dst,
        uint8_t *dst_prefix,
        uint16_t *dst_port,
        uint8_t *proto)
{
    ASSERT(selector != NULL);

    /* Protocol */
    *proto = selector->proto;

    /* Addresses */

    if (selector->family == AF_INET)
    {
        in_addr_import(
                dst,
                &selector->daddr.a4,
                sizeof selector->daddr.a4);
        in_addr_import(
                src,
                &selector->saddr.a4,
                sizeof selector->saddr.a4);
    }
    else        /* IPv6 */
    {
        in_addr_import(
                dst,
                &selector->daddr.a6,
                sizeof selector->daddr.a6);
        in_addr_import(
                src,
                &selector->saddr.a6,
                sizeof selector->saddr.a6);
    }

    *src_prefix = selector->prefixlen_s;
    *dst_prefix = selector->prefixlen_d;

    /* Ports */
    *dst_port = ntohs(selector->dport);
    *src_port = ntohs(selector->sport);
}

static void
netlink_xfrm_decode_tmpl(
        struct xfrm_user_tmpl *user_tmpl,
        struct InAddr *src,
        struct InAddr *dst,
        uint8_t *proto,
        uint8_t *mode,
        uint32_t *request_id)
{
    /* Protocol, mode and request ID */
    *proto = user_tmpl->id.proto;
    *mode = user_tmpl->mode;
    *request_id = user_tmpl->reqid;

    /* Addresses */

    if (user_tmpl->family == AF_INET)
    {
        in_addr_import(
                dst,
                &user_tmpl->id.daddr.a4,
                sizeof user_tmpl->id.daddr.a4);
        in_addr_import(
                src,
                &user_tmpl->saddr.a4,
                sizeof user_tmpl->saddr.a4);
    }
    else        /* IPv6 */
    {
        in_addr_import(
                dst,
                &user_tmpl->id.daddr.a6,
                sizeof user_tmpl->id.daddr.a6);
        in_addr_import(
                src,
                &user_tmpl->saddr.a6,
                sizeof user_tmpl->saddr.a6);
    }
}

static void
netlink_xfrm_log_error_header(
        struct nlmsghdr *hdr)
{
    ssh_log_event(
            SSH_LOGFACILITY_DAEMON,
            SSH_LOG_ERROR,
            "  Header:");

    ssh_log_event(
            SSH_LOGFACILITY_DAEMON,
            SSH_LOG_ERROR,
            "    len %u type %s flags 0x%x seq %u",
            hdr->nlmsg_len,
            netlink_xfrm_type_str(hdr->nlmsg_type),
            hdr->nlmsg_flags,
            hdr->nlmsg_seq);
}


static void
netlink_xfrm_log_selector(
        struct xfrm_selector *selector)
{
    char proto_buf[16];
    struct InAddr src;
    struct InAddr dst;
    uint8_t src_prefix;
    uint8_t dst_prefix;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t proto;

    /* Get information from selector. */
    netlink_xfrm_decode_selector(
            selector,
            &src,
            &src_prefix,
            &src_port,
            &dst,
            &dst_prefix,
            &dst_port,
            &proto);

    netlink_xfrm_proto_str(proto, proto_buf, sizeof proto_buf);

    ssh_log_event(
            SSH_LOGFACILITY_DAEMON,
            SSH_LOG_ERROR,
            "  Policy:");

    ssh_log_event(
            SSH_LOGFACILITY_DAEMON,
            SSH_LOG_ERROR,
            "    src %@/%u dst %@/%u proto %s sport %u dport %u",
            ssh_in_addr_render, &src,
            src_prefix,
            ssh_in_addr_render, &dst,
            dst_prefix,
            proto_buf,
            src_port,
            dst_port);
}

static void
netlink_xfrm_log_lifetime(
        struct xfrm_lifetime_cfg *lifetime_cfg)
    {

        ssh_log_event(
                SSH_LOGFACILITY_DAEMON,
                SSH_LOG_ERROR,
                "  Limits:");

        ssh_log_event(
                SSH_LOGFACILITY_DAEMON,
                SSH_LOG_ERROR,
                "    soft byte limit %llu",
                lifetime_cfg->soft_byte_limit);

        ssh_log_event(
                SSH_LOGFACILITY_DAEMON,
                SSH_LOG_ERROR,
                "    hard byte limit %llu",
                lifetime_cfg->hard_byte_limit);

        ssh_log_event(
                SSH_LOGFACILITY_DAEMON,
                SSH_LOG_ERROR,
                "    soft packet limit %llu",
                lifetime_cfg->soft_packet_limit);

        ssh_log_event(
                SSH_LOGFACILITY_DAEMON,
                SSH_LOG_ERROR,
                "    hard packet limit %llu",
                lifetime_cfg->hard_packet_limit);
    }

static void
netlink_xfrm_process_newsa_error(
        struct nlmsghdr *msg,
        int error)
{
    struct xfrm_usersa_info *usersa_info = NLMSG_DATA(msg);
    size_t payload_size =  NLMSG_PAYLOAD(msg, 0);
    size_t len = sizeof *usersa_info;

    ssh_log_event(
            SSH_LOGFACILITY_DAEMON,
            SSH_LOG_ERROR,
            "XFRM error:");

    ssh_log_event(
            SSH_LOGFACILITY_DAEMON,
            SSH_LOG_ERROR,
            "    SA %s failed, error %d (%s)",
            (msg->nlmsg_type == XFRM_MSG_NEWSA ? "create" : "update"),
            error,
            strerror(-error));

    /* Log header information. */
    netlink_xfrm_log_error_header(msg);

    /* Check that message contains usersa_info structure. */
    if (payload_size < len)
    {
        ssh_log_event(
                SSH_LOGFACILITY_DAEMON,
                SSH_LOG_ERROR,
                "  Message content corrupted");
        return;
    }

    {
        struct xfrm_selector *selector;
        selector = &usersa_info->sel;
        netlink_xfrm_log_selector(selector);
    }

    {
        struct InAddr saddr;

        if (usersa_info->family == AF_INET)
        {
            in_addr_import(&saddr, &usersa_info->saddr.a4, 4);
        }
        else
        {
            in_addr_import(&saddr, &usersa_info->saddr.a6, 16);
        }

        ssh_log_event(
                SSH_LOGFACILITY_DAEMON,
                SSH_LOG_ERROR,
                "    src %@",
                ssh_in_addr_render, &saddr);
    }

    {
        struct xfrm_lifetime_cfg *lifetime_cfg = &usersa_info->lft;
        netlink_xfrm_log_lifetime(lifetime_cfg);
    }
}

static void
netlink_xfrm_log_usersa_id_error(
        struct xfrm_usersa_id *usersa_id)
{

    struct InAddr daddr;

    if (usersa_id->family == AF_INET)
    {
        in_addr_import(&daddr, &usersa_id->daddr.a4, 4);
    }
    else
    {
        in_addr_import(&daddr, &usersa_id->daddr.a6, 16);
    }

    ssh_log_event(
            SSH_LOGFACILITY_DAEMON,
            SSH_LOG_ERROR,
            "  usersa id:");

    ssh_log_event(
            SSH_LOGFACILITY_DAEMON,
            SSH_LOG_ERROR,
            "    dst %@ proto %d",
            ssh_in_addr_render, &daddr,
            usersa_id->proto);

}

static void
netlink_xfrm_process_delsa_error(
        struct nlmsghdr *msg,
        int error)
{
    struct xfrm_usersa_id *usersa_id = NLMSG_DATA(msg);
    size_t payload_size =  NLMSG_PAYLOAD(msg, 0);
    size_t len = sizeof *usersa_id;

    ssh_log_event(
            SSH_LOGFACILITY_DAEMON,
            SSH_LOG_ERROR,
            "XFRM error:");

    ssh_log_event(
            SSH_LOGFACILITY_DAEMON,
            SSH_LOG_ERROR,
            "    SA delete failed, error %d (%s)",
            error,
            strerror(-error));

    /* Log header information. */
    netlink_xfrm_log_error_header(msg);

    /* Check that message contains usersa_id structure. */
    if (payload_size < len)
    {
        ssh_log_event(
                SSH_LOGFACILITY_DAEMON,
                SSH_LOG_ERROR,
                "  Message content corrupted");
        return;
    }

    netlink_xfrm_log_usersa_id_error(usersa_id);

}

static void
netlink_xfrm_process_getsa_error(
        struct nlmsghdr *msg,
        int error)
{
    struct xfrm_usersa_id *usersa_id = NLMSG_DATA(msg);
    size_t payload_size =  NLMSG_PAYLOAD(msg, 0);
    size_t len = sizeof *usersa_id;

    ssh_log_event(
            SSH_LOGFACILITY_DAEMON,
            SSH_LOG_ERROR,
            "XFRM error:");

    ssh_log_event(
            SSH_LOGFACILITY_DAEMON,
            SSH_LOG_ERROR,
            "    Get SA failed, error %d (%s)",
            error,
            strerror(-error));

    /* Log header information. */
    netlink_xfrm_log_error_header(msg);

    /* Check that message contains usersa_id structure. */
    if (payload_size < len)
    {
        ssh_log_event(
                SSH_LOGFACILITY_DAEMON,
                SSH_LOG_ERROR,
                "  Message content corrupted");
        return;
    }

    netlink_xfrm_log_usersa_id_error(usersa_id);
}

static void
netlink_xfrm_process_newpolicy_error(
        struct nlmsghdr *msg,
        int error)
{
    struct xfrm_userpolicy_info *userpolicy_info = NLMSG_DATA(msg);
    size_t payload_size =  NLMSG_PAYLOAD(msg, 0);
    size_t len = sizeof *userpolicy_info;

    ssh_log_event(
            SSH_LOGFACILITY_DAEMON,
            SSH_LOG_ERROR,
            "XFRM error:");

    ssh_log_event(
            SSH_LOGFACILITY_DAEMON,
            SSH_LOG_ERROR,
            "    policy %s failed, error %d (%s)",
            (msg->nlmsg_type == XFRM_MSG_NEWPOLICY ? "create" : "update"),
            error,
            strerror(-error));

    /* Log header information. */
    netlink_xfrm_log_error_header(msg);

    /* Check that message contains userpolicy_info structure. */
    if (payload_size < len)
    {
        ssh_log_event(
                SSH_LOGFACILITY_DAEMON,
                SSH_LOG_ERROR,
                "  Message content corrupted");
        return;
    }

    {
        struct xfrm_selector *selector;
        selector = &userpolicy_info->sel;
        netlink_xfrm_log_selector(selector);
    }

    ssh_log_event(
                SSH_LOGFACILITY_DAEMON,
                SSH_LOG_ERROR,
                "    dir %s action %s priority %d",
                netlink_xfrm_direction_str(userpolicy_info->dir),
                netlink_xfrm_action_str(userpolicy_info->action),
                userpolicy_info->priority);

    {
        struct nlattr *attr;
        size_t size;

        attr = NETLINK_XFRM_ATTR_FIRST(msg, sizeof(*userpolicy_info));
        size = NLMSG_PAYLOAD(msg, sizeof(*userpolicy_info));

        if (NETLINK_XFRM_ATTR_OK(attr, size) && attr->nla_type == XFRMA_TMPL)
        {
            struct xfrm_user_tmpl *user_tmpl = NETLINK_XFRM_NLA_DATA(attr);
            char tmpl_src_buf[100];
            char tmpl_dst_buf[100];
            char tmpl_proto_buf[16];
            struct InAddr tmpl_src;
            struct InAddr tmpl_dst;
            uint8_t tmpl_proto;
            uint8_t mode;
            uint32_t request_id;

            netlink_xfrm_decode_tmpl(
                    user_tmpl,
                    &tmpl_src,
                    &tmpl_dst,
                    &tmpl_proto,
                    &mode,
                    &request_id);

            /* Convert information to strings. */

            in_addr_str(
                    &tmpl_src,
                    tmpl_src_buf,
                    sizeof tmpl_src_buf);

            in_addr_str(
                    &tmpl_dst,
                    tmpl_dst_buf,
                    sizeof tmpl_dst_buf);

            netlink_xfrm_proto_str(
                    tmpl_proto,
                    tmpl_proto_buf,
                    sizeof tmpl_proto_buf);

            ssh_log_event(
                    SSH_LOGFACILITY_DAEMON,
                    SSH_LOG_ERROR,
                    "  Template:");

            ssh_log_event(
                    SSH_LOGFACILITY_DAEMON,
                    SSH_LOG_ERROR,
                    "    src %s dst %s proto %s reqid %u mode %s",
                    tmpl_src_buf,
                    tmpl_dst_buf,
                    tmpl_proto_buf,
                    request_id,
                    netlink_xfrm_mode_str(mode));
        }
    }

    {
        struct xfrm_lifetime_cfg *lifetime_cfg = &userpolicy_info->lft;
        netlink_xfrm_log_lifetime(lifetime_cfg);
    }
}

static void
netlink_xfrm_process_delpolicy_error(
        struct nlmsghdr *msg,
        int error)
{
    struct xfrm_userpolicy_id *userpolicy_id = NLMSG_DATA(msg);
    size_t payload_size =  NLMSG_PAYLOAD(msg, 0);
    size_t len = sizeof *userpolicy_id;

    ssh_log_event(
            SSH_LOGFACILITY_DAEMON,
            SSH_LOG_ERROR,
            "XFRM error:");

    ssh_log_event(
            SSH_LOGFACILITY_DAEMON,
            SSH_LOG_ERROR,
            "    policy delete failed, error %d (%s)",
            error,
            strerror(-error));

    /* Log header information. */
    netlink_xfrm_log_error_header(msg);

    /* Check that message contains userpolicy_id structure. */
    if (payload_size < len)
    {
        ssh_log_event(
                SSH_LOGFACILITY_DAEMON,
                SSH_LOG_ERROR,
                "  Message content corrupted");
        return;
    }

    {
        struct xfrm_selector *selector;
        selector = &userpolicy_id->sel;
        netlink_xfrm_log_selector(selector);
    }

    ssh_log_event(
                SSH_LOGFACILITY_DAEMON,
                SSH_LOG_ERROR,
                "    dir %s",
                netlink_xfrm_direction_str(userpolicy_id->dir));

}

static void
netlink_xfrm_process_flushpolicy_error(
        struct nlmsghdr *msg,
        int error)
{
    ssh_log_event(
            SSH_LOGFACILITY_DAEMON,
            SSH_LOG_ERROR,
            "XFRM error:");

    ssh_log_event(
            SSH_LOGFACILITY_DAEMON,
            SSH_LOG_ERROR,
            "    policy flush failed, error %d (%s)",
            error,
            strerror(-error));

    /* Log header information. */
    netlink_xfrm_log_error_header(msg);
}

static void
netlink_xfrm_process_flushsa_error(
        struct nlmsghdr *msg,
        int error)
{
    struct xfrm_usersa_flush *usersa_flush = NLMSG_DATA(msg);
    size_t payload_size =  NLMSG_PAYLOAD(msg, 0);
    size_t len = sizeof *usersa_flush;

    ssh_log_event(
            SSH_LOGFACILITY_DAEMON,
            SSH_LOG_ERROR,
            "XFRM error:");

    ssh_log_event(
            SSH_LOGFACILITY_DAEMON,
            SSH_LOG_ERROR,
            "    SA flush failed, error %d (%s)",
            error,
            strerror(-error));

    /* Log header information. */
    netlink_xfrm_log_error_header(msg);

    /* Check that message contains usersa_flush structure. */
    if (payload_size < len)
    {
        ssh_log_event(
                SSH_LOGFACILITY_DAEMON,
                SSH_LOG_ERROR,
                "  Message content corrupted");
    }
    else
    {
        char proto_buf[16];

        netlink_xfrm_proto_str(
                usersa_flush->proto,
                proto_buf,
                sizeof proto_buf);

        ssh_log_event(
                SSH_LOGFACILITY_DAEMON,
                SSH_LOG_ERROR,
                "  Content:");

        ssh_log_event(
                SSH_LOGFACILITY_DAEMON,
                SSH_LOG_ERROR,
                "    proto %s",
                proto_buf);
    }
}

static int
netlink_xfrm_process_error(
        struct NetlinkXfrm *netlink_xfrm,
        struct nlmsghdr *hdr)
{
    struct nlmsgerr *errmsg;
    int error = 0;

    errmsg = NLMSG_DATA(hdr);
    error = errmsg->error;

    /* Acknowledgements are sent with error code 0. */
    if (error == 0)
    {
        SSH_DEBUG(
                SSH_D_NICETOKNOW,
                ("Ack from XFRM, sequence number %u",
                 hdr->nlmsg_seq));
    }
    else
    {
        struct nlmsghdr *orig_msg = &errmsg->msg;
        uint16_t msg_type = orig_msg->nlmsg_type;

        SSH_DEBUG(
                SSH_D_FAIL,
                ("Error from XFRM, msg type 0x%x, seq number %u, error %d",
                 hdr->nlmsg_type,
                 hdr->nlmsg_seq,
                 error));

        switch (msg_type)
        {
        case XFRM_MSG_NEWSA:
        case XFRM_MSG_UPDSA:
            netlink_xfrm_process_newsa_error(
                    orig_msg,
                    error);
            break;
        case XFRM_MSG_DELSA:
            netlink_xfrm_process_delsa_error(
                    orig_msg,
                    error);
            break;
        case XFRM_MSG_GETSA:
            netlink_xfrm_process_getsa_error(
                    orig_msg,
                    error);
            break;
        case XFRM_MSG_NEWPOLICY:
        case XFRM_MSG_UPDPOLICY:
            netlink_xfrm_process_newpolicy_error(
                    orig_msg,
                    error);
            break;
        case XFRM_MSG_DELPOLICY:
            netlink_xfrm_process_delpolicy_error(
                    orig_msg,
                    error);
            break;
        case XFRM_MSG_FLUSHPOLICY:
            netlink_xfrm_process_flushpolicy_error(
                    orig_msg,
                    error);
            break;
        case XFRM_MSG_FLUSHSA:
            netlink_xfrm_process_flushsa_error(
                    orig_msg,
                    error);
            break;
        default:
            break;
        }
    }

    return error;
}

static bool
netlink_xfrm_is_overflow(
        struct xfrm_user_expire *user_expire)
{
    if (user_expire->hard == 1)
    {
        return true;
    }

    return false;
}

static bool
netlink_xfrm_is_first_packet(
        struct xfrm_usersa_info *usersa_info)
{
    if (usersa_info->curlft.packets == 0 && usersa_info->curlft.bytes == 0)
    {
        return true;
    }
    else
    {
        return false;
    }
}

static bool
netlink_xfrm_is_rekey(
        struct xfrm_usersa_info *usersa_info)
{
    if (usersa_info->lft.soft_byte_limit != XFRM_INF &&
        usersa_info->curlft.bytes >= usersa_info->lft.soft_byte_limit)
    {
        return true;
    }
    else
    if(usersa_info->lft.soft_packet_limit != 0 &&
       usersa_info->lft.soft_packet_limit != XFRM_INF &&
       usersa_info->curlft.packets >= usersa_info->lft.soft_packet_limit)
    {
        return true;
    }
    else
    {
        return false;
    }
}

static void
netlink_xfrm_process_expire(
        struct NetlinkXfrm *netlink_xfrm,
        struct nlmsghdr *hdr)
{
    struct xfrm_user_expire *user_expire;
    struct xfrm_usersa_info *usersa_info;
    uint32_t request_id;
    bool first_packet = false;
    bool rekey = false;
    bool overflow;

    user_expire = NLMSG_DATA(hdr);
    usersa_info = &user_expire->state;

    request_id = usersa_info->reqid;

    SSH_DEBUG(
            SSH_D_NICETOKNOW,
            ("XFRM packets %llu, bytes %llu, "
             "add time %llu, use time %llu, "
             "soft packet limit %llu, hard packet limit %llu, "
             "soft byte limit %llu, hard byte limit %llu",
             usersa_info->curlft.packets,
             usersa_info->curlft.bytes,
             usersa_info->curlft.add_time,
             usersa_info->curlft.use_time,
             usersa_info->lft.soft_packet_limit,
             usersa_info->lft.hard_packet_limit,
             usersa_info->lft.soft_byte_limit,
             usersa_info->lft.hard_byte_limit));

    overflow = netlink_xfrm_is_overflow(user_expire);

    /* Check other cases only if overflow has not been happend. */
    if (overflow == false)
    {
        first_packet = netlink_xfrm_is_first_packet(usersa_info);

        rekey = netlink_xfrm_is_rekey(usersa_info);
    }

    SSH_DEBUG(
            SSH_D_NICETOKNOW,
            ("Expire from XFRM, SPI 0x%.8x, protocol %u, request id %u, "
             "overflow '%s', first packet '%s', rekey '%s'",
             ntohl(usersa_info->id.spi),
             usersa_info->id.proto,
             request_id,
             overflow == true ? "yes" : "no",
             first_packet == true ? "yes" : "no",
             rekey == true ? "yes" : "no"));

    if (netlink_xfrm->event_cb != NULL)
    {
        netlink_xfrm->event_cb(
                netlink_xfrm->event_context,
                request_id,
                ntohl(usersa_info->id.spi),
                overflow,
                first_packet,
                rekey,
                false);
    }
}

/* This is used fo debugging only now */
static void
netlink_xfrm_process_newsa(
        struct NetlinkXfrm *netlink_xfrm,
        struct nlmsghdr *hdr)
{
    struct nlattr *encap_attr = NULL;
    struct xfrm_usersa_info *usersa_info;
    struct nlattr *attr;
    size_t size;

    SSH_DEBUG(SSH_D_ERROR, ("NEWSA received, seq %u", hdr->nlmsg_seq));

    usersa_info = NLMSG_DATA(hdr);
    attr = NETLINK_XFRM_ATTR_FIRST(hdr, sizeof(*usersa_info));
    size = NLMSG_PAYLOAD(hdr, sizeof(*usersa_info));

    while (NETLINK_XFRM_ATTR_OK(attr, size))
    {
        if (attr->nla_type == XFRMA_ENCAP)
        {
            encap_attr = attr;
            attr = NETLINK_XFRM_ATTR_NEXT(attr, size);
            break;
        }

        attr = NETLINK_XFRM_ATTR_NEXT(attr, size);
    }

    /* Remove ENCAP attribute. */
    if (encap_attr != NULL)
    {
        SSH_DEBUG(
                SSH_D_LOWOK,
                ("Removing ENCAP attribute from NEWSA message, "
                 "SPI 0x%.8x, protocol %u, request id %u, seq %u",
                 ntohl(usersa_info->id.spi),
                 usersa_info->id.proto,
                 usersa_info->reqid,
                 usersa_info->seq));

        hdr->nlmsg_len =
            NETLINK_XFRM_NLMSG_DEC_LENGTH(hdr, encap_attr->nla_len);

        if (size > 0)
        {
            memmove(encap_attr, attr, size);
        }
    }
}

static int
netlink_xfrm_process_message(
        struct NetlinkXfrm *netlink_xfrm,
        struct nlmsghdr *hdr)
{
    uint16_t type = hdr->nlmsg_type;
    int error = 0;

    switch (type)
    {
    case NLMSG_ERROR:
        error = netlink_xfrm_process_error(netlink_xfrm, hdr);
        break;
    case XFRM_MSG_EXPIRE:
        netlink_xfrm_process_expire(netlink_xfrm, hdr);
        break;
    /* we receive NEWSA when we send GETSA */
    case XFRM_MSG_NEWSA:
        netlink_xfrm_process_newsa(netlink_xfrm, hdr);
        break;
    default:
        SSH_DEBUG(
                SSH_D_LOWOK,
                ("Unsupported message type 0x%x received from XFRM", type));
        break;
    }

    return error;
}

static int
netlink_xfrm_receive(
        struct NetlinkXfrm *netlink_xfrm,
        int sock,
        bool check_sequence_number,
        uint32_t sequence_number)
{
    unsigned char buf[4096];
    struct nlmsghdr *hdr;
    int result = 0;
    int len;

    len = netlink_xfrm_receive_message(sock, buf, sizeof buf);
    if (len <= 0)
    {
        return -1;
    }

    for (hdr = (struct nlmsghdr *) buf;
         NLMSG_OK(hdr, len);
         hdr = NLMSG_NEXT(hdr, len))
    {
        int error;

        if (hdr->nlmsg_type == NLMSG_DONE)
        {
            len = 0; /* we don't care about the length of the DONE message */
            break;
        }

        if (check_sequence_number == true && hdr->nlmsg_seq != sequence_number)
        {
            SSH_DEBUG(
                    SSH_D_LOWOK,
                    ("Ignoring message with unexpected sequence %d "
                     "(expected %d).",
                     hdr->nlmsg_seq,
                     sequence_number));
            continue;
        }

        /* Process message. */
        error = netlink_xfrm_process_message(netlink_xfrm, hdr);
        if (error != 0)
        {
            result = error;
        }
    }

    if (len != 0)
    {
        SSH_DEBUG(
                SSH_D_FAIL,
                ("Could not process all messages, "
                 "erroneous packet received from Netlink XFRM"));
    }

    return result;
}

static bool
netlink_xfrm_receive_response(
        struct NetlinkXfrm *netlink_xfrm,
        uint32_t sequence_number,
        struct NetlinkRequest *response)
{
    unsigned char *buf = (unsigned char*) response->message;
    size_t buf_size = sizeof response->message;
    int sock = netlink_xfrm->request_sock;
    struct nlmsghdr *hdr;
    int ok = false;
    int error;

    while (netlink_xfrm_receive_message(sock, buf, buf_size) > 0)
    {
        hdr = (struct nlmsghdr *) buf;

        if (hdr->nlmsg_type == NLMSG_DONE)
        {
            continue;
        }

        if (hdr->nlmsg_seq != sequence_number)
        {
            SSH_DEBUG(
                    SSH_D_LOWOK,
                    ("Message with unexpected sequence %u (expected %u).",
                     hdr->nlmsg_seq,
                     sequence_number));

            netlink_xfrm_process_message(netlink_xfrm, hdr);
            continue;
        }

        /* Process message. */
        error = netlink_xfrm_process_message(netlink_xfrm, hdr);
        if (error != 0)
        {
            SSH_DEBUG(
                    SSH_D_FAIL,
                    ("Error when getting response with sequence %u.",
                     sequence_number));
            break;
        }

        ok = true;
        break;
    }

    return ok;
}

static bool
netlink_xfrm_send(
        struct NetlinkRequest **request_p,
        bool check_response,
        uint32_t *sequence_number_p)
{
    struct NetlinkXfrm *netlink_xfrm = (*request_p)->netlink_xfrm;
    struct sockaddr_nl sa;
    struct nlmsghdr *hdr = (struct nlmsghdr *) &(*request_p)->message;
    int sock = netlink_xfrm->request_sock;
    int result = 0;
    bool ok = true;

    *sequence_number_p = netlink_xfrm->sequence_number++;

    /* Fill netlink destination address. */
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    sa.nl_pid = 0; /* Message is directed to kernel */

    hdr->nlmsg_seq = *sequence_number_p;
    hdr->nlmsg_pid = getpid(); /* Message originates from user process. */

    SSH_DEBUG(
            SSH_D_LOWOK,
            ("Sending XFRM request type 0x%x seq %u",
             hdr->nlmsg_type, hdr->nlmsg_seq));

    /* Send the request. This request should not require
       root permissions or any special capabilities. */
    result =
        sendto(
                sock,
                hdr,
                hdr->nlmsg_len,
                0,
                (struct sockaddr *) &sa,
                (ssh_socklen_t) sizeof(sa));
    if (result < 0)
    {
        SSH_DEBUG(
                SSH_D_FAIL,
                ("sendto() of NETLINK_XFRM request failed with error %d.",
                 result));

        ok = false;
    }
    else
    if (check_response == true)
    {
        result =
            netlink_xfrm_receive(
                    netlink_xfrm,
                    sock,
                    true,
                    hdr->nlmsg_seq);

        if (result != 0)
        {
            SSH_DEBUG(
                    SSH_D_FAIL,
                    ("NETLINK_XFRM request type 0x%x returned error %d",
                     hdr->nlmsg_type,
                     result));
            ok = false;
        }
    }

    netlink_xfrm_request_free(request_p);

    return ok;
}

/*
   Function to receive packets from a request socket. This function is
   registered to the Event Loop when Netlink XFRM is initialized.
 */
static void
netlink_xfrm_request_socket_callback(
        unsigned int events,
        void *context)
{
    struct NetlinkXfrm *netlink_xfrm = context;

    if ((events & SSH_IO_READ) != 0)
    {
        int sock = netlink_xfrm->request_sock;

        SSH_DEBUG(SSH_D_LOWOK, ("Reading data from request socket"));

        (void) netlink_xfrm_receive(netlink_xfrm, sock, false, 0);
    }
}

/*
   Function to receive packets from a event socket. This function is
   registered to the Event Loop when Netlink XFRM is initialized.
 */
static void
netlink_xfrm_event_socket_callback(
        unsigned int events,
        void *context)
{
    struct NetlinkXfrm *netlink_xfrm = context;

    if ((events & SSH_IO_READ) != 0)
    {
        int sock = netlink_xfrm->event_sock;

        SSH_DEBUG(SSH_D_LOWOK, ("Reading data from event socket"));

        (void) netlink_xfrm_receive(netlink_xfrm, sock, false, 0);
    }
}

static bool
netlink_xfrm_flush_sa(
        struct NetlinkXfrm *netlink_xfrm)
{
    struct NetlinkRequest *request;
    bool ok = false;

    request = netlink_xfrm_request_alloc(netlink_xfrm);
    if (request != NULL)
    {
        struct nlmsghdr *hdr = (struct nlmsghdr *) &request->message;
        uint32_t unused;

        hdr->nlmsg_len = NLMSG_LENGTH(sizeof(struct xfrm_usersa_flush));
        hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
        hdr->nlmsg_type = XFRM_MSG_FLUSHSA;

        /* Send request */
        ok = netlink_xfrm_send(&request, true, &unused);

        if (ok == false)
        {
            SSH_DEBUG(SSH_D_FAIL, ("Flushing SAs failed"));
        }
        else
        {
            SSH_DEBUG(SSH_D_LOWSTART, ("Flushing SAs successful"));
        }
    }

    return ok;
}

static bool
netlink_xfrm_flush_policy(
        struct NetlinkXfrm *netlink_xfrm)
{
    struct NetlinkRequest *request;
    bool ok = false;

    request = netlink_xfrm_request_alloc(netlink_xfrm);
    if (request != NULL)
    {
        struct nlmsghdr *hdr = (struct nlmsghdr *) &request->message;
        uint32_t unused;

        hdr->nlmsg_len = NLMSG_LENGTH(0);
        hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
        hdr->nlmsg_type = XFRM_MSG_FLUSHPOLICY;

        /* Send request */
        ok = netlink_xfrm_send(&request, true, &unused);

        if (ok == false)
        {
            SSH_DEBUG(SSH_D_FAIL, ("Flushing policies failed"));
        }
        else
        {
            SSH_DEBUG(SSH_D_LOWSTART, ("Flushing policies successful"));
        }
    }
    else
    {
        SSH_DEBUG(SSH_D_FAIL, ("Cannot allocate memory for request"));
    }

    return ok;
}

/* Standalone (doesn't need preallocated request) function that flushes
 states (SA's) and policies */
static bool
netlink_xfrm_flush(
        struct NetlinkXfrm *netlink_xfrm)
{
    bool ok = true;

    if (ok == true)
    {
        ok = netlink_xfrm_flush_sa(netlink_xfrm);
    }

    if (ok == true)
    {
        ok = netlink_xfrm_flush_policy(netlink_xfrm);
    }

    return ok;
}

static bool
netlink_xfrm_create_request_socket(
        struct NetlinkXfrm *netlink_xfrm)
{
    bool ok = false;
    int sock;

    /* Open the socket. */
    sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_XFRM);
    if (sock < 0)
    {
        SSH_DEBUG(
                SSH_D_ERROR,
                ("Failed to open Netlink XFRM request socket"));
    }
    else
    {
        /* Register socket. */
        if (ssh_io_register_fd(
                    sock,
                    netlink_xfrm_request_socket_callback,
                    netlink_xfrm))
        {
            /* In successful case activate reading. */
            ssh_io_set_fd_request(sock, SSH_IO_READ);
            ok = true;
        }
        else
        {
            SSH_DEBUG(
                    SSH_D_FAIL,
                    ("Failed to register request socket %d to event loop",
                     sock));

            close(sock);
            sock = -1;
        }
    }

    if (sock >= 0)
    {
        SSH_DEBUG(
                SSH_D_HIGHOK,
                ("Netlink XFRM request socket %d successfully created",
                 sock));

        netlink_xfrm->request_sock = sock;
    }

    return ok;
}

#define NETLINK_XFRM_GROUPS_FLAG(group) (1 << (group-1))

static bool
netlink_xfrm_create_event_socket(
        struct NetlinkXfrm *netlink_xfrm)
{
    bool ok = true;
    int sock;

    /* Open the socket. */
    sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_XFRM);
    if (sock < 0)
    {
        SSH_DEBUG(
                SSH_D_ERROR,
                ("Failed to open Netlink XFRM event socket"));
        ok = false;
    }

    if (ok == true)
    {
        struct sockaddr_nl sa;
        int ret;

        memset(&sa, 0, sizeof(sa));
        sa.nl_family = AF_NETLINK;
        sa.nl_groups = NETLINK_XFRM_GROUPS_FLAG(XFRMNLGRP_EXPIRE);

        ret = bind(sock, (struct sockaddr*)&sa, sizeof(sa));
        if (ret < 0)
        {
            SSH_DEBUG(
                    SSH_D_ERROR,
                    ("Failed to bind Netlink XFRM event socket"));
            ok = false;
        }
    }

    if (ok == true)
    {
        /* Register socket. */
        if (ssh_io_register_fd(
                    sock,
                    netlink_xfrm_event_socket_callback,
                    netlink_xfrm))
        {
            /* In successful case activate reading. */
            ssh_io_set_fd_request(sock, SSH_IO_READ);
        }
        else
        {
            SSH_DEBUG(
                    SSH_D_FAIL,
                    ("Failed to register event socket %d to event loop",
                     sock));
            ok = false;
        }
    }

    if (ok == true)
    {
        SSH_DEBUG(
                SSH_D_HIGHOK,
                ("Netlink XFRM event socket %d successfully created",
                 sock));

        netlink_xfrm->event_sock = sock;
    }
    else
    {
        if (sock >= 0)
        {
            close(sock);
        }
    }

    return ok;
}

static void
netlink_xfrm_close_socket(
        int *sock_p)
{
   int result;
   int sock;

   sock = *sock_p;
   *sock_p = -1;

    /* Unregister file descriptor if it exists. */
    if (sock >= 0)
    {
        SSH_DEBUG(
                SSH_D_LOWOK,
                ("Unregistering socket %d from event loop",
                 sock));

        ssh_io_unregister_fd(sock, true);

        result = close(sock);
        if (result == 0)
        {
            SSH_DEBUG(
                    SSH_D_HIGHOK,
                    ("Netlink XFRM socket %d closed",
                     sock));
        }
        else
        {
            SSH_DEBUG(
                    SSH_D_ERROR,
                    ("Failed to close Netlink XFRM socket %d, errno %d",
                     sock,
                     errno));
        }
    }
}

static struct NetlinkXfrm *
netlink_xfrm_alloc(
        void)
{
    struct NetlinkXfrm *netlink_xfrm;

    netlink_xfrm = ssh_calloc(1, sizeof *netlink_xfrm);
    if (netlink_xfrm == NULL)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Out of memory!"));
    }
    else
    {
        netlink_xfrm->request_sock = -1;
        netlink_xfrm->event_sock = -1;
    }

    return netlink_xfrm;
}

bool
netlink_xfrm_init(
        struct NetlinkXfrmParams *params,
        struct NetlinkXfrm **netlink_xfrm_p)
{
    struct NetlinkXfrm *netlink_xfrm = NULL;
    bool ok = true;

    *netlink_xfrm_p = NULL;

    netlink_xfrm = netlink_xfrm_alloc();
    if (netlink_xfrm == NULL)
    {
        ok = false;
    }

    if (ok == true)
    {
        ok = netlink_xfrm_create_request_socket(netlink_xfrm);
    }

    if (ok == true)
    {
        ok = netlink_xfrm_create_event_socket(netlink_xfrm);
    }

    if (ok == true)
    {
        ok = netlink_xfrm_flush(netlink_xfrm);
    }

    if (ok == true)
    {
        /* Copy configuration parameters. */
        netlink_xfrm->event_cb = params->event_cb;
        netlink_xfrm->event_context = params->event_context;

        *netlink_xfrm_p = netlink_xfrm;

        SSH_DEBUG(
                SSH_D_HIGHOK,
                ("Netlink XFRM initialization successful"));
    }
    else
    {
        SSH_DEBUG(
                SSH_D_ERROR,
                ("Netlink XFRM initialization failed"));

        netlink_xfrm_uninit(&netlink_xfrm);

        *netlink_xfrm_p = NULL;
    }

    return ok;
}

void
netlink_xfrm_uninit(
        struct NetlinkXfrm **netlink_xfrm_p)
{
    if (*netlink_xfrm_p != NULL)
    {
        SSH_DEBUG(SSH_D_HIGHOK, ("Closing request socket"));
        netlink_xfrm_close_socket(&(*netlink_xfrm_p)->request_sock);

        SSH_DEBUG(SSH_D_HIGHOK, ("Closing event socket"));
        netlink_xfrm_close_socket(&(*netlink_xfrm_p)->event_sock);

        ssh_free(*netlink_xfrm_p);
        *netlink_xfrm_p = NULL;
    }
}

bool
netlink_xfrm_request_send(
        struct NetlinkRequest **request_p)
{
    uint32_t unused;
    bool ok;

    ok = netlink_xfrm_send(request_p, false, &unused);

    return ok;
}

static void
netlink_xfrm_encode_algo(
        struct nlmsghdr *hdr,
        const struct netlink_xfrm_alg_properties* alg_prop,
        unsigned int alg_key_len,
        const unsigned char *alg_key)
{
    struct xfrm_algo* algo;
    struct nlattr *attr;

    attr = NETLINK_XFRM_ATTR_DATA(hdr);
    algo = NETLINK_XFRM_NLA_DATA(attr);

    algo->alg_key_len = alg_key_len * 8; /* this length is in bits */

    strncpy(
            algo->alg_name,
            alg_prop->name,
            MIN(sizeof(algo->alg_name) - 1, strlen(alg_prop->name)));
    memcpy(algo->alg_key, alg_key, alg_key_len);

    attr->nla_type = alg_prop->xfrm_type;
    attr->nla_len = NETLINK_XFRM_NLA_LENGTH(sizeof(*algo) + alg_key_len);

    /* Update length. */
    hdr->nlmsg_len = NETLINK_XFRM_NLMSG_CALC_LENGTH(hdr, attr->nla_len);
}

static void
netlink_xfrm_encode_algo_auth(
        struct nlmsghdr *hdr,
        const struct netlink_xfrm_alg_properties* alg_prop,
        TransformId alg_id,
        unsigned int alg_key_len,
        const unsigned char *alg_key)
{
    struct xfrm_algo_auth* algo_auth;
    struct nlattr *attr;

    attr = NETLINK_XFRM_ATTR_DATA(hdr);
    algo_auth = NETLINK_XFRM_NLA_DATA(attr);

    algo_auth->alg_key_len = alg_key_len * 8; /* lengths are in bits */
    algo_auth->alg_trunc_len = transformid_to_security_strength(alg_id);

    strncpy(
            algo_auth->alg_name,
            alg_prop->name,
            MIN(sizeof(algo_auth->alg_name) -1, strlen(alg_prop->name)));
    memcpy(algo_auth->alg_key, alg_key, alg_key_len);

    attr->nla_type = alg_prop->xfrm_type;
    attr->nla_len = NETLINK_XFRM_NLA_LENGTH(sizeof(*algo_auth) + alg_key_len);

    /* Update length. */
    hdr->nlmsg_len = NETLINK_XFRM_NLMSG_CALC_LENGTH(hdr, attr->nla_len);
}

static void
netlink_xfrm_encode_algo_aead(
        struct nlmsghdr *hdr,
        const struct netlink_xfrm_alg_properties* alg_prop,
        unsigned int alg_key_len,
        const unsigned char *alg_key)
{
    struct xfrm_algo_aead* algo_aead;
    struct nlattr *attr;

    attr = NETLINK_XFRM_ATTR_DATA(hdr);
    algo_aead = NETLINK_XFRM_NLA_DATA(attr);

    algo_aead->alg_key_len =  alg_key_len * 8; /* length is in bits */
    algo_aead->alg_icv_len = alg_prop->icv_len;

    strncpy(
            algo_aead->alg_name,
            alg_prop->name,
            MIN(sizeof(algo_aead->alg_name) - 1, strlen(alg_prop->name)));
    memcpy(algo_aead->alg_key, alg_key, alg_key_len);

    attr->nla_type = alg_prop->xfrm_type;
    attr->nla_len = NETLINK_XFRM_NLA_LENGTH(sizeof(*algo_aead) + alg_key_len);

    /* Update length. */
    hdr->nlmsg_len = NETLINK_XFRM_NLMSG_CALC_LENGTH(hdr, attr->nla_len);
}

int
netlink_xfrm_newsa_encode_algorithm(
        struct NetlinkRequest *request,
        TransformId alg_id,
        unsigned int alg_key_len,
        const unsigned char *alg_key)
{
    const struct netlink_xfrm_alg_properties* alg_prop;
    struct nlmsghdr *hdr = (struct nlmsghdr *) &request->message;
    int result = 0;

    alg_prop = netlink_xfrm_get_alg_properties(alg_id);

    if (alg_prop == NULL)
    {
        ssh_log_event(
                SSH_LOGFACILITY_DAEMON,
                SSH_LOG_ERROR,
                "Cannot convert transform id 0x%lx to a "
                "kernel supported algorithm",
                alg_id);
        return -1;
    }

    switch (alg_prop->xfrm_type)
    {
    case XFRMA_ALG_CRYPT:

        netlink_xfrm_encode_algo(
                hdr,
                alg_prop,
                alg_key_len,
                alg_key);
        break;

    case XFRMA_ALG_AUTH_TRUNC:

        netlink_xfrm_encode_algo_auth(
                hdr,
                alg_prop,
                alg_id,
                alg_key_len,
                alg_key);
        break;

    case XFRMA_ALG_AEAD:

        netlink_xfrm_encode_algo_aead(
                hdr,
                alg_prop,
                alg_key_len,
                alg_key);
        break;

    default:
        SSH_DEBUG(
                SSH_D_FAIL,
                ("Xfrm attribute type %d is not supported.",
                 alg_prop->xfrm_type));
        result = -1;
    }

    return result;
}

void
netlink_xfrm_set_natt(
    struct NetlinkRequest* request,
    int local_port,
    int remote_port)
{
    struct nlmsghdr *hdr = (struct nlmsghdr *) &request->message;
    struct xfrm_encap_tmpl *encap_tmpl;
    struct nlattr *attr;

    attr = NETLINK_XFRM_ATTR_DATA(hdr);
    encap_tmpl = NETLINK_XFRM_NLA_DATA(attr);

    encap_tmpl->encap_type = UDP_ENCAP_ESPINUDP;
    encap_tmpl->encap_sport = htons(local_port);
    encap_tmpl->encap_dport = htons(remote_port);
    memset(&encap_tmpl->encap_oa, 0, sizeof (xfrm_address_t));

    attr->nla_type = XFRMA_ENCAP;
    attr->nla_len = NETLINK_XFRM_NLA_LENGTH(sizeof(*encap_tmpl));

    hdr->nlmsg_len = NETLINK_XFRM_NLMSG_CALC_LENGTH(hdr, attr->nla_len);
}

void
netlink_xfrm_newpolicy_encode_tmpl(
        struct NetlinkRequest *request,
        const struct InAddr *src,
        const struct InAddr *dst,
        uint8_t proto,
        bool tunnel_mode,
        uint32_t request_id)
{
    struct nlmsghdr *hdr = (struct nlmsghdr *) &request->message;
    struct xfrm_user_tmpl *user_tmpl;
    struct nlattr *attr;

    attr = NETLINK_XFRM_ATTR_DATA(hdr);
    user_tmpl = NETLINK_XFRM_NLA_DATA(attr);

    /* xfrm_id struct */
    user_tmpl->id.proto = proto;

    /* addresses */
    if (in_addr_version(dst) == IN_ADDR_FOUR)
    {
        int32_t ipv4_tmp;

        in_addr_export(dst, &ipv4_tmp, 4);
        user_tmpl->id.daddr.a4 = ipv4_tmp;
        in_addr_export(src, &ipv4_tmp, 4);
        user_tmpl->saddr.a4 = ipv4_tmp;
        user_tmpl->family = AF_INET;
    }
    else        /* IPv6 */
    {
        in_addr_export(dst, user_tmpl->id.daddr.a6, 16);
        in_addr_export(src, user_tmpl->saddr.a6, 16);
        user_tmpl->family = AF_INET6;
    }

    user_tmpl->reqid = request_id;
    user_tmpl->mode = tunnel_mode ? XFRM_MODE_TUNNEL : XFRM_MODE_TRANSPORT;

    /* Bit mask of algos allowed */
    user_tmpl->aalgos = (~(__u32)0);
    user_tmpl->ealgos = (~(__u32)0);
    user_tmpl->calgos = (~(__u32)0);

    attr->nla_type = XFRMA_TMPL;
    attr->nla_len = NETLINK_XFRM_NLA_LENGTH(sizeof(*user_tmpl));

    hdr->nlmsg_len = NETLINK_XFRM_NLMSG_CALC_LENGTH(hdr, attr->nla_len);
}

struct NetlinkRequest*
netlink_xfrm_request_alloc(
        struct NetlinkXfrm *netlink_xfrm)
{
    struct NetlinkRequest *request;

    request = ssh_calloc(sizeof *request, 1);

    if (request != NULL)
    {
        request->netlink_xfrm = netlink_xfrm;
    }
    else
    {
        SSH_DEBUG(SSH_D_FAIL, ("Cannot allocate memory for request"));
    }

    return request;
}

void
netlink_xfrm_request_free(
        struct NetlinkRequest **request_p)
{
    if (*request_p != NULL)
    {
        ssh_free(*request_p);
        *request_p = NULL;
    }
}

void
netlink_xfrm_newsa_init(
        struct NetlinkRequest *request)
{
    struct nlmsghdr *hdr = (struct nlmsghdr *) &request->message;

    hdr->nlmsg_len = NLMSG_LENGTH(sizeof(struct xfrm_usersa_info));
    hdr->nlmsg_flags = NLM_F_REQUEST| NLM_F_CREATE| NLM_F_EXCL| NLM_F_ACK;
    hdr->nlmsg_type = XFRM_MSG_NEWSA;
}

/* Compute and return a percentage of an uint64_t. */
static uint64_t
netlink_xfrm_percent_of(
        uint64_t percent,
        uint64_t value)
{
    if (value > 10000000) /* */
    {
        return (value / 100) * percent;
    }
    else
    {
        return (value * percent) / 100;
    }
}

static void
netlink_xfrm_calculate_byte_limits(
        uint64_t life_bytes,
        uint64_t life_bytes_rekey,
        uint64_t *soft_byte_limit_p,
        uint64_t *hard_byte_limit_p)
{
    if (life_bytes == 0)
    {
        /* Use infinitive limits when byte limits are not activated. */
        *soft_byte_limit_p = XFRM_INF;
        *hard_byte_limit_p = XFRM_INF;
    }
    else
    {
        if (life_bytes > NETLINK_XFRM_BYTE_LIMIT_MAX)
        {
            *hard_byte_limit_p = NETLINK_XFRM_BYTE_LIMIT_MAX;
        }
        else
        {
            *hard_byte_limit_p = life_bytes;
        }

        if (life_bytes_rekey > NETLINK_XFRM_BYTE_LIMIT_MAX)
        {
            *soft_byte_limit_p = NETLINK_XFRM_BYTE_LIMIT_MAX;
        }
        else
        {
            *soft_byte_limit_p = life_bytes_rekey;
        }
    }
}

static void
netlink_xfrm_calculate_packet_limits(
        bool esn,
        bool is_outbound,
        uint64_t *soft_packet_limit_p,
        uint64_t *hard_packet_limit_p)
{
    if (is_outbound == true)
    {
        if (esn == true)
        {
            *hard_packet_limit_p = XFRM_INF - 1;
        }
        else
        {
            *hard_packet_limit_p = 0xfffffffe;
        }

        *soft_packet_limit_p =
            netlink_xfrm_percent_of(
                    NETLINK_XFRM_SOFT_PACKET_LIMIT_PERCENTAGE,
                    *hard_packet_limit_p);
    }
    else
    {
        /* In inbound direction set soft_packet_limit to zero to get
           expire message from XFRM when first packet is received. */
        *soft_packet_limit_p = 0;
        *hard_packet_limit_p = XFRM_INF;
    }
}

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
        bool is_outbound)
{
    struct xfrm_usersa_info *usersa_info = NLMSG_DATA(&request->message);

    /* Request ID is used to match policy with SA. */
    usersa_info->reqid = request_id;
    usersa_info->id.spi = htonl(spi);
    usersa_info->id.proto = protocol;

    if (tunnel_mode == true)
    {
        usersa_info->mode = XFRM_MODE_TUNNEL;

        /* AF_UNSPEC allows tunneling IPv6 over IPv4 and vice versa. */
        usersa_info->flags |= XFRM_STATE_AF_UNSPEC;
    }
    else
    {
        usersa_info->mode = XFRM_MODE_TRANSPORT;
    }

    /* Calculate and set byte limits. */
    {
        uint64_t soft_byte_limit;
        uint64_t hard_byte_limit;

        netlink_xfrm_calculate_byte_limits(
                life_bytes,
                life_bytes_rekey,
                &soft_byte_limit,
                &hard_byte_limit);

        usersa_info->lft.soft_byte_limit = soft_byte_limit;
        usersa_info->lft.hard_byte_limit = hard_byte_limit;
    }

    /* Calculate and set packet limits. */
    {
        uint64_t soft_packet_limit;
        uint64_t hard_packet_limit;

        netlink_xfrm_calculate_packet_limits(
                esn,
                is_outbound,
                &soft_packet_limit,
                &hard_packet_limit);

        usersa_info->lft.soft_packet_limit = soft_packet_limit;
        usersa_info->lft.hard_packet_limit = hard_packet_limit;
    }
}

void
netlink_xfrm_newsa_encode_addresses(
        struct NetlinkRequest *request,
        const struct InAddr *src,
        const struct InAddr *dst)
{
    struct xfrm_usersa_info *usersa_info = NLMSG_DATA(&request->message);
    int32_t ipv4_tmp;

    if (in_addr_version(dst) == IN_ADDR_FOUR)
    {
        in_addr_export(dst, &ipv4_tmp, 4);
        usersa_info->id.daddr.a4 = ipv4_tmp;
        in_addr_export(src, &ipv4_tmp, 4);
        usersa_info->saddr.a4 = ipv4_tmp;
        usersa_info->family = AF_INET;
    }
    else        /* IPv6 */
    {
        in_addr_export(dst, usersa_info->id.daddr.a6, 16);
        in_addr_export(src, usersa_info->saddr.a6, 16);
        usersa_info->family = AF_INET6;
    }

}


void
netlink_xfrm_newsa_encode_replay_window_esn(
        struct NetlinkRequest *request,
        uint32_t replay_window,
        uint32_t seq_high,
        uint32_t seq_low,
        bool outbound,
        bool esn)
{
    struct nlmsghdr *hdr = (struct nlmsghdr *) &request->message;
    struct xfrm_usersa_info *usersa_info = NLMSG_DATA(&request->message);
    struct nlattr *nla = NETLINK_XFRM_ATTR_DATA(hdr);

    /* Set the anti-replay window and ESN. */
    if (replay_window != 0 || esn == true)
    {
        struct xfrm_replay_state_esn *replay = NETLINK_XFRM_NLA_DATA(nla);
        uint32_t bitmap_len;

        /* Set anti-reply window in pre defined range. */
        replay_window = MAX(replay_window, XFRM_MIN_ANTIREPLAY_WINDOW_SIZE);
        replay_window = MIN(replay_window, XFRM_MAX_ANTIREPLAY_WINDOW_SIZE);

        /* Bitmap size has to be a multiple of 32 bits */
        bitmap_len = replay_window % 32 ? replay_window / 32 + 1 :
                                          replay_window / 32;

        nla->nla_type = XFRMA_REPLAY_ESN_VAL;
        /* Size of replay struct plus the bitmap length in bytes. */
        nla->nla_len = NETLINK_XFRM_NLA_LENGTH(sizeof(*replay) +
                                               bitmap_len * 4);
        hdr->nlmsg_len = NETLINK_XFRM_NLMSG_CALC_LENGTH(hdr, nla->nla_len);

        replay->bmp_len = bitmap_len;
        replay->replay_window = replay_window;

        if (outbound == true)
        {
            replay->oseq_hi = seq_high;
            replay->oseq = seq_low;
        }

        if (outbound == true)
        {
            /* set also packet count */
            struct nlattr *attr = NETLINK_XFRM_ATTR_DATA(hdr);
            struct xfrm_lifetime_cur *lf = NETLINK_XFRM_NLA_DATA(attr);

            attr->nla_type = XFRMA_LTIME_VAL;
            attr->nla_len = NETLINK_XFRM_NLA_LENGTH(sizeof(*lf));
            hdr->nlmsg_len =
                NETLINK_XFRM_NLMSG_CALC_LENGTH(
                        hdr,
                        attr->nla_len);

            lf->packets = (uint64_t)seq_high << 32 | seq_low;
        }

        if (esn == true)
        {
            usersa_info->flags |= XFRM_STATE_ESN;
        }
    }
}

void
netlink_xfrm_delsa_init(
        struct NetlinkRequest *request)
{
    struct nlmsghdr *hdr = (struct nlmsghdr *) &request->message;

    hdr->nlmsg_len = NLMSG_LENGTH(sizeof(struct xfrm_usersa_id));
    hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    hdr->nlmsg_type = XFRM_MSG_DELSA;
}

void
netlink_xfrm_encode_id(
        struct NetlinkRequest *request,
        const struct InAddr *dst,
        uint8_t proto,
        uint32_t spi)
{
    struct xfrm_usersa_id *usersa_id = NLMSG_DATA(&request->message);
    int32_t ipv4_tmp;

    usersa_id->spi = htonl(spi);
    usersa_id->proto = proto;

    if (in_addr_version(dst) == IN_ADDR_FOUR)
    {
        in_addr_export(dst, &ipv4_tmp, 4);
        usersa_id->daddr.a4 = ipv4_tmp;
        usersa_id->family = AF_INET;
    }
    else
    {
        in_addr_export(dst, usersa_id->daddr.a6, 16);
        usersa_id->family = AF_INET6;
    }
}

static int
netlink_xfrm_direction_to_xfrm(
        int spd_dir)
{
    switch(spd_dir)
    {
    case NETLINK_XFRM_DIRECTION_IN:
        return XFRM_POLICY_IN;
    case NETLINK_XFRM_DIRECTION_OUT:
        return XFRM_POLICY_OUT;
    case NETLINK_XFRM_DIRECTION_FWD:
        return XFRM_POLICY_FWD;
    default:
        return XFRM_POLICY_MAX;
    }
}

static int
netlink_xfrm_policy_action_to_xfrm(
        int action)
{
    switch(action)
    {
    case NETLINK_XFRM_POLICY_ALLOW:
        return XFRM_POLICY_ALLOW;
    case NETLINK_XFRM_POLICY_BLOCK:
        return XFRM_POLICY_BLOCK;
    default:
        return XFRM_POLICY_ALLOW;
    }
}

void
netlink_xfrm_newpolicy_init(
        struct NetlinkRequest* request,
        bool update,
        uint8_t direction,
        uint8_t action,
        uint32_t priority)
{
    struct nlmsghdr *hdr = (struct nlmsghdr *) &request->message;
    struct xfrm_userpolicy_info *userpolicy_info = NLMSG_DATA(hdr);

    hdr->nlmsg_len = NLMSG_LENGTH(sizeof(struct xfrm_userpolicy_info));
    hdr->nlmsg_flags = NLM_F_REQUEST| NLM_F_CREATE| NLM_F_EXCL| NLM_F_ACK;
    if (update == true)
    {
        hdr->nlmsg_type = XFRM_MSG_UPDPOLICY;
    }
    else
    {
        hdr->nlmsg_type = XFRM_MSG_NEWPOLICY;
    }

    userpolicy_info->priority = priority;
    userpolicy_info->action = netlink_xfrm_policy_action_to_xfrm(action);
    userpolicy_info->dir = netlink_xfrm_direction_to_xfrm(direction);

    userpolicy_info->lft.soft_byte_limit = XFRM_INF;
    userpolicy_info->lft.hard_byte_limit = XFRM_INF;
    userpolicy_info->lft.soft_packet_limit = XFRM_INF;
    userpolicy_info->lft.hard_packet_limit = XFRM_INF;
}

void
netlink_xfrm_delpolicy_init(
        struct NetlinkRequest *request,
        uint8_t direction)
{
    struct nlmsghdr *hdr = (struct nlmsghdr *) &request->message;
    struct xfrm_userpolicy_id *userpolicy_id = NLMSG_DATA(hdr);

    hdr->nlmsg_len = NLMSG_LENGTH(sizeof(struct xfrm_userpolicy_id));
    hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    hdr->nlmsg_type = XFRM_MSG_DELPOLICY;

    userpolicy_id->dir = netlink_xfrm_direction_to_xfrm(direction);
}


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
        uint8_t proto)
{
    struct nlmsghdr *hdr = (struct nlmsghdr *) &request->message;
    struct xfrm_selector *selector = NULL;
    int32_t ipv4_tmp;

    if (hdr->nlmsg_type == XFRM_MSG_DELPOLICY)
    {
        struct xfrm_userpolicy_id *userpolicy_id = NLMSG_DATA(hdr);

        selector = &userpolicy_id->sel;
    }
    else
    if (hdr->nlmsg_type == XFRM_MSG_NEWPOLICY ||
        hdr->nlmsg_type == XFRM_MSG_UPDPOLICY)
    {
        struct xfrm_userpolicy_info *userpolicy_info = NLMSG_DATA(hdr);

        selector = &userpolicy_info->sel;
    }

    ASSERT(selector != NULL);

    selector->proto = proto;

    /* addresses */
    if (in_addr_version(dst) == IN_ADDR_FOUR)
    {
        in_addr_export(dst, &ipv4_tmp, 4);
        selector->daddr.a4 = ipv4_tmp;
        in_addr_export(src, &ipv4_tmp, 4);
        selector->saddr.a4 = ipv4_tmp;
        selector->family = AF_INET;
    }
    else        /* IPv6 */
    {
        in_addr_export(dst, selector->daddr.a6, 16);
        in_addr_export(src, selector->saddr.a6, 16);
        selector->family = AF_INET6;
    }

    selector->prefixlen_s = src_prefix;
    selector->prefixlen_d = dst_prefix;

    /* ports */
    selector->dport = htons(dst_port);
    selector->sport = htons(src_port);

    /* port mask */
    selector->dport_mask = htons(dst_port_mask);
    selector->sport_mask = htons(src_port_mask);
}

static void
netlink_xfrm_getsa_init(
        struct NetlinkRequest *request)
{
    struct nlmsghdr *hdr = (struct nlmsghdr *) &request->message;

    hdr->nlmsg_len = NLMSG_LENGTH(sizeof(struct xfrm_usersa_id));
    hdr->nlmsg_flags = NLM_F_REQUEST;
    hdr->nlmsg_type = XFRM_MSG_GETSA;
}

static void
netlink_xfrm_getsa_encode_id(
        struct NetlinkRequest *request,
        const struct InAddr *dst,
        uint8_t proto,
        uint32_t spi)

{
    netlink_xfrm_encode_id(request, dst, proto, spi);
}

void
netlink_xfrm_delsa_encode_id(
        struct NetlinkRequest *request,
        const struct InAddr *dst,
        uint8_t proto,
         uint32_t spi)
{
    netlink_xfrm_encode_id(request, dst, proto, spi);
}


void
netlink_xfrm_newsa_init_from_getsa(
        struct NetlinkRequest *request)
{
    struct nlmsghdr *hdr = (struct nlmsghdr *) &request->message;

    /* we don't have to change the header length */
    hdr->nlmsg_flags = NLM_F_REQUEST| NLM_F_CREATE| NLM_F_EXCL| NLM_F_ACK;
    hdr->nlmsg_type = XFRM_MSG_NEWSA;
}

static bool
netlink_xfrm_getsa_request(
        struct NetlinkXfrm *netlink_xfrm,
        const struct InAddr *dst,
        uint8_t proto,
        uint32_t spi,
        uint32_t *sequence_number_p)
{
    struct NetlinkRequest *request = NULL;
    bool ok = false;

    request = netlink_xfrm_request_alloc(netlink_xfrm);
    if (request != NULL)
    {
        netlink_xfrm_getsa_init(request);
        netlink_xfrm_getsa_encode_id(request, dst, proto, spi);

        SSH_DEBUG(SSH_D_MIDOK, ("Sending XFRM GETSA"));

        ok = netlink_xfrm_send(&request, false, sequence_number_p);
    }

    return ok;
}

bool
netlink_xfrm_getsa(
        struct NetlinkXfrm *netlink_xfrm,
        const struct InAddr *dst,
        uint8_t proto,
        uint32_t spi,
        struct NetlinkRequest **response_p)
{
    struct NetlinkRequest *response = NULL;
    uint32_t sequence_number;
    bool ok = true;

    /* Allocate memory for the response. */
    response = netlink_xfrm_request_alloc(netlink_xfrm);
    if (response == NULL)
    {
        ok = false;
    }

    /* Request SA information from kernel. */
    if (ok == true)
    {
        ok =
            netlink_xfrm_getsa_request(
                    netlink_xfrm,
                    dst,
                    proto,
                    spi,
                    &sequence_number);
    }

    /* Receive SA information response from kernel. */
    if (ok == true)
    {
        ok =
            netlink_xfrm_receive_response(
                    netlink_xfrm,
                    sequence_number,
                    response);
    }

    /* Free response in failure case. */
    if (ok == false)
    {
        if (response != NULL)
        {
            netlink_xfrm_request_free(&response);
        }
    }

    *response_p = response;

    return ok;
}

