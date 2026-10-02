/**
   @copyright
   Copyright (c) 2007 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   Interface for network interface and routing table configuration from
   userspace. This API can be used also without the SSH eventloop
   runtime environment.
*/

#ifndef SSHNETCONFIG_H
#define SSHNETCONFIG_H

#include "sshinet.h"


/* ********************* Error codes and common defines *********************/

/** Error values. */
typedef enum {
  SSH_NETCONFIG_ERROR_OK                          = 0,  /** OK. */
  SSH_NETCONFIG_ERROR_OUT_OF_MEMORY               = 1,  /** Out of memory. */
  SSH_NETCONFIG_ERROR_INVALID_ARGUMENT            = 2,  /** Invalid argument.*/
  SSH_NETCONFIG_ERROR_NON_EXISTENT                = 3,  /** Non-existent. */
  SSH_NETCONFIG_ERROR_EEXIST                      = 4,  /** The requested
                                                            element existed. */
  SSH_NETCONFIG_ERROR_UNDEFINED                   = 0xffff /** Undefined. */
} SshNetconfigError;

/** Maximum length for link addresses. */
#define SSH_NETCONFIG_MEDIA_ADDRLEN               SSH_ETHERH_ADDRLEN



/* ********************* Accessing and modifying link state ******************/


/*********************** Getting links ***************************************/

/** Fetch a list of ifnums of the links in the system. Parameter `ifnums' is
    a caller allocated array of ifnums and the value of `num_ifnums' specifies
    the size of ifnum array. On success this fills `ifnums' and sets
    `num_ifnums' to number of links in the system. */
SshNetconfigError
ssh_netconfig_get_links(uint32_t *ifnums, uint32_t *num_ifnums);

/*********************** Accessing and modifying link state ******************/

/* Link flags. These flags can be read and modified via the
sshnetconfig API. */

/** Link state up. */
#define SSH_NETCONFIG_LINK_UP                     0x00000001
/** Link is loopback. */
#define SSH_NETCONFIG_LINK_LOOPBACK               0x00000002
/** Link is broadcast. */
#define SSH_NETCONFIG_LINK_BROADCAST              0x00000004
/** Link is point-to-point. */
#define SSH_NETCONFIG_LINK_POINTOPOINT            0x00000008
/** RFC 2863 OPER state. */
#define SSH_NETCONFIG_LINK_RUNNING                0x00000010
/** RFC 2863 OPER state. */
#define SSH_NETCONFIG_LINK_LOWER_DOWN             0x00000020

/* Link properties. These flags indicate static properties of a link,
   which cannot be set via sshnetconfig API. */

/** Link duplex: half duplex. */
#define SSH_NETCONFIG_LINK_PROPERTY_HALF_DUPLEX   0x00000001
/** Link duplex: full duplex. */
#define SSH_NETCONFIG_LINK_PROPERTY_FULL_DUPLEX   0x00000002
/** Link duplex: virtual. */
#define SSH_NETCONFIG_LINK_PROPERTY_VIRTUAL       0x00000004
/** Link duplex: virtual LAN. */
#define SSH_NETCONFIG_LINK_PROPERTY_VLAN          0x00000008


/** Link object. */
typedef struct SshNetconfigLinkRec
{
    /** Interface index - this index is a unique identifier for the link. */
    uint32_t ifnum;

    /** Interface index of the underlying link - for virtual interfaces this
        index specifies the interface that this virtual interface is bound to;
        it may be SSH_INVALID_IFNUM if the virtual interface is not strictly
        bound to any interface but may use a number of underlying links (for
        example IPIP tunneling device); for non-virtual interfaces this index
        is equal to 'ifnum'. */
    uint32_t iflink;

    /** Media address of the link. */
    unsigned char media_addr[SSH_NETCONFIG_MEDIA_ADDRLEN];

    /** Broadcast address of the link. */
    unsigned char broadcast_addr[SSH_NETCONFIG_MEDIA_ADDRLEN];

    /** Address length for this link. */
    size_t addr_len;

    /** Bitmap of SSH_NETCONFIG_LINK_* flags. */
    uint32_t flags;

    /** Bitmap of SSH_NETCONFIG_LINK_* flags. */
    uint32_t flags_mask;

    /** Link MTU. */
    uint16_t mtu;

    /** Link speed, in kilobits per second, read only */
    uint32_t speed;

    /** Link properties */
    uint32_t properties;

    /** Routing instance id */
    int routing_instance_id;

} SshNetconfigLinkStruct, *SshNetconfigLink;

/** Get link status for interface 'ifnum'.

    @return
    This returns SSH_NETCONFIG_ERROR_OK on success and fills the
    return value parameter 'link', which is allocated by the caller of
    the function.

    @param ifnum
    Interface number.

    @param link
    To be filled by the function when it returns.

    */
SshNetconfigError
ssh_netconfig_get_link(uint32_t ifnum, SshNetconfigLink link);

/** Set link VRI for interface 'ifnum'.

    @param ifnum
    Interface number.

    @param routing_instance_id
    The routing instance id.

    @return
    This returns SSH_NETCONFIG_ERROR_OK on success.

    */
SshNetconfigError
ssh_netconfig_set_link_routing_instance(uint32_t ifnum,
                                        int routing_instance_id);

/** Set link flags for interface 'ifnum'.

    @param ifnum
    Interface number.

    @param flags
    Flags to be set.

    @param mask
    Indicates which bits in parameter 'flags' are to be set.

    @return
    This returns SSH_NETCONFIG_ERROR_OK on success.

    */
SshNetconfigError
ssh_netconfig_set_link_flags(uint32_t ifnum, uint32_t flags, uint32_t mask);

/** Set link mtu to 'mtu' for interface 'ifnum'.

    @return
    This returns SSH_NETCONFIG_ERROR_OK on success.

    */
SshNetconfigError
ssh_netconfig_set_link_mtu(uint32_t ifnum, uint16_t mtu);

/** Resolve interface index for interface name 'ifname'.

    @return
    This function returns SSH_NETCONFIG_ERROR_OK on success and sets
    value of 'ifnum_ret' to interface index.

    */
SshNetconfigError
ssh_netconfig_resolve_ifname(const char *ifname,
                             uint32_t *ifnum_ret);

/** Resolve interface name for 'ifnum'.

    @return
    This function returns SSH_NETCONFIG_ERROR_OK on success and sets
    value of 'ifname' to interface name.

    */
SshNetconfigError
ssh_netconfig_resolve_ifnum(uint32_t ifnum,
                            char *ifname,
                            size_t ifname_len);

/** Join media-level multicast group 'mcast_addr' on interface 'ifnum'.

    The multicast group memberships are reference counted. The
    interface will stop receiving frames on the multicast group only
    after all users have left the multicast group.

    @param mcast_addr
    The media address of the multicast group.

    @return
    This returns SSH_NETCONFIG_ERROR_OK on success.

    */
SshNetconfigError
ssh_netconfig_link_multicast_add_membership(uint32_t ifnum,
                                            unsigned char *mcast_addr,
                                            size_t mcast_addr_len);

/** Leave multicast group 'mcast_addr' on interface 'ifnum'.

    The multicast group memberships are reference counted. The
    interface will stop receiving frames on the multicast group only
    after all users have left the multicast group.

    @param mcast_addr
    The media address of the multicast group.

    @return
    This returns SSH_NETCONFIG_ERROR_OK on success.

    */
SshNetconfigError
ssh_netconfig_link_multicast_drop_membership(uint32_t ifnum,
                                             unsigned char *mcast_addr,
                                             size_t mcast_addr_len);


/* ***************** Accessing and modifying IP addresses *******************/

/*  Address flags. */

/** Broadcast address is defined in SshNetconfigInterfaceAddr. */
#define SSH_NETCONFIG_ADDR_BROADCAST                0x0001

/** Address state is tentative. */
#define SSH_NETCONFIG_ADDR_TENTATIVE                0x0002

typedef struct SshNetconfigInterfaceAddrRec
{
    SshIpAddrStruct address;
    SshIpAddrStruct broadcast;
    uint32_t flags;
} SshNetconfigInterfaceAddrStruct, *SshNetconfigInterfaceAddr;

/** Fetch all IP addresses from interface 'ifnum'.

    @param addresses
    An array of 'num_addresses' interface address structures, which
    must be allocated by the caller.

    @return
    The function returns SSH_NETCONFIG_ERROR_OK on success and fills
    'addresses' with address data and sets 'num_addresses' to indicate
    the number of addresses returned. If an interface has more than
    'num_addresses' addresses, then this function returns
    SSH_NETCONFIG_ERROR_OUT_OF_MEMORY, and the caller should retry
    with a larger value of 'num_addresses'.

    */
SshNetconfigError
ssh_netconfig_get_addresses(uint32_t ifnum,
                            uint32_t *num_addresses,
                            SshNetconfigInterfaceAddr addresses);

/** Add an IP address 'address' for interface 'ifnum'. Caller must set the
    netmask / prefix length for 'address'.

    @return
    This returns SSH_NETCONFIG_ERROR_OK on success.

    */
SshNetconfigError
ssh_netconfig_add_address(uint32_t ifnum,
                          SshNetconfigInterfaceAddr address);

/** Delete an IP address 'address' from interface 'ifnum'. Caller must set the
    netmask / prefix length for 'address'.

    @return
    This returns SSH_NETCONFIG_ERROR_OK on success.

    */
SshNetconfigError
ssh_netconfig_del_address(uint32_t ifnum,
                          SshNetconfigInterfaceAddr address);

/** Flush all IP addresses from interface 'ifnum'.

    @return
    This returns SSH_NETCONFIG_ERROR_OK on success.

    */
SshNetconfigError
ssh_netconfig_flush_addresses(uint32_t ifnum);


/* ******************** Accessing and modifying routing tables **************/

/* Route flags. */
/* None at the moment. */
/* #define SSH_NETCONFIG_ROUTE_* */

typedef struct SshNetconfigRouteRec
{
    SshIpAddrStruct prefix;
    SshIpAddrStruct gateway;
    int routing_instance_id;
    uint32_t ifnum;
    uint32_t metric;
    uint32_t flags;
} SshNetconfigRouteStruct, *SshNetconfigRoute;

/** Fetch routes matching 'prefix'. If 'prefix' is NULL then all
    routes will be returned.

    @param routes
    An array of 'num_routes' SshNetconfigRoute structures, which must
    be allocated by the caller.

    @return
    The function returns SSH_NETCONFIG_ERROR_OK on success and fills
    'routes' with route data and sets 'num_routes' to indicate the
    number of routes returned. If there are more than 'num_routes'
    matching routes, then this function returns
    SSH_NETCONFIG_ERROR_OUT_OF_MEMORY, and the caller should retry
    with a larger value of 'num_routes'.

    */
SshNetconfigError
ssh_netconfig_get_route(SshIpAddr prefix,
                        uint32_t *num_routes,
                        SshNetconfigRoute routes);

/** Add a route 'route'. If 'route->gateway' is defined, it will be used as
    the next hop. Otherwise the resulting route will be a direct route through.
    'route->ifnum'. */
SshNetconfigError
ssh_netconfig_add_route(SshNetconfigRoute route);

/** Delete route 'route'. */
SshNetconfigError
ssh_netconfig_del_route(SshNetconfigRoute route);

char* ssh_netconfig_get_default_route_ifname();

/** Returns route metric matching 'precedence'.

    @param ipv6
    If 'ipv6' is true, then return metric for an IPv6 route, otherwise
    return metric for an IPv4 route.

    */
uint32_t
ssh_netconfig_route_metric(SshRoutePrecedence precedence, bool ipv6);


/** Select source address to be used for specified destination. */
bool
ssh_netconfig_udp_select_src(SshIpAddr remote_ip,
                             uint16_t remote_port,
                             SshIpAddr local_ip_ret);

/** Return PMTU towards specified destination. */
bool
ssh_netconfig_udp_pmtu(SshIpAddr remote_ip,
                       uint16_t remote_port,
                       uint16_t *pmtu_ret);

/* **************************** Renders *************************************/

/** Renders a SshNetconfigLink. */
int ssh_netconfig_link_render(char *buf, int buf_size, int precision,
                              void *datum);

/** Renders a SshNetconfigRoute. */
int ssh_netconfig_route_render(char *buf, int buf_size, int precision,
                               void *datum);

#endif /* SSHNETCONFIG_H */
