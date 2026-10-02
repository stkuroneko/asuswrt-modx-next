/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   Management utils for the IP interface table.
*/

#ifndef SSH_IP_INTERFACES_H

#define SSH_IP_INTERFACES_H 1


#include "sshinet.h"

/** Size of interface system name. */
#define SSH_INTERFACE_IFNAME_SIZE     64

#define SSH_VRI_NAMESIZE              64

/** Virtual routing instance id **/
typedef int SshVriId;

/** Protocol identifiers.  These identify recognized protocols (packet
    formats) in a portable manner.  This enumeration includes media
    types, but also all recognized higher-level protocols. */
typedef enum
{
    SSH_PROTOCOL_IP4,             /** IPv4 frame */
    SSH_PROTOCOL_IP6,             /** IPv6 frame */
    SSH_PROTOCOL_IPX,             /** IPX frame */
    SSH_PROTOCOL_ETHERNET,        /** Ethernet frame */
    SSH_PROTOCOL_FDDI,            /** FDDI frame */
    SSH_PROTOCOL_TOKENRING,       /** Token Ring frame */
    SSH_PROTOCOL_ARP,             /** ARP frame */
    SSH_PROTOCOL_OTHER,           /** some other type frame */
    SSH_PROTOCOL_NUM_PROTOCOLS    /** must be the last entry! */
} SshPacketProtocol;


/** Data type for an interface number. This type must be atleast as big as
    the system interface index. */
typedef uint32_t SshInterfaceIfnum;

/** Maximum value of interface number.
    All valid interface numbers must be smaller than this value. */
#define SSH_INTERFACE_MAX_IFNUM ((SshInterfaceIfnum) 0xffffffff)

/** Reserved value for invalid interface number. */
#define SSH_INTERFACE_INVALID_IFNUM SSH_INTERFACE_MAX_IFNUM

/** Data structure for representing an address for a network interface. */
typedef struct SshInterfaceAddressRec
{
#ifndef SSH_IPSEC_SMALL
    /** Internal data structures for book-keeping by ip_interfaces.c */
    struct SshInterfaceAddressRec *next_ip;
    struct SshInterfaceAddressRec *next_broadcast;
    void *ctx_ifnum;
#endif /* SSH_IPSEC_SMALL */
    /** Protocol for which the address is. */
    SshPacketProtocol protocol;

    /** The address itself. */
    union
  {
      /** IPv4 and IPv6. */
      struct
    {
        SshIpAddrStruct ip;
        SshIpAddrStruct mask;
        SshIpAddrStruct broadcast;
      } ip;

      /** IPX */
      struct
    {
        uint32_t net;
        unsigned char host[6];
      } ns;
    } addr;
} *SshInterfaceAddress, SshInterfaceAddressStruct;


/** Media direction information. */
typedef struct SshPacketMediaDirectionInfoRec
{
    uint32_t flags;     /* flags */
    size_t mtu_ipv4;    /* mtu for the direction (ipv4) */
#ifdef WITH_IPV6
    size_t mtu_ipv6;    /* mtu for the direction (ipv6) */
#endif /* WITH_IPV6 */
} *SshPacketMediaDirectionInfo, SshPacketMediaDirectionInfoStruct;

/** Flag values for flags in SshInterface */
/* Interface type */
#define SSH_INTERFACE_FLAG_VIP         0x0001
#define SSH_INTERFACE_FLAG_POINTOPOINT 0x0002
#define SSH_INTERFACE_FLAG_BROADCAST   0x0004
/* Interface link status */
#define SSH_INTERFACE_FLAG_LINK_DOWN   0x0100

/** Data structure for providing information about a network
    interface.  The address lists in this structure are
    comma-separated lists of the format "proto/addr", where proto is a
    protocol number defined above. */
typedef struct
{
    SshPacketMediaDirectionInfoStruct to_protocol;
    SshPacketMediaDirectionInfoStruct to_adapter;
    char name[SSH_INTERFACE_IFNAME_SIZE]; /** system name for the
                                                interface */
    SshInterfaceIfnum ifnum;      /** Interface number */
    uint32_t num_addrs;          /** Number of addresses for the
                                      interface. */
    SshInterfaceAddress addrs;    /** xmallocated array of address
                                      structures. */
    unsigned char media_addr[16]; /** MAC address, medium size and format */
    size_t media_addr_len;        /** Length of the MAC address. */
    SshVriId routing_instance_id; /** Vrf routing instance identifier. */
    /** routing instance name */
    char routing_instance_name[SSH_VRI_NAMESIZE];

    uint32_t flags;              /** Flags for the interface. */

#ifndef SSH_IPSEC_SMALL
    /** Context pointer related to ifnum. For internal book-keeping by
       ip_interfaces.c */
    void *ctx_ifnum;
#endif /* SSH_IPSEC_SMALL */

    /** Context pointer for owner/user for this SshInterface.
        Can be used for e.g. storing interface-specific
        NAT-configuration. */
    void *ctx_user;
} SshInterface;



/** Error codes for route add / remove functions. */
typedef enum {
  SSH_ROUTE_ERROR_OK = 0,
  SSH_ROUTE_ERROR_NONEXISTENT = 1,
  SSH_ROUTE_ERROR_OUT_OF_MEMORY = 2,
  SSH_ROUTE_ERROR_UNDEFINED = 255
} SshRouteError;

/** Flag values for the route add / remove functions. */

/** Ignore non-existent routes when attempting to remove the route. */
#define SSH_ROUTE_FLAG_IGNORE_NONEXISTENT   0x0001

/** Data structure for routing key, used in route lookups and routing table
    manipulation.

    Note that on platforms that do not support policy routing, the route lookup
    uses only the destination address. On other platforms other fields of the
    SshRouteKey may be used in the route lookup. */
typedef struct SshRouteKeyRec
{
    /** Destination address, mandatory */
    SshIpAddrStruct dst;
    /** Source address, optional */
    SshIpAddrStruct src;
    /** IP protocol identifier, optional */
    SshInetIPProtocolID ipproto;
    /** Interface number, optional.
        Note that this field specifies either the inbound interface number
        or the outbound interface number, depending on the value of the
        'selector' field. */
    uint32_t ifnum;

    /** Routing instance */
    SshVriId routing_instance_id;

    /** Bitmap of selectors that are to be used in the route lookup.
        Use the provided macros to add selectors to the routing key,
        do not access this field directly. The highest 3 bits of
        'selector' are reserved for flags defined below. */
    uint32_t selector;
} *SshRouteKey, SshRouteKeyStruct;


/** Global definitions for virtual routing id's. */
#define SSH_VRI_ID_GLOBAL 0
#define SSH_VRI_ID_ANY (-1)

#ifdef HAVE_WRL_VRF
#define SSH_VRI_NAME_GLOBAL "0"
#else /* HAVE_WRL_VRF */
#define SSH_VRI_NAME_GLOBAL "global"
#endif /* HAVE_WRL_VRF */


/* The SshIpInterfaces structure is used to encapsulate the main
   interface table manipulation. All modifications to the table
   should go through the API defined in this file, to keep any
   encapsulated data structures used to speed up lookups consistent.

   If any of the mutator functions return failure, it is because
   they were unable to allocate memory for updating any lookup
   data structures. */

typedef struct SshIpInterfacesRec
{
    /* Number of interfaces */
    uint32_t nifs;
    /* Number of allocated entries in 'ifs' */
    uint32_t ifs_size;
    /* Table of interface entries */
    SshInterface *ifs;

#ifndef SSH_IPSEC_SMALL
    /* Map from ifnum to interface */
    SshInterface **map_from_ifnum;

    /* Map from IP address to interface */
    struct SshInterfaceAddressRec **map_from_ip;

    /* Map from broadcast address to interface */
    struct SshInterfaceAddressRec **map_from_broadcast;
#endif /* SSH_IPSEC_SMALL */
} *SshIpInterfaces, SshIpInterfacesStruct;


/*********************** Interface Table Initialization *********************/

/* There are two alternative ways for interface table initialization:

   1. The hard way:
      ssh_ip_init_interfaces(interfaces);
      for (i = 0; i < nifs; i++)
        ssh_ip_init_interfaces_add(interface, &ifs[i]);
      ssh_ip_init_interfaces_done(interface);

      It is safe to call ssh_ip_uninit_interfaces() in any error case.

   2. The easy way:
      ssh_ip_init_interfaces_from_table(interfaces, ifs, nifs);

      If this call fails, then the interface table is left in an
      uninitialized state.
*/

/* The ssh_ip_init_interfaces() function initializes an uninitialized
   SshIpInterfaces structure. It returns false if it fails. If it fails
   it is still safe to call ssh_ip_uninit_interfaces() for 'interfaces'. */
bool
ssh_ip_init_interfaces(
        SshIpInterfaces interfaces);

/* The ssh_ip_init_interfaces_add() function adds an interface to the
   interface list. This function is used for performing a batch of
   interface additions to the interface table. The caller must call
   ssh_ip_init_interfaces_done() to finalize the job before any lookup
   functions are called for the interface table. This returns false if
   it fails. */
bool
ssh_ip_init_interfaces_add(
        SshIpInterfaces interfaces,
        const SshInterface *iface);

/* The ssh_ip_init_interfaces_done() function finalizes interface table
   initialization. It returns false if it fails and in this case the
   caller must call ssh_ip_uninit_interfaces(). */
bool
ssh_ip_init_interfaces_done(
        SshIpInterfaces interfaces);

/* ssh_ip_uninit_interfaces() frees the resources allocated
   for 'interfaces' in a previous initialization. */
void
ssh_ip_uninit_interfaces(
        SshIpInterfaces interfaces);

/* The ssh_ip_init_interfaces_from_table() initializes an uninitialized
   SshIpInterfaces structure, adds the 'nifs' interfaces in the array
   'table' and finalizes interface table initialization. On error it
   uninitializes the interface table and returns false. This conviniency
   function can be used as a substitution for the above functions. */
bool
ssh_ip_init_interfaces_from_table(
        SshIpInterfaces interfaces,
        SshInterface *table,
        uint32_t nifs);


/*************** Adding Interfaces and Addresses to Interface Table *********/

/* ssh_ip_add_interface() adds an interface to the table
   'interfaces'. It returns false if it fails. If it fails,
   the table is still in a consistent state, but without
   'iface' added to it. */
SshInterface *
ssh_ip_add_interface(
        SshIpInterfaces interfaces,
        const SshInterface *iface);

/* ssh_ip_add_interface_address() adds address 'address' to the table
   'iface'. It returns false if it fails. If it fails, the table is
   left in an consistent state. */
bool
ssh_ip_add_interface_address(
        SshIpInterfaces interfaces,
        SshInterface *iface,
        const SshInterfaceAddress address);

/** Compare the interface information in 'ifp1' and 'ifp2'. Returns true
    if the interfaces are equivalent and false otherwise. */
bool
ssh_ip_interface_compare(
        SshInterface *ifp1,
        SshInterface *ifp2);


/*********************** Interface Table Lookup *****************************/

/* ssh_ip_get_interface_by_subnet() returns an interface which
   has a subnet which contains the address 'ip'. It returns NULL
   if no such interface exists. */
SshInterface *
ssh_ip_get_interface_by_subnet(
        SshIpInterfaces interfaces,
        const SshIpAddr ip,
        SshVriId routing_instance_id);

/* ssh_ip_get_interface_by_broadcast() returns an interface which
   has a broadcast address of 'ip'. It returns NULL if no such
   interface exists. */
SshInterface *
ssh_ip_get_interface_by_broadcast(
        SshIpInterfaces interfaces,
        const SshIpAddr ip,
        SshVriId routing_instance_id);

/* ssh_ip_get_interface_by_ifnum() returns the interface which
   has interface number 'ifnum'. It returns NULL if no such interface
   exists. */
SshInterface *
ssh_ip_get_interface_by_ifnum(
        SshIpInterfaces interfaces,
        uint32_t ifnum);

/* ssh_ip_get_interface_flags_by_ifnum() returns the interface flags which
   has interface number 'ifnum'. It returns 0 if no such interface
   exists or if the flags really are 0. */
uint32_t
ssh_ip_get_interface_flags_by_ifnum(
        SshIpInterfaces interfaces,
        uint32_t ifnum);

/* ssh_ip_get_interface_by_ip() returns an interface which has
   IP address 'ip'. */
SshInterface *
ssh_ip_get_interface_by_ip(
        SshIpInterfaces interfaces,
        const SshIpAddr ip,
        int routing_instance_id);

/* ssh_ip_enumerate_start returns the interface number of the first
   interface, or SSH_INVALID_INDEX if no such interface exists. */
uint32_t
ssh_ip_enumerate_start(
        SshIpInterfaces interfaces);

/* ssh_ip_enumerate_next returns the interface number of the interface
   that follows the interface identified by number 'ifnum', or
   SSH_INVALID_IFNUM if no such interface exists. */
uint32_t
ssh_ip_enumerate_next(
        SshIpInterfaces interfaces,
        uint32_t ifnum);

const char *
ssh_ip_get_interface_vri_name(
        SshIpInterfaces interfaces,
        int routing_instance_id);

int
ssh_ip_get_interface_vri_id(
        SshIpInterfaces interfaces,
        const char *routing_instance_name);

#endif /* SSH_IP_INTERFACES_H */
