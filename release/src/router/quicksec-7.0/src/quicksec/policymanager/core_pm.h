/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
       Top-level policy management API for QuickSec.

       @description
       This API defines means for the following operations:

       - Creating, configuring and destroying the Policy Manager object:
         ssh_pm_create, ssh_pm_destroy, ssh_pm_set_params,
         etc. (ssh_pm_set_*)
       - Accessing network interfaces at the system:
         - ssh_pm_interface_get_address, ssh_pm_interface_get_broadcast,
           ssh_pm_interface_get_netmask, ssh_pm_interface_enumerate_start,
           etc. (ssh_pm_interface_*, ssh_pm_get_interface*)
         - ssh_pm_get_interface_name, ssh_pm_get_interface_number
       - Processing of top level policy objects:
         - rules: ssh_pm_rule_create, ssh_pm_rule_add,
           ssh_pm_rule_delete, etc. (ssh_pm_rule*)
         - services: ssh_pm_service_create, ssh_pm_service_compare,
           ssh_pm_service_destroy, etc. (ssh_pm_service*)
         - use of new policy: ssh_pm_commit, ssh_pm_abort
       - Configuring system information into the Policy Manager:
         ssh_pm_configure_interface, ssh_pm_configure_route,
         etc. (ssh_pm_configure*)
       - Configuring auditing:
         ssh_pm_create_audit_module, ssh_pm_attach_audit_module,
         SSH_PM_AUDIT_ALL, SSH_PM_AUDIT_POLICY, etc. (ssh_pm_*audit*)
       - Accessing rule information:
         ssh_pm_get_rule_info, ssh_pm_get_rule_stats,
         etc. (ssh_pm_get_rule*)
       - Using DNS name resolution for policies:
         ssh_pm_indicate_dns_change, ssh_pm_rule_get_dns_status.

   Note: This header file is not intended to be included directly.
   The quicksecpm.h header file should be included instead.
*/

#ifndef CORE_PM_H
#define CORE_PM_H

#include "sshaudit.h"
#include "sshoperation.h"
#include "sshpdbg.h"
#include "sshikev2-initiator.h"
#include "sshikev2-payloads.h"

/** Data type for the policy manager object handle. */
typedef struct SshPmRec *SshPm;

/*--------------------------------------------------------------------*/
/* Parameters for IPsec tunnels                                       */
/*--------------------------------------------------------------------*/

/*  These bit masks define the characteristics of IPsec tunnels
    (transforms and algorithms).  The bit masks for encryption
    algorithms, MAC algorithms, compression algorithms and transforms
    are designed to be non-overlapping so that they can be stored in
    the same 64-bit variable. */

typedef uint64_t SshPmTransform;

/*  Bit masks for encryption algorithms. */
#define SSH_PM_CRYPT_EXT1       0x00000001
#define SSH_PM_CRYPT_EXT2       0x00000002
#define SSH_PM_CRYPT_NULL       0x00000004 /** Allow no encryption. */
#define SSH_PM_CRYPT_DES        0x00000008 /** 56 bit key. */
#define SSH_PM_CRYPT_3DES       0x00000010 /** 168 bit key. */
#define SSH_PM_CRYPT_AES        0x00000020 /** 128 bit key. */
#define SSH_PM_CRYPT_AES_CTR    0x00000040 /** AES counter mode,
                                               128 bit key. */
#define SSH_PM_CRYPT_AES_GCM    0x00000080 /** AES GCM mode, 128 bit key,
                                               128 bit digest. */
#define SSH_PM_CRYPT_AES_GCM_8  0x00000100 /** AES GCM mode, 128 bit key,
                                               64 bit digest. */
#define SSH_PM_CRYPT_AES_GCM_12 0x00000200 /** AES GCM mode, 128 bit key,
                                               64 bit digest. */
#define SSH_PM_CRYPT_NULL_AUTH_AES_GMAC \
                                0x00000400 /** AES GCM-GMAC, no encryption. */
#define SSH_PM_CRYPT_AES_CCM    0x00000800 /** AES CCM mode, 128 bit key,
                                               128 bit digest. */
#define SSH_PM_CRYPT_AES_CCM_8  0x00001000 /** AES CCM mode, 128 bit key,
                                               64 bit digest. */
#define SSH_PM_CRYPT_AES_CCM_12 0x00002000 /** AES CCM mode, 128 bit key,
                                               64 bit digest. */
#define SSH_PM_CRYPT_MASK       0x00003fff /** Mask for ciphers. */
#define SSH_PM_COMBINED_MASK    0x00003f80 /** Mask for combined algorithms. */

/*  Bit masks for MAC and hash algorithms. */
#define SSH_PM_MAC_EXT1         0x00004000
#define SSH_PM_MAC_EXT2         0x00008000
#define SSH_PM_MAC_HMAC_MD5     0x00010000 /** 128 bit key. */
#define SSH_PM_MAC_HMAC_SHA1    0x00020000 /** 160 bit key. */
#define SSH_PM_MAC_XCBC_AES     0x00040000 /** 128 bit key. */
#define SSH_PM_MAC_HMAC_SHA2    0x00080000 /** 256-512 bit key. */
#define SSH_PM_MAC_MASK         0x000fc000 /** Mask for MACs. */

/*  Bit masks for compression algorithms. */
#define SSH_PM_COMPRESS_DEFLATE 0x00100000 /** Compress using deflate. */
#define SSH_PM_COMPRESS_LZS     0x00200000 /** Compress using LZS. */
#define SSH_PM_COMPRESS_MASK    0x00300000 /** Mask for compressions. */

/*  Bit masks for IPSec transforms. */
#define SSH_PM_IPSEC_ESP        0x00400000 /** Perform ESP. */
#define SSH_PM_IPSEC_IPCOMP     0x00800000 /** Perform IPPCP. */
#define SSH_PM_IPSEC_AH         0x01000000 /** Perform AH. */
#define SSH_PM_IPSEC_MASK       0x01c00000 /** Mask for transforms. */

/*  Additional transforms / transforms options. */
#define SSH_PM_IPSEC_TUNNEL     0x02000000 /** Use tunnel mode (IP-in-IP). */
#define SSH_PM_IPSEC_ANTIREPLAY 0x08000000 /*  (int) enable anti-replay. */
#define SSH_PM_IPSEC_NATT       0x20000000 /*  (int) NAT-T UDP encap. */
#define SSH_PM_IPSEC_L2TP       0x40000000 /*  (int) L2TP UDP+PPP encap. */
#define SSH_PM_IPSEC_LONGSEQ    0x80000000 /** Use 64 bit sequence number. */
/* (LL is added to following values to make them long long, otherwise they are
 * just long and failing on some 32 bit systems) */
#define SSH_PM_IPSEC_SHORTSEQ  0x100000000LL /** Use 32 bit sequence number. */

/*--------------------------------------------------------------------*/
/* Constants                                                          */
/*--------------------------------------------------------------------*/

/** Value used to indicate an invalid 32-bit index (of any kind) used
    in QuickSec.  This is guaranteed to be a very large number. */
#define SSH_IPSEC_INVALID_INDEX         ((uint32_t)0xddffffff)


typedef struct SshPmGlobalStatsRec
{
    /* Current operational statistics. */
    uint32_t num_p1_active;
    uint32_t num_qm_active;

    /* Cumulative statistics. */
    uint32_t num_p1_done;
    uint32_t num_p1_failed;
    uint32_t num_p1_rekeyed;

    uint32_t num_qm_done;
    uint32_t num_qm_failed;

    /** The size of rule object in Policy Manager. */
    uint32_t rule_struct_size;

    /** The size of tunnel object in Policy Manager. */
    uint32_t tunnel_struct_size;

} SshPmGlobalStatsStruct, *SshPmGlobalStats;

typedef struct SshPmIPsecSaStatsRec
{
    uint32_t created;
    uint32_t rekeyed;
    uint32_t deleted;
} SshPmIPsecSaStatsStruct, *SshPmIPsecSaStats;

typedef struct SshPmPolicyStatsRec
{
    uint32_t drop_rule_cnt;
    uint32_t pass_rule_cnt;
} SshPmPolicyStatsStruct, *SshPmPolicyStats;


/* ********************* Flag bits for IPSec tunnels ************************/

/*  These bit masks define additional behavior of the initiator and
    responder for IPSec tunnels.  The SSH_PM_T_* values are common to
    initiator and responder; the SSH_PM_TR_* values affect the
    responder only, and the SSH_PM_TI_* flags affect the initiator
    only.  Note that a gateway may act as both an initiator and as a
    responder for a tunnel, and thus none of the flags may overlap. */

/*  Flags common to both initiator and responder. */
#define SSH_PM_T_PER_HOST_SA            0x00000001 /** Use per-host SAs. */
#define SSH_PM_T_PER_PORT_SA            0x00000002 /** Use per-port SAs. */
#define SSH_PM_T_TRANSPORT_MODE         0x00000004  /** As initiator propose
                                                        transport mode,
                                                        as responder allow
                                                        transport mode. */
#define SSH_PM_T_PORT_NAT               0x00000010 /** NAT decapsulated pkts.*/
#define SSH_PM_T_NO_CERT_CHAINS         0x00000020 /** Do not send chains. */
#ifdef SSHDIST_IPSEC_MOBIKE
#define SSH_PM_T_MOBIKE                 0x00000080 /** Enable MOBIKE. */
#endif /* SSHDIST_IPSEC_MOBIKE */
#define SSH_PM_T_NO_NATS_ALLOWED        0x00000100 /** Fail negotiation if NAT
                                                       is detected. */
#define SSH_PM_T_TCPENCAP               0x00000200 /** Enable IPsec over TCP.*/
#define SSH_PM_T_DISABLE_NATT           0x00000400 /** Do not initiate NAT-T
                                                       or reply NAT-T. */
#define SSH_PM_T_XAUTH_METHODS          0x00000800 /** IKEv1 Xauth methods.*/

/* Flags that affect the initiator only. */
#define SSH_PM_TI_DONT_INITIATE         0x00001000 /** Don't initiate IKE SA.*/
#define SSH_PM_TI_DELAYED_OPEN          0x00002000 /** Open on first packet.*/
#ifdef SSHDIST_IKEV1
#define SSH_PM_TI_AGGRESSIVE_MODE       0x00004000 /** Aggressive mode for
                                                       PSK. */
#endif /* SSHDIST_IKEV1 */
#define SSH_PM_TI_NO_TRIGGER_PACKET     0x00008000 /** No trigger packet sent.
                                                    */
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
#define SSH_PM_TI_CFGMODE               0x00010000 /** Use IKE config mode. */
#define SSH_PM_TI_L2TP                  0x00020000 /** L2TP encapsulate. */

#define SSH_PM_TI_INTERFACE_TRIGGER     0x00040000 /** Virtual interface
                                                       trigger. */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */
#define SSH_PM_TI_START_WITH_NATT       0x00080000 /** Start IKE with NAT-T. */
/* For backwards compatibility */
#define SSH_PM_TI_DONT_INITIATE_NATT    SSH_PM_T_DISABLE_NATT

/* Flags that affect the responder only. */
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
#define SSH_PM_TR_ALLOW_CFGMODE         0x00100000 /** Allow config mode. */
#define SSH_PM_TR_ALLOW_L2TP            0x00200000 /** Allow L2TP. */
#define SSH_PM_TR_REQUIRE_CFGMODE       0x00400000 /** Require config mode for
                                                       IKEv2 SAs. */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */

#ifdef SSHDIST_IKE_EAP_AUTH
#define SSH_PM_TR_EAP_REQUEST_ID        0x02000000 /** EAP, request client ID.
                                                    */
#define SSH_PM_T_EAP_ONLY_AUTH          0x04000000 /** EAP only authentication
                                                    */
#endif /* SSHDIST_IKE_EAP_AUTH */


/*--------------------------------------------------------------------*/
/* Data types.                                                        */
/*--------------------------------------------------------------------*/

/** Data type for a top level policy tunnel object handle. A tunnel
    object specifies IKE and IPSec algorithms, peers and other
    tunneling parameters. */
typedef struct SshPmTunnelRec *SshPmTunnel;

/** Data type for a top level policy rule object handle.  A rule binds
    together optional from and to tunnels, service, and rule selectors
    (IP addresses, DNS names, interfaces, etc). */
typedef struct SshPmRuleRec *SshPmRule;

typedef struct SshPmAuthDomainRec *SshPmAuthDomain;


/*--------------------------------------------------------------------*/
/* Callback types.                                                    */
/*--------------------------------------------------------------------*/

/** A callback function of this type is called to report success of
    opening the policy manager.  If the argument 'pm' is NULL, the
    policy manager creation failed.  Otherwise, it specifies a Policy
    Manager object that is used to configure IPsec policy. */
typedef void (*SshPmCreateCB)(SshPm pm, void *context);

/** A callback function of this type is called when a Policy Manager
    object is destroyed. */
typedef void (*SshPmDestroyCB)(void *context);

/** Callback function used to indicate whether an operation was
    successful or not.

    On return:
    The value of 'success' is true on success, and false on failure. */
typedef void (*SshPmStatusCB)(SshPm pm, bool success, void *context);

/** Callback function used to return indices.

    @param index
    The 'index' argument has the value SSH_IPSEC_INVALID_INDEX on
    error and a valid index otherwise. */
typedef void (*SshPmIndexCB)(SshPm pm, uint32_t index, void *context);


/*--------------------------------------------------------------------*/
/* Top-level functions.                                               */
/*--------------------------------------------------------------------*/

/** Parameters for ssh_pm_create; the parameters are static so that
    you cannot change them after Policy Manager has been created. */
struct SshPmParamsRec
{
    /** The name of the host - this is used, for example, in L2TP to
        identify the host; this should be a human readable name for the
        machine (DNS name, etc.); if the hostname is unset, no hostname
        is send to remote machines. */
    char *hostname;

    /** Only bind IKE sockets to these IP addresses; this means IKE will
        only respond to requests at these addresses. */
    size_t ike_addrs_count;

    /** An array containing 'ike_addrs_count' elements each containing
    one IP address structure; it must be dynamic memory allocated with
    ssh_malloc(); Policy Manager steals that pointer and frees it upon
    exit. */
    SshIpAddrStruct *ike_addrs;

    /** Optional parameters for the IKE library. The 'externalkey' and
        'accelerator_short_name' parameters cannot be set in this manner,
        they are overwritten by the Policy Manager. */
    SshIkev2Params ike_params;

    /** The number of IKE ports. */
    uint16_t num_ike_ports;

    /** Local port number to use for IKE; an IKE server
        will be started for each specified port on each local
        address. */
    uint16_t local_ike_ports[SSH_IPSEC_MAX_IKE_PORTS];

    /** Port number to use for IKE NAT Traversal; an IKE server
        will be started for each specified port on each local
        address. */
    uint16_t local_ike_natt_ports[SSH_IPSEC_MAX_IKE_PORTS];

    /** Remote port number to use for IKE. */
    uint16_t remote_ike_ports[SSH_IPSEC_MAX_IKE_PORTS];

    /** Remote port number to use for IKE NAT Traversal. */
    uint16_t remote_ike_natt_ports[SSH_IPSEC_MAX_IKE_PORTS];

#ifdef SSHDIST_EXTERNALKEY
    /** Externalkey accelerator, type. */
    char *ek_accelerator_type;
    /** Externalkey accelerator, initialization information. */
    char *ek_accelerator_init_info;
#endif /* SSHDIST_EXTERNALKEY */

    /** Do not install default pass rules for DNS traffic originating
        from the local host. If this flag is set, the application using
        this API must configure suitable rules for handling DNS traffic
        from the local host. */

#define SSH_PM_PARAM_FLAG_NO_DNS_FROM_LOCAL_PASS_RULE     0x0001

    /** Disable default DHCP client pass-by rule. */
#define SSH_PM_PARAM_FLAG_DISABLE_DHCP_CLIENT_PASSBY_RULE 0x0002

    /** Enable default DHCP server pass-by rule. */
#define SSH_PM_PARAM_FLAG_ENABLE_DHCP_SERVER_PASSBY_RULE  0x0004

  /** Always request an cookie when acting as an IKEv2 responder */
#define SSH_PM_FLAG_REQUIRE_COOKIE                         0x0008

    /** Global Policy Manager flags. */
    uint32_t flags;

    /** DHCP address pool enabled */
    bool dhcp_ras_enabled;

    /** NIST 800-131A key and algorithm restrictions */
#define SSH_PM_PARAM_ALGORITHMS_NIST_800_131A             0x0001

    /** Key strength requirements and algorithm set restrictions enforced.
        Currently NIST 800-131A key and algorithm restrictions supported. */
    uint32_t enable_key_restrictions;
};

typedef struct SshPmParamsRec SshPmParamsStruct;
typedef struct SshPmParamsRec *SshPmParams;

/** This function initializes libraries needed by policy manager.
    This function must be called after the event loop has been
    initialized and before it is started.

    */
void
ssh_pm_library_init();

/** This function uninitializes libraries needed by policy manager.
    This function must be called after the event loop has returned
    and it is uninitialized.

    */
void
ssh_pm_library_uninit();

/** This function creates a Policy Manager object.

    This calls the callback function 'callback' to report the success
    of creating Policy Manager.

    @param params
    The argument 'params' specifies optional configuration parameters
    for the Policy Manager.  These parameters are static by nature.
    You cannot change them after Policy Manager is created.

    The argument 'params' can have the value NULL or any field in the
    parameters structure can have the value 0 or NULL.  In that case
    sane default values will be used.  The values of the `params'
    structure must remain valid as long as the control remains the
    ssh_pm_create function.

    @param callback
    The callback function 'callback' is called after the Policy Manager
    creation.

    */

void
ssh_pm_create(
        SshPmParams params,
        SshPmCreateCB callback,
        void *context);

/** This function destroys the Policy Manager object, frees any memory
    it has allocated, and closes the connection to the dataplane.

    Note that any policy objects created by the user must be freed by
    the user.

    @param callback
    The function will call the callback function 'callback' when the
    destroy operation is complete.  The callback may also be NULL.

    */
void
ssh_pm_destroy(
        SshPm pm,
        SshPmDestroyCB callback,
        void *context);

/** Disable high-level policy lookups in Policy Manager.
    While the high-level policy lookups are disabled, Policy Manager
    ignores any events that would require a high-level policy lookup
    (for example trigger and rekey events or policy calls from the IKE
    library).

    Note: It is an error to call this multiple times without calling
    ssh_pm_enable_policy_lookups in between.

    @param callback
    The function will call the callback function 'callback' when the
    high-level policy lookups are disabled.  The callback may also be
    NULL.

    */
void
ssh_pm_disable_policy_lookups(
        SshPm pm,
        SshPmStatusCB callback,
        void *context);

/** Enables high-level policy lookups in Policy Manager.

    Note: It is an error to call this before the previous
    ssh_pm_disable_policy_lookups has completed.

    @param callback
    The function will call the callback function 'callback' when the
    high-level policy lookups are enabled.  The callback may also be
    NULL.

    */
void
ssh_pm_enable_policy_lookups(
        SshPm pm,
        SshPmStatusCB callback,
        void *context);

/** Set the Policy Manager flags during runtime. */
void
ssh_pm_set_flags(
        SshPm pm,
        uint32_t flags);

/** Start certificate access server to provide hash-and-url IKEv2
    services on given 'port'. Reconfiguration to different port can
    be done without stopping the server. The caller of this needs to
    make sure that the current policy allows access to this service
    (preferably without IPSEC protection). A rule that allows access
    SRC: (ANY) <-> DST: (TCP:PORT:TO-LOCAL) is recommended. */
bool
ssh_pm_cert_access_server_start(
        SshPm pm,
        uint16_t port,
        uint32_t flags);

/** Send certificate chains as a single bundle as defined by
    RFC 4306 Section 3.6 */
#define SSH_PM_CERT_ACCESS_SERVER_FLAGS_SEND_BUNDLES 0x0001

/** Stop the certificate access server for providing hash-and-url IKEv2
    services. */
void
ssh_pm_cert_access_server_stop(SshPm pm);

/** Function returns the number of network interfaces managed by the
    Policy Manager. */
uint32_t
ssh_pm_get_number_of_interfaces(SshPm pm);


/** Starts the iteration of interfaces.

    The function returns true if there are any interfaces to iterate
    and sets 'ifnum_return' to the first interface index. Otherwise
    the function returns false and does not set 'ifnum_return'. */
bool
ssh_pm_interface_enumerate_start(
        SshPm pm,
        uint32_t *ifnum_return);


/** Continues the iteration of interfaces from the interface following
    the interface identified by 'ifnum'.

    The function returns true if there are interfaces following
    interface 'ifnum' and sets 'ifnum_return' to the index of the
    following interface. Otherwise the function returns false and
    does not set 'ifnum_return'. */
bool
ssh_pm_interface_enumerate_next(
        SshPm pm,
        uint32_t ifnum,
        uint32_t *ifnum_return);


/** Returns the name of the interface identified by number `ifnum'.

    The function returns true if there are an interface at the index
    `ifnum' and false if the interface number was out of range.  The
    function sets `ifname_return' to point to the name of the
    interface or NULL if the interface is not currently active.  The
    value, pointed by `ifname_return' is valid until the control
    returns to the event loop. */
bool
ssh_pm_get_interface_name(
        SshPm pm,
        uint32_t ifnum,
        char **ifname_return);

/** Returns the number of IP addresses, configured for the interface
    identified by `ifnum'.

    The function returns true if the interface index `ifnum' is valid
    and false otherwise.  The function return the address count in
    `addr_count_return'. */
bool
ssh_pm_interface_get_number_of_addresses(
        SshPm pm,
        uint32_t ifnum,
        uint32_t *addr_count_return);

/** Returns the IP address at the index `addrnum' of the interface
    identified by `ifnum'.

    The function returns true if the interface number `ifnum' and
    address number `addrnum' were valid and false otherwise.  The
    function copies the IP address into the variable, pointed by the
    argument `addr'. */
bool
ssh_pm_interface_get_address(
        SshPm pm,
        uint32_t ifnum,
        uint32_t addrnum,
        SshIpAddr addr);

/** Returns the IP netmask at the index `addrnum' of the interface
    identified by `ifnum'.

    The function returns true if the interface number `ifnum' and
    address number `addrnum' were valid and false otherwise.  The
    function copies the IP netmask into the variable, pointed by the
    argument `netmask'. */
bool
ssh_pm_interface_get_netmask(
        SshPm pm,
        uint32_t ifnum,
        uint32_t addrnum,
        SshIpAddr netmask);

/** Returns the broadcast address at the index `addrnum' of the
    interface idetified by `ifnum'.

    The function returns true if the interface number `ifnum' and
    address number `addrnum' were valid and false otherwise.  The
    function copies the broadcast address into the variable, pointed
    by the argument `broadcast'. */
bool
ssh_pm_interface_get_broadcast(
        SshPm pm,
        uint32_t ifnum,
        uint32_t addrnum,
        SshIpAddr broadcast);

/** Returns the routing instance id of the interface idetified by `ifnum'.

    The function returns true if the interface number `ifnum' is
    valid and false otherwise.  The function copies the routing instance
    id into the variable, pointed by the argument `id_return'. */
bool
ssh_pm_interface_get_routing_instance_id(
        SshPm pm,
        uint32_t ifnum,
        SshVriId *id_return);

/** Returns the routing instance name of the interface idetified by `ifnum'.

    The function returns true if the interface number `ifnum' is
    valid and false otherwise.  The function sets `riname_return' to
    point to the name of the interface.  The value, pointed by
    `ifname_return' is valid until the control returns to the event loop. */
bool
ssh_pm_get_interface_routing_instance_name(
        SshPm pm,
        uint32_t ifnum,
        const char **riname_return);


/** Finds interface number when given interface name.

    Returns true, if name maps into existing interface. If so, fills
    interface number into ifnum_return, unless it is a NULL
    pointer. The returned 'ifnum_return' can then be used as argument
    to functions ssh_pm_interface_* functions. */
bool
ssh_pm_get_interface_number(
        SshPm pm,
        const char *ifname,
        uint32_t *ifnum_return);


/** Definitions for the IKEv2 fragment sizes. */
#define SSH_PM_IKE_FRAGMENTATION_DISABLED 0
#define SSH_PM_IKE_FRAGMENT_MIN_SIZE 576
#define SSH_PM_IKE_FRAGMENT_MAX_SIZE 1280

/** Disables IKEv2 fragmentation.

    IKEv2 fragmentation is enabled by default and can be disabled with
    a call to this function. */
void
ssh_pm_disable_ike_fragmentation(SshPm pm);

/** Set fragment size for IKEv2 fragmentation.

    The fragment size should be between SSH_PM_IKE_FRAGMENTATION_MIN_SIZE
    and SSH_PM_IKE_FRAGMENTATION_MAX_SIZE. If not defined, the default value
    for the fragment size is SSH_PM_IKE_FRAGMENTATION_MAX_SIZE.

    If this function is called with acceptable parameters after the call to
    ssh_pm_disable_ike_fragmentation, the IKEv2 fragmentation will be
    re-enabled. */
bool
ssh_pm_set_ike_fragment_size(
        SshPm pm,
        int fragment_size);

#ifdef SSHDIST_IKE_REDIRECT

/** Definitions for IKEv2 Redirect phases */

/** IKEv2 Redirect done at phase IKE_INIT */
#define SSH_PM_IKE_REDIRECT_IKE_INIT 0x0001

/** IKEv2 Redirect done at phase IKE_AUTH */
#define SSH_PM_IKE_REDIRECT_IKE_AUTH 0x0002

/** Mask for IKEv2 Redirect phases */
#define SSH_PM_IKE_REDIRECT_MASK     0x0003

/** Disables the global IKE redirect functionality. */
void
ssh_pm_clear_ike_redirect(SshPm pm);

/** Enables the global IKE redirect functionality.

    @param redirect_addr
    The address of the alternative gateway.

    @param phase
    IKEv2 Redirect phase
*/
bool
ssh_pm_set_ike_redirect(
        SshPm pm,
        SshIpAddr redirect_addr,
        uint8_t phase);
#endif /* SSHDIST_IKE_REDIRECT */

/* A callback function of this type is called when the policy manager has
   received and processed an interface change notification. */
typedef void (*SshPmInterfaceChangeCB)(SshPm pm,
                                       void *context);

/** Sets a callback function that is called whenever there are changes in
    interface information. */
void
ssh_pm_set_interface_callback(
        SshPm pm,
        SshPmInterfaceChangeCB callback,
        void *context);

/*--------------------------------------------------------------------*/
/* Policy rule manipulation functions.                                */
/*--------------------------------------------------------------------*/


/*  Public rule flags.
    Values above 0x000fffff are reserved for internal rule flags. */
#define SSH_PM_RULE_PASS                0x00000001 /** Passby. */
#define SSH_PM_RULE_REJECT              0x00000002 /** Drop with ICMP/RST. */
#define SSH_PM_RULE_LOG                 0x00000004 /** Log all connections. */
#define SSH_PM_RULE_RATE_LIMIT          0x00000008 /** Enable rate limiter. */
#ifdef SSHDIST_IPSEC_SCTP_MULTIHOME
#define SSH_PM_RULE_MULTIHOME           0x00000020  /** Rule has SCTP
                                                        multihomed addrs. */
#endif /* SSHDIST_IPSEC_SCTP_MULTIHOME */

#define SSH_PM_RULE_DF_SET              0x00000040  /** Set the DF bit on
                                                        encapsulation. */
#define SSH_PM_RULE_DF_CLEAR            0x00000080  /** Clear the DF bit on
                                                        encapsulation. */
#define SSH_PM_RULE_ADJUST_LOCAL_ADDRESS 0x00000200 /** Use IKE address or
                                                        internal address
                                                        acquired by IKEv1
                                                        config mode to
                                                        override address of
                                                        local traffic
                                                        selector. */
#define SSH_PM_RULE_PASS_UNMODIFIED     0x00000400  /** Set the DF bit on
                                                        encapsulation. */
#ifdef SSHDIST_ISAKMP_CFG_MODE_RULES
#define SSH_PM_RULE_CFGMODE_RULES       0x00000800  /** Don't make an IPsec
                                                        SA from this rule.
                                                        Create rules from
                                                        received internal
                                                        subnets. */
#endif /* SSHDIST_ISAKMP_CFG_MODE_RULES */

/** Create a new policy rule object. The rule is not automatically
    inserted into Policy Manager data structures; instead,
    ssh_pm_rule_add must be called to add the rule, and ssh_pm_commit
    must be called to actually make the rule effective.

    The code that calls this API should attempt to group all rules
    using an identical tunnel to use the same tunnel object; this will
    improve efficiency and may result in fewer IPSec SAs between the
    two hosts/gateways.

    @param pm
    The Policy Manager object to which the rule will be added.

    @param precedence
    Precedence value for the rule.  This argument must be in the range
    0..99 999 999 (10^8 - 1).  Rules with higher precedence values
    take priority over rules with lower preference values (i.e., a
    rule with higher numeric value is considered before any rules with
    a lower precedence value).

    @param flags
    Flags that specify the type of the rule and various actions
    performed by the rule (a rule with no flags is an implicit drop
    rule). This field is a bitmask.

    Specifying PASS means that access from (initiating connections
    from) the SSH_PM_FROM side of the rule is allowed.

    REJECT means that dropped packets/connections should be dropped
    gracefully (sending ICMP or TCP RST back to the sender, with
    automatic rate limitation).  If no PASS or REJECT are specified,
    packets are silently dropped.

    LOG means that every new connection should be logged. 

    @param from_tunnel
    Can be NULL. If non-NULL, this rule will only apply to packets
    arriving from this tunnel (and to return packets on their way to
    that tunnel).

    @param to_tunnel
    Can be NULL. If non-NULL, packets matching this rule will be
    tunneled as indicated by this tunnel. The rule will also apply to
    return packets coming from that tunnel.

    If both 'from_tunnel' and 'to_tunnel' are specified, then
    traffic will be routed between the two remote networks as
    permitted by the rule. The same tunnel objects can be shared
    among many objects.

    @return
    Returns the created rule object, or NULL if an error occurs (e.g.,
    if no more rule objects can be created).

    @see SshPmRule
    @see ssh_pm_rule_add
    @see ssh_pm_rule_free

*/

SshPmRule
ssh_pm_rule_create(
        SshPm pm,
        uint32_t precedence,
        uint32_t flags,
        SshPmTunnel from_tunnel,
        SshPmTunnel to_tunnel);

SshPmRule
ssh_pm_rule_copy(
        SshPm pm,
        SshPmRule rule);

/** This type is used to select which side of the rule ("from" or "to"
    side) is being constrainted. */
typedef enum
{
    SSH_PM_FROM,
    SSH_PM_TO
} SshPmRuleSide;


/** This function adds a traffic selector constraint to the given
    rule.

    This constrains which packets the rule applies to. Only one
    traffic selector can be specified for each side of the rule (it is
    a fatal error to try to add more). This function returns true on
    success and false if the traffic selector could not be parsed. */
bool
ssh_pm_rule_set_traffic_selector(
        SshPmRule rule,
        SshPmRuleSide side,
        const char *traffic_selector);

/** This function adds a traffic selector constraint to the given
    rule. This function behaves exactly as ssh_pm_rule_set_traffic_selector
    execpt the traffic selector is input as a SshIkev2PayloadTS type.
    After this function is called the user must not touch or free "ts",
    it is owned by the policy manager application. The ssh_pm_ts_
    routines can be used to construct the traffic selector 'ts'. */
bool
ssh_pm_rule_set_ts(
        SshPmRule rule,
        SshPmRuleSide side,
        SshIkev2PayloadTS ts);

/** This function sets the VRF routing instance identifier for the rule.

    When the rule is created, its VRF routing instance name is set to
    same value as the tunnel it is attached to. If the rule is not attached
    to a tunnel, the name will default to "global", meaning it belongs to
    the default routing instance. In order to set a name other than the
    default values, this function is used.
    It is not possible to update the rule VRF routing instance identifier
    after the rule has been committed to Policy Manager. Nor is it possible
    to set a name that differs from the name of the attached tunnel.

    @param routing_instance_name
    The VRF routing instance name. This must be valid for the duration
    of the function call.

    @return
    On success this returns true, otherwise false.
*/
bool
ssh_pm_rule_set_routing_instance(
        SshPmRule rule,
        const char *routing_instance_name);

/** Adds an address constraint to the given rule.  This constrains
   which packets the rule applies to. The address must be a DNS name
   resolving to IPv4 or IPv6 address, or an IP address. Only one
   address can be specified on each side of the rule. If multiple
   addresses are to be used, separate rules must be created for each
   of them. This API does not allow for adding port or protocol selectors
   to policy rules which use DNS addresses.

   The function returns true on success and false, if it
   runs out of memory. It is legal for name to be NULL. This clears
   rules dependency from previously assigned DNS name. */
bool
ssh_pm_rule_set_dns(
        SshPmRule rule,
        SshPmRuleSide side,
        const char *name);

#ifdef SSHDIST_IPSEC_SA_EXPORT

/** Maximum length of application specific identifier data. */
#define SSH_PM_APPLICATION_IDENTIFIER_MAX_LENGTH 64

/** Sets the application specific identifier 'id' of length 'id_len' for
    'rule'. `id_len' must not be larger than
    SSH_PM_APPLICATION_IDENTIFIER_MAX_LENGTH. The contents of 'id' are
    completely application-specific and Policy Manager does not use it for
    anything (not even for ssh_pm_rule_compare()).

    @return
    On failure this returns false, and otherwise true.

    */
bool
ssh_pm_rule_set_application_identifier(
        SshPmRule rule,
        const char *id,
        size_t id_len);

/** Returns the application-specific identifier for 'rule' in return
    value parameters 'id' and 'id_len'. When this function is called,
    the value of '*id_len' contains the length of buffer pointed by
    'id'.

    @return
    If the buffer length is too short for the rule's application
    identifier, this fails and returns false. Otherwise this copies the
    rule's application identifier to 'id', sets '*id_len' and returns
    true.

    */
bool
ssh_pm_rule_get_application_identifier(
        SshPmRule rule,
        char *id,
        size_t *id_len);
#endif /* SSHDIST_IPSEC_SA_EXPORT */

/** This function deletes a policy rule.

    This function should be called to delete a rule that has not been
    added to the policy manager databases (i.e. if ssh_pm_rule_add()
    hash not been called for the rule). If the rule has been added to
    the policy manager databases the rule should be freed using
    ssh_pm_rule_delete(). */
void
ssh_pm_rule_free(
        SshPm pm,
        SshPmRule rule);

/** This function adds the given rule to the policy manager databases.

    This returns a handle for the rule that can be used later to
    delete the rule.  This returns SSH_IPSEC_INVALID_INDEX if adding
    the rule failed.  The new rule will not take effect until
    ssh_pm_commit is called. */
uint32_t
ssh_pm_rule_add(
        SshPm pm,
        SshPmRule rule);

/** Lookup PM rule handle by rule id. */
SshPmRule
ssh_pm_rule_lookup(
        SshPm pm,
        uint32_t id);

/** This function deletes a policy rule with the given index.

    The index must have
    been previously returned by ssh_pm_add_rule.  The deletion will
    not take effect until ssh_pm_commit is called. */
void
ssh_pm_rule_delete(
        SshPm pm,
        uint32_t rule_id);

/** This function compares the rules `rule1' and `rule2' for equality.

    The function returns true if the rules are equal and false
    otherwise. Function is intented to be used */
bool
ssh_pm_rule_compare(
        SshPm pm,
        uint32_t rule1,
        uint32_t rule2);

/** This function commits added and deleted rules to the policy
    manager and takes them into use for packet processing.

    This will call the callback when done; if the operation is
    successful, then `success' argument to the callback will be true.
    If adding failed, `success' will be false, in which case
    ssh_pm_abort will have been automatically called. It is illegal to
    call this function a second time before the callback has been
    received. */
void
ssh_pm_commit(
        SshPm pm,
        SshPmStatusCB callback,
        void *context);

/** This function cancels any calls to ssh_pm_rule_{add,delete} since
    the last commit.

    Call restores the configuration to the state where it was
    immediately after the last commit.  Note that the function also
    frees all rules created with the ssh_pm_rule_create() function but
    which have not yet been added to the policy manager with the
    ssh_pm_rule_add() function. */
void
ssh_pm_abort(SshPm pm);


/** Iterates through rule objects in ascending order of rule id.

    @param previous_rule
    The argument 'previous_rule' should be the return value of the
    previous call to this function, or NULL to retrieve the first
    rule.

    @return
    This function returns the next rule after 'previous_rule', or
    the first rule if 'previous_rule' is NULL. If no more rules
    are available, the function returns NULL. */
SshPmRule
ssh_pm_rule_get_next(
        SshPm pm,
        SshPmRule previous_rule);

/*--------------------------------------------------------------------*/
/* Auditing.                                                          */
/*--------------------------------------------------------------------*/

/*  Flags for ssh_pm_attach_audit_module. Audit events from the given
    subsystems are of interest. */
#define SSH_PM_AUDIT_IKE           0x00000001 /** Audit IKE module */
#define SSH_PM_AUDIT_POLICY        0x00000002 /** Audit Controlling Element */
#define SSH_PM_AUDIT_ALL           0xffffffff /** Audit all modules */

/** This function creates an audit module from the parameters 'format'
    with name 'audit_name'.

    If 'audit_name' is NULL or "syslog" audit events are sent to the
    syslog, otherwise they are sent to a file name specified by
    'audit_name'.  'format' specifies the formatting which is used for
    logging the audit events, see sshaudit.h for the different
    possible format types. This function returns an audit context or
    NULL on failure. The policymanager will not begin auditing to the
    returned audit module until ssh_pm_attach_audit_module is called
    for the returned audit context. */
SshAuditContext
ssh_pm_create_audit_module(
        SshPm pm,
        SshAuditFormatType format,
        const char *audit_name);

/** This function enables auditing to the given audit context.

    Argument 'audit_systems' is a bitmask of the SSH_PM_AUDIT_* flags
    which determines which subsystem of audit events this audit module
    should consider for auditing. After this function call, 'audit'
    belongs to the policymanager and the using application must not
    alter 'audit' in any way. This returns true if attaching the audit
    context succeeds and false otherwise in which case
    ssh_audit_destroy will already have been called for 'audit'. */
bool
ssh_pm_attach_audit_module(
        SshPm pm,
        uint32_t audit_subsystems,
        SshAuditContext audit);

/*--------------------------------------------------------------------*/
/* Statistics functions.                                              */
/*--------------------------------------------------------------------*/

/** A callback function of this type is called to return global
    statistics for the policy manager. */
typedef void
(*SshPmGlobalStatsCB)(
        SshPm pm,
        const SshPmGlobalStats pm_stats,
        void *context);

/** This function reads the global statistics counters for the the
    policy manager. */
void
ssh_pm_get_global_stats(
        SshPm pm,
        SshPmGlobalStatsCB callback,
        void *context);

/** This function reads the basic IPsec SA statistics counters.

    @param ipsec_sa_stats
    The structure for passing the retrieved statistics must be allocated
    by the caller.
*/
void
ssh_pm_get_ipsec_sa_stats(
        SshPm pm,
        SshPmIPsecSaStats ipsec_sa_stats);

#ifdef SSHDIST_IPSEC_DNSPOLICY
/*--------------------------------------------------------------------*/
/* Rule and tunnel DNS name resolution functions.                     */
/*--------------------------------------------------------------------*/

/** This function is used for indicating changes on DNS.

    If both 'dnsname' and 'ip' are NULL, then this will start
    resolution of all dns names referenced at the current policy. If
    'dnsname' is given, and 'ip' is NULL, then only that name is
    resolved. If both 'dnsname' and 'ip' are given, then names IP
    address assignment is changed directly without additional DNS
    lookup (providing means for optimization and indepence of DNS
    availability).

    The callback will be called when name resolution for all indicated
    by 'dnsname' on current policy has been tried (either success or
    failure).

    The function obeys standard SshOperation semantics on its return
    value. */
SshOperationHandle
ssh_pm_indicate_dns_change(
        SshPm pm,
        const char *dnsname,
        const char *ip,
        SshPmStatusCB callback,
        void *context);

typedef enum {
  /* Rule has all the DNS names resolved. */
  SSH_PM_DNS_STATUS_OK    = 0,
  /* Rule has all the DNS names resolved, but the information might not
     be fresh, as last DNS query for them failed. */
  SSH_PM_DNS_STATUS_STALE = 1,
  /* Rule has unresolved DNS names, and is not usable */
  SSH_PM_DNS_STATUS_ERROR = 2
} SshPmDnsStatus;

/** This function returns information if all DNS names required by the
    rule have been resolved.

    Value SSH_PM_RULE_DNS_STATUS_OK, indicates the names have been
    resolved, and are fresh. Value SSH_PM_RULE_DNS_STATUS_STALE,
    indicates the addresses have been resolved, but the latest attempt
    to resolve them failed, and value SSH_PM_RULE_DNS_STATUS_ERROR
    indicates the rule can not be used as there are unresolved
    addresses.

    This function also checks the local and peer DNS names of any tunnels
    referenced by this rule. It is required to have atleast one valid
    and resolved DNS peer name per tunnel. */
SshPmDnsStatus
ssh_pm_rule_get_dns_status(
        SshPm pm,
        uint32_t rule);

/* This function will check whether the local_ip and peer
   fields get resolved if given as DNS. If all local_ip fields
   and atleast one peer field is resolved then this will return
   SSH_PM_DNS_STATUS_OK, otherwise SSH_PM_DNS_STATUS_ERROR/STALE */
SshPmDnsStatus
ssh_pm_tunnel_get_dns_status(
        SshPm pm,
        SshPmTunnel tunnel);

/** This function is used for removing old DNS names from the cache
    after reconfiguration, and for removing newly added DNS names
    from the cache after a failed configuration.

    If 'purge_old' is true then those names that were added to cache
    with ssh_pm_indicate_dns_change() before the last call to
    ssh_pm_dns_cache_purge() are removed. Otherwise the DNS names
    added to cache after the last are removed. */
void
ssh_pm_dns_cache_purge(
        SshPm pm,
        bool purge_old);

#endif /* SSHDIST_IPSEC_DNSPOLICY */

#endif /* CORE_PM_H */
