/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file defines tunable configuration parameters for the IPsec
   system.

   @description
   Most values define the maximum number of objects allowed, and some
   are used for scaling the system.

   Note: When deleting rules, tunnels or services for an existing
   policy and replacing them with new ones in the same commit call,
   the deletions are done only after the additions. This should be
   taken into account when estimating resource usage.
*/

#ifndef IPSEC_PARAMS_H
#define IPSEC_PARAMS_H

/* Get distribution definition and configuration values. */
#include "sshincludes.h"

/* ********************************************************************
 * The following parameters can be tuned on a per-system basis.  They
 * directly affect memory allocation style and memory requirements of
 * policy manager, and consequently the number of maximum security
 * security associations etc. that can be supported.  Several options
 * related to whether individual features should be compiled in are also
 * included here.
 * ********************************************************************/

/** Define this if statistics should be collected. */
#define SSH_IPSEC_STATISTICS




























/** Maximum number of bits in an ESP encryption key.  Make this bigger
    if you want to use bigger keys.  However, 256 bits should be
    sufficient for most practical purposes and for standards
    compliance (aes, 3des, des).

    If using counter mode encryption, the ESP cipher nonce is
    concatenated with the ESP encryption key. This implies that the
    ESP cipher key length plus the ESP cipher nonce length must be no
    larger than SSH_IPSEC_MAX_ESP_KEY_BITS, e.g. if you wish to use
    AES-192 CTR mode or AES-192 GCM mode, SSH_IPSEC_MAX_ESP_KEY_BITS
    must be 192 + 32 = 224 (the nonce size is 32 bits). For cbc mode
    of encryption the cipher nonce is not present.

*/
#ifndef SSH_IPSEC_MAX_ESP_KEY_BITS
# define SSH_IPSEC_MAX_ESP_KEY_BITS      (256+32) /* aes256-ctr */
#endif /* SSH_IPSEC_MAX_ESP_KEY_BITS */

/** The maximum number of bits in a message authentication code key
   (for AH or ESP).  Make this bigger if you want to use bigger keys.
   160 should be sufficient for most practical purposes and for
   standards compliance. However, SHA2 requires up-to 512 bits and
   AES-GMAC requires up-to 288 bits. */

#ifdef SSHDIST_CRYPT_SHA512
#define SSH_IPSEC_MAX_MAC_KEY_BITS      512
#else /* SSHDIST_CRYPT_SHA512 */
#ifdef SSHDIST_CRYPT_MODE_GCM
#define SSH_IPSEC_MAX_MAC_KEY_BITS      (256+32)
#else /* SSHDIST_CRYPT_MODE_GCM */
#ifdef SSHDIST_CRYPT_SHA256
#define SSH_IPSEC_MAX_MAC_KEY_BITS      256
#else /* SSHDIST_CRYPT_SHA256 */
#define SSH_IPSEC_MAX_MAC_KEY_BITS      160
#endif /* SSHDIST_CRYPT_SHA256 */
#endif /* SSHDIST_CRYPT_MODE_GCM */
#endif /* SSHDIST_CRYPT_SHA512 */

/** The maximum number of bits in a message integrity check value.
    With hmac-md5 and hmac-sha1 96 bits are typically used. However,
    with SHA2 algorithms 128 to 256 bits are used.
    AES-GCM also requires 128 bits. */
#ifdef SSHDIST_CRYPT_SHA512
#define SSH_IPSEC_MAX_HMAC_OUTPUT_BITS  256
#else /* SSHDIST_CRYPT_SHA512 */
#ifdef SSHDIST_CRYPT_SHA256
#define SSH_IPSEC_MAX_HMAC_OUTPUT_BITS  128
#else /* SSHDIST_CRYPT_SHA256 */
#ifdef SSHDIST_CRYPT_MODE_GCM
#define SSH_IPSEC_MAX_HMAC_OUTPUT_BITS  128
#else /* SSHDIST_CRYPT_MODE_GCM */
#define SSH_IPSEC_MAX_HMAC_OUTPUT_BITS   96
#endif /* SSHDIST_CRYPT_MODE_GCM */
#endif /* SSHDIST_CRYPT_SHA256 */
#endif /* SSHDIST_CRYPT_SHA512 */

/* Enable this to start IKE & other servers on link local
   addresses. */
/* #define SSH_IPSEC_LINK_LOCAL_SERVERS */

#ifdef SSHDIST_XML
/* Enable XML policy parsing. If this is not set, then no
   XML parsing will be performed. The purpose of this tunable
   is to let the source tree compile cleanly even if sshxml
   library is not included. */
#define SSH_IPSEC_XML_CONFIGURATION
#endif /* SSHDIST_XML */

#ifdef SSHDIST_HTTP_SERVER
/* Enable HTTP interface for statistics etc. If this is set,
   then the HTTP interface can be configured via policy, otherwise
   it does not exist in the binary. The existence of the HTTP
   interface is currently dependent on the inclusion of XML config
   parsing. */
#ifdef SSH_IPSEC_XML_CONFIGURATION
#define SSH_IPSEC_HTTP_INTERFACE
#endif /* SSH_IPSEC_XML_CONFIGURATION */
#endif /* SSHDIST_HTTP_SERVER */

/* The maximum number of filedescriptors the quicksecpm tries to
   request from the operating system. If SSH_PM_MAX_FILEDESCRIPTORS is
   set to -1 then the policymanager leaves the "max filedescriptors"
   limit untouched. If SSH_PM_MAX_FILEDESCRIPTORS is 0 then the pm
   requests unlimited filedescriptors. If SSH_PM_MAX_FILEDESCRIPTORS
   is set to any other value then this amount is requested to be used
   as the maximum. */








#ifndef SSH_PM_MAX_FILEDESCRIPTORS
#define SSH_PM_MAX_FILEDESCRIPTORS (-1)
#endif /* not SSH_PM_MAX_FILEDESCRIPTORS */



/* The maximum number of high-level tunnel objects. */
#ifndef SSH_PM_MAX_TUNNELS
#define SSH_PM_MAX_TUNNELS              150
#endif /* not SSH_PM_MAX_TUNNELS */

/* The maximum number of high-level policy rules. */
#ifndef SSH_PM_MAX_RULES
#define SSH_PM_MAX_RULES        (SSH_PM_MAX_TUNNELS * 4)
#endif /* not SSH_PM_MAX_RULES */

/** Maximum number of peer objects in the peer information database. */
#define SSH_PM_MAX_PEER_HANDLES      (SSH_PM_MAX_TUNNELS * 2)

/** Maximum number of port pairs IKE is listening. The default is one
    pair (500,4500). */
#ifndef SSH_IPSEC_MAX_IKE_PORTS
#define SSH_IPSEC_MAX_IKE_PORTS 2
#endif /* SSH_IPSEC_MAX_IKE_PORTS */

/* The maximum number of active IKE SAs at the IKE library. */
#ifndef SSH_PM_MAX_IKE_SAS_IKE
#define SSH_PM_MAX_IKE_SAS_IKE       (SSH_PM_MAX_TUNNELS * 2)
#endif /* not SSH_PM_MAX_IKE_SAS_IKE */

/* The maximum number of active IKE SA contexts at policy manager.
   The policy manager has few more contexts than our IKE library.
   This way IKE can expire old negotiation and policy manager can
   start new ones even if IKE has all its SSH_PM_MAX_IKE_SAS_IKE
   established. */
#ifndef SSH_PM_MAX_IKE_SAS
#define SSH_PM_MAX_IKE_SAS   \
(SSH_PM_MAX_IKE_SAS_IKE + SSH_PM_MAX_IKE_SAS_IKE / 10)
#endif /* SSH_PM_MAX_IKE_SAS */

/* Size of the IKE SA hash table in the policy manager. */
#ifndef SSH_PM_IKE_SA_HASH_TABLE_SIZE
#define SSH_PM_IKE_SA_HASH_TABLE_SIZE   \
(SSH_PM_MAX_IKE_SAS < 100 ? 10 : SSH_PM_MAX_IKE_SAS / 10)
#endif /* SSH_PM_IKE_SA_HASH_TABLE_SIZE */

/* The maximum number of simultaneous IKE SA negotiations.  The system
   can have SSH_PM_MAX_IKE_SAS SAs but this limits the number of
   active negotiations. */
#ifndef SSH_PM_MAX_IKE_SA_NEGOTIATIONS
#define SSH_PM_MAX_IKE_SA_NEGOTIATIONS  25
#endif /* not SSH_PM_MAX_IKE_SA_NEGOTIATIONS */

/* The maximum number of simultaneous aggressive mode IKE SA
   negotiations. This value should always be less than or equal to
   SSH_PM_MAX_IKE_SA_NEGOTIATIONS */
#ifndef SSH_PM_MAX_AGGR_MODE_NEGOTIATIONS
#define SSH_PM_MAX_AGGR_MODE_NEGOTIATIONS \
        ((SSH_PM_MAX_IKE_SA_NEGOTIATIONS / 10) + 1)
#endif /* SSH_PM_MAX_AGGR_MODE_NEGOTIATIONS */

/* The maximum number of simultaneous Quick-Mode (IPsec) negotiations.
   The system supports more IPsec SAs but this limits the number of
   active negotiations. One half of this number of negotiations,
   SSH_PM_MAX_QM_NEGOTIATIONS/2, are reserved for rekeys.  */
#ifndef SSH_PM_MAX_QM_NEGOTIATIONS
#define SSH_PM_MAX_QM_NEGOTIATIONS      50
#endif /* not SSH_PM_MAX_QM_NEGOTIATIONS */

/* The maximum number of child SAs per IKE SA. Define to zero to allow
   unlimited number of child SAs per IKE SA. The default value allows
   half of available child SAs for one IKE SA. */
#ifndef SSH_PM_MAX_CHILD_SAS
#define SSH_PM_MAX_CHILD_SAS            (SSH_PM_MAX_TUNNELS)
#endif /* not SSH_PM_MAX_CHILD_SAS */

/* The maximum number of pending IPsec delete notifications.  The
   IPsec delete notification processing is delayed for about 1 second
   after it is received.  This is needed to interoperate with some
   IPsec implementations which delete the old inbound IPsec SA
   immediately after rekey. */
#ifndef SSH_PM_MAX_PENDING_DELETE_NOTIFICATIONS
#define SSH_PM_MAX_PENDING_DELETE_NOTIFICATIONS (SSH_PM_MAX_IKE_SAS * 2)
#endif /* not SSH_PM_MAX_PENDING_DELETE_NOTIFICATIONS */

/* Maximum number of remote access clients using IKE configuration
   mode.  The IKE configuration mode does not have an easy way to
   implement IP address lease.  Therefore, the remote access server
   must have its own bookkeeping for these remote access clients.
   Note that the system can simultaneously have other remote access
   clients using, for example, L2TP or DHCP over IPsec. */
#ifndef SSH_PM_MAX_CONFIG_MODE_CLIENTS
#define SSH_PM_MAX_CONFIG_MODE_CLIENTS  SSH_PM_MAX_TUNNELS
#endif /* SSH_PM_MAX_CONFIG_MODE_CLIENTS */

/* Maximun number of L2TP clients. */
#ifndef SSH_PM_MAX_L2TP_CLIENTS
#define SSH_PM_MAX_L2TP_CLIENTS         SSH_PM_MAX_TUNNELS
#endif /* SSH_PM_MAX_L2TP_CLIENTS */

/* Maximum number of concurrent L2TP tunnel requests. */
#ifndef SSH_PM_MAX_L2TP_TUNNEL_REQUESTS
#define SSH_PM_MAX_L2TP_TUNNEL_REQUESTS \
(SSH_PM_MAX_L2TP_CLIENTS > 5 ? 5 : SSH_PM_MAX_L2TP_CLIENTS)
#endif  /* SSH_PM_MAX_L2TP_TUNNEL_REQUESTS */

/* The maximum lifetime in seconds of an IPsec SA which has only a
   kilobyte lifetime. An IPsec SA which has only a kilobyte lifetime will
   be deleted after this number of seconds if the SA has not already been
   deleted. This ensures that SA's with kilobyte lifetimes are always deleted
   even if there is no traffic through such SA's. This parameter does not
   affect SA's that have a lifetime in seconds. */
#ifndef SSH_IPSEC_MAXIMUM_IPSEC_SA_LIFETIME_SEC
#define SSH_IPSEC_MAXIMUM_IPSEC_SA_LIFETIME_SEC  (24 * 60 * 60)
#endif /* SSH_IPSEC_MAXIMUM_IPSEC_SA_LIFETIME_SEC  */

/* Number of concurrent DNS queries */
#ifndef SSH_PM_MAX_DNS_QUERIES
# define SSH_PM_MAX_DNS_QUERIES         10
#endif /* SSH_PM_MAX_DNS_QUERIES */

/* The number of times per second for which the policymanager will
   request the audit events. This number may be dynamically decreased
   if the system is under attack. */
#ifndef SSH_PM_AUDIT_REQUESTS_PER_SECOND
# define SSH_PM_AUDIT_REQUESTS_PER_SECOND 10
#endif /* SSH_PM_AUDIT_REQUESTS_PER_SECOND */

/* ********************************************************************
 * Values computed from the number of sessions and security associations.
 * These usually need not be touched, but can be tuned if desired.
 * ********************************************************************/

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL

/* Size of the peer ID in the transform data structure. */
#ifndef SSH_PM_PEER_ID_SIZE
#define SSH_PM_PEER_ID_SIZE 8
#endif /* SSH_PM_PEER_ID_SIZE */
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

/* ********************************************************************
 * The following parameters can also be tuned; however, these would
 * usually not be tuned on a per-system basis, and some represent
 * tradeoffs in security policy etc.
 * ********************************************************************/

/* The maximum amount of traffic selector items allowed in a traffic
   selector. The memory usage of high-level policy level rules
   (SshPmRuleStruct) is proportional to the square of this value,
   in bytes the memory usage per rule is
   8 * (SSH_MAX_RULE_TRAFFIC_SELECTORS_ITEMS ^ 2). */
#ifndef SSH_MAX_RULE_TRAFFIC_SELECTORS_ITEMS
#define SSH_MAX_RULE_TRAFFIC_SELECTORS_ITEMS 5
#endif /* SSH_MAX_RULE_TRAFFIC_SELECTORS_ITEMS */

/* ********************************************************************
 * The following parameters are not normally tuned.
 * ********************************************************************/

/* Port number at which IKE runs.  Note that some protocols, such as
   NAT Traversal, may depend on IKE running in the standard port. */
#ifndef SSH_IPSEC_IKE_PORT
#define SSH_IPSEC_IKE_PORT      500
#endif /* SSH_IPSEC_IKE_PORT */

/* Port number at which IKE runs in NAT traversal. */
#ifndef SSH_IPSEC_IKE_NATT_PORT
#define SSH_IPSEC_IKE_NATT_PORT 4500
#endif /* SSH_IPSEC_IKE_NATT_PORT */

/* Port number at which L2TP runs. */
#define SSH_IPSEC_L2TP_PORT     1701

/* The interval (in seconds) how often NAT-T keepalive packets are
   sent. If interval is zero, NAT-T keepalive is disabled. */
#define SSH_IPSEC_NATT_KEEPALIVE_INTERVAL 20

/* Enable Multicast feature. This will enable multicast traffic forwarding
   and esp tunnel with manual SA's for Multicast peers. For identifying the
   SA for esp packets between multicast peers,spi and destination multicast
   address will be used (as per rfc 4303). Rules should be added with
   destination multicast address for the packets we want to secure using
   tunnel. Routing information for Multicast packets is picked from system
   routing table. */
/* #define SSH_IPSEC_MULTICAST */

/* Enable multiple authentications feature. This will enable initiator
   to perform a second authentication round during IKEv2 negotiation
   and responder to require it. First authentication method is not limited,
   but only EAP is supported as the second method. */

#ifdef SSHDIST_IKE_EAP_AUTH
#define SSH_IKEV2_MULTIPLE_AUTH
#endif /* SSHDIST_IKE_EAP_AUTH */

/* Set the maximum number of proposal per SA. This affect also
   IKEv1. Some implementations send many proposals for example for IKE
   SA. Only SSH_IKEV2_SA_MAX_PROPOSALS proposals are decoded and taken
   into account in the negotiation the rest are ignored. Value affects
   also size of SshIkev2PayloadSA structure.
 */
#ifndef SSH_IKEV2_SA_MAX_PROPOSALS
#define SSH_IKEV2_SA_MAX_PROPOSALS   20
#endif /* SSH_IKEV2_SA_MAX_PROPOSALS */

/* When when combined mode (authenticating) ciphers are used together
   with normal node (non-authenticating) ciphers. Two proposals, one
   for each mode, are formed to the SA payloads.

   The order of the proposals in the SA payloads defines the
   preference of the proposals. Setting SSH_PM_COMBINED_MODE_FIRST to
   true causes the proposal containing combined mode ciphers to be
   placed first in the SA payload. Setting it to false places it
   second.
 */
#ifndef SSH_PM_COMBINED_MODE_FIRST
#define SSH_PM_COMBINED_MODE_FIRST false
#endif /* SSH_PM_COMBINED_MODE_FIRST */

#endif /* IPSEC_PARAMS_H */
