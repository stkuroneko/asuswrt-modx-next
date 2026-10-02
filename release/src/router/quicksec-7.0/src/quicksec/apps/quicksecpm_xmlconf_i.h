/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   Internal definitions for the QuickSec XML configuration module.
*/

#include "common_xmlconf.h"
#ifdef SSHDIST_XML
#include "sshxml.h"
#include "sshxml_dom.h"
#endif /* SSHDIST_XML */

#include "sshdsprintf.h"
#include "sshnameserver.h"
#include "sshdatastream.h"
#include "sshurl.h"


#ifdef SSHDIST_DIRECTORY_HTTP
#include "sshhttp.h"
#endif /* SSHDIST_DIRECTORY_HTTP */

#include "sshfdstream.h"
#include "sshfileio.h"
#include "sshadt.h"
#include "sshadt_bag.h"
#include "sshfsm.h"
#include "version.h"

#include "pad_authorization_local.h"
#include "quicksec_pm.h"

#include "pad_auth_domain.h"

#ifdef SSHDIST_CERT
/* For raw RSA keys */
#include "sshpkcs1.h"
#endif /* SSHDIST_CERT */

#ifdef SSHDIST_IKE_EAP_AUTH
#include "ssheap.h"
#endif /* SSHDIST_IKE_EAP_AUTH */

#include "ipsec_params.h"

#ifdef SSH_IPSEC_XML_CONFIGURATION

/*************************** Types and definitions ***************************/

/** Predicate to check whether the character `ch' is a whitespace
   character. */
#define SSH_IPM_IS_SPACE(ch) \
((ch) == 0x20 || (ch) == 0x9 || (ch) == 0xd || (ch) == 0xa)

/** Predicate to check whether the character `ch' is a decimal digit. */
#define SSH_IPM_IS_DEC(ch)      \
('0' <= (ch) && (ch) <= '9')

/** Predicate to check whether the character `ch' is a hexadecimal
   digit. */
#define SSH_IPM_IS_HEX(ch)              \
(('0' <= (ch) && (ch) <= '9')           \
 || ('a' <= (ch) && (ch) <= 'f')        \
 || ('A' <= (ch) && (ch) <= 'F'))

/** Convert hexadecimal digit `ch' to its integer value. */
#define SSH_IPM_HEX_TO_INT(ch)  \
('0' <= (ch) && (ch) <= '9'     \
 ? (ch) - '0'                   \
 : ('a' <= (ch) && (ch) <= 'f'  \
    ? (ch) - 'a' + 10           \
    : (ch) - 'A' + 10))

#ifdef DEBUG_LIGHT
#define SSH_XML_VERIFIER(what)                          \
do                                                      \
  {                                                     \
    if (!(what))                                        \
      ssh_fatal("XML verifier did not verify: " #what); \
  }                                                     \
while (0);
#else /** DEBUG_LIGHT */
#define SSH_XML_VERIFIER(what)
#endif /* DEBUG_LIGHT */

/** Information about a policy rule. */
struct SshIpmRuleRec
{
    SshADTBagHeaderStruct adt_header;

    /** The precedence of the rule.  This is also rule's key in the
       bag. */
    uint32_t precedence;

    /** Flags. */
    unsigned int seen : 1;        /** Rule seen in the configuration batch. */
    unsigned int unused : 1;      /** Unused in the current configuration. */

    /** Index of the current rule.  This has the value
       `SSH_IPSEC_INVALID_INDEX' if there is no current rule. */
    uint32_t rule;

    /** The new rule created by this reconfiguration operation. */
    uint32_t new_rule;
};

typedef struct SshIpmRuleRec SshIpmRuleStruct;
typedef struct SshIpmRuleRec *SshIpmRule;

/** Policy object types. */
typedef enum
{
    SSH_IPM_POLICY_OBJECT_NONE,
    SSH_IPM_POLICY_OBJECT_PSK,
    SSH_IPM_POLICY_OBJECT_TUNNEL,
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
    SSH_IPM_POLICY_OBJECT_ADDRPOOL
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
} SshIpmPolicyObjectType;

/** Audit module information. */
struct SshIpmAuditRec
{
    SshADTBagHeaderStruct adt_header;

    char *audit_name;
    uint32_t format;
    uint32_t subsystems;

    unsigned int seen : 1; /** Seen in a previous configuration. */
};

typedef struct SshIpmAuditRec SshIpmAuditStruct;
typedef struct SshIpmAuditRec *SshIpmAudit;


/** A pre-shared key. */
struct SshIpmPskRec
{
    SshPmIdentityType id_type;
    char *identity;
    SshPmSecretEncoding id_encoding;

    SshPmSecretEncoding encoding;
    unsigned char *secret;
    size_t secret_len;
};

typedef struct SshIpmPskRec SshIpmPskStruct;
typedef struct SshIpmPskRec *SshIpmPsk;

/** A policy object value. */
struct SshIpmPolicyObjectValueRec
{
    SshIpmPolicyObjectType type;
    union
  {
      SshIpmPskStruct psk;
      SshPmTunnel tunnel;
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
      char *addrpool_name;
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
    } u;
};

typedef struct SshIpmPolicyObjectValueRec SshIpmPolicyObjectValueStruct;
typedef struct SshIpmPolicyObjectValueRec *SshIpmPolicyObjectValue;

/** Information about policy objects, other than rules.  These objects
   share the same name-space. */
struct SshIpmPolicyObjectRec
{
    SshADTBagHeaderStruct adt_header;

    /** The name of the object.  This is also they key in the ADT
       container. */
    char *name;
    size_t name_len;

    /** Flags. */
    unsigned int seen : 1;     /** Object seen in the configuration batch. */

    /** The current value. */
    SshIpmPolicyObjectValueStruct value;

    /** The new value from the current reconfiguration. */
    SshIpmPolicyObjectValueStruct new_value;
};

typedef struct SshIpmPolicyObjectRec SshIpmPolicyObjectStruct;
typedef struct SshIpmPolicyObjectRec *SshIpmPolicyObject;

/** Configuration object types. */
typedef enum
{
    SSH_IPM_XMLCONF_PARAMS,
    SSH_IPM_XMLCONF_IKE_VERSIONS,
    SSH_IPM_XMLCONF_IKE_GROUPS,
    SSH_IPM_XMLCONF_PFS_GROUPS,
    SSH_IPM_XMLCONF_IKE_ALGORITHMS,
    SSH_IPM_XMLCONF_IKE_WINDOW_SIZE,
    SSH_IPM_XMLCONF_IKE_FRAGMENTATION,
#ifdef SSHDIST_IKE_REDIRECT
    SSH_IPM_XMLCONF_IKE_REDIRECT,
    SSH_IPM_XMLCONF_REDIRECT_ADDRESS,
#endif /* SSHDIST_IKE_REDIRECT */
    SSH_IPM_XMLCONF_CA,
    SSH_IPM_XMLCONF_TUNNEL,
    SSH_IPM_XMLCONF_AUTH_DOMAIN,
#ifdef SSHDIST_CERT
    SSH_IPM_XMLCONF_CERTIFICATE,
    SSH_IPM_XMLCONF_CRL,
#endif /* SSHDIST_CERT */
    SSH_IPM_XMLCONF_PSK,
    SSH_IPM_XMLCONF_ACCESS_GROUP,
    SSH_IPM_XMLCONF_PEER,
    SSH_IPM_XMLCONF_LOCAL_IP,
    SSH_IPM_XMLCONF_LOCAL_PORT,
    SSH_IPM_XMLCONF_IDLE_TIMEOUT,
    SSH_IPM_XMLCONF_LOCAL_IFACE,
    SSH_IPM_XMLCONF_CFGMODE_ADDRESS,
    SSH_IPM_XMLCONF_VIRTUAL_IFNAME,
    SSH_IPM_XMLCONF_DPD_TIMEOUT,
    SSH_IPM_XMLCONF_LIFE,
    SSH_IPM_XMLCONF_IDENTITY,
    SSH_IPM_XMLCONF_TUNNEL_AUTH,
    SSH_IPM_XMLCONF_TUNNEL_ADDRESS_POOL,
    SSH_IPM_XMLCONF_ADDR_POOL,
    SSH_IPM_XMLCONF_SUBNET,
    SSH_IPM_XMLCONF_ADDRESS,
    SSH_IPM_XMLCONF_POLICY,
    SSH_IPM_XMLCONF_RULE,
    SSH_IPM_XMLCONF_SRC,
    SSH_IPM_XMLCONF_DST,
    SSH_IPM_XMLCONF_IFNAME,
    SSH_IPM_XMLCONF_DNS,
    SSH_IPM_XMLCONF_AUDIT,
    SSH_IPM_XMLCONF_GROUP_REF,
    SSH_IPM_XMLCONF_IPV6_PREFIX,
    SSH_IPM_XMLCONF_RADIUS_ACCOUNTING
} SshIpmXmlconfType;

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER

typedef struct SshIpmRasSubnetConfigRec
SshIpmRasSubnetConfigStruct, *SshIpmRasSubnetConfig;

struct SshIpmRasSubnetConfigRec
{
    SshIpmRasSubnetConfig next;
    char *address;
};

typedef struct SshIpmRasAddressConfigRec
SshIpmRasAddressConfigStruct, *SshIpmRasAddressConfig;

struct SshIpmRasAddressConfigRec
{
    SshIpmRasAddressConfig next;
    char *address;
    char *netmask;
};
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */

/** A configuration object. */
struct SshIpmXmlconfRec
{
    SshIpmXmlconfType type;
    SshIpmPolicyObject object;

    /** Character data. */
    unsigned char *data;
    size_t data_len;

    union
    {
        struct
        {
            char *file;
        }
        keycert;

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
        struct
        {
            SshIpAddrStruct netmask;
            char *address_pool_name;
            char *remote_access_attr_own_ip;
            char *remote_access_attr_dns;
            char *remote_access_attr_wins;
            char *remote_access_attr_dhcp;
            uint32_t flags;
            char *remote_access_ipv6_prefix;
            SshIpmRasSubnetConfig remote_access_attr_subnet_list;
            SshIpmRasAddressConfig remote_access_attr_address_list;
        }
        addrpool;
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */

#ifdef SSHDIST_IKE_REDIRECT
        struct
        {
            char *redirect_addr;
            uint8_t phase;
        }
        ike_redirect;
#endif /* SSHDIST_IKE_REDIRECT */

        struct
        {
            const char *status;
            int fragment_size;
        }
        ike_fragmentation;

      /** Attributes for Pre-shared keys and aggressive mode secrets. */
        struct
        {
            /** Reference to a named pre-shared key. */
            char *psk_ref;
            size_t psk_ref_len;

            /** IKE identity. */
            SshPmIdentityType id_type;
            SshPmSecretEncoding id_encoding;
            char *identity;
            size_t identity_len;

            /** The type of the secret. */
            SshPmSecretEncoding encoding;
            uint32_t flags;
        }
        psk;

        struct
        {
            SshPmRule rule;
            uint32_t precedence;
        }
        rule;

        struct
        {
            uint32_t transform;
            uint8_t ike_versions;
            bool default_ike_preferences;
            bool default_pfs_preferences;

            /** IKE identity. */
            uint32_t identity_flags;
            uint8_t remote_identity; /** bool, local or remote identity */
#ifdef SSH_IKEV2_MULTIPLE_AUTH
            uint8_t second_identity;
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
            SshPmIdentityType id_type;
            SshPmSecretEncoding id_encoding;
            char *identity;
            size_t identity_len;

            /** Authentication domain */
            char *auth_domain_name;
            size_t auth_domain_name_len;
            uint32_t order;

            SshPmTunnel tunnel;
        }
        tunnel;

        struct
        {
#ifdef SSHDIST_IKE_EAP_AUTH
            uint8_t eap_preference_next;
#endif /* SSHDIST_IKE_EAP_AUTH */
            SshPmAuthDomain auth_domain;
        }
        auth_domain;

        struct
        {
            SshPmLifeType type;
        }
        life;

        struct
        {
            uint32_t precedence;
        }
        local_address;

        struct
        {
            uint32_t flags;
            char *file;
        }
        ca;

        struct
        {
            SshPmAuthorizationGroup group;
        }
        group;
    } u;
};

typedef struct SshIpmXmlconfRec SshIpmXmlconfStruct;
typedef struct SshIpmXmlconfRec *SshIpmXmlconf;

/** Legacy authentication client. */
struct SshIpmLegacyAuthClientAuthRec
{
    struct SshIpmLegacyAuthClientAuthRec *next;

    /** Number of references to this object */
    uint32_t references;

    /** Flags for which this entry applies to. */
    uint32_t flags;

    /** IP address of the gateway. */
    SshIpAddrStruct gateway_ip;

    /** User-name. */
    char *user_name;
    size_t user_name_len;

    /** Password. */
    char *password;
    size_t password_len;
};

typedef struct SshIpmLegacyAuthClientAuthRec *SshIpmLegacyAuthClientAuth;

/** Mapping to hold authorization group IDs. */
struct SshIpmAuthGroupIdRec
{
    SshADTBagHeaderStruct adt_header;

    /** The name of the group. */
    char *name;
    size_t name_len;

    /** Its ID. */
    uint32_t group_id;
};

typedef struct SshIpmAuthGroupIdRec SshIpmAuthGroupIdStruct;
typedef struct SshIpmAuthGroupIdRec *SshIpmAuthGroupId;

/** Legacy client authentication methods. */
typedef enum
{
    SSH_IPM_LA_AUTH_NONE,
    SSH_IPM_LA_AUTH_PASSWD,
    SSH_IPM_LA_AUTH_RADIUS
} SshIpmLegacyAuthMethod;

/** HTTP interface for statistics. */
typedef struct SshIpmHttpStatisticsRec *SshIpmHttpStatistics;

/** The depth of the parsing stack. */
#define SSH_IPM_STACK_DEPTH 5


/** Ipm configuration contexts. */

/** Context data for policy manager. */
struct SshIpmContextRec
{
    /** Flags. */
    unsigned int bootstrap_done : 1; /** Bootstrap configure done for
                                        enabling policy fetch. */

    unsigned int initial_done : 1; /** Initial configure using real
                                       policy done. */
    unsigned int ldap_changed : 1;   /** LDAP servers changed. */
    unsigned int http_interface : 1; /** HTTP interface configured. */

    unsigned int auth_domains : 1;
    unsigned int default_auth_domain_present : 1;
    unsigned int auth_domain_reset_failed : 1;

    unsigned int dns_names_allowed : 1;
    unsigned int dns_configuration_done : 1;

    unsigned int parse_completed : 1;

    unsigned int dtd_specified : 1; /** Have seen DTD spec on doc */

    unsigned int commit_called : 1; /** ssh_pm_commit() has been called. */

    unsigned int commit_failed : 1; /** ssh_pm_commit() has failed. */

    unsigned int aborted : 1;       /** Configuration was aborted. */

    /** Time when the system was started. */
    SshTime start_time;

    /** Rules allowing the bootstrap configuration. */
    struct
  {
      uint32_t rule;
      char *traffic_selector;

      /** Success from a bootstrap rule operation. */
      bool success;
    } bootstrap;

    /** Pointer to our policy manager object. */
    void * pm;

    /** FSM. */
    SshFSMStruct fsm;

    /** FSM thread taking care of policy reconfiguration. */
    SshFSMThreadStruct thread;

    /** Command line arguments and other static-like parameters. */
    SshIpmParams params;

    /** Ipm Create Callback and its context */
    SshIpmCtxEventCB cb;
    void *cb_ctx;

    /** The configuration stream.  This is resolved from the
       `params.config_file' using the normal system resource
       resolver. */
    struct
  {
      SshStream stream;
      char *stream_name;
      SshXmlDestructorCB destructor_cb;
      void *destructor_cb_context;
    } config;

    /** Prefix, extracted from the `params.config_file'. */
    char *prefix;

    /** XML parser and verifier. */
    SshXmlParser parser;
    SshXmlVerifier verifier;

    /** Completion callback for a configuration file parsing
       operation. */
    SshPmStatusCB parse_status_cb;
    void *parse_status_cb_context;

    /** The result of the parse operation. */
    bool parse_result;

    /** A timeout that calls the parse result callback. */
    SshTimeoutStruct timeout;

    /** Rules. */
    SshADTContainer rules;

    /** Audit modules. */
    SshADTContainer audit_modules;

    /** Policy objects, other than rules and audit modules. */
    SshADTContainer policy_objects;

    /** LDAP servers. */
    SshBufferStruct ldap_servers;

    /** PM parameter flags */
    uint32_t pm_flags;

    /** Local authorization group module. */
    SshPmAuthorizationLocal authorization;

    /** Legacy authentication method. */
    SshIpmLegacyAuthMethod la_auth_method;

#ifdef SSHDIST_RADIUS
    SshRadiusClient radius_acct_client;
    SshRadiusClientServerInfo radius_acct_servers;
#endif /* SSHDIST_RADIUS */

    /** Mapping from authorization group names to their IDs. */
    SshADTContainer auth_groups;

    /** The next available authorization group ID. */
    uint32_t next_group_id;

    /** Legaycy authentication client. */
    SshIpmLegacyAuthClientAuth la_client_auth;

    /** HTTP statistics interface. */
    SshIpmHttpStatistics http_statistics;

    /** Number of references to the HTTP interface. */
    uint32_t http_statistics_refcount;

#ifdef SSHDIST_EXTERNALKEY
    SshEkProvider ek_providers;
    uint32_t num_ek_providers;
#endif /* SSHDIST_EXTERNALKEY */

    /** The current state of the parsing. */
    SshIpmXmlconf state;
    SshIpmXmlconfStruct stack[SSH_IPM_STACK_DEPTH];

    /** The available precedence space. */
    uint32_t precedence_used_min;

    /** The precedence range of the current policy block. */
    uint32_t precedence_max;
    uint32_t precedence_min;
    uint32_t precedence_next;

    /** XML library's completion callback for policy end-element. */
    SshXmlResultCB result_cb;
    void *result_cb_context;

    /** The smallest refresh value seen so far.  Zero means that there is
       no automatic refresh configured so far. */
    uint32_t refresh;

    /** Temporary variables. */
    unsigned char buf[1024];

    /** Temporary configuration parameters. */
    struct {
      /** IKE default algorithms */
      uint32_t default_ike_algorithms;
    } config_parameters;

    SshOperationHandle sub_operation;
    SshOperationHandle parse_operation;
    SshOperationHandleStruct operation[1];
};

typedef struct SshIpmContextRec SshIpmContextStruct;

/** QuickSec DTD. */
extern const unsigned char quicksec_dtd[];
extern const size_t quicksec_dtd_len;


/******************* Prototypes for internal help functions ******************/




void ssh_ipm_error(SshIpmContext ctx, const char *fmt, ...);
void ssh_ipm_warning(SshIpmContext ctx, const char *fmt, ...);


/************************* HTTP statistics interface *************************/

/** Parameters for the HTTP statistics interface. */
struct SshIpmHttpStatisticsParamsRec
{
    /** The local IP address to listen to.  The default address is
       SSH_IPADDR_ANY. */
    char *address;

    /** The port number on which the HTTP interface is running. */
    uint16_t port;

    /** Use frames? */
    bool frames;

    /** Refresh interval.  If the value is 0, no refreshing is
       requested. */
    uint32_t refresh;
};

typedef struct SshIpmHttpStatisticsParamsRec SshIpmHttpStatisticsParamsStruct;
typedef struct SshIpmHttpStatisticsParamsRec *SshIpmHttpStatisticsParams;

/** Start the HTTP statistics interface for the policy manager `ctx' to
   port `port'.  The argument `frames' specifies whether the interface
   uses frames or not.  The function returns a boolean success
   status. */
bool ssh_ipm_http_statistics_start(SshIpmContext ctx,
                                      SshIpmHttpStatisticsParams params);

/** Stop the HTTP statistics interface of the policy manager `ctx'.
   The function returns true if the HTTP statistics interface was
   stopped and false otherwise.  If the function returns false, the
   caller should call the function again at some later time to retry
   stopping the HTTP interface. */
bool ssh_ipm_http_statistics_stop(SshIpmContext ctx);


#ifdef SSHDIST_IKE_REDIRECT
/************************ IKE redirect sample filter *************************/
void
ssh_ike_redirect_decision_cb(char *client_id,
                             size_t client_id_len,
                             SshPmIkeRedirectResultCB result_cb,
                             void *result_cb_context,
                             void *context);
#endif /* SSHDIST_IKE_REDIRECT */

#endif /* SSH_IPSEC_XML_CONFIGURATION */
