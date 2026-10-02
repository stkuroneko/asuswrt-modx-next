/**
   @copyright
   Copyright (c) 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   Header for IPsec SA structures.
*/

#ifndef IPSEC_SA_PARAMS_H
#define IPSEC_SA_PARAMS_H

#include "sshincludes.h"
#include "sshinet.h"
#include "sshtimeouts.h"

#include "idtransformer.h"
#include "in_addr.h"


#define IPSEC_KEY_MATERIAL_BYTES_MAX 64

/**
   Structure for providing key material for IPsec algorithms for an
   IPsec SA.
 */
struct IPsecSaKeyMaterial
{
    /** Length of integrity key material in bytes. The length is same
        for inbound and outbound integrity. */
    int integrity_keymaterial_len;

    /** Length of encryption key material in bytes. The length is same
        for inbound and outbound encryption. */
    int encryption_keymaterial_len;

    /** Buffer for inbound integrity key material. */
    unsigned char inbound_integrity_keymaterial[IPSEC_KEY_MATERIAL_BYTES_MAX];

    /** Buffer for inbound encryption key material. */
    unsigned char inbound_encryption_keymaterial[IPSEC_KEY_MATERIAL_BYTES_MAX];

    /** Buffer for outbound integrity key material. */
    unsigned char outbound_integrity_keymaterial[IPSEC_KEY_MATERIAL_BYTES_MAX];

    /** Buffer for outbound encryption key material. */
    unsigned char
    outbound_encryption_keymaterial[IPSEC_KEY_MATERIAL_BYTES_MAX];
};


/**
   Enumerated IPsec SA Don't Fragment Bit policies.
 */
typedef enum IPsecSaDontFragmentBitPolicyEnum
{
    /** Don't Fragment bit should be untouched on IPsec packets. */
    IPSEC_SA_DONT_FRAGMENT_BIT_UNTOUCH,

    /** Don't Fragment bit should be set on IPsec packets. */
    IPSEC_SA_DONT_FRAGMENT_BIT_SET,

    /** Don't Fragment bit should be clear on IPsec packets. */
    IPSEC_SA_DONT_FRAGMENT_BIT_CLEAR,

    /** Don't Fragment bit should be copied from encapsulated packets
        to the encapsulating IPsec packets. */
    IPSEC_SA_DONT_FRAGMENT_BIT_COPY

} IPsecSaDontFragmentBitPolicy;


/**
   Structure for IPsec SA endpoint parameters.
 */
struct IPsecSaEndpoints
{
    /** Local address. */
    struct InAddr local_address;

    /** Local port for UDP Encapsulation. */
    int local_port;

    /** Remote address. */
    struct InAddr remote_address;

    /** Remote port for UDP Encapsulation. */
    int remote_port;

    /** Set to true if IPsec SA should use UDP Encapsulation. */
    bool natt;

    /** Set to true if local end point is behind a NAT. */
    bool natt_local_nat;

    /** Set to true if remote end point is behind a NAT. */
    bool natt_remote_nat;

    /** Set to true if this IPsec SA needs NATT keepalives. */
    bool natt_keepalive;
};


/**
   Structure for IPsec SA parameters.
 */
struct IPsecSaParams
{
    /** Tunnel identifier. */
    uint32_t tunnel_id;

    /** Rule identifier. */
    uint32_t rule_id;

    /** Inbound SPI. */
    uint32_t inbound_spi;

    /** Outbound SPI.  */
    uint32_t outbound_spi;

    /** Inbound SPI of an SA that this SA rekeys. */
    uint32_t rekeyed_inbound_spi;

    /** Peer handle to peer SA is linked to. */
    uint32_t peer_handle;

    /** Log facility to use when logging about this SA. */
    int log_facility;

    /** IP protocol identifier, either ESP or AH. */
    SshInetIPProtocolID ipproto;

    /** Numeric identifier for integrity algorithm. From idtransformer
        module.
     */
    int integrity_algorithm_id;

    /** Numeric identifier for encryption algorithm. From idtransformer
        module.
     */
    int encryption_algorithm_id;

    /** Numeric identifier for diffie hellman group. From idtransformer
        module.
    */
    int dh_algorithm_id;

    /**  Set to true if IPsec SA is keyed by IKEv1. Other wise IKEv2. */
    bool ikev1_sa;

    /** Set to true if IPsec SA is in tunnel mode, false for transport
        mode. */
    bool tunnel_mode;

    /** NAT-T local original address. */
    struct InAddr natt_local_original_address;

    /** NAT-T remote original address. */
    struct InAddr natt_remote_original_address;

    /** Set to true if Extended Sequence Numbers are used for the IPsec
        SA. */
    bool esn;

    /** Set to true is this IPsec SA was negotiated as initiator. */
    bool initiator;

    /** Set to true is this IPsec SA is a rekey for an existing SA. */
    bool rekey;

    /** Set to true when this IPsec SA has been rekeyed. */
    bool rekeyed;

    /** Set to true before removal, when the IPsec is last in a chain
        of rekeys. */
    bool last;

    /** Don't Fragment Bit policy on IPsec packets. */
    IPsecSaDontFragmentBitPolicy dont_fragment_bit_policy;

    /** Set to true to enable stateful fragment checking for IPsec
        SA. */
    bool stateful_fragment_check;

    /** IPsec life time in seconds. */
    uint32_t life_seconds;

    /** IPsec life time in bytes. */
    uint64_t life_bytes;

    /** IPsec life time in bytes when IPsec SA should be rekeyed. */
    uint64_t life_bytes_rekey;

    /** UDP NAT-T keepalive timeout is seconds. */
    int natt_keepalive_timeout;

    /** Idle timeout threshold in seconds */
    int idle_timeout_threshold_seconds;

    /** Idle event interval in seconds */
    int idle_event_interval_seconds;

    /** Policy priority for SPD-O entries of the SA. */
    uint32_t policy_priority;

    /** Traffic selectors */
    struct IPSelectorGroup *selector_group;

    /** Event identifier. */
    int event_id;

    /** Event identifier to inbound direction. */
    uint32_t event_id_inbound;

    /** Event identifier to outbound direction. */
    uint32_t event_id_outbound;

    /** Sequence number (high is used if the sequence has 64 bits)*/
    uint32_t seq_high;
    uint32_t seq_low;
};

#endif /* IPSEC_SA_PARAMS_H */
