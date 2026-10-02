/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   Internal header for IKE/IPsec algorithm functionality.
*/

#ifndef UTIL_ALGORITHMS_INTERNAL_H
#define UTIL_ALGORITHMS_INTERNAL_H


/** A cipher algorithm. */
struct SshPmCipherRec
{
    /** Bit mask, using the values from the `quicksec_pm.h' for selecting this
       encryption algorithm. */
    uint32_t mask_bits;

    /** The name of the algorithm. */
    char *name;

    /** The allowed minimum and maximum key sizes (in bits) for the
       algorithm. */
    uint32_t min_key_size;
    uint32_t max_key_size;

    /** The default key size (in bits) we use when we are initiating
       using this algorithm. */
    uint32_t default_key_size;

    /** They increment of the key size for variable key size algorithms.
       This has the value 0 for fixed key size ciphers. */
    uint32_t key_increment;

    /** The cipher block size (in bits). This is used for calculating the
        padding length for outbound packets. For counter mode and NULL
        algorithms this is the pad boundary required by ESP. For other
        algorithms this is the cipher output block size. */
    uint32_t block_size;

    /** The size (in bits) of the cipher iv that is sent on the wire. For cbc
       mode this is always equal to the cipher block size. For counter mode,
       the iv size is usually less than the cipher block size. */
    uint32_t iv_size;

    /** The size in bits of the nonce that this cipher may use. Only non-zero
       for counter mode encryption.  */
    uint32_t nonce_size;

    /** The IKE ESP transform identifiers for this encryption
       algorithm. */
    SshIkev2TransformID esp_transform_id;

    /** The IKE encryption algorithm identifier for this cipher. */
    SshIkev2TransformID ike_encr_transform_id;
};

typedef struct SshPmCipherRec SshPmCipherStruct;
typedef struct SshPmCipherRec *SshPmCipher;

/** A MAC algorithm. */
struct SshPmMacRec
{
    /** Bit mask, using the values from the `quicksec_pm.h' for selecting this
       MAC algorithm. Use array element 0 for ESP/IKE and array element 1
       for AH. */
    uint32_t mask_bits[2];

    /** The name of the algorithm. */
    char *name;

    /* The digest size in bits of the MAC */
    uint32_t digest_size;

    /** The allowed minimum and maximum key sizes (in bits) for the
       algorithm. */
    uint32_t min_key_size;
    uint32_t max_key_size;

    /** The default key size (in bits) we use when we are initiating
       using this algorithm. */
    uint32_t default_key_size;

    /** The increment of the key size for variable key size algorithms.
       This has the value 0 for fixed key size MACs. */
    uint32_t key_increment;

    /** The size (in bits) of the iv that is sent on the wire. Only non-zero
        for counter mode macs. */
    uint32_t iv_size;

    /** The size in bits of the nonce that this mac may use. Only non-zero
        for counter mode macs.  */
    uint32_t nonce_size;

    /** The IPsec transform identifier for this MAC algorithm. */
    SshIkev2TransformID ipsec_transform_id;

    /** The IKE Integrity transform identifier for this MAC algorithm. */
    SshIkev2TransformID ike_auth_transform_id;

    /** The IKE authentication algorithm identifier for this MAC
       algorithms. */
    SshIkev2TransformID ike_prf_transform_id;

    /** Is there more IPsec transform identifiers for this
        MAC algorithms? (MAC algorithms are layed out so that
        first one does not contain identifier at all
        (as there is no common identifier for MAC, but separate
        identifiers for each possible keysize), but
        only size range, then the next entries contain
        identifiers for different sizes). */
    bool more_ipsec_transform_ids;

    /* Is this super entry possibly containing some children or
       standalone entry.  Subentries of super entry have this flag set
       as false. */
    bool master_flag;
};

typedef struct SshPmMacRec SshPmMacStruct;
typedef struct SshPmMacRec *SshPmMac;

/** A compression algorithm. */
struct SshPmCompressionRec
{
    /** Bit mask, using the values from the `quicksec_pm.h' for selecting this
       compression algorithm. */
    uint32_t mask_bits;

    /** The name of the algorithm. */
    char *name;

    /** The IKE IPComp transform identifier for this compression
       algorithm. */
    SshIkev2IPCompTypes ipcomp_transform_id;
};

typedef struct SshPmCompressionRec SshPmCompressionStruct;
typedef struct SshPmCompressionRec *SshPmCompression;

/** A Diffie-Hellman group. */
struct SshPmDHGroupRec
{
    /** Bit mask, using the values from the `quicksec_pm.h' for selecting this
       Diffie-Hellman group. */
    uint32_t mask_bits;

    /** The IKE group description number. 0xffff is end of array marker. */
    uint16_t group_desc;

    /** The group size in bits. */
    uint16_t group_size;

   /** The preference value for this group. */
    uint8_t preference;
};

typedef struct SshPmDHGroupRec SshPmDHGroupStruct;
typedef struct SshPmDHGroupRec *SshPmDHGroup;

/** Algorithm properties. */
struct SshPmAlgorithmPropertiesRec
{
    struct SshPmAlgorithmPropertiesRec *next;

    /** Algorithm specifier and usage flags for this properties structure. */
    uint32_t algorithm;

    /** Properties. */
    uint32_t min_key_size;
    uint32_t max_key_size;
    uint32_t default_key_size;
};

typedef struct SshPmAlgorithmPropertiesRec SshPmAlgorithmPropertiesStruct;
typedef struct SshPmAlgorithmPropertiesRec *SshPmAlgorithmProperties;


/* ******************************* Algorithms ********************************/

/** Check if the group represented by the integer 'group' is known to the
   system. Known groups are of the form SSH_PM_DH_GROUP_* as defined in
   ipsec_pm.h. Returns true if the group is known and false otherwise. */
bool ssh_pm_dh_group_is_known(uint32_t group);

/** Count the number of algorithms the tunnel attributes `algorithms'
   and `dhflags' specify for IKE SA.  The function returns true if all
   algorithms were known and false otherwise. */
bool ssh_pm_ike_num_algorithms(SshPm pm,
                                  uint32_t algorithms, uint32_t dhflags,
                                  uint32_t *num_ciphers_return,
                                  uint32_t *num_hashes_return,
                                  uint32_t *num_dh_groups_return);

/** Count the number of algorithms the transform `transform' specifies
   for IPSec SA.  The function returns true if all algorithms were
   known and false otherwise. */
bool ssh_pm_ipsec_num_algorithms(SshPm pm,
                                    SshPmTransform transform,
                                    uint32_t dhflags,
                                    uint32_t *num_ciphers_return,
                                    uint32_t *num_macs_return,
                                    uint32_t *num_compressions_return,
                                    uint32_t *num_dh_return);

/** Return the `index'th IKE encryption algorithm matching the algorithm
   specification `algorithms'. */
SshPmCipher ssh_pm_ike_cipher(SshPm pm, uint32_t index, uint32_t algorithms);

/** Return the `index'th IPSec encryption algorithm matching the algorithm
   specification `algorithms'. */
SshPmCipher ssh_pm_ipsec_cipher(SshPm pm, uint32_t index,
                                uint32_t algorithms);

/* Return the `index'th IPSec encryption algorithm matching the transform id
   `id'. */
SshPmCipher ssh_pm_ipsec_cipher_by_id(SshPm pm, SshIkev2TransformID id);


/** Return the `index'th IKE MAC algorithm matching the algorithm
   specification `algorithm'. */
SshPmMac ssh_pm_ike_mac(SshPm pm, uint32_t index, uint32_t algorithm);

/** Return the `index'th IPSec MAC algorithm matching the algorithm
   specification `algorithm'. */
SshPmMac ssh_pm_ipsec_mac(SshPm pm, uint32_t index, uint32_t algorithm);

/** Return the `index'th IPSec MAC algorithm matching the transform ID `id'. */
SshPmMac ssh_pm_ipsec_mac_by_id(SshPm pm, SshIkev2TransformID id);

/** Return the `index'th compression algorithm matching the transform
   specification `transform'. */
SshPmCompression ssh_pm_compression(SshPm pm,
                                    uint32_t index, SshPmTransform transform);

/** Return the `index'th Diffie-Hellman group matching DH flags
   `dhflags'. */
SshPmDHGroup ssh_pm_dh_group(SshPm pm, uint32_t index, uint32_t dhflags);

/** Return the size of the Diffie-Hellman group `group_desc'. */
uint16_t ssh_pm_dh_group_size(SshPm pm, uint16_t group_desc);

/** A predicate to check if the cipher has fixed key length. */
bool ssh_pm_cipher_is_fixed_key_length(SshPmCipher cipher);

/** A predicate to check if the mac has fixed key length. */
bool ssh_pm_mac_is_fixed_key_length(SshPmMac mac);

/** Return the cipher key sizes for the tunnel `tunnel'.  If any of the
   `{min,max,default,increment}_key_size_return' is NULL, the corresponding
   value is not returned. */
void ssh_pm_cipher_key_sizes(SshPmTunnel tunnel,
                             SshPmCipher cipher,
                             uint32_t scope,
                             uint32_t *min_key_size_return,
                             uint32_t *max_key_size_return,
                             uint32_t *increment_key_size_return,
                             uint32_t *default_key_size_return);

/** Return the MAC key sizes for the tunnel `tunnel'.  If any of the
   `{min,max,default,increment}_key_sizes_return' is NULL, the corresponding
   value is not returned. */
void ssh_pm_mac_key_sizes(SshPmTunnel tunnel,
                          SshPmMac mac,
                          uint32_t scope,
                          uint32_t *min_key_size_return,
                          uint32_t *max_key_size_return,
                          uint32_t *increment_key_size_return,
                          uint32_t *default_key_size_return);

/** Return IPSec Authentication algorithm ID for given MAC and key_size.
    If no such algorithm is found, zero is returned. */
SshIkev2TransformID
ssh_pm_mac_auth_id_for_keysize(SshPmMac mac, uint32_t key_size);

/** Return IKE Authentication algorithm ID for given MAC and key_size.
    If no such algorithm is found, zero is returned. */
SshIkev2TransformID
ssh_pm_mac_ike_auth_id_for_keysize(SshPmMac mac, uint32_t key_size);

/** Return IKE PRF algorithm ID for given MAC and key_size.
    If no such algorithm is found, zero is returned. */
SshIkev2TransformID
ssh_pm_mac_ike_prf_id_for_keysize(SshPmMac mac, uint32_t key_size);

#endif /* not UTIL_ALGORITHMS_INTERNAL_H */
