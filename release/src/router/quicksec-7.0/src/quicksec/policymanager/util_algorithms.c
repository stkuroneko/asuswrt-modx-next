/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   Known algorithms.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"

#define SSH_DEBUG_MODULE "SshPmAlgorithms"

#undef SSH_IPSEC_IPCOMP_LZS_AVAILABLE






#define PM_IPSEC_AES_KEY_MAX 256

#if SSH_IPSEC_MAX_ESP_KEY_BITS < PM_IPSEC_AES_KEY_MAX
# undef PM_IPSEC_AES_KEY_MAX
# if SSH_IPSEC_MAX_ESP_KEY_BITS > 191
#  define PM_IPSEC_AES_KEY_MAX 192
# elif SSH_IPSEC_MAX_ESP_KEY_BITS > 127
#  define PM_IPSEC_AES_KEY_MAX 128
# else
#  error "SSH_IPSEC_MAX_ESP_KEY_BITS too small in ipsec_params.h"
# endif
#endif
















static const SshPmCipherStruct ssh_pm_ciphers[] =
{
    /* Mask bits            Name          Min   Max  Def  Incr  Blck  IV  Nonce
     */
#ifdef SSHDIST_CRYPT_RIJNDAEL
    {SSH_PM_CRYPT_AES,    "aes-cbc",      128,  PM_IPSEC_AES_KEY_MAX,
                                                     128,  64,  128, 128,   0,
     SSH_IKEV2_TRANSFORM_ENCR_AES_CBC,
     SSH_IKEV2_TRANSFORM_ENCR_AES_CBC},

    {SSH_PM_CRYPT_AES_CTR, "aes-ctr",     128,  PM_IPSEC_AES_KEY_MAX,
                                                     128,  64,   32,  64,  32,
     SSH_IKEV2_TRANSFORM_ENCR_AES_CTR,
     SSH_IKEV2_TRANSFORM_ENCR_AES_CTR},

#ifdef SSHDIST_CRYPT_MODE_GCM
    {SSH_PM_CRYPT_AES_GCM, "aes-gcm",     128,  PM_IPSEC_AES_KEY_MAX,
                                                     128,  64,   32,  64,  32,
     SSH_IKEV2_TRANSFORM_ENCR_AES_GCM_16,
     SSH_IKEV2_TRANSFORM_ENCR_AES_GCM_16},

    {SSH_PM_CRYPT_AES_GCM_8, "aes-gcm-64",128,  PM_IPSEC_AES_KEY_MAX,
                                                     128,  64,   32,  64,  32,
     SSH_IKEV2_TRANSFORM_ENCR_AES_GCM_8,
     SSH_IKEV2_TRANSFORM_ENCR_AES_GCM_8},

    {SSH_PM_CRYPT_AES_GCM_12, "aes-gcm-96",128, PM_IPSEC_AES_KEY_MAX,
                                                     128,  64,   32,  64,  32,
     SSH_IKEV2_TRANSFORM_ENCR_AES_GCM_12,
     SSH_IKEV2_TRANSFORM_ENCR_AES_GCM_12},

    {SSH_PM_CRYPT_NULL_AUTH_AES_GMAC, "null-auth-aes-gmac",
                                          128,  PM_IPSEC_AES_KEY_MAX,
                                                     128,  64,   32,  64,  32,
     SSH_IKEV2_TRANSFORM_ENCR_NULL_AUTH_AES_GMAC,
     0},
#endif /* SSHDIST_CRYPT_MODE_GCM */
#ifdef SSHDIST_CRYPT_MODE_CCM
    {SSH_PM_CRYPT_AES_CCM, "aes-ccm",     128,  PM_IPSEC_AES_KEY_MAX,
                                                     128,  64,   32,  64,  24,
     SSH_IKEV2_TRANSFORM_ENCR_AES_CCM_16,
     SSH_IKEV2_TRANSFORM_ENCR_AES_CCM_16},

    {SSH_PM_CRYPT_AES_CCM_8, "aes-ccm-64",128,  PM_IPSEC_AES_KEY_MAX,
                                                     128,  64,   32,  64,  24,
     SSH_IKEV2_TRANSFORM_ENCR_AES_CCM_8,
     SSH_IKEV2_TRANSFORM_ENCR_AES_CCM_8},

    {SSH_PM_CRYPT_AES_CCM_12, "aes-ccm-96",128, PM_IPSEC_AES_KEY_MAX,
                                                     128,  64,   32,  64,  24,
     SSH_IKEV2_TRANSFORM_ENCR_AES_CCM_12,
     SSH_IKEV2_TRANSFORM_ENCR_AES_CCM_12},

#endif /* SSHDIST_CRYPT_MODE_CCM */
#endif /* SSHDIST_CRYPT_RIJNDAEL */

#ifdef SSHDIST_CRYPT_DES
#if SSH_IPSEC_MAX_ESP_KEY_BITS > 191
    {SSH_PM_CRYPT_3DES,   "3des-cbc",     192,  192, 192,   0,   64,  64,   0,
     SSH_IKEV2_TRANSFORM_ENCR_3DES,
     SSH_IKEV2_TRANSFORM_ENCR_3DES},
#endif
#ifndef HAVE_FIPSLIB
#ifdef SSH_IPSEC_CRYPT_DES
    {SSH_PM_CRYPT_DES,    "des-cbc",       64,   64,  64,   0,   64,  64,   0,
     SSH_IKEV2_TRANSFORM_ENCR_DES,
     SSH_IKEV2_TRANSFORM_ENCR_DES},
#endif /* SSH_IPSEC_CRYPT_DES */
#endif /* !HAVE_FIPSLIB */
#endif /* SSHDIST_CRYPT_DES */










    {SSH_PM_CRYPT_NULL,   "null",         0,      0,   0,   0,   32,   1,   0,
     SSH_IKEV2_TRANSFORM_ENCR_NULL,
     0},

    {0,                   NULL,           0,      0,    0,  0,    0,   0,   0,
     0,
     0},
};

static const SshPmMacStruct ssh_pm_macs[] =
{
    /* Mask bits               Name          Digest Min  Max  Def Incr IV Nonce
     */
#ifdef SSHDIST_CRYPT_SHA
    {{SSH_PM_MAC_HMAC_SHA1,
      SSH_PM_MAC_HMAC_SHA1},   "hmac-sha1-96",  96, 160, 160, 160,  0,  0,  0,
     SSH_IKEV2_TRANSFORM_AUTH_HMAC_SHA1_96,
     SSH_IKEV2_TRANSFORM_AUTH_HMAC_SHA1_96,
     SSH_IKEV2_TRANSFORM_PRF_HMAC_SHA1, false, true},
#endif /* SSHDIST_CRYPT_SHA */
#ifdef SSHDIST_CRYPT_SHA256
#ifdef SSHDIST_CRYPT_SHA512
    {{SSH_PM_MAC_HMAC_SHA2,
      SSH_PM_MAC_HMAC_SHA2},   "hmac-sha2",      0, 256, 512, 256, 128, 0,  0,
      0, 0, 0, true, true},
#else /* SSHDIST_CRYPT_SHA512 */
    {{SSH_PM_MAC_HMAC_SHA2,
      SSH_PM_MAC_HMAC_SHA2},   "hmac-sha2",      0, 256, 256, 256, 128, 0,  0,
      0, 0, 0, true, true},
#endif /*  SSHDIST_CRYPT_SHA512 */
#else /* SSHDIST_CRYPT_SHA256 */
#ifdef SSHDIST_CRYPT_SHA512
    {{SSH_PM_MAC_HMAC_SHA2,
      SSH_PM_MAC_HMAC_SHA2},   "hmac-sha2",      0, 384, 512, 384, 128, 0,  0,
      0, 0, 0, true, true},
#endif /*  SSHDIST_CRYPT_SHA512 */
#endif /* SSHDIST_CRYPT_SHA256 */
#ifdef SSHDIST_CRYPT_SHA256
    {{SSH_PM_MAC_HMAC_SHA2,
      SSH_PM_MAC_HMAC_SHA2}, "hmac-sha256-128", 128, 256, 256, 256, 0,  0,  0,
     SSH_IKEV2_TRANSFORM_AUTH_HMAC_SHA256_128,
     SSH_IKEV2_TRANSFORM_AUTH_HMAC_SHA256_128,
     SSH_IKEV2_TRANSFORM_PRF_HMAC_SHA256,
#ifdef SSHDIST_CRYPT_SHA512
     true,
#else /* SSHDIST_CRYPT_SHA512 */
     false,
#endif /*  SSHDIST_CRYPT_SHA512 */
     false
    },
#endif /* SSHDIST_CRYPT_SHA256 */
#ifdef SSHDIST_CRYPT_SHA512
    {{SSH_PM_MAC_HMAC_SHA2,
      SSH_PM_MAC_HMAC_SHA2}, "hmac-sha384-192", 192, 384, 384, 384, 0,  0,  0,
     SSH_IKEV2_TRANSFORM_AUTH_HMAC_SHA384_192,
     SSH_IKEV2_TRANSFORM_AUTH_HMAC_SHA384_192,
     SSH_IKEV2_TRANSFORM_PRF_HMAC_SHA384, true, false},
    {{SSH_PM_MAC_HMAC_SHA2,
      SSH_PM_MAC_HMAC_SHA2}, "hmac-sha512-256", 256, 512, 512, 512, 0,  0,  0,
     SSH_IKEV2_TRANSFORM_AUTH_HMAC_SHA512_256,
     SSH_IKEV2_TRANSFORM_AUTH_HMAC_SHA512_256,
     SSH_IKEV2_TRANSFORM_PRF_HMAC_SHA512, false, false},
#endif /* SSHDIST_CRYPT_SHA512 */
#ifdef SSHDIST_CRYPT_XCBCMAC
#ifdef SSHDIST_CRYPT_RIJNDAEL
    {{SSH_PM_MAC_XCBC_AES,
      SSH_PM_MAC_XCBC_AES},    "xcbc-aes-96",    96, 128, 128, 128, 0,  0,  0,
     SSH_IKEV2_TRANSFORM_AUTH_AES_XCBC_96,
     SSH_IKEV2_TRANSFORM_AUTH_AES_XCBC_96,
     SSH_IKEV2_TRANSFORM_PRF_AES128_CBC, false, true},
#endif /*  SSHDIST_CRYPT_RIJNDAEL */
#endif /* SSHDIST_CRYPT_XCBCMAC */
#ifdef SSHDIST_CRYPT_RIJNDAEL
#ifdef SSHDIST_CRYPT_MODE_GCM
    {{0,
      SSH_PM_CRYPT_NULL_AUTH_AES_GMAC},
     "gmac-aes-128",    128, 128, 256, 128, 64, 64,  32,
     0, 0, 0, true, true},
    {{0,
      SSH_PM_CRYPT_NULL_AUTH_AES_GMAC},
     "gmac-aes128-128", 128, 128, 128, 128, 0,  64,  32,
     SSH_IKEV2_TRANSFORM_AUTH_AES_128_GMAC_128,
     0, 0, true, false},
    {{0,
      SSH_PM_CRYPT_NULL_AUTH_AES_GMAC},
     "gmac-aes192-128", 128, 192, 192, 192, 0,  64,  32,
     SSH_IKEV2_TRANSFORM_AUTH_AES_192_GMAC_128,
     0, 0, true, false},
    {{0,
      SSH_PM_CRYPT_NULL_AUTH_AES_GMAC},
     "gmac-aes256-128", 128, 256, 256, 256, 0,  64,  32,
     SSH_IKEV2_TRANSFORM_AUTH_AES_256_GMAC_128,
     0, 0, false, false},
#endif /* SSHDIST_CRYPT_MODE_GCM */
#endif /* SSHDIST_CRYPT_RIJNDAEL */

    {{0, 0},                   NULL,
     0,   0,   0,   0,  0,  0,   0,
     0, 0, false, false},
};


static const SshPmCompressionStruct ssh_pm_compressions[] =
{
    /* Mask bits                  Name       IKE ID */
#if defined SSH_IPSEC_IPCOMP_IN_SOFTWARE
#ifdef SSHDIST_IPSEC_COMPRESSION_DEFLATE
    {SSH_PM_COMPRESS_DEFLATE,     "deflate", SSH_IKEV2_IPCOMP_DEFLATE},
#endif /* SSHDIST_IPSEC_COMPRESSION_DEFLATE */
#ifdef SSHDIST_IPSEC_COMPRESSION_LZS
#ifdef SSH_IPSEC_IPCOMP_LZS_AVAILABLE
    {SSH_PM_COMPRESS_LZS,         "lzs",     SSH_IKEV2_IPCOMP_LZS},
#endif /* SSH_IPSEC_IPCOMP_LZS_AVAILABLE */
#endif /* SSHDIST_IPSEC_COMPRESSION_LZS */
#endif /* defined SSH_IPSEC_IPCOMP_IN_SOFTWARE .. */
    {0,                           NULL,      0},
};

/* Known Diffie-Hellman groups with default preference . */
static const SshPmDHGroupStruct ssh_pm_dh_groups[] =
{
    /* Mask bits          Descr   Size   Preference */
    {SSH_PM_DH_GROUP_0,   0,      0,       200},
    {SSH_PM_DH_GROUP_2,   2,      1024,    190},
    {SSH_PM_DH_GROUP_5,   5,      1536,    180},
    {SSH_PM_DH_GROUP_1,   1,      768,     170},
    {SSH_PM_DH_GROUP_14,  14,     2048,    160},
    {SSH_PM_DH_GROUP_15,  15,     3072,    150},
    {SSH_PM_DH_GROUP_16,  16,     4096,    140},
    {SSH_PM_DH_GROUP_17,  17,     6144,    130},
    {SSH_PM_DH_GROUP_18,  18,     8192,    120},
#ifdef SSHDIST_CRYPT_ECP
    {SSH_PM_DH_GROUP_19,  19,     256,     110},
    {SSH_PM_DH_GROUP_20,  20,     384,     100},
    {SSH_PM_DH_GROUP_21,  21,     521,      90},
#endif /* SSHDIST_CRYPT_ECP  */
    {SSH_PM_DH_GROUP_22,  22,     1024,    185},
    {SSH_PM_DH_GROUP_23,  23,     2048,    165},
    {SSH_PM_DH_GROUP_24,  24,     2048,    166},
#ifdef SSHDIST_CRYPT_ECP
    {SSH_PM_DH_GROUP_25,  25,     192,     125},
    {SSH_PM_DH_GROUP_26,  26,     224,     128},
#endif /* SSHDIST_CRYPT_ECP  */
#ifdef SSHDIST_CRYPT_BRAINPOOL_ECP
    {SSH_PM_DH_GROUP_27,  27,     224,     127},
    {SSH_PM_DH_GROUP_28,  28,     256,     109},
    {SSH_PM_DH_GROUP_29,  29,     384,     99},
    {SSH_PM_DH_GROUP_30,  30,     512,     89},
#endif /* SSHDIST_CRYPT_BRAINPOOL_ECP  */
    {0,                   0xffff, 0,         0},
};


/********************* Public functions for algorithms **********************/

bool
ssh_pm_ike_num_algorithms(SshPm pm,
                          uint32_t algorithms, uint32_t dhflags,
                          uint32_t *num_ciphers_return,
                          uint32_t *num_hashes_return,
                          uint32_t *num_dh_groups_return)
{
    uint32_t i;
    uint32_t count;
    uint32_t flags;
    bool result = true;
    bool is_ah = false; /* Do not consider special "AH only" algorithms. */

    /* Ciphers. */

    count = 0;
    flags = 0;

    for (i = 0; ssh_pm_ciphers[i].name; i++)
      if ((ssh_pm_ciphers[i].mask_bits & algorithms)
          && ssh_pm_ciphers[i].ike_encr_transform_id)
      {
          count++;
          flags |= ssh_pm_ciphers[i].mask_bits;
      }

    if (num_ciphers_return)
      *num_ciphers_return = count;

    /* Were all ciphers defined? */
    if ((algorithms & SSH_PM_IKE_CRYPT_MASK) != flags)
      result = false;

    /* Hashes. */

    count = 0;
    flags = 0;

    /* Use the hashes, matching the MAC algorithms. */
    for (i = 0; ssh_pm_macs[i].name; i++)
      if ((ssh_pm_macs[i].mask_bits[is_ah] & algorithms)
          && ssh_pm_macs[i].ike_auth_transform_id
          && ssh_pm_macs[i].ike_prf_transform_id)
      {
          if (!(flags & ssh_pm_macs[i].mask_bits[is_ah]))
            count++;
          flags |= ssh_pm_macs[i].mask_bits[is_ah];
      }

    /* Were all hashes defined? */
    if ((algorithms & SSH_PM_MAC_MASK) != flags)
      result = false;

    if (num_hashes_return)
      *num_hashes_return = count;

    /* Diffie-Hellman groups. */

    count = 0;
    flags = 0;

    for (i = 0; ssh_pm_dh_groups[i].group_desc != 0xffff; i++)
      if (ssh_pm_dh_groups[i].mask_bits & dhflags)
      {
          count++;
          flags |= ssh_pm_dh_groups[i].mask_bits;
      }

    if (num_dh_groups_return)
      *num_dh_groups_return = count;

    /* Were all DH groups defined. */
    if ((dhflags & 0x000fffff) != flags)
      result = false;

    return result;
}

bool
ssh_pm_ipsec_num_algorithms(SshPm pm,
                            SshPmTransform transform, uint32_t dhflags,
                            uint32_t *num_ciphers_return,
                            uint32_t *num_macs_return,
                            uint32_t *num_compressions_return,
                            uint32_t *num_dh_groups_return)
{
    uint32_t i;
    uint32_t count;
    uint32_t flags;
    bool result = true;
    bool is_ah = !!(transform & SSH_PM_IPSEC_AH);

    /* Ciphers. */
    count = 0;
    flags = 0;

    for (i = 0; ssh_pm_ciphers[i].name; i++)
      if (ssh_pm_ciphers[i].mask_bits & transform)
      {
          count++;
          flags |= ssh_pm_ciphers[i].mask_bits;
      }

    if (num_ciphers_return)
      *num_ciphers_return = count;

    /* Were all ciphers defined? */
    if ((transform & SSH_PM_CRYPT_MASK) != flags)
      /* No. */
      result = false;

    /* MACS. */
    count = 0;
    flags = 0;

    for (i = 0; ssh_pm_macs[i].name; i++)
      if (ssh_pm_macs[i].mask_bits[is_ah] & transform)
      {
          if (!(flags & ssh_pm_macs[i].mask_bits[is_ah]))
            count++;
          flags |= ssh_pm_macs[i].mask_bits[is_ah];
      }

    if (num_macs_return)
      *num_macs_return = count;

    /* Were all MACS defined? */
    if ((transform & SSH_PM_MAC_MASK) != (flags & SSH_PM_MAC_MASK))
      /* No. */
      result = false;

    /* Compressions. */
    count = 0;
    flags = 0;

    for (i = 0; ssh_pm_compressions[i].name; i++)
      if (ssh_pm_compressions[i].mask_bits & transform)
      {
          count++;
          flags |= ssh_pm_compressions[i].mask_bits;
      }

    if (num_compressions_return)
      *num_compressions_return = count;

    /* Were all compressions defined? */
    if ((transform & SSH_PM_COMPRESS_MASK) != flags)
      /* No. */
      result = false;

    /* DHs */
    count = 0;
    flags = 0;

    for (i = 0; ssh_pm_dh_groups[i].group_desc != 0xffff; i++)
      if (ssh_pm_dh_groups[i].mask_bits & dhflags)
      {
          count++;
          flags |= ssh_pm_dh_groups[i].mask_bits;
      }

    if (num_dh_groups_return)
      *num_dh_groups_return = count;

    return result;
}

SshPmCipher
ssh_pm_ike_cipher(SshPm pm, uint32_t index, uint32_t algorithms)
{
    uint32_t i;
    uint32_t matches = 0;

    for (i = 0; ssh_pm_ciphers[i].name; i++)
      if ((ssh_pm_ciphers[i].mask_bits & algorithms) &&
          ssh_pm_ciphers[i].ike_encr_transform_id)
      {
          if (matches == index)
            return (SshPmCipher) &ssh_pm_ciphers[i];

          matches++;
      }

    return NULL;
}

SshPmCipher
ssh_pm_ipsec_cipher(SshPm pm, uint32_t index, uint32_t algorithms)
{
    uint32_t i;
    uint32_t matches = 0;

    for (i = 0; ssh_pm_ciphers[i].name; i++)
      if (ssh_pm_ciphers[i].mask_bits & algorithms)
      {
          if (matches == index)
            return (SshPmCipher) &ssh_pm_ciphers[i];

          matches++;
      }

    return NULL;
}

SshPmCipher
ssh_pm_ipsec_cipher_by_id(SshPm pm, SshIkev2TransformID id)
{
    uint32_t i;

    for (i = 0; ssh_pm_ciphers[i].name; i++)
      if (ssh_pm_ciphers[i].esp_transform_id == id)
        return (SshPmCipher) &ssh_pm_ciphers[i];

    return NULL;
}

SshPmCipher
ssh_pm_cipher_by_encr_id(SshPm pm, SshIkev2TransformID id)
{
    uint32_t i;

    for (i = 0; ssh_pm_ciphers[i].name; i++)
      if (ssh_pm_ciphers[i].ike_encr_transform_id == id)
        return (SshPmCipher) &ssh_pm_ciphers[i];

    return NULL;
}

SshPmMac
ssh_pm_ike_mac(SshPm pm, uint32_t index, uint32_t algorithm)
{
    uint32_t i;
    uint32_t matches = 0;

    for (i = 0; ssh_pm_macs[i].name; i++)
      if ((ssh_pm_macs[i].mask_bits[0] & algorithm) &&
          ssh_pm_macs[i].master_flag == true)
      {
          if (matches == index)
            return (SshPmMac) &ssh_pm_macs[i];

          matches++;
      }

    return NULL;
}


SshPmMac
ssh_pm_ipsec_mac(SshPm pm, uint32_t index, uint32_t algorithms)
{
    uint32_t i;
    uint32_t matches = 0;

    for (i = 0; ssh_pm_macs[i].name; i++)
      if ((ssh_pm_macs[i].mask_bits[1] & algorithms) &&
          ssh_pm_macs[i].master_flag == true)
      {
          if (matches == index)
            return (SshPmMac) &ssh_pm_macs[i];

          matches++;
      }

    return NULL;
}

SshPmMac
ssh_pm_ipsec_mac_by_id(SshPm pm, SshIkev2TransformID id)
{
    uint32_t i;

    if (id != SSH_IKEV2_TRANSFORM_AUTH_NONE)
    {
        for (i = 0; ssh_pm_macs[i].name; i++)
          if (ssh_pm_macs[i].ipsec_transform_id == id)
            return (SshPmMac) &ssh_pm_macs[i];
    }

    return NULL;
}

SshIkev2TransformID
ssh_pm_mac_auth_id_for_keysize(SshPmMac mac,
                               uint32_t key_size)
{
    mac--;
    do
    {
        mac++;
        if (key_size >= mac->min_key_size &&
            key_size <= mac->max_key_size &&
            mac->ipsec_transform_id)
        {
            return mac->ipsec_transform_id;
        }
    }
    while (mac->more_ipsec_transform_ids);
    return 0;
}

SshIkev2TransformID
ssh_pm_mac_ike_auth_id_for_keysize(SshPmMac mac,
                                   uint32_t key_size)
{
    mac--;
    do
    {
        mac++;
        if (key_size >= mac->min_key_size &&
            key_size <= mac->max_key_size &&
            mac->ike_auth_transform_id)
        {
            return mac->ike_auth_transform_id;
        }
    }
    while (mac->more_ipsec_transform_ids);
    return 0;
}

SshIkev2TransformID
ssh_pm_mac_ike_prf_id_for_keysize(SshPmMac mac,
                                  uint32_t key_size)
{
    mac--;
    do
    {
        mac++;
        if (key_size >= mac->min_key_size &&
            key_size <= mac->max_key_size &&
            mac->ike_prf_transform_id)
        {
            return mac->ike_prf_transform_id;
        }
    }
    while (mac->more_ipsec_transform_ids);
    return 0;
}

SshPmCompression
ssh_pm_compression(SshPm pm, uint32_t index, SshPmTransform transform)
{
    uint32_t i;
    uint32_t matches = 0;

    for (i = 0; ssh_pm_compressions[i].name; i++)
    {
        if (ssh_pm_compressions[i].mask_bits & transform)
        {
            if (matches == index)
              return (SshPmCompression) &ssh_pm_compressions[i];

            matches++;
        }
    }

    return NULL;
}

bool ssh_pm_dh_group_is_known(uint32_t group)
{
    uint32_t i;

    for (i = 0; ssh_pm_dh_groups[i].group_desc != 0xffff; i++)
      if (group == ssh_pm_dh_groups[i].mask_bits)
        return true;

    return false;
}

SshPmDHGroup
ssh_pm_dh_group(SshPm pm, uint32_t index, uint32_t dhflags)
{
    uint32_t i;
    uint32_t matches = 0;

    for (i = 0; ssh_pm_dh_groups[i].group_desc != 0xffff; i++)
      if (ssh_pm_dh_groups[i].mask_bits & dhflags)
      {
          if (matches == index)
            return (SshPmDHGroup) &ssh_pm_dh_groups[i];

          matches++;
      }

    return NULL;
}

uint16_t
ssh_pm_dh_group_size(SshPm pm, uint16_t group_desc)
{
    uint32_t i;

    for (i = 0; ssh_pm_dh_groups[i].mask_bits; i++)
      if (ssh_pm_dh_groups[i].group_desc == group_desc)
        return ssh_pm_dh_groups[i].group_size;

    return 0;
}


void
ssh_pm_cipher_key_sizes(SshPmTunnel tunnel,
                        SshPmCipher cipher,
                        uint32_t scope,
                        uint32_t *min_key_size_return,
                        uint32_t *max_key_size_return,
                        uint32_t *increment_key_size_return,
                        uint32_t *default_key_size_return)
{
    uint32_t min_key_size = cipher->min_key_size;
    uint32_t max_key_size = cipher->max_key_size;
    uint32_t default_key_size = cipher->default_key_size;
    SshPmAlgorithmProperties prop;

    /* Check if the tunnel has any algorithm properties defining other
       key sizes. */
    for (prop = tunnel->algorithm_properties; prop; prop = prop->next)
    {
        if (prop->algorithm & scope
            && prop->algorithm & cipher->mask_bits)
        {
            /* Found custom key sizes. */
            min_key_size = prop->min_key_size;
            max_key_size = prop->max_key_size;
            default_key_size = prop->default_key_size;
            break;
        }
    }

    /* Return all values requested. */
    if (min_key_size_return)
      *min_key_size_return = min_key_size;
    if (max_key_size_return)
      *max_key_size_return = max_key_size;
    if (default_key_size_return)
      *default_key_size_return = default_key_size;

    if (increment_key_size_return)
      *increment_key_size_return = cipher->key_increment;
}

bool ssh_pm_cipher_is_fixed_key_length(SshPmCipher cipher)
{
    return (cipher->min_key_size == cipher->max_key_size) ? true : false;
}

void
ssh_pm_mac_key_sizes(SshPmTunnel tunnel,
                     SshPmMac mac,
                     uint32_t scope,
                     uint32_t *min_key_size_return,
                     uint32_t *max_key_size_return,
                     uint32_t *increment_key_size_return,
                     uint32_t *default_key_size_return)
{
    uint32_t min_key_size = mac->min_key_size;
    uint32_t max_key_size = mac->max_key_size;
    uint32_t default_key_size = mac->default_key_size;
    SshPmAlgorithmProperties prop;

    /* Check if the tunnel has any algorithm properties defining other
       key sizes. */
    for (prop = tunnel->algorithm_properties; prop; prop = prop->next)
    {
        if (prop->algorithm & scope
            && prop->algorithm & mac->mask_bits[1])
        {
            /* Found custom key sizes. */
            SSH_DEBUG(SSH_D_LOWOK,
                      ("Requested mac algorithm "
                       "key size for 0x%x, got 0x%x: %d-%d,step=%d <%d>\n",
                       (int)prop->min_key_size,
                       (int)prop->max_key_size,
                       (int)mac->key_increment,
                       (int)prop->default_key_size));
            min_key_size = prop->min_key_size;
            max_key_size = prop->max_key_size;
            default_key_size = prop->default_key_size;
            break;
        }
    }

    /* Return all values requested. */
    if (min_key_size_return)
      *min_key_size_return = min_key_size;
    if (max_key_size_return)
      *max_key_size_return = max_key_size;
    if (default_key_size_return)
      *default_key_size_return = default_key_size;

    if (increment_key_size_return)
     *increment_key_size_return = mac->key_increment;
}

bool ssh_pm_mac_is_fixed_key_length(SshPmMac mac)
{
    return (mac->key_increment == 0) ? true : false;
}
