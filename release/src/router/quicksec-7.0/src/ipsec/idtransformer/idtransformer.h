/**
   @copyright
   Copyright (c) 2011 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Transform Identifiers
*/

#include "sshenum.h"

#ifndef IDTRANSFORMER_H
#define IDTRANSFORMER_H

/** Transform identifiers

    The transform identifier consists of the following parts:

    Highest byte specifies the transform type:
    1       encryption
    2       pseudo-random function
    3       integrity
    4       Diffie-Hellman
    5       extended sequence number
    6-240   unassigned
    241-255 private use

    Second highest byte contains the optional key length distinguisher.

    Lowest two bytes contain the transform id as specified by IANA
    for IKEv2.
*/

#define TRANSFORMID_TYPE_ENCR  0x01
#define TRANSFORMID_TYPE_PRF   0x02
#define TRANSFORMID_TYPE_INTEG 0x03
#define TRANSFORMID_TYPE_D_H   0x04
#define TRANSFORMID_TYPE_ESN   0x05

#define TRANSFORMID_IS_ENCR(id) \
  (((id) >> 24) == TRANSFORMID_TYPE_ENCR ? true : false)
#define TRANSFORMID_IS_PRF(id) \
  (((id) >> 24) == TRANSFORMID_TYPE_PRF ? true : false)
#define TRANSFORMID_IS_INTEG(id) \
  (((id) >> 24) == TRANSFORMID_TYPE_INTEG ? true : false)
#define TRANSFORMID_IS_D_H(id) \
  (((id) >> 24) == TRANSFORMID_TYPE_D_H ? true : false)
#define TRANSFORMID_IS_ESN(id) \
  (((id) >> 24) == TRANSFORMID_TYPE_ESN ? true : false)

typedef enum
  {
    TRANSFORMID_INVALID =                  0x00000000,

    /* Encryption */
    TRANSFORMID_ENCR_DES_IV64 =            0x01000001,
    TRANSFORMID_ENCR_DES_CBC =             0x01000002,
    TRANSFORMID_ENCR_3DES_CBC =            0x01000003,
    TRANSFORMID_ENCR_RC5 =                 0x01000004,
    TRANSFORMID_ENCR_IDEA =                0x01000005,
    TRANSFORMID_ENCR_CAST =                0x01000006,
    TRANSFORMID_ENCR_BLOWFISH =            0x01000007,
    TRANSFORMID_ENCR_3IDEA =               0x01000008,
    TRANSFORMID_ENCR_DES_IV32 =            0x01000009,
    /* Reserved 10 */
    TRANSFORMID_ENCR_NULL =                0x0100000b,
    TRANSFORMID_ENCR_AES_128_CBC =         0x0100000c,
    TRANSFORMID_ENCR_AES_192_CBC =         0x0101000c,
    TRANSFORMID_ENCR_AES_256_CBC =         0x0102000c,
    TRANSFORMID_ENCR_AES_128_CTR =         0x0100000d,
    TRANSFORMID_ENCR_AES_192_CTR =         0x0101000d,
    TRANSFORMID_ENCR_AES_256_CTR =         0x0102000d,
    TRANSFORMID_ENCR_AES_128_CCM_8 =       0x0100000e,
    TRANSFORMID_ENCR_AES_192_CCM_8 =       0x0101000e,
    TRANSFORMID_ENCR_AES_256_CCM_8 =       0x0102000e,
    TRANSFORMID_ENCR_AES_128_CCM_12 =      0x0100000f,
    TRANSFORMID_ENCR_AES_192_CCM_12 =      0x0101000f,
    TRANSFORMID_ENCR_AES_256_CCM_12 =      0x0102000f,
    TRANSFORMID_ENCR_AES_128_CCM_16 =      0x01000010,
    TRANSFORMID_ENCR_AES_192_CCM_16 =      0x01010010,
    TRANSFORMID_ENCR_AES_256_CCM_16 =      0x01020010,
    /* Unassigned 17 */
    TRANSFORMID_ENCR_AES_128_GCM_8 =       0x01000012,
    TRANSFORMID_ENCR_AES_192_GCM_8 =       0x01010012,
    TRANSFORMID_ENCR_AES_256_GCM_8 =       0x01020012,
    TRANSFORMID_ENCR_AES_128_GCM_12 =      0x01000013,
    TRANSFORMID_ENCR_AES_192_GCM_12 =      0x01010013,
    TRANSFORMID_ENCR_AES_256_GCM_12 =      0x01020013,
    TRANSFORMID_ENCR_AES_128_GCM_16 =      0x01000014,
    TRANSFORMID_ENCR_AES_192_GCM_16 =      0x01010014,
    TRANSFORMID_ENCR_AES_256_GCM_16 =      0x01020014,
    TRANSFORMID_ENCR_AES_128_GMAC =        0x01000015,
    TRANSFORMID_ENCR_AES_192_GMAC =        0x01010015,
    TRANSFORMID_ENCR_AES_256_GMAC =        0x01020015,
    /* Reserved 22 */
    TRANSFORMID_ENCR_CAMELLIA_128_CBC =    0x01000017,
    TRANSFORMID_ENCR_CAMELLIA_192_CBC =    0x01010017,
    TRANSFORMID_ENCR_CAMELLIA_256_CBC =    0x01020017,
    TRANSFORMID_ENCR_CAMELLIA_128_CTR =    0x01000018,
    TRANSFORMID_ENCR_CAMELLIA_192_CTR =    0x01010018,
    TRANSFORMID_ENCR_CAMELLIA_256_CTR =    0x01020018,
    TRANSFORMID_ENCR_CAMELLIA_128_CCM_8 =  0x01000019,
    TRANSFORMID_ENCR_CAMELLIA_192_CCM_8 =  0x01010019,
    TRANSFORMID_ENCR_CAMELLIA_256_CCM_8 =  0x01020019,
    TRANSFORMID_ENCR_CAMELLIA_128_CCM_12 = 0x0100001a,
    TRANSFORMID_ENCR_CAMELLIA_192_CCM_12 = 0x0101001a,
    TRANSFORMID_ENCR_CAMELLIA_256_CCM_12 = 0x0102001a,
    TRANSFORMID_ENCR_CAMELLIA_128_CCM_16 = 0x0100001b,
    TRANSFORMID_ENCR_CAMELLIA_192_CCM_16 = 0x0101001b,
    TRANSFORMID_ENCR_CAMELLIA_256_CCM_16 = 0x0102001b,
    /* Unassigned 28-1023 */
    /* Private use 1024-65535 */

    /* Pseudo-random functions */
    /* Reserved 0 */
    TRANSFORMID_PRF_HMAC_MD5 =             0x02000001,
    TRANSFORMID_PRF_HMAC_SHA1 =            0x02000002,
    TRANSFORMID_PRF_HMAC_TIGER =           0x02000003,
    TRANSFORMID_PRF_HMAC_AES_128_XCBC =    0x02000004,
    TRANSFORMID_PRF_HMAC_SHA2_256 =        0x02000005,
    TRANSFORMID_PRF_HMAC_SHA2_384 =        0x02000006,
    TRANSFORMID_PRF_HMAC_SHA2_512 =        0x02000007,
    TRANSFORMID_PRF_HMAC_AES_128_CMAC =    0x02000008,
    /* Unassigned 9-1023 */
    /* Private use 1024-65535 */

    /* Integrity */
    TRANSFORMID_INTEG_NONE =               0x03000000,
    TRANSFORMID_INTEG_HMAC_MD5_96 =        0x03000001,
    TRANSFORMID_INTEG_HMAC_SHA1_96 =       0x03000002,
    TRANSFORMID_INTEG_DES_MAC =            0x03000003,
    TRANSFORMID_INTEG_KPDK_MD5 =           0x03000004,
    TRANSFORMID_INTEG_AES_XCBC_96 =        0x03000005,
    TRANSFORMID_INTEG_HMAC_MD5_128 =       0x03000006,
    TRANSFORMID_INTEG_HMAC_SHA1_160 =      0x03000007,
    TRANSFORMID_INTEG_AES_CMAC_96 =        0x03000008,
    TRANSFORMID_INTEG_AES_128_GMAC =       0x03000009,
    TRANSFORMID_INTEG_AES_192_GMAC =       0x0300000a,
    TRANSFORMID_INTEG_AES_256_GMAC =       0x0300000b,
    TRANSFORMID_INTEG_HMAC_SHA256_128 =    0x0300000c,
    TRANSFORMID_INTEG_HMAC_SHA384_192 =    0x0300000d,
    TRANSFORMID_INTEG_HMAC_SHA512_256 =    0x0300000e,
    /* Unassigned 15-1023 */
    /* Private use 1024-65535 */

    /* Diffie-Hellman */
    TRANSFORMID_D_H_NONE =                 0x04000000,
    TRANSFORMID_D_H_MODP_768 =             0x04000001,
    TRANSFORMID_D_H_MODP_1024 =            0x04000002,
    /* Reserved 3-4 */
    TRANSFORMID_D_H_MODP_1536 =            0x04000005,
    /* Unassigned 6-13 */
    TRANSFORMID_D_H_MODP_2048 =            0x0400000e,
    TRANSFORMID_D_H_MODP_3072 =            0x0400000f,
    TRANSFORMID_D_H_MODP_4096 =            0x04000010,
    TRANSFORMID_D_H_MODP_6144 =            0x04000011,
    TRANSFORMID_D_H_MODP_8192 =            0x04000012,
    TRANSFORMID_D_H_ECP_256 =              0x04000013,
    TRANSFORMID_D_H_ECP_384 =              0x04000014,
    TRANSFORMID_D_H_ECP_512 =              0x04000015,
    TRANSFORMID_D_H_MODP_1024_160 =        0x04000016,
    TRANSFORMID_D_H_MODP_2048_224 =        0x04000017,
    TRANSFORMID_D_H_MODP_2048_256 =        0x04000018,
    TRANSFORMID_D_H_ECP_192 =              0x04000019,
    TRANSFORMID_D_H_ECP_224 =              0x0400001a,
    TRANSFORMID_D_H_BRAINPOOL_ECP_224 =    0x0400001b,
    TRANSFORMID_D_H_BRAINPOOL_ECP_256 =    0x0400001c,
    TRANSFORMID_D_H_BRAINPOOL_ECP_384 =    0x0400001d,
    TRANSFORMID_D_H_BRAINPOOL_ECP_512 =    0x0400001e,
    /* Unassigned 31-1023 */
    /* Private use 1024-65535 */

    /* Extended sequence numbers */
    TRANSFORMID_ESN_DISABLE =              0x05000000,
    TRANSFORMID_ESN_ENABLE =               0x05000001
    /* Reserved 2-65535 */

  } TransformId;

/** Transform id value to name mapping table */
extern const SshKeywordStruct transformid_names[];

int idtransformer_id_to_ikev2_encr_id(TransformId id, int *keylen_p);
TransformId idtransformer_id_from_ikev2_encr_id(int ike_id, int keylen);

int idtransformer_id_to_ikev2_integ_id(TransformId id);
TransformId idtransformer_id_from_ikev2_integ_id(int ike_id);

int idtransformer_id_to_ikev2_prf_id(TransformId id);

int idtransformer_id_to_ikev2_dh_id(TransformId id);
TransformId idtransformer_id_from_ikev2_dh_id(int ike_id);

int transformid_to_security_strength(TransformId id);

const char *idtransformer_to_string(TransformId id);

#endif /* IDTRANSFORMER_H */
