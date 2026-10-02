/**
   @copyright
   Copyright (c) 2014 - 2015, INSIDE Secure Oy. All rights reserved.
*/

#include "idtransformer.h"

static const struct
{
    TransformId transformid;
    int algorithm_security_strength;
}
alg_strength_table[] =
{
    /* Encryption */
    { TRANSFORMID_ENCR_3DES_CBC,         112},
    { TRANSFORMID_ENCR_AES_128_CBC,      128},
    { TRANSFORMID_ENCR_AES_192_CBC,      192},
    { TRANSFORMID_ENCR_AES_256_CBC,      256},
    { TRANSFORMID_ENCR_AES_128_CTR,      128},
    { TRANSFORMID_ENCR_AES_192_CTR,      192},
    { TRANSFORMID_ENCR_AES_256_CTR,      256},
    { TRANSFORMID_ENCR_AES_128_CCM_8,    128},
    { TRANSFORMID_ENCR_AES_192_CCM_8,    192},
    { TRANSFORMID_ENCR_AES_256_CCM_8,    256},
    { TRANSFORMID_ENCR_AES_128_CCM_12,   128},
    { TRANSFORMID_ENCR_AES_192_CCM_12,   192},
    { TRANSFORMID_ENCR_AES_256_CCM_12,   256},
    { TRANSFORMID_ENCR_AES_128_CCM_16,   128},
    { TRANSFORMID_ENCR_AES_192_CCM_16,   192},
    { TRANSFORMID_ENCR_AES_256_CCM_16,   256},
    { TRANSFORMID_ENCR_AES_128_GCM_8,    128},
    { TRANSFORMID_ENCR_AES_192_GCM_8,    192},
    { TRANSFORMID_ENCR_AES_256_GCM_8,    256},
    { TRANSFORMID_ENCR_AES_128_GCM_12,   128},
    { TRANSFORMID_ENCR_AES_192_GCM_12,   192},
    { TRANSFORMID_ENCR_AES_256_GCM_12,   256},
    { TRANSFORMID_ENCR_AES_128_GCM_16,   128},
    { TRANSFORMID_ENCR_AES_192_GCM_16,   192},
    { TRANSFORMID_ENCR_AES_256_GCM_16,   256},

    /* PRF */
    { TRANSFORMID_PRF_HMAC_SHA1,         128},
    { TRANSFORMID_PRF_HMAC_AES_128_XCBC, 128},
    { TRANSFORMID_PRF_HMAC_SHA2_256,     256},
    { TRANSFORMID_PRF_HMAC_SHA2_384,     384},
    { TRANSFORMID_PRF_HMAC_SHA2_512,     512},

    /* Integrity */
    { TRANSFORMID_INTEG_HMAC_SHA1_96,     96},
    { TRANSFORMID_INTEG_AES_XCBC_96,      96},
    { TRANSFORMID_INTEG_HMAC_SHA256_128, 128},
    { TRANSFORMID_INTEG_HMAC_SHA384_192, 192},
    { TRANSFORMID_INTEG_HMAC_SHA512_256, 256},

    /* Groups */
    { TRANSFORMID_D_H_MODP_1024,            80},
    { TRANSFORMID_D_H_MODP_1536,            80},
    { TRANSFORMID_D_H_MODP_2048,           112},
    { TRANSFORMID_D_H_MODP_3072,           128},
    { TRANSFORMID_D_H_MODP_4096,           128},
    { TRANSFORMID_D_H_MODP_6144,           128},
    { TRANSFORMID_D_H_MODP_8192,           192},
    { TRANSFORMID_D_H_ECP_256,             128},
    { TRANSFORMID_D_H_ECP_384,             192},
    { TRANSFORMID_D_H_ECP_512,             256},
    { TRANSFORMID_D_H_MODP_1024_160,        80},
    { TRANSFORMID_D_H_MODP_2048_224,       112},
    { TRANSFORMID_D_H_MODP_2048_256,       112},
    { TRANSFORMID_D_H_ECP_192,              80},
    { TRANSFORMID_D_H_ECP_224,             112},
    { TRANSFORMID_D_H_BRAINPOOL_ECP_224,   112},
    { TRANSFORMID_D_H_BRAINPOOL_ECP_256,   128},
    { TRANSFORMID_D_H_BRAINPOOL_ECP_384,   192},
    { TRANSFORMID_D_H_BRAINPOOL_ECP_512,   256},

    /* Not found */
    {TRANSFORMID_INVALID,                  0}
};

int transformid_to_security_strength(TransformId id)
{
    int i;

    for (i = 0; alg_strength_table[i].transformid != TRANSFORMID_INVALID; i++)
    {
        if (alg_strength_table[i].transformid == id)
          return alg_strength_table[i].algorithm_security_strength;
    }

    return 0;
}
