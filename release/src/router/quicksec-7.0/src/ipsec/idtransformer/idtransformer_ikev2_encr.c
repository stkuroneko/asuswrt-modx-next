/**
   @copyright
   Copyright (c) 2012 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Conversions functions between IKEv2 encryption identifiers and
   generic TransformIds.
*/

#include "idtransformer.h"

static const struct
{
    TransformId transformid;
    int ikev2_id;
    int fixed_key;
    int keylength;
}
ikev2id_table[] =
{
    { TRANSFORMID_ENCR_NULL,                    11, 1,   0 },
    { TRANSFORMID_ENCR_3DES_CBC,                 3, 1, 192 },
    { TRANSFORMID_ENCR_AES_128_CBC,             12, 0, 128 },
    { TRANSFORMID_ENCR_AES_192_CBC,             12, 0, 192 },
    { TRANSFORMID_ENCR_AES_256_CBC,             12, 0, 256 },
    { TRANSFORMID_ENCR_AES_128_CTR,             13, 0, 128 },
    { TRANSFORMID_ENCR_AES_192_CTR,             13, 0, 192 },
    { TRANSFORMID_ENCR_AES_256_CTR,             13, 0, 256 },
    { TRANSFORMID_ENCR_AES_128_CCM_8,           14, 0, 128 },
    { TRANSFORMID_ENCR_AES_192_CCM_8,           14, 0, 192 },
    { TRANSFORMID_ENCR_AES_256_CCM_8,           14, 0, 256 },
    { TRANSFORMID_ENCR_AES_128_CCM_12,          15, 0, 128 },
    { TRANSFORMID_ENCR_AES_192_CCM_12,          15, 0, 192 },
    { TRANSFORMID_ENCR_AES_256_CCM_12,          15, 0, 256 },
    { TRANSFORMID_ENCR_AES_128_CCM_16,          16, 0, 128 },
    { TRANSFORMID_ENCR_AES_192_CCM_16,          16, 0, 192 },
    { TRANSFORMID_ENCR_AES_256_CCM_16,          16, 0, 256 },
    /* Unassigned 17 */
    { TRANSFORMID_ENCR_AES_128_GCM_8,           18, 0, 128 },
    { TRANSFORMID_ENCR_AES_192_GCM_8,           18, 0, 192 },
    { TRANSFORMID_ENCR_AES_256_GCM_8,           18, 0, 256 },
    { TRANSFORMID_ENCR_AES_128_GCM_12,          19, 0, 128 },
    { TRANSFORMID_ENCR_AES_192_GCM_12,          19, 0, 192 },
    { TRANSFORMID_ENCR_AES_256_GCM_12,          19, 0, 256 },
    { TRANSFORMID_ENCR_AES_128_GCM_16,          20, 0, 128 },
    { TRANSFORMID_ENCR_AES_192_GCM_16,          20, 0, 192 },
    { TRANSFORMID_ENCR_AES_256_GCM_16,          20, 0, 256 },
    { TRANSFORMID_ENCR_AES_128_GMAC,            21, 0, 128 },
    { TRANSFORMID_ENCR_AES_192_GMAC,            21, 0, 192 },
    { TRANSFORMID_ENCR_AES_256_GMAC,            21, 0, 256 },
    /* Reserved 22 */
    { TRANSFORMID_ENCR_CAMELLIA_128_CBC,        23, 0, 128 },
    { TRANSFORMID_ENCR_CAMELLIA_192_CBC,        23, 0, 192 },
    { TRANSFORMID_ENCR_CAMELLIA_256_CBC,        23, 0, 256 },
    { TRANSFORMID_ENCR_CAMELLIA_128_CTR,        24, 0, 128 },
    { TRANSFORMID_ENCR_CAMELLIA_192_CTR,        24, 0, 192 },
    { TRANSFORMID_ENCR_CAMELLIA_256_CTR,        24, 0, 256 },
    { TRANSFORMID_ENCR_CAMELLIA_128_CCM_8,      25, 0, 128 },
    { TRANSFORMID_ENCR_CAMELLIA_192_CCM_8,      25, 0, 192 },
    { TRANSFORMID_ENCR_CAMELLIA_256_CCM_8,      25, 0, 256 },
    { TRANSFORMID_ENCR_CAMELLIA_128_CCM_12,     26, 0, 128 },
    { TRANSFORMID_ENCR_CAMELLIA_192_CCM_12,     26, 0, 192 },
    { TRANSFORMID_ENCR_CAMELLIA_256_CCM_12,     26, 0, 256 },
    { TRANSFORMID_ENCR_CAMELLIA_128_CCM_16,     27, 0, 128 },
    { TRANSFORMID_ENCR_CAMELLIA_192_CCM_16,     27, 0, 192 },
    { TRANSFORMID_ENCR_CAMELLIA_256_CCM_16,     27, 0, 256 },

    { TRANSFORMID_INVALID, -1, -1 }
};


int
idtransformer_id_to_ikev2_encr_id(TransformId id, int *keylen_p)
{
    int i;

    for (i = 0; ikev2id_table[i].transformid != TRANSFORMID_INVALID; i++)
    {
        if (ikev2id_table[i].transformid == id)
        {
            if (keylen_p != 0)
            {
                *keylen_p = 0;

                if (ikev2id_table[i].fixed_key == 0)
                {
                    *keylen_p = ikev2id_table[i].keylength;
                }
            }

            return ikev2id_table[i].ikev2_id;
        }
    }

    return -1;
}


TransformId
idtransformer_id_from_ikev2_encr_id(int ike_id, int keylen)
{
    int i;

    for (i = 0; ikev2id_table[i].transformid != TRANSFORMID_INVALID; i++)
    {
        if (ikev2id_table[i].ikev2_id == ike_id &&
            (keylen == 0 ||
             ikev2id_table[i].keylength == keylen))
        {
            return ikev2id_table[i].transformid;
        }
    }

    return TRANSFORMID_INVALID;
}

