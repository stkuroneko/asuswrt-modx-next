/**
   @copyright
   Copyright (c) 2012 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Conversions functions between IKEv2 integrity identifiers and
   generic TransformIds.
*/

#include "idtransformer.h"

static const struct
{
    TransformId transformid;
    int ikev2_id;
}
ikev2id_table[] =
{
    { TRANSFORMID_INTEG_NONE, 0 },
    { TRANSFORMID_INTEG_HMAC_MD5_96, 1 },
    { TRANSFORMID_INTEG_HMAC_SHA1_96, 2 },
    { TRANSFORMID_INTEG_AES_XCBC_96, 5 },
    { TRANSFORMID_INTEG_HMAC_SHA256_128, 12 },
    { TRANSFORMID_INTEG_HMAC_SHA384_192, 13},
    { TRANSFORMID_INTEG_HMAC_SHA512_256, 14 },
    { TRANSFORMID_INTEG_AES_128_GMAC, 9 },
    { TRANSFORMID_INTEG_AES_192_GMAC, 10 },
    { TRANSFORMID_INTEG_AES_256_GMAC, 11 },

    { TRANSFORMID_INVALID, -1 }
};


int
idtransformer_id_to_ikev2_integ_id(TransformId id)
{
    int i;

    for (i = 0; ikev2id_table[i].transformid != TRANSFORMID_INVALID; i++)
    {
        if (ikev2id_table[i].transformid == id)
        {
            return ikev2id_table[i].ikev2_id;
        }
    }

    return -1;
}


TransformId
idtransformer_id_from_ikev2_integ_id(int ike_id)
{
    int i;

    for (i = 0; ikev2id_table[i].transformid != TRANSFORMID_INVALID; i++)
    {
        if (ikev2id_table[i].ikev2_id == ike_id)
        {
            return ikev2id_table[i].transformid;
        }
    }

    return TRANSFORMID_INVALID;
}

