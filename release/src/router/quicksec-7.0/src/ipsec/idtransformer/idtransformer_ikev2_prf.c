/**
   @copyright
   Copyright (c) 2012 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Conversions functions between IKEv2 prf identifiers and
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
    { TRANSFORMID_PRF_HMAC_MD5,          1},
    { TRANSFORMID_PRF_HMAC_SHA1,         2},
    { TRANSFORMID_PRF_HMAC_TIGER,        3},
    { TRANSFORMID_PRF_HMAC_AES_128_XCBC, 4},
    { TRANSFORMID_PRF_HMAC_SHA2_256,     5},
    { TRANSFORMID_PRF_HMAC_SHA2_384,     6},
    { TRANSFORMID_PRF_HMAC_SHA2_512,     7},

    { TRANSFORMID_INVALID, -1 }
};


int
idtransformer_id_to_ikev2_prf_id(TransformId id)
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


