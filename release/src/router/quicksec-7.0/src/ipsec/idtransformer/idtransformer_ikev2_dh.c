/**
   @copyright
   Copyright (c) 2012 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Conversions functions between IKEv2 DH identifiers and generic
   TransformIds.
*/

#include "idtransformer.h"

static const struct
{
    TransformId transformid;
    int ikev2_id;
}
ikev2id_table[] =
{
    { TRANSFORMID_D_H_NONE,                0 },
    { TRANSFORMID_D_H_MODP_768,            1 },
    { TRANSFORMID_D_H_MODP_1024,           2 },
    { TRANSFORMID_D_H_MODP_1536,           5 },
    { TRANSFORMID_D_H_MODP_2048,           14 },
    { TRANSFORMID_D_H_MODP_3072,           15 },
    { TRANSFORMID_D_H_MODP_4096,           16 },
    { TRANSFORMID_D_H_MODP_6144,           17 },
    { TRANSFORMID_D_H_MODP_8192,           18 },
    { TRANSFORMID_D_H_ECP_256,             19 },
    { TRANSFORMID_D_H_ECP_384,             20 },
    { TRANSFORMID_D_H_ECP_512,             21 },
    { TRANSFORMID_D_H_MODP_1024_160,       22 },
    { TRANSFORMID_D_H_MODP_2048_224,       23 },
    { TRANSFORMID_D_H_MODP_2048_256,       24 },
    { TRANSFORMID_D_H_ECP_192,             25 },
    { TRANSFORMID_D_H_ECP_224,             26 },
    { TRANSFORMID_D_H_BRAINPOOL_ECP_224,   27 },
    { TRANSFORMID_D_H_BRAINPOOL_ECP_256,   28 },
    { TRANSFORMID_D_H_BRAINPOOL_ECP_384,   29 },
    { TRANSFORMID_D_H_BRAINPOOL_ECP_512,   30 },

    { TRANSFORMID_INVALID, -1 }
};


int
idtransformer_id_to_ikev2_dh_id(TransformId id)
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
idtransformer_id_from_ikev2_dh_id(int ike_id)
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

