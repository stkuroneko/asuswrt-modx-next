/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file contains generic functions to generate random
   multiple-precision integers.
*/

#include "sshincludes.h"

#include "sshmp.h"
#include "sshgenmp.h"
#include "sshcrypt.h"
#include "sshcrypt_i.h"

#define SSH_DEBUG_MODULE "SshGenMPInteger"

SshCryptoStatus
ssh_mprz_random_integer(SshMPInteger ret,
                        unsigned int bits,
                        unsigned int security_strength)
{
    unsigned int i, buffer_len;
    unsigned char *buffer;

    ssh_mprz_set_ui(ret, 0);

    if ((security_strength != 0) &&
        (security_strength > ssh_random_get_default_security_strength()))
    {
        SSH_DEBUG(SSH_D_ERROR,
                  ("Too low security strength RNG available for the "
                   "operation, required %u and %u was available.",
                   security_strength,
                   ssh_random_get_default_security_strength()));
        return SSH_CRYPTO_UNSUPPORTED;
    }

    buffer_len = (bits + 7) / 8;
    if ((buffer = ssh_malloc(buffer_len)) == NULL)
    {
        SSH_DEBUG(SSH_D_ERROR, ("Memory allocation failed"));
        ssh_mprz_makenan(ret, SSH_MP_NAN_ENOMEM);
        return SSH_CRYPTO_NO_MEMORY;
    }

    for (i = 0; i < buffer_len; i++)
        buffer[i] = ssh_random_object_get_byte();

    ssh_mprz_set_buf(ret, buffer, buffer_len);

    memset(buffer, 0x00, buffer_len);
    ssh_free(buffer);

    /* Cut unneeded bits off */
    ssh_mprz_mod_2exp(ret, ret, bits);

    return SSH_CRYPTO_OK;
}


/* Get random number mod 'modulo' */

/* Random number with some sense in getting only a small number of
   bits. This will avoid most of the extra bits. However, we could
   do it in many other ways too. Like we could distribute the random bits
   in reasonably random fashion around the available size. This would
   ensure that cryptographical use would be slightly safer. */
SshCryptoStatus ssh_mprz_mod_random_entropy(SshMPInteger op,
                                            SshMPIntegerConst modulo,
                                            unsigned int bits,
                                            unsigned int security_strength)
{
    SshCryptoStatus status;

    status = ssh_mprz_random_integer(op, bits, security_strength);

    ssh_mprz_mod(op, op, modulo);

    return status;
}

/* Just plain _modular_ random number generation. */
SshCryptoStatus ssh_mprz_mod_random(SshMPInteger op,
                                    SshMPIntegerConst modulo,
                                    unsigned int security_strength)
{
    SshCryptoStatus status;
    unsigned int bits;

    bits = ssh_mprz_bit_size(modulo);
    status = ssh_mprz_random_integer(op, bits, security_strength);
    ssh_mprz_mod(op, op, modulo);

    return status;
}

/* Return op, where min < op < max */
SshCryptoStatus
ssh_mprz_random_integer_between(SshMPInteger op,
                                SshMPIntegerConst min,
                                SshMPIntegerConst max,
                                unsigned int security_strength)
{
    SshCryptoStatus status;
    SshMPIntegerStruct temp;

    SSH_ASSERT(ssh_mprz_signum(min) == 1);
    SSH_ASSERT(ssh_mprz_signum(max) == 1);
    SSH_ASSERT(ssh_mprz_cmp(max, min) == 1);

    ssh_mprz_init(&temp);

    ssh_mprz_sub(&temp, max, min);
    status = ssh_mprz_mod_random(op, &temp, security_strength);
    ssh_mprz_add(op, op, min);

    ssh_mprz_clear(&temp);

    return status;
}


#ifdef SSHDIST_CRYPT_DSA

/* FIPS PUB 186-3 B.1.1 */
SshCryptoStatus
ssh_mp_fips186_ffc_keypair_generation(SshMPIntegerConst p,
                                      SshMPIntegerConst q,
                                      SshMPIntegerConst g,
                                      SshMPInteger x,
                                      SshMPInteger y)
{
    SshMPIntegerStruct c, temp;
    unsigned int p_bits, q_bits, security_strength;

    p_bits = ssh_mprz_get_size(p, 2);
    q_bits = ssh_mprz_get_size(q, 2);

    /* Accepted pairs are (1024,160), (2048,224), (2048,256) and (3072,256) */
    if ((p_bits == 1024) && (q_bits == 160))
    {
        security_strength = 80;
    }
    else if (((p_bits == 2048) && (q_bits == 224)) ||
             ((p_bits == 2048) && (q_bits == 256)))
    {
        security_strength = 112;
    }
    else if ((p_bits == 3072) && (q_bits == 256))
    {
        security_strength = 128;
    }
    else
    {
        SSH_DEBUG(SSH_D_FAIL,
                  ("Invalid prime length pair for p and q (%u,%u)",
                   p_bits, q_bits));
        return SSH_CRYPTO_KEY_INVALID;
    }


    if (!((p_bits == 1024) && (q_bits == 160)) &&
        !((p_bits == 2048) && (q_bits == 224)) &&
        !((p_bits == 2048) && (q_bits == 256)) &&
        !((p_bits == 3072) && (q_bits == 256)))
    {
        SSH_DEBUG(SSH_D_FAIL,
                  ("Invalid prime length pair for p and q (%u,%u)",
                   p_bits, q_bits));
        return SSH_CRYPTO_KEY_INVALID;
    }

    ssh_mprz_init(&c);
    ssh_mprz_init(&temp);

    if (ssh_mprz_random_integer(&c, q_bits + 64, security_strength)
        != SSH_CRYPTO_OK)
    {
        ssh_mprz_clear(&c);
        ssh_mprz_clear(&temp);
        return SSH_CRYPTO_NO_MEMORY;
    }

    /* Step 6 */
    ssh_mprz_sub_ui(&temp, q, 1);
    ssh_mprz_mod(x, &c, &temp);
    ssh_mprz_add_ui(x, x, 1);

    /* Step 7 */
    ssh_mprz_powm(y, g, x, p);

    ssh_mprz_clear(&c);
    ssh_mprz_clear(&temp);

    return SSH_CRYPTO_OK;
}

/* FIPS PUB 186-3 B.2.1 */
SshCryptoStatus
ssh_mp_fips186_ffc_per_message_secret(SshMPIntegerConst p,
                                      SshMPIntegerConst q,
                                      SshMPIntegerConst g,
                                      SshMPInteger k,
                                      SshMPInteger k_inverse)
{
    SshMPIntegerStruct c, temp;
  unsigned int p_bits, q_bits, security_strength;
  bool success;

    p_bits = ssh_mprz_get_size(p, 2);
    q_bits = ssh_mprz_get_size(q, 2);

    /* Accepted pairs are (1024,160), (2048,224), (2048,256) and (3072,256) */
    /* Accepted pairs are (1024,160), (2048,224), (2048,256) and (3072,256) */
    if ((p_bits == 1024) && (q_bits == 160))
    {
        security_strength = 80;
    }
    else if (((p_bits == 2048) && (q_bits == 224)) ||
             ((p_bits == 2048) && (q_bits == 256)))
    {
        security_strength = 112;
    }
    else if ((p_bits == 3072) && (q_bits == 256))
    {
        security_strength = 128;
    }
    else
    {
        SSH_DEBUG(SSH_D_FAIL,
                  ("Invalid prime length pair for p and q (%u,%u)",
                   p_bits, q_bits));
        return SSH_CRYPTO_KEY_INVALID;
    }

    ssh_mprz_init(&c);
    ssh_mprz_init(&temp);

    if (ssh_mprz_random_integer(&c, q_bits + 64, security_strength)
        != SSH_CRYPTO_OK)
    {
        ssh_mprz_clear(&c);
        ssh_mprz_clear(&temp);
        return SSH_CRYPTO_NO_MEMORY;
    }

    /* Step 6 */
    ssh_mprz_sub_ui(&temp, q, 1);
    ssh_mprz_mod(k, &c, &temp);
    ssh_mprz_add_ui(k, k, 1);

    /* Step 7 */
    success = ssh_mprz_mod_invert(k_inverse, k, q);

    ssh_mprz_clear(&c);
    ssh_mprz_clear(&temp);

    if (success)
      return SSH_CRYPTO_OK;
    else
      return SSH_CRYPTO_NO_MEMORY;
}
#endif /* SSHDIST_CRYPT_DSA */

#ifdef SSHDIST_CRYPT_ECP

/* Generic FIPS PUB 186-3 ECDSA random number creator used by
   private key generation and per-message secret generation.
   This is consistent with FIPS PUB 186-3 4.1 and 5.1.
*/
SshCryptoStatus
ssh_mp_fips186_ecc_random_number_generate(SshMPIntegerConst n,
                                          SshMPInteger number)
{
    SshMPIntegerStruct c, temp;
    unsigned int n_bits, security_strength;

    n_bits = ssh_mprz_get_size(n, 2);

    if (n_bits < 160)
    {
        SSH_DEBUG(SSH_D_ERROR,
                  ("Too small prime size for ECDSA: %u", n_bits));
        ssh_mprz_makenan(number, SSH_MP_NAN_ENOMEM);
        return SSH_CRYPTO_KEY_INVALID;
    }
    else if (n_bits < 224)
    {
        security_strength = 80;
    }
    else if (n_bits < 256)
    {
        security_strength = 112;
    }
    else if (n_bits < 384)
    {
        security_strength = 128;
    }
    else if (n_bits < 512)
    {
        security_strength = 192;
    }
    else if (n_bits < 522)
    {
        security_strength = 256;
    }
    else
    {
        SSH_DEBUG(SSH_D_ERROR,
                  ("Too large prime size for ECDSA: %u", n_bits));
        ssh_mprz_makenan(number, SSH_MP_NAN_ENOMEM);
        return SSH_CRYPTO_KEY_INVALID;
    }

    ssh_mprz_init(&c);
    ssh_mprz_init(&temp);

    if (ssh_mprz_random_integer(&c, n_bits + 64, security_strength)
        != SSH_CRYPTO_OK)
    {
        ssh_mprz_clear(&c);
        ssh_mprz_clear(&temp);
        return SSH_CRYPTO_NO_MEMORY;
    }

    ssh_mprz_sub_ui(&temp, n, 1);
    ssh_mprz_mod(number, &c, &temp);
    ssh_mprz_add_ui(number, number, 1);

    /* Cleanup */
    ssh_mprz_clear(&c);
    ssh_mprz_clear(&temp);

    return SSH_CRYPTO_OK;
}

#endif /* SSHDIST_CRYPT_ECP */

/* Basic modular enhancements. Due the nature of extended euclids algorithm
   it sometimes returns integers that are negative. For our cases positive
   results are better. */

bool ssh_mprz_mod_invert(SshMPInteger op_dest, SshMPIntegerConst op_src,
                      SshMPIntegerConst modulo)
{
    bool rv;

    rv = ssh_mprz_invert(op_dest, op_src, modulo);

    if (ssh_mprz_cmp_ui(op_dest, 0) < 0)
        ssh_mprz_add(op_dest, op_dest, modulo);

    return rv;
}
