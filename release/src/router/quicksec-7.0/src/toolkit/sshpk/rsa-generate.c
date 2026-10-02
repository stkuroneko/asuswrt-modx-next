/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   Description:

         Take on the RSA key generation, modified after Tatu Ylonen's
         original SSH implementation.

         Description of the RSA algorithm can be found e.g. from the
         following sources:

   - Bruce Schneier: Applied Cryptography.  John Wiley & Sons, 1994.
   - Jennifer Seberry and Josed Pieprzyk: Cryptography: An Introduction to
     Computer Security.  Prentice-Hall, 1989.
   - Man Young Rhee: Cryptography and Secure Data Communications.  McGraw-Hill,
     1994.
   - R. Rivest, A. Shamir, and L. M. Adleman: Cryptographic Communications
     System and Method.  US Patent 4,405,829, 1983.
   - Hans Riesel: Prime Numbers and Computer Methods for Factorization.
     Birkhauser, 1994.
*/

#include "sshincludes.h"
#include "sshmp.h"
#include "sshgenmp.h"
#include "sshcrypt.h"
#include "sshpk_i.h"
#include "sshhash_i.h"
#include "rsa.h"

#define SSH_DEBUG_MODULE "SshCryptoRSA"

#define SSH_RSA_MINIMUM_PADDING 10
#define SSH_RSA_MAX_BYTES       65535

/* The size in bits of the integer r in the SshRSAPrivateKey structure
   used to protect against fault attacks. If a fault occurs, the probability
   that the fault verification test will fail is
   2^(-SSH_RSA_RANDOM_CRT_INTEGER_SIZE). 48 seems a reasonable number here,
   we don't want it too large as it will slow the private key operations
   excessively.
*/
#define SSH_RSA_RANDOM_CRT_INTEGER_SIZE 48

#define SSH_RSA_DEFAULT_PUBLIC_EXPONENT 65537

/* Generate a random short prime r, and compute the CRT
   exponents dp, dq from the private exponent d, and r.
   Since we choose r to be prime, this computes
   dp = d mod (r-1)(p-1) and dq = d mod (r-1)(q-1) */
void ssh_rsa_private_key_generate_crt_exponents(SshMPInteger dp,
                                                SshMPInteger dq,
                                                SshMPInteger r,
                                                SshMPIntegerConst p,
                                                SshMPIntegerConst q,
                                                SshMPIntegerConst d)
{
    SshMPIntegerStruct t1, t2;

   retry:
    ssh_mprz_random_prime(r, SSH_RSA_RANDOM_CRT_INTEGER_SIZE);

    /* Check the generate prime r is different to both p and q */
    if (ssh_mprz_isnan(r) || (ssh_mprz_cmp(r, p) == 0) ||
        (ssh_mprz_cmp(r, q) == 0))
    {
        if (ssh_mprz_isnan(r))
          return;
        goto retry;
    }

    ssh_mprz_init(&t1);
    ssh_mprz_init(&t2);

    ssh_mprz_sub_ui(&t1, r, 1);
    ssh_mprz_sub_ui(&t2, p, 1);
    ssh_mprz_mul(&t1, &t1, &t2);
    ssh_mprz_mod(dp, d, &t1);

    ssh_mprz_sub_ui(&t1, r, 1);
    ssh_mprz_sub_ui(&t2, q, 1);
    ssh_mprz_mul(&t1, &t1, &t2);
    ssh_mprz_mod(dq, d, &t1);

    ssh_mprz_clear(&t1);
    ssh_mprz_clear(&t2);
}

/* Initialize the blinding integers, i.e. generate a random integer b,
   and compute b_exp = b^e mod n, and b_inv = b ^ (-1) mod n */
void ssh_rsa_private_key_init_blinding(SshMPInteger b_exp,
                                       SshMPInteger b_inv,
                                       SshMPIntegerConst n,
                                       SshMPIntegerConst e)
{
    SshMPIntegerStruct b;

    ssh_mprz_init(&b);

    /* Choose a random integer b */
    ssh_mprz_mod_random(&b, n, 0);
    /* Compute b_exp as b ^ e mod n */
    ssh_mprz_powm(b_exp, &b, e, n);
    /* Compute b_inv as b ^ (-1) mod n */
    ssh_mprz_mod_invert(b_inv, &b, n);

    ssh_mprz_clear(&b);
}

/* Given mutual primes p and q, derives RSA key components n, d, e,
   and u.  The exponent e will be at least ebits bits in size. p must
   be smaller than q. */

static bool
derive_rsa_keys(SshMPInteger n, SshMPIntegerConst e,
                SshMPInteger d, SshMPInteger u,
                SshMPIntegerConst p, SshMPIntegerConst q)
{
    SshMPIntegerStruct p_minus_1, q_minus_1, aux, phi, G, F;
    bool rv = true;

    /* Initialize. */
    ssh_mprz_init(&p_minus_1);
    ssh_mprz_init(&q_minus_1);
    ssh_mprz_init(&aux);
    ssh_mprz_init(&phi);
    ssh_mprz_init(&G);
    ssh_mprz_init(&F);

    /* Compute p-1 and q-1. */
    ssh_mprz_sub_ui(&p_minus_1, p, 1);
    ssh_mprz_sub_ui(&q_minus_1, q, 1);

    /* phi = (p - 1) * (q - 1); the number of positive integers less than p*q
       that are relatively prime to p*q. */
    ssh_mprz_mul(&phi, &p_minus_1, &q_minus_1);

    /* G is the number of "spare key sets" for a given modulus n.  The
       smaller G is, the better.  The smallest G can get is 2. This
       tells in practice nothing about the safety of primes p and q. */
    ssh_mprz_gcd(&G, &p_minus_1, &q_minus_1);

    /* F = phi / G; the number of relative prime numbers per spare key set. */
    ssh_mprz_div(&F, &phi, &G);

    /* F = LCM(p - 1, q - 1)
    d = e mod^(-1) F  */
    ssh_mprz_mod_invert(d, e, &F);

    /* u = p mod^(-1) q */
    ssh_mprz_mod_invert(u, p, q);

    /* n = p * q */
    ssh_mprz_mul(n, p, q);

    /* Check modulus (n) inv(p) (u) and inv(e) (d) */
    if (ssh_mprz_isnan(n) || ssh_mprz_isnan(u) || ssh_mprz_isnan(d))
      rv = false;

    /* Clear auxiliary variables. */
    ssh_mprz_clear(&p_minus_1);
    ssh_mprz_clear(&q_minus_1);
    ssh_mprz_clear(&aux);
    ssh_mprz_clear(&phi);
    ssh_mprz_clear(&G);
    ssh_mprz_clear(&F);

    return rv;
}


SshCryptoStatus
ssh_rsa_generate_private_key_components(SshMPIntegerConst p,
                                        SshMPIntegerConst q,
                                        SshMPIntegerConst e,
                                        void **key_ctx)
{
    SshMPIntegerStruct aux;
    SshRSAPrivateKey *prv;

    prv = ssh_malloc(sizeof(*prv));

    if (prv == NULL)
        return SSH_CRYPTO_NO_MEMORY;

    /* Initialize our key. */
    ssh_mprz_init(&prv->q);
    ssh_mprz_init(&prv->p);
    ssh_mprz_init(&prv->e);
    ssh_mprz_init(&prv->d);
    ssh_mprz_init(&prv->u);
    ssh_mprz_init(&prv->n);
    ssh_mprz_init(&prv->dp);
    ssh_mprz_init(&prv->dq);
    ssh_mprz_init(&prv->r);
    ssh_mprz_init(&prv->b_exp);
    ssh_mprz_init(&prv->b_inv);

    /* Auxiliary variables. */
    ssh_mprz_init(&aux);

    /* Set known values */
    ssh_mprz_set(&prv->e, e);
    ssh_mprz_set(&prv->p, p);
    ssh_mprz_set(&prv->q, q);

    /* Derive the RSA private key components */
    if (!derive_rsa_keys(&prv->n, &prv->e, &prv->d, &prv->u,
                         &prv->p, &prv->q))
        goto failure;

    /* Compute the bit size of the key. */
    prv->bits = ssh_mprz_bit_size(&prv->n);


    /* We generate a new random prime r and from this dp, dq */
    ssh_rsa_private_key_generate_crt_exponents(&prv->dp, &prv->dq,
                                               &prv->r, &prv->p,
                                               &prv->q, &prv->d);

    ssh_rsa_private_key_init_blinding(&prv->b_exp, &prv->b_inv,
                                      &prv->n, &prv->e);

    if (ssh_mprz_isnan(&prv->b_exp) || ssh_mprz_isnan(&prv->b_inv) ||
        ssh_mprz_isnan(&prv->dp) || ssh_mprz_isnan(&prv->dq))
        goto failure;

    /* Check that 2^(nlen / 2) < d */
    ssh_mprz_set_2exp(&aux, prv->bits / 2);
    if (ssh_mprz_cmp(&prv->d, &aux) < 0)
        goto failure;

#ifdef DEBUG_LIGHT
    /* Assert that p * qInv = 1 mod q */
    ssh_mprz_mul(&aux, &prv->p, &prv->u);
    ssh_mprz_mod(&aux, &aux, &prv->q);
    SSH_ASSERT(ssh_mprz_cmp_ui(&aux, 1) == 0);
#endif /* DEBUG_LIGHT */

    ssh_mprz_clear(&aux);

    *key_ctx = (void *)prv;
    return SSH_CRYPTO_OK;

   failure:
    ssh_mprz_clear(&prv->n);
    ssh_mprz_clear(&prv->e);
    ssh_mprz_clear(&prv->d);
    ssh_mprz_clear(&prv->u);
    ssh_mprz_clear(&prv->p);
    ssh_mprz_clear(&prv->q);
    ssh_mprz_clear(&prv->dp);
    ssh_mprz_clear(&prv->dq);
    ssh_mprz_clear(&prv->r);
    ssh_mprz_clear(&prv->b_exp);
    ssh_mprz_clear(&prv->b_inv);
    ssh_free(prv);

    ssh_mprz_clear(&aux);
    return SSH_CRYPTO_OPERATION_FAILED;
}

/* Try to handle the given data in a reasonable manner. This can
   generate and define key. */
SshCryptoStatus
ssh_rsa_private_key_generate_action(void *context, void **key_ctx)
{
    SshRSAInitCtx *ctx = context;

    /* Relevant values are already set */
    if (ssh_mprz_cmp_ui(&ctx->d, 0) != 0 &&
        ssh_mprz_cmp_ui(&ctx->p, 0) != 0 &&
        ssh_mprz_cmp_ui(&ctx->q, 0) != 0 &&
        ssh_mprz_cmp_ui(&ctx->e, 0) != 0 &&
        ssh_mprz_cmp_ui(&ctx->n, 0) != 0 &&
        ssh_mprz_cmp_ui(&ctx->u, 0) != 0)
    {
        return ssh_rsa_make_private_key_of_all(&ctx->p, &ctx->q,
                                               &ctx->n, &ctx->e,
                                               &ctx->d, &ctx->u, key_ctx);
    }

    /* If p, q and e need to be created */
    if (ssh_mprz_cmp_ui(&ctx->p, 0) == 0 ||
        ssh_mprz_cmp_ui(&ctx->q, 0) == 0)
    {
        /* Do not accept partial definition */
        if (ssh_mprz_cmp_ui(&ctx->p, 0) != 0 ||
            ssh_mprz_cmp_ui(&ctx->q, 0) != 0)
        {
            SSH_DEBUG(SSH_D_ERROR,
                     ("Unable to generate RSA key from provided components"));
            return SSH_CRYPTO_UNSUPPORTED;
        }

        /* Key length is not set */
        if (ctx->bits == 0)
        {
            SSH_DEBUG(SSH_D_ERROR,
                      ("RSA key length not set, unable to generate key"));
            return SSH_CRYPTO_KEY_INVALID;
        }

        /* Set e if not provided */
        if (ssh_mprz_cmp_ui(&ctx->e, 0) == 0)
            ssh_mprz_set_ui(&ctx->e, SSH_RSA_DEFAULT_PUBLIC_EXPONENT);

        /* Create p and q */
        if (ssh_mp_fip186_ifc_key_pair_generate(ctx->bits,
                                                &ctx->e,
                                                &ctx->p,
                                                &ctx->q) != SSH_CRYPTO_OK)
        {
            SSH_DEBUG(SSH_D_ERROR, ("Failed to create RSA primes"));
            return SSH_CRYPTO_KEY_INVALID;
        }
    }

    return ssh_rsa_generate_private_key_components(&ctx->p,
                                                   &ctx->q,
                                                   &ctx->e,
                                                   key_ctx);
}
