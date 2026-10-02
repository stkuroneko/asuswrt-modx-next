/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   Functions for generating primes.
*/

#ifndef GENMP_H
#define GENMP_H

#include "sshcrypt.h"
#include "sshmp.h"

/* Random integer generation functions */
SshCryptoStatus ssh_mprz_random_integer(SshMPInteger ret,
                                        unsigned int bits,
                                        unsigned int security_strength);

SshCryptoStatus ssh_mprz_mod_random(SshMPInteger op,
                                    SshMPIntegerConst modulo,
                                    unsigned int security_strength);

SshCryptoStatus ssh_mprz_mod_random_entropy(SshMPInteger op,
                                            SshMPIntegerConst modulo,
                                            unsigned int bits,
                                            unsigned int security_strength);

SshCryptoStatus
ssh_mprz_random_integer_between(SshMPInteger op,
                                SshMPIntegerConst min,
                                SshMPIntegerConst max,
                                unsigned int security_strength);

/* Makes and returns a random pseudo prime of the desired number of bits.
   Note that the random number generator must be initialized properly
   before using this.

   The generated prime will have the highest bit set, and will have
   the two lowest bits set.

   Primality is tested with Miller-Rabin test, ret thus having
   probability about 1 - 2^(-50) (or more) of being a true prime.
   */
void ssh_mprz_random_prime(SshMPInteger ret,unsigned int bits);

/* Modular invert with positive results. */
bool ssh_mprz_mod_invert(SshMPInteger op_dest, SshMPIntegerConst op_src,
                            SshMPIntegerConst modulo);



/* Find a random generator of order 'order' modulo 'modulo'. */
bool ssh_mprz_random_generator(SshMPInteger g,
                                  SshMPInteger order, SshMPInteger modulo);


/* FIPS PUB 186-3 B.3.6 */
SshCryptoStatus
ssh_mp_fip186_ifc_key_pair_generate(unsigned int nlen,
                                    SshMPIntegerConst e,
                                    SshMPInteger p,
                                    SshMPInteger q);

/* Generate primes p and q according to the method described in
   Appendix A.1.1.2 of FIPS 186-3. The input is p_bits and q_bits, the
   bit sizes of the primes to be generated. Output the primes p, q and
   return crypto status.
*/
SshCryptoStatus
ssh_mp_fips186_ffc_domain_parameter_create(SshMPInteger p,
                                           SshMPInteger q,
                                           unsigned int p_bits,
                                           unsigned int q_bits);

/* Create FFC keypair (x, y) from domain parameters p, q and g using
   extra random bits according to the Appendix B.1.1 of FIPS 186-3 */
SshCryptoStatus
ssh_mp_fips186_ffc_keypair_generation(SshMPIntegerConst p,
                                      SshMPIntegerConst q,
                                      SshMPIntegerConst g,
                                      SshMPInteger x,
                                      SshMPInteger y);

/* Create FFC per-message secret random number using extra random bits
   according to the Appendix B.2.1 of FIPS 186-3 */
SshCryptoStatus
ssh_mp_fips186_ffc_per_message_secret(SshMPIntegerConst p,
                                      SshMPIntegerConst q,
                                      SshMPIntegerConst g,
                                      SshMPInteger k,
                                      SshMPInteger k_inverse);

#ifdef SSHDIST_CRYPT_ECP
/* Generic FIPS PUB 186-3 ECDSA random number creator used by
   private key generation and per-message secret generation.
   This is consistent with FIPS PUB 186-3 4.1 and 5.1.
*/
SshCryptoStatus
ssh_mp_fips186_ecc_random_number_generate(SshMPIntegerConst n,
                                          SshMPInteger number);
#endif /* SSHDIST_CRYPT_ECP */


/* Run General Lucas Probabilistic Primality Test for integer
   according to the Appendix C.3.3 of FIPS 186-3. Return false
   if integer is composite, true if integer is probably prime. */
bool ssh_mprz_crypto_lucas_test(SshMPIntegerConst c);

/* Run Miller-Rabin test with limit-number of iterations. Return
   true if test succeeds. */
bool ssh_mprz_crypto_miller_rabin(SshMPIntegerConst op,
                                     unsigned int limit);

typedef enum
{
    SSH_MP_EMR_PROVABLY_COMPOSITE_WITH_FACTOR,
    SSH_MP_EMR_PROVABLY_COMPOSITE_AND_NOT_POWER_OF_PRIME,
    SSH_MP_EMR_PROBABLY_PRIME,
    SSH_MP_EMR_ERROR
} SshMPEnhancedMRResult;

/* Run enhanced Miller-Rabin probabilistic primality test. This
   is based on Appendix C.3.2 of FIPS 186-3 and is used to
   validate RSA moduli */
SshMPEnhancedMRResult
ssh_mprz_enhanced_miller_rabin(SshMPIntegerConst w,
                               unsigned int iterations);

#endif /* GENMP_H */
