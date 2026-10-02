/**
   @copyright
   Copyright (c) 2011 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Transform Identifiers
*/

#include "sshincludes.h"
#include "sshenum.h"
#include "idtransformer.h"

const SshKeywordStruct transformid_names[] = {

  { "invalid-transform-id", TRANSFORMID_INVALID },

  /* Encryption */
  { "des_iv64", TRANSFORMID_ENCR_DES_IV64 },
  { "des-cbc", TRANSFORMID_ENCR_DES_CBC },
  { "3des-cbc", TRANSFORMID_ENCR_3DES_CBC },
  { "rc5-16-cbc", TRANSFORMID_ENCR_RC5 },
  { "idea-cbc", TRANSFORMID_ENCR_IDEA },
  { "cast128-cbc", TRANSFORMID_ENCR_CAST },
  { "blowfish-cbc", TRANSFORMID_ENCR_BLOWFISH },
  { "3idea", TRANSFORMID_ENCR_3IDEA },
  { "des_iv32", TRANSFORMID_ENCR_DES_IV32 },
  /* Reserved 10 */
  { "null", TRANSFORMID_ENCR_NULL },
  { "aes128-cbc", TRANSFORMID_ENCR_AES_128_CBC },
  { "aes192-cbc", TRANSFORMID_ENCR_AES_192_CBC },
  { "aes256-cbc", TRANSFORMID_ENCR_AES_256_CBC },
  { "aes128-ctr", TRANSFORMID_ENCR_AES_128_CTR },
  { "aes192-ctr", TRANSFORMID_ENCR_AES_192_CTR },
  { "aes256-ctr", TRANSFORMID_ENCR_AES_256_CTR },
  { "aes128-ccm-8", TRANSFORMID_ENCR_AES_128_CCM_8 },
  { "aes192-ccm-8", TRANSFORMID_ENCR_AES_192_CCM_8 },
  { "aes256-ccm-8", TRANSFORMID_ENCR_AES_256_CCM_8 },
  { "aes128-ccm-12", TRANSFORMID_ENCR_AES_128_CCM_12 },
  { "aes192-ccm-12", TRANSFORMID_ENCR_AES_192_CCM_12 },
  { "aes256-ccm-12", TRANSFORMID_ENCR_AES_256_CCM_12 },
  { "aes128-ccm-16", TRANSFORMID_ENCR_AES_128_CCM_16 },
  { "aes192-ccm-16", TRANSFORMID_ENCR_AES_192_CCM_16 },
  { "aes256-ccm-16", TRANSFORMID_ENCR_AES_256_CCM_16 },
  /* Unassigned 17 */
  { "aes128-gcm-8", TRANSFORMID_ENCR_AES_128_GCM_8 },
  { "aes192-gcm-8", TRANSFORMID_ENCR_AES_192_GCM_8 },
  { "aes256-gcm-8", TRANSFORMID_ENCR_AES_256_GCM_8 },
  { "aes128-gcm-12", TRANSFORMID_ENCR_AES_128_GCM_12 },
  { "aes192-gcm-12", TRANSFORMID_ENCR_AES_192_GCM_12 },
  { "aes256-gcm-12", TRANSFORMID_ENCR_AES_256_GCM_12 },
  { "aes128-gcm-16", TRANSFORMID_ENCR_AES_128_GCM_16 },
  { "aes192-gcm-16", TRANSFORMID_ENCR_AES_192_GCM_16 },
  { "aes256-gcm-16", TRANSFORMID_ENCR_AES_256_GCM_16 },
  { "aes128-gmac", TRANSFORMID_ENCR_AES_128_GMAC },
  { "aes192-gmac", TRANSFORMID_ENCR_AES_192_GMAC },
  { "aes256-gmac", TRANSFORMID_ENCR_AES_256_GMAC },
  /* Reserved 22 */
  { "camellia128-cbc", TRANSFORMID_ENCR_CAMELLIA_128_CBC },
  { "camellia192-cbc", TRANSFORMID_ENCR_CAMELLIA_192_CBC },
  { "camellia256-cbc", TRANSFORMID_ENCR_CAMELLIA_256_CBC },
  { "camellia128-ctr", TRANSFORMID_ENCR_CAMELLIA_128_CTR },
  { "camellia192-ctr", TRANSFORMID_ENCR_CAMELLIA_192_CTR },
  { "camellia256-ctr", TRANSFORMID_ENCR_CAMELLIA_256_CTR },
  { "camellia128-ccm-8", TRANSFORMID_ENCR_CAMELLIA_128_CCM_8 },
  { "camellia192-ccm-8", TRANSFORMID_ENCR_CAMELLIA_192_CCM_8 },
  { "camellia256-ccm-8", TRANSFORMID_ENCR_CAMELLIA_256_CCM_8 },
  { "camellia128-ccm-12", TRANSFORMID_ENCR_CAMELLIA_128_CCM_12 },
  { "camellia192-ccm-12", TRANSFORMID_ENCR_CAMELLIA_192_CCM_12 },
  { "camellia256-ccm-12", TRANSFORMID_ENCR_CAMELLIA_256_CCM_12 },
  { "camellia128-ccm-16", TRANSFORMID_ENCR_CAMELLIA_128_CCM_16 },
  { "camellia128-ccm-16", TRANSFORMID_ENCR_CAMELLIA_192_CCM_16 },
  { "camellia128-ccm-16", TRANSFORMID_ENCR_CAMELLIA_256_CCM_16 },
  /* Unassigned 28-1023 */
  /* Private use 1024-65535 */

  /* Pseudo-random functions */
  /* Reserved 0 */
  { "hmac-md5", TRANSFORMID_PRF_HMAC_MD5 },
  { "hmac-sha1", TRANSFORMID_PRF_HMAC_SHA1 },
  { "hmac-tiger128", TRANSFORMID_PRF_HMAC_TIGER },
  { "xcbc-aes", TRANSFORMID_PRF_HMAC_AES_128_XCBC },
  { "hmac-sha256", TRANSFORMID_PRF_HMAC_SHA2_256 },
  { "hmac-sha384", TRANSFORMID_PRF_HMAC_SHA2_384 },
  { "hmac-sha512", TRANSFORMID_PRF_HMAC_SHA2_512 },
  { "cmac-aes", TRANSFORMID_PRF_HMAC_AES_128_CMAC },
  /* Unassigned 9-1023 */
  /* Private use 1024-65535 */

  /* Integrity */
  { "none", TRANSFORMID_INTEG_NONE },
  { "hmac-md5-96", TRANSFORMID_INTEG_HMAC_MD5_96 },
  { "hmac-sha1-96", TRANSFORMID_INTEG_HMAC_SHA1_96 },
  { "cbcmac-des", TRANSFORMID_INTEG_DES_MAC },
  { "kdpk-md5", TRANSFORMID_INTEG_KPDK_MD5 },
  { "xcbc-aes-96", TRANSFORMID_INTEG_AES_XCBC_96 },
  { "hmac-md5-128", TRANSFORMID_INTEG_HMAC_MD5_128 },
  { "hmac-sha1-160", TRANSFORMID_INTEG_HMAC_SHA1_160 },
  { "cmac-aes-160", TRANSFORMID_INTEG_AES_CMAC_96 },
  { "gmac-aes128", TRANSFORMID_INTEG_AES_128_GMAC },
  { "gmac-aes192", TRANSFORMID_INTEG_AES_192_GMAC },
  { "gmac-aes256", TRANSFORMID_INTEG_AES_256_GMAC },
  { "hmac-sha256-128", TRANSFORMID_INTEG_HMAC_SHA256_128 },
  { "hmac-sha384-192", TRANSFORMID_INTEG_HMAC_SHA384_192 },
  { "hmac-sha512-256", TRANSFORMID_INTEG_HMAC_SHA512_256 },
  /* Unassigned 15-1023 */
  /* Private use 1024-65535 */

  /* Diffie-Hellman */
  { "dh-none", TRANSFORMID_D_H_NONE },
  { "dh-modp-786", TRANSFORMID_D_H_MODP_768 },
  { "dh-modp-1024", TRANSFORMID_D_H_MODP_1024 },
  /* Reserved 3-4 */
  { "dh-modp-1536", TRANSFORMID_D_H_MODP_1536 },
  /* Unassigned 6-13 */
  { "dh-modp-2048", TRANSFORMID_D_H_MODP_2048 },
  { "dh-modp-3072", TRANSFORMID_D_H_MODP_3072 },
  { "dh-modp-4096", TRANSFORMID_D_H_MODP_4096 },
  { "dh-modp-6144", TRANSFORMID_D_H_MODP_6144 },
  { "dh-modp-8192", TRANSFORMID_D_H_MODP_8192 },
  /* RFC5903 */
  { "dh-ecp-256", TRANSFORMID_D_H_ECP_256 },
  { "dh-ecp-384", TRANSFORMID_D_H_ECP_384 },
  { "dh-ecp-512", TRANSFORMID_D_H_ECP_512 },
  /* RFC5114 */
  { "dh-modp-1024-160", TRANSFORMID_D_H_MODP_1024_160 },
  { "dh-modp-2048-224", TRANSFORMID_D_H_MODP_2048_224 },
  { "dh-modp-2048-256", TRANSFORMID_D_H_MODP_2048_256 },
  { "dh-ecp-192", TRANSFORMID_D_H_ECP_192 },
  { "dh-ecp-224", TRANSFORMID_D_H_ECP_224 },
  { "dh-brainpool-ecp-224", TRANSFORMID_D_H_BRAINPOOL_ECP_224 },
  { "dh-brainpool-ecp-256", TRANSFORMID_D_H_BRAINPOOL_ECP_256 },
  { "dh-brainpool-ecp-384", TRANSFORMID_D_H_BRAINPOOL_ECP_384 },
  { "dh-brainpool-ecp-512", TRANSFORMID_D_H_BRAINPOOL_ECP_512 },
  /* Unassigned 31-1023 */
  /* Private use 1024-65535 */

  /* Extended sequence numbers */
  { "esn-disable", TRANSFORMID_ESN_DISABLE },
  { "esn-enable", TRANSFORMID_ESN_ENABLE },

  { NULL, 0 }
};

const char *
idtransformer_to_string(TransformId id)
{
    return
        ssh_find_keyword_name(
                transformid_names,
                id);
}
