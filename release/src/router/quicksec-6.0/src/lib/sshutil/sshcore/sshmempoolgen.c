/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Reverse mapping of SANA assigned memory pools.
*/

#include "sshincludes.h"
#include "sshmempool.h"

const char *ssh_mempool_name_generated(int mempool_num);

const char *ssh_mempool_name_generated(int mempool_num)
{
  switch (mempool_num)
    {
    case SSH_MEMPOOL_ANY: return "Default pool that can be used anywhere";
#ifdef SSHDIST_CRYPT
    case SSH_MEMPOOL_CRYPTO: return "Cryptographic library";
#endif /* SSHDIST_CRYPT */
#ifdef SSHDIST_MATH
    case SSH_MEMPOOL_MATH: return "Multiple precision arithmetics library";
#endif /* SSHDIST_MATH */
#ifdef SSHDIST_CERT
    case SSH_MEMPOOL_CERT: return "X.509 certificate library";
#endif /* SSHDIST_CERT */
#ifdef SSHDIST_IKEV1
    case SSH_MEMPOOL_IKE: return "IKE library";
#endif /* SSHDIST_IKEV1 */
#ifdef SSHDIST_IPSEC
    case SSH_MEMPOOL_IPM: return "IPSEC policy manager";
#endif /* SSHDIST_IPSEC */
    case SSH_MEMPOOL_STREAM: return "Stream implementations";



#ifdef SSHDIST_FUNCTIONALITY_TLS
    case SSH_MEMPOOL_TLS: return "TLS protocol library *";
#endif /* SSHDIST_FUNCTIONALITY_TLS */
#ifdef SSHDIST_DIRECTORY_HTTP
    case SSH_MEMPOOL_HTTP: return "HTTP library";
#endif /* SSHDIST_DIRECTORY_HTTP */
#ifdef SSHDIST_LDAP
    case SSH_MEMPOOL_LDAP: return "LDAP library";
#endif /* SSHDIST_LDAP */
    case SSH_MEMPOOL_ADT: return "Abstract data type library";
#ifdef SSHDIST_IPSEC
    case SSH_MEMPOOL_APF: return "Abstract packet filter";
#endif /* SSHDIST_IPSEC */
    case SSH_MEMPOOL_TEST: return "Temporary testing memory pool";
    case SSH_MEMPOOL_TEST1: return "Temporary testing memory pool #1";
    case SSH_MEMPOOL_TEST2: return "Temporary testing memory pool #2";
    case SSH_MEMPOOL_TEST3: return "Temporary testing memory pool #3";
    case SSH_MEMPOOL_TEST4: return "Temporary testing memory pool #4";
    case SSH_MEMPOOL_TEST5: return "Temporary testing memory pool #5";
    case SSH_MEMPOOL_TEST6: return "Temporary testing memory pool #6";
    case SSH_MEMPOOL_TEST7: return "Temporary testing memory pool #7";
    case SSH_MEMPOOL_TEST8: return "Temporary testing memory pool #8";
    case SSH_MEMPOOL_TEST9: return "Temporary testing memory pool #9";
    }
  return NULL;
}
/* eof (sshmempoolgen.c) */
