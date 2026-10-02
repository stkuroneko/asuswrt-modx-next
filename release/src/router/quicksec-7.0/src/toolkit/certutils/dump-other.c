/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   Functions to output structured object other than certificates,
   plain public and private keys, or certificate lists (on
   certtools).
*/

#include "sshincludes.h"

#ifdef SSHDIST_CERT

#include "sshmp.h"
#include "x509.h"
#include "x509cmp.h"

#define SSH_DEBUG_MODULE "SshDumpCRL"

bool cu_dump_cmp(SshCmpMessage m, unsigned char *der, size_t der_len)
{
    ssh_warning("dump_cmp not implemented");
    return false;
}

bool cu_dump_scep(void *m, unsigned char *der, size_t der_len)
{
    ssh_warning("dump_scep not implemented");
    return false;
}
#endif /* SSHDIST_CERT */
