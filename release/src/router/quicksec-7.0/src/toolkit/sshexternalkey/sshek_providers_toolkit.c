/**
   @copyright
   Copyright (c) 2012 - 2015, INSIDE Secure Oy. All rights reserved.
*/

#include "sshexternalkey_internal.h"
#include "extkeyprov.h"

/* Type for provider ops/type mapping */

#include "dummyprov.h"
#include "genaccprovider.h"





#ifdef SSHDIST_EXTKEY_SOFT_ACCELERATOR_PROV
#include "softprovider.h"
#endif /* SSHDIST_EXTKEY_SOFT_ACCELERATOR_PROV */









const SSH_DATA_INITONCE
SshEkProviderOps ssh_ek_supported_providers[] =
{
    (SshEkProviderOps) &ssh_ek_gen_acc_ops,

#if 0
  /* Do not link the dummy provider. */
    (SshEkProviderOps) &ssh_ek_dummy_ops,
#endif











#ifdef SSHDIST_EXTKEY_SOFT_ACCELERATOR_PROV
    (SshEkProviderOps) &ssh_ek_soft_ops,
#endif /* SSHDIST_EXTKEY_SOFT_ACCELERATOR_PROV */





    NULL,
};
