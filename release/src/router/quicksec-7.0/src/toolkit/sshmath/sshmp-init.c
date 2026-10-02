/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshmp.h"

#define SSH_DEBUG_MODULE "SshMPInit"

#ifdef SSHDIST_MATH
bool ssh_math_library_initialize(void)
{
    return true;
}

void ssh_math_library_uninitialize(void)
{
    return;
}

bool ssh_math_library_is_initialized(void)
{
    return true;
}
#endif /* SSHDIST_MATH */
