/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshbuffer.h"
#include "sshcrypt.h"

#include "ssheap.h"
#include "ssheapi.h"

#define SSH_DEBUG_MODULE "SshEapOtp"

void*
ssh_eap_otp_create(SshEapProtocol protocol, SshEap eap, uint8_t type)
{
    return NULL;
}

void
ssh_eap_otp_destroy(SshEapProtocol protocol, uint8_t type, void *state)
{


}

SshEapOpStatus
ssh_eap_otp_signal(SshEapProtocolSignalEnum sig,
                   SshEap eap,
                   SshEapProtocol protocol,
                   void *data)
{
    return SSH_EAP_OPSTATUS_SUCCESS;
}
