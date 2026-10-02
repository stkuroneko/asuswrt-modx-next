/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

#ifndef SSH_EAP_OTP_H

#define SSH_EAP_OTP_H 1

void* ssh_eap_otp_create(SshEapProtocol, SshEap eap, uint8_t);
void ssh_eap_otp_destroy(SshEapProtocol, uint8_t, void*);
SshEapOpStatus ssh_eap_otp_signal(SshEapProtocolSignalEnum, SshEap,
                                  SshEapProtocol, void*);


#endif
