/**
   @copyright
   Copyright (c) 2007 - 2016, INSIDE Secure Oy. All rights reserved.
*/

#ifndef SSH_EAP_TLS_H
#define SSH_EAP_TLS_H 1

/* Common client and server functionality */
void *ssh_eap_tls_create(SshEapProtocol, SshEap eap, uint8_t);
void ssh_eap_tls_destroy(SshEapProtocol, uint8_t, void*);
SshEapOpStatus ssh_eap_tls_signal(SshEapProtocolSignalEnum,
                                  SshEap,
                                  SshEapProtocol,
                                  SshEapProtocolSignalData);
SshEapOpStatus
ssh_eap_tls_key(SshEapProtocol protocol,
                SshEap eap, uint8_t type);
#endif /* SSH_EAP_TLS_H */
