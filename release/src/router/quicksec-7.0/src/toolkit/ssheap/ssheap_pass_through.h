/**
   @copyright
   Copyright (c) 2010 - 2016, INSIDE Secure Oy. All rights reserved.
*/

#ifndef SSH_EAP_PASS_THROUGH_H
#define SSH_EAP_PASS_THROUGH_H 1

void *ssh_eap_pass_through_create(SshEapProtocol protocol,
                                  SshEap eap,
                                  uint8_t type);

void ssh_eap_pass_through_destroy(SshEapProtocol protocol,
                                  uint8_t type,
                                  void* state);

SshEapOpStatus ssh_eap_pass_through_signal(SshEapProtocolSignalEnum sig,
                                           SshEap eap,
                                           SshEapProtocol protocol,
                                           SshEapProtocolSignalData data);

SshEapOpStatus ssh_eap_pass_through_key(SshEapProtocol protocol,
                                        SshEap eap,
                                        uint8_t type);

typedef struct SshEapPassThroughStateRec {
  uint32_t dummy_data;
} *SshEapPassThroughState, SshEapPassThroughStateStruct;

#endif /** SSH_EAP_PASS_THROUGH_H */
