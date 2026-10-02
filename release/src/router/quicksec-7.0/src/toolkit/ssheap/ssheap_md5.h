/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

#ifndef SSH_EAP_MD5_H

#define SSH_EAP_MD5_H 1

typedef struct SshEapMd5StateRec {

  /** The challenge sent */
  uint8_t* challenge_buffer;
  unsigned long challenge_length;

  /** The response received */
  uint8_t* response_buffer;
  unsigned long response_length;
  uint8_t response_id;

} *SshEapMd5State, SshEapMd5StateStruct;

typedef struct SshEapMd5ParamsRec {

  /** Length of challenge to create */
  unsigned long challenge_length;

  /** Name of this instance to use in CHAP authentication */

  uint8_t* name_buffer;
  unsigned long name_length;

} *SshEapMd5Params, SshEapMd5ParamsStruct;

void* ssh_eap_md5_create(SshEapProtocol, SshEap eap, uint8_t);
void ssh_eap_md5_destroy(SshEapProtocol, uint8_t,void*);
SshEapOpStatus ssh_eap_md5_signal(SshEapProtocolSignalEnum,
                                  SshEap,
                                  SshEapProtocol,
                                  SshEapProtocolSignalData);


#endif
