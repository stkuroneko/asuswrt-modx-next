/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

#ifndef SSH_EAP_MSCHAPV2_H

#define SSH_EAP_MSCHAPV2_H 1

#ifdef SSHDIST_EAP_MSCHAPV2

#define SSH_EAP_MSCHAPV2_CHALLENGE 1
#define SSH_EAP_MSCHAPV2_RESPONSE  2
#define SSH_EAP_MSCHAPV2_SUCCESS   3
#define SSH_EAP_MSCHAPV2_FAILURE   4
#define SSH_EAP_MSCHAPV2_CHANGE_PW 7

#define SSH_EAP_MSCHAPV2_MSK_LEN                  64
#define SSH_EAP_MSCHAPV2_KEY_LEN                  16

#define SSH_EAP_MSCHAPV2_CHALLENGE_LENGTH         16
#define SSH_EAP_MSCHAPV2_FAILURE_CHALLENGE_LENGTH 32
#define SSH_EAP_MSCHAPV2_RESERVED_LENGTH          8
#define SSH_EAP_MSCHAPV2_NTRESPONSE_LENGTH        24
#define SSH_EAP_MSCHAPV2_RESPONSE_LENGTH          49
/* The length of "E=xxx R=x C=xxxx V=xxx" for MS-CHAPv2 */
#define SSH_EAP_MSCHAPV2_FAILURE_LENGTH           74

/* Length of the MS-CHAPv2 response authenticator */
#define SSH_EAP_MSCHAPV2_AUTHRESP_LENGTH       20
#define SSH_EAP_MSCHAPV2_MAX_RESPONSE_LENGTH   SSH_EAP_MSCHAPV2_FAILURE_LENGTH

/* Peer flags */
#define SSH_EAP_MSCHAPV2_BEGIN                      0x0001
#define SSH_EAP_MSCHAPV2_CHALLENGE_REQUEST_RECEIVED 0x0002
#define SSH_EAP_MSCHAPV2_CHALLENGE_RESPONSE_SENT    0x0004
#define SSH_EAP_MSCHAPV2_SUCCESS_REQUEST_RECEIVED   0x0008
#define SSH_EAP_MSCHAPV2_FAILURE_REQUEST_RECEIVED   0x0010
#define SSH_EAP_MSCHAPV2_FAILURE_RESPONSE_SENT      0x0020
#define SSH_EAP_MSCHAPV2_SUCCESS_STATUS             0x0040
#define SSH_EAP_MSCHAPV2_FAILURE_STATUS             0x0080

typedef struct SshEapMschapv2StateRec {
  /* Peer */
  uint32_t flags;
  /** The received challenge */
  uint8_t *challenge_buffer;
  uint16_t challenge_length;

  /** The peer challenge */
  uint8_t peer_challenge_buffer[SSH_EAP_MSCHAPV2_CHALLENGE_LENGTH];

  /** The MS-CHAPv2-ID */
  uint8_t identifier;

  /* NT response buffer */
  uint8_t nt_response_buffer[SSH_EAP_MSCHAPV2_NTRESPONSE_LENGTH];

  /* The latest peer name used */
  uint16_t peer_name_length;
  uint8_t *peer_name;

  /* The secret as provided via caller */
  uint8_t *secret_buf;
  uint16_t secret_length;

  /* New secret for MS-CHAP password changing */
  uint8_t *new_secret_buf;
  uint16_t new_secret_length;
  unsigned int is_secret_newpw : 1;

  uint8_t  msk[SSH_EAP_MSCHAPV2_MSK_LEN];

} *SshEapMschapv2State, SshEapMschapv2StateStruct;
#endif /* SSHDIST_EAP_MSCHAPV2 */

void*
ssh_eap_mschap_v2_create(SshEapProtocol protocol,
                         SshEap eap,
                         uint8_t type);
void
ssh_eap_mschap_v2_destroy(SshEapProtocol protocol,
                          uint8_t type,
                          void *ctx);
SshEapOpStatus
ssh_eap_mschap_v2_signal(SshEapProtocolSignalEnum sig,
                         SshEap eap,
                         SshEapProtocol protocol,
                         SshEapProtocolSignalData data);

SshEapOpStatus
ssh_eap_mschap_v2_key(SshEapProtocol protocol,
                      SshEap eap,
                      uint8_t type);

#endif /* SSH_EAP_MSCHAPV2_H */
