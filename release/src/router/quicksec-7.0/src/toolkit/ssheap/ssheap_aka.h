/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   ssheap_aka.h
*/

#ifndef SSH_EAP_AKA_H
#define SSH_EAP_AKA_H 1

/* Common client and server functionality */
void *ssh_eap_aka_create(SshEapProtocol, SshEap eap, uint8_t);
void ssh_eap_aka_destroy(SshEapProtocol, uint8_t, void*);

SshEapOpStatus
ssh_eap_aka_signal(SshEapProtocolSignalEnum sig,
                   SshEap eap,
                   SshEapProtocol protocol,
                   SshEapProtocolSignalData data);

SshEapOpStatus
ssh_eap_aka_key(SshEapProtocol protocol,
                SshEap eap, uint8_t type);

#ifdef SSHDIST_EAP_AKA
/* Client only functionality below */

/* Decoding codes for EAP AKA */
#define SSH_EAP_AKA_DEC_OK                  0

/* EAP aka error codes. */
#define SSH_EAP_AKA_ERR_GENERAL             50
#define SSH_EAP_AKA_ERR_INVALID_IE          51
#define SSH_EAP_AKA_ERR_PACKET_CORRUPTED    52
#define SSH_EAP_AKA_ERR_MEMALLOC_FAILED     53
#define SSH_EAP_AKA_ERR_INVALID_STATE       54

/* Flags for EAP AKA protocol state. RFC 4187 strictly defines,
   which information elements may exist and what state and
   therefore we'll have to maintain strict state of the
   protocol. */
#define SSH_EAP_AKA_IDENTITY_RCVD       0x0001
#define SSH_EAP_AKA_CHALLENGE_RCVD      0x0002
#define SSH_EAP_AKA_SYNCH_REQ_SENT      0x0004
#define SSH_EAP_AKA_PROT_SUCCESS        0x0008
#define SSH_EAP_AKA_PROCESSING_RAND     0x0010
#define SSH_EAP_AKA_FULLID_RCVD         0x0020
#define SSH_EAP_AKA_PERMID_RCVD         0x0040
#define SSH_EAP_AKA_ANYID_RCVD          0x0080
#define SSH_EAP_AKA_STATE_FAILED        0x0100
#define SSH_EAP_AKA_BIDDING_REQ_RCVD    0x0200
#define SSH_EAP_AKA_FAST_REAUTH_ID_SENT 0x0400

typedef struct SshEapAkaIdentityRec {
    uint8_t rand[SSH_EAP_AKA_RAND_LEN];
    uint8_t autn[SSH_EAP_AKA_AUTN_LEN];
    uint8_t auts[SSH_EAP_AKA_AUTS_LEN];

    uint8_t IK[SSH_EAP_AKA_IK_LEN];
    uint8_t CK[SSH_EAP_AKA_CK_LEN];

    uint8_t res[16];
    uint8_t res_len;

} *SshEapAkaIdentity, SshEapAkaIdentityStruct;

typedef struct SshEapAkaStateRec {
    uint32_t aka_proto_flags;

    uint8_t  mk[SSH_EAP_AKA_MK_LEN];
    uint8_t  msk[SSH_EAP_AKA_MSK_LEN];
    uint8_t  emsk[SSH_EAP_AKA_EMSK_LEN];
    uint8_t  K_encr[SSH_EAP_AKA_KENCR_LEN];
    uint8_t  K_aut[SSH_EAP_AKA_KAUT_LEN];

    uint8_t xkey[SSH_EAP_AKA_MK_LEN];

    SshEapAkaIdentityStruct aka_id;

    unsigned char *user;
    uint8_t user_len;

    uint8_t  response_id;
    /* Transform value, this transform represents the capability for KDF
       algorithm */
    uint32_t transform;

    SshBuffer challenge_packet;
    unsigned char challenge_packet_mac[SSH_EAP_AKA_MAC_LEN];

    unsigned char *encrypted_data;
    size_t encrypted_data_len;

    unsigned char iv[SSH_EAP_AKA_IV_LEN];

    unsigned char *next_pseudonym;
    size_t next_pseudonym_len;

    unsigned char *next_reauth_id;
    size_t next_reauth_id_len;

    uint16_t reauth_counter;
    uint16_t authenticator_counter;

    unsigned char nonce_s[SSH_EAP_AKA_NONCE_S_LEN];
} *SshEapAkaState, SshEapAkaStateStruct;

#endif /* SSHDIST_EAP_AKA */
#endif /** SSH_EAP_AKA_H */
