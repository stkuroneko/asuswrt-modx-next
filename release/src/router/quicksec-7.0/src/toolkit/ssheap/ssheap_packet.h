/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

#ifndef SSH_EAP_PACKET_H

#define SSH_EAP_PACKET_H 1

/* Message subtype definitions. */
#ifdef SSHDIST_EAP_AKA
#define SSH_EAP_AKA_CHALLENGE           1
#define SSH_EAP_AKA_AUTH_REJECT         2
#define SSH_EAP_AKA_SYNCH_FAILURE       4
#define SSH_EAP_AKA_IDENTITY            5
#endif /* SSHDIST_EAP_AKA */
#ifdef SSHDIST_EAP_SIM
#define SSH_EAP_SIM_START              10
#define SSH_EAP_SIM_CHALLENGE          11
#endif /* SSHDIST_EAP_SIM */
#define SSH_EAP_NOTIFICATION           12
#define SSH_EAP_REAUTHENTICATION       13
#define SSH_EAP_CLIENT_ERROR           14

/* Defines for AT attributes found in EAP messages. */
#define SSH_EAP_AT_RAND               1
#define SSH_EAP_AT_AUTN               2
#define SSH_EAP_AT_RES                3
#define SSH_EAP_AT_AUTS               4
#define SSH_EAP_AT_PADDING            6
#define SSH_EAP_AT_NONCE_MT           7
#define SSH_EAP_AT_PERMANENT_ID_REQ   10
#define SSH_EAP_AT_MAC                11
#define SSH_EAP_AT_NOTIFICATION       12
#define SSH_EAP_AT_ANY_ID_REQ         13
#define SSH_EAP_AT_IDENTITY           14
#define SSH_EAP_AT_VERSION_LIST       15
#define SSH_EAP_AT_SELECTED_VERSION   16
#define SSH_EAP_AT_FULLAUTH_ID_REQ    17
#define SSH_EAP_AT_COUNTER            19
#define SSH_EAP_AT_COUNTER_TOO_SMALL  20
#define SSH_EAP_AT_NONCE_S            21
#define SSH_EAP_AT_CLIENT_ERROR_CODE  22
#define SSH_EAP_AT_IV                 129
#define SSH_EAP_AT_ENCR_DATA          130
#define SSH_EAP_AT_NEXT_PSEUDONYM     132
#define SSH_EAP_AT_NEXT_REAUTH_ID     133
#define SSH_EAP_AT_CHECKCODE          134
#define SSH_EAP_AT_RESULT_IND         135
/* Skippable attribute for EAP-AKA.*/
#define SSH_EAP_AT_BIDDING            136
/* Attribute for EAP-AKA-DASH in non-skippable range */
#define SSH_EAP_AT_KDF_INPUT          23
#define SSH_EAP_AT_KDF                24

#define SSH_EAP_AKA_AT_LEN_MIN 4
#define SSH_EAP_AKA_AT_LEN_MAX 1024

#define SSH_EAP_AKA_MK_LEN        20
#define SSH_EAP_AKA_MSK_LEN       64
#define SSH_EAP_AKA_EMSK_LEN      64
#define SSH_EAP_AKA_KENCR_LEN     16
#define SSH_EAP_AKA_KAUT_LEN      16
#define SSH_EAP_AKA_RAND_LEN      16
#define SSH_EAP_AKA_MAC_LEN       16
#define SSH_EAP_AKA_CHECKCODE_LEN 20
#define SSH_EAP_AKA_AUTS_LEN      14
#define SSH_EAP_AKA_AUTN_LEN      16
#define SSH_EAP_AKA_CK_LEN        16
#define SSH_EAP_AKA_IK_LEN        16
#define SSH_EAP_AKA_IV_LEN        16
#define SSH_EAP_AKA_NONCE_S_LEN   16

/* Returns the real length of AT attribute in message. */
#define SSH_EAP_AT_LEN(buf, offset)  \
                       ((ssh_buffer_byte_ptr(buf)[offset + 1] & 0xFF) * 4)

/* Return string for EAP attribute code. */
const char*
ssh_eap_at_code_to_string(uint8_t code);

SshCryptoStatus
ssh_eap_aka_cipher_transform(unsigned char *payload,
                             size_t payload_len,
                             unsigned char *key,
                             unsigned char *iv,
                             bool encrypt);

/* Verify EAP message MAC, the MAC value inside packet must
   be zeroized before this. */
SshCryptoStatus
ssh_eap_packet_verify_mac(SshBuffer pkt,
                          unsigned char *aad,
                          size_t aad_len,
                          unsigned char *key,
                          size_t key_len,
                          unsigned char *packet_mac,
                          size_t packet_mac_len);

SshBuffer
ssh_eap_packet_append_res_attr(SshBuffer pkt,
                               uint8_t *res,
                               uint8_t res_len);

bool
ssh_eap_packet_append_mac_attribute(SshBuffer pkt,
                                    unsigned char *aad,
                                    size_t aad_len,
                                    unsigned char *key,
                                    size_t key_len);

bool
ssh_eap_packet_append_at_counter(SshBuffer pkt,
                                 uint16_t counter);

bool
ssh_eap_packet_append_at_counter_too_small(SshBuffer pkt);

bool
ssh_eap_packet_append_at_encr_data(SshBuffer pkt,
                                   SshBuffer data,
                                   unsigned char *key,
                                   unsigned char *iv);

bool
ssh_eap_packet_append_at_iv(SshBuffer pkt,
                            unsigned char *iv);

SshBuffer
ssh_eap_packet_append_auts_attr(SshBuffer pkt, uint8_t *auts);

SshBuffer
ssh_eap_packet_append_nonce_attr(SshBuffer pkt,
                                 uint8_t *nonce);

SshBuffer
ssh_eap_packet_append_selected_version_attr(SshBuffer pkt,
                                            uint8_t *version);

SshBuffer
ssh_eap_packet_append_identity_attr(SshBuffer pkt,
                                    const uint8_t *id,
                                    uint8_t id_len);

uint8_t
ssh_eap_packet_get_code(SshBuffer buf);

uint8_t
ssh_eap_packet_get_identifier(SshBuffer buf);

uint16_t
ssh_eap_packet_get_length(SshBuffer buf);

void
ssh_eap_packet_strip_pad(SshBuffer buf);

uint8_t
ssh_eap_packet_get_type(SshBuffer buf);

bool
ssh_eap_packet_isvalid(SshBuffer buf);

void
ssh_eap_packet_skip_hdr(SshBuffer buf);

bool
ssh_eap_packet_build_hdr(SshBuffer buf,
                         uint8_t code,
                         uint8_t id,
                         uint16_t length);

bool
ssh_eap_packet_build_hdr_with_type(SshBuffer buf,
                                   uint8_t code,
                                   uint8_t id,
                                   uint16_t length,
                                   uint8_t type);
#endif
