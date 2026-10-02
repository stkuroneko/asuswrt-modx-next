/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshbuffer.h"
#include "sshgetput.h"
#include "sshcrypt.h"
#include "ansi_x962.h"
#include "sshmiscstring.h"
#include "sshencode.h"

#include "ssheap.h"
#include "ssheapi.h"
#include "ssheap_packet.h"
#include "ssheap_aka.h"

#define SSH_DEBUG_MODULE "SshEapAka"

#ifdef SSHDIST_EAP_AKA

#define SSH_EAP_AKA_NON_SKIPPABLE_AT_MAX 127

#define SSH_EAP_AKA_HEADER_LEN 8

#define SSH_EAP_AKA_SESSION_KEYS_LEN \
    SSH_EAP_AKA_KENCR_LEN + SSH_EAP_AKA_KAUT_LEN + \
    SSH_EAP_AKA_MSK_LEN + SSH_EAP_AKA_EMSK_LEN

#define SSH_EAP_AKA_CHALLENGE_LEN SSH_EAP_AKA_RAND_LEN + SSH_EAP_AKA_AUTN_LEN

#define AT_NOTIFICATION_SUCCESS_BIT 0x8000
#define AT_NOTIFICATION_PHASE_BIT   0x4000

typedef struct SshEapAkaAttributeRec
{
    uint8_t type;

    /* Length is stored in bytes, not multiple of 4 bytes as in attribute */
    size_t len_bytes;

    union {
        uint16_t reserved;
        uint16_t actual_len;
        uint16_t res_len;
        uint16_t counter;
        uint16_t notification_code;
    } u;

    unsigned char data[SSH_EAP_AKA_AT_LEN_MAX];
    size_t data_len;
} *SshEapAkaAttribute, SshEapAkaAttributeStruct;

static bool
eap_aka_calculate_master_key(SshEapAkaState state)
{
    SshHash hash = NULL;
    bool rv;

    if (ssh_hash_allocate("sha1", &hash) != SSH_CRYPTO_OK)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed"));
        return false;
    }

    ssh_hash_reset(hash);

    /* MK generation section.
       MK = SHA1(Identity, IK, CK) */
    ssh_hash_update(hash, state->user, state->user_len);

    ssh_hash_update(hash, state->aka_id.IK, SSH_EAP_AKA_IK_LEN);
    ssh_hash_update(hash, state->aka_id.CK, SSH_EAP_AKA_CK_LEN);

    if (ssh_hash_final(hash, state->mk) != SSH_CRYPTO_OK)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Hash generation failed"));
        rv = false;
    }
    else
    {
        rv = true;
    }

    ssh_hash_free(hash);
    return rv;
}

static bool
eap_aka_calculate_xkey(SshEapAkaState state)
{
    unsigned char counter_buffer[2];
    SshHash hash = NULL;
    bool rv;

    SSH_PUT_16BIT(counter_buffer, state->reauth_counter);

    if (ssh_hash_allocate("sha1", &hash) != SSH_CRYPTO_OK)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed"));
        return false;
    }

    ssh_hash_reset(hash);

    /* XKEY' = SHA1(Identity | counter | NONCE_S | MK) */
    ssh_hash_update(hash, state->user, state->user_len);
    ssh_hash_update(hash, counter_buffer, 2);
    ssh_hash_update(hash, state->nonce_s, SSH_EAP_AKA_NONCE_S_LEN);
    ssh_hash_update(hash, state->mk, SSH_EAP_AKA_MK_LEN);

    if (ssh_hash_final(hash, state->xkey) != SSH_CRYPTO_OK)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Hash generation failed"));
        rv = false;
    }
    else
    {
        rv = true;
    }

    ssh_hash_free(hash);
    return rv;
}

static bool
eap_aka_calculate_session_keys(SshEapAkaState state,
                               bool initial_authentication)
{
    SshAnsiX962 x962 = NULL;
    unsigned char session_keys[SSH_EAP_AKA_SESSION_KEYS_LEN];
    unsigned char *seed;
    size_t offset = 0;

    if (initial_authentication)
        seed = state->mk;
    else
        seed = state->xkey;

    /* Generate the MSK, EMSK, K_aut and K_encr keys. */
    x962 = ssh_ansi_x962_init();

    if (x962 == NULL)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed"));
        goto fail;
    }

    if (ssh_ansi_x962_add_entropy(x962, seed, SSH_EAP_AKA_MK_LEN)
        != SSH_CRYPTO_OK)
    {
        SSH_DEBUG(SSH_D_FAIL, ("ansi-x9.62 entropy addition failed"));
        goto fail;
    }

    if (ssh_ansi_x962_get_bytes(x962,
                                session_keys,
                                SSH_EAP_AKA_SESSION_KEYS_LEN)
        != SSH_CRYPTO_OK)
    {
        SSH_DEBUG(SSH_D_FAIL, ("ansi-x9.62 operation failed"));
        goto fail;
    }

    ssh_ansi_x962_uninit(x962);

    if (initial_authentication == true)
    {
        memcpy(state->K_encr, session_keys + offset, SSH_EAP_AKA_KENCR_LEN);
        offset += SSH_EAP_AKA_KENCR_LEN;
        memcpy(state->K_aut,  session_keys + offset, SSH_EAP_AKA_KAUT_LEN);
        offset += SSH_EAP_AKA_KAUT_LEN;
    }

    memcpy(state->msk,  session_keys + offset, SSH_EAP_AKA_MSK_LEN);
    offset += SSH_EAP_AKA_MSK_LEN;
    memcpy(state->emsk, session_keys + offset, SSH_EAP_AKA_EMSK_LEN);

    SSH_DEBUG_HEXDUMP(SSH_D_LOWOK, ("MSK"), state->msk, SSH_EAP_AKA_MSK_LEN);

    return true;

fail:
    if (x962 != NULL)
        ssh_ansi_x962_uninit(x962);

    return false;
}

static void
eap_aka_signal_next_auth_params(SshEap eap,
                                SshEapAkaState state)
{
    SshBufferStruct buffer;
    size_t encoded_len, mk_len;

    ssh_buffer_init(&buffer);

    if ((state->next_reauth_id == NULL) && (state->next_pseudonym == NULL))
    {
        SSH_DEBUG(SSH_D_NICETOKNOW,
                  ("EAP-AKA next authentication parameters not available"));
        goto end;
    }

    if (state->next_reauth_id != NULL)
    {
        SSH_DEBUG(SSH_D_NICETOKNOW,
                  ("EAP-AKA Fast Re-Authentication parameters available"));
        SSH_ASSERT(state->next_reauth_id_len > 0);
        state->reauth_counter++;
        mk_len = SSH_EAP_AKA_MK_LEN;
    }
    else
    {
        SSH_DEBUG(SSH_D_NICETOKNOW,
                  ("EAP-AKA Fast Re-Authentication parameters not available"));
        SSH_ASSERT(state->next_reauth_id_len == 0);
        mk_len = 0;
    }

    encoded_len =
        ssh_encode_buffer(&buffer,
                          SSH_ENCODE_UINT32_STR(state->next_pseudonym,
                                                state->next_pseudonym_len),
                          SSH_ENCODE_UINT32_STR(state->next_reauth_id,
                                                state->next_reauth_id_len),
                          SSH_ENCODE_UINT32_STR(state->mk,
                                                mk_len),
                          SSH_ENCODE_UINT16(state->reauth_counter),
                          SSH_FORMAT_END);

    if (encoded_len == 0)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed"));
        goto end;
    }

    SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW,
                      ("Signaling next authentication parameters"),
                      ssh_buffer_ptr(&buffer), ssh_buffer_len(&buffer));

    ssh_eap_send_signal(eap,
                        SSH_EAP_TYPE_AKA,
                        SSH_EAP_SIGNAL_NEXT_AUTH_PARAMS,
                        &buffer);

end:
    ssh_buffer_uninit(&buffer);
    return;
}

static bool
ssh_eap_aka_attribute_size_check(SshEapAkaAttribute attribute)
{
    size_t expected_len = 0;
    bool fixed_size = true;
    bool ok;

    switch (attribute->type)
    {
    case SSH_EAP_AT_PERMANENT_ID_REQ:
    case SSH_EAP_AT_ANY_ID_REQ:
    case SSH_EAP_AT_FULLAUTH_ID_REQ:
    case SSH_EAP_AT_RESULT_IND:
    case SSH_EAP_AT_COUNTER:
    case SSH_EAP_AT_COUNTER_TOO_SMALL:
    case SSH_EAP_AT_NOTIFICATION:
    case SSH_EAP_AT_CLIENT_ERROR_CODE:
    case SSH_EAP_AT_BIDDING:
        expected_len = 4;
        break;

    case SSH_EAP_AT_RAND:
        expected_len = 4 + SSH_EAP_AKA_RAND_LEN;
        break;

    case SSH_EAP_AT_AUTN:
        expected_len = 4 + SSH_EAP_AKA_AUTN_LEN;
        break;

    case SSH_EAP_AT_AUTS:
        expected_len = 2 + SSH_EAP_AKA_AUTS_LEN;
        break;

    case SSH_EAP_AT_IV:
        expected_len = 4 + SSH_EAP_AKA_IV_LEN;
        break;

    case SSH_EAP_AT_MAC:
        expected_len = 4 + SSH_EAP_AKA_MAC_LEN;
        break;

    case SSH_EAP_AT_NONCE_S:
        expected_len = 4 + SSH_EAP_AKA_NONCE_S_LEN;
        break;

    default:
        /* Other attribute types do not have fixed size */
        fixed_size = false;
        break;
    }

    if ((fixed_size == true) &&
        (attribute->len_bytes != expected_len))
    {
        ok = false;
    }
    else if (attribute->type == SSH_EAP_AT_CHECKCODE)
    {
        /* Special case, value may be 0 or 20 bytes */
        if ((attribute->len_bytes == 4 + SSH_EAP_AKA_CHECKCODE_LEN) ||
            (attribute->len_bytes == 4))
        {
            ok = true;
        }
        else
        {
            ok = false;
        }
    }
    else if (attribute->type == SSH_EAP_AT_PADDING)
    {
        /* Special case, may be 4, 8 of 12 bytes */
        if ((attribute->len_bytes == 4) ||
            (attribute->len_bytes == 8) ||
            (attribute->len_bytes == 12))
        {
            ok = true;
        }
        else
        {
            ok = false;
        }
    }
    else
    {
        ok = true;
    }

    return ok;
}

static bool
ssh_eap_aka_attribute_id_sanity_check(SshEapAkaAttribute attribute)
{
    unsigned int i;

    SSH_ASSERT((attribute->type == SSH_EAP_AT_NEXT_PSEUDONYM) ||
               (attribute->type == SSH_EAP_AT_NEXT_REAUTH_ID));

    if (attribute->u.actual_len == 0)
    {
        SSH_DEBUG(SSH_D_FAIL, ("No payload in attribute"));
        return false;
    }

    if (attribute->u.actual_len > attribute->data_len)
    {
        SSH_DEBUG(SSH_D_FAIL,
                  ("Invalid actual length value in attribute: %u, cannot be "
                   "larger than packet data length: %u",
                   (unsigned int) attribute->u.actual_len,
                   (unsigned int) attribute->data_len));
        return false;
    }

    /* Terminating zero not allowed in string, but padding must be all zero */
    for (i = 0; i < attribute->data_len; i++)
    {
        if (i < attribute->u.actual_len)
        {
            if (attribute->data[i] == 0x00)
            {
                SSH_DEBUG(SSH_D_FAIL,
                          ("Invalid NULL-termination in attribute"));
                return false;
            }
        }
        else
        {
            if (attribute->data[i] != 0x00)
            {
                SSH_DEBUG(SSH_D_FAIL,
                          ("Invalid zero-padding in attribute"));
                return false;
            }
        }
    }

    return true;
}

static bool
ssh_eap_aka_attribute_sanity_check(SshEapAkaAttribute attribute)
{
    if (ssh_eap_aka_attribute_size_check(attribute) == false)
    {
        SSH_DEBUG(SSH_D_FAIL,
                  ("Invalid attribute length for attribute type %s: %u bytes",
                   ssh_eap_at_code_to_string(attribute->type),
                   (unsigned int) attribute->len_bytes));

        return false;
    }

    if (attribute->type == SSH_EAP_AT_PADDING)
    {
        int i;

        for (i = 0; i < attribute->data_len; i++)
        {
            if (attribute->data[i] != 0)
            {
                SSH_DEBUG_HEXDUMP(SSH_D_FAIL,
                                  ("AT_PADDING data not zero"),
                                  attribute->data,
                                  attribute->data_len);
                return false;
            }
        }
    }

    return true;
}

static size_t
ssh_eap_aka_attribute_decode(unsigned char *buffer,
                             size_t buffer_len,
                             SshEapAkaAttribute attribute)
{
    size_t data_offset;

    if (buffer_len < SSH_EAP_AKA_AT_LEN_MIN)
    {
        SSH_DEBUG(SSH_D_FAIL,
                  ("Too short buffer for EAP-AKA attribute: %u",
                   (unsigned int) buffer_len));
        return 0;
    }

    attribute->type = SSH_GET_8BIT(buffer);
    attribute->len_bytes = SSH_GET_8BIT(buffer + 1) * 4;
    attribute->u.reserved = SSH_GET_16BIT(buffer + 2);

    if ((attribute->len_bytes < SSH_EAP_AKA_AT_LEN_MIN) &&
        (attribute->len_bytes > SSH_EAP_AKA_AT_LEN_MAX))
    {
        SSH_DEBUG(SSH_D_FAIL,
                  ("Invalid EAP-AKA attribute length in bytes: %u",
                   (unsigned int) attribute->len_bytes));
        return 0;
    }

    if (attribute->len_bytes > buffer_len)
    {
        SSH_DEBUG(SSH_D_FAIL,
                  ("Corrupted EAP-AKA attribute, length larger than buffer: "
                   "%u > %u",
                   (unsigned int) attribute->len_bytes,
                   (unsigned int) buffer_len));
        return 0;
    }

    if (ssh_eap_aka_attribute_sanity_check(attribute) == false)
    {
        SSH_DEBUG(SSH_D_FAIL,
                  ("Invalid EAP-AKA attribute sanity check failed"));
        return 0;
    }

    if ((attribute->type == SSH_EAP_AT_PADDING) ||
        (attribute->type == SSH_EAP_AT_AUTS))
    {
        data_offset = 2;
    }
    else
    {
        data_offset = 4;
    }

    memcpy(attribute->data,
           buffer + data_offset,
           attribute->len_bytes - data_offset);
    attribute->data_len = attribute->len_bytes - data_offset;

    if ((attribute->type == SSH_EAP_AT_NEXT_PSEUDONYM) ||
        (attribute->type == SSH_EAP_AT_NEXT_REAUTH_ID))
    {
        if (ssh_eap_aka_attribute_id_sanity_check(attribute)
            == false)
        {
            SSH_DEBUG(SSH_D_FAIL, ("Invalid EAP-AKA attribute"));
            return 0;
        }
    }

    /* When MAC attribute is found, make packet ready for MAC verification
       by zeroizing the value. */
    if (attribute->type == SSH_EAP_AT_MAC)
    {
        memset(buffer + 4, 0, attribute->len_bytes - 4);
    }

#ifdef DEBUG_LIGHT
    {
        char *special_bytes_info;
        char header_info[64] = { 0 };

        switch (attribute->type)
        {
        case SSH_EAP_AT_IDENTITY:
        case SSH_EAP_AT_NEXT_PSEUDONYM:
        case SSH_EAP_AT_NEXT_REAUTH_ID:
            special_bytes_info = "actual length";
            break;
        case SSH_EAP_AT_RES:
            special_bytes_info = "RES length";
            break;
        case SSH_EAP_AT_COUNTER:
            special_bytes_info = "counter value";
            break;
        case SSH_EAP_AT_NOTIFICATION:
            special_bytes_info = "notification code";
            break;
        case SSH_EAP_AT_CLIENT_ERROR_CODE:
            special_bytes_info = "error code";
            break;
        default:
            /* No need to print reserved bytes */
            special_bytes_info = NULL;
            break;
        }

        if (special_bytes_info == NULL)
        {
            ssh_snprintf(header_info,
                         sizeof(header_info),
                         "length: %u",
                         attribute->len_bytes);
        }
        else
        {
            ssh_snprintf(header_info,
                         sizeof(header_info),
                         "length: %u, %s: %u",
                         attribute->len_bytes,
                         special_bytes_info,
                         (unsigned int) attribute->u.reserved);
        }

        if (attribute->data_len == 0)
        {
            SSH_DEBUG(SSH_D_DATADUMP,
                      ("%s(%s)",
                       ssh_eap_at_code_to_string(attribute->type),
                       header_info));
        }
        else
        {
            SSH_DEBUG(SSH_D_DATADUMP,
                      ("%s(%s, data: %.*@)",
                       ssh_eap_at_code_to_string(attribute->type),
                       header_info,
                       attribute->data_len,
                       ssh_hex_render,
                       attribute->data));
        }
    }
#endif /* DEBUG_LIGHT */

    return attribute->len_bytes;
}

static uint8_t
ssh_eap_aka_encrypted_data_decode(SshEapAkaState state,
                                  unsigned char *payload,
                                  size_t payload_len,
                                  unsigned char *key,
                                  unsigned char *iv)
{
    SshCryptoStatus crypto_status;
    unsigned int next_pseudonym_count = 0;
    unsigned int next_reauth_id_count = 0;
    unsigned int counter_count = 0;
    unsigned int nonce_s_count = 0;
    unsigned int padding_count = 0;

    size_t offset = 0;

    crypto_status =
        ssh_eap_aka_cipher_transform(payload, payload_len, key, iv, false);

    if (crypto_status != SSH_CRYPTO_OK)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Failed to decrypt encrypted payload"));
        return SSH_EAP_AKA_ERR_GENERAL;
    }

    while (offset < payload_len)
    {
        SshEapAkaAttributeStruct attribute = { 0 };
        size_t read_len;

        read_len = ssh_eap_aka_attribute_decode(payload + offset,
                                                payload_len - offset,
                                                &attribute);

        if (read_len == 0)
        {
            SSH_DEBUG(SSH_D_FAIL, ("Failed to decode EAP-AKA attribute"));
            return SSH_EAP_AKA_ERR_PACKET_CORRUPTED;
        }

        offset += read_len;

        switch (attribute.type)
        {
        case SSH_EAP_AT_NEXT_PSEUDONYM:
            if (state->next_pseudonym != NULL)
            {
                ssh_free(state->next_pseudonym);
                state->next_pseudonym_len = 0;
            }

            state->next_pseudonym = ssh_memdup(attribute.data,
                                               attribute.u.actual_len);

            if (state->next_pseudonym == NULL)
            {
                SSH_DEBUG(SSH_D_NICETOKNOW, ("Memory allocation failed"));
                return SSH_EAP_AKA_ERR_MEMALLOC_FAILED;
            }

            state->next_pseudonym_len = attribute.u.actual_len;
            next_pseudonym_count++;
            break;
        case SSH_EAP_AT_NEXT_REAUTH_ID:
            if (state->next_reauth_id != NULL)
            {
                ssh_free(state->next_reauth_id);
                state->next_reauth_id_len = 0;
            }

            state->next_reauth_id = ssh_memdup(attribute.data,
                                               attribute.u.actual_len);

            if (state->next_reauth_id == NULL)
            {
                SSH_DEBUG(SSH_D_NICETOKNOW, ("Memory allocation failed"));
                return SSH_EAP_AKA_ERR_MEMALLOC_FAILED;
            }

            state->next_reauth_id_len = attribute.u.actual_len;
            next_reauth_id_count++;
            break;
        case SSH_EAP_AT_COUNTER:
            state->authenticator_counter = attribute.u.counter;
            counter_count++;
            break;
        case SSH_EAP_AT_NONCE_S:
            memcpy(state->nonce_s, attribute.data, attribute.data_len);
            nonce_s_count++;
            break;
        case SSH_EAP_AT_PADDING:
            padding_count++;
            break;
        default:
            break;
        }
    }

    if (next_pseudonym_count > 1 || next_reauth_id_count > 1 ||
        counter_count > 1 || nonce_s_count > 1 || padding_count > 1)
    {
        SSH_DEBUG(SSH_D_FAIL,
                  ("Corrupted EAP-AKA encrypted payload attributes"));
        return SSH_EAP_AKA_ERR_PACKET_CORRUPTED;
    }

    return SSH_EAP_AKA_DEC_OK;
}

static uint8_t
ssh_eap_aka_decode_req_identity(SshEapProtocol protocol,
                                SshBuffer buf)
{
    uint8_t  id_cnt      = 0;
    SshEapAkaState state  = NULL;
    size_t offset = SSH_EAP_AKA_HEADER_LEN;
    size_t eap_packet_len;
    unsigned char *eap_packet;

    SSH_ASSERT(protocol != NULL);
    SSH_ASSERT(buf != NULL);

    state = ssh_eap_protocol_get_state(protocol);

    if (state->aka_proto_flags & SSH_EAP_AKA_PERMID_RCVD)
    {
        SSH_DEBUG(SSH_D_FAIL,
                  ("No identity requests allowed after PERMANENT_ID request "
                   "has been received."));
        return SSH_EAP_AKA_ERR_INVALID_STATE;
    }

    SSH_DEBUG(SSH_D_NICETOKNOW, ("Decoding AKA-Request/AKA-Identity"));

    eap_packet = ssh_buffer_byte_ptr(buf);
    eap_packet_len = ssh_buffer_len(buf);

    while (offset < eap_packet_len)
    {
        SshEapAkaAttributeStruct attribute = { 0 };
        size_t read_len;

        read_len = ssh_eap_aka_attribute_decode(eap_packet + offset,
                                                eap_packet_len - offset,
                                                &attribute);

        if (read_len == 0)
        {
            SSH_DEBUG(SSH_D_FAIL, ("Failed to decode EAP-AKA attribute"));
            return SSH_EAP_AKA_ERR_PACKET_CORRUPTED;
        }

        offset += read_len;

        switch (attribute.type)
        {
        case SSH_EAP_AT_ANY_ID_REQ:

            if (state->aka_proto_flags & SSH_EAP_AKA_FULLID_RCVD ||
                state->aka_proto_flags & SSH_EAP_AKA_ANYID_RCVD)
            {
                SSH_DEBUG(SSH_D_FAIL,
                          ("ANY_ID request not allowed after ANY_ID or "
                           "FULL_ID request has been received."));
                return SSH_EAP_AKA_ERR_INVALID_STATE;
            }

            state->aka_proto_flags |= SSH_EAP_AKA_ANYID_RCVD;
            id_cnt++;
            break;

        case SSH_EAP_AT_FULLAUTH_ID_REQ:

            if (state->aka_proto_flags & SSH_EAP_AKA_FULLID_RCVD)
            {
                SSH_DEBUG(SSH_D_FAIL,
                          ("FULL_ID request not allowed if FULL_ID request "
                           "has already been received."));
                return SSH_EAP_AKA_ERR_INVALID_STATE;
            }

            state->aka_proto_flags |= SSH_EAP_AKA_FULLID_RCVD;
            id_cnt++;
            break;

        case SSH_EAP_AT_PERMANENT_ID_REQ:
            state->aka_proto_flags |= SSH_EAP_AKA_PERMID_RCVD;
            id_cnt++;
            break;

        default:
            if (attribute.type > SSH_EAP_AKA_NON_SKIPPABLE_AT_MAX)
            {
                SSH_DEBUG(SSH_D_NETGARB,
                          ("EAP-AKA skippable attribute: %u",
                           (unsigned int) attribute.type));
                break;
            }
            else
            {
                SSH_DEBUG(SSH_D_FAIL,
                          ("EAP-AKA invalid attribute for request identity: "
                           "%u",
                           (unsigned int) attribute.type));
                return SSH_EAP_AKA_ERR_INVALID_IE;
            }
        }
    }


    state->aka_proto_flags |= SSH_EAP_AKA_ANYID_RCVD;

    if (offset != eap_packet_len)
        return SSH_EAP_AKA_ERR_PACKET_CORRUPTED;

    if (id_cnt != 1)
    {
        SSH_DEBUG(SSH_D_FAIL,
                  ("Invalid number of identity request attributes."));
        return SSH_EAP_AKA_ERR_GENERAL;
    }

    return SSH_EAP_AKA_DEC_OK;
}

static uint8_t
ssh_eap_aka_decode_challenge(SshEapProtocol protocol,
                             SshBuffer buf,
                             unsigned char *rand,
                             unsigned char *autn,
                             unsigned char *packet_mac)
{
    uint8_t  mac_found     = 0;
    uint8_t  check_cnt     = 0;
    uint8_t  autn_cnt      = 0;
    uint8_t  rand_found    = 0;
    uint8_t  resultind_cnt = 0;
    uint8_t  bidding_cnt   = 0;
    uint8_t  iv_cnt        = 0;
    uint8_t  encrypted_cnt = 0;
    SshEapAkaState state    = NULL;

    unsigned char *eap_packet;
    size_t eap_packet_len;
    size_t offset = SSH_EAP_AKA_HEADER_LEN;

    SSH_ASSERT(protocol != NULL);
    SSH_ASSERT(buf != NULL);
    SSH_ASSERT(rand != NULL);
    SSH_ASSERT(autn != NULL);

    state = ssh_eap_protocol_get_state(protocol);

    SSH_DEBUG(SSH_D_NICETOKNOW, ("Decoding AKA-Request/AKA-Challenge"));

    eap_packet = ssh_buffer_byte_ptr(buf);
    eap_packet_len = ssh_buffer_len(buf);

    while (offset < eap_packet_len)
    {
        SshEapAkaAttributeStruct attribute = { 0 };
        size_t read_len;

        read_len = ssh_eap_aka_attribute_decode(eap_packet + offset,
                                                eap_packet_len - offset,
                                                &attribute);

        if (read_len == 0)
        {
            SSH_DEBUG(SSH_D_FAIL, ("Failed to decode EAP-AKA attribute"));
            return SSH_EAP_AKA_ERR_PACKET_CORRUPTED;
        }

        offset += read_len;

        switch (attribute.type)
        {
        case SSH_EAP_AT_IV:
            SSH_ASSERT(attribute.data != NULL);
            SSH_ASSERT(attribute.data_len == SSH_EAP_AKA_IV_LEN);

            memcpy(state->iv, attribute.data, attribute.data_len);
            iv_cnt++;

            break;

        case SSH_EAP_AT_ENCR_DATA:
            if (state->encrypted_data != NULL)
            {
                ssh_free(state->encrypted_data);
                state->encrypted_data = NULL;
                state->encrypted_data_len = 0;
            }

            SSH_ASSERT(attribute.data != NULL);
            SSH_ASSERT(attribute.data_len > 0);

            state->encrypted_data = ssh_memdup(attribute.data,
                                               attribute.data_len);

            if (state->encrypted_data == NULL)
            {
                SSH_DEBUG(SSH_D_FAIL,
                          ("Memory allocation failed"));
                return SSH_EAP_AKA_ERR_MEMALLOC_FAILED;
            }
            state->encrypted_data_len = attribute.data_len;

            encrypted_cnt++;
            break;

        case SSH_EAP_AT_CHECKCODE:
            check_cnt++;
            SSH_DEBUG(SSH_D_NICETOKNOW,
                      ("EAP-AKA server requested checkcode, ignored."));
            break;

        case SSH_EAP_AT_RESULT_IND:

            SSH_DEBUG(SSH_D_NICETOKNOW,
                      ("EAP-AKA server indicated it want's"
                       " to use protected success messages"));

            resultind_cnt++;

            state->aka_proto_flags |= SSH_EAP_AKA_PROT_SUCCESS;
            break;

        case SSH_EAP_AT_MAC:
            memcpy(packet_mac, attribute.data, SSH_EAP_AKA_MAC_LEN);
            mac_found++;
            break;

        case SSH_EAP_AT_AUTN:
            SSH_ASSERT(attribute.data_len == SSH_EAP_AKA_AUTN_LEN);

            memcpy(autn, attribute.data, SSH_EAP_AKA_AUTN_LEN);
            autn_cnt++;
            break;

        case SSH_EAP_AT_RAND:
            SSH_ASSERT(attribute.data_len == SSH_EAP_AKA_RAND_LEN);

            memcpy(rand, attribute.data, SSH_EAP_AKA_RAND_LEN);
            rand_found++;
            break;

        case SSH_EAP_AT_BIDDING:

            SSH_DEBUG(SSH_D_NICETOKNOW,
                      ("EAP-AKA server sent us AT_BIDDING"));
            bidding_cnt++;

            state->aka_proto_flags |= SSH_EAP_AKA_BIDDING_REQ_RCVD;
            break;

        default:
            if (attribute.type > SSH_EAP_AKA_NON_SKIPPABLE_AT_MAX)
            {
                SSH_DEBUG(SSH_D_NETGARB,
                          ("EAP-AKA skippable attribute: %u",
                           (unsigned int) attribute.type));
                break;
            }
            else
            {
                SSH_DEBUG(SSH_D_FAIL,
                          ("EAP-AKA invalid attribute: %u",
                           (unsigned int) attribute.type));
                return SSH_EAP_AKA_ERR_INVALID_IE;
            }
        }
    }

    if (offset != eap_packet_len)
        return SSH_EAP_AKA_ERR_PACKET_CORRUPTED;

    if (resultind_cnt > 1 || autn_cnt > 1 || check_cnt > 1 ||
        bidding_cnt > 1 || iv_cnt > 1 || encrypted_cnt > 1)
        return SSH_EAP_AKA_ERR_GENERAL;

    if (mac_found == 1 && rand_found == 1)
        return SSH_EAP_AKA_DEC_OK;

    return SSH_EAP_AKA_ERR_GENERAL;
}

static uint8_t
ssh_eap_aka_decode_reauth(SshEapProtocol protocol,
                          SshBuffer buf,
                          unsigned char *packet_mac)
{
    SshEapAkaState state = NULL;
    unsigned char *eap_packet;
    size_t eap_packet_len;
    size_t offset = SSH_EAP_AKA_HEADER_LEN;
    unsigned int iv_count = 0;
    unsigned int encr_count = 0;
    unsigned int checkcode_count = 0;
    unsigned int result_ind_count = 0;
    unsigned int mac_count = 0;

    SSH_ASSERT(protocol != NULL);
    SSH_ASSERT(buf != NULL);

    eap_packet = ssh_buffer_byte_ptr(buf);
    eap_packet_len = ssh_buffer_len(buf);

    state = ssh_eap_protocol_get_state(protocol);
    SSH_ASSERT(state != NULL);

    SSH_DEBUG(SSH_D_NICETOKNOW, ("Decoding EAP-Request/AKA-Reauthentication"));

    while (offset < eap_packet_len)
    {
        SshEapAkaAttributeStruct attribute = { 0 };
        size_t read_len;

        read_len = ssh_eap_aka_attribute_decode(eap_packet + offset,
                                                eap_packet_len - offset,
                                                &attribute);

        if (read_len == 0)
        {
            SSH_DEBUG(SSH_D_FAIL, ("Failed to decode EAP-AKA attribute"));
            return SSH_EAP_AKA_ERR_PACKET_CORRUPTED;
        }

        offset += read_len;

        switch (attribute.type)
        {
        case SSH_EAP_AT_IV:
            SSH_ASSERT(attribute.data != NULL);
            SSH_ASSERT(attribute.data_len == SSH_EAP_AKA_IV_LEN);

            memcpy(state->iv, attribute.data, attribute.data_len);
            iv_count++;
            break;

        case SSH_EAP_AT_ENCR_DATA:
            SSH_ASSERT(attribute.data != NULL);
            SSH_ASSERT(attribute.data_len > 0);

            if (state->encrypted_data)
            {
                ssh_free(state->encrypted_data);
                state->encrypted_data = NULL;
                state->encrypted_data_len = 0;
            }

            state->encrypted_data = ssh_memdup(attribute.data,
                                               attribute.data_len);

            if (state->encrypted_data == NULL)
            {
                SSH_DEBUG(SSH_D_FAIL,
                          ("Memory allocation failed"));
                return SSH_EAP_AKA_ERR_MEMALLOC_FAILED;
            }
            state->encrypted_data_len = attribute.data_len;

            encr_count++;
            break;

        case SSH_EAP_AT_CHECKCODE:
            SSH_DEBUG(SSH_D_NICETOKNOW, ("Ignoring AT_CHECKCODE"));
            checkcode_count++;
            break;

        case SSH_EAP_AT_RESULT_IND:
            SSH_DEBUG(SSH_D_NICETOKNOW, ("Ignoring AT_RESULT_IND"));
            result_ind_count++;
            break;

        case SSH_EAP_AT_MAC:
            memcpy(packet_mac, attribute.data, SSH_EAP_AKA_MAC_LEN);
            mac_count++;
            break;

        default:
            if (attribute.type > SSH_EAP_AKA_NON_SKIPPABLE_AT_MAX)
            {
                SSH_DEBUG(SSH_D_NETGARB,
                          ("EAP-AKA skippable attribute: %u",
                           (unsigned int) attribute.type));
                break;
            }
            else
            {
                SSH_DEBUG(SSH_D_FAIL,
                          ("EAP-AKA invalid attribute: %u",
                           (unsigned int) attribute.type));
                return SSH_EAP_AKA_ERR_INVALID_IE;
            }
        }

    }

    if (checkcode_count > 1 || result_ind_count > 1)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Invalid number of attributes in packet"));
        return SSH_EAP_AKA_ERR_PACKET_CORRUPTED;
    }

    if (iv_count != 1 || encr_count != 1 || mac_count != 1)
    {
        SSH_DEBUG(SSH_D_FAIL, ("EAP-AKA Reauth request not protected"));
        return SSH_EAP_AKA_ERR_PACKET_CORRUPTED;
    }

    return SSH_EAP_AKA_DEC_OK;
}

static uint8_t
ssh_eap_aka_decode_notification(SshEapProtocol protocol,
                                SshBuffer buf,
                                uint16_t *notif_val,
                                unsigned char *packet_mac)
{
    uint8_t  mac_cnt       = 0;
    uint8_t  ativ_cnt      = 0;
    uint8_t  notif_cnt     = 0;
    uint8_t  encrdata_cnt  = 0;

    unsigned char *eap_packet;
    size_t eap_packet_len;
    size_t offset = SSH_EAP_AKA_HEADER_LEN;

    SSH_ASSERT(protocol != NULL);
    SSH_ASSERT(buf != NULL);
    SSH_ASSERT(notif_val != NULL);

    SSH_DEBUG(SSH_D_NICETOKNOW, ("Decoding EAP-Request/AKA-Notification"));

    eap_packet = ssh_buffer_byte_ptr(buf);
    eap_packet_len = ssh_buffer_len(buf);

    while (offset < eap_packet_len)
    {
        SshEapAkaAttributeStruct attribute = { 0 };
        size_t read_len;

        read_len = ssh_eap_aka_attribute_decode(eap_packet + offset,
                                                eap_packet_len - offset,
                                                &attribute);

        if (read_len == 0)
        {
            SSH_DEBUG(SSH_D_FAIL, ("Failed to decode EAP-AKA attribute"));
            return SSH_EAP_AKA_ERR_PACKET_CORRUPTED;
        }

        offset += read_len;

        switch (attribute.type)
        {
        case SSH_EAP_AT_IV:
            ativ_cnt++;
            break;

        case SSH_EAP_AT_ENCR_DATA:
            encrdata_cnt++;
            break;

        case SSH_EAP_AT_MAC:
            memcpy(packet_mac, attribute.data, SSH_EAP_AKA_MAC_LEN);
            mac_cnt++;
            break;

        case SSH_EAP_AT_NOTIFICATION:
            *notif_val = attribute.u.notification_code;
            notif_cnt++;
            break;

        default:
            if (attribute.type > SSH_EAP_AKA_NON_SKIPPABLE_AT_MAX)
            {
                SSH_DEBUG(SSH_D_NETGARB,
                          ("EAP-AKA skippable attribute: %u",
                           (unsigned int) attribute.type));
                break;
            }
            else
            {
                SSH_DEBUG(SSH_D_FAIL,
                          ("EAP-AKA invalid attribute: %u",
                           (unsigned int) attribute.type));
                return SSH_EAP_AKA_ERR_INVALID_IE;
            }
        }
    }

    if (offset != ssh_buffer_len(buf))
        return SSH_EAP_AKA_ERR_PACKET_CORRUPTED;

    if (ativ_cnt > 1 || encrdata_cnt > 1 || mac_cnt > 1 ||
        notif_cnt > 1)
        return SSH_EAP_AKA_ERR_GENERAL;

    if (notif_cnt == 1)
        return SSH_EAP_AKA_DEC_OK;

    return SSH_EAP_AKA_ERR_GENERAL;
}

/* Pass information to the upper layer. */
static void
ssh_eap_aka_auth_fail(SshEapProtocol protocol, SshEap eap,
                      SshEapSignal sig, const char *cause_str,
                      const char *additional_str)
{
    SshBufferStruct dummy;
    SshBuffer dummy_p = NULL;
    char *combined_str = NULL;

    if (cause_str != NULL)
    {
        if (additional_str != NULL)
        {
            size_t len = strlen(cause_str) + strlen(additional_str) + 3;

            combined_str = ssh_malloc(len);
            if (combined_str != NULL)
            {
                ssh_snprintf(combined_str, len, "%s, %s", cause_str,
                             additional_str);
            }
        }
        else
        {
            combined_str = ssh_memdup(cause_str, strlen(cause_str));
        }

        if (combined_str != NULL)
        {
            dummy.dynamic = false;
            dummy.offset = 0;
            dummy.alloc = strlen(combined_str);
            dummy.end = dummy.alloc;
            dummy.buf = (unsigned char *) combined_str;

            dummy_p = &dummy;
        }
    }

    /* Pass information the upper layer. */
    ssh_eap_protocol_auth_fail(protocol, eap, sig, dummy_p);

    if (combined_str != NULL)
        ssh_free(combined_str);
}

static void
ssh_eap_aka_send_client_error(SshEapProtocol protocol, SshEap eap,
                              uint16_t err_code)
{
    SshBuffer pkt = NULL;
    unsigned char buf[7] = {SSH_EAP_CLIENT_ERROR, 0, 0,
                            SSH_EAP_AT_CLIENT_ERROR_CODE, 1, 0xff, 0xff};

    SSH_ASSERT(protocol != NULL);
    SSH_ASSERT(eap != NULL);

    SSH_DEBUG(SSH_D_NICETOKNOW, ("Sending EAP-Response/AKA-Client-Error"));

    pkt = ssh_eap_create_reply(eap,
                               (uint16_t) sizeof(buf),
                               protocol->impl->id);
    if (!pkt)
    {
        ssh_eap_fatal(eap, protocol, "Out of memory. Can not send reply.");
        return;
    }

    if (ssh_buffer_append(pkt, buf, sizeof(buf)) != SSH_BUFFER_OK)
    {
        ssh_buffer_free(pkt);
        ssh_eap_fatal(eap, protocol, "Out of memory. Can not send reply.");
        return;
    }

    ssh_eap_protocol_send_response(protocol, eap, pkt);
}

/* Handle all possible error cases here. In short, all errors are
   treated as fatal and always terminate authentication. */
static void
ssh_eap_aka_client_error(SshEapProtocol protocol, SshEap eap,
                         uint8_t error, const char *error_str,
                         const char *additional_str)
{
    SshEapAkaState state;

    SSH_ASSERT(protocol != NULL);
    SSH_ASSERT(eap != NULL);

    SSH_DEBUG(SSH_D_NICETOKNOW,
              ("EAP-AKA processing client error of type %u", error));

    state = ssh_eap_protocol_get_state(protocol);
    state->aka_proto_flags |= SSH_EAP_AKA_STATE_FAILED;

    switch (error)
    {
    case SSH_EAP_AKA_ERR_GENERAL:
    case SSH_EAP_AKA_ERR_INVALID_IE:
    case SSH_EAP_AKA_ERR_PACKET_CORRUPTED:
    case SSH_EAP_AKA_ERR_MEMALLOC_FAILED:
    case SSH_EAP_AKA_ERR_INVALID_STATE:
        ssh_eap_aka_send_client_error(protocol, eap, 0);
        break;

    case SSH_EAP_AKA_DEC_OK:
    default:
        SSH_ASSERT(0);
        break;
    }

    /* Inform the upper layer that something has gone bad here. */
    ssh_eap_aka_auth_fail(protocol, eap, SSH_EAP_SIGNAL_AUTH_FAIL_REPLY,
                          error_str, additional_str);
}

static void
ssh_eap_aka_send_identity_reply(SshEapProtocol protocol,
                                SshEap eap)
{
    SshEapAkaState state   = NULL;
    SshBuffer      pkt     = NULL;
    uint8_t       buf[3]  = { SSH_EAP_AKA_IDENTITY, 0, 0 };
    uint16_t      identity_len = 0;

    SSH_ASSERT(protocol != NULL);
    SSH_ASSERT(eap != NULL);

    SSH_DEBUG(SSH_D_NICETOKNOW, ("Sending EAP-Response/AKA-Identity"));

    state = ssh_eap_protocol_get_state(protocol);

    /* Calculate the real packet length. */
    if (state->user_len % 4)
        identity_len += 4 + state->user_len + (4 - (state->user_len % 4));
    else
        identity_len += 4 + state->user_len;

    pkt = ssh_eap_create_reply(eap,
                               ((uint16_t) sizeof(buf)) + identity_len,
                               protocol->impl->id);
    if (!pkt)
    {
        ssh_eap_fatal(eap, protocol, "Out of memory. Can not send reply.");
        return;
    }

    if (ssh_buffer_append(pkt, buf, sizeof(buf)) != SSH_BUFFER_OK)
    {
        ssh_buffer_free(pkt);

        ssh_eap_fatal(eap, protocol, "Out of memory. Can not send reply.");
        return;
    }

    if (!ssh_eap_packet_append_identity_attr(pkt,
                                             state->user,
                                             state->user_len))
    {
        ssh_buffer_free(pkt);

        ssh_eap_fatal(eap, protocol, "Out of memory. Can not send reply.");
        return;
    }

    ssh_eap_protocol_send_response(protocol, eap, pkt);
}

static void
ssh_eap_aka_send_synch_fail_reply(SshEapProtocol protocol,
                                  SshEap eap)
{
    SshEapAkaState state   = NULL;
    SshBuffer      pkt     = NULL;
    uint8_t       buf[3]  = { SSH_EAP_AKA_SYNCH_FAILURE, 0, 0 };
    uint16_t      pkt_len = 0;

    SSH_ASSERT(protocol != NULL);
    SSH_ASSERT(eap != NULL);

    SSH_DEBUG(SSH_D_NICETOKNOW,
              ("Sending EAP-Response/AKA-Synchronization-Failure"));

    state = ssh_eap_protocol_get_state(protocol);

    /* AT_AUTS uses 2-byte header length */
    pkt_len = (uint16_t) sizeof(buf) + 2 + SSH_EAP_AKA_AUTS_LEN;

    pkt = ssh_eap_create_reply(eap, pkt_len, protocol->impl->id);

    if (!pkt)
    {
        ssh_eap_fatal(eap, protocol, "Out of memory. Can not send reply.");
        return;
    }

    if (ssh_buffer_append(pkt, buf, (uint16_t) sizeof(buf)) != SSH_BUFFER_OK)
    {
        ssh_buffer_free(pkt);

        ssh_eap_fatal(eap, protocol, "Out of memory. Can not send reply.");
        return;
    }

    if (!ssh_eap_packet_append_auts_attr(pkt, state->aka_id.auts))
    {
        ssh_buffer_free(pkt);

        ssh_eap_fatal(eap, protocol, "Out of memory. Can not send reply.");
        return;
    }

    ssh_eap_protocol_send_response(protocol, eap, pkt);
}

static void
ssh_eap_aka_send_auth_reject_reply(SshEapProtocol protocol,
                                   SshEap eap)
{
    SshBuffer      pkt     = NULL;
    uint8_t       buf[3]  = { SSH_EAP_AKA_AUTH_REJECT, 0, 0 };

    SSH_ASSERT(protocol != NULL);
    SSH_ASSERT(eap != NULL);

    SSH_DEBUG(SSH_D_NICETOKNOW,
              ("Sending EAP-Response/AKA-Authentication-Reject"));

    pkt = ssh_eap_create_reply(eap,
                               (uint16_t) sizeof(buf),
                               protocol->impl->id);
    if (!pkt)
    {
        ssh_eap_fatal(eap, protocol, "Out of memory. Can not send reply.");
        return;
    }

    if (ssh_buffer_append(pkt, buf, sizeof(buf)) != SSH_BUFFER_OK)
    {
        ssh_buffer_free(pkt);

        ssh_eap_fatal(eap, protocol, "Out of memory. Can not send reply.");
        return;
    }

    ssh_eap_protocol_send_response(protocol, eap, pkt);
}

static void
ssh_eap_aka_send_challenge_reply(SshEapProtocol protocol,
                                 SshEap eap)
{
    SshEapAkaState state        = NULL;
    SshBuffer      pkt          = NULL;
    uint8_t       buf[3]       = { SSH_EAP_AKA_CHALLENGE, 0, 0 };
    uint16_t      pkt_len      = 0;
    uint16_t      res_byte_len = 0;

    SSH_ASSERT(protocol != NULL);
    SSH_ASSERT(eap != NULL);

    state = ssh_eap_protocol_get_state(protocol);

    SSH_ASSERT(state != NULL);

    res_byte_len = (state->aka_id.res_len + 7) / 8;

    SSH_DEBUG(SSH_D_NICETOKNOW, ("Sending EAP-Response/AKA-Challenge"));

    /* Header + AT_RES + MAC */
    pkt_len =
        (uint16_t) sizeof(buf) + 4 + res_byte_len + 4 + SSH_EAP_AKA_MAC_LEN;

    pkt = ssh_eap_create_reply(eap, pkt_len, protocol->impl->id);
    if (!pkt)
    {
        ssh_eap_fatal(eap, protocol, "Out of memory. Can not send reply.");
        return;
    }

    if (ssh_buffer_append(pkt, buf, (uint16_t) sizeof(buf)) != SSH_BUFFER_OK)
    {
        ssh_buffer_free(pkt);

        ssh_eap_fatal(eap, protocol, "Out of memory. Can not send reply.");
        return;
    }

    if (!ssh_eap_packet_append_res_attr(pkt, state->aka_id.res,
                                        state->aka_id.res_len))
    {
        ssh_buffer_free(pkt);

        ssh_eap_fatal(eap, protocol, "Out of memory. Can not send reply.");
        return;
    }

    if (ssh_eap_packet_append_mac_attribute(pkt,
                                            NULL,
                                            0,
                                            state->K_aut,
                                            SSH_EAP_AKA_KAUT_LEN)
        == false)
    {
        ssh_buffer_free(pkt);
        ssh_eap_fatal(eap, protocol,
                      "EAP-AKA could not calculate mac for challenge "
                      "response");
        return;
    }

    ssh_eap_protocol_send_response(protocol, eap, pkt);
}

static void
ssh_eap_aka_send_reauth_reply(SshEapProtocol protocol,
                              SshEap eap,
                              bool counter_too_small)
{
    SshEapAkaState state = NULL;
    SshBuffer packet = NULL;
    SshBuffer encrypted_payload = NULL;
    uint16_t packet_len= 0, at_padding_len = 0;
    unsigned char iv[SSH_EAP_AKA_IV_LEN];
    unsigned char subtype_header[3];
    unsigned int i;

    SSH_ASSERT(protocol != NULL);
    SSH_ASSERT(eap != NULL);

    SSH_DEBUG(SSH_D_NICETOKNOW, ("Sending EAP-Response/AKA-Reauthentication"));

    state = ssh_eap_protocol_get_state(protocol);

    encrypted_payload = ssh_buffer_allocate();

    if (encrypted_payload == NULL)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed"));
        goto fail;
    }

    if (ssh_eap_packet_append_at_counter(encrypted_payload,
                                         state->reauth_counter)
        == false)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed"));
        goto fail;
    }

    if ((counter_too_small == true) &&
        (ssh_eap_packet_append_at_counter_too_small(encrypted_payload)
         == false))
    {
        SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed"));
        goto fail;
    }

    if (ssh_buffer_len(encrypted_payload) % 16)
    {
        at_padding_len =
            (uint16_t) (16 - (ssh_buffer_len(encrypted_payload) % 16));
    }

    packet_len = (uint16_t) sizeof(subtype_header) +
        SSH_EAP_AKA_AT_LEN_MIN + (uint16_t)ssh_buffer_len(encrypted_payload) +
        at_padding_len +
        SSH_EAP_AKA_AT_LEN_MIN + SSH_EAP_AKA_IV_LEN +
        SSH_EAP_AKA_AT_LEN_MIN + SSH_EAP_AKA_MAC_LEN;

    packet = ssh_eap_create_reply(eap, packet_len, protocol->impl->id);

    if (packet == NULL)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed"));
        goto fail;
    }

    subtype_header[0] = SSH_EAP_REAUTHENTICATION;
    subtype_header[1] = 0;
    subtype_header[2] = 0;

    if (ssh_buffer_append(packet, subtype_header, 3) != SSH_BUFFER_OK)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed"));
        goto fail;
    }

    for (i = 0; i < SSH_EAP_AKA_IV_LEN; i++)
        iv[i] = ssh_random_get_byte();

    if (ssh_eap_packet_append_at_encr_data(packet,
                                           encrypted_payload,
                                           state->K_encr,
                                           iv)
        == false)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed"));
        goto fail;
    }

    ssh_buffer_free(encrypted_payload);
    encrypted_payload = NULL;

    if (ssh_eap_packet_append_at_iv(packet, iv) == false)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed"));
        goto fail;
    }

    if (ssh_eap_packet_append_mac_attribute(packet,
                                            state->nonce_s,
                                            SSH_EAP_AKA_NONCE_S_LEN,
                                            state->K_aut,
                                            SSH_EAP_AKA_KAUT_LEN)
        == false)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed"));
        goto fail;
    }

    ssh_eap_protocol_send_response(protocol, eap, packet);
    return;

fail:
    if (packet != NULL)
        ssh_buffer_free(packet);

    if (encrypted_payload != NULL)
        ssh_buffer_free(encrypted_payload);

    ssh_eap_fatal(eap, protocol, "EAP-AKA memory allocation failed.");
}

static void
ssh_eap_aka_send_notification_reply(SshEapProtocol protocol,
                                    SshEap eap,
                                    uint8_t include_mac)
{
    SshEapAkaState state     = NULL;
    SshBuffer      pkt       = NULL;
    uint8_t       buf[3]    = { SSH_EAP_NOTIFICATION, 0, 0 };
    uint16_t      pkt_len   = 0;

    SSH_ASSERT(protocol != NULL);
    SSH_ASSERT(eap != NULL);

    SSH_DEBUG(SSH_D_NICETOKNOW, ("Sending EAP-Response/AKA-Notification"));

    state = ssh_eap_protocol_get_state(protocol);

    pkt_len = (uint16_t) sizeof(buf);

    if (include_mac)
        pkt_len += SSH_EAP_AKA_AT_LEN_MIN + SSH_EAP_AKA_MAC_LEN;

    pkt = ssh_eap_create_reply(eap, pkt_len, protocol->impl->id);
    if (!pkt)
    {
        ssh_eap_fatal(eap, protocol, "Out of memory. Can not send reply.");
        return;
    }

    if (ssh_buffer_append(pkt, buf, sizeof(buf)) != SSH_BUFFER_OK)
    {
        ssh_buffer_free(pkt);

        ssh_eap_fatal(eap, protocol, "Out of memory. Can not send reply.");
        return;
    }

    if (include_mac)
    {
        if (ssh_eap_packet_append_mac_attribute(pkt,
                                                NULL,
                                                0,
                                                state->K_aut,
                                                SSH_EAP_AKA_KAUT_LEN)
            == false)
        {
            ssh_buffer_free(pkt);

            ssh_eap_fatal(eap, protocol, "EAP-AKA MAC calculation failed");
            return;
        }
    }

    ssh_eap_protocol_send_response(protocol, eap, pkt);
}

static void
ssh_eap_aka_client_recv_identity(SshEapProtocol protocol,
                                 SshEap eap,
                                 SshBuffer buf)
{
    SshEapAkaState state = NULL;
    uint8_t       rval  = 0;

    SSH_ASSERT(protocol != NULL);
    SSH_ASSERT(eap != NULL);
    SSH_ASSERT(buf != NULL);

    SSH_DEBUG(SSH_D_NICETOKNOW, ("Processing EAP-Request/Identity"));

    state = ssh_eap_protocol_get_state(protocol);

    if (state->aka_proto_flags & SSH_EAP_AKA_CHALLENGE_RCVD)
    {
        char *error_str =
            "EAP-Request/Identity received after AKA-Challenge completed";

        SSH_DEBUG(SSH_D_FAIL, (error_str));

        ssh_eap_discard_packet(eap, protocol, buf, error_str);

        ssh_eap_aka_client_error(protocol, eap,
                                 SSH_EAP_AKA_ERR_INVALID_STATE,
                                 error_str,
                                 NULL);
        return;
    }

    rval = ssh_eap_aka_decode_req_identity(protocol, buf);

    if (rval != SSH_EAP_AKA_DEC_OK)
    {
        char *error_str =
            "EAP-Request/Identity decoding failed";

        SSH_DEBUG(SSH_D_FAIL, ("%s: %u", error_str, rval));

        ssh_eap_discard_packet(eap, protocol, buf, error_str);

        ssh_eap_aka_client_error(protocol, eap, rval, error_str, NULL);
        return;
    }

    state->response_id = ssh_eap_packet_get_identifier(buf);

    if (((state->aka_proto_flags & SSH_EAP_AKA_ANYID_RCVD)  != 0) &&
        ((state->aka_proto_flags & SSH_EAP_AKA_FULLID_RCVD) == 0) &&
        ((state->aka_proto_flags & SSH_EAP_AKA_PERMID_RCVD) == 0))
    {
        SSH_DEBUG(SSH_D_NICETOKNOW, ("EAP-AKA requesting fast reauth token"));

        ssh_eap_protocol_request_token(eap, protocol->impl->id,
                                       SSH_EAP_TOKEN_AKA_FAST_REAUTH);
    }
    else if (((state->aka_proto_flags & SSH_EAP_AKA_FULLID_RCVD) != 0) &&
             ((state->aka_proto_flags & SSH_EAP_AKA_PERMID_RCVD) == 0))
    {
        SSH_DEBUG(SSH_D_NICETOKNOW, ("EAP-AKA requesting pseudonym token"));

        ssh_eap_protocol_request_token(eap, protocol->impl->id,
                                       SSH_EAP_TOKEN_AKA_PSEUDONYM);
    }
    else
    {
        SSH_ASSERT((state->aka_proto_flags & SSH_EAP_AKA_PERMID_RCVD) != 0);

        SSH_DEBUG(SSH_D_NICETOKNOW,
                  ("EAP-AKA requesting permanent identity token"));

        ssh_eap_protocol_request_token(eap, protocol->impl->id,
                                       SSH_EAP_TOKEN_USERNAME);
    }
}


static void
ssh_eap_aka_client_recv_challenge(SshEapProtocol protocol,
                                  SshEap eap,
                                  SshBuffer buf)
{
    SshEapAkaState   state    = NULL;
    uint8_t         rval     = 0;
    unsigned char    chal[SSH_EAP_AKA_CHALLENGE_LEN] = { 0 };
    unsigned char    packet_mac[SSH_EAP_AKA_MAC_LEN] = { 0 };

    SSH_DEBUG(SSH_D_NICETOKNOW,("Processing EAP-Request/AKA-Challenge"));

    SSH_ASSERT(protocol != NULL);
    SSH_ASSERT(eap != NULL);
    SSH_ASSERT(buf != NULL);

    state = ssh_eap_protocol_get_state(protocol);

    /* Freeradius 1.1.4 and below seem to be answering with new challenge
       message altough client-error message has been sent to it. This is
       totally against RFC 4187. */
    if (state->aka_proto_flags & SSH_EAP_AKA_CHALLENGE_RCVD)
    {
        char *error_str =
            "EAP-Request/AKA-Challenge received after AKA-Challenge completed";

        SSH_DEBUG(SSH_D_FAIL, (error_str));

        ssh_eap_discard_packet(eap, protocol, buf, error_str);

        ssh_eap_aka_client_error(protocol,
                                 eap,
                                 SSH_EAP_AKA_ERR_INVALID_STATE,
                                 error_str,
                                 NULL);
        return;
    }

    state->aka_proto_flags |= SSH_EAP_AKA_CHALLENGE_RCVD;

    /* Probably a retransmission of RAND challenge? Anyway
       discard it silently. Only done when we are actually
       processing the RAND's. If we receive this message when
       we are already setup, we'll send an error message... */
    if (state->aka_proto_flags & SSH_EAP_AKA_PROCESSING_RAND)
    {
        ssh_eap_discard_packet(eap, protocol, buf,
                               "EAP-AKA already waiting for PM's response"
                               " for RAND challenge.");
        return;
    }

    rval = ssh_eap_aka_decode_challenge(protocol,
                                        buf,
                                        state->aka_id.rand,
                                        state->aka_id.autn,
                                        packet_mac);

    if (rval != SSH_EAP_AKA_DEC_OK)
    {
        char *error_str =
            "EAP-Request/AKA-CHALLENGE decoding failed";

        SSH_DEBUG(SSH_D_FAIL, ("%s: %u", error_str, rval));

        ssh_eap_aka_client_error(protocol, eap, rval, error_str, NULL);
        ssh_eap_discard_packet(eap, protocol, buf, error_str);
        return;
    }

    if ((state->challenge_packet = ssh_buffer_allocate()) == NULL)
    {
        ssh_eap_discard_packet(eap,
                               protocol,
                               buf,
                               "EAP-AKA memory allocation failed");
        return;
    }

    if (ssh_buffer_append(state->challenge_packet, ssh_buffer_byte_ptr(buf),
                          ssh_buffer_len(buf)) != SSH_BUFFER_OK)
    {
        ssh_buffer_free(state->challenge_packet);
        state->challenge_packet = NULL;

        ssh_eap_discard_packet(eap,
                               protocol,
                               buf,
                               "EAP-AKA memory allocation failed");
        return;
    }

    /* Store mac and verify when key is calculated */
    memcpy(state->challenge_packet_mac, packet_mac, SSH_EAP_AKA_MAC_LEN);

    state->aka_proto_flags |= SSH_EAP_AKA_PROCESSING_RAND;

    /* If we have got the username from identity round,
       use it, otherwise first request for username and
       after that send token for challenge. */
    if (state->user != NULL)
    {
        memcpy(chal, state->aka_id.rand, SSH_EAP_AKA_RAND_LEN);
        memcpy(chal + SSH_EAP_AKA_RAND_LEN,
               state->aka_id.autn,
               SSH_EAP_AKA_AUTN_LEN);

        ssh_eap_protocol_request_token_with_args(eap, protocol->impl->id,
                                                 SSH_EAP_TOKEN_AKA_CHALLENGE,
                                                 chal, 32);
    }
    else
    {
        ssh_eap_protocol_request_token(eap, protocol->impl->id,
                                       SSH_EAP_TOKEN_USERNAME);
    }
}

static void
ssh_eap_aka_client_recv_reauth(SshEapProtocol protocol,
                               SshEap eap,
                               SshBuffer buf)
{
    SshEapAkaState state = NULL;
    SshCryptoStatus crypto_status;
    bool counter_too_small = false;
    unsigned char packet_mac[SSH_EAP_AKA_MAC_LEN] = { 0 };
    uint8_t rval;

    SSH_DEBUG(SSH_D_NICETOKNOW,
              ("Processing EAP-Request/AKA-Reauthentication"));

    SSH_ASSERT(protocol != NULL);
    SSH_ASSERT(eap != NULL);
    SSH_ASSERT(buf != NULL);

    state = ssh_eap_protocol_get_state(protocol);

    if ((state->aka_proto_flags & SSH_EAP_AKA_FAST_REAUTH_ID_SENT) == 0)
    {
        char *error_str =
            "EAP-AKA, unexpected reauthentication message received.";

        SSH_DEBUG(SSH_D_FAIL, (error_str));

        ssh_eap_discard_packet(eap, protocol, buf, error_str);

        ssh_eap_aka_client_error(protocol,
                                 eap,
                                 SSH_EAP_AKA_ERR_INVALID_STATE,
                                 error_str,
                                 NULL);
        return;
    }

    rval = ssh_eap_aka_decode_reauth(protocol, buf, packet_mac);

    if (rval != SSH_EAP_AKA_DEC_OK)
    {
        char *error_str =
            "EAP-AKA, reauthentication message decode failed.";

        SSH_DEBUG(SSH_D_FAIL, (error_str));

        ssh_eap_discard_packet(eap, protocol, buf, error_str);

        ssh_eap_aka_client_error(protocol, eap, rval, error_str, NULL);
        return;
    }


    crypto_status = ssh_eap_packet_verify_mac(buf,
                                              NULL,
                                              0,
                                              state->K_aut,
                                              SSH_EAP_AKA_KAUT_LEN,
                                              packet_mac,
                                              SSH_EAP_AKA_MAC_LEN);

    if (crypto_status != SSH_CRYPTO_OK)
    {
        char *error_str =
            "EAP-AKA, packet MAC verification failed.";

        SSH_DEBUG(SSH_D_FAIL,
                  ("%s Crypto status: %s.",
                   error_str,
                   ssh_crypto_status_message(crypto_status)));

        ssh_eap_discard_packet(eap, protocol, buf, error_str);

        ssh_eap_aka_client_error(protocol,
                                 eap,
                                 SSH_EAP_AKA_ERR_INVALID_IE,
                                 error_str,
                                 ssh_crypto_status_message(crypto_status));
        return;
    }

    if (ssh_eap_aka_encrypted_data_decode(state,
                                          state->encrypted_data,
                                          state->encrypted_data_len,
                                          state->K_encr,
                                          state->iv)
        != SSH_EAP_AKA_DEC_OK)
    {
        char *error_str =
            "EAP-AKA, reauthentication message decrypt failed.";

        SSH_DEBUG(SSH_D_FAIL, (error_str));

        ssh_eap_discard_packet(eap, protocol, buf, error_str);

        ssh_eap_aka_client_error(protocol,
                                 eap,
                                 SSH_EAP_AKA_ERR_PACKET_CORRUPTED,
                                 error_str,
                                 NULL);
        return;
    }

    ssh_free(state->encrypted_data);
    state->encrypted_data = NULL;
    state->encrypted_data_len = 0;

    if (state->authenticator_counter < state->reauth_counter)
    {
        counter_too_small = true;
        SSH_DEBUG(SSH_D_UNCOMMON,
                  ("EAP-AKA reauthentication received counter too small, "
                   "expected at least: %u, got: %u",
                   (unsigned int) state->reauth_counter,
                   (unsigned int) state->authenticator_counter));

        SSH_DEBUG(SSH_D_UNCOMMON,
                  ("EAP-AKA Fast Re-Authentication failed due to invalid "
                   "counter value. Informing authenticator and awaiting "
                   "fallback to full EAP-AKA authentication."));
    }
    else
    {
        /* Calculate new keys */
        if ((eap_aka_calculate_xkey(state) == false) ||
            (eap_aka_calculate_session_keys(state, false) == false))
        {
            char *error_str = "EAP-AKA, memory allocation failed.";

            SSH_DEBUG(SSH_D_FAIL, (error_str));

            ssh_eap_discard_packet(eap, protocol, buf, error_str);

            ssh_eap_aka_client_error(protocol,
                                     eap,
                                     SSH_EAP_AKA_ERR_PACKET_CORRUPTED,
                                     error_str,
                                     NULL);
            return;
        }
    }

    ssh_eap_aka_send_reauth_reply(protocol, eap, counter_too_small);

    if (counter_too_small == false)
    {
        SSH_ASSERT(SSH_EAP_AKA_MSK_LEN <= SSH_EAP_MSK_LEN_MAX);
        memcpy(eap->msk, state->msk, SSH_EAP_AKA_MSK_LEN);
        eap->msk_len = SSH_EAP_AKA_MSK_LEN;

        eap_aka_signal_next_auth_params(eap, state);
        ssh_eap_protocol_auth_ok(protocol, eap, SSH_EAP_SIGNAL_NONE, NULL);
    }
}


static void
ssh_eap_aka_client_recv_notification(SshEapProtocol protocol,
                                     SshEap eap,
                                     SshBuffer buf)
{
    SshEapAkaState state = NULL;
    unsigned char packet_mac[SSH_EAP_AKA_MAC_LEN] = { 0 };
    uint16_t ret = 0;
    uint8_t rval = 0;

    SSH_ASSERT(protocol != NULL);
    SSH_ASSERT(eap != NULL);
    SSH_ASSERT(buf != NULL);

    SSH_DEBUG(SSH_D_NICETOKNOW,
              ("Processing EAP-Request/AKA-Notification"));

    state = ssh_eap_protocol_get_state(protocol);

    rval = ssh_eap_aka_decode_notification(protocol, buf, &ret, packet_mac);

    if (rval != SSH_EAP_AKA_DEC_OK)
    {
        char *error_str = "EAP-AKA, decoding AKA-Notification failed";

        SSH_DEBUG(SSH_D_FAIL, (error_str));

        ssh_eap_aka_client_error(protocol, eap, rval, error_str, NULL);
        ssh_eap_discard_packet(eap, protocol, buf, error_str);
        return;
    }

    /* Do we have to verify the MAC? */
    if (!(ret & AT_NOTIFICATION_PHASE_BIT))
    {
        SshCryptoStatus crypto_status;

        crypto_status = ssh_eap_packet_verify_mac(buf,
                                                  NULL,
                                                  0,
                                                  state->K_aut,
                                                  SSH_EAP_AKA_KAUT_LEN,
                                                  packet_mac,
                                                  SSH_EAP_AKA_MAC_LEN);

        if (crypto_status != SSH_CRYPTO_OK)
        {
            char *error_str = "EAP-AKA MAC verification failed";

            SSH_DEBUG(SSH_D_FAIL, (error_str));

            ssh_eap_aka_client_error(protocol,
                                     eap,
                                     SSH_EAP_AKA_ERR_INVALID_IE,
                                     error_str,
                                     ssh_crypto_status_message(crypto_status));
            ssh_eap_discard_packet(eap, protocol, buf, error_str);
            return;
        }
    }

    if (ret & AT_NOTIFICATION_SUCCESS_BIT)
    {
        /* Success message. Discard and send error. Shouldn't be
           getting these since we did not approve protected successes. */
        char *error_str = "EAP-AKA AKA-Notification with Status bit received";

        SSH_DEBUG(SSH_D_FAIL, (error_str));

        ssh_eap_aka_client_error(protocol,
                                 eap,
                                 SSH_EAP_AKA_ERR_GENERAL,
                                 error_str,
                                 NULL);
        ssh_eap_discard_packet(eap, protocol, buf, error_str);
        return;
    }

    if ((ret & AT_NOTIFICATION_PHASE_BIT) &&
        state->aka_proto_flags & SSH_EAP_AKA_CHALLENGE_RCVD)
    {
        char *error_str =
            "EAP-AKA AKA-Notification with Phase bit received after "
            "AKA-Challenge exchange completed";

        SSH_DEBUG(SSH_D_FAIL, (error_str));

        ssh_eap_aka_client_error(protocol,
                                 eap,
                                 SSH_EAP_AKA_ERR_GENERAL,
                                 error_str,
                                 NULL);
        ssh_eap_discard_packet(eap, protocol, buf, error_str);
        return;
    }

    if (!(ret & AT_NOTIFICATION_PHASE_BIT) &&
        !(state->aka_proto_flags & SSH_EAP_AKA_CHALLENGE_RCVD))
    {
        char *error_str =
            "EAP-AKA AKA-Notification without Phase bit received";

        SSH_DEBUG(SSH_D_FAIL, (error_str));

        ssh_eap_aka_client_error(protocol,
                                 eap,
                                 SSH_EAP_AKA_ERR_GENERAL,
                                 error_str,
                                 NULL);
        ssh_eap_discard_packet(eap, protocol, buf, error_str);
        return;
    }

    ssh_eap_aka_send_notification_reply(protocol,
                                        eap,
                                        !(ret & AT_NOTIFICATION_PHASE_BIT));

    /* Inform the upper layer that something has gone bad here. */
    SSH_DEBUG(SSH_D_FAIL,
              ("EAP-AKA notification: authentication failed with code: %u",
               (unsigned int) ret));
    ssh_eap_aka_auth_fail(protocol, eap,
                          SSH_EAP_SIGNAL_AUTH_FAIL_NEGOTIATION, NULL, NULL);
}

static void
ssh_eap_aka_client_recv_msg(SshEapProtocol protocol,
                            SshEap eap,
                            SshBuffer buf)
{
    SshEapAkaState state   = NULL;
    uint16_t      msg_len = 0;
    uint8_t       msg_subtype;

    SSH_ASSERT(protocol != NULL);
    SSH_ASSERT(eap != NULL);
    SSH_ASSERT(buf != NULL);

    state = ssh_eap_protocol_get_state(protocol);

    if (state == NULL)
    {
        ssh_eap_discard_packet(eap, protocol, buf,
                               "EAP-AKA state uninitialized");
        return;
    }

    /* Here we handle only EAP-AKA specific messages. some notifications
       and Identity requests etc... are handled in ssheap_common. */
    if (ssh_buffer_len(buf) < 6)
    {
        ssh_eap_discard_packet(eap, protocol, buf,
                               "Packet too short to be EAP-AKA request");
        return;
    }

    msg_len = SSH_GET_16BIT(ssh_buffer_byte_ptr(buf) + 2);
    if (msg_len != ssh_buffer_len(buf))
    {
        ssh_eap_discard_packet(eap, protocol, buf,
                               "EAP-AKA msg length invalid");
        return;
    }

    msg_subtype = ssh_buffer_byte_ptr(buf)[5];
    switch (msg_subtype)
    {
    case SSH_EAP_AKA_IDENTITY:
        ssh_eap_aka_client_recv_identity(protocol, eap, buf);
        break;

    case SSH_EAP_AKA_CHALLENGE:
        ssh_eap_aka_client_recv_challenge(protocol, eap, buf);
        break;

    case SSH_EAP_REAUTHENTICATION:
        ssh_eap_aka_client_recv_reauth(protocol, eap, buf);
        break;

    case SSH_EAP_NOTIFICATION:
        ssh_eap_aka_client_recv_notification(protocol, eap, buf);
        break;

    default:
        {
            char error_buf[64] = { 0 };

            ssh_snprintf(error_buf, sizeof(error_buf),
                         "EAP-AKA, unknown message type %d", msg_subtype);

            ssh_eap_discard_packet(eap, protocol, buf, error_buf);

            ssh_eap_aka_client_error(protocol, eap,
                                     SSH_EAP_AKA_ERR_GENERAL, error_buf, NULL);
        }
        break;
    }
}

bool
ssh_eap_aka_calculate_keys(SshEapProtocol protocol,
                           SshEap eap)
{
    SshEapAkaState state = NULL;

    SSH_ASSERT(protocol != NULL);
    SSH_ASSERT(eap != NULL);

    state = ssh_eap_protocol_get_state(protocol);

    SSH_DEBUG(SSH_D_NICETOKNOW, ("EAP-AKA calculating keys"));

    if (eap_aka_calculate_master_key(state) == false)
    {
        SSH_DEBUG(SSH_D_FAIL, ("MK creation failed"));
        return false;
    }

    if (eap_aka_calculate_session_keys(state, true) == false)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Session key creation failed"));
        return false;
    }

    return true;
}

static void
ssh_eap_aka_auth_reject(SshEapProtocol protocol,
                        SshEap eap,
                        const char *cause_str)
{
    ssh_eap_aka_send_auth_reject_reply(protocol, eap);

    ssh_eap_aka_auth_fail(protocol, eap, SSH_EAP_SIGNAL_AUTH_FAIL_REPLY,
                          cause_str, NULL);
}

static void
ssh_eap_aka_recv_token_auth_reject(SshEapProtocol protocol,
                                   SshEap eap,
                                   SshEapToken token)
{
    ssh_eap_aka_auth_reject(protocol, eap,
                            "EAP-AKA, unacceptable AUTN parameter, sending "
                            "AKA-Authentication-Reject");
}

static void
ssh_eap_aka_recv_token_synch_required(SshEapProtocol protocol,
                                      SshEap eap,
                                      SshEapToken token)
{
    SshEapAkaState   state     = NULL;
    uint8_t        *auts_ptr  = NULL;

    SSH_ASSERT(protocol != NULL);
    SSH_ASSERT(token != NULL);
    SSH_ASSERT(eap != NULL);

    state = ssh_eap_protocol_get_state(protocol);

    SSH_DEBUG(SSH_D_NICETOKNOW, ("EAP-AKA received token auts"));

    if (!(state->aka_proto_flags & SSH_EAP_AKA_PROCESSING_RAND))
    {
        ssh_eap_discard_token(eap,
                              protocol,
                              token,
                              ("EAP-AKA, received sync req token although not "
                               "requested one"));
        return;
    }

    if (token->token.buffer.len != SSH_EAP_AKA_AUTS_LEN)
    {
        ssh_eap_discard_token(eap,
                              protocol,
                              token,
                              ("EAP-AKA, received invalid length AUTS token"));

        ssh_buffer_free(state->challenge_packet);
        state->challenge_packet = NULL;
        state->aka_proto_flags &= ~SSH_EAP_AKA_PROCESSING_RAND;
        return;

    }

    if (state->aka_proto_flags & SSH_EAP_AKA_SYNCH_REQ_SENT)
    {
        char *error_str =
            "EAP-AKA multiple synchronization requests triggered";

        ssh_eap_discard_token(eap, protocol, token, error_str);

        ssh_buffer_free(state->challenge_packet);
        state->challenge_packet = NULL;

        ssh_eap_aka_client_error(protocol,
                                 eap,
                                 SSH_EAP_AKA_ERR_GENERAL,
                                 error_str,
                                 NULL);
        return;
    }

    /* Copy the outputs from token. */
    auts_ptr = token->token.buffer.dptr;
    memcpy(state->aka_id.auts, auts_ptr, SSH_EAP_AKA_AUTS_LEN);

    ssh_buffer_free(state->challenge_packet);
    state->challenge_packet = NULL;

    state->aka_proto_flags &= ~SSH_EAP_AKA_PROCESSING_RAND;
    state->aka_proto_flags &= ~SSH_EAP_AKA_CHALLENGE_RCVD;
    state->aka_proto_flags |=  SSH_EAP_AKA_SYNCH_REQ_SENT;

    ssh_eap_aka_send_synch_fail_reply(protocol, eap);
}

static void
ssh_eap_aka_recv_token_challenge_response(SshEapProtocol protocol,
                                          SshEap eap,
                                          SshEapToken token)
{
    SshEapAkaState   state     = NULL;
    uint8_t        *chal_ptr  = NULL;
    uint32_t        res_byte_len;
    SshCryptoStatus  crypto_status;

    SSH_ASSERT(protocol != NULL);
    SSH_ASSERT(eap != NULL);
    SSH_ASSERT(token != NULL);

    state = ssh_eap_protocol_get_state(protocol);

    SSH_DEBUG(SSH_D_NICETOKNOW, ("EAP-AKA received token rand"));

    if (!(state->aka_proto_flags & SSH_EAP_AKA_PROCESSING_RAND))
    {
        ssh_eap_discard_token(eap, protocol, token,
                              "EAP-AKA, received challenge token although not"
                              " requested one");
        return;
    }

    if (token->token.buffer.len > ((2 * SSH_EAP_AKA_IK_LEN) + 17) ||
        token->token.buffer.len < ((2 * SSH_EAP_AKA_IK_LEN) + 5))
    {
        ssh_eap_discard_token(eap,
                              protocol,
                              token,
                              ("EAP-AKA, received invalid length token"));

        ssh_buffer_free(state->challenge_packet);
        state->challenge_packet = NULL;
        state->aka_proto_flags &= ~SSH_EAP_AKA_PROCESSING_RAND;
        return;

    }

    /* Copy the outputs from token. */
    chal_ptr = token->token.buffer.dptr;
    memcpy(state->aka_id.IK, chal_ptr, SSH_EAP_AKA_IK_LEN);

    chal_ptr += SSH_EAP_AKA_IK_LEN;
    memcpy(state->aka_id.CK, chal_ptr, SSH_EAP_AKA_CK_LEN);

    chal_ptr += SSH_EAP_AKA_CK_LEN;
    state->aka_id.res_len = SSH_GET_8BIT(chal_ptr);
    res_byte_len = (state->aka_id.res_len + 7) / 8;

    if (state->aka_id.res_len > 128 || state->aka_id.res_len < 32)
    {
        ssh_eap_discard_token(eap,
                              protocol,
                              token,
                              ("EAP-AKA, received invalid length challenge "
                               "token"));

        ssh_buffer_free(state->challenge_packet);
        state->challenge_packet = NULL;
        state->aka_proto_flags &= ~SSH_EAP_AKA_PROCESSING_RAND;
        return;

    }

    memset(state->aka_id.res, 0x0, sizeof(state->aka_id.res));
    memcpy(state->aka_id.res, &chal_ptr[1], res_byte_len);

    if (ssh_eap_aka_calculate_keys(protocol, eap) == false)
    {
        ssh_eap_discard_token(eap,
                              protocol,
                              token,
                              ("EAP-AKA, key generation failed, dropping "
                               "token"));
        ssh_buffer_free(state->challenge_packet);
        state->challenge_packet = NULL;

        state->aka_proto_flags &= ~SSH_EAP_AKA_PROCESSING_RAND;
        ssh_eap_aka_client_error(
                protocol, eap, SSH_EAP_AKA_ERR_GENERAL,
                "EAP-AKA, key material generation for session "
                "keys failed", NULL);
        return;
    }

    crypto_status = ssh_eap_packet_verify_mac(state->challenge_packet,
                                              NULL,
                                              0,
                                              state->K_aut,
                                              SSH_EAP_AKA_KAUT_LEN,
                                              state->challenge_packet_mac,
                                              SSH_EAP_AKA_MAC_LEN);

    ssh_buffer_free(state->challenge_packet);
    state->challenge_packet = NULL;

    if (crypto_status != SSH_CRYPTO_OK)
    {
        ssh_eap_discard_token(eap,
                              protocol,
                              token,
                              ("EAP-AKA message mac verification"
                               " failed, dropping token"));

        memset(state->K_encr, 0x00, SSH_EAP_AKA_KENCR_LEN);
        memset(state->K_aut,  0x00, SSH_EAP_AKA_KAUT_LEN);
        memset(state->msk,    0x00, SSH_EAP_AKA_MSK_LEN);
        memset(state->emsk,   0x00, SSH_EAP_AKA_EMSK_LEN);

        state->aka_proto_flags &= ~SSH_EAP_AKA_PROCESSING_RAND;
        ssh_eap_aka_client_error(protocol, eap, SSH_EAP_AKA_ERR_INVALID_IE,
                                 "EAP-AKA, MAC error",
                                 ssh_crypto_status_message(crypto_status));
        return;
    }

    (void) ssh_eap_aka_encrypted_data_decode(state,
                                             state->encrypted_data,
                                             state->encrypted_data_len,
                                             state->K_encr,
                                             state->iv);

    ssh_free(state->encrypted_data);
    state->encrypted_data = NULL;
    state->encrypted_data_len = 0;

    state->aka_proto_flags &= ~SSH_EAP_AKA_PROCESSING_RAND;

    SSH_ASSERT(SSH_EAP_AKA_MSK_LEN <= SSH_EAP_MSK_LEN_MAX);
    memcpy(eap->msk, state->msk, SSH_EAP_AKA_MSK_LEN);
    eap->msk_len = SSH_EAP_AKA_MSK_LEN;

    eap_aka_signal_next_auth_params(eap, state);

    ssh_eap_aka_send_challenge_reply(protocol, eap);
    ssh_eap_protocol_auth_ok(protocol, eap, SSH_EAP_SIGNAL_NONE, NULL);
}

static void
ssh_eap_aka_recv_token_username(SshEapProtocol protocol,
                                SshEap eap,
                                SshEapToken token)
{
    SshEapAkaState state = NULL;

    SSH_ASSERT(protocol != NULL);
    SSH_ASSERT(token != NULL);
    SSH_ASSERT(eap != NULL);

    state = ssh_eap_protocol_get_state(protocol);

    /* Wipe out the old stuff if required. */
    if (state->user != NULL)
    {
        ssh_free(state->user);
        state->user = NULL;
    }

    if (!token->token.buffer.dptr || token->token.buffer.len <= 0)
    {
        ssh_eap_discard_token(eap,
                              protocol,
                              token,
                              ("EAP-AKA did not receive valid username"));
        ssh_eap_aka_auth_fail(protocol,
                              eap,
                              SSH_EAP_SIGNAL_AUTH_FAIL_NEGOTIATION,
                              "EAP-AKA, mandatory user name missing",
                              NULL);
        return;
    }

    state->user = ssh_memdup(token->token.buffer.dptr,
                             token->token.buffer.len);

    if (state->user == NULL)
    {
        ssh_eap_discard_token(eap,
                              protocol,
                              token,
                              ("EAP-AKA buffer allocation failed"));
        return;
    }

    state->user_len = (uint8_t)token->token.buffer.len;

    /* If we have entered already for processing rand, the server
       obviously skipped the identity round and therefore we had
       to first ask for username and after that only we can
       proceed with processing the rand (so request
       token AKA_CHALLENGE). */
    if (state->aka_proto_flags & SSH_EAP_AKA_PROCESSING_RAND)
    {
        unsigned char chal[SSH_EAP_AKA_CHALLENGE_LEN] = { 0 };

        memcpy(chal, state->aka_id.rand, SSH_EAP_AKA_RAND_LEN);
        memcpy(chal + SSH_EAP_AKA_RAND_LEN,
               state->aka_id.autn,
               SSH_EAP_AKA_AUTN_LEN);

        ssh_eap_protocol_request_token_with_args(eap, protocol->impl->id,
                                                 SSH_EAP_TOKEN_AKA_CHALLENGE,
                                                 chal,
                                                 SSH_EAP_AKA_CHALLENGE_LEN);
    }
    else
    {
        ssh_eap_aka_send_identity_reply(protocol, eap);
    }
}

static void
ssh_eap_aka_recv_token_pseudonym(SshEapProtocol protocol,
                                 SshEap eap,
                                 SshEapToken token)
{
    SshEapAkaState state = NULL;

    SSH_ASSERT(protocol != NULL);
    SSH_ASSERT(token != NULL);
    SSH_ASSERT(eap != NULL);

    state = ssh_eap_protocol_get_state(protocol);

    if (!token->token.buffer.dptr || token->token.buffer.len <= 0)
    {
        SSH_DEBUG(SSH_D_NICETOKNOW,
                  ("EAP-AKA PSEUDONYM_ID unavailable, "
                   "requesting PERMANENT_ID"));

        ssh_eap_protocol_request_token(eap, protocol->impl->id,
                                       SSH_EAP_TOKEN_USERNAME);
        return;
    }

    /* Wipe out the old stuff if required. */
    if (state->user != NULL)
    {
        ssh_free(state->user);
        state->user = NULL;
    }

    state->user = ssh_memdup(token->token.buffer.dptr,
                             token->token.buffer.len);

    if (state->user == NULL)
    {
        ssh_eap_discard_token(eap,
                              protocol,
                              token,
                              ("EAP-AKA memory allocation failed"));
        return;
    }

    state->user_len = (uint8_t)token->token.buffer.len;
    ssh_eap_aka_send_identity_reply(protocol, eap);
}

static void
ssh_eap_aka_recv_token_fast_reauth(SshEapProtocol protocol,
                                   SshEap eap,
                                   SshEapToken token)
{
    SshEapAkaState state = NULL;
    uint16_t reauth_counter;
    unsigned char *reauth_id, *mk;
    size_t decoded_len, reauth_id_len, mk_len;
    char error_str[64] = { 0 };

    SSH_ASSERT(protocol != NULL);
    SSH_ASSERT(token != NULL);
    SSH_ASSERT(eap != NULL);

    state = ssh_eap_protocol_get_state(protocol);

    if (!token->token.buffer.dptr || token->token.buffer.len <= 0)
    {
        SSH_DEBUG(SSH_D_NICETOKNOW,
                  ("EAP-AKA REAUTH_ID unavailable, "
                   "requesting FULLAUTH_ID"));

        ssh_eap_protocol_request_token(eap, protocol->impl->id,
                                       SSH_EAP_TOKEN_AKA_PSEUDONYM);
        return;
    }

    /* Wipe out the old stuff if required. */
    if (state->user != NULL)
    {
        ssh_free(state->user);
        state->user = NULL;
    }

    decoded_len =
        ssh_decode_array(
                token->token.buffer.dptr,
                token->token.buffer.len,
                SSH_DECODE_UINT32_STR_NOCOPY(NULL, NULL),
                SSH_DECODE_UINT32_STR(&reauth_id, &reauth_id_len),
                SSH_DECODE_UINT32_STR_NOCOPY(&mk, &mk_len),
                SSH_DECODE_UINT16(&reauth_counter),
                SSH_FORMAT_END);

    if (decoded_len != token->token.buffer.len)
    {
        ssh_snprintf(error_str, sizeof(error_str),
                     "Fast Re-Authentication data decode failed");
        goto fail;
    }

    if (mk_len != SSH_EAP_AKA_MK_LEN)
    {
        ssh_snprintf(error_str, sizeof(error_str),
                     "Invalid MK length: %u", (unsigned int) mk_len);
        goto fail;
    }

    if (reauth_id == NULL)
    {
        ssh_snprintf(error_str, sizeof(error_str), "No reauth id found");
        goto fail;
    }

    if ((reauth_counter == 0) || (reauth_counter == 0xffff))
    {
        ssh_snprintf(error_str, sizeof(error_str),
                     "Invalid Fast Re-Authentication counter value: %u",
                     (unsigned int) reauth_counter);
        goto fail;
    }

    memcpy(state->mk, mk, mk_len);
    state->reauth_counter = reauth_counter;

    if (eap_aka_calculate_session_keys(state, true)
        == false)
    {
        ssh_snprintf(error_str, sizeof(error_str),
                     "EAP-AKA calculating session keys failed");
        goto fail;
    }

    SSH_DEBUG_HEXDUMP(
            SSH_D_NICETOKNOW,
            ("EAP-AKA Fast Re-Authentication id:"),
            reauth_id,
            reauth_id_len);

    SSH_DEBUG(
            SSH_D_DATADUMP,
            ("EAP-AKA Fast Re-Authentication counter value: %u",
             (unsigned int)reauth_counter));

    SSH_DEBUG_HEXDUMP(
            SSH_D_NICETOKNOW,
            ("EAP-AKA Fast Re-Authentication mk:"),
            state->mk,
            SSH_EAP_AKA_MK_LEN);

    state->user = reauth_id;
    state->user_len = (uint8_t)reauth_id_len;

    ssh_eap_aka_send_identity_reply(protocol, eap);

    state->aka_proto_flags |= SSH_EAP_AKA_FAST_REAUTH_ID_SENT;
    return;

fail:
    SSH_DEBUG(SSH_D_FAIL, (error_str));

    if (reauth_id != NULL)
        ssh_free(reauth_id);

    ssh_eap_discard_token(eap, protocol, token, error_str);
}

static void
ssh_eap_aka_recv_token(SshEapProtocol protocol,
                       SshEap eap,
                       SshEapToken token)
{
    uint8_t token_type = 0;

    SSH_ASSERT(protocol != NULL);
    SSH_ASSERT(eap != NULL);

    token_type = ssh_eap_get_token_type(token);

    SSH_DEBUG(SSH_D_NICETOKNOW,
              ("Received token of type: %s",
               ssh_eap_token_type_to_string(token_type)));

    switch (token_type)
    {
    case SSH_EAP_TOKEN_USERNAME:
        SSH_ASSERT(token != NULL);
        ssh_eap_aka_recv_token_username(protocol, eap, token);
        break;

    case SSH_EAP_TOKEN_AKA_PSEUDONYM:
        SSH_ASSERT(token != NULL);
        ssh_eap_aka_recv_token_pseudonym(protocol, eap, token);
        break;

    case SSH_EAP_TOKEN_AKA_FAST_REAUTH:
        SSH_ASSERT(token != NULL);
        ssh_eap_aka_recv_token_fast_reauth(protocol, eap, token);
        break;

    case SSH_EAP_TOKEN_AKA_CHALLENGE:
        SSH_ASSERT(token != NULL);
        ssh_eap_aka_recv_token_challenge_response(protocol, eap, token);
        break;

    case SSH_EAP_TOKEN_AKA_SYNCH_REQ:
        SSH_ASSERT(token != NULL);
        ssh_eap_aka_recv_token_synch_required(protocol, eap, token);
        break;

    case SSH_EAP_TOKEN_AKA_AUTH_REJECT:
        ssh_eap_aka_recv_token_auth_reject(protocol, eap, token);
        break;
    default:
        ssh_eap_discard_token(eap, protocol, token,
                              ("Unexpected token type"));
        return;
    }
}

void
ssh_eap_aka_recv_params(SshEapProtocol protocol,
                        SshEap eap,
                        SshEapAkaParams params)
{
    SshEapAkaState state;

    state = ssh_eap_protocol_get_state(protocol);

    state->transform = params->transform;
    SSH_ASSERT((state->transform & SSH_EAP_TRANSFORM_PRF_HMAC_SHA1) ||
               (state->transform & SSH_EAP_TRANSFORM_PRF_HMAC_SHA256));

    SSH_DEBUG(SSH_D_NICETOKNOW,
              ("Set transform for EAP-AKA to %x",
               state->transform));

    return;
}

void* ssh_eap_aka_create(SshEapProtocol protocol,
                         SshEap eap, uint8_t type)
{
    SshEapAkaState state;

    state = ssh_malloc(sizeof(*state));
    if (state == NULL)
        return NULL;

    memset(state, 0, sizeof(SshEapAkaStateStruct));

    state->reauth_counter = 0;

    SSH_DEBUG(SSH_D_NICETOKNOW, ("Created EAP-AKA auth state"));

    return state;
}

void
ssh_eap_aka_destroy(SshEapProtocol protocol,
                    uint8_t type, void *state)
{
    SshEapAkaState statex;

    statex = ssh_eap_protocol_get_state(protocol);

    if (statex)
    {
        if (statex->user)
            ssh_free(statex->user);

        if (statex->challenge_packet)
            ssh_buffer_free(statex->challenge_packet);

        if (statex->encrypted_data)
            ssh_free(statex->encrypted_data);

        if (statex->next_reauth_id)
            ssh_free(statex->next_reauth_id);

        if (statex->next_pseudonym)
            ssh_free(statex->next_pseudonym);

        ssh_free(protocol->state);
    }

    SSH_DEBUG(SSH_D_NICETOKNOW, ("EAP-AKA state destroyed"));
}

SshEapOpStatus
ssh_eap_aka_signal(SshEapProtocolSignalEnum sig,
                   SshEap eap,
                   SshEapProtocol protocol,
                   SshEapProtocolSignalData data)
{

    if (ssh_eap_isauthenticator(eap) == false)
    {
        switch (sig)
        {
        case SSH_EAP_PROTOCOL_RESET:
            SSH_ASSERT(data == NULL);
            SSH_DEBUG(SSH_D_NICETOKNOW, ("EAP-AKA signal protocol reset"));
            break;

        case SSH_EAP_PROTOCOL_BEGIN:
            SSH_ASSERT(data == NULL);
            SSH_DEBUG(SSH_D_NICETOKNOW, ("EAP-AKA signal protocol begin"));
            break;

        case SSH_EAP_PROTOCOL_RECV_MSG:
            SSH_ASSERT(data != NULL);
            ssh_eap_aka_client_recv_msg(protocol, eap, data->u.message);
            break;

        case SSH_EAP_PROTOCOL_RECV_TOKEN:
            ssh_eap_aka_recv_token(protocol, eap, data->u.token);
            break;

        case SSH_EAP_PROTOCOL_RECV_PARAMS:
            SSH_ASSERT(data != NULL);
            SSH_DEBUG(SSH_D_NICETOKNOW, ("EAP-AKA receive params"));
            ssh_eap_aka_recv_params(protocol,
                                    eap,
                                    data->u.config->u.aka_params);
            break;

        default:
            SSH_NOTREACHED;
        }
    }
    else
    {
        SSH_DEBUG(SSH_D_FAIL, ("EAP-AKA not supported for authenticator"));
    }

    return SSH_EAP_OPSTATUS_SUCCESS;
}

SshEapOpStatus
ssh_eap_aka_key(SshEapProtocol protocol,
                SshEap eap, uint8_t type)
{
    SSH_ASSERT(protocol != NULL);
    SSH_ASSERT(eap != NULL);
    SSH_ASSERT(eap->is_authenticator == true);

    if (eap->mppe_send_keylen < 32 || eap->mppe_recv_keylen < 32)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Keys too short %d %d",
                               eap->mppe_send_keylen,
                               eap->mppe_recv_keylen));
        return SSH_EAP_OPSTATUS_FAILURE;
    }

    SSH_ASSERT(SSH_EAP_MSK_LEN_MAX >= 64);

    eap->msk_len = 64;

    memcpy(eap->msk, eap->mppe_recv_key, 32);
    memcpy(eap->msk + 32, eap->mppe_send_key, 32);

    SSH_DEBUG_HEXDUMP(SSH_D_MIDOK, ("64 byte EAP-AKA MSK"),
                      eap->msk, eap->msk_len);

    return SSH_EAP_OPSTATUS_SUCCESS;
}

#else  /* SSHDIST_EAP_AKA */

void *
ssh_eap_aka_create(SshEapProtocol protocol,
                   SshEap eap, uint8_t type)
{
    return NULL;
}

void
ssh_eap_aka_destroy(SshEapProtocol protocol,
                    uint8_t type, void *state)
{
}

SshEapOpStatus
ssh_eap_aka_signal(SshEapProtocolSignalEnum sig,
                   SshEap eap,
                   SshEapProtocol protocol,
                   SshEapProtocolSignalData data)
{
    return SSH_EAP_OPSTATUS_UNKNOWN_PROTOCOL;
}

SshEapOpStatus
ssh_eap_aka_key(SshEapProtocol protocol,
                SshEap eap, uint8_t type)
{
    return SSH_EAP_OPSTATUS_UNKNOWN_PROTOCOL;
}
#endif /* SSHDIST_EAP_AKA */
