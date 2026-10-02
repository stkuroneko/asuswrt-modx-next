/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshbuffer.h"
#include "sshcrypt.h"

#include "ssheap.h"
#include "ssheapi.h"

#include "ssheap_packet.h"
#include "ssheap_md5.h"

#define SSH_DEBUG_MODULE "SshEapMd5"

static void
ssh_eap_md5_reset(SshEapProtocol protocol, SshEap eap)
{
    SshEapMd5State state;

    state = ssh_eap_protocol_get_state(protocol);

    if (state == NULL)
      return;

    if (state->response_buffer != NULL)
    {
        ssh_free(state->response_buffer);
        state->response_buffer = NULL;
        state->response_length = 0;
    }

    if (state->challenge_buffer != NULL)
    {
        ssh_free(state->challenge_buffer);
        state->challenge_buffer = NULL;
        state->challenge_length = 0;
    }

    SSH_DEBUG(SSH_D_MIDOK,("eap md5 state reset"));
}

static void
ssh_eap_md5_server_begin(SshEapProtocol protocol, SshEap eap)
{
    unsigned long name_len;
    SshEapMd5State state;
    SshEapMd5Params params;
    uint8_t rndbyte;
    SshBuffer pkt;
    int i;

    state = ssh_eap_protocol_get_state(protocol);
    params = ssh_eap_protocol_get_params(protocol);

    if (state == NULL)
    {
        SSH_DEBUG(SSH_D_ERROR,
                  ("eap md5 state not initialized. "
                   "can not begin authentication"));
        return;
    }

    /* Parse parameters for defaults and free any "old" state */

    if (params == NULL)
    {
        /* Do not leak too much information regarding the state of the PRNG,
           but make a sufficiently difficult (256 bits) challenge. */
        state->challenge_length = 32;
        name_len = 0;
    }
    else
    {
        state->challenge_length = params->challenge_length;
        name_len = params->name_length;
    }

    if (state->challenge_length > 255)
      state->challenge_length = 255;

    SSH_ASSERT(state->challenge_length > 0);

    if (state->challenge_buffer != NULL)
    {
        ssh_free(state->challenge_buffer);
        state->challenge_buffer = NULL;
    }

    /* Build packet */

    pkt = ssh_eap_create_request(eap,
                                 (uint16_t)(1 + state->challenge_length
                                             + name_len),
                                 protocol->impl->id);

    if (pkt == NULL)
    {
        ssh_eap_fatal(eap, protocol,
                      "Out of memory. Could not create request");
        return;
    }

    SSH_ASSERT(state->challenge_length < 256);

    rndbyte = (uint8_t)state->challenge_length;

    if (ssh_buffer_append(pkt, &rndbyte, 1) != SSH_BUFFER_OK)
    {
        ssh_buffer_free(pkt);
        ssh_eap_fatal(eap, protocol,
                      "Out of memory. Could not create request");
        return;
    }

    state->challenge_buffer = ssh_malloc(state->challenge_length);

    if (state->challenge_buffer == NULL)
    {
        ssh_buffer_free(pkt);
        ssh_eap_fatal(eap, protocol,
                      "Out of memory. Could not create challenge");
        return;
    }


    for (i = 0; i < state->challenge_length; i++)
    {
        rndbyte = (uint8_t)ssh_random_get_byte();
        state->challenge_buffer[i] = rndbyte;
        if (ssh_buffer_append(pkt, &rndbyte, 1) != SSH_BUFFER_OK)
        {
            ssh_buffer_free(pkt);
            ssh_free(state->challenge_buffer);
            state->challenge_buffer = NULL;
            ssh_eap_fatal(eap, protocol,
                          "Out of memory. Could not create request");
            return;
        }
    }

    if (name_len > 0)
    {
        SSH_ASSERT(params != NULL && params->name_buffer != NULL);

        if (ssh_buffer_append(pkt, params->name_buffer, name_len))
        {
            ssh_buffer_free(pkt);
            ssh_free(state->challenge_buffer);
            state->challenge_buffer = NULL;
            ssh_eap_fatal(eap, protocol,
                          "Out of memory. Could not create request");
            return;
        }
    }

    state->response_id = ssh_eap_packet_get_identifier(pkt);

    SSH_DEBUG(SSH_D_MIDOK,("sending eap md5 authentication request"));
    ssh_eap_protocol_send_request(protocol, eap, pkt);
}

static void
ssh_eap_md5_server_recv_msg(SshEapProtocol protocol,
                            SshEap eap,
                            SshBuffer buf)
{
    SshEapMd5State state;
    unsigned char *ucp = NULL;

    state = ssh_eap_protocol_get_state(protocol);

    if (state == NULL)
    {
        ssh_eap_discard_packet(eap, protocol, buf,
                               "eap md5 auth state not initialized");
        return;
    }
    ucp = ssh_buffer_ptr(buf);

    if (ucp == NULL || (ssh_buffer_len(buf) < 6))
    {
        ssh_eap_discard_packet(eap, protocol, buf,
                               "packet too short to be eap md5 response");
        return;
    }

    state->response_length = ucp[5] & 0xFF;

    if (state->response_length < 1
        || (state->response_length + 6) > ssh_buffer_len(buf))
    {
        ssh_eap_discard_packet(eap, protocol, buf,
                               "invalid response value length");
        return;
    }

    SSH_ASSERT(state->response_buffer == NULL);

    state->response_buffer = ssh_malloc(state->response_length);

    if (state->response_buffer == NULL)
    {
        ssh_eap_fatal(eap, protocol,
                      "Could not cache challenge response. Out of memory");
        return;
    }

    memcpy(state->response_buffer, ucp + 6, state->response_length);

    ssh_eap_protocol_request_token(eap, protocol->impl->id,
                                   SSH_EAP_TOKEN_SHARED_SECRET);
}

static void
ssh_eap_md5_server_recv_token(SshEapProtocol protocol,
                              SshEap eap,
                              SshEapToken token)
{
    SshEapMd5State state;
    bool ok;
    SshHash hash = NULL;
    uint8_t *secret_ptr;
    unsigned long secret_len;

    SSH_ASSERT(token != NULL);

    if (ssh_eap_get_token_type(token) != SSH_EAP_TOKEN_SHARED_SECRET)
    {
        ssh_eap_discard_token(eap, protocol, token, "incorrect token type");
        return;
    }

    secret_ptr = ssh_eap_get_token_secret_ptr(token);
    secret_len = ssh_eap_get_token_secret_len(token);

    SSH_ASSERT(secret_ptr != NULL || secret_len == 0);

    ok = false;

    state = ssh_eap_protocol_get_state(protocol);

    if (state == NULL)
    {
        SSH_DEBUG(SSH_D_FAIL,("EAP-MD5 state uninitialized"));
        goto fail_auth;
    }

    if (state->response_buffer == NULL
        || state->challenge_buffer == NULL)
    {
        SSH_DEBUG(SSH_D_FAIL,("EAP-MD5 state lacks challenge or response"));
        goto fail_auth;
    }

    {
        SshCryptoStatus status;

        status = ssh_hash_allocate("md5",&hash);

        if (status != SSH_CRYPTO_OK)
        {
            SSH_DEBUG(SSH_D_FAIL,("failed to initialize MD5 function"));
            goto fail_auth;
        }
        status = ssh_hash_compare_start(hash, state->response_buffer,
                                        state->response_length);
        if (status != SSH_CRYPTO_OK)
        {
            SSH_DEBUG(SSH_D_NETGARB,
                      ("Challenge response compare start failed"));
            goto fail_auth;
        }

        ssh_hash_update(hash, &state->response_id, 1);
        ssh_hash_update(hash, secret_ptr, secret_len);
        ssh_hash_update(
                hash, state->challenge_buffer, state->challenge_length);

        status = ssh_hash_compare_result(hash);
        if (status == SSH_CRYPTO_OK)
          ok = true;
    }

   fail_auth:

    /* Reset module. Authentication has succeeded */
    ssh_eap_md5_reset(protocol, eap);

    if (hash)
      ssh_hash_free(hash);

    if (ok == true)
    {
        ssh_eap_protocol_auth_ok(protocol, eap,
                                 SSH_EAP_SIGNAL_NONE, NULL);
    }
    else
    {
        ssh_eap_protocol_auth_fail(protocol, eap,
                                   SSH_EAP_SIGNAL_AUTH_FAIL_REPLY, NULL);
    }
}

void*
ssh_eap_md5_create(SshEapProtocol protocol, SshEap eap, uint8_t type)
{
    SshEapMd5State state;

    state = ssh_malloc(sizeof(*state));

    if (state == NULL)
      return NULL;

    state->response_buffer = NULL;
    state->response_length = 0;

    state->challenge_buffer = NULL;
    state->challenge_length = 0;

    SSH_DEBUG(SSH_D_LOWOK,("created eap md5 auth state"));

    return state;
}

void
ssh_eap_md5_destroy(SshEapProtocol protocol, uint8_t type, void *ctx)
{
    SshEapMd5State state;

    state = (SshEapMd5State)ctx;

    if (state != NULL)
    {
        if (state->response_buffer != NULL)
        {
            ssh_free(state->response_buffer);
        }

        if (state->challenge_buffer != NULL)
        {
            ssh_free(state->challenge_buffer);
        }

        ssh_free(state);
    }
}

static void
ssh_eap_md5_client_recv_msg(SshEapProtocol protocol,
                            SshEap eap,
                            SshBuffer buf)
{
    SshEapMd5State state;
    unsigned char *ucp = NULL;

    state = ssh_eap_protocol_get_state(protocol);

    if (state == NULL)
    {
        ssh_eap_discard_packet(eap, protocol, buf,
                               "EAP MD5 state uninitialized");
        return;
    }

    if (state->challenge_buffer != NULL)
    {
        ssh_free(state->challenge_buffer);
        state->challenge_buffer =  NULL;
    }

    ucp = ssh_buffer_ptr(buf);

    if (ucp == NULL || (ssh_buffer_len(buf) < 6))
    {
        ssh_eap_discard_packet(eap, protocol, buf,
                               "packet length incorrect for EAP MD5 packet");
        return;
    }

    state->challenge_length = ucp[5];

    /* Note that RFC 1994 requires the challenge to be at least one octet */

    if (state->challenge_length == 0
        || (state->challenge_length + 6) > ssh_buffer_len(buf))
    {
        ssh_eap_discard_packet(eap, protocol, buf,
                               "EAP MD5 incorrect challenge length");
        return;
    }

    state->challenge_buffer = ssh_malloc(state->challenge_length);

    if (state->challenge_buffer == NULL)
    {
        ssh_eap_fatal(eap, protocol,
                      "Could not allocate buffer for challenge");
        return;
    }

    memcpy(state->challenge_buffer, ucp + 6, state->challenge_length);

    state->response_id = ssh_eap_packet_get_identifier(buf);

    ssh_eap_protocol_request_token(eap, protocol->impl->id,
                                   SSH_EAP_TOKEN_SHARED_SECRET);
}

static void
ssh_eap_md5_client_recv_token(SshEapProtocol protocol,
                              SshEap eap,
                              SshEapToken token)
{
    SshEapMd5State state;
    SshEapMd5Params params;
    SshBuffer pkt = NULL;
    uint8_t b;
    SshHash hash = NULL;
    SshCryptoStatus status;
    unsigned long len;
    unsigned long name_len;
    unsigned long secret_len;
    uint8_t *secret_ptr;
    uint8_t hashbuf[32];

    SSH_ASSERT(token != NULL);

    if (ssh_eap_get_token_type(token) != SSH_EAP_TOKEN_SHARED_SECRET)
    {
        ssh_eap_discard_token(eap, protocol, token, ("unexpected token type"));
        return;
    }

    secret_ptr = ssh_eap_get_token_secret_ptr(token);
    secret_len = ssh_eap_get_token_secret_len(token);

    SSH_ASSERT(secret_ptr != NULL || secret_len == 0);

    state = ssh_eap_protocol_get_state(protocol);
    params = ssh_eap_protocol_get_params(protocol);

    name_len = 0;

    if (params != NULL && params->name_buffer != NULL)
      name_len = params->name_length;

    if (state->challenge_buffer == NULL)
    {
        ssh_eap_discard_token(eap, protocol, token,
                              "EAP MD5 state lacks authenticator challenge");
        goto fail_auth;
    }

    status = ssh_hash_allocate("md5", &hash);
    if (status != SSH_CRYPTO_OK)
    {
        ssh_eap_discard_token(eap, protocol, token,
                              "failed to initialize MD5 function");
        goto fail_auth;
    }

    len = ssh_hash_digest_length(ssh_hash_name(hash));

    if (len > 32)
    {
        ssh_eap_fatal(eap, protocol,
                      "MD5 output of unexpected size");
        goto fail_auth;
    }

    pkt = ssh_eap_create_reply(eap,
                               (uint16_t)(1 + len + name_len),
                               protocol->impl->id);

    if (pkt == NULL)
    {
        ssh_eap_fatal(eap, protocol,
                      "Out of memory. Could not allocate reply packet.");
        goto fail_auth;
    }

    b = (uint8_t)(len & 0xFF);

    if (ssh_buffer_append(pkt,&b,1) != SSH_BUFFER_OK)
    {
        ssh_eap_fatal(eap, protocol,
                      "Out of memory. Could not build reply packet.");
        goto fail_auth;
    }

    ssh_hash_reset(hash);
    ssh_hash_update(hash, &state->response_id, 1);
    ssh_hash_update(hash, secret_ptr, secret_len);
    ssh_hash_update(hash, state->challenge_buffer, state->challenge_length);
    ssh_hash_final(hash, hashbuf);

    if (ssh_buffer_append(pkt, hashbuf, len) != SSH_BUFFER_OK)
    {
        ssh_eap_fatal(eap, protocol,
                      "Out of memory. Could not build reply packet.");
        goto fail_auth;
    }

    if (name_len > 0)
    {
        if (ssh_buffer_append(pkt, params->name_buffer, name_len)
            != SSH_BUFFER_OK)
        {
            ssh_eap_fatal(eap, protocol,
                          "Out of memory. Could not build reply packet.");
            goto fail_auth;
        }
    }

    ssh_eap_protocol_send_response(protocol, eap, pkt);
    pkt = NULL;

    ssh_eap_protocol_auth_ok(protocol, eap, SSH_EAP_SIGNAL_NONE, NULL);

   fail_auth:
    if (pkt != NULL)
      ssh_buffer_free(pkt);
    if (hash != NULL)
      ssh_hash_free(hash);

    ssh_eap_md5_reset(protocol,eap);
}

SshEapOpStatus
ssh_eap_md5_signal(SshEapProtocolSignalEnum sig,
                   SshEap eap,
                   SshEapProtocol protocol,
                   SshEapProtocolSignalData data)
{
    if (ssh_eap_isauthenticator(eap) == true)
    {
        switch (sig)
        {
          case SSH_EAP_PROTOCOL_RESET:
            SSH_ASSERT(data == NULL);
            ssh_eap_md5_reset(protocol, eap);
            break;

          case SSH_EAP_PROTOCOL_BEGIN:
            SSH_ASSERT(data == NULL);
            ssh_eap_md5_server_begin(protocol, eap);
            break;

          case SSH_EAP_PROTOCOL_RECV_MSG:
            SSH_ASSERT(data != NULL);
            ssh_eap_md5_server_recv_msg(protocol, eap, data->u.message);
            break;

          case SSH_EAP_PROTOCOL_RECV_TOKEN:
            SSH_ASSERT(data != NULL);
            ssh_eap_md5_server_recv_token(protocol, eap, data->u.token);
            break;

          default:
            SSH_NOTREACHED;
        }
    }
    else
    {
        switch (sig)
        {
          case SSH_EAP_PROTOCOL_RESET:
            SSH_ASSERT(data == NULL);
            ssh_eap_md5_reset(protocol,eap);
            break;

          case SSH_EAP_PROTOCOL_BEGIN:
            SSH_ASSERT(data == NULL);
            break;

          case SSH_EAP_PROTOCOL_RECV_MSG:
            SSH_ASSERT(data != NULL);
            ssh_eap_md5_client_recv_msg(protocol, eap, data->u.message);
            break;

          case SSH_EAP_PROTOCOL_RECV_TOKEN:
            ssh_eap_md5_client_recv_token(protocol, eap, data->u.token);
            break;

          default:
            SSH_NOTREACHED;
        }
    }
    return SSH_EAP_OPSTATUS_SUCCESS;
}
