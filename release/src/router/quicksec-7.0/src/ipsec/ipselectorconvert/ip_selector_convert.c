/**
   @copyright
   Copyright (c) 2015, INSIDE Secure Oy. All rights reserved.
*/


#include "ip_selector_convert.h"
#include "ip_selector_encode.h"
#include "ip_selector_parse.h"
#include "ip_selector_match.h"
#include "in_addr.h"

#define SSH_DEBUG_MODULE "ipselectorconvert"
#define __DEBUG_MODULE__ ipselectorconvert

#include "sshincludes.h"
#include "sshadt_list.h"
#include "sshinet.h"
#include "sshikev2-payloads.h"
#include "sshikev2-initiator.h"
#include "sshikev2-util.h"

#include "implementation_defs.h"

static int
ip_selector_convert_addresses_from_ssh(
        SshIpAddr start_address,
        SshIpAddr end_address,
        unsigned char *selector_address_begin,
        unsigned char *selector_address_end)
{
    int ip_version;

    if (SSH_IP_IS4(start_address))
    {
        memset(selector_address_begin, 0, 12);
        SSH_IP4_ENCODE(start_address, &selector_address_begin[12]);

        memset(selector_address_end, 0, 12);
        SSH_IP4_ENCODE(end_address, &selector_address_end[12]);

        ip_version = 4;
    }
    else
    {
        SSH_IP6_ENCODE(start_address, selector_address_begin);
        SSH_IP6_ENCODE(end_address, selector_address_end);

        ip_version = 6;
    }

    return ip_version;
}

static void
ip_selector_convert_encode_source_endpoint_from_ikev2(
        struct IPSelectorEncode *encoder,
        SshIkev2PayloadTSItem ike_tsi)
{
    int ip_version;
    unsigned char address_begin[16];
    unsigned char address_end[16];

    ip_version =
        ip_selector_convert_addresses_from_ssh(
                ike_tsi->start_address,
                ike_tsi->end_address,
                address_begin,
                address_end);

    ip_selector_encode_add_source_endpoint(
            encoder,
            address_begin,
            address_end,
            ike_tsi->start_port,
            ike_tsi->end_port,
            ip_version,
            ike_tsi->proto);
}

static void
ip_selector_convert_encode_destination_endpoint_from_ikev2(
        struct IPSelectorEncode *encoder,
        SshIkev2PayloadTSItem ike_tsi)
{
    int ip_version;
    unsigned char address_begin[16];
    unsigned char address_end[16];

    ip_version =
        ip_selector_convert_addresses_from_ssh(
                ike_tsi->start_address,
                ike_tsi->end_address,
                address_begin,
                address_end);

    ip_selector_encode_add_destination_endpoint(
            encoder,
            address_begin,
            address_end,
            ike_tsi->start_port,
            ike_tsi->end_port,
            ip_version,
            ike_tsi->proto);
}


int
ip_selector_convert_group_bytecount_ikev2ts(
        const struct SshIkev2PayloadTSRec *ike_local_ts,
        const struct SshIkev2PayloadTSRec *ike_remote_ts)
{
    int endpoint_count;
    int selector_group_bytecount;

    endpoint_count =
        ike_local_ts->number_of_items_used +
        ike_remote_ts->number_of_items_used;

    selector_group_bytecount =
        ip_selector_encode_selector_group_bytecount(
                1,
                endpoint_count,
                0,
                0);

    return selector_group_bytecount;
}


void
ip_selector_convert_from_ikev2ts(
        struct IPSelectorGroup *selector_group,
        int selector_group_bytecount,
        const struct SshIkev2PayloadTSRec *ike_local_ts,
        const struct SshIkev2PayloadTSRec *ike_remote_ts)
{
    struct IPSelectorEncode encoder_st;
    SshIkev2PayloadTSItem ike_tsi;
    int i;

    ip_selector_encode_init(
            &encoder_st,
            selector_group,
            selector_group_bytecount);

    ip_selector_encode_add_selector(&encoder_st, 0, 0);

    for (i = 0; i < ike_local_ts->number_of_items_used; i++)
    {
        ike_tsi = &ike_local_ts->items[i];

        ip_selector_convert_encode_source_endpoint_from_ikev2(
                &encoder_st,
                ike_tsi);
    }

    for (i = 0; i < ike_remote_ts->number_of_items_used; i++)
    {
        ike_tsi = &ike_remote_ts->items[i];

        ip_selector_convert_encode_destination_endpoint_from_ikev2(
                &encoder_st,
                ike_tsi);
    }
}

void
ip_selector_convert_address_to_ikev2(
        const struct InAddr *address,
        SshIpAddr address_ssh)
{
    unsigned char address_buf[16];
    int byte_count;

    byte_count = in_addr_byte_count(address);
    in_addr_export(address, address_buf, byte_count);
    SSH_IP_DECODE(address_ssh, address_buf, byte_count);
}

static bool
ip_selector_convert_add_endpoints_to_ikev2(
        struct IPSelectorParse *parser,
        int selector_field,
        SshIkev2PayloadTS ike_ts)
{
    struct InAddr begin_address;
    struct InAddr end_address;
    int ip_protocol;
    int begin_port;
    int end_port;

    while (ip_selector_parse_next_endpoint(
                   parser,
                   selector_field,
                   &begin_address,
                   &end_address,
                   &ip_protocol,
                   &begin_port,
                   &end_port)
           == true)
    {
        SshIpAddrStruct begin_address_ssh;
        SshIpAddrStruct end_address_ssh;

        ip_selector_convert_address_to_ikev2(
                &begin_address,
                &begin_address_ssh);

        ip_selector_convert_address_to_ikev2(
                &end_address,
                &end_address_ssh);

        if (ssh_ikev2_ts_item_add(
                    ike_ts,
                    ip_protocol,
                    &begin_address_ssh,
                    &end_address_ssh,
                    begin_port,
                    end_port)
            != SSH_IKEV2_ERROR_OK)
        {
            return false;
        }
    }

    return true;
}


bool
ip_selector_convert_is_convertible(
        const struct IPSelectorGroup *ip_selector_group)
{
    const struct IPSelector *ip_selector;
    bool ok = true;

    if (ip_selector_group->selector_count != 1)
    {
        DEBUG_LOW(
                convert,
                "Cannot convert multiple IPSelectors to Ikev2 TS.");

        ok = false;
    }

    ip_selector = (const struct IPSelector *) (ip_selector_group + 1);

    if (ok == true)
    {
        int unsupported_selector_type_count =
            ip_selector->source_address_count +
            ip_selector->destination_address_count +
            ip_selector->source_port_count +
            ip_selector->destination_port_count;


        if (unsupported_selector_type_count != 0)
        {
            DEBUG_LOW(
                    convert,
                    "Cannot convert IPSelectors with "
                    "other than endpoints to Ikev2 TS.");

            ok = false;
        }
    }

    return ok;
}


bool
ip_selector_convert_to_ikev2ts(
        struct SshSADHandleRec *sad_handle,
        struct SshIkev2PayloadTSRec **ike_local_ts_p,
        struct SshIkev2PayloadTSRec **ike_remote_ts_p,
        const struct IPSelectorGroup *ip_selector_group)
{
    SshIkev2PayloadTS ts_local = NULL;
    SshIkev2PayloadTS ts_remote = NULL;
    bool ok = true;

    ASSERT(
            ip_selector_match_validate_selector_group(
                    ip_selector_group,
                    ip_selector_group->bytecount) == 0);

    ASSERT(
            ip_selector_convert_is_convertible(
                    ip_selector_group));

    *ike_local_ts_p = NULL;
    *ike_remote_ts_p = NULL;

    if (ok == true)
    {
        ts_local = ssh_ikev2_ts_allocate(sad_handle);
        ts_remote = ssh_ikev2_ts_allocate(sad_handle);

        if (ts_local == NULL || ts_remote == NULL)
        {
            DEBUG_FAIL(alloc, "IKEv2 TS allocation failed.");

            ok = false;
        }
    }

    if (ok == true)
    {
        struct IPSelectorParse parser;
        int ip_version;
        int ip_protocol;

        ip_selector_parse_init(&parser, ip_selector_group);

        ok =
            ip_selector_parse_next_selector(
                    &parser,
                    &ip_version,
                    &ip_protocol);

        if (ok == true)
        {
            ok =
                ip_selector_convert_add_endpoints_to_ikev2(
                        &parser,
                        IP_SELECTOR_SOURCE_ENDPOINT,
                        ts_local);
        }

        if (ok == true)
        {
            ok =
                ip_selector_convert_add_endpoints_to_ikev2(
                        &parser,
                        IP_SELECTOR_DESTINATION_ENDPOINT,
                        ts_remote);
        }
    }

    if (ok == true)
    {
        *ike_local_ts_p = ts_local;
        *ike_remote_ts_p = ts_remote;
    }
    else
    {
        if (ts_local != NULL)
        {
            ssh_ikev2_ts_free(sad_handle, ts_local);
        }

        if (ts_remote != NULL)
        {
            ssh_ikev2_ts_free(sad_handle, ts_remote);
        }
    }

    return ok;
}
