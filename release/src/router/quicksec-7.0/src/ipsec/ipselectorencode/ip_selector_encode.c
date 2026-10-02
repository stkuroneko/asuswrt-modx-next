/**
   @copyright
   Copyright (c) 2015, INSIDE Secure Oy. All rights reserved.
*/

#include "ip_selector_encode.h"
#include "implementation_defs.h"

#define __DEBUG_MODULE__ ipselector

int
ip_selector_encode_selector_group_bytecount(
        int selector_count,
        int endpoint_count,
        int port_count,
        int address_count)
{
    int size = 0;

    size += sizeof (struct IPSelectorGroup);
    size += selector_count * sizeof (struct IPSelector);
    size += endpoint_count * sizeof (struct IPSelectorEndpoint);
    size += port_count * sizeof (struct IPSelectorPort);
    size += address_count * sizeof (struct IPSelectorAddress);

    return size;
}


static void *
ip_selector_encode_add_stuff(
        struct IPSelectorEncode *encoder,
        int size)
{
    void *p;

    ASSERT(
            encoder->selector_group_bytecount -
            encoder->selector_group_offset
            >= size);

    {
        uint8_t *group = (uint8_t *) encoder->selector_group;

        p = group + encoder->selector_group_offset;
    }

    memset(p, 0, size);
    encoder->selector_group_offset += size;

    return p;
}


void
ip_selector_encode_init(
        struct IPSelectorEncode *encoder,
        struct IPSelectorGroup *selector_group,
        int selector_group_bytecount)
{
    ASSERT(selector_group_bytecount >= sizeof *selector_group);

    encoder->selector_group_offset = sizeof *selector_group;
    encoder->selector_group_bytecount = selector_group_bytecount;
    encoder->selector_group = selector_group;
    encoder->current_selector = NULL;

    memset(selector_group, 0, sizeof *selector_group);
    selector_group->bytecount = sizeof *selector_group;
}


void
ip_selector_encode_add_selector(
        struct IPSelectorEncode *encoder,
        int ip_version,
        int ip_protocol)
{
    struct IPSelectorGroup *selector_group = encoder->selector_group;
    struct IPSelector *selector;

    selector = ip_selector_encode_add_stuff(encoder, sizeof *selector);

    encoder->current_selector = selector;

    selector->ip_version = ip_version;
    selector->ip_protocol = ip_protocol;
    selector->bytecount = sizeof *selector;

    selector_group->selector_count++;
    selector_group->bytecount += sizeof *selector;
}



static void *
ip_selector_encode_add_selector_stuff(
        struct IPSelectorEncode *encoder,
        int size)
{
    struct IPSelectorGroup *selector_group = encoder->selector_group;
    struct IPSelector *selector = encoder->current_selector;
    void *p;

    ASSERT(selector != NULL);

    p = ip_selector_encode_add_stuff(encoder, size);

    selector_group->bytecount += size;
    selector->bytecount += size;

    return p;
}


static void
ip_selector_encode_memcpy_address(
        unsigned char dst[16],
        const unsigned char src[16])
{
    memcpy(dst, src, 16);
}


static void
ip_selector_encode_add_endpoint(
        struct IPSelectorEncode *encoder,
        const unsigned char address_begin[16],
        const unsigned char address_end[16],
        int port_begin,
        int port_end,
        int ip_version,
        int ip_protocol)
{
    struct IPSelectorEndpoint *endpoint;

    endpoint =
        ip_selector_encode_add_selector_stuff(
                encoder,
                sizeof *endpoint);

    ip_selector_encode_memcpy_address(endpoint->address.begin, address_begin);
    ip_selector_encode_memcpy_address(endpoint->address.end, address_end);

    endpoint->port.begin = port_begin;
    endpoint->port.end = port_end;
    endpoint->ip_version = ip_version;
    endpoint->ip_protocol = ip_protocol;
}


static void
ip_selector_encode_add_address(
        struct IPSelectorEncode *encoder,
        const unsigned char address_begin[16],
        const unsigned char address_end[16])
{
    struct IPSelectorAddress *address;

    address = ip_selector_encode_add_selector_stuff(encoder, sizeof *address);

    ip_selector_encode_memcpy_address(address->begin, address_begin);
    ip_selector_encode_memcpy_address(address->end, address_end);
}


static void
ip_selector_encode_add_port(
        struct IPSelectorEncode *encoder,
        int port_begin,
        int port_end)
{
    struct IPSelectorPort *port;

    port = ip_selector_encode_add_selector_stuff(encoder, sizeof *port);

    port->begin = port_begin;
    port->end = port_end;
}


void
ip_selector_encode_add_source_endpoint(
        struct IPSelectorEncode *encoder,
        const unsigned char address_begin[16],
        const unsigned char address_end[16],
        int port_begin,
        int port_end,
        int ip_version,
        int ip_protocol)
{
    ASSERT(encoder->current_selector != NULL);
    ASSERT(encoder->current_selector->destination_endpoint_count == 0);
    ASSERT(encoder->current_selector->source_address_count == 0);
    ASSERT(encoder->current_selector->destination_address_count == 0);
    ASSERT(encoder->current_selector->source_port_count == 0);
    ASSERT(encoder->current_selector->destination_port_count == 0);

    ip_selector_encode_add_endpoint(
            encoder,
            address_begin,
            address_end,
            port_begin,
            port_end,
            ip_version,
            ip_protocol);

    encoder->current_selector->source_endpoint_count++;

    ASSERT(encoder->current_selector->source_endpoint_count != 0);
}


void
ip_selector_encode_add_destination_endpoint(
        struct IPSelectorEncode *encoder,
        const unsigned char address_begin[16],
        const unsigned char address_end[16],
        int port_begin,
        int port_end,
        int ip_version,
        int ip_protocol)
{
    ASSERT(encoder->current_selector != NULL);
    ASSERT(encoder->current_selector->source_address_count == 0);
    ASSERT(encoder->current_selector->destination_address_count == 0);
    ASSERT(encoder->current_selector->source_port_count == 0);
    ASSERT(encoder->current_selector->destination_port_count == 0);

    ip_selector_encode_add_endpoint(
            encoder,
            address_begin,
            address_end,
            port_begin,
            port_end,
            ip_version,
            ip_protocol);

    encoder->current_selector->destination_endpoint_count++;

    ASSERT(encoder->current_selector->destination_endpoint_count != 0);
}


void
ip_selector_encode_add_source_address(
        struct IPSelectorEncode *encoder,
        const unsigned char address_begin[16],
        const unsigned char address_end[16])
{
    ASSERT(encoder->current_selector != NULL);
    ASSERT(encoder->current_selector->destination_address_count == 0);
    ASSERT(encoder->current_selector->source_port_count == 0);
    ASSERT(encoder->current_selector->destination_port_count == 0);

    ip_selector_encode_add_address(
            encoder,
            address_begin,
            address_end);

    encoder->current_selector->source_address_count++;

    ASSERT(encoder->current_selector->source_address_count != 0);
}


void
ip_selector_encode_add_destination_address(
        struct IPSelectorEncode *encoder,
        const unsigned char address_begin[16],
        const unsigned char address_end[16])
{
    ASSERT(encoder->current_selector != NULL);
    ASSERT(encoder->current_selector->source_port_count == 0);
    ASSERT(encoder->current_selector->destination_port_count == 0);

    ip_selector_encode_add_address(
            encoder,
            address_begin,
            address_end);

    encoder->current_selector->destination_address_count++;

    ASSERT(encoder->current_selector->destination_address_count != 0);
}


void
ip_selector_encode_add_source_port(
        struct IPSelectorEncode *encoder,
        int port_begin,
        int port_end)
{
    ASSERT(encoder->current_selector != NULL);
    ASSERT(encoder->current_selector->destination_port_count == 0);

    ip_selector_encode_add_port(
            encoder,
            port_begin,
            port_end);

    encoder->current_selector->source_port_count++;

    ASSERT(encoder->current_selector->source_port_count != 0);
}


void
ip_selector_encode_add_destination_port(
        struct IPSelectorEncode *encoder,
        int port_begin,
        int port_end)
{
    ASSERT(encoder->current_selector != NULL);

    ip_selector_encode_add_port(
            encoder,
            port_begin,
            port_end);

    encoder->current_selector->destination_port_count++;

    ASSERT(encoder->current_selector->destination_port_count != 0);
}
