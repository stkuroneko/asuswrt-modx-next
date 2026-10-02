/**
   @copyright
   Copyright (c) 2015 - 2016, INSIDE Secure Oy. All rights reserved.
*/

#include "ip_selector_parse.h"
#include "ip_selector_match.h"
#include "in_addr.h"

#include "implementation_defs.h"

static const int ip_selector_field_sizes[IP_SELECTOR_COUNT] =
{
    sizeof (struct IPSelectorEndpoint),
    sizeof (struct IPSelectorEndpoint),
    sizeof (struct IPSelectorAddress),
    sizeof (struct IPSelectorAddress),
    sizeof (struct IPSelectorPort),
    sizeof (struct IPSelectorPort)
};

static int
ip_selector_parse_field_size(
        int selector_field)
{
    return ip_selector_field_sizes[selector_field];
}

static const void *
ip_parse_pointer_add(
        const void *pointer,
        int byte_offset)
{
    const uint8_t *base = pointer;

    base += byte_offset;

    return base;
}

static int
ip_parse_offset_get(
        const void *base_pointer,
        const void *offset_pointer)
{
    const uint8_t *base_p = base_pointer;
    const uint8_t *offset_p = offset_pointer;

    return offset_p - base_p;
}


static const void *
ip_selector_parse_get_selector_pointer(
        struct IPSelectorParse *parser,
        int selector_field)
{
    const struct IPSelector *current_selector = parser->current_selector;
    int offset = 0;
    int i;

    offset = sizeof *current_selector;

    for (i = 0; i < selector_field; i++)
    {
        offset +=
            ip_selector_parse_field_size(i) *
            ip_selector_parse_field_count(parser, i);
    }

    offset +=
        ip_selector_parse_field_size(selector_field) *
        parser->fields[selector_field];

    return ip_parse_pointer_add(current_selector, offset);
}

static const void *
ip_selector_parse_get_next_pointer(
        struct IPSelectorParse *parser,
        int selector_field)
{
    const struct IPSelector *current_selector = parser->current_selector;
    const void *pointer = NULL;
    int field_count = ip_selector_parse_field_count(parser, selector_field);

    if (current_selector != NULL &&
        parser->fields[selector_field] < field_count)
    {
        pointer =
            ip_selector_parse_get_selector_pointer(
                    parser,
                    selector_field);

        ++parser->fields[selector_field];
    }

    return pointer;
}

static void
ip_parse_reset_counters(
        struct IPSelectorParse *parser)
{
    memset(parser->fields, 0, sizeof parser->fields);
}


static void
ip_selector_parse_make_in_addr(
        struct InAddr *in_addr,
        int ip_version,
        const uint8_t address[16])
{
    if (ip_version == 4)
    {
        in_addr_import(in_addr, address + 12, 4);
    }
    else
    {
        in_addr_import(in_addr, address, 16);
    }
}

void
ip_selector_parse_init(
        struct IPSelectorParse *parser,
        const struct IPSelectorGroup *selector_group)
{
    ASSERT(
            ip_selector_match_validate_selector_group(
                    selector_group,
                    selector_group->bytecount)
           == 0);

    parser->selector_group = selector_group;
    parser->current_selector = NULL;
    ip_parse_reset_counters(parser);
}

void
ip_selector_parse_field_reset(
        struct IPSelectorParse *parser,
        int selector_field)
{
    parser->fields[selector_field] = 0;
}

bool
ip_selector_parse_next_selector(
        struct IPSelectorParse *parser,
        int *ip_version,
        int *ip_protocol)
{
    const struct IPSelector *selector;
    bool ok = true;

    if (parser->current_selector != NULL)
    {
        selector =
            ip_parse_pointer_add(
                    parser->current_selector,
                    parser->current_selector->bytecount);
    }
    else
    {
        selector =
            ip_parse_pointer_add(
                    parser->selector_group,
                    sizeof *parser->selector_group);
    }

    if (ip_parse_offset_get(
                parser->selector_group,
                selector + 1)
        > parser->selector_group->bytecount)
    {
        selector = NULL;
        ok = false;
    }

    parser->current_selector = selector;

    ip_parse_reset_counters(parser);

    if (ok == true)
    {
        *ip_version = selector->ip_version;
        *ip_protocol = selector->ip_protocol;
    }

    return ok;
}

int
ip_selector_parse_field_count(
        struct IPSelectorParse *parser,
        int selector_field)
{
    const struct IPSelector *current_selector = parser->current_selector;
    int count = -1;

    if (current_selector != NULL)
    {
        switch (selector_field)
        {
        case IP_SELECTOR_SOURCE_ENDPOINT:
            count = current_selector->source_endpoint_count;
            break;

        case IP_SELECTOR_DESTINATION_ENDPOINT:
            count = current_selector->destination_endpoint_count;
            break;

        case IP_SELECTOR_SOURCE_ADDRESS:
            count = current_selector->source_address_count;
            break;

        case IP_SELECTOR_DESTINATION_ADDRESS:
            count = current_selector->destination_address_count;
            break;

        case IP_SELECTOR_SOURCE_PORT:
            count = current_selector->source_port_count;
            break;

        case IP_SELECTOR_DESTINATION_PORT:
            count = current_selector->destination_port_count;
            break;

        case IP_SELECTOR_COUNT:
        default:
            break;
        }
    }

    ASSERT(count != -1);

    return count;
}


bool
ip_selector_parse_next_endpoint(
        struct IPSelectorParse *parser,
        int selector_field,
        struct InAddr *begin_address,
        struct InAddr *end_address,
        int *ip_protocol,
        int *begin_port,
        int *end_port)
{
    const struct IPSelectorEndpoint *endpoint = NULL;

    ASSERT(
            selector_field == IP_SELECTOR_SOURCE_ENDPOINT ||
            selector_field == IP_SELECTOR_DESTINATION_ENDPOINT);

    endpoint =
        ip_selector_parse_get_next_pointer(
                parser,
                selector_field);

    if (endpoint != NULL)
    {
        ip_selector_parse_make_in_addr(
                begin_address,
                endpoint->ip_version,
                endpoint->address.begin);

        ip_selector_parse_make_in_addr(
                end_address,
                endpoint->ip_version,
                endpoint->address.end);

        *ip_protocol = endpoint->ip_protocol;
        *begin_port = endpoint->port.begin;
        *end_port = endpoint->port.end;

        return true;
    }

    return false;
}

bool
ip_selector_parse_next_address(
        struct IPSelectorParse *parser,
        int selector_field,
        struct InAddr *begin_address,
        struct InAddr *end_address)
{
    const struct IPSelector *current_selector = parser->current_selector;
    const struct IPSelectorAddress *address = NULL;

    ASSERT(
            selector_field == IP_SELECTOR_SOURCE_ADDRESS ||
            selector_field == IP_SELECTOR_DESTINATION_ADDRESS);

    address =
        ip_selector_parse_get_next_pointer(
                parser,
                selector_field);

    if (current_selector != NULL && address != NULL)
    {
        int ip_version = current_selector->ip_version;

        ip_selector_parse_make_in_addr(
                begin_address,
                ip_version,
                address->begin);

        ip_selector_parse_make_in_addr(
                end_address,
                ip_version,
                address->end);

        return true;
    }

    return false;
}

bool
ip_selector_parse_next_port(
        struct IPSelectorParse *parser,
        int selector_field,
        int *begin_port,
        int *end_port)
{
    const struct IPSelectorPort *port = NULL;

    ASSERT(
            selector_field == IP_SELECTOR_SOURCE_PORT ||
            selector_field == IP_SELECTOR_DESTINATION_PORT);

    port =
        ip_selector_parse_get_next_pointer(
                parser,
                selector_field);

    if (port != NULL)
    {
        *begin_port = port->begin;
        *end_port = port->end;

        return true;
    }

    return false;
}
