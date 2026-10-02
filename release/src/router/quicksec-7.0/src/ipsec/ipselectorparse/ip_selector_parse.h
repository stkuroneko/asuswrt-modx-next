/**
   @copyright
   Copyright (c) 2015 - 2016, INSIDE Secure Oy. All rights reserved.
*/

#ifndef IP_SELECTOR_PARSE_H
#define IP_SELECTOR_PARSE_H

#include "public_defs.h"
#include "ip_selector.h"

struct InAddr;
struct IPSelector;
struct IPSelectorGroup;
struct IPSelectorPort;
struct IPSelectorAddress;
struct IPSelectorEndpoint;

enum
{
    IP_SELECTOR_SOURCE_ENDPOINT,
    IP_SELECTOR_DESTINATION_ENDPOINT,
    IP_SELECTOR_SOURCE_ADDRESS,
    IP_SELECTOR_DESTINATION_ADDRESS,
    IP_SELECTOR_SOURCE_PORT,
    IP_SELECTOR_DESTINATION_PORT,
    IP_SELECTOR_COUNT
};

struct IPSelectorParse
{
    const struct IPSelectorGroup *selector_group;
    const struct IPSelector *current_selector;
    int fields[IP_SELECTOR_COUNT];
};

void
ip_selector_parse_init(
        struct IPSelectorParse *parser,
        const struct IPSelectorGroup *selector_group);

void
ip_selector_parse_field_reset(
        struct IPSelectorParse *parser,
        int selector_field);

bool
ip_selector_parse_next_selector(
        struct IPSelectorParse *parser,
        int *ip_version,
        int *ip_protocol);

int
ip_selector_parse_field_count(
        struct IPSelectorParse *parser,
        int selector_field);

bool
ip_selector_parse_next_endpoint(
        struct IPSelectorParse *parser,
        int selector_field,
        struct InAddr *begin_address,
        struct InAddr *end_address,
        int *ip_protocol,
        int *begin_port,
        int *end_port);

bool
ip_selector_parse_next_address(
        struct IPSelectorParse *parser,
        int selector_field,
        struct InAddr *begin_address,
        struct InAddr *end_address);

bool
ip_selector_parse_next_port(
        struct IPSelectorParse *parser,
        int selector_field,
        int *begin_port,
        int *end_port);

#endif /* IP_SELECTOR_PARSE_H */
