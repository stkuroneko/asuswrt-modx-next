/**
   @copyright
   Copyright (c) 2015, INSIDE Secure Oy. All rights reserved.
*/

#ifndef IP_SELECTOR_ENCODE_H
#define IP_SELECTOR_ENCODE_H

#include "ip_selector.h"


struct IPSelectorEncode
{
    struct IPSelectorGroup *selector_group;
    struct IPSelector *current_selector;
    int selector_group_offset;
    int selector_group_bytecount;
};


int
ip_selector_encode_selector_group_bytecount(
        int selector_count,
        int endpoint_count,
        int port_count,
        int address_count);


void
ip_selector_encode_init(
        struct IPSelectorEncode *encoder,
        struct IPSelectorGroup *selector_group,
        int selector_group_bytecount);


void
ip_selector_encode_add_selector(
        struct IPSelectorEncode *encoder,
        int ip_version,
        int ip_protocol);


void
ip_selector_encode_add_source_endpoint(
        struct IPSelectorEncode *encoder,
        const unsigned char address_begin[16],
        const unsigned char address_end[16],
        int port_begin,
        int port_end,
        int ip_version,
        int ip_protocol);


void
ip_selector_encode_add_destination_endpoint(
        struct IPSelectorEncode *encoder,
        const unsigned char address_begin[16],
        const unsigned char address_end[16],
        int port_begin,
        int port_end,
        int ip_version,
        int ip_protocol);


void
ip_selector_encode_add_source_address(
        struct IPSelectorEncode *encoder,
        const unsigned char address_begin[16],
        const unsigned char address_end[16]);


void
ip_selector_encode_add_destination_address(
        struct IPSelectorEncode *encoder,
        const unsigned char address_begin[16],
        const unsigned char address_end[16]);


void
ip_selector_encode_add_source_port(
        struct IPSelectorEncode *encoder,
        int port_begin,
        int port_end);


void
ip_selector_encode_add_destination_port(
        struct IPSelectorEncode *encoder,
        int port_begin,
        int port_end);


#endif /* IP_SELECTOR_ENCODE_H */
