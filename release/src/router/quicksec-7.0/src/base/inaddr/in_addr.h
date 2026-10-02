/**
   @copyright
   Copyright (c) 2015, INSIDE Secure Oy. All rights reserved.
*/

#ifndef IN_ADDR_H
#define IN_ADDR_H

#include "public_defs.h"

struct InAddr
{
    /* An Internet address. IPv6 address. IPv4 address are represented
       as "IPv4-Mapped IPv6 Address" (RFC4291), that is 10 bytes of 0, 2
       bytes of 0xff., last 4 bytes IPv4 address.
    */
    unsigned char addr[16];
};

enum
{
    IN_ADDR_BIT_COUNT = 128,
    IN_ADDR_FOUR_MASK_OFFSET = 96
};

typedef enum
{
    IN_ADDR_FOUR = 4,
    IN_ADDR_SIX = 6
}
InAddrVersion;


InAddrVersion
in_addr_version(
        const struct InAddr *inaddr);

int
in_addr_compare(
        const struct InAddr *inaddr_first,
        const struct InAddr *inaddr_second);

int
in_addr_compare_masked(
        const struct InAddr *inaddr_first,
        const struct InAddr *inaddr_second,
        int mask_len);

void
in_addr_import(
        struct InAddr *inaddr,
        const void *bytes,
        int bytecount);

void
in_addr_export(
        const struct InAddr *inaddr,
        void *bytes,
        int bytecount);

const unsigned char *
in_addr_ip_data(
        const struct InAddr *in_addr);

void
in_addr_copy(
        struct InAddr *addr_to,
        const struct InAddr *addr_from,
        int mask_bit_count);

int
in_addr_byte_count(
        const struct InAddr *in_addr);

void
in_addr_host_bits_set(
        struct InAddr *in_addr,
        int mask_bit_count);

void
in_addr_host_bits_clear(
        struct InAddr *in_addr,
        int mask_bit_count);

const char *
debug_strbuf_in_addr(
        void *buf,
        const struct InAddr *in_addr);

int
in_addr_str(
        const struct InAddr *in_addr,
        char *buf,
        int buf_len);

int
ssh_in_addr_render(
        char *buf,
        int buf_size,
        int precision,
        void *datum);

#endif /* IN_ADDR_H */
