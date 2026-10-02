/**
   @copyright
   Copyright (c) 2015 - 2016, INSIDE Secure Oy. All rights reserved.
*/

#include "in_addr.h"
#include "implementation_defs.h"


static const unsigned char in_addr_four_prefix[12] =
{
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff
};

static const int in_addr_byte_size = sizeof(struct InAddr);


InAddrVersion
in_addr_version(
        const struct InAddr *in_addr)
{
    InAddrVersion version = IN_ADDR_SIX;
    int is_four;

    is_four = !
        memcmp(
                in_addr->addr,
                in_addr_four_prefix,
                sizeof in_addr_four_prefix);

    if (is_four)
    {
        version = IN_ADDR_FOUR;
    }

    return version;
}


int
in_addr_compare(
        const struct InAddr *in_addr_first,
        const struct InAddr *in_addr_second)
{
    return
        memcmp(
                in_addr_first->addr,
                in_addr_second->addr,
                in_addr_byte_size);
}

int
in_addr_compare_masked(
        const struct InAddr *in_addr_first,
        const struct InAddr *in_addr_second,
        int mask_bit_count)
{
    int byte_count;
    int last_bits;
    int result;

    byte_count = mask_bit_count >> 3;
    byte_count = MIN(in_addr_byte_size, byte_count);

    last_bits = 0xffffff00 >> (mask_bit_count & 7);

    result =
        memcmp(
                in_addr_first->addr,
                in_addr_second,
                byte_count);

    if (result == 0 && byte_count < in_addr_byte_size)
    {
        int first_bits = in_addr_first->addr[byte_count] & last_bits;
        int second_bits = in_addr_second->addr[byte_count] & last_bits;

        result = second_bits - first_bits;
    }

    return result;
}


void
in_addr_import(
        struct InAddr *in_addr,
        const void *bytes,
        int bytecount)
{
    ASSERT(bytecount == 4 || bytecount == 16);

    if (bytecount == 4)
    {
        int prefix_byte_count = sizeof in_addr_four_prefix;

        memcpy(
                in_addr->addr,
                in_addr_four_prefix,
                prefix_byte_count);

        memcpy(
                in_addr->addr + prefix_byte_count,
                bytes,
                bytecount);
    }

    if (bytecount == 16)
    {
        memcpy(in_addr->addr, bytes, bytecount);
    }
}


void
in_addr_export(
        const struct InAddr *in_addr,
        void *bytes,
        int bytecount)
{
    if (in_addr_version(in_addr) == 4)
    {
        ASSERT(bytecount == 4);

        memcpy(bytes, in_addr->addr + sizeof(in_addr_four_prefix), bytecount);
    }

    if (in_addr_version(in_addr) == 6)
    {
        ASSERT(bytecount == 16);

        memcpy(bytes, in_addr->addr, bytecount);
    }
}

const unsigned char*
in_addr_ip_data(
        const struct InAddr *in_addr)
{
    if (in_addr_version(in_addr) == IN_ADDR_FOUR)
    {
        return in_addr->addr + 12;
    }
    if (in_addr_version(in_addr) == IN_ADDR_SIX)
    {
        return in_addr->addr;
    }

    return NULL;
}

static void
in_addr_host_bits_set_byte_value(
        struct InAddr *in_addr,
        int mask_bit_count,
        int byte_value)
{
    int byte_count;

    byte_count = mask_bit_count >> 3;
    byte_count = MIN(in_addr_byte_size, byte_count);

    if (byte_count < in_addr_byte_size)
    {
        int first_bits = ~(0xff >> (mask_bit_count & 7));
        int byte;

        byte = in_addr->addr[byte_count];

        memset(
                in_addr->addr + byte_count,
                byte_value,
                in_addr_byte_size - byte_count);

        byte &= first_bits;
        byte |= (~first_bits & byte_value);
        in_addr->addr[byte_count] =  byte;
    }
}


void
in_addr_host_bits_clear(
        struct InAddr *in_addr,
        int mask_bit_count)
{
    in_addr_host_bits_set_byte_value(
            in_addr,
            mask_bit_count,
            0);
}

void
in_addr_host_bits_set(
        struct InAddr *in_addr,
        int mask_bit_count)
{
    in_addr_host_bits_set_byte_value(
            in_addr,
            mask_bit_count,
            0xff);
}


void
in_addr_copy(
        struct InAddr *in_addr_to,
        const struct InAddr *in_addr_from,
        int mask_bit_count)
{
    int byte_count;
    int last_bits;

    byte_count = mask_bit_count >> 3;
    byte_count = MIN(in_addr_byte_size, byte_count);

    memcpy(
            in_addr_to->addr,
            in_addr_from->addr,
            byte_count);

    if (byte_count < in_addr_byte_size)
    {
        int byte;
        last_bits = ~(0xff >> (mask_bit_count & 7));

        memset(
                in_addr_to->addr + byte_count,
                0,
                in_addr_byte_size - byte_count);

        byte = in_addr_from->addr[byte_count];
        byte &= last_bits;
        in_addr_to->addr[byte_count] =  byte;
    }
}

int
in_addr_byte_count(
        const struct InAddr *in_addr)
{
    int bytecount = 16;

    if (in_addr_version(in_addr) == IN_ADDR_FOUR)
    {
        bytecount = 4;
    }

    return bytecount;
}

static int
in_addr_to_str(
        char *buf,
        int buf_len,
        const struct InAddr *in_addr)
{
    const uint8_t *address = in_addr->addr;
    int len;

    if (in_addr_version(in_addr) == IN_ADDR_FOUR)
    {
        const int a1 = address[12 + 0];
        const int a2 = address[12 + 1];
        const int a3 = address[12 + 2];
        const int a4 = address[12 + 3];

        len = snprintf(buf, buf_len, "%d.%d.%d.%d", a1, a2, a3, a4);
    }
    else
    {
        len = format_ipaddress(buf, buf_len, address);
    }

    return len;
}

const char *
debug_strbuf_in_addr(
        void *buf,
        const struct InAddr *in_addr)
{

    int used;
    char *p;
    int p_len;

    DEBUG_STRBUF_BUFFER_GET(buf, &p, &p_len);

    used = in_addr_to_str(p, p_len, in_addr);

    DEBUG_STRBUF_BUFFER_COMMIT(buf, used + 1);

    return p;
}

int
in_addr_str(
        const struct InAddr *in_addr,
        char *buf,
        int buf_len)
{
    return in_addr_to_str(buf, buf_len, in_addr);
}


int
ssh_in_addr_render(
        char *buf,
        int buf_size,
        int precision,
        void *datum)
{
    return in_addr_to_str(buf, buf_size, datum);
}

