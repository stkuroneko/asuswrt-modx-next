/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   IP bits related functions and definitions.
*/

#include "sshincludes.h"
#include "sshinet.h"

#define SSH_DEBUG_MODULE "SshInetBits"

/* Sets all rightmost bits after keeping `keep_bits' bits on the left to
   the value specified by `value'. */

void ssh_ipaddr_set_bits(SshIpAddr result, SshIpAddr ip,
                         unsigned int keep_bits, unsigned int value)
{
    size_t len;
    unsigned int i;

    len = SSH_IP_IS6(ip) ? 16 : 4;

    *result = *ip;
    for (i = keep_bits / 8; i < len; i++)
    {
        if (8 * i >= keep_bits)
          result->addr_data[i] = value ? 0xff : 0;
        else
        {
            SSH_ASSERT(keep_bits - 8 * i < 8);
            result->addr_data[i] &= (0xff << (8 - (keep_bits - 8 * i)));
            if (value)
              result->addr_data[i] |= (0xff >> (keep_bits - 8 * i));
        }
    }
}


void
ssh_ipaddr_set_mask_bits(
        SshIpAddr result,
        SshIpAddrType type,
        int mask_len)
{
    int bits;
    int byte;

    SSH_ASSERT(mask_len <= SSH_IP_ADDR_SIZE * 8);

    memset(result, 0, sizeof *result);

    result->type = type;
    if (type == SSH_IP_TYPE_IPV4)
    {
        result->mask_len = 32;
    }

    if (type == SSH_IP_TYPE_IPV6)
    {
        result->mask_len = 128;
    }

    bits = 0;
    byte = 0;
    while (bits < mask_len)
    {
        unsigned char *addr_bytes = result->addr_union._addr_data;
        int mask_bits = mask_len - bits;

        if (mask_bits > 8)
        {
            mask_bits = 8;
        }

        addr_bytes[byte] = (unsigned char) (0xff & (0xff << (8 - mask_bits)));

        bits += 8;
        ++byte;
    }
}
