/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   IP mask related related functions and definitions.
*/

#include "sshincludes.h"
#include "sshinet.h"

#define SSH_DEBUG_MODULE "SshInetMask"

#define MAX_IP_ADDR_LEN 16


/* Compares two IP addresses in the internal representation and returns
   true if they are equal. */

bool ssh_ipaddr_with_mask_equal(SshIpAddr ip1, SshIpAddr ip2,
                                   SshIpAddr mask)
{
    unsigned int i;
    unsigned char i1[MAX_IP_ADDR_LEN], i2[MAX_IP_ADDR_LEN], m[MAX_IP_ADDR_LEN];

    if ((ip1->type != ip2->type) || (ip2->type != mask->type))
      return false;

    memset(i1, 0, 16);
    memset(i2, 0, 16);
    memset(m, 255, 16);

    if (SSH_IP_IS4(ip1))
      memcpy(i1 + 12, ip1->addr_data, 4);
    else
      memcpy(i1, ip1->addr_data, 16);

    if (SSH_IP_IS4(ip2))
      memcpy(i2 + 12, ip2->addr_data, 4);
    else
      memcpy(i2, ip2->addr_data, 16);

    if (SSH_IP_IS4(mask))
      memcpy(m + 12, mask->addr_data, 4);
    else
      memcpy(m, mask->addr_data, 16);

    for (i = 0; i < 16; i++)
      if ((i1[i] & m[i]) != (i2[i] & m[i]))
        return false;

    return true;
}

bool ssh_ipaddr_mask_equal(SshIpAddr ip, SshIpAddr masked_ip)
{
    register uint32_t *a1, *a2;
    register int ml;
#ifndef WORDS_BIGENDIAN
    register unsigned char *c1, *c2;
#endif

    /* Different type? */
    if (ip->type != masked_ip->type)
      return false;

    a1 = (uint32_t *) ip->addr_data;
    a2 = (uint32_t *) masked_ip->addr_data;
    ml = masked_ip->mask_len;

    /* Chuck away ml in full 32-bit words */
    for (; ml > 31; ml -= 32)
    {
        if (*a1++ != *a2++)
          return false;
    }

    if (ml == 0)
      return true;

    /* Then we have only <32 bit part left */
#ifdef WORDS_BIGENDIAN
    if ((*a1 ^ *a2) & (0xffffffff << (32 - ml)))
      return false;

    return true;
#else
    c1 = (unsigned char *) a1;
    c2 = (unsigned char *) a2;

    for (; ml > 7; ml -= 8)
    {
        if (*c1++ != *c2++)
          return false;
    }

    if (ml == 0)
      return true;

    if ((*c1 ^ *c2) & (0xff  << (8 - ml)))
      return false;

    return true;
#endif
}
