/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   IP calculation related functions and definitions.
*/

#include "sshincludes.h"
#include "sshinet.h"

#define SSH_DEBUG_MODULE "SshInetCalc"

/* Increment IP address by one. Return true if success and
   false if the IP address wrapped. */
bool ssh_ipaddr_increment(SshIpAddr ip)
{
    if (SSH_IP_IS4(ip))
    {
        uint32_t temp;

        temp = SSH_IP4_TO_INT(ip);
        temp++;
        temp &= 0xffffffffL;
        SSH_INT_TO_IP4(ip, temp);
        if (temp == 0)
          return false;
        return true;
    }
#if defined(WITH_IPV6)
    else
    {
        uint8_t temp;
        int i;

        for(i = 15; i >= 0; i--)
        {
            temp = SSH_IP6_BYTEN(ip, i);
            temp++;
            temp &= 0xff;
            SSH_IP6_BYTEN(ip, i) = temp;
            if (temp != 0)
              return true;
        }
        return false;
    }
#endif /* WITH_IPV6 */
    return false;
}

/* Decrement IP address by one. Return true if success and
   false if the IP address wrapped. */
bool ssh_ipaddr_decrement(SshIpAddr ip)
{
    if (SSH_IP_IS4(ip))
    {
        uint32_t temp;

        temp = SSH_IP4_TO_INT(ip);
        temp--;
        temp &= 0xffffffffL;
        SSH_INT_TO_IP4(ip, temp);
        if (temp == 0xffffffff)
          return false;
        return true;
    }
#if defined(WITH_IPV6)
    else
    {
        uint8_t temp;
        int i;

        for(i = 15; i >= 0; i--)
        {
            temp = SSH_IP6_BYTEN(ip, i);
            temp--;
            temp &= 0xff;
            SSH_IP6_BYTEN(ip, i) = temp;
            if (temp != 0xff)
              return true;
        }
        return false;
    }
#endif /* WITH_IPV6 */
    return false;
}
