/**
   @copyright
   Copyright (c) 2015, INSIDE Secure Oy. All rights reserved.
*/

#include "in_addr.h"
#include "in_addr_convert.h"

#include "sshincludes.h"
#include "sshinet.h"

#include "implementation_defs.h"

#define __DEBUG_MODULE__ inaddrconvert

void
in_addr_convert_from_sshipaddr(
        struct InAddr *inaddr,
        const struct SshIpAddrRec *sshipaddr)
{
    if (SSH_IP_DEFINED(sshipaddr))
    {
        in_addr_import(
                inaddr,
                SSH_IP_ADDR_DATA(sshipaddr),
                SSH_IP_ADDR_LEN(sshipaddr));
    }
    else
    {
        DEBUG_HIGH(
                convert,
                "Converting undefined sshipaddr %p to zero inaddr %p.",
                sshipaddr,
                inaddr);

        memset(inaddr, 0, sizeof *inaddr);
    }
}


void
in_addr_convert_to_sshipaddr(
        const struct InAddr *inaddr,
        struct SshIpAddrRec *sshipaddr)
{
    SSH_IP_DECODE(
            sshipaddr,
            in_addr_ip_data(inaddr),
            in_addr_byte_count(inaddr));
}
