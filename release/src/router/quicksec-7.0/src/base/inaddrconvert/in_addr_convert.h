/**
   @copyright
   Copyright (c) 2015, INSIDE Secure Oy. All rights reserved.
*/

#ifndef IN_ADDR_CONVERT_H
#define IN_ADDR_CONVERT_H

struct InAddr;
struct SshIpAddrRec;

void
in_addr_convert_from_sshipaddr(
        struct InAddr *inaddr,
        const struct SshIpAddrRec *sshipaddr);


void
in_addr_convert_to_sshipaddr(
        const struct InAddr *inaddr,
        struct SshIpAddrRec *sshipaddr);

#endif /* IN_ADDR_CONVERT_H */
