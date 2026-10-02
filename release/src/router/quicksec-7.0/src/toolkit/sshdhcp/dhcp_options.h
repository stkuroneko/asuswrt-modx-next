/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   dhcp_options.h
*/

#ifndef DHCP_OPTIONS_H
#define DHCP_OPTIONS_H

#include "sshdhcp.h"

/* Structure to return default options from DHCP packet. */
typedef struct
{
    uint32_t t1;
    uint32_t t2;

    uint32_t server_ip;
    size_t server_ip_len;
    uint32_t netmask;

    uint32_t *gateway_ip;
    size_t gateway_ip_count;

    uint32_t *dns_ip;
    size_t dns_ip_count;

    uint32_t *wins_ip;
    size_t wins_ip_count;

    char hostname[256];
    char dns_name[256];
    char file[128];
    char nis_name[256];
}
*SshDHCPOptionsDefault;

/* This function can be used to free the SshDHCPOptionsDefault structure. */
void ssh_dhcp_free_options_default(SshDHCPOptionsDefault def);

#endif /* DHCP_OPTIONS_H */
