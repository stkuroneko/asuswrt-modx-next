/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file implements the DHCP spoof protocol to configure the virtual
   adapters on Windows systems.  This can handle incoming DHCP packets
   and answer to them with our configuration.  The virtual adapters
   on WIN32 systems are always configured by letting the system to
   perform DHCP for the created interface.  We, however intercept that
   DHCP session and give our configuration data to the system instead.

   This is not real DHCP server but only a subset of the server.  It
   supports some of the server features but cannot be used as full
   featured DHCP server.
*/

#ifndef SSHDHCP_SPOOF_H
#define SSHDHCP_SPOOF_H

#include "sshdhcp.h"

/* Forward declaration for the SshDHCPSpoof context. This is allocated
   by the ssh_dhcp_spoof_allocate and freed by the ssh_dhcp_spoof_free
   functions. */
typedef struct SshDHCPSpoofRec *SshDHCPSpoof;

/* Allocates new DHCP Spoof context. The `server_address' is the IP address
   we will send to DHCP Client and pretend to be. The `client_address'
   is the IP address that caller wants to spoof for the DHCP Client.
   The caller should also call the ssh_dhcp_spoof_option_put to set all
   the options and parameters it wants to spoof for the DHCP Client. This
   function returns NULL on error. */
SshDHCPSpoof ssh_dhcp_spoof_allocate(SshIpAddr server_ip,
                                     SshIpAddr client_ip);

/* Frees the spoof context and all data in it. */
void ssh_dhcp_spoof_free(SshDHCPSpoof spoof);

#define SSH_DHCP_SPOOF_MAX_OPTIONS_SIZE 512

/* Set the DHCP options lowlevel structure by hand. This function should
   be used only if one REALLY knows what's lying under the hood. */
void ssh_dhcp_spoof_options_set(SshDHCPSpoof spoof,
                                const unsigned char *data, size_t data_len);

/* Put new option to the DHCP options. The caller of the DHCP Spoof
   should add all the DHCP options and paratemers using this function
   it wants to send to the DHCP Client. See the sshdhcp.h for all
   the DHCP options. See the RFC 2132 for all the DHCP options and
   parameters they rquire. Each of the options must be added only
   once. */
void ssh_dhcp_spoof_option_put(SshDHCPSpoof spoof, SshDHCPOption option,
                               unsigned char *data, size_t data_len);

/* Process incoming DHCP packet from DHCP Client. This is called by
   the external process to process the incoming DHCP packet. This function
   returns a reply to the packet that the external process must send
   to the DHCP Client. This function returns NULL on error. The `data'
   is the DHCP packet from the client. */
unsigned char *ssh_dhcp_spoof_process_packet(SshDHCPSpoof spoof,
                                             const unsigned char *data,
                                             size_t data_len,
                                             size_t *ret_len);

#endif /* SSHDHCP_SPOOF_H */
