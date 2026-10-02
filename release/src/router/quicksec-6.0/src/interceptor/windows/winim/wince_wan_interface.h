/**
   @copyright
   Copyright (c) 2008 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file contains the type definitions and function declarations
   for Windows CE WAN Interfaces (i.e. dial-up interfaces).
*/

#ifndef SSH_WINCE_WAN_INTERFACE_H
#define SSH_WINCE_WAN_INTERFACE_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _WIN32_WCE
/*--------------------------------------------------------------------------
  DEFINITIONS
  --------------------------------------------------------------------------*/


/*--------------------------------------------------------------------------
  ENUMERATIONS
  --------------------------------------------------------------------------*/


/*--------------------------------------------------------------------------
  TYPE DEFINITIONS
  --------------------------------------------------------------------------*/


/*--------------------------------------------------------------------------
  EXPORTED FUNCTIONS
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  Frees buffer returned by ssh_wan_alloc_buffer_send(). Can be called from
  a WanSendComplete handler.
  --------------------------------------------------------------------------*/
void
ssh_wan_free_buffer_send(PNDIS_WAN_PACKET wan_pkt);

/*--------------------------------------------------------------------------
  Inspects a PPP-encapsulated packet received from a WAN protocol. If
  it is an IPv4 or IPv6 packet, removes the PPP header from the packet,
  leaving a bare IPv4 or IPv6 packet, stores the protocol (IPv4 or
  IPv6) in *protocol and returns TRUE. Otherwise leaves the packet
  untouched and returns FALSE.
  --------------------------------------------------------------------------*/
Boolean
ssh_wan_intercept_from_protocol(SshNdisIMAdapter adapter, 
                                PNDIS_WAN_PACKET packet,
                                SshInterceptorProtocol *protocol);

/*--------------------------------------------------------------------------
  Processes a PPP-encapsulated non-IP packet received from a WAN
  protocol. The packet will be either dropped, rejected or passed
  directly to the corresponding WAN adapter. The status stored in
  *status should be returned to NDIS by the caller.
  --------------------------------------------------------------------------*/
void
ssh_wan_process_from_protocol(SshNdisIMAdapter adapter, 
                              PNDIS_WAN_PACKET packet,
                              PNDIS_STATUS status);

/*--------------------------------------------------------------------------
  Inspects a PPP-encapsulated packet received from a WAN adapter. If
  it is an IPv4 or IPv6 packet, removes the PPP header from the packet,
  leaving a bare IPv4 or IPv6 packet, stores the protocol (IPv4 or
  IPv6) in *protocol and returns TRUE. Otherwise leaves the packet
  untouched and returns FALSE.
  --------------------------------------------------------------------------*/
Boolean
ssh_wan_intercept_from_adapter(SshNdisIMAdapter adapter,
                               PUCHAR *packet, 
                               ULONG *packet_size,
                               SshInterceptorProtocol *protocol);


/*--------------------------------------------------------------------------
  Processes a PPP-encapsulated non-IP packet received from a WAN
  adapter. The packet will be either dropped, rejected or passed
  directly to the corresponding WAN protocol. The status stored in
  *status should be returned to NDIS by the caller.
  --------------------------------------------------------------------------*/
void
ssh_wan_process_from_adapter(SshNdisIMAdapter adapter,
                             PUCHAR packet, 
                             ULONG packet_size,
                             PNDIS_STATUS status);

/*--------------------------------------------------------------------------
  PPP-encapsulates an IPv4 or IPv6 packet and sends it to WAN
  adapter. If successful, returns TRUE, otherwise returns FALSE.
 --------------------------------------------------------------------------*/
Boolean
ssh_wan_send_to_adapter(SshNdisIMAdapter adapter, 
                        SshNdisPacket packet,
                        SshInterceptorProtocol protocol);


/*--------------------------------------------------------------------------
  PPP-encapsulates an IPv4 or IPv6 packet and indicates it to WAN
  protocol. If successful, returns TRUE, otherwise returns FALSE.
  --------------------------------------------------------------------------*/
Boolean
ssh_wan_send_to_protocol(SshNdisIMAdapter adapter, 
                         SshNdisPacket packet,
                         SshInterceptorProtocol protocol);
#endif /* _WIN32_WCE */

#ifdef __cplusplus
}
#endif

#endif /* SSH_WINCE_WAN_INTERCFACE */

