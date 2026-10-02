/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file contains definitions for SSH Interceptor object.
*/

#ifndef SSH_INTERCEPTOR_I_H
#define SSH_INTERCEPTOR_I_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*--------------------------------------------------------------------------
  INCLUDE FILES
  --------------------------------------------------------------------------*/

#define HAS_DELAYED_SEND_THREAD  
#ifdef _WIN32_WCE
#define SSH_INTERCEPTOR_PER_CPU_PACKET_POOL_SIZE    80
#define SSH_INTERCEPTOR_PER_CPU_BUFFER_POOL_SIZE    160
#else
#define HAS_IEEE802_3_PASSTHRU
#define HAS_INTERFACE_NAME_MAPPINGS
#define SSH_INTERCEPTOR_PER_CPU_PACKET_POOL_SIZE    800
#define SSH_INTERCEPTOR_PER_CPU_BUFFER_POOL_SIZE    1600
#endif /* _WIN32_WCE */


/* This compilation flag must be defined for NDIS intermediate driver */
#define SSH_IM_INTERCEPTOR

#include "interceptor_i_common.h"
#include "ndis5_packet_pool.h"
#ifdef _WIN32_WCE
#include "event.h"
#endif /* _WIN32_WCE */
#ifdef DEBUG_LIGHT
#include "ndis_render.h"
#endif /* DEBUG_LIGHT */

/*--------------------------------------------------------------------------
  DEFINITIONS
  --------------------------------------------------------------------------*/

#define SSH_DELAYED_SEND_THREAD_ID    (SSH_LAST_COMMON_THREAD_ID + 1)
#define SSH_ADDRESS_CHANGE_THREAD_ID  (SSH_LAST_COMMON_THREAD_ID + 2)
#define SSH_ROUTE_CHANGE_THREAD_ID    (SSH_LAST_COMMON_THREAD_ID + 3)

#ifdef _WIN32_WCE

typedef UINT SSH_IRQL;

#define SSH_PASSIVE_LEVEL      0
#define SSH_APC_LEVEL          1
#define SSH_DISPATCH_LEVEL     2

#define SSH_GET_IRQL()         SSH_PASSIVE_LEVEL

#define SSH_RAISE_IRQL(n,o)    \
do                             \
{                              \
  *(o) = SSH_PASSIVE_LEVEL;    \
} while (0);

#define SSH_LOWER_IRQL(n)      \
do                             \
{                              \
} while (0); 

#define QUICKSEC_REGISTRY_PATH          L"Comm\\QSEC"

#define QUICKSEC_MINIPORT_PREFIX        L"QSEC\\"
#define QUICKSEC_MINIPORT_PREFIX_LEN    5
#define ASYNCMAC_MINIPORT_PREFIX        L"ASYNCMAC"
#define ASYNCMAC_MINIPORT_PREFIX_LEN    8
#define PPTP_MINIPORT_PREFIX            L"PPTP"
#define PPTP_MINIPORT_PREFIX_LEN        4
#define L2TP_MINIPORT_PREFIX            L"L2TP"
#define L2TP_MINIPORT_PREFIX_LEN        4
#define WWAN_MINIPORT_PREFIX            L"WWAN"
#define WWAN_MINIPORT_PREFIX_LEN        4
#define PPPOE_MINIPORT_PREFIX           L"PPPOE"
#define PPPOE_MINIPORT_PREFIX_LEN       5

#else

typedef KIRQL SSH_IRQL;

#define SSH_PASSIVE_LEVEL      PASSIVE_LEVEL
#define SSH_APC_LEVEL          APC_LEVEL
#define SSH_DISPATCH_LEVEL     DISPATCH_LEVEL

#define SSH_GET_IRQL()         KeGetCurrentIrql()
#define SSH_RAISE_IRQL(n,o)    do { KeRaiseIrql((n),(o)); } while (0);
#define SSH_LOWER_IRQL(n)      do { KeLowerIrql((n)); } while (0);

#endif /* _WIN32_WCE */

/* NDIS REV. 4.0 - */  
#define SSH_MAJOR_NDIS_VERSION        0x04
#define SSH_MINOR_NDIS_VERSION        0x00

/* NDIS_MAC_OPTION_8021Q_VLAN not defined in Win2K DDK */
#ifndef NDIS_MAC_OPTION_8021Q_VLAN
#define NDIS_MAC_OPTION_8021Q_VLAN       0x00000200
#endif /* NDIS_MAC_OPTION_8021Q_VLAN */

/* Macro for setting IP configuration refresh request */
#ifdef _WIN32_WCE

/* Replace default SSH_IP_REFRESH_REQUEST() macro with Windows CE specific
   one. */
#undef SSH_IP_REFRESH_REQUEST
#define SSH_IP_REFRESH_REQUEST(interceptor)                       \
do                                                                \
{                                                                 \
  ssh_event_signal(                                               \
   ((SshNdisIMInterceptor)interceptor)->ip_config_change_event);  \
}                                                                 \
while (0);

#endif /* _WIN32_WCE */

/*--------------------------------------------------------------------------
  TYPE DEFINITIONS
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  SshNdisIMInterceptor

  "Controller" object that contains the Windows 2000 specific global 
  attributes, adapter and network connection lists, transform engine and 
  I/O device for policy manager communication.
  --------------------------------------------------------------------------*/

typedef struct SshNdisIMInterceptorRec
{
  /* Generic interceptor object. DO NOT move! */
  SshInterceptorStruct ;

  /* Interceptor initialization completed (i.e. DriverEntry returned) */
  BOOLEAN init_complete;

#ifdef _WIN32_WCE
  NDIS_HANDLE wan_protocol_handle;
#else
  /* Number of network providers initialized */
  SshUInt16 net_providers;

  /* Handle to TDI interface */
  HANDLE tdi_handle;
#endif _WIN32_WCE
  
  /* Handles that are global to our driver */
  NDIS_HANDLE miniport_handle;
  NDIS_HANDLE protocol_handle;

#ifdef _WIN32_WCE
  SshTaskStruct ip_addr_change_thread;
  SshTaskStruct ip_route_change_thread;
  SshEvent ip_addr_change_event;
  SshEvent ip_route_change_event;
  SshEvent ip_config_change_event;
#endif /* _WIN32_WCE */

} SshNdisIMInterceptorStruct, *SshNdisIMInterceptor;

#include "adapter.h"

/*--------------------------------------------------------------------------
  MACROS AND INLINE FUNCTIONS
  --------------------------------------------------------------------------*/

/*-------------------------------------------------------------------------
  ssh_interceptor_register_stack_notifications()
  
  Registers some callbacks with IP protocol stack so that we get 
  notifications from some transport protocol specific events.
  
  Arguments:
  interceptor - SshInterceptor object
  enable - register/deregister flag
  
  Returns:
  NDIS_STATUS_SUCCESS - operation succeeded
  NDIS_STATUS_FAILURE - otherwise

  Notes:
  ------------------------------------------------------------------------*/
NDIS_STATUS
ssh_interceptor_register_stack_notifications(SshNdisIMInterceptor interceptor,
                                             BOOLEAN enable);


/*--------------------------------------------------------------------------
  EXPORTED FUNCTIONS
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  Unload handler for SSH Interceptor driver.
  --------------------------------------------------------------------------*/
#ifdef _WIN32_WCE
void DriverUnload(PDRIVER_OBJECT driver_object);
#else
DRIVER_UNLOAD DriverUnload;
#endif /* _WIN32_WCE */

/*--------------------------------------------------------------------------
  Sends the given packet to IPSec engine.
  --------------------------------------------------------------------------*/
void
ssh_interceptor_send_to_engine(SshNdisIMInterceptor interceptor,
                               SshNdisIMAdapter adapter,
                               SshNdisPacket packet);

/*--------------------------------------------------------------------------
  Processes all packets previously enqued by the current CPU.

  This function must be called after engine callback returns (either once
  per each captured packet or when the last packet of multi-packet send
  receive operation has been sent to engine). 
  --------------------------------------------------------------------------*/
void
ssh_interceptor_process_enqueued_packets(SshNdisIMInterceptor interceptor, 
                                         SshCpuContext cpu_ctx);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* SSH_INTERCEPTOR_I_H */
