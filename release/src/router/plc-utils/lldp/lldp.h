/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   lldp.h - link level discovery protocol definitions and declarations;
 *
 *   this file contains defintions for TLV structures used in the 
 *   QCA Manifiest and in IEEE 802.1AB-2009 Link Layer Discovery
 *   Protocol;
 *
 *--------------------------------------------------------------------*/

#ifndef LLDP_HEADER
#define LLDP_HEADER

/*====================================================================*
 *   system header files;
 *--------------------------------------------------------------------*/

#include <stdint.h>

/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

#include "../tools/endian.h"
#include "../ether/ether.h"

/*====================================================================*
 *   constants and macros;
 *--------------------------------------------------------------------*/

#ifndef BROADCAST
#define BROADCAST "FF:FF:FF:FF:FF:FF"
#endif

#ifndef ETH_P_LLDP
#define ETH_P_LLDP 0x88CC
#endif

#define LLDP_NEAREST_BRIDGE "01:80:C2:00:00:0E"
#define LLDP_NEAREST_NON_TMPR_BRIDGE "01:80:C2:00:00:03"
#define LLDP_NEAREST_CUSTOMER_BRIDGE "01:80:C2:00:00:00"

#define LLDP_ADDRESSES 4
#define LLDP_TIMER (~0)
#define LLDP_BAD_MAC "Have '%s' but want MAC address"

#define TLV_TYPE_BITS 7
#define TLV_SIZE_BITS 9
#define TLV_TYPE_MASK (~(~0 << TLV_TYPE_BITS))
#define TLV_SIZE_MASK (~(~0 << TLV_SIZE_BITS))
#define TLV_TYPE(tlv) ((ntohs (tlv->head) >> TLV_SIZE_BITS) & TLV_TYPE_MASK)
#define TLV_SIZE(tlv) ((ntohs (tlv->head)) & TLV_SIZE_MASK)
#define TLV_DATA(tlv) ((char *)(tlv) + sizeof(tlv->head))
#define TLV_OS_DATA(tlv) (TLV_DATA (tlv) + 4)
#define TLV_HEAD(type, size) htons ((((uint16_t)(type) & TLV_TYPE_MASK) << TLV_SIZE_BITS) | ((uint16_t)(size) & TLV_SIZE_MASK))

#define TLV_IEEE_EOLLDPPDU 0
#define TLV_IEEE_CHASSIS_ID 1
#define TLV_IEEE_PORT_ID 2
#define TLV_IEEE_TIME_TO_LIVE 3
#define TLV_IEEE_PORT_DESCRIPTION 4
#define TLV_IEEE_SYSTEM_NAME 5
#define TLV_IEEE_SYSTEM_DESCRIPTION 6
#define TLV_IEEE_SYSTEM_CAPABILITIES 7
#define TLV_IEEE_MANAGEMENT_ADDRESS 8
#define TLV_IEEE_ORG_SPECIFIC 127

#define TLV_OS_MANUFACTURER 1
#define TLV_OS_HARDWARE_MODEL 2
#define TLV_OS_SERIAL_NUMBER 3
#define TLV_OS_HOST_MAC 4
#define TLV_OS_PLC_MAC 5
#define TLV_OS_WIFI_MAC 6
#define TLV_OS_WIFI_IP 7

/*====================================================================*
 *   variables;
 *--------------------------------------------------------------------*/

typedef struct tlv 

{ 
	uint16_t head; 
	uint8_t data [0]; 
} 

tlv; 
typedef struct tlv_id 

{ 
	uint8_t subtype; 
	uint8_t data [0]; 
} 

tlv_id; 
typedef struct tlv_os 

{ 
	uint16_t head; 
	uint8_t OUI [3]; 
	uint8_t subtype; 
	uint8_t data [0]; 
} 

tlv_os; 

/*====================================================================*
 *   functions;
 *--------------------------------------------------------------------*/

void * TLVPack (void const * memory, size_t extent, uint8_t type, uint16_t length, void const * value); 
void * TLVPackOS (void const * memory, size_t extent, uint8_t type, uint16_t length, void const * value); 
void * TLVPick (void const * memory, size_t extent, uint8_t type); 
void TLVPeek (void const * memory, size_t extent); 

/*====================================================================*
 *
 *--------------------------------------------------------------------*/

#endif



