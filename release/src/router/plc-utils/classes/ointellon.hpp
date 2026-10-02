/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   ointellon.hpp - ointellon class declaration;
 *
 *   implement an Intellon vendor specific HomePlug AV message header
 *   consisting of an Ethernet header, message version, message type 
 *   and vendor OUI; provide methods to encode and decode external 
 *   memory; 
 *
 *   Contributor(s): 
 *	    Charles Maier <charles.maier@intellon.com>
 *
 *--------------------------------------------------------------------*/

#ifndef oINTELLON_HEADER
#define oINTELLON_HEADER

/*====================================================================*
 *   system header files;
 *--------------------------------------------------------------------*/

#include <stdint.h>

/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

#include "../classes/stdafx.hpp"
#include "../classes/oethernet.hpp"
#include "../classes/ohomeplug.hpp"

/*====================================================================*
 *   header constants;
 *--------------------------------------------------------------------*/

#define oINTELLON_MTYPE 0x88E1
#define oINTELLON_MMV 0x00
#define oINTELLON_MMTYPE 0xA000
#define oINTELLON_FMI 0x0000

#define oINTELLON_LOCALCAST "00:B0:52:00:00:01"
#define oINTELLON_BLOCKSIZE 1024

#define oINTELLON_BAD_OFFSET "Bad Offset"
#define oINTELLON_BAD_LENGTH "Bad Length"

/*====================================================================*
 * Intellon Manufacturer Specific Management Message Types;
 *--------------------------------------------------------------------*/

#define MS_PB_ENC 0x8000

/*====================================================================*
 *  Intellon Vendor Specific Management Message Types;
 *--------------------------------------------------------------------*/

#define VS_SW_VER 0xA000
#define VS_WR_MEM 0xA004
#define VS_RD_MEM 0xA008
#define VS_ST_MAC 0xA00C
#define VS_GET_NVM 0xA010
#define VS_RSVD_1 0xA014
#define VS_RSVD_2 0xA018
#define VS_RS_DEV 0xA01C
#define VS_WR_MOD 0xA020
#define VS_RD_MOD 0xA024
#define VS_MOD_NVM 0xA028
#define VS_WD_RPT 0xA02C
#define VS_LNK_STATS 0xA030
#define VS_SNIFFER 0xA034
#define VS_NW_INFO 0xA038
#define VS_RSVD_3 0xA03C
#define VS_CP_RPT 0xA040
#define VS_ARPC 0xA044
#define VS_RSVD_4 0xA044
#define VS_FR_LBK 0xA048
#define VS_LBK_STAT 0xA04C
#define VS_SET_KEY 0xA050
#define VS_MFG_STRING 0xA054
#define VS_RD_CBLOCK 0xA058
#define VS_SET_SDRAM 0xA05C
#define VS_HST_ACTION 0xA060
#define VS_RSVD_7 0xA064
#define VS_OP_ATTRIBUTES 0xA068
#define VS_ENET_SETTINGS 0xA06C
#define VS_TONE_MAP_CHAR 0xA070
#define VS_NW_INFO_STATS 0xA074
#define VS_RSVD_8 0xA078
#define VS_FAC_DEFAULT 0xA07C
#define VS_RSVD_9 0xA080
#define VS_RSVD_10 0xA084
#define VS_CLASSIFICATION 0xA088
#define VS_RSVD_11 0xA08C
#define VS_RX_TONE_MAP_CHAR 0xA090
#define VS_SET_LED_BEHAVIOR 0xA094
#define VS_RSVD_12 0xA098
#define VS_RSVD_13 0xA09C
#define VS_RSVD_14 0xA0A0
#define VS_RSVD_15 0xA0A4
#define VS_RSVD_16 0xA0A8
#define VS_NN_MITIGATE 0xA0AC
#define VS_MODULE_OPERATION 0xA0B0
#define VS_DIAG_NETWORK_PROBE 0xA0B4
#define VS_PL_LINK_STATUS 0xA0B8
#define VS_GPIO_STATE_CHANGE 0xA0BC
#define VS_ADD_CONN 0xA0C0
#define VS_MOD_CONN 0xA0C4
#define VS_REL_CONN 0xA0C8
#define VS_CON_INFO 0xA0CC

/*====================================================================*
 *   module codes for VS_RD_MOD, VS_WR_MOD and VS_MOD_NVM;
 *--------------------------------------------------------------------*/

#define VS_MODULE_MAC   (1 << 0)
#define VS_MODULE_PIB   (1 << 1)
#define VS_MODULE_ALL   (VS_MODULE_MAC|VS_MODULE_PIB)
#define VS_MODULE_FORCE (1 << 4)

#define VS_MODULE_OPERATION_MDIO  0x1000
#define VS_MODULE_OPERATION_SL    0x8000
#define VS_MODULE_OPERATION_MAC   0x8001
#define VS_MODULE_OPERATION_PIB   0x8002

/*====================================================================*
 *   class datatypes;
 *--------------------------------------------------------------------*/

typedef unsigned char byte;

/*====================================================================*
 *   class declaration;
 *--------------------------------------------------------------------*/

class __declspec (dllexport) ointellon: public ohomeplug 

{
public:
	ointellon (void);
	virtual ~ ointellon (void);
	size_t HeaderLength (void) const;
	size_t BufferLength (size_t extent) const;
	void * ExportHeader (void * memory) const;
	void const * ImportHeader (void const * memory);
	uint8_t const * VendorOUI (void) const;
	char const * VendorOUIString (void) const;
	ointellon & Print ();
	static const byte LocalcastAddress [ETHER_ADDR_LEN];
private:
	uint8_t moui [ETHER_ADDR_LEN >> 1];
};

/*====================================================================*
 *   end declaration;
 *--------------------------------------------------------------------*/

#endif

