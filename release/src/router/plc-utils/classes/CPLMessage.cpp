/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   CPLMessage.cpp - CPLMessage class definition;
 *
 *   the bootloader and firmware share some message types that return
 *   different status codes for the same error condition; differences 
 *   are enabled and disabled by constant CPLMESSAGE_BOOTLOADER;
 *
 *   VS_WR_MEM and VS_ST_MAC are only recognized by the Bootloader so
 *   we define CPLMESSAGE_BOOTLOADER to replace associated firmware 
 *   messages;
 *
 *   table entries must appear in ascending order by message type or
 *   lookups will be unreliable;
 * 
 *   Contributor(s):
 *	    Charles Maier <charles.maier@intellon.com>
 *
 *--------------------------------------------------------------------*/

#ifndef CPLMESSAGE_SOURCE
#define CPLMESSAGE_SOURCE

/*====================================================================*
 *   system header files;
 *--------------------------------------------------------------------*/

#include <iostream>

/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

#include "../classes/CPLMessage.hpp"
#include "../classes/ohomeplug.hpp"

/*====================================================================*
 *   class variables;
 *--------------------------------------------------------------------*/

struct CPLMessage::name CPLMessage::names [] =

{
	{
		0x0000,
		"CC_CCO_APPOINT"
	},
	{
		0x0004,
		"CC_BACKUP_APPOINT"
	},
	{
		0x0008,
		"CC_LINK_INFO"
	},
	{
		0x000C,
		"CC_HANDOVER"
	},
	{
		0x0010,
		"CC_HANDOVER_INFO"
	},
	{
		0x0014,
		"CC_DISCOVER_LIST"
	},
	{
		0x0018,
		"CC_LINK_NEW"
	},
	{
		0x001C,
		"CC_LINK_MOD"
	},
	{
		0x0020,
		"CC_LINK_SQZ"
	},
	{
		0x0024,
		"CC_LINK_REL"
	},
	{
		0x0028,
		"CC_DETECT_REPORT"
	},
	{
		0x002C,
		"CC_WHO_RU"
	},
	{
		0x0030,
		"CC_ASSOC"
	},
	{
		0x0034,
		"CC_LEAVE"
	},
	{
		0x0038,
		"CC_SET_TEI_MAP"
	},
	{
		0x003C,
		"CC_RELAY"
	},
	{
		0x0040,
		"CC_BEACON_RELIABILITY"
	},
	{
		0x0044,
		"CC_ALLOC_MOVE"
	},
	{
		0x0048,
		"CC_ACCESS_NEW"
	},
	{
		0x004C,
		"CC_ACCESS_REL"
	},
	{
		0x0050,
		"CC_DCPPC"
	},
	{
		0x0054,
		"CC_HP1_DET"
	},
	{
		0x0058,
		"CC_BLE_UPDATE"
	},
	{
		0x2000,
		"CP_PROXY_APPOINT"
	},
	{
		0x2004,
		"PH_PROXY_APPOINT"
	},
	{
		0x2008,
		"CP_PROXY_WAKE"
	},
	{
		0x4000,
		"NN_INL"
	},
	{
		0x4004,
		"NN_NEW_NET"
	},
	{
		0x4008,
		"NN_ADD_ALLOC"
	},
	{
		0x400C,
		"NN_REL_ALLOC"
	},
	{
		0x4010,
		"NN_REL_NET"
	},
	{
		0x6000,
		"CM_ASSOCIATED_STA"
	},
	{
		0x6004,
		"CM_ENCRYPTED_PAYLOAD"
	},
	{
		0x6008,
		"CM_SET_KEY"
	},
	{
		0x600C,
		"CM_GET_KEY"
	},
	{
		0x6010,
		"CM_SC_JOIN"
	},
	{
		0x6014,
		"CM_CHAN_EST"
	},
	{
		0x6018,
		"CM_TM_UPDATE"
	},
	{
		0x601C,
		"CM_AMP_MAP"
	},
	{
		0x6020,
		"CM_BRG_INFO"
	},
	{
		0x6024,
		"CM_CONN_NEW"
	},
	{
		0x6028,
		"CM_CONN_REL"
	},
	{
		0x602C,
		"CM_CONN_MOD"
	},
	{
		0x6030,
		"CM_CONN_INFO"
	},
	{
		0x6034,
		"CM_STA_CAP"
	},
	{
		0x6038,
		"CM_NW_INFO"
	},
	{
		0x603C,
		"CM_GET_BEACON"
	},
	{
		0x6040,
		"CM_HFID"
	},
	{
		0x6044,
		"CM__ERROR"
	},
	{
		0x6048,
		"CM_NW_STATS"
	},
	{
		0x8000,
		"MS_PB_ENC"
	},
	{
		0xA000,
		"VS_SW_VER"
	},
	{
		0xA004,
		"VS_WR_MEM"
	},
	{
		0xA008,
		"VS_RD_MEM"
	},
	{
		0xA00C,
		"VS_ST_MAC"
	},
	{
		0xA010,
		"VS_GET_NVM"
	},
	{
		0xA014,
		"VS_RSVD_1"
	},
	{
		0xA018,
		"VS_RSVD_2"
	},
	{
		0xA01C,
		"VS_RS_DEV"
	},
	{
		0xA020,
		"VS_WR_MOD"
	},
	{
		0xA024,
		"VS_RD_MOD"
	},
	{
		0xA028,
		"VS_MOD_NVM"
	},
	{
		0xA02C,
		"VS_WD_RPT"
	},
	{
		0xA030,
		"VS_LNK_STATS"
	},
	{
		0xA034,
		"VS_SNIFFER"
	},
	{
		0xA038,
		"VS_NW_INFO"
	},
	{
		0xA03C,
		"VS_RSVD_3"
	},
	{
		0xA040,
		"VS_CP_RPT"
	},
	{
		0xA044,
		"VS_ARPC"
	},
	{
		0xA048,
		"VS_FR_LBK"
	},
	{
		0xA04C,
		"VS_LBK_STAT"
	},
	{
		0xA050,
		"VS_SET_KEY"
	},
	{
		0xA054,
		"VS_MFG_STRING"
	},
	{
		0xA058,
		"VS_RD_CBLOCK"
	},
	{
		0xA05C,
		"VS_SET_SDRAM"
	},
	{
		0xA060,
		"VS_HOST_ACTION"
	},
	{
		0xA064,
		"VS_RSVD_7"
	},
	{
		0xA068,
		"VS_OP_ATTRIBUTES"
	},
	{
		0xA06C,
		"VS_ENET_SETTINGS"
	},
	{
		0xA070,
		"VS_TONE_MAP_CHAR"
	},
	{
		0xA074,
		"VS_NW_INFO_STATS"
	},
	{
		0xA078,
		"VS_SLAVE_MEM"
	},
	{
		0xA07C,
		"VS_FAC_DEFAULTS"
	},
	{
		0xA080,
		"VS_PTS_NVM"
	},
	{
		0xA084,
		"VS_MCAST_INFO"
	},
	{
		0xA088,
		"VS_CLASSIFICATION"
	},
	{
		0xA08C,
		"VS_DIAG_STAGE"
	},
	{
		0xA090,
		"VS_RX_TONE_MAP_CHAR"
	},
	{
		0xA094,
		"VS_SET_LED_BEHAVIOR"
	},
	{
		0xA098,
		"VS_SET_SDRAM_DENALI"
	},
	{
		0xA09C,
		"VS_MDIO_CMD"
	},
	{
		0xA0A0,
		"VS_SLAVE_REG"
	},
	{
		0xA0A4,
		"VS_BANDWIDTH_LIMITING"
	},
	{
		0xA0A8,
		"VS_SNID_OPERATION"
	},
	{
		0xA0AC,
		"VS_NN_MITIGATE"
	},
	{
		0xA0B0,
		"VS_MODULE_OPERATION"
	},
	{
		0xA0B4,
		"VS_DIAG_NETWORK_PROBE"
	},
	{
		0xA0B8,
		"VS_PL_LINK_STATUS"
	},
	{
		0xA0BC,
		"VS_GPIO_STATE_CHANGE",
	},
	{
		0xA0C0,
		"VS_CONN_ADD"
	},
	{
		0xA0C4,
		"VS_CONN_MOD"
	},
	{
		0xA0C8,
		"VS_CONN_REL"
	},
	{
		0xA0CC,
		"VS_CONN_INFO"
	},
	{
		0xA0D0,
		"VS_MULTIPORT_LNK_STA"
	},
	{
		0xA0D0,
		"VS_CUSTOM_INFO"
	},
	{
		0xA0D0,
		"VS_EM_ID_TABLE"
	}
};

/*
 *   table entries must appear in ascending order by message type then
 *   message status code;
 */

struct CPLMessage::code CPLMessage::mcodes [] =

{

#ifdef CPLMESSAGE_BOOTLOADER

	{
		0xA005,
		0x14,
		"Bad Checksum"
	},
	{
		0xA005,
		0x1C,
		"Bad Length"
	},
	{
		0xA005,
		0x38,
		"Bad Address"
	},
	{
		0xA005,
		0x3C,
		"Bad Data Alignment"
	},

#else

	{
		0xA005,
		0x10,
		"Bad Address"
	},
	{
		0xA005,
		0x14,
		"Bad Length"
	},

#endif

	{
		0xA009,
		0x10,
		"Bad Offset"
	},
	{
		0xA009,
		0x14,
		"Bad Length"
	},
	{
		0xA00D,
		0x10,
		"Bad Module ID"
	},

#ifdef CPLMESSAGE_BOOTLOADER

	{
		0xA00D,
		0x14,
		"Bad Image Checksum"
	},
	{
		0xA00D,
		0x1C,
		"Bad Image Length"
	},
	{
		0xA00D,
		0x38,
		"Bad Image Load Address"
	},
	{
		0xA00D,
		0x3C,
		"Bad Data Alignment"
	},
	{
		0xA00D,
		0x40,
		"Bad Start Address"
	},

#else

	{
		0xA00D,
		0x14,
		"Bad Command"
	},

#endif

	{
		0xA011,
		0x10,
		"No NVRAM"
	},
	{
		0xA01D,
		0x01,
		"Device Failed to Reset"
	},
	{
		0xA01D,
		0x02,
		"Device Busy"
	},
	{
		0xA021,
		0x10,
		"Bad Module"
	},
	{
		0xA021,
		0x12,
		"Bad Length"
	},
	{
		0xA021,
		0x14,
		"Bad Checksum"
	},
	{
		0xA021,
		0x20,
		"Bad Offset"
	},
	{
		0xA021,
		0x40,
		"Operation Blocked"
	},
	{
		0xA021,
		0x50,
		"Fail to lock NVM"
	},
	{
		0xA025,
		0x10,
		"Bad Module"
	},
	{
		0xA025,
		0x12,
		"Bad Length"
	},
	{
		0xA025,
		0x14,
		"Bad Checksum"
	},
	{
		0xA025,
		0x20,
		"Unexpected Offset"
	},
	{
		0xA025,
		0x50,
		"Fail to lock NVM"
	},
	{
		0xA025,
		0x58,
		"DAK Mismatch"
	},
	{
		0xA029,
		0x10,
		"Bad Module"
	},
	{
		0xA029,
		0x14,
		"No NVRAM"
	},
	{
		0xA029,
		0x18,
		"Not enough NVRAM"
	},
	{
		0xA029,
		0x1C,
		"Bad Header Checksum"
	},
	{
		0xA029,
		0x20,
		"Bad Image Checksum"
	},
	{
		0xA029,
		0x24,
		"Bad PIB"
	},
	{
		0xA029,
		0x28,
		"Softloader Too Large"
	},
	{
		0xA029,
		0x2C,
		"Firmware Too Large"
	},
	{
		0xA029,
		0x42,
		"Firmware without PIB"
	},
	{
		0xA029,
		0x44,
		"Bad PIB Checksum"
	},
	{
		0xA029,
		0x46,
		"DAK Not Zero"
	},
	{
		0xA029,
		0x48,
		"DAC Mismatch"
	},
	{
		0xA029,
		0x50,
		"MFG HFID Mismatch"
	},
	{
		0xA029,
		0x52,
		"Bad Bind Factory Defaults"
	},
	{
		0xA029,
		0x54,
		"Bad Bind Template PIB"
	},
	{
		0xA029,
		0x56,
		"Bad Bind Working PIB"
	},
	{
		0xA029,
		0x58,
		"Error Computing PIB Checksum"
	},
	{
		0xA029,
		0x5A,
		"Bad Bind Scratch PIB"
	},
	{
		0xA029,
		0x5C,
		"No Firmware Version"
	},
	{
		0xA029,
		0x5E,
		"Version Mismatch"
	},
	{
		0xA029,
		0x60,
		"Bad 01PIB Checksum"
	},
	{
		0xA029,
		0x62,
		"Bad 02PIB Checksum"
	},
	{
		0xA029,
		0x64,
		"Bad WPIB Checksum"
	},
	{
		0xA029,
		0x66,
		"Illegal Firmware Revision"
	},
	{
		0xA031,
		0x01,
		"Bad Control"
	},
	{
		0xA031,
		0x02,
		"Bad Direction"
	},
	{
		0xA031,
		0x10,
		"Bad Link ID"
	},
	{
		0xA031,
		0x20,
		"Bad MAC Address"
	},
	{
		0xA035,
		0x10,
		"Bad Control"
	},
	{
		0xA049,
		0x20,
		"Invalid Duration"
	},
	{
		0xA049,
		0x12,
		"Invalid Length"
	},
	{
		0xA049,
		0x24,
		"Already Set"
	},
	{
		0xA051,
		0x10,
		"Bad PEKS"
	},
	{
		0xA051,
		0x11,
		"Bad PIB"
	},
	{
		0xA051,
		0x12,
		"Bad PEKS Encrypted Payload"
	},
	{
		0xA051,
		0x13,
		"Remote Failure"
	},
	{
		0xA051,
		0x14,
		"Bad Remote Response"
	},
	{
		0xA051,
		0x15,
		"Remote Decryption Failed"
	},
	{
		0xA059,
		0x10,
		"No NVRAM"
	},
	{
		0xA05D,
		0x30,
		"Bad Checksum"
	},
	{
		0xA05D,
		0x34,
		"BIST Failed"
	},
	{
		0xA065,
		0x10,
		"No NVRAM"
	},
	{
		0xA069,
		0x02,
		"Not Supported"
	},
	{
		0xA06D,
		0x01,
		"Bad Control"
	},
	{
		0xA06D,
		0x02,
		"Success Write"
	},
	{
		0xA06D,
		0x03,
		"Bad Write Parameter"
	},
	{
		0xA071,
		0x01,
		"Bad MAC Address"
	},
	{
		0xA071,
		0x02,
		"Bad TMSLOT"
	},
	{
		0xA081,
		0x10,
		"Bad Module ID"
	},
	{
		0xA081,
		0x14,
		"No Flash Memory"
	},
	{
		0xA081,
		0x18,
		"Not Enough Flash Memory"
	},
	{
		0xA081,
		0x1C,
		"Bad Image Header Checksum"
	},
	{
		0xA081,
		0x20,
		"Bad Image Checksum"
	},
	{
		0xA081,
		0x24,
		"Invalid PIB"
	},
	{
		0xA081,
		0x28,
		"Softloader Too Large"
	},
	{
		0xA081,
		0x2C,
		"Firmware File Too Large"
	},
	{
		0xA081,
		0x42,
		"Firmware without PIB"
	},
	{
		0xA081,
		0x44,
		"Bad PIB Checksum"
	},
	{
		0xA081,
		0x46,
		"DAK Not Zero"
	},
	{
		0xA081,
		0x48,
		"DAC Mismatch"
	},
	{
		0xA081,
		0x50,
		"MFG HFID Mismatch"
	},
	{
		0xA081,
		0x52,
		"Bad Bind Factory Defaults"
	},
	{
		0xA081,
		0x54,
		"Bad Bind Template PIB"
	},
	{
		0xA081,
		0x56,
		"Bad Bind Working PIB"
	},
	{
		0xA081,
		0x58,
		"DAK Mismatch"
	},
	{
		0xA081,
		0x5A,
		"Failed to Lock NVM"
	},
	{
		0xA089,
		0x01,
		"Bad Control"
	},
	{
		0xA089,
		0x02,
		"Bad Volatility"
	},
	{
		0xA089,
		0x03,
		"Bad Classifier"
	},
	{
		0xA089,
		0x04,
		"Classifier table full"
	},
	{
		0xA089,
		0x05,
		"Classifier exists with different action"
	},
	{
		0xA089,
		0x06,
		"Classifier not found"
	},
	{
		0xA08D,
		0x10,
		"Refused"
	},
	{
		0xA08D,
		0x11,
		"Refused"
	},
	{
		0xA08F,
		0x10,
		"Error"
	},
	{
		0xA091,
		0x01,
		"Bad MAC"
	},
	{
		0xA091,
		0x02,
		"Bad Slot"
	},
	{
		0xA099,
		0x01,
		"Misaligned Address"
	},
	{
		0xA099,
		0x02,
		"Misaligned Entry Point"
	},
	{
		0xA099,
		0x04,
		"Foreign Entry Point"
	},
	{
		0xA099,
		0x08,
		"Bad Checksum"
	},
	{
		0xA099,
		0x10,
		"Out of Memory"
	},
	{
		0xA099,
		0x20,
		"Offset/Length Mismatch"
	},
	{
		0xA099,
		0x40,
		"Memory not Operational"
	},
	{
		0xA099,
		0x80,
		"Bad Length"
	},
	{
		0xA0B1,
		0x10,
		"Invalid Number of Module Operations"
	},
	{
		0xA0B1,
		0x11,
		"Invalid Module Operation ID"
	},
	{
		0xA0B1,
		0x12,
		"Invalid Session ID"
	},
	{
		0xA0B1,
		0x13,
		"Invalid Num Module Operation Specific Data"
	},
	{
		0xA0B1,
		0x14,
		"Module ID not found"
	},
	{
		0xA0B1,
		0x15,
		"Invalid Module Length"
	},
	{
		0xA0B1,
		0x16,
		"Invalid Module Index"
	},
	{
		0xA0B1,
		0x17,
		"Invalid Data Length"
	},
	{
		0xA0B1,
		0x18,
		"Unexpected Offset"
	},
	{
		0xA0B1,
		0x19,
		"Invalid Commit Action Code"
	},
	{
		0xA0B1,
		0x1A,
		"Operation Block by previous Commit"
	},
	{
		0xA0B1,
		0x1B,
		"Duplicate Module ID/SubID"
	},
	{
		0xA0B1,
		0x1C,
		"Invalid Module ID/SubID"
	},
	{
		0xA0B1,
		0x20,
		"NVM not Present"
	},
	{
		0xA0B1,
		0x21,
		"NVM too small"
	},
	{
		0xA0B1,
		0x22,
		"Unsupported Flash"
	},
	{
		0xA0B1,
		0x23,
		"Fail to lock NVM"
	},
	{
		0xA0B1,
		0x24,
		"Unsupported Flash"
	},
	{
		0xA0B1,
		0x30,
		"Invalid Module checksum"
	},
	{
		0xA0B1,
		0x31,
		"Individual Module Error"
	},
	{
		0xA0B1,
		0x32,
		"Expected module not available in NVM or memory"
	},
	{
		0xA0B1,
		0x40,
		"Invalid Header Checksum"
	},
	{
		0xA0B1,
		0x41,
		"Invalid FW Checksum"
	},
	{
		0xA0B1,
		0x42,
		"Invalid FW Checksum"
	},
	{
		0xA0B1,
		0x43,
		"Soft-loader is too large"
	},
	{
		0xA0B1,
		0x44,
		"Invalid PIB Checksum"
	},
	{
		0xA0B1,
		0x45,
		"No Firmware Version"
	},
	{
		0xA0B1,
		0x46,
		"FW Commit but no PIB"
	},
	{
		0xA0B1,
		0x47,
		"Version Mismatch"
	},
	{
		0xA0B1,
		0x50,
		"Invalid PIB"
	},
	{
		0xA0B1,
		0x51,
		"DAK not zero"
	},
	{
		0xA0B1,
		0x52,
		"MAC mismatch"
	},
	{
		0xA0B1,
		0x53,
		"DAK mismatch"
	},
	{
		0xA0B1,
		0x54,
		"Mfg HFID mismatch"
	},
	{
		0xA0B1,
		0x55,
		"Bad bind to FAC. Default PIB"
	},
	{
		0xA0B1,
		0x56,
		"Bad bind to template PIB"
	},
	{
		0xA0B1,
		0x57,
		"Bad bind to working PIB"
	},
	{
		0xA0B1,
		0x58,
		"Bad Bind Scratch PIB"
	},
	{
		0xA0B1,
		0x59,
		"Error Generating Checksum Scratch PIB"
	},
	{
		0xA0B1,
		0x5a,
		"Checksum Error O1 PIB"
	},
	{
		0xA0B1,
		0x5b,
		"Checksum Error O2 PIB"
	},
	{
		0xA0B1,
		0x5c,
		"Checksum Error Working PIB"
	},
	{
		0xA0C1,
		0x03,
		"Invalid Classifier"
	},
	{
		0xA0C1,
		0x04,
		"Already too many Classifiers"
	},
	{
		0xA0C1,
		0x05,
		"Classifier exists with different Classification Action"
	},
	{
		0xA0C1,
		0x07,
		"Link Already in Progress"
	},
	{
		0xA0C1,
		0x08,
		"Invalid Configuration"
	},
	{
		0xA0C1,
		0x10,
		"Invalid CSPEC Version"
	},
	{
		0xA0C1,
		0x11,
		"Invalid CSPEC"
	},
	{
		0xA0C1,
		0x20,
		"Out of Local Resources"
	},
	{
		0xA0C1,
		0x30,
		"Invalid Peer"
	},
	{
		0xA0C1,
		0x31,
		"Peer Confirm Timed out"
	},
	{
		0xA0C1,
		0x40,
		"Peer rejection"
	},
	{
		0xA0C5,
		0x01,
		"Invalid Modification Control"
	},
	{
		0xA0C5,
		0x06,
		"CID Not Found"
	},
	{
		0xA0C5,
		0x07,
		"Link Update in Progress, try again later"
	},
	{
		0xA0C9,
		0x06,
		"CID Not Found"
	},
	{
		0xA0C9,
		0x07,
		"Link Update in Progress. Try again later"
	},
	{
		0xA0C9,
		0x31,
		"Peer Confirm Timed out"
	},
	{
		0xA0CD,
		0x01,
		"Invalid Request Type"
	},
	{
		0xA0CD,
		0x04,
		"Too Many Requests",
	},
	{
		0xA0CD,
		0x06,
		"CID Not Found"
	},
	{
		0xA0CD,
		0x10,
		"Invalid CSPEC Version"
	},
	{
		0xA0CD,
		0x31,
		"Peer Confirm Timed out"
	}
};

char const * CPLMessage::modes [] = 
{
	"REQ",
	"CNF",
	"IND",
	"RSP" 
};

/*====================================================================*
 *
 *   char const * CPLMessage::MessageName (uint16_t type) const;
 *
 *   return the HomePlug AV or Intellon Management Message name for
 *   a given message type;
 *
 *--------------------------------------------------------------------*/

char const * CPLMessage::MessageName (uint16_t type) const

{
	size_t lower = 0;
	size_t upper = sizeof (CPLMessage::names)/sizeof (struct CPLMessage::name);
	type &= MMTYPE_MODE;
	while (lower < upper)
	{
		size_t index = (lower + upper) >> 1;
		signed order = type - names [index].type;
		if (order < 0)
		{
			upper = index - 0;
			continue;
		}
		if (order > 0)
		{
			lower = index + 1;
			continue;
		}
		return (CPLMessage::names [index].name);
	}
	return ("UNKNOWN_MME");
}

/*====================================================================*
 *
 *   char const * CPLMessage::MessageMode (uint16_t type) const;
 *
 *--------------------------------------------------------------------*/

char const * CPLMessage::MessageMode (uint16_t type) const

{
	return (CPLMessage::modes [type & MMTYPE_MODE]);
}

/*====================================================================*
 *
 *   char const * MessageErrorText (uint16_t type, uint8_t code) const
 *
 *   return the text for a given Intellon Management Message type
 *   and status code; search is done using a nested binary search;
 *
 *--------------------------------------------------------------------*/

char const * CPLMessage::MessageErrorText (uint16_t type, uint8_t code) const

{
	size_t lower = 0;
	size_t upper = sizeof (CPLMessage::mcodes) / sizeof (struct CPLMessage::code);
	size_t limit = upper;
	while (lower < upper)
	{
		size_t index = (lower + upper) >> 1;
		signed order = type - CPLMessage::mcodes [index].type;
		if (order < 0)
		{
			upper = index - 0;
			continue;
		}
		if (order > 0)
		{
			lower = index + 1;
			continue;
		}
		for (lower = index; lower > 0; lower--)
		{
			if (CPLMessage::mcodes [lower - 1].type != CPLMessage::mcodes [index].type)
			{
				break;
			}
		}
		for (upper = index; upper < limit; upper++)
		{
			if (CPLMessage::mcodes [upper + 0].type != CPLMessage::mcodes [index].type)
			{
				break;
			}
		}
		while (lower < upper)
		{
			index = (lower + upper) >> 1;
			order = code - CPLMessage::mcodes [index].code;
			if (order < 0)
			{
				upper = index - 0;
				continue;
			}
			if (order > 0)
			{
				lower = index + 1;
				continue;
			}
			return (CPLMessage::mcodes [index].text);
		}
	}
	return ((code)? ("Failure"):("Success"));
}

/*====================================================================*
 *
 *   CPLMessage & CPLMessage::CVS ();
 *
 *   print names table on stdout in CVS format; this methods is not
 *   used by application software; it exists for maintenance only;
 *
 *--------------------------------------------------------------------*/

CPLMessage & CPLMessage::CSV ()

{
	unsigned code = 0;
	std::cout << "Name,Type,Code,Text" << std::endl;
	while (code < (sizeof (CPLMessage::mcodes) / sizeof (struct CPLMessage::code)))
	{
		std::cout << CPLMessage::MessageName (CPLMessage::mcodes [code].type) << ",";
		std::printf ("0x%04X,", CPLMessage::mcodes [code].type);
		std::printf ("0x%02X,", CPLMessage::mcodes [code].code);
		std::cout << CPLMessage::mcodes [code].text << std::endl;
		code++;
	}
	return (*this);
}

/*====================================================================*
 *
 *   CPLMessage & CPLMessage::HTML ();
 *
 *   print message table on stdout in HTML format; this method is 
 *   not used by application software; it exists for maintenance only;
 *
 *--------------------------------------------------------------------*/

CPLMessage & CPLMessage::HTML ()

{
	unsigned code = 0;
	std::cout << "<table>" << std::endl;
	std::cout << "\t<tr>" << std::endl;
	std::cout << "\t\t<th>Name</th>" << std::endl;
	std::cout << "\t\t<th>Type</th>" << std::endl;
	std::cout << "\t\t<th>Code</th>" << std::endl;
	std::cout << "\t\t<th>Text</th>" << std::endl;
	std::cout << "\t\t</tr>" << std::endl;
	while (code < (sizeof (CPLMessage::mcodes) / sizeof (struct CPLMessage::code)))
	{
		std::cout << "\t<tr>" << std::endl;
		std::cout << "\t\t<td>" << CPLMessage::MessageName (CPLMessage::mcodes [code].type) << "</td>" << std::endl;
		printf ("\t\t<td>0x%04X</td>\n", CPLMessage::mcodes [code].type);
		printf ("\t\t<td>0x%02X</td>\n", CPLMessage::mcodes [code].code);
		std::cout << "\t\t<td>" << CPLMessage::mcodes [code].text << "</td>" << std::endl;;
		std::cout << "\t\t</tr>" << std::endl;
		code++;
	}
	std::cout << "\t</table>" << std::endl;
	return (*this);
}

/*====================================================================*
 *
 *   CPLMessage ()
 *
 *--------------------------------------------------------------------*/

CPLMessage::CPLMessage ()

{
	return;
}

/*====================================================================*
 *
 *   ~CPLMessage ()
 *
 *--------------------------------------------------------------------*/

CPLMessage::~CPLMessage ()

{
	return;
}

/*====================================================================*
 *   end definition;
 *--------------------------------------------------------------------*/

#endif

