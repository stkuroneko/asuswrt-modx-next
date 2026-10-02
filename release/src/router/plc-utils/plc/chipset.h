/****************************************************************************
#    Copyright (c) 2020 Qualcomm Technologies, Inc. 
#    All Rights Reserved. 
#    Confidential and Proprietary - Qualcomm Technologies, Inc. 
#**********************************************************************       
#    2013 Qualcomm Atheros, Inc. 
#                    
****************************************************************************/

#ifndef CHIPSET_HEADER
#define CHIPSET_HEADER

/*====================================================================*
 *   system header files;
 *--------------------------------------------------------------------*/

#include <stdint.h>

/*====================================================================*
 *   constants;
 *--------------------------------------------------------------------*/

#define PLCHIPSET "PLCDEVICE"

/*====================================================================*
 *   chipset codes returned in VS_SW_VER MDEVICE_CLASS field;
 *--------------------------------------------------------------------*/

#define CHIPSET_UNKNOWN 0x00
#define CHIPSET_INT6000A1 0x01
#define CHIPSET_INT6300A0 0x02
#define CHIPSET_INT6400A0 0x03
#define CHIPSET_AR7400A0 0x04
#define CHIPSET_AR6405A0 0x05
#define CHIPSET_PANTHER_LYNX 0x06
#define CHIPSET_QCA7450A0 0x07
#define CHIPSET_QCA7451A0 0x08
#define CHIPSET_QCA7452A0 0x09
#define CHIPSET_QCA7420A0 0x20
#define CHIPSET_QCA6410A0 0x21
#define CHIPSET_QCA6411A0 0x21
#define CHIPSET_QCA7000A0 0x22
#define CHIPSET_QCA7000I 0x22
#define CHIPSET_QCA7005A0 0x22
#define CHIPSET_QCA7500A0 0x30
#define CHIPSET_QCA7520A0 0x30
#define CHIPSET_QCA7550A0 0x30

/*
 * the following definitions define older constants in terms of
 * newer constants to avoid compiler errors; there is nothing
 * magic about the A0/A1 suffixes;
 */

#define CHIPSET_INT6000 CHIPSET_INT6000A1
#define CHIPSET_INT6300 CHIPSET_INT6300A0
#define CHIPSET_INT6400 CHIPSET_INT6400A0
#define CHIPSET_AR7400  CHIPSET_AR7400A0
#define CHIPSET_INT6405 CHIPSET_AR6405A0
#define CHIPSET_AR6405  CHIPSET_AR6405A0
#define CHIPSET_QCA7450 CHIPSET_QCA7450A0
#define CHIPSET_QCA7451 CHIPSET_QCA7451A0
#define CHIPSET_QCA7452 CHIPSET_QCA7452A0
#define CHIPSET_QCA7420 CHIPSET_QCA7420A0
#define CHIPSET_QCA6410 CHIPSET_QCA6410A0
#define CHIPSET_QCA6411 CHIPSET_QCA6411A0
#define CHIPSET_QCA7000 CHIPSET_QCA7000A0
#define CHIPSET_QCA7005 CHIPSET_QCA7005A0
#define CHIPSET_QCA7500 CHIPSET_QCA7500A0


/*====================================================================*
 *   chipset functions;
 *--------------------------------------------------------------------*/
	enum tChipSignature {
		eChipSignature_Default		= 0x00000000,
		eChipSignature_Qca7420 		= 0x001CFCFC,
		eChipSignature_Qca6411 		= 0x001B58BC,
		eChipSignature_Qca6410 		= 0x001B58EC,
		eChipSignature_Qca7000 		= 0x001B58DC,
		eChipSignature_Qca7000I		= 0x001B589C,
		eChipSignature_Qca7420ES 	= 0x001CFC00,
		eChipSignature_Qca7000ES 	= 0x001B5800,
		eChipSignature_Qca7500 		= 0x001D4C0F,
		eChipSignature_Qca7500ES	= 0x001D4C00,
		eChipSignature_Qca7520		= 0x001D4C02,
		eChipSignature_Qca7550		= 0x001D4C05,
		
		//Note: also add new ID to IsChipIdSupported function

		eChipSignature_Invalid	 = 0xBAD0DEAD
	};
char const * chipsetname (uint8_t chipset);
void chipset (void const * memory);
const char * ConvertChipSignatureId2ProductIdStr( enum tChipSignature aChipSignature);

/*====================================================================*
 *
 *--------------------------------------------------------------------*/



	enum tDeviceClass {
		eClass_20	= 0x20,
		eClass_21	= 0x21,
		eClass_22	= 0x22,
		eClass_30	= 0x30,

		eNoClass	= 0xffff
	};

#endif



