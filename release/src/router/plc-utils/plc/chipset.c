/****************************************************************************
#    Copyright (c) 2020 Qualcomm Technologies, Inc. 
#    All Rights Reserved. 
#    Confidential and Proprietary - Qualcomm Technologies, Inc. 
#**********************************************************************       
#    2013 Qualcomm Atheros, Inc. 
#                    
****************************************************************************/

#ifndef CHIPSET_SOURCE
#define CHIPSET_SOURCE

/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

#include "../plc/plc.h"
#include "../tools/types.h"
#include "../tools/symbol.h"

/*====================================================================*
 *
 *   char const * chipsetname (uint8_t MDEVICE)
 *
 *   plc.h
 *
 *   return the ASCII name string associated with the MDEVICE_CLASS
 *   field in the VS_SW_VER.CNF message; this field represents the
 *   chipset family or class of device;
 *
 *   the MDEVICE_CLASS field was named MDEVICEID at one time;
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

char const * chipsetname (uint8_t MDEVICE_CLASS)

{
	static const struct _type_ chipname [] =
	{
		{
			CHIPSET_UNKNOWN,
			"UNKNOWN"
		},
		{
			CHIPSET_INT6000A1,
			"INT6000"
		},
		{
			CHIPSET_INT6300A0,
			"INT6300"
		},
		{
			CHIPSET_INT6400A0,
			"INT6400"
		},
		{
			CHIPSET_AR7400A0,
			" AR7400"
		},
		{
			CHIPSET_AR6405A0,
			" AR6405"
		},
		{
			CHIPSET_PANTHER_LYNX,
			"PANTHER/LYNX"
		},
		{
			CHIPSET_QCA7450A0,
			"QCA7450"
		},
		{
			CHIPSET_QCA7451A0,
			"QCA7451"
		},
		{
			CHIPSET_QCA7420A0,
			"QCA7420"
		},
		{
			CHIPSET_QCA6410A0,
			"QCA6410"
		},
		{
			CHIPSET_QCA7000A0,
			"QCA7000"
		},
		{
			CHIPSET_QCA7005A0,
			"QCA7005"
		},
		{
			CHIPSET_QCA7500A0,
			"QCA7500"
		},
		{
			CHIPSET_QCA7520A0,
			"QCA7520"
		},
		{
			CHIPSET_QCA7550A0,
			"QCA7550"
		}
	};
	return (typename (chipname, SIZEOF (chipname), MDEVICE_CLASS, chipname [0].name));
}

/*====================================================================*
 *
 *   void chipset (void const * memory);
 *
 *   Chipset.h
 *
 *   replace VS_SW_VER message MDEVICE_CLASS field with correct value;
 *   the MDEVICE_CLASS field was named MDEVICEID at one time;
 *
 *   Atheros chipsets are identified by code in the VS_SW_VER vendor
 *   specific management message; the chipset [] vector translates a
 *   chipset code to a chipset name;
 *
 *   the basic assumption is that the firmware always tells the truth
 *   but the bootrom does not; because of engineering changes, the
 *   firmware uses a different device identification scheme than that
 *   used by the bootrom and that information appears in different
 *   locations depending on the source of the VS_SW_VER confirmation;
 *   see the Programmer's Guide for more information.
 *
 *   INT6000   0x01 / 0x01  0x00000042 / NA
 *   INT6300   0x01 / 0x02  0x00006300 / NA
 *   INT6400   0x03 / 0x03  0x00006400 / NA
 *    AR7400   0x03 / 0x04  0x00007400 / NA
 *    AR6405   0x03 / 0x05  0x00006400 / NA
 *   QCA7450   0x03 / 0x20  0x0F001D1A / NA
 *   QCA7420   0x06 / 0x20  0x001CFCFC
 *   QCA6410   0x06 / 0x21  0x001B58EC
 *   QCA6411   0x06 / 0x21  0x001B58BC
 *   QCA7000   0x06 / 0x22  0x001B589C
 *   QCA7000   0x06 / 0x22  0x001B58DC
 *   QCA7005   0x06 / 0x22  0x001B587C
 *   QCA7500   0x06 / 0x30  0x001D4C0F
 *   QCA7520   0x06 / 0x30  0x001D4C02
 *   QCA7550   0x06 / 0x30  0x001D4C05
 *
 *   some chipsets have have multiple STRAP field values; this is
 *   not an error; there may be multiple versions of a chipset;
 *
 *--------------------------------------------------------------------*/

//***************************************************************************
//
//	Function: ConvertChipSignatureId2ProductIdStr()
//
//***************************************************************************
const char * ConvertChipSignatureId2ProductIdStr(
	enum tChipSignature aChipSignature
	)
{
	switch(aChipSignature)
	{
	case eChipSignature_Qca7420:
		return "QCA7420";
		break;
	case eChipSignature_Qca6411:
		return "QCA6411";
		break;
	case eChipSignature_Qca6410:
		return "QCA6410";
		break;
	case eChipSignature_Qca7000:
		return "QCA7000";
		break;
	case eChipSignature_Qca7000I:
		return "QCA7000I";
		break;
	case eChipSignature_Qca7420ES:
		return "QCA7420ES";
		break;
	case eChipSignature_Qca7000ES:
		return "QCA7000ES";
		break;
	case eChipSignature_Qca7500:
		return "QCA7500";
		break;
	case eChipSignature_Qca7500ES:
		return "QCA7500ES";
		break;
	case eChipSignature_Qca7520:
		return "QCA7520";
		break;
	case eChipSignature_Qca7550:
		return "QCA7550";
		break;
	default:
		return "QCA????";
		break;
	}
}
void chipset (void const * memory)

{

#ifndef __GNUC__
#pragma pack (push,1)
#endif

	struct __packed vs_sw_ver_confirm
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
		uint8_t MSTATUS;
		uint8_t MDEVICE_CLASS;
		uint8_t MVERLENGTH;
		char MVERSION [254];
	}
	* confirm = (struct vs_sw_ver_confirm *) (memory);
	struct __packed chipinfo
	{
		uint8_t RESVD;
		uint32_t STRAP;
		uint32_t STEP_NUMBER;
	}
	* chipinfo = (struct chipinfo *) (& confirm->MVERSION [64]);
	typedef struct __packed
	{
		uint32_t STRAP;
		uint8_t CLASS;
		uint8_t DEVICE;
	}
	chipdata;

#ifndef __GNUC__
#pragma pack (pop)
#endif

	chipdata bootrom [] =
	{
		{
			0x00000042,
			0x01,
			CHIPSET_INT6000A1
		},
		{
			0x00006300,
			0x01,
			CHIPSET_INT6300A0
		},
		{
			0x00006400,
			0x03,
			CHIPSET_INT6400A0
		},
		{
			0x00007400,
			0x03,
			CHIPSET_AR7400A0
		},
		{
			0x0F001D1A,
			0x03,
			CHIPSET_QCA7450A0
		},
		{
			0x0E001D1A,
			0x03,
			CHIPSET_QCA7451A0
		},
		{
			0x001CFC00,
			0x05,
			CHIPSET_QCA7420A0
		},
		{
			0x001CFCFC,
			0x05,
			CHIPSET_QCA7420A0
		},
		{
			0x001CFCFC,
			0x06,
			CHIPSET_QCA7420A0
		},
		{
			0x001B58EC,
			0x06,
			CHIPSET_QCA6410A0
		},
		{
			0x001B58BC,
			0x06,
			CHIPSET_QCA6411A0
		},
		{
			0x001B58DC,
			0x06,
			CHIPSET_QCA7000A0
		},
		{
			0x001B587C,
			0x06,
			CHIPSET_QCA7005A0
		},
		{
			0x001D4C00,
			0x06,
			CHIPSET_QCA7500A0
		},
		{
			0x001D4C0F,
			0x06,
			CHIPSET_QCA7500A0
		},
		{
			0x001D4C02,
			0x06,
			CHIPSET_QCA7520A0
		},
		{
			0x001D4C05,
			0x06,
			CHIPSET_QCA7550A0
		}
	};
	chipdata firmware [] =
	{
		{
			0x00000000,
			0x01,
			CHIPSET_INT6000A1
		},
		{
			0x00000000,
			0x02,
			CHIPSET_INT6300A0
		},
		{
			0x00000000,
			0x03,
			CHIPSET_INT6400A0
		},
		{
			0x00000000,
			0x05,
			CHIPSET_AR6405A0
		},
		{
			0x00000000,
			0x04,
			CHIPSET_AR7400A0
		},
		{
			0x0F001D1A,
			0x20,
			CHIPSET_QCA7450A0
		},
		{
			0x0E001D1A,
			0x20,
			CHIPSET_QCA7451A0
		},
		{
			0x001CFCFC,
			0x20,
			CHIPSET_QCA7420A0
		},
		{
			0x001B58EC,
			0x21,
			CHIPSET_QCA6410A0
		},
		{
			0x001B58BC,
			0x21,
			CHIPSET_QCA6411A0
		},
		{
			0x001B58DC,
			0x22,
			CHIPSET_QCA7000A0
		},
		{
			0x001D4C00,
			0x30,
			CHIPSET_QCA7500A0
		},
		{
			0x001D4C0F,
			0x30,
			CHIPSET_QCA7500A0
		},
		{
			0x001D4C02,
			0x30,
			CHIPSET_QCA7520A0 
		},
		{
			0x001D4C05,
			0x30,
			CHIPSET_QCA7550A0
		}
	};
	unsigned chip;
	if (! strcmp (confirm->MVERSION, "BootLoader"))
	{
		for (chip = 0; chip < SIZEOF (bootrom); chip++)
		{
			if (bootrom [chip].CLASS != confirm->MDEVICE_CLASS)
			{
				continue;
			}
			if (bootrom [chip].STRAP != LE32TOH (chipinfo->STRAP))
			{
				continue;
			}
			confirm->MDEVICE_CLASS = bootrom [chip].DEVICE;
			return;
		}
	}
	else 
	{
		for (chip = 0; chip < SIZEOF (firmware); chip++)
		{
			if (firmware [chip].CLASS != confirm->MDEVICE_CLASS)
			{
				continue;
			}
			if (firmware [chip].STRAP < CHIPSET_PANTHER_LYNX)
			{
				confirm->MDEVICE_CLASS = firmware [chip].DEVICE;
				return;
			}
			chipinfo = (struct chipinfo *) (& confirm->MVERSION [64]);
			if (firmware [chip].STRAP == LE32TOH (chipinfo->STRAP))
			{
				confirm->MDEVICE_CLASS = firmware [chip].DEVICE;
				return;
			}
			chipinfo = (struct chipinfo *) (& confirm->MVERSION [128]);
			if (firmware [chip].STRAP == LE32TOH (chipinfo->STRAP))
			{
				confirm->MDEVICE_CLASS = firmware [chip].DEVICE;
				return;
			}
			chipinfo = (struct chipinfo *) (& confirm->MVERSION [253]);
			if (firmware [chip].STRAP == LE32TOH (chipinfo->STRAP))
			{
				confirm->MDEVICE_CLASS = firmware [chip].DEVICE;
				return;
			}
		}
	}
	return;
}




#endif



