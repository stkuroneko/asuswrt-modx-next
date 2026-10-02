/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed VersionInfo2 (struct plc * plc);
 *
 *   plc.h
 *
 *   read hardware and software version information from an INT6000
 *   using a VS_SW_VER Request Message;
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef VERSIONINFO2_SOURCE
#define VERSIONINFO2_SOURCE

#include <stdint.h>
#include <memory.h>

#include "../tools/error.h"
#include "../tools/memory.h"
#include "../tools/symbol.h"
#include "../plc/plc.h"

signed VersionInfo2 (struct plc * plc)

{
	struct channel * channel = (struct channel *) (plc->channel);
	struct message * message = (struct message *) (plc->message);

#ifndef __GNUC__
#pragma pack (push,1)
#endif

	struct __packed vs_sw_ver_request
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
		uint32_t COOKIE;
	}
	* request = (struct vs_sw_ver_request *) (message);
	struct __packed vs_sw_ver_confirm
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
		uint8_t MSTATUS;
		uint8_t MDEVICE_CLASS;
		uint8_t MVERLENGTH;
		char MVERSION [254];
		uint32_t IDENT;
		uint32_t STEPPING_NUM;
		uint32_t COOKIE;
		uint32_t RSVD [6];
	}

	* confirm = (struct vs_sw_ver_confirm *) (message);
	struct __packed vs_sw_ver_confirm_bootrom
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
		uint8_t MSTATUS;
		uint8_t MDEVICE_CLASS;
		uint8_t MVERLENGTH;
		char MVERSION [64];
		uint8_t res;
		uint32_t IDENT;
		uint32_t STEPPING_NUM;
		uint32_t COOKIE;
		uint32_t RSVD [6];
	}

* confirm1 = (struct vs_sw_ver_confirm_bootrom *) (message);

#ifndef __GNUC__
#pragma pack (pop)
#endif

	Request (plc, "Request Version Information");
	memset (message, 0, sizeof (* message));
	EthernetHeader (& request->ethernet, channel->peer, channel->host, channel->type);
	QualcommHeader (& request->qualcomm, 0, (VS_SW_VER | MMTYPE_REQ));
	request->COOKIE = HTOLE32 (plc->cookie);
	plc->packetsize = (ETHER_MIN_LEN - ETHER_CRC_LEN);
	if (SendMME (plc) <= 0)
	{
		error (PLC_EXIT (plc), errno, CHANNEL_CANTSEND);
		return (-1);
	}
	while (ReadMME (plc, 0, (VS_SW_VER | MMTYPE_CNF)) > 0)
	{
		if( LE32TOH (confirm->MVERLENGTH) == 0x0B )
		{
#if 0
			// in the bootrom
			fprintf (stderr, "BR_DEVICE CLASS (%d)\n", LE32TOH (confirm1->MDEVICE_CLASS));
			fprintf (stderr, "BR_VERSION LENGTH (%d)\n", LE32TOH (confirm1->MVERLENGTH));
			fprintf (stderr, "BR_VERSION STRING [%s]\n", LE32TOH (confirm1->MVERSION));
			fprintf (stderr, "BR_IDENT [0x%08X]\n", LE32TOH (confirm1->IDENT));
			fprintf (stderr, "BR_STEPPING NUMBER [0x%08X]\n", LE32TOH (confirm1->STEPPING_NUM));
			fprintf (stderr, "BR_COOKIE [0x%08X]\n", LE32TOH (confirm1->COOKIE));
#endif
			if (confirm1->MSTATUS)
			{
				Failure (plc, PLC_WONTDOIT);
				continue;
			}
			chipset (confirm1);
			Display (plc, "%s %s", ConvertChipSignatureId2ProductIdStr((enum tChipSignature)confirm1->IDENT), confirm1->MVERSION);
		}
		else
		{
#if 0
			// in the fw
			fprintf (stderr, "DEVICE CLASS (%d)\n", LE32TOH (confirm->MDEVICE_CLASS));
			fprintf (stderr, "VERSION LENGTH (%d)\n", LE32TOH (confirm->MVERLENGTH));
			fprintf (stderr, "VERSION STRING [%s]\n", LE32TOH (confirm->MVERSION));
			fprintf (stderr, "IDENT [0x%08X]\n", LE32TOH (confirm->IDENT));
			fprintf (stderr, "STEPPING NUMBER [0x%08X]\n", LE32TOH (confirm->STEPPING_NUM));
			fprintf (stderr, "COOKIE [0x%08X]\n", LE32TOH (confirm->COOKIE));
#endif
			if (confirm->MSTATUS)
			{
				Failure (plc, PLC_WONTDOIT);
				continue;
			}
			chipset (confirm);
			Display (plc, "%s %s", ConvertChipSignatureId2ProductIdStr((enum tChipSignature)confirm->IDENT), confirm->MVERSION);
		}
	}
	return (0);
}

#endif



