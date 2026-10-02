/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed Platform (struct channel * channel, const uint8_t device []);
 *
 *   plc.h
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *      Matthieu Poullet <m.poullet@avm.de>
 *
 *--------------------------------------------------------------------*/

#ifndef PLATFORM_SOURCE
#define PLATFORM_SOURCE

#include <memory.h>
#include <errno.h>

#include "../ether/channel.h"
#include "../tools/memory.h"
#include "../tools/symbol.h"
#include "../tools/error.h"
#include "../tools/flags.h"
#include "../plc/plc.h"

signed Platform (struct channel * channel, const uint8_t device [])

{
	struct message message;
	ssize_t packetsize;

#ifndef __GNUC__
#pragma pack (push,1)
#endif

	struct __packed vs_sw_ver_request
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
	}
	* request = (struct vs_sw_ver_request *) (& message);


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
	* confirm = (struct vs_sw_ver_confirm *) (& message);

#ifndef __GNUC__
#pragma pack (pop)
#endif

	memset (& message, 0, sizeof (message));
	EthernetHeader (& request->ethernet, device, channel->host, channel->type);
	QualcommHeader (& request->qualcomm, 0, (VS_SW_VER | MMTYPE_REQ));
	if (sendpacket (channel, & message, (ETHER_MIN_LEN - ETHER_CRC_LEN)) > 0)
	{
		while ((packetsize = readpacket (channel, & message, sizeof (message))) > 0)
		{
			if (! UnwantedMessage (& message, packetsize, 0, (VS_SW_VER | MMTYPE_CNF)))
			{
				chipset (confirm);
				if( (enum tDeviceClass)confirm->MDEVICE_CLASS == eClass_30 )
				{
					printf (" %s", ConvertChipSignatureId2ProductIdStr((enum tChipSignature)confirm->IDENT));
				}
				else
				{
					printf (" %s", chipsetname (confirm->MDEVICE_CLASS));
				}
				printf (" %s", confirm->MVERSION);
				return (0);
			}
		}
	}
	return (-1);
}

#endif
