/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed RemoteHosts (struct plc * plc);
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

#ifndef REMOTEHOSTS_SOURCE
#define REMOTEHOSTS_SOURCE

#include <stdint.h>
#include <memory.h>

#include "../tools/error.h"
#include "../tools/memory.h"
#include "../tools/symbol.h"
#include "../plc/plc.h"

signed RemoteHosts (struct plc * plc)

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
	}
	* request = (struct vs_sw_ver_request *) (message);
	struct __packed vs_sw_ver_confirm
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
		uint8_t MSTATUS;
		uint32_t NUMDEVICES;
		struct __packed
		{
			uint8_t MACADDRESS [ETHER_ADDR_LEN];
			uint8_t ENUMID;
		}
		DEVICE [1];
	}
	* confirm = (struct vs_sw_ver_confirm *) (message);

#ifndef __GNUC__
#pragma pack (pop)
#endif

	Request (plc, "Request Enumeration ID Table");
	memset (message, 0, sizeof (* message));
	EthernetHeader (& request->ethernet, channel->peer, channel->host, channel->type);
	QualcommHeader (& request->qualcomm, 0, (VS_EM_ID_TABLE | MMTYPE_REQ));
	plc->packetsize = (ETHER_MIN_LEN - ETHER_CRC_LEN);
	if (SendMME (plc) <= 0)
	{
		error (PLC_EXIT (plc), errno, CHANNEL_CANTSEND);
		return (-1);
	}
	while (ReadMME (plc, 0, (VS_EM_ID_TABLE | MMTYPE_CNF)) > 0)
	{
		unsigned count = LE32TOH (confirm->NUMDEVICES);
		if (confirm->MSTATUS)
		{
			Failure (plc, PLC_WONTDOIT);
			continue;
		}
		while (count--)
		{
			hexout (confirm->DEVICE [count].MACADDRESS, ETHER_ADDR_LEN, ':', count? ' ': '\n', stdout);
		}
	}
	return (0);
}

#endif



