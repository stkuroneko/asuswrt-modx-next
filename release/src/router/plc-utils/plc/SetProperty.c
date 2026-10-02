/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed SetProperty (struct plc * plc);
 *
 *   plc.h
 *
 *--------------------------------------------------------------------*/

#ifndef SETPROPERTY_SOURCE
#define SETPROPERTY_SOURCE

#include <stdint.h>
#include <memory.h>

#include "../plc/plc.h"
#include "../tools/error.h"
#include "../tools/memory.h"

signed SetProperty (struct plc * plc, struct plcproperty * plcproperty)

{
	struct channel * channel = (struct channel *) (plc->channel);
	struct message * message = (struct message *) (plc->message);

#ifndef __GNUC__
#pragma pack (push,1)
#endif

	struct __packed vs_set_property_request
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
		uint32_t COOKIE;
		uint8_t OPTION;
		uint8_t RESERVED [3];
		uint32_t PROP_VERSION;
		uint32_t PROP_NUMBER;
		uint32_t DATA_LENGTH;
		uint8_t DATA_BUFFER [256];
	}
	* request = (struct vs_set_property_request *) (message);
	struct __packed vs_set_property_confirm
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
		uint32_t MSTATUS;
		uint32_t COOKIE;
	}
	* confirm = (struct vs_set_property_confirm *) (message);

#ifndef __GNUC__
#pragma pack (pop)
#endif

	Request (plc, "Set Property");
	memset (message, 0, sizeof (* message));
	EthernetHeader (& request->ethernet, channel->peer, channel->host, channel->type);
	QualcommHeader (& request->qualcomm, 0, (VS_SET_PROPERTY | MMTYPE_REQ));
	request->COOKIE = HTOLE32 (plc->cookie);
	request->OPTION = plcproperty->PROP_OPTION;
	request->PROP_VERSION = HTOLE32 (plcproperty->PROP_VERSION);
	request->PROP_NUMBER = HTOLE32 (plcproperty->PROP_NUMBER);
	request->DATA_LENGTH = HTOLE32 (plcproperty->DATA_LENGTH);
	memcpy (& request->DATA_BUFFER, & plcproperty->DATA_BUFFER, plcproperty->DATA_LENGTH);
	plc->packetsize = sizeof (* request);
	if (SendMME (plc) <= 0)
	{
		error (PLC_EXIT (plc), errno, CHANNEL_CANTSEND);
		return (-1);
	}
	while (ReadMME (plc, 0, (VS_SET_PROPERTY | MMTYPE_CNF)) > 0)
	{
		if (confirm->MSTATUS)
		{
			Failure (plc, PLC_WONTDOIT);
			continue;
		}
	}
	return (0);
}

#endif



