/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed GetProperty (struct plc * plc, struct property * property);
 *
 *   plc.h
 *
 *   interrogte PLC devices for a property using the VS_GET_PROPERTY
 *   message and display the property value on stdout as a series of
 *   binary, decimal or hexadecimal bytes or an ASCII string;
 *
 *   the current implementation retrieves properties by number, not
 *   by name;
 *
 *--------------------------------------------------------------------*/

#ifndef GETPROPERTY_SOURCE
#define GETPROPERTY_SOURCE

#include <ctype.h>
#include <stdint.h>
#include <memory.h>

#include "../tools/error.h"
#include "../tools/memory.h"
#include "../tools/number.h"
#include "../tools/flags.h"
#include "../plc/plc.h"

signed GetProperty (struct plc * plc, struct plcproperty * plcproperty)

{
	struct channel * channel = (struct channel *) (plc->channel);
	struct message * message = (struct message *) (plc->message);

#ifndef __GNUC__
#pragma pack (push,1)
#endif

	struct __packed vs_get_property_request
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
		uint32_t COOKIE;
		uint8_t DATA_FORMAT;
		uint8_t PROP_FORMAT;
		uint8_t RESERVED [2];
		uint32_t PROP_VERSION;
		uint32_t PROP_LENGTH;
		uint8_t PROP_NUMBER;
	}
	* request = (struct vs_get_property_request *) (message);
	struct __packed vs_get_property_confirm
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
		uint32_t MSTATUS;
		uint32_t COOKIE;
		uint8_t DATA_FORMAT;
		uint8_t RESERVED [3];
		uint32_t DATA_LENGTH;
		uint32_t DATA_BUFFER [1];
	}
	* confirm = (struct vs_get_property_confirm *) (message);

#ifndef __GNUC__
#pragma pack (pop)
#endif

	Request (plc, "Get Property");
	memset (message, 0, sizeof (* message));
	EthernetHeader (& request->ethernet, channel->peer, channel->host, channel->type);
	QualcommHeader (& request->qualcomm, 0, (VS_GET_PROPERTY | MMTYPE_REQ));
	request->COOKIE = HTOLE32 (plc->cookie);
	request->DATA_FORMAT = plcproperty->DATA_FORMAT;
	request->PROP_FORMAT = plcproperty->PROP_FORMAT;
	request->PROP_VERSION = HTOLE32 (plcproperty->PROP_VERSION);
	request->PROP_LENGTH = HTOLE32 (plcproperty->PROP_LENGTH);
	request->PROP_NUMBER = HTOLE32 (plcproperty->PROP_NUMBER);
	plc->packetsize = (ETHER_MIN_LEN - ETHER_CRC_LEN);
	if (SendMME (plc) <= 0)
	{
		error (PLC_EXIT (plc), errno, CHANNEL_CANTSEND);
		return (-1);
	}
	while (ReadMME (plc, 0, (VS_GET_PROPERTY | MMTYPE_CNF)) > 0)
	{
		if (confirm->MSTATUS)
		{
			Failure (plc, PLC_WONTDOIT);
			continue;
		}
		if (_anyset (plc->flags, PLC_ANALYSE))
		{
			unsigned bit;
			struct gpio { uint32_t GPIO_STATE; uint32_t GPIO_INPUT; uint32_t RESERVED; } * gpio = (struct gpio *)(confirm->DATA_BUFFER);
			for (bit = 0; bit < 9; ++bit)
			{
				printf("GPIO %02d %6s %d \n", bit, ((gpio->GPIO_INPUT >> bit) & 1)? "OUTPUT": "INPUT", ((gpio->GPIO_STATE >> bit) & 1));
			}
			continue;
		}
		if (plcproperty->DATA_FORMAT == PLC_FORMAT_BIN)
		{
			binout (confirm->DATA_BUFFER, confirm->DATA_LENGTH, ' ', '\n', stdout);
			continue;
		}
		if (plcproperty->DATA_FORMAT == PLC_FORMAT_HEX)
		{
			hexout (confirm->DATA_BUFFER, confirm->DATA_LENGTH, ' ', '\n', stdout);
			continue;
		}
		if (plcproperty->DATA_FORMAT == PLC_FORMAT_DEC)
		{
			decout (confirm->DATA_BUFFER, confirm->DATA_LENGTH, ' ', '\n', stdout);
			continue;
		}
		if (plcproperty->DATA_FORMAT == PLC_FORMAT_ASC)
		{
			chrout (confirm->DATA_BUFFER, confirm->DATA_LENGTH, '.', '\n', stdout);
			continue;
		}
	}
	return (0);
}

#endif



