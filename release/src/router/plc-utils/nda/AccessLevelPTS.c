/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed AccessLevelPTS (struct plc * plc);
 *
 *   plc.h
 *
 *   Request PTS level access on a QCA6410, QCA7000 or QCA7420 device
 *   using the VS_ACCESS_CONTROL_LEVEL Request Message;
 *
 *   this function is a customized version of function AccessLevel;
 *
 *   Contributor(s):
 *      Nathaniel Houghton <nhoughto@qca.qualcomm.com>
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef ACCESSLEVELPTS_SOURCE
#define ACCESSLEVELPTS_SOURCE

#include <stdint.h>
#include <memory.h>

#include "../tools/error.h"
#include "../nda/nda.h"
#include "../plc/plc.h"

#define ACCESS_CONTROL_MAX_KEY_LENGTH 1024

signed AccessLevelPTS (struct plc * plc)

{
	struct channel * channel = (struct channel *) (plc->channel);
	struct message * message = (struct message *) (plc->message);

#ifndef __GNUC__
#pragma pack (push,1)
#endif

	struct __packed vs_access_level_request
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
		uint32_t RSVD1;
		uint8_t ACCESS_LEVEL;
		uint16_t RSVD2;
		uint8_t ACCESS_TYPE;
		uint16_t RSVD3;
		uint16_t KEY_LENGTH;
		uint8_t KEY [1024];
	}
	* request = (struct vs_access_level_request *) (message);
	struct __packed vs_access_level_confirm
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
		uint16_t RSVD1;
		uint16_t MRESPONSE;
	}
	* confirm = (struct vs_access_level_confirm *) (message);

#ifndef __GNUC__
#pragma pack (pop)
#endif

	memset (message, 0, sizeof (* message));
	EthernetHeader (& request->ethernet, channel->peer, channel->host, channel->type);
	QualcommHeader (& request->qualcomm, 0, (VS_ACCESS_LEVEL_CONTROL | MMTYPE_REQ));
	plc->packetsize = sizeof (* request) - sizeof (request->KEY) +  sizeof (plc->DAK);
	if (plc->packetsize < ETHER_MIN_LEN - ETHER_CRC_LEN)
	{
		plc->packetsize = (ETHER_MIN_LEN - ETHER_CRC_LEN);
	}
	memcpy (request->KEY, plc->DAK, sizeof (plc->DAK));
	request->ACCESS_LEVEL = ACCESS_LEVEL_PTS;
	request->KEY_LENGTH = sizeof (plc->DAK);
	request->ACCESS_TYPE = ACCESS_KEY_TYPE_DAK;
	if (SendMME (plc) <= 0)
	{
		error (PLC_EXIT (plc), errno, CHANNEL_CANTSEND);
		return (-1);
	}
	if (ReadMME (plc, 0, (VS_ACCESS_LEVEL_CONTROL | MMTYPE_CNF)) <= 0)
	{
		error (PLC_EXIT (plc), ECANCELED, CHANNEL_CANTREAD);
		return (-1);
	}
	if (confirm->MRESPONSE)
	{
		Failure (plc, PLC_WONTDOIT);
		return (-1);
	}
	return (0);
}

#endif



