/*====================================================================*
 *	Copyright (c) 2018-19 Qualcomm Technologies, Inc.
 *	All Rights Reserved.
 *	Confidential and Proprietary - Qualcomm Technologies, Inc.
 *--------------------------------------------------------------------*/
 
/*====================================================================*
 *
 *   signed Traffic3 (struct plc * plc);
 *
 *   generate data traffic between two devices using MME 
 *	 VS_TRAFFIC_GENERATOR
 *
 *   Contributor(s):
 *			Nisha K(nishk@qti.qualcomm.com)
 *--------------------------------------------------------------------*/

#ifndef TRAFFIC3_SOURCE
#define TRAFFIC3_SOURCE

#include <memory.h>
#include <errno.h>

#include "../tools/memory.h"
#include "../tools/number.h"
#include "../tools/error.h"
#include "../tools/flags.h"
#include "../plc/plc.h"

signed Traffic3 (struct plc * plc, uint8_t trafficgen_rate)

{
	struct channel * channel = (struct channel *) (plc->channel);
	struct message * message = (struct message *) (plc->message);

#ifndef __GNUC__
#pragma pack (push,1)
#endif

	struct __packed vs_traffic_generator_request
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
		uint8_t	DMAC[6];
		uint8_t	DURATION;
		uint8_t TRAFFICGEN_RATE;
	}
	* request = (struct vs_traffic_generator_request *) (message);

	struct __packed vs_traffic_generator_confirm
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
		uint8_t MSTATUS;
	}
	* confirm = (struct vs_traffic_generator_confirm *) (message);

#ifndef __GNUC__
#pragma pack (pop)
#endif

	memset (message, 0, sizeof (* message));
	EthernetHeader (& request->ethernet, channel->peer, channel->host, channel->type);
	QualcommHeader (& request->qualcomm, 0, (VS_TRAFFIC_GENERATOR | MMTYPE_REQ));
	plc->packetsize = (ETHER_MIN_LEN - ETHER_CRC_LEN);
	memcpy (request->DMAC, plc->RDA, ETHER_ADDR_LEN);
	request->DURATION = plc->timer;
	request->TRAFFICGEN_RATE = trafficgen_rate;

	if (SendMME (plc) <= 0)
	{
		error (0, errno, CHANNEL_CANTSEND);
		return (-1);
	}
	if (ReadMME (plc, 0, (VS_TRAFFIC_GENERATOR | MMTYPE_CNF)) <= 0)
	{
		error (0, errno, CHANNEL_CANTREAD);
		return (-1);
	}
	if (confirm->MSTATUS)
	{
		Failure (plc, PLC_WONTDOIT);
		return (-1);
	}

	memcpy (plc->MAC, confirm->ethernet.OSA, 6);
	sleep (plc->timer);

	memset (message, 0, sizeof (* message));
	
	EthernetHeader (& request->ethernet, plc->RDA, channel->host, channel->type);
	QualcommHeader (& request->qualcomm, 0, (VS_TRAFFIC_GENERATOR | MMTYPE_REQ));
	plc->packetsize = (ETHER_MIN_LEN - ETHER_CRC_LEN);
	memcpy (request->DMAC, plc->MAC, ETHER_ADDR_LEN);
	request->DURATION = plc->timer;
	request->TRAFFICGEN_RATE = trafficgen_rate;

	if (SendMME (plc) <= 0)
	{
		error (0, errno, CHANNEL_CANTSEND);
		return (-1);
	}
	if (ReadMME (plc, 0, (VS_TRAFFIC_GENERATOR | MMTYPE_CNF)) <= 0)
	{
		error (0, errno, CHANNEL_CANTREAD);
		return (-1);
	}
	if (confirm->MSTATUS)
	{
		Failure (plc, PLC_WONTDOIT);
		return (-1);
	}

	sleep (plc->timer);

	return (0);
}

#endif

/*====================================================================*
 *
 *   signed Traffic3_unidi (struct plc * plc);
 *
 *   generate data traffic between two devices using MME in only one direction
 *	 VS_TRAFFIC_GENERATOR
 *
 *   Contributor(s):
 *			Ananya Barat(abarat@qti.qualcomm.com)
 *--------------------------------------------------------------------*/


signed Traffic3_unidi (struct plc * plc, uint8_t trafficgen_rate)

{
	
	struct channel * channel = (struct channel *) (plc->channel);
	struct message * message = (struct message *) (plc->message);

#ifndef __GNUC__
#pragma pack (push,1)
#endif
	
	struct __packed vs_traffic_generator_request
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
		uint8_t	DMAC[6];
		uint8_t	DURATION;
		uint8_t TRAFFICGEN_RATE;
	}
	* request = (struct vs_traffic_generator_request *) (message);

	struct __packed vs_traffic_generator_confirm
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
		uint8_t MSTATUS;
	}
	* confirm = (struct vs_traffic_generator_confirm *) (message);

#ifndef __GNUC__
#pragma pack (pop)
#endif

	memset (message, 0, sizeof (* message));
	EthernetHeader (& request->ethernet, plc->RDA,channel->host , channel->type);
	QualcommHeader (& request->qualcomm, 0, (VS_TRAFFIC_GENERATOR | MMTYPE_REQ));
	plc->packetsize = (ETHER_MIN_LEN - ETHER_CRC_LEN);
	memcpy (request->DMAC, channel->peer, ETHER_ADDR_LEN);
	request->DURATION = plc->timer;
	request->TRAFFICGEN_RATE = trafficgen_rate;

	if (SendMME (plc) <= 0)
	{
		error (0, errno, CHANNEL_CANTSEND);
		return (-1);
	}
	if (ReadMME (plc, 0, (VS_TRAFFIC_GENERATOR | MMTYPE_CNF)) <= 0)
	{
		error (0, errno, CHANNEL_CANTREAD);
		return (-1);
	}
	if (confirm->MSTATUS)
	{
		Failure (plc, PLC_WONTDOIT);
		return (-1);
	}
	 

   sleep (plc->timer);   
   return (0); 

}



