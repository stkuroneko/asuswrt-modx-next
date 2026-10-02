/****************************************************************************
#    Copyright (c) 2020 Qualcomm Technologies, Inc. 
#    All Rights Reserved. 
#    Confidential and Proprietary - Qualcomm Technologies, Inc. 
#**********************************************************************       
#    2013 Qualcomm Atheros, Inc. 
#                    
****************************************************************************/

/*====================================================================*
 *
 *   signed WaitForStart (struct plc * plc, char string [], size_t length);
 *
 *   plc.h
 *
 *   poll the local device with VS_SW_VER requests until it responds
 *   with a confirmation or the retry count expires; return 0 if the 
 *   device responds in time or -1 if it does not;
 *
 *   if the device responds then set the struct plc hardwareID field
 *   to indicate the true hardware platform; function chipset corrects
 *   some unfortunate bootloader errors;
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *      Nathaniel Houghton <nhoughto@qca.qualcomm.com>
 *	Werner Henze <w.henze@avm.de>
 *
 *--------------------------------------------------------------------*/

#ifndef WAITFORSTART_SOURCE
#define WAITFORSTART_SOURCE

#include <stdint.h>
#include <unistd.h>
#include <memory.h>
#include <string.h>
#include <sys/time.h>

#include "../plc/plc.h"
#include "../tools/timer.h"
#include "../tools/error.h"
#include "../tools/flags.h"

signed WaitForStart (struct plc * plc, char string [], size_t length)

{
	extern const byte localcast [ETHER_ADDR_LEN];
	struct channel * channel = (struct channel *) (plc->channel);
	struct message * message = (struct message *) (plc->message);
	struct timeval ts;
	struct timeval tc;
	unsigned timer = 0;

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
		uint8_t MDEVICEID;
		uint8_t MVERLENGTH;
		char MVERSION [PLC_VERSION_STRING];
		uint16_t MPLATFORM;
	}
	* confirm = (struct vs_sw_ver_confirm *) (message);

#ifndef __GNUC__
#pragma pack (pop)
#endif
	flag_t flags = channel->flags;
	memset (string, 0, length);
	if (gettimeofday (& ts, NULL) == -1)
	{
		error (1, errno, CANT_START_TIMER);
	}
	for (timer = 0; timer < plc->timer; timer = SECONDS (ts, tc))
	{
		memset (message, 0, sizeof (* message));
		EthernetHeader (& request->ethernet, localcast, channel->host, channel->type);
		QualcommHeader (& request->qualcomm, 0, (VS_SW_VER | MMTYPE_REQ));
		plc->packetsize = (ETHER_MIN_LEN - ETHER_CRC_LEN);
		_clrbits (channel->flags, CHANNEL_VERBOSE);
		if (SendMME (plc) <= 0)
		{
			error (PLC_EXIT (plc), errno, CHANNEL_CANTSEND);
			channel->flags = flags;
			return (-1);
		}
		if (ReadMME (plc, 0, (VS_SW_VER | MMTYPE_CNF)) < 0)
		{
			error (PLC_EXIT (plc), errno, CHANNEL_CANTREAD);
			channel->flags = flags;
			return (-1);
		}
		channel->flags = flags;
		if (gettimeofday (& tc, NULL) == -1)
		{
			error (1, errno, CANT_RESET_TIMER);
		}
		if (plc->packetsize)
		{
			chipset (confirm);
			plc->hardwareID = confirm->MDEVICEID;
			memcpy (channel->peer, request->ethernet.OSA, sizeof (channel->peer));
			if (confirm->MVERLENGTH > length)
			{
				confirm->MVERLENGTH = length;
			}
			memcpy (string, confirm->MVERSION, confirm->MVERLENGTH);
			return (0);
		}
	}
	return (-1);
}

signed WaitForStart_Destination(struct plc* plc)

{
	struct channel* channel = (struct channel*) (plc->channel);
	struct message* message = (struct message*) (plc->message);
	struct timeval ts;
	struct timeval tc;

	#ifndef __GNUC__
	#pragma pack (push,1)
	#endif

	struct __packed vs_sw_ver_request
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
	}
	*request = (struct vs_sw_ver_request*) (message);
	struct __packed vs_sw_ver_confirm
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
		uint8_t MSTATUS;
		uint8_t MDEVICEID;
		uint8_t MVERLENGTH;
		char MVERSION[PLC_VERSION_STRING];
		uint16_t MPLATFORM;
	}
	*confirm = (struct vs_sw_ver_confirm*) (message);

	#ifndef __GNUC__
	#pragma pack (pop)
	#endif
	flag_t flags = channel->flags;
	if (gettimeofday(&ts, NULL) == -1)
	{
		error(1, errno, CANT_START_TIMER);
	}
	memset(message, 0, sizeof(*message));
	EthernetHeader(&request->ethernet, channel->peer, channel->host, channel->type);
	QualcommHeader(&request->qualcomm, 0, (VS_SW_VER | MMTYPE_REQ));
	plc->packetsize = (ETHER_MIN_LEN - ETHER_CRC_LEN);
	_clrbits(channel->flags, CHANNEL_VERBOSE);
	if (SendMME(plc) <= 0)
	{
		error(PLC_EXIT(plc), errno, CHANNEL_CANTSEND);
		channel->flags = flags;
		return (-1);
	}
	if (ReadMME(plc, 0, (VS_SW_VER | MMTYPE_CNF)) < 0)
	{
		error(PLC_EXIT(plc), errno, CHANNEL_CANTREAD);
		channel->flags = flags;
		return (-1);
	}
	channel->flags = flags;
	if (gettimeofday(&tc, NULL) == -1)
	{
		error(1, errno, CANT_RESET_TIMER);
	}
	if (plc->packetsize)
	{
		chipset(confirm);
		plc->hardwareID = confirm->MDEVICEID;
		memcpy(channel->peer, request->ethernet.OSA, sizeof(channel->peer));
		return (0);
	}
	return (-1);
}
#endif



