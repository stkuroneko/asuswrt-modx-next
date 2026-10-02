/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed EraseFlashMemory1 (struct plc * plc);
 *
 *   plc.h
 *
 *   commit downloaded firmware and/or parameters to NVRAM using a
 *   VS_PTS_NVM message; flash-less devices will attempt to upload
 *   to their local host because they have no NVRAM; the host must
 *   be prepared to handle this situation;
 *
 *   See the Atheros HomePlug AV Firmware Technical Reference Manual
 *   for more information;
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef ERASEFLASHMEMORY1_SOURCE
#define ERASEFLASHMEMORY1_SOURCE

#include <stdint.h>
#include <memory.h>

#include "../tools/memory.h"
#include "../tools/error.h"
#include "../tools/flags.h"
#include "../plc/plc.h"

signed EraseFlashMemory1 (struct plc * plc)

{
	struct channel * channel = (struct channel *) (plc->channel);
	struct message * message = (struct message *) (plc->message);

#ifndef __GNUC__
#pragma pack (push,1)
#endif

	struct __packed vs_pts_nvm_request
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
		uint8_t MODULEID;
		uint8_t RESERVED;
		uint8_t DAK [HPAVKEY_DAK_LEN];
	}
	* request = (struct vs_pts_nvm_request *) (message);
	struct __packed vs_pts_nvm_confirm
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
		uint8_t MSTATUS;
		uint8_t MODULEID;
	}
	* confirm = (struct vs_pts_nvm_confirm *) (message);

#ifndef __GNUC__
#pragma pack (pop)
#endif

	Request (plc, "Erasing Flash Memory (PTS)");
	memset (message, 0, sizeof (* message));
	EthernetHeader (& request->ethernet, channel->peer, channel->host, channel->type);
	QualcommHeader (& request->qualcomm, 0, (VS_PTS_NVM | MMTYPE_REQ));
	request->MODULEID = 0x0C;
	memcpy (request->DAK, plc->DAK, sizeof (request->DAK));
	plc->packetsize = (ETHER_MIN_LEN - ETHER_CRC_LEN);
	if (SendMME (plc) <= 0)
	{
		error (PLC_EXIT (plc), ECANCELED, CHANNEL_CANTSEND);
		return (-1);
	}
	if (ReadMME (plc, 0, (VS_PTS_NVM | MMTYPE_CNF)) <= 0)
	{
		error (PLC_EXIT (plc), ECANCELED, CHANNEL_CANTREAD);
		return (-1);
	}
	if (confirm->MSTATUS)
	{
		Failure (plc, PLC_WONTDOIT);
		return (-1);
	}

#if 1

/*
 *   this code is needed because the AR7400 behaves differently than the INT6x00 after flash
 *   memory is erased; the AR7400 returns to bootloader and sends HARs but ignores VS_SW_VER
 *   requests; consequently, if we are erasing flash memory and have not requested immediate
 *   return then we wait indefinitely for a VS_HOST_ACTION.IND before proceding;
 */

	if (_allclr (plc->flags, PLC_QUICK_FLASH))
	{
		while (ReadMME (plc, 0, (VS_HOST_ACTION | MMTYPE_IND)) <= 0);
		_setbits (plc->flags, PLC_QUICK_FLASH);
	}

#endif

	return (0);
}

#endif



