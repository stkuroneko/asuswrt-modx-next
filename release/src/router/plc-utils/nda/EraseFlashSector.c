/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed EraseFlashSector (struct plc * plc);
 *
 *   nda.h
 *
 *   erase a specific sector of flash memory when the DAK is known;
 *   the sector is passed in plc->modulecode as an 8 bit value so
 *   make sure that plc->modulecode is not being used by another
 *   function such as function Flash () in module FlashPTS;
 *
 *   See the Atheros HomePlug AV Firmware Technical Reference Manual
 *   for more information;
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef ERASEFLASHSECTOR_SOURCE
#define ERASEFLASHSECTOR_SOURCE

#include <stdint.h>
#include <memory.h>

#include "../tools/memory.h"
#include "../tools/error.h"
#include "../plc/plc.h"
#include "../nda/nda.h"

signed EraseFlashSector (struct plc * plc)

{
	struct channel * channel = (struct channel *) (plc->channel);
	struct message * message = (struct message *) (plc->message);

#ifndef __GNUC__
#pragma pack (push,1)
#endif

	struct __packed vs_flash_erase_request
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
		uint8_t SECTOR;
		uint8_t DAK [HPAVKEY_DAK_LEN];
	}
	* request = (struct vs_flash_erase_request *) (message);
	struct __packed vs_flash_erase_confirm
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
		uint8_t STATUS;
		uint8_t SECTOR;
	}
	* confirm = (struct vs_flash_erase_confirm *) (message);

#ifndef __GNUC__
#pragma pack (pop)
#endif

	Request (plc, "Erase Flash Memory Sector");
	memset (message, 0, sizeof (* message));
	EthernetHeader (& request->ethernet, channel->peer, channel->host, channel->type);
	QualcommHeader (& request->qualcomm, 0, (VS_FLASH_ERASE | MMTYPE_REQ));
	request->SECTOR = plc->sector;
	memcpy (request->DAK, plc->DAK, sizeof (request->DAK));
	plc->packetsize = (ETHER_MIN_LEN - ETHER_CRC_LEN);
	if (SendMME (plc) <= 0)
	{
		error (PLC_EXIT (plc), ECANCELED, CHANNEL_CANTSEND);
		return (-1);
	}
	if (ReadMME (plc, 0, (VS_FLASH_ERASE | MMTYPE_CNF)) <= 0)
	{
		error (PLC_EXIT (plc), ECANCELED, CHANNEL_CANTREAD);
		return (-1);
	}
	if (confirm->STATUS)
	{
		Failure (plc, PLC_WONTDOIT);
		return (-1);
	}
	Confirm (plc, "Erased Sector %d", confirm->SECTOR);
	return (0);
}

#endif



