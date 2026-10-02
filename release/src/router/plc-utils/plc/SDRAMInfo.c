/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed SDRAMInfo (struct plc * plc);
 *
 *   plc.h
 *
 *   read the flash resident NVM header and SDRAM configuration block
 *   with VS_RD_CBLOCK;
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef SDRAMINFO_SOURCE
#define SDRAMINFO_SOURCE

#include <stdint.h>
#include <memory.h>

#include "../plc/plc.h"
#include "../tools/error.h"
#include "../tools/memory.h"
#include "../ram/sdram.h"
#include "../nvm/nvm.h"

signed SDRAMInfo (struct plc * plc)

{
	struct channel * channel = (struct channel *) (plc->channel);
	struct message * message = (struct message *) (plc->message);

#ifndef __GNUC__
#pragma pack (push,1)
#endif

	struct __packed vs_rd_cblock_request
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
	}
	* request = (struct vs_rd_cblock_request *) (message);
	struct __packed vs_rd_cblock_confirm
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
		uint8_t MSTATUS;
		uint8_t CONFIGLENGTH;
		struct lightning_nvm_header nvm_header;
		struct config_ram config_ram;
	}
	* confirm = (struct vs_rd_cblock_confirm *) (message);

#ifndef __GNUC__
#pragma pack (pop)
#endif

	struct config_ram * config_ram = (struct config_ram *) (& confirm->config_ram);
	Request (plc, "Fetch SDRAM Parameters");
	memset (message, 0, sizeof (* message));
	EthernetHeader (& request->ethernet, channel->peer, channel->host, channel->type);
	QualcommHeader (& request->qualcomm, 0, (VS_RD_CBLOCK | MMTYPE_REQ));
	plc->packetsize = (ETHER_MIN_LEN - ETHER_CRC_LEN);
	if (SendMME (plc) <= 0)
	{
		error (PLC_EXIT (plc), errno, CHANNEL_CANTSEND);
		return (-1);
	}
	while (ReadMME (plc, 0, (VS_RD_CBLOCK | MMTYPE_CNF)) > 0)
	{
		if (confirm->MSTATUS)
		{
			Failure (plc, PLC_WONTDOIT);
			continue;
		}
		Confirm (plc, "-------");
		sdrampeek (config_ram);
	}
	return (0);
}

#endif



