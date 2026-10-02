/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed ReadFlashMemory1 (struct plc * plc);
 *
 *   plc.h
 *
 *   read all of flash memory and write to file;
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef READFLASHMEMORY1_SOURCE
#define READFLASHMEMORY1_SOURCE

#include <string.h>

#include "../tools/error.h"
#include "../tools/files.h"
#include "../tools/memory.h"
#include "../tools/endian.h"
#include "../plc/plc.h" 
#include "../nda/nda.h"

signed ReadFlashMemory1 (struct plc * plc)

{
	struct channel * channel = (struct channel *) (plc->channel);
	struct message * message = (struct message *) (plc->message);

#ifndef __GNUC__
#pragma pack (push,1)
#endif

	struct __packed vs_rd_blk_nvm_request
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
		uint16_t MODULEID;
		uint32_t MOFFSET;
		uint32_t MLENGTH;
	}
	* request = (struct vs_rd_blk_nvm_request *) (message);
	struct __packed vs_rd_blk_nvm_confirm
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
		uint8_t MSTATUS;
		uint16_t MODULEID;
		uint32_t MOFFSET;
		uint32_t MLENGTH;
		uint8_t BUFFER [PLC_RECORD_SIZE];
	}
	* confirm = (struct vs_rd_blk_nvm_confirm *) (message);

#ifndef __GNUC__
#pragma pack (pop)
#endif

	unsigned offset = 0;
	unsigned length = PLC_MODULE_SIZE;
	Request (plc, "Read Flash Memory");
	while (length == PLC_MODULE_SIZE)
	{
		memset (message, 0, sizeof (* message));
		EthernetHeader (& request->ethernet, channel->peer, channel->host, channel->type);
		QualcommHeader (& request->qualcomm, 0, (VS_RD_BLK_NVM | MMTYPE_REQ));
		plc->packetsize = (ETHER_MIN_LEN - ETHER_CRC_LEN);
		request->MODULEID = HTOLE16 (MID_USERPIB);
		request->MOFFSET = HTOLE32 (offset);
		request->MLENGTH = HTOLE32 (length);
		if (SendMME (plc) <= 0)
		{
			error (PLC_EXIT (plc), errno, CHANNEL_CANTSEND);
			return (-1);
		}
		if (ReadMME (plc, 0, (VS_RD_BLK_NVM | MMTYPE_CNF)) <= 0)
		{
			error (PLC_EXIT (plc), errno, CHANNEL_CANTREAD);
			return (-1);
		}
		if (confirm->MSTATUS)
		{
			Failure (plc, PLC_WONTDOIT);
			return (-1);
		}
		length = LE16TOH (confirm->MLENGTH);
		offset = LE32TOH (confirm->MOFFSET);
		if (write (plc->nvm.file, confirm->BUFFER, length) != (signed) (length))
		{
			error (PLC_EXIT (plc), errno, FILE_CANTSAVE, plc->nvm.name);
			return (-1);
		}
		offset += length;
	}
	return (0);
}

#endif



