/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed WriteNVM (struct plc * plc);
 *
 *   plc.h
 *
 *   write an entire .nvm file into PLC SDRAM using as many VS_WR_MEM
 *   messages as needed to complete the transfer;
 *
 *   runtime firmware must be running for this to work; the NVM file
 *   in struct plc must be opened before calling this function;
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *      Nathaniel Houghton <nhoughto@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef WRITENVM_SOURCE
#define WRITENVM_SOURCE

#include <stdint.h>
#include <unistd.h>
#include <memory.h>

#include "../plc/plc.h" 
#include "../tools/memory.h"
#include "../tools/error.h"
#include "../tools/files.h"

signed WriteNVM (struct plc * plc)

{
	struct channel * channel = (struct channel *) (plc->channel);
	struct message * message = (struct message *) (plc->message);

#ifndef __GNUC__
#pragma pack (push,1)
#endif

	struct __packed vs_wr_mod_request
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
		uint8_t MODULEID;
		uint8_t RESERVED;
		uint16_t MLENGTH;
		uint32_t MOFFSET;
		uint32_t MCHKSUM;
		uint8_t MBUFFER [PLC_RECORD_SIZE];
	}
	* request = (struct vs_wr_mod_request *) (message);
	struct __packed vs_wr_mod_confirm
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
		uint8_t MSTATUS;
		uint8_t MODULEID;
		uint8_t RESERVED;
		uint16_t MLENGTH;
		uint32_t MOFFSET;
	}
	* confirm = (struct vs_wr_mod_confirm *) (message);

#ifndef __GNUC__
#pragma pack (pop)
#endif

	uint16_t length = PLC_RECORD_SIZE;
	uint32_t extent = lseek (plc->NVM.file, 0, SEEK_END);
	uint32_t offset = lseek (plc->NVM.file, 0, SEEK_SET);
	if (~ plc->NVM.file)
	{
		Request (plc, "Write %s to scratch", plc->NVM.name);
		while (extent)
		{
			memset (message, 0, sizeof (* message));
			EthernetHeader (& request->ethernet, channel->peer, channel->host, channel->type);
			QualcommHeader (& request->qualcomm, 0, (VS_WR_MOD | MMTYPE_REQ));
			if (length > extent)
			{
				length = extent;
			}
			if (read (plc->NVM.file, request->MBUFFER, length) != length)
			{
				error (1, errno, FILE_CANTREAD, plc->NVM.name);
			}
			request->MODULEID = VS_MODULE_MAC;
			request->RESERVED = 0;
			request->MLENGTH = HTOLE16 (length);
			request->MOFFSET = HTOLE32 (offset);
			request->MCHKSUM = checksum32 (request->MBUFFER, length, 0);
			plc->packetsize = sizeof (* request);
			if (SendMME (plc) <= 0)
			{
				error (PLC_EXIT (plc), errno, CHANNEL_CANTSEND);
				return (-1);
			}
			if (ReadMME (plc, 0, (VS_WR_MOD | MMTYPE_CNF)) <= 0)
			{
				error (PLC_EXIT (plc), errno, CHANNEL_CANTREAD);
				return (-1);
			}
			if (confirm->MSTATUS)
			{
				Failure (plc, PLC_WONTDOIT);
				return (-1);
			}
			if (LE16TOH (confirm->MLENGTH) != length)
			{
				error (PLC_EXIT (plc), 0, PLC_ERR_LENGTH);
				return (-1);
			}
			if (LE32TOH (confirm->MOFFSET) != offset)
			{
				error (PLC_EXIT (plc), 0, PLC_ERR_OFFSET);
				return (-1);
			}
			extent -= length;
			offset += length;
		}
	}
	return (0);
}

#endif



