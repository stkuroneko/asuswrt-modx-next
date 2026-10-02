/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed WriteParamters2 (struct plc * plc, unsigned module, const struct panther_nvm_header * nvm_header);
 *
 *   plc.h
 *
 *   use VS_WR_MEM message to write a parameter block into SDRAM
 *   when the image is stored in the old image file format;
 *
 *   the boot loader must be running for this to work since runtime
 *   firmware ignores VS_WR_MEM messages;
 *
 *   future devices will ignore VS_WR_MEM messages so use function
 *   WriteExecuteParameters2, instead;
 *
 *   this function makes no attempt to validate the information sent
 *   to the device;
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef WRITEPARAMETERS2_SOURCE
#define WRITEPARAMETERS2_SOURCE

#include <stdint.h>
#include <unistd.h>
#include <memory.h>

#include "../tools/files.h"
#include "../tools/error.h"
#include "../tools/memory.h"
#include "../plc/plc.h"

signed WriteParameters2 (struct plc * plc, unsigned module, const struct panther_nvm_header * nvm_header)

{
	struct channel * channel = (struct channel *) (plc->channel);
	struct message * message = (struct message *) (plc->message);

#ifndef __GNUC__
#pragma pack (push,1)
#endif

	struct __packed vs_wr_mem_request
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
		uint32_t MOFFSET;
		uint32_t MLENGTH;
		uint8_t BUFFER [PLC_RECORD_SIZE];
	}
	* request = (struct vs_wr_mem_request *) (message);
	struct __packed vs_wr_mem_confirm
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
		uint8_t MSTATUS;
		uint32_t MOFFSET;
		uint32_t MLENGTH;
	}
	* confirm = (struct vs_wr_mem_confirm *) (message);

#ifndef __GNUC__
#pragma pack (pop)
#endif

	uint32_t length = PLC_RECORD_SIZE;
	uint32_t offset = LE32TOH (nvm_header->ImageAddress);
	uint32_t extent = LE32TOH (nvm_header->ImageLength);
	Request (plc, "Write %s (%d) (%08X:%d)", plc->PIB.name, module, offset, extent);
	while (extent)
	{
		memset (message, 0, sizeof (* message));
		EthernetHeader (& request->ethernet, channel->peer, channel->host, channel->type);
		QualcommHeader (& request->qualcomm, 0, (VS_WR_MEM | MMTYPE_REQ));
		if (length > extent)
		{
			length = extent;
		}
		if (read (plc->PIB.file, request->BUFFER, length) != (signed) (length))
		{
			error (1, errno, FILE_CANTREAD, plc->PIB.name);
		}
		request->MLENGTH = HTOLE32 (length);
		request->MOFFSET = HTOLE32 (offset);
		plc->packetsize = sizeof (* request);
		if (SendMME (plc) <= 0)
		{
			error (PLC_EXIT (plc), errno, CHANNEL_CANTSEND);
			return (-1);
		}
		if (ReadMME (plc, 0, (VS_WR_MEM | MMTYPE_CNF)) <= 0)
		{
			error (PLC_EXIT (plc), errno, CHANNEL_CANTREAD);
			return (-1);
		}
		if (confirm->MSTATUS)
		{
			Failure (plc, PLC_WONTDOIT);
			return (-1);
		}
		if (LE32TOH (confirm->MLENGTH) != length)
		{
			error (PLC_EXIT (plc), 0, PLC_ERR_LENGTH);
			length = PLC_RECORD_SIZE;
			offset = 0;
			continue;
		}
		if (LE32TOH (confirm->MOFFSET) != offset)
		{
			error (PLC_EXIT (plc), 0, PLC_ERR_OFFSET);
			length = PLC_RECORD_SIZE;
			offset = 0;
			continue;
		}
		offset += length;
		extent -= length;
	}
	return (0);
}

#endif



