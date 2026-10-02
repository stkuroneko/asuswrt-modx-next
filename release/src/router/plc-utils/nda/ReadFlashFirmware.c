/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed ReadFlashFirmware (struct plc *plc);
 *
 *   nda.h
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef READFLASHFIRMWARE_SOURCE
#define READFLASHFIRMWARE_SOURCE

#include <stdint.h>
#include <unistd.h>
#include <memory.h>

#include "../tools/error.h"
#include "../tools/files.h"
#include "../nvm/nvm.h"
#include "../plc/plc.h"
#include "../nda/nda.h"

signed ReadFlashFirmware (struct plc * plc)

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

	uint32_t offset = 0;
	uint32_t length = PLC_RECORD_SIZE;
	Request (plc, "Reading Flash");
	if (lseek (plc->nvm.file, 0, SEEK_SET))
	{
		error (PLC_EXIT (plc), errno, FILE_CANTHOME, plc->nvm.name);
		return (1);
	}
	do 
	{
		memset (message, 0, sizeof (* message));
		EthernetHeader (& request->ethernet, channel->peer, channel->host, channel->type);
		QualcommHeader (& request->qualcomm, 0, (VS_RD_BLK_NVM | MMTYPE_REQ));
		plc->packetsize = (ETHER_MIN_LEN - ETHER_CRC_LEN);
		request->MODULEID = HTOLE16 (MID_FIRMWARE);
		request->MLENGTH = HTOLE32 (length);
		request->MOFFSET = HTOLE32 (offset);
		if (SendMME (plc) <= 0)
		{
			error (PLC_EXIT (plc), ECANCELED, CHANNEL_CANTSEND);
			return (-1);
		}
		if (ReadMME (plc, 0, (VS_RD_BLK_NVM | MMTYPE_CNF)) <= 0)
		{
			error (PLC_EXIT (plc), ECANCELED, CHANNEL_CANTREAD);
			return (-1);
		}
		if (confirm->MSTATUS)
		{
			Failure (plc, PLC_WONTDOIT);
			return (-1);
		}
		if (LE32TOH (confirm->MOFFSET) != offset)
		{
			Failure (plc, PLC_ERR_OFFSET);
			return (-1);
		}
		if (LE32TOH (confirm->MLENGTH) != length)
		{
			Failure (plc, PLC_ERR_LENGTH);
			return (-1);
		}
		

		if (lseek (plc->nvm.file, offset, SEEK_SET) != (signed) (offset))
		{
			error (PLC_EXIT (plc), errno, "Can't seek %s", plc->nvm.name);
			return (-1);
		}
		if (write (plc->nvm.file, confirm->BUFFER, length) < (signed) (length))
		{
			error (PLC_EXIT (plc), errno, "Can't save %s", plc->nvm.name);
			return (-1);
		}
		offset += length;// read another 1K block
		
	}
	// read the entire flash
	while ( offset < ( 2048 * 1024 ) );
	return (0);
}

#endif



