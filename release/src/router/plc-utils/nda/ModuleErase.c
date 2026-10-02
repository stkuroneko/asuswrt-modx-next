/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed ModuleErase (struct plc * plc, struct vs_module_spec * vs_module_spec);
 *
 *   plc.h
 *
 *   erase a module by writing 0xFF to all locations in flash memory;
 *   in most cases, the module will be all of flash memory; allow up
 *   to 60 seconds for each write to complete; extra time is needed
 *   because memory must be erased;
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef MODULEERASE_SOURCE
#define MODULEERASE_SOURCE

#include <stdint.h>
#include <limits.h>
#include <unistd.h>
#include <string.h>
#include <memory.h>

#include "../tools/error.h"
#include "../plc/plc.h" 

signed ModuleErase (struct plc * plc, struct vs_module_spec * vs_module_spec)

{
	struct channel * channel = (struct channel *) (plc->channel);
	struct message * message = (struct message *) (plc->message);

#ifndef __GNUC__
#pragma pack (push,1)
#endif

	struct __packed vs_module_operation_write_request
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
		uint32_t RESERVED;
		uint8_t NUM_OP_DATA;
		struct __packed
		{
			uint16_t MOD_OP;
			uint16_t MOD_OP_DATA_LEN;
			uint32_t MOD_OP_RSVD;
			uint32_t MOD_OP_SESSION_ID;
			uint8_t MODULE_IDX;
			uint16_t MODULE_ID;
			uint16_t MODULE_SUB_ID;
			uint16_t DATA_LENGTH;
			uint32_t DATA_OFFSET;
		}
		MODULE_SPEC;
		uint8_t MODULE_DATA [PLC_MODULE_SIZE];
	}
	* request = (struct vs_module_operation_write_request *) (message);
	struct __packed vs_module_operation_write_confirm
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
		uint16_t MSTATUS;
		uint16_t ERR_REC_CODE;
		uint32_t RESERVED;
		uint8_t NUM_OP_DATA;
		struct __packed
		{
			uint16_t MOD_OP;
			uint16_t MOD_OP_DATA_LEN;
			uint32_t MOD_OP_RSVD;
			uint32_t MOD_OP_SESSION_ID;
			uint8_t MODULE_IDX;
			uint16_t MODULE_ID;
			uint16_t MODULE_SUB_ID;
			uint16_t DATA_LENGTH;
			uint32_t DATA_OFFSET;
		}
		MODULE_SPEC;
	}
	* confirm = (struct vs_module_operation_write_confirm *) (message);

#ifndef __GNUC__
#pragma pack (pop)
#endif

	unsigned timeout = channel->timeout;
	uint16_t length = PLC_MODULE_SIZE;
	uint32_t extent = vs_module_spec->MODULE_LENGTH;
	uint32_t offset = 0;
	Request (plc, "Erase Flash Memory");
	while (extent)
	{
		memset (message, 0, sizeof (* message));
		EthernetHeader (& request->ethernet, channel->peer, channel->host, channel->type);
		QualcommHeader (& request->qualcomm, 0, (VS_MODULE_OPERATION | MMTYPE_REQ));
		plc->packetsize = sizeof (struct vs_module_operation_write_request);
		if (length > extent)
		{
			length = extent;
		}
		request->NUM_OP_DATA = 1;
		request->MODULE_SPEC.MOD_OP = HTOLE16 (0x11);
		request->MODULE_SPEC.MOD_OP_DATA_LEN = HTOLE16 (sizeof (request->MODULE_SPEC) +  sizeof (request->MODULE_DATA));
		request->MODULE_SPEC.MOD_OP_SESSION_ID = HTOLE32 (plc->cookie);
		request->MODULE_SPEC.MODULE_IDX = 0;
		request->MODULE_SPEC.MODULE_ID = HTOLE16 (vs_module_spec->MODULE_ID);
		request->MODULE_SPEC.MODULE_SUB_ID = HTOLE16 (vs_module_spec->MODULE_SUB_ID);
		request->MODULE_SPEC.DATA_LENGTH = HTOLE16 (length);
		request->MODULE_SPEC.DATA_OFFSET = HTOLE32 (offset);
		memset (request->MODULE_DATA, 0xFF, length);
		if (SendMME (plc) <= 0)
		{
			error (1, errno, CHANNEL_CANTSEND);
		}
		channel->timeout = PLC_MODULE_WRITE_TIMEOUT;
		if (ReadMME (plc, 0, (VS_MODULE_OPERATION | MMTYPE_CNF)) <= 0)
		{
			error (1, errno, CHANNEL_CANTREAD);
		}
		channel->timeout = timeout;
		if (confirm->MSTATUS)
		{
			Failure (plc, PLC_WONTDOIT);
			return (-1);
		}
		if (LE16TOH (confirm->MODULE_SPEC.DATA_LENGTH) != length)
		{
			error (1, 0, PLC_ERR_LENGTH);
		}
		if (LE32TOH (confirm->MODULE_SPEC.DATA_OFFSET) != offset)
		{
			error (1, 0, PLC_ERR_OFFSET);
		}
		extent -= length;
		offset += length;
	}
	return (0);
}

#endif



