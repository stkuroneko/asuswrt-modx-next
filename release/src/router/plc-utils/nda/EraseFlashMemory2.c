/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed EraseFlashMemory2 (struct plc * plc);
 *
 *   plc.h
 *
 *   determine the overall size of flash memory with VS_GET_NVM then
 *   erase flash memory by writing 0xFF to all of flash memory using
 *   VS_MODULE_OPERATION messages; force flash but do not reset;
 *
 *   struct vs_module_spec is defined in plc.h;
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef ERASEFLASHMEMORY2_SOURCE
#define ERASEFLASHMEMORY2_SOURCE

#include <stdint.h>
#include <memory.h>

#include "../tools/error.h"
#include "../tools/memory.h"
#include "../tools/symbol.h"
#include "../ram/nvram.h"
#include "../plc/plc.h"
#include "../nda/nda.h"

signed EraseFlashMemory2 (struct plc * plc)

{
	struct channel * channel = (struct channel *) (plc->channel);
	struct message * message = (struct message *) (plc->message);

#ifndef __GNUC__
#pragma pack (push,1)
#endif

	struct __packed vs_get_nvm_request
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
	}
	* request = (struct vs_get_nvm_request *) (message);
	struct __packed vs_get_nvm_confirm
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
		uint8_t MSTATUS;
		struct config_nvram config_nvram;
	}
	* confirm = (struct vs_get_nvm_confirm *) (message);

#ifndef __GNUC__
#pragma pack (pop)
#endif

	struct vs_module_spec vs_module_spec =
	{
		PLC_MODULEID_RESERVED1,
		0,
		0,
		0
	};
	struct config_nvram * config_nvram = (struct config_nvram *) (& confirm->config_nvram);
	memcpy (channel->peer, message->ethernet.OSA, sizeof (channel->peer));
	Request (plc, "Probe Flash Memory");
	memset (message, 0, sizeof (* message));
	EthernetHeader (& request->ethernet, channel->peer, channel->host, channel->type);
	QualcommHeader (& request->qualcomm, 0, (VS_GET_NVM | MMTYPE_REQ));
	plc->packetsize = (ETHER_MIN_LEN - ETHER_CRC_LEN);
	if (SendMME (plc) <= 0)
	{
		error (PLC_EXIT (plc), errno, CHANNEL_CANTSEND);
		return (-1);
	}
	if (ReadMME (plc, 0, (VS_GET_NVM | MMTYPE_CNF)) <= 0)
	{
		error (PLC_EXIT (plc), errno, CHANNEL_CANTSEND);
		return (-1);
	}
	if (confirm->MSTATUS)
	{
		Failure (plc, PLC_WONTDOIT);
		return (-1);
	}
	vs_module_spec.MODULE_LENGTH = LE32TOH (config_nvram->NVRAMSIZE);
	if (vs_module_spec.MODULE_LENGTH & sizeof (uint32_t))
	{
		vs_module_spec.MODULE_CHKSUM = 0;
	}
	else 
	{
		vs_module_spec.MODULE_CHKSUM = ~ 0;
	}
	if (ModuleSession (plc, 1, & vs_module_spec))
	{
		return (-1);
	}
	if (ModuleErase (plc, & vs_module_spec))
	{
		return (-1);
	}
	if (ModuleCommit (plc, 0))
	{
		return (-1);
	}
	return (0);
}

#endif



