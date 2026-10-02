/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed FlashMOD (struct channel * channel, uint8_t module);
 *
 *   plc.h
 *
 *   commit downloaded firmware and/or parameters to NVRAM using a
 *   VS_MOD_NVM message; flash-less devices will attempt to upload
 *   to the local host since they have no NVRAM; the host must be
 *   ready to receive the module;
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *      Nathaniel Houghton <nhoughto@qca.qualcomm.com>
 *      Matthieu Poullet <m.poullet@avm.de>
 *
 *--------------------------------------------------------------------*/

#ifndef FLASHMOD_SOURCE
#define FLASHMOD_SOURCE

#include <stdint.h>
#include <memory.h>

#include "../plc/plc.h"
#include "../tools/error.h"
#include "../tools/memory.h"

signed FlashMOD (struct channel * channel, uint8_t module)

{
	struct message message;

#ifndef __GNUC__
#pragma pack (push,1)
#endif

	struct __packed vs_mod_nvm_request
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
		uint8_t MODULEID;
	}
	* request = (struct vs_mod_nvm_request *) (& message);
	struct __packed vs_mod_nvm_confirm
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
		uint8_t MSTATUS;
		uint8_t MODULEID;
	}
	* confirm = (struct vs_mod_nvm_confirm *) (& message);

#ifndef __GNUC__
#pragma pack (pop)
#endif

	ssize_t packetsize;
	memset (& message, 0, sizeof (message));
	EthernetHeader (& request->ethernet, channel->peer, channel->host, channel->type);
	QualcommHeader (& request->qualcomm, 0, (VS_MOD_NVM | MMTYPE_REQ));
	request->MODULEID = module;
	if (sendpacket (channel, & message, (ETHER_MIN_LEN - ETHER_CRC_LEN)) <= 0)
	{
		error (1, errno, CHANNEL_CANTSEND);
	}
	if ((packetsize = readpacket (channel, & message, sizeof (message))) <= 0)
	{
		error (1, errno, CHANNEL_CANTREAD);
	}
	if (UnwantedMessage (& message, packetsize, 0, (VS_MOD_NVM | MMTYPE_CNF)))
	{
		error (1, ECANCELED, PLC_BADFRAME);
	}
	if (confirm->MSTATUS)
	{
		error (1, ECANCELED, PLC_WONTDOIT);
	}
	return (0);
}

#endif



