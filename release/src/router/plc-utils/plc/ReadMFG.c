/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed ReadMFG (struct plc * plc, uint16_t MMTYPE);
 *
 *   plc.h
 *
 *   read a manufacturer specific management message of the given
 *   type in platform independent manner; return the number of bytes
 *   read, 0 on timeout or -1 on error;
 *
 *   see SendMME for the send counterpart to this function;
 *
 *   see ReadMME for the vendor specific version of this function;
 *
 *   readpacket behaves like the read function but there are several
 *   readpacket functions in the toolkit and each performs raw packet
 *   i/o differently depending on environment; they all use a channel
 *   structure;
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *      Nathaniel Houghton <nhoughto@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef READMFG_SOURCE
#define READMFG_SOURCE

#include <memory.h>

#include "../plc/plc.h"
#include "../ether/channel.h"
#include "../tools/memory.h" 
#include "../tools/flags.h"

signed ReadMFG (struct plc * plc, uint8_t MMV, uint16_t MMTYPE)

{
	struct channel * channel = (struct channel *) (plc->channel);
	struct message * message = (struct message *) (plc->message);
	struct homeplug1 * homeplug = (struct homeplug1 *) (message);
	while ((plc->packetsize = readpacket (channel, message, sizeof (* message))) > 0)
	{
		if (homeplug->homeplug.MMV != MMV)
		{
			continue;
		}
		if (homeplug->homeplug.MMTYPE != HTOLE16 (MMTYPE))
		{
			continue;
		}
		break;
	}
	return (plc->packetsize);
}

#endif



