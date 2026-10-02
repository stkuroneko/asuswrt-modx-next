/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed SendMME (struct plc * plc);
 *
 *   plc.h
 *
 *   send management message over Ethernet in a platform independent
 *   fashion; return the number of bytes sent on succes, 0 on timeout
 *   or -1 on error;
 *
 *   see ReadMME for the vendor specific read counterpart to this
 *   function;
 *
 *   see ReadMFG for the manufacturer specific read counterpart to
 *   this function;
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *      Nathaniel Houghton <nhoughto@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef SENDMME_SOURCE
#define SENDMME_SOURCE

#include <stdint.h>

#include "../plc/plc.h"

signed SendMME (struct plc * plc)

{
	struct channel * channel = (struct channel *) (plc->channel);
	struct message * message = (struct message *) (plc->message);
	signed length = sendpacket (channel, message, plc->packetsize);
	return (length);
}
signed SendMME1 (struct plc * plc)

{
	struct channel * channel1 = (struct channel *) (plc->channel1);
	struct message * message = (struct message *) (plc->message);
	signed length = sendpacket (channel1, message, plc->packetsize);
	return (length);
}
#endif



