/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   void Request (struct plc * plc, char const * format, ...);
 *
 *   plc.h
 *
 *   Inform the user that an operation has started; print the channel
 *   name, template destination address and user message on stdout
 *   unless the PLC_SILENCE flag is set;
 *
 *   This function is identical to Confirm () except that it prints
 *   the template destination address instead of the packet source
 *   address because it is called before outgoing frames are encoded;
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef REQUEST_SOURCE
#define REQUEST_SOURCE

#include <stdio.h>
#include <stdarg.h>

#include "../plc/plc.h"
#include "../tools/memory.h"
#include "../tools/flags.h"

#ifdef __GNUC__

__attribute__ ((format (printf, 2, 3))) 

#endif

void Request (struct plc * plc, char const * format, ...)

{
	if (_allclr (plc->flags, PLC_SILENCE))
	{
		char address [ETHER_ADDR_LEN * 3];
		struct channel * channel = (struct channel *) (plc->channel);
		hexdecode (channel->peer, sizeof (channel->peer), address, sizeof (address));
		fprintf (stderr, "%s %s ", channel->ifname, address);
		if ((format) && (* format))
		{
			va_list arglist;
			va_start (arglist, format);
			vfprintf (stderr, format, arglist);
			va_end (arglist);
		}
		fprintf (stderr, "\n");
	}
	return;
}

#endif



