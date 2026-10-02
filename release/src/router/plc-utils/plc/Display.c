/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   void Display (struct plc * plc, char const * message);
 *
 *   plc.h
 *
 *   Inform the user that an operation suceeded; print channel name,
 *   packet source device and user defined message on stdout;
 *
 *   This function is identical to Confirm () except that a message
 *   is always printed on stdout and cannot be suppressed;
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef DISPLAY_SOURCE
#define DISPLAY_SOURCE

#include <stdio.h>
#include <stdarg.h>

#include "../plc/plc.h"
#include "../tools/memory.h"

#ifdef __GNUC__

__attribute__ ((format (printf, 2, 3))) 

#endif

void Display (struct plc * plc, char const * format, ...)

{
	char address [ETHER_ADDR_LEN * 3];
	struct channel * channel = (struct channel *) (plc->channel);
	struct message * message = (struct message *) (plc->message);
	hexdecode (message->ethernet.OSA, sizeof (message->ethernet.OSA), address, sizeof (address));
	printf ("%s %s ", channel->ifname, address);
	if ((format) && (* format))
	{
		va_list arglist;
		va_start (arglist, format);
		vprintf (format, arglist);
		va_end (arglist);
	}
	printf ("\n");
	return;
}

#endif



