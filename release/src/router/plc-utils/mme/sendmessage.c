/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   ssize_t sendmessage (struct channel const * channel, struct message * message, ssize_t length);
 *
 *   plc.h
 *   
 *   send management message over Ethernet in a platform independent
 *   fashion; return the number of bytes sent on succes, 0 on timeout
 *   or -1 on error;
 *
 *   see readmessage for the vendor specific read counterpart to this 
 *   function;
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *      Nathaniel Houghton <nhoughto@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef SENDMESSAGE_SOURCE
#define SENDMESSAGE_SOURCE

#include <stdint.h>

#include "../plc/plc.h"

ssize_t sendmessage (struct channel const * channel, struct message * message, ssize_t length) 

{ 
	return (sendpacket (channel, message, length)); 
} 

#endif



