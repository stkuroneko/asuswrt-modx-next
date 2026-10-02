/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   void closeport (struct _file_ * port);
 *
 *   serial.h
 *
 *   close a serial port;
 *
 *   Contributor(s):
 *	Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef CLOSEPORT_SOURCE
#define CLOSEPORT_SOURCE

#include <unistd.h>
#include <stdlib.h>

#include "../tools/types.h"
#include "../serial/serial.h"

void closeport (struct _file_ * port) 

{ 
	close (port->file); 
	return; 
} 

#endif



