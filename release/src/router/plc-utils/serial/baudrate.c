/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   baud_t baudrate (unsigned rate) 
 *
 *   convert integer baud rate to system constant or bitmap;
 *   
 *
 *   Contributor(s):
 *	Nathaniel Houghton <nhoughto@qca.qualcomm.com>
 *	Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef BAUDRATE_SOURCE
#define BAUDRATE_SOURCE

#include <termios.h>
#include <errno.h>

#include "../tools/error.h"

signed baudrate (unsigned baud, speed_t * speed) 

{ 
	static struct baud 
	{ 
		unsigned baud; 
		speed_t code; 
	} 
	bauds [] = 
	{ 
		{ 
			0, 
			B0
		}, 
		{ 
			50, 
			B50
		}, 
		{ 
			75, 
			B75
		}, 
		{ 
			110, 
			B110
		}, 
		{ 
			134, 
			B134
		}, 
		{ 
			150, 
			B150
		}, 
		{ 
			200, 
			B200
		}, 
		{ 
			300, 
			B300
		}, 
		{ 
			600, 
			B600
		}, 
		{ 
			1200, 
			B1200
		}, 
		{ 
			1800, 
			B1800
		}, 
		{ 
			2400, 
			B2400
		}, 
		{ 
			4800, 
			B4800
		}, 
		{ 
			9600, 
			B9600
		}, 
		{ 
			19200, 
			B19200
		}, 
		{ 
			38400, 
			B38400
		}, 
		{ 
			57600, 
			B57600
		}, 
		{ 
			115200, 
			B115200
		}, 

#ifdef B230400

		{ 
			230400, 
			B230400
		}, 

#endif
#ifdef B460800

		{ 
			460800, 
			B460800
		}, 

#endif
#ifdef B500000

		{ 
			500000, 
			B500000
		}, 

#endif
#ifdef B921600

		{ 
			921600, 
			B921600
		}, 

#endif

	}; 
	signed lower = 0; 
	signed upper = sizeof (bauds) / sizeof (struct baud); 
	while (lower < upper) 
	{ 
		signed index = (lower +  upper) >> 1; 
		signed order = baud - bauds [index].baud; 
		if (order < 0) 
		{ 
			upper = index - 0; 
			continue; 
		} 
		if (order > 0) 
		{ 
			lower = index +  1; 
			continue; 
		} 
		* speed = bauds [index].code; 
		return (0); 
	} 
	return (- 1); 
} 

#endif



