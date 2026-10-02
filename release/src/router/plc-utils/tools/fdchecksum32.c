/*====================================================================*
 *
 *   uint32_t fdchecksum32 (int fd, size_t extent, uint32_t checksum);
 *
 *   memory.h
 *
 *   return the 32-bit checksum of a file region starting from the
 *   current file position; extent is specified in bytes but will be
 *   rounded to a multiple of four bytes;
 *
 *   Motley Tools by Charles Maier <cmaier@cmassoc.net>;
 *   Copyright (c) 2001-2006 by Charles Maier Associates;
 *   Licensed under the Internet Software Consortium License;
 *
 *--------------------------------------------------------------------*/

#ifndef FDCHECKSUM32_SOURCE
#define FDCHECKSUM32_SOURCE

#include <stdio.h>
#include <unistd.h>
#include <errno.h>

#include "../tools/memory.h"

#define FDCHECKSUM32_BUFFERED

uint32_t fdchecksum32 (int fd, register size_t extent, register uint32_t checksum) 

{ 

#ifdef FDCHECKSUM32_BUFFERED

	uint32_t buf [256]; 
	size_t read_amt; 
	while (extent >= sizeof (checksum)) 
	{ 
		read_amt = extent; 
		if (read_amt > sizeof (buf)) 
		{ 
			read_amt = sizeof (buf); 
		} 
		if (read (fd, buf, read_amt) != (ssize_t) read_amt) 
		{ 
			return (- 1); 
		} 
		extent -= read_amt; 
		while (read_amt >= sizeof (checksum)) 
		{ 
			checksum ^= buf [(read_amt >> 2) - 1]; 
			read_amt -= sizeof (checksum); 
		} 
	} 
	return (~ checksum); 

#else

	uint32_t memory; 
	while (extent >= sizeof (memory)) 
	{ 
		if (read (fd, & memory, sizeof (memory)) != sizeof (memory)) 
		{ 
			return (- 1); 
		} 
		extent -= sizeof (memory); 
		checksum ^= memory; 
	} 
	return (~ checksum); 

#endif

} 

#endif



