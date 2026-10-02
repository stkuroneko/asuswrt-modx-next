/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   int sdramfileA (int fd, char const * filename, flag_t flags);
 *
 *   sdram.h
 *
 *   open an SDRAM configuration file and validate it by checking the
 *   file length; unfortunately there are not many things to check;
 *
 *   Contributor(s):
 *	Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef SDRAMFILEA_SOURCE
#define SDRAMFILEA_SOURCE

#include <unistd.h>
#include <memory.h>
#include <fcntl.h>
#include <errno.h>

#include "../ram/sdram.h"
#include "../tools/memory.h"
#include "../tools/error.h"
#include "../tools/flags.h"

int sdramfileA (int fd, char const * filename, flag_t flags) 

{ 
	uint32_t checksum; 
	struct config_ram config_ram; 
	memset (& config_ram, 0, sizeof (config_ram)); 
	if (lseek (fd, 0, SEEK_SET) == - 1) 
	{ 
		if (_allclr (flags, SDRAM_SILENCE)) 
		{ 
			error (0, errno, "Can't rewind file: %s", filename); 
		} 
		return (- 1); 
	} 
	if (read (fd, & config_ram, sizeof (config_ram)) != sizeof (config_ram)) 
	{ 
		if (_allclr (flags, SDRAM_SILENCE)) 
		{ 
			error (0, errno, "Wrong file size: %s", filename); 
		} 
		return (- 1); 
	} 
	if (read (fd, & checksum, sizeof (checksum)) != sizeof (checksum)) 
	{ 
		if (_allclr (flags, SDRAM_SILENCE)) 
		{ 
			error (0, errno, "Can't read checksum: %s", filename); 
		} 
		return (- 1); 
	} 
	if (checksum32 ((uint32_t *) (& config_ram), sizeof (config_ram) >> 2, checksum)) 
	{ 
		if (_allclr (flags, SDRAM_SILENCE)) 
		{ 
			error (0, 0, "Bad checksum: %s", filename); 
		} 
		return (- 1); 
	} 
	if (_anyset (flags, SDRAM_VERBOSE)) 
	{ 
		if ((filename) && (* filename)) 
		{ 
			printf ("------- %s -------\n", filename); 
		} 
		sdrampeek (& config_ram); 
	} 
	if (lseek (fd, 0, SEEK_SET) == - 1) 
	{ 
		if (_allclr (flags, SDRAM_SILENCE)) 
		{ 
			error (0, errno, "Can't rewind file: %s", filename); 
		} 
		return (- 1); 
	} 
	return (0); 
} 

#endif



