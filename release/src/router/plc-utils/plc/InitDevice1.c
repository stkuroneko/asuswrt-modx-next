/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   int InitDevice1 (struct plc * plc);
 *
 *   plc.h
 *
 *   configure volatile memory by finding the memctl applet in an
 *   older .nvm file then downloading it and executing it;
 *
 *   this implementation detects chipsets prior to INT6400 and uses
 *   VS_WR_MEM/VS_ST_MAC messages instead of VS_WRITE_AND_EXECUTE
 *   messages;
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef INITDEVICE1_SOURCE
#define INITDEVICE1_SOURCE

#include <stdint.h>
#include <unistd.h>
#include <memory.h>
#include <errno.h>

#include "../tools/memory.h"
#include "../tools/files.h"
#include "../tools/flags.h"
#include "../tools/error.h"
#include "../plc/plc.h"
#include "../nvm/nvm.h"

int InitDevice1 (struct plc * plc)

{
	unsigned module = 0;
	struct lightning_nvm_header nvm_header;
	if (lseek (plc->NVM.file, 0, SEEK_SET))
	{
		error (1, errno, FILE_CANTHOME, plc->NVM.name);
	}
	do 
	{
		if (read (plc->NVM.file, & nvm_header, sizeof (nvm_header)) != sizeof (nvm_header))
		{
			error (1, errno, NVM_HDR_CANTREAD, plc->NVM.name, module);
		}
		if (LE32TOH (nvm_header.HEADERVERSION) != 0x60000000)
		{
			error (1, 0, NVM_HDR_VERSION, plc->NVM.name, module);
		}
		if (checksum32 (& nvm_header, sizeof (nvm_header), 0))
		{
			error (1, 0, NVM_HDR_CHECKSUM, plc->NVM.name, module);
		}

#if 0

		if (_anyset (LE16TOH (nvm_header.IGNOREMASK), (1 << (plc->hardwareID -1))))
		{
			if (lseek (plc->NVM.file, LE32TOH (nvm_header.NEXTHEADER), SEEK_SET) == -1)
			{
				error (1, errno, "Can't skip module: %s (%d)", plc->NVM.name, module);
			}
		}
		else

#endif

		if (nvm_header.IMAGETYPE == NVM_IMAGE_MEMCTL)
		{
			if (plc->hardwareID < CHIPSET_AR7400)
			{
				if (WriteFirmware1 (plc, module, & nvm_header))
				{
					return (-1);
				}
				if (StartFirmware1 (plc, module, & nvm_header))
				{
					return (-1);
				}
				break;
			}
			WriteExecuteFirmware1 (plc, module, & nvm_header);
			break;
		}
		if (lseek (plc->NVM.file, LE32TOH (nvm_header.NEXTHEADER), SEEK_SET) == -1)
		{
			error (1, errno, "Can't skip module: %s (%d)", plc->NVM.name, module);
		}
		module++;
	}
	while (nvm_header.NEXTHEADER);
	return (0);
}

#endif



