/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   int StartDevice1 (struct plc * plc);
 *
 *   plc.h
 *
 *   This int6kboot plugin initialize a device having no NVRAM or blank
 *   or corrupted NVRAM; ensure Bootloader is running before starting;
 *   write SDRAM configuration then NVM and PIB files to SDRAM and
 *   start firmware execution;
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef STARTDEVICE1_SOURCE
#define STARTDEVICE1_SOURCE

#include <stdint.h>
#include <unistd.h>
#include <memory.h>
#include <errno.h>

#include "../tools/error.h"
#include "../tools/files.h"
#include "../nvm/nvm.h"
#include "../pib/pib.h"
#include "../plc/plc.h"

int StartDevice1 (struct plc * plc)

{
	unsigned module = 0;
	struct lightning_nvm_header nvm_header;
	struct pib_header pib_header;
	uint32_t offset = INT6x00_PIBOFFSET;
	if (WriteCFG (plc))
	{
		return (-1);
	}
	if (lseek (plc->NVM.file, 0, SEEK_SET))
	{
		error (PLC_EXIT (plc), errno, FILE_CANTHOME, plc->NVM.name);
		return (-1);
	}
	if (read (plc->NVM.file, & nvm_header, sizeof (nvm_header)) != sizeof (nvm_header))
	{
		error (PLC_EXIT (plc), errno, FILE_CANTREAD, plc->NVM.name);
		return (-1);
	}
	while (nvm_header.NEXTHEADER)
	{
		if (lseek (plc->NVM.file, LE32TOH (nvm_header.NEXTHEADER), SEEK_SET) == -1)
		{
			error (PLC_EXIT (plc), errno, FILE_CANTHOME, plc->NVM.name);
			return (-1);
		}
		if (read (plc->NVM.file, & nvm_header, sizeof (nvm_header)) != sizeof (nvm_header))
		{
			error (PLC_EXIT (plc), errno, FILE_CANTREAD, plc->NVM.name);
			return (-1);
		}
		module++;
	}
	if (lseek (plc->PIB.file, 0, SEEK_SET))
	{
		error (1, errno, FILE_CANTHOME, plc->PIB.name);
	}
	if (read (plc->PIB.file, & pib_header, sizeof (pib_header)) != sizeof (pib_header))
	{
		error (1, errno, FILE_CANTREAD, plc->PIB.name);
	}
	if (lseek (plc->PIB.file, 0, SEEK_SET))
	{
		error (1, errno, FILE_CANTHOME, plc->PIB.name);
	}
	if (BE16TOH (* (uint16_t *) (& pib_header)) < 0x0305)
	{
		offset = LEGACY_PIBOFFSET;
	}
#if 0
	else if (BE16TOH (* (uint16_t *) (& pib_header)) < 0x0500)
	{
		offset = INT6x00_PIBOFFSET;
	}
	else 
	{
		offset = AR7x00_PIBOFFSET;
	}
#endif
	if (WriteMEM (plc, & plc->PIB, 0, offset, LE16TOH (pib_header.PIBLENGTH)))
	{
		return (-1);
	}
	if (WriteFirmware1 (plc, module, & nvm_header))
	{
		return (-1);
	}
	if (StartFirmware1 (plc, module, & nvm_header))
	{
		return (-1);
	}
	if (lseek (plc->NVM.file, 0, SEEK_SET))
	{
		error (PLC_EXIT (plc), errno, FILE_CANTHOME, plc->NVM.name);
		return (-1);
	}
	return (0);
}

#endif



