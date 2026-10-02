/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed ExecuteApplets2 (struct plc * plc);
 *
 *   plc.h
 *
 *   download and execute all modules in a new nvm image files;
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef EXECUTEAPPLETS2_SOURCE
#define EXECUTEAPPLETS2_SOURCE

#include "../tools/flags.h"
#include "../tools/files.h"
#include "../tools/error.h"
#include "../plc/plc.h"

signed ExecuteApplets2 (struct plc * plc)

{
	unsigned module = 0;
	struct panther_nvm_header nvm_header;
	if (lseek (plc->NVM.file, 0, SEEK_SET))
	{
		if (_allclr (plc->flags, PLC_SILENCE))
		{
			error (PLC_EXIT (plc), errno, FILE_CANTHOME, plc->NVM.name);
		}
		return (-1);
	}
	do 
	{
		if (read (plc->NVM.file, & nvm_header, sizeof (nvm_header)) != sizeof (nvm_header))
		{
			if (_allclr (plc->flags, PLC_SILENCE))
			{
				error (PLC_EXIT (plc), errno, NVM_HDR_CANTREAD, plc->NVM.name, module);
			}
			return (-1);
		}
		if (LE16TOH (nvm_header.MajorVersion) != 1)
		{
			if (_allclr (plc->flags, PLC_SILENCE))
			{
				error (PLC_EXIT (plc), 0, NVM_HDR_VERSION, plc->NVM.name, module);
			}
			return (-1);
		}
		if (LE32TOH (nvm_header.MinorVersion) != 1)
		{
			if (_allclr (plc->flags, PLC_SILENCE))
			{
				error (PLC_EXIT (plc), 0, NVM_HDR_VERSION, plc->NVM.name, module);
			}
			return (-1);
		}
		if (checksum32 (& nvm_header, sizeof (nvm_header), 0))
		{
			if (_allclr (plc->flags, PLC_SILENCE))
			{
				error (PLC_EXIT (plc), 0, NVM_HDR_CHECKSUM, plc->NVM.name, module);
			}
			return (-1);
		}
		if (WriteExecuteApplet2 (plc, module, & nvm_header))
		{
			return (-1);
		}
		if (_anyset (plc->flags, PLC_QUICK_FLASH))
		{
			break;
		}
		while (! ReadMME (plc, 0, (VS_HOST_ACTION | MMTYPE_IND)));
		module++;
	}
	while (~ nvm_header.NextHeader);
	return (0);
}

#endif



