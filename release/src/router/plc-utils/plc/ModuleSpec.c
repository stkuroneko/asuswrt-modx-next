/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed ModuleSpec (struct _file_ * module, struct vs_module_spec * vs_module_spec);
 *
 *   plc.h
 *
 *   compute file length and checksum for module operation functions;
 *   struct vs_module_spec is defined in plc.h;
 *
 *--------------------------------------------------------------------*/

#ifndef MODULESPEC_SOURCE
#define MODULESPEC_SOURCE

#include "../tools/error.h"
#include "../tools/files.h"
#include "../plc/plc.h"

signed ModuleSpec (struct _file_ * file, struct vs_module_spec * spec)

{
	off_t length;
	if ((length = lseek (file->file, 0, SEEK_END)) == -1)
	{
		error (1, errno, FILE_CANTSIZE, file->name);
	}

#if 1

	if (length % sizeof (uint32_t))
	{
		error (1, ENOTSUP, "%s not multiple of " SIZE_T_SPEC " bytes", file->name, sizeof (uint32_t));
	}

#endif

	if (lseek (file->file, 0, SEEK_SET))
	{
		error (1, errno, FILE_CANTHOME, file->name);
	}
	spec->MODULE_LENGTH = length;
	spec->MODULE_CHKSUM = fdchecksum32 (file->file, length, 0);
	if (lseek (file->file, 0, SEEK_SET))
	{
		error (1, errno, FILE_CANTHOME, file->name);
	}
	return (0);
}

#endif



