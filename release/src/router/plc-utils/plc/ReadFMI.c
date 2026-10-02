/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed ReadFMI (struct plc * plc, uint8_t MMV, uint16_t MMTYPE);
 *
 *   plc.h
 *
 *   read a fragmented message and return a pointer to a buffer that
 *   contains the concatenated message fragments; the buffer address
 *   is returned in plc->content; the calling function must free the
 *   buffer when done; buffer length is computed from the number of
 *   fragments returned in the FMI field of the first fragment;
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *      Nathaniel Houghton <nhoughto@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef READFMI_SOURCE
#define READFMI_SOURCE

#include <stdint.h>
#include <stdlib.h>
#include <memory.h>

#include "../tools/memory.h"
#include "../tools/number.h"
#include "../tools/error.h"
#include "../plc/plc.h"

signed ReadFMI (struct plc * plc, uint8_t MMV, uint16_t MMTYPE)

{
	if (ReadMME (plc, MMV, MMTYPE) > 0)
	{
		struct homeplug1 * homeplug = (struct homeplug1 *) (plc->message);
		unsigned count = ((homeplug->homeplug.FMID >> 4) & 0x0F);
		unsigned index = ((homeplug->homeplug.FMID >> 0) & 0x0F);
		signed length = sizeof (* homeplug) +  count * sizeof (homeplug->content);
		if ((plc->content = malloc (length)))
		{
			signed offset = plc->packetsize;
			memcpy (plc->content, homeplug, offset);
			while (index < count)
			{
				if (ReadMME (plc, MMV, MMTYPE) <= 0)
				{
					free (plc->content);
					plc->content = NULL;
					return (-1);
				}
				count = ((homeplug->homeplug.FMID >> 4) & 0x0F);
				index = ((homeplug->homeplug.FMID >> 0) & 0x0F);
				plc->packetsize -= sizeof (struct ethernet_hdr);
				plc->packetsize -= sizeof (struct homeplug_fmi);
				if ((offset +  plc->packetsize) > length)
				{
					error (1, EOVERFLOW, "%s", __func__);
				}
				memcpy ((uint8_t *) (plc->content) +  offset, homeplug->content, plc->packetsize);
				offset += plc->packetsize;
			}
			plc->packetsize = offset;
		}
	}
	return (plc->packetsize);
}

#endif



