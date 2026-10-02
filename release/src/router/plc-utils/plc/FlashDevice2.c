/*====================================================================*
	Copyright (c) 2013,2019 Qualcomm Technologies, Inc.
	All Rights Reserved.
	Confidential and Proprietary - Qualcomm Technologies, Inc.
	******************************************************************
	2013 Qualcomm Atheros, Inc.
 *--------------------------------------------------------------------*/

/*====================================================================*
 *
 *   signed FlashDevice2 (struct plc * plc, uint32_t options);
 *
 *   plc.h
 *   
 *   flash a QCA7420 device; force a reset because a reset is not
 *   automatic;
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *		Kalaivani Somasundaram <kalaivan@qti.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef FLASHDEVICE2_SOURCE
#define FLASHDEVICE2_SOURCE

#include "../plc/plc.h"

signed FlashDevice2 (struct plc * plc, uint32_t options)

{
	char firmware [256];
	if (plc->SFT.file != -1)
	{
		if (FlashSoftloader (plc, options))
		{
			return (-1);
		}
	}
	if ((plc->NVM.file != -1) && (plc->PIB.file != -1))
	{
		if (FlashFirmware (plc, options))
		{
			return (-1);
		}
	}
	else if (plc->PIB.file != -1)
	{
		if (FlashParameters (plc, options))
		{
			return (-1);
		}
	}
	if(IsFlashExists(plc))
	{
		if (ResetDevice (plc))
		{
			return (-1);
		}
	}
	sleep (5);
	if (WaitForStart (plc, firmware, sizeof (firmware)))
	{
		return (-1);
	}
	return (0);
}

#endif

