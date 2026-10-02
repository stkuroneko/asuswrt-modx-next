/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   CPLMessage.hpp - interface for the CPLMessage class
 *
 *   Contributor(s):
 *	    Charles Maier <charles.maier@intellon.com>
 *
 *--------------------------------------------------------------------*/

#ifndef CPLMESSAGE_HEADER
#define CPLMESSAGE_HEADER

/*====================================================================*
 *  system header files;
 *--------------------------------------------------------------------*/

#include <stdint.h>
#include <cstdio>

/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

#include "../classes/stdafx.hpp"

/*====================================================================*
 *   class constants;
 *--------------------------------------------------------------------*/

#define CPLMESSAGE_BOOTLOADER

/*====================================================================*
 *   class declaration;
 *--------------------------------------------------------------------*/

class __declspec (dllexport) CPLMessage

{
public:
	CPLMessage ();
	virtual ~ CPLMessage ();
	char const * MessageName (uint16_t type) const;
	char const * MessageMode (uint16_t type) const;
	char const * MessageErrorText (uint16_t type, uint8_t code) const;
	CPLMessage & CSV ();
	CPLMessage & HTML ();
private:
	static struct name
	{
		uint16_t type;
		char const * name;
	}
	names [];
	static char const * modes [];
	static struct code
	{
		uint16_t type;
		uint8_t code;
		char const * text;
	}
	mcodes [];
};

/*====================================================================*
 *   end definition;
 *--------------------------------------------------------------------*/

#endif

