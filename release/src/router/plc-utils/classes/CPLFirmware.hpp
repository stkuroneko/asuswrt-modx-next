/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   CPLFirmware.hpp - interface for the CPLFirmware class
 *
 *   read/write runtime firmware images from/to a device/file;
 *
 *   Contributor(s):
 *	    Charles Maier <charles.maier@intellon.com>
 *
 *--------------------------------------------------------------------*/

#ifndef CPLFIRMWARE_HEADER
#define CPLFIRMWARE_HEADER

/*====================================================================*
 *   system header files;
 *--------------------------------------------------------------------*/

#include <stdint.h>
#include <cstddef>

/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

#include "../classes/stdafx.hpp"
#include "../classes/CPLChannel.hpp"

#define NVM_HEADER_VERSION 0x60000000
#define NVM_HEADER_MINOR_VERSION 1

/*====================================================================*
 *   class declaration;
 *--------------------------------------------------------------------*/

class __declspec (dllexport) CPLFirmware 

{
public:
	CPLFirmware ();
	explicit CPLFirmware (char const * filename);
	explicit CPLFirmware (CPLChannel * channel);
	virtual ~ CPLFirmware ();
	void * Data () const;
	size_t Size () const;
	bool IsValid () const;
	signed Write (char const * filename);
	signed Write (CPLChannel * channel);
	signed Read (char const * filename);
	signed Read (CPLChannel *);
	signed Flash (CPLChannel * channel);
	void Peek (void const * memory) const;

private:
	void bitmap (char const * operands [], unsigned flagword) const;
	CPLFirmware & Init ();

#ifndef __GNUC__
#pragma pack (push,1)
#endif

	typedef struct __packed 
	{
		uint32_t HEADERVERSION;
		uint32_t IMAGEROMADDR;
		uint32_t IMAGEADDR;
		uint32_t IMAGELENGTH;
		uint32_t IMAGECHECKSUM;
		uint32_t ENTRYPOINT;
		uint8_t HEADERMINORVERSION;
		uint8_t IMAGETYPE;
		uint16_t IGNOREMASK;
		uint32_t RESERVED [2];
		uint32_t NEXTHEADER;
		uint32_t HEADERCHECKSUM;
	} Header;

#ifndef __GNUC__
#pragma pack (pop)
#endif

	uint8_t * mbuffer;
	uint16_t mextent;

};

/*====================================================================*
 *   end definition;
 *--------------------------------------------------------------------*/

#endif

