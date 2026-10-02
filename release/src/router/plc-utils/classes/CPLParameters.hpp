/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   CPLParameters.hpp - interface for the CPLParameters class
 *
 *   read/write a parameter block image from/to a device/file;
 *
 *   Contributor(s):
 *	    Charles Maier <charles.maier@intellon.com>
 *
 *--------------------------------------------------------------------*/

#ifndef CPLPARAMETERS_HEADER
#define CPLPARAMETERS_HEADER

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
#include "../classes/CPLMessage.hpp"

/*====================================================================*
 *   class declaration;
 *--------------------------------------------------------------------*/

class __declspec (dllexport) CPLParameters:public CPLMessage

{
public:
	CPLParameters ();
	explicit CPLParameters (char const * filename);
	explicit CPLParameters (CPLChannel * channel);
	virtual ~ CPLParameters ();
	void * Data () const;
	size_t Size () const;
	bool IsValid () const;
	signed Flash (CPLChannel * channel);
	signed Write (CPLChannel * channel);
	signed Write (char const * filename);
	signed Read (CPLChannel *);
	signed Read (char const * filename);
	CPLParameters & SetCAPPriority (int CAPpriority);
	int Write_QoS_block (int selectPIB);
	CPLParameters & Lock ();
private:
//    uint8_t * mbuffer;
	CPLParameters & Init ();
	uint16_t mextent;

#ifndef __GNUC__
#pragma pack (push, 1)
#endif

	typedef struct __packed 
	{
		uint8_t FWVERSION;
		uint8_t PIBVERSION;
		uint16_t RESERVED1;
		uint16_t PIBLENGTH;
		uint16_t RESERVED2;
		uint32_t CHECKSUM;
	}
	Header;
	CPLParameters::Header * mheader;

protected:

	uint8_t * mbuffer;

#ifndef __GNUC__
#pragma pack (pop)
#endif

};

/*====================================================================*
 *   end definition;
 *--------------------------------------------------------------------*/

#endif

