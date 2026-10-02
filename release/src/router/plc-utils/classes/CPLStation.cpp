/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   CPLStation.cpp - CPLStation class implementation;
 *
 *   Contributor(s): 
 *	Charles Maier <charles.maier@intellon.com>
 *
 *--------------------------------------------------------------------*/

#ifndef CPLSTATION_SOURCE
#define CPLSTATION_SOURCE

/*====================================================================*
 *   system header files;
 *--------------------------------------------------------------------*/

#include <cstring>
#include <iostream>

/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

#include "../classes/CPLStation.hpp"
#include "../classes/omemory.hpp"
#include "../tools/types.h"

/*====================================================================*
 *   class variables;
 *--------------------------------------------------------------------*/

char const * CPLStation::PrefaceString = "P/L NET TEI ------ MAC ------ ------ BDA ------  TX  RX CHIPSET FIRMWARE";
char const * CPLStation::link [] = 

{
	"LOC",
	"REM" 
};

char const * CPLStation::role [] = 

{
	"STA",
	"CCO" 
};

char const * CPLStation::chipset [] = 

{
	"unknown",
	"INT6000",
	"INT6300",
	"INT6400",
	" AR7400",
	" AR6405"
	" AR7420"
};

/*====================================================================*
 *
 *   bool IsBridge (void) const;
 *
 *   return logical true if the station is a local powerline device;
 *
 *--------------------------------------------------------------------*/

bool CPLStation::IsBridge (void) const 

{
	return (this->mlink == CPLSTATION_BRIDGE);
}

/*====================================================================*
 *
 *   unsigned LinkType (void) const;
 *
 *   return the station link type as an unsigned integer; 
 *
 *--------------------------------------------------------------------*/

unsigned CPLStation::LinkType (void) const 

{
	return (this->mlink);
}

/*====================================================================*
 *
 *   char const * LinkName (void) const;
 *
 *--------------------------------------------------------------------*/

char const * CPLStation::LinkName (void) const 

{
	return (CPLStation::link [this->mlink]);
}

/*====================================================================*
 *
 *   byte StationID (void) const;
 *
 *   return the network station identifier as an unsigned integer; 
 *   the station identifier is the same as the TEI;
 *
 *--------------------------------------------------------------------*/

unsigned CPLStation::StationID (void) const 

{
	return (this->mstation);
}

/*====================================================================*
 *
 *   unsigned RoleType (void) const;
 *
 *--------------------------------------------------------------------*/

unsigned CPLStation::RoleType (void) const 

{
	return (this->mrole);
}

/*====================================================================*
 *
 *   unsigned RoleName (void) const;
 *
 *--------------------------------------------------------------------*/

char const * CPLStation::RoleName (void) const 

{
	return (CPLStation::role [this->mrole]);
}

/*====================================================================*
 *
 *   byte const * HostAddress (void) const;
 *
 *--------------------------------------------------------------------*/

byte const * CPLStation::NodeAddress (void) const 

{
	return (this->mnodeaddr);
}

/*====================================================================*
 *
 *   byte const * NodeAddress (void) const;
 *
 *--------------------------------------------------------------------*/

char const * CPLStation::NodeAddressString (void) const 

{
	static char address [ETHER_ADDR_LEN * 3];
	omemory::hexstring (address, sizeof (address), this->mnodeaddr, sizeof (this->mnodeaddr));
	return (address);
}

/*====================================================================*
 *
 *   byte const * HostAddress (void) const;
 *
 *--------------------------------------------------------------------*/

byte const * CPLStation::HostAddress (void) const 

{
	return (this->mhostaddr);
}

/*====================================================================*
 *
 *   char const * HostAddressString (void) const;
 *
 *--------------------------------------------------------------------*/

char const * CPLStation::HostAddressString (void) const 

{
	static char address [ETHER_ADDR_LEN * 3];
	omemory::hexstring (address, sizeof (address), this->mhostaddr, sizeof (this->mhostaddr));
	return (address);
}

/*====================================================================*
 *
 *   unsigned TxRate (void) const;
 *
 *--------------------------------------------------------------------*/

unsigned CPLStation::TxRate (void) const 

{
	return (this->mtxrate);
}

/*====================================================================*
 *
 *   unsigned RxRate (void) const;
 *
 *--------------------------------------------------------------------*/

unsigned CPLStation::RxRate (void) const 

{
	return (this->mrxrate);
}

/*====================================================================*
 *
 *   unsigned HardwareType (void) const;
 *
 *   return the hardware platform code (chipset ID) ensuring that it
 *   does not fall outside the bounds of array CPLStation::chipset;
 *
 *--------------------------------------------------------------------*/

unsigned CPLStation::HardwareType (void) const 

{
	if (this->mhardware < (sizeof (CPLStation::chipset) / sizeof (const char *)))
	{
		return (this->mhardware);
	}
	return (0);
}

/*====================================================================*
 *
 *   cons char * HardwareName (void) const;
 *
 *--------------------------------------------------------------------*/

char const * CPLStation::HardwareName (void) const 

{
	return (CPLStation::chipset [this->HardwareType ()]);
}

/*====================================================================*
 *
 *   char const * FirmwareName (void) const;
 *
 *--------------------------------------------------------------------*/

char const * CPLStation::FirmwareName (void) const 

{
	return (this->mfirmware);
}

/*====================================================================*
 *
 *   CPLStation & Revision (CPLChannel * channel) 
 *
 *   update the mhardware and mfirmware members using a VS_SW_VER 
 *   management message;
 *
 *--------------------------------------------------------------------*/

CPLStation & CPLStation::Revision (CPLChannel * channel) 

{
	ointellon intellon;
	byte message [ETHER_MAX_LEN];

#ifndef __GNUC__
#pragma pack (push,1)
#endif

	struct __packed version 
	{
		uint8_t MSTATUS;
		uint8_t MDEVICEID;
		uint8_t MVERSIONLENGTH;
		uint8_t MVERSION [128];
	}
	* version;

#ifndef __GNUC__
#pragma pack (pop)
#endif

	std::memset (message, 0, sizeof (message));
	intellon.ImportPeerAddress (this->mnodeaddr);
	intellon.ImportHostAddress (channel->HostAddress ());
	version = (struct version *)(intellon.ExportHeader (message));
	if (channel->SendMessage (message, ETHER_MIN_LEN) > 0) 
	{
		while (channel->ReadMessage (message, sizeof (message)) > 0) 
		{
			this->mhardware = version->MDEVICEID;
			std::memcpy (this->mfirmware, version->MVERSION, version->MVERSIONLENGTH);
		}
	}
	return (*this);
}

/*====================================================================*
 *
 *   CPLStation & Preface ();
 *
 *--------------------------------------------------------------------*/

CPLStation & CPLStation::Preface () 

{
	std::cout << CPLStation::PrefaceString << std::endl;
	return (*this);
}

/*====================================================================*
 *
 *   CPLStation & Print ();
 *
 *--------------------------------------------------------------------*/

CPLStation & CPLStation::Print () 

{
	char buffer [10];
	std::cout << this->LinkName () << " ";
	std::cout << this->RoleName () << " ";
	std::cout << omemory::serial (buffer, 3, this->StationID (), 10, 0) << " ";
	std::cout << this->NodeAddressString () << " ";
	std::cout << this->HostAddressString () << " ";
	std::cout << omemory::serial (buffer, 3, this->TxRate (), 10, 0) << " ";
	std::cout << omemory::serial (buffer, 3, this->RxRate (), 10, 0) << " ";
	std::cout << this->HardwareName () << " ";
	std::cout << this->FirmwareName () << "\n";
	return (*this);
}

/*====================================================================*
 *
 *   CPLStation (void);
 *
 *--------------------------------------------------------------------*/

CPLStation::CPLStation (void) 

{
	this->mlink = 0;
	this->mrole = 0;
	this->mstation = 0;
	std::memset (this->mnodeaddr, 0x00, sizeof (this->mnodeaddr));
	std::memset (this->mhostaddr, 0x00, sizeof (this->mhostaddr));
	std::memset (this->mfirmware, 0, sizeof (this->mfirmware));
	omemory::memtext ("unknown", this->mfirmware, sizeof (this->mfirmware));
	this->mhardware = 0;
	return;
}

/*====================================================================*
 *
 *   ~ CPLStation (void);
 *
 *--------------------------------------------------------------------*/

CPLStation::~CPLStation (void) 

{
	return;
}

/*====================================================================*
 *   end implementation;
 *--------------------------------------------------------------------*/

#endif

