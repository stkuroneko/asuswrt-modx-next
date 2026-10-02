/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   CPLFirmware.cpp - CPLFirmware class definition;
 *
 *   read/write a parameter block image from/to a device/file;
 *
 *   Contributor(s):
 *	    Charles Maier <charles.maier@intellon.com>
 *
 *--------------------------------------------------------------------*/

#ifndef CPLFIRMWARE_SOURCE
#define CPLFIRMWARE_SOURCE

/*====================================================================*
 *   system header files;
 *--------------------------------------------------------------------*/

#include <cstring>
#include <fstream>

/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

#include "../classes/CPLFirmware.hpp"
#include "../classes/ohomeplug.hpp"
#include "../classes/omemory.hpp"
#include "../classes/oerror.hpp"
#include "../tools/endian.h"

/*====================================================================*
 *
 *   void * Data () const;
 *
 *   return firmware image sequence address as a void pointer; this 
 *   property can be used to perform image sequence operations that 
 *   have not been implemented by this class;
 *
 *--------------------------------------------------------------------*/

void * CPLFirmware::Data () const 

{
	return ((void *)(this->mbuffer));
}

/*====================================================================*
 *
 *   size_t Size () const;
 *
 *   return firmware image sequence extent (length) in bytes;
 *
 *--------------------------------------------------------------------*/

size_t CPLFirmware::Size () const 

{
	return (this->mextent);
}

/*====================================================================*
 *
 *   bool IsValid () const;
 *
 *   return true of the firmware image sequence is valid; check the 
 * 
 *   this method may be expanded to include other parameter block
 *   validity tests; 
 *
 *--------------------------------------------------------------------*/

bool CPLFirmware::IsValid () const 

{
	CPLFirmware::Header const * header;
	byte const * offset = (byte const *)(this->mbuffer);
	signed extent = this->mextent;
	signed image = 0;
	if ((!this->mbuffer) || (!this->mextent)) 
	{

// oerror::error (0, ECANCELED, "No Firmware Image Available");

		return (false);
	}
	do 
	{
	std::cout << "start " << image << std::endl;
		header = (CPLFirmware::Header const *)(offset);
#if 1
  		CPLFirmware::Peek (header);
#endif
		if (LE32TOH (header->HEADERVERSION) != NVM_HEADER_VERSION) 
		{
			oerror::error (1, 0, "Bad header version");
			return (false);
		}
		if (omemory::checksum32 (header, sizeof (CPLFirmware::Header), 0)) 
		{
			oerror::error (1, 0, "Bad header checksum");
			return (false);
		}
		offset += sizeof (CPLFirmware::Header);
		extent -= sizeof (CPLFirmware::Header);
		if (omemory::checksum32 (offset, LE32TOH (header->IMAGELENGTH), header->IMAGECHECKSUM)) 
		{
			oerror::error (1, 0, "Bad image checksum");
			return (false);
		}
		offset += header->IMAGELENGTH;
		extent -= header->IMAGELENGTH;
		image++;
		std::cout << "end " << image << std::endl;
	}
	while (header->NEXTHEADER);
	std::cout << "exit" << std::endl;
	return (!extent);
}

/*====================================================================*
 *
 *   signed CPLFirmware::Read (char const * filename);
 *
 *   read firmware image sequence from the named file;
 *
 *--------------------------------------------------------------------*/

signed CPLFirmware::Read (char const * filename) 

{
	if (this->mbuffer) 
	{
		delete [] this->mbuffer;
	}
	this->mextent = 0;
	if ((filename) && (*filename)) 
	{
		std::ifstream stream;
		stream.open (filename, std::ios::binary);
		if (stream.good ()) 
		{
			stream.seekg (0, std::ios::end);
			this->mextent = stream.tellg ();
			stream.seekg (0, std::ios::beg);
			this->mbuffer = new uint8_t [this->mextent];
			stream.read ((char *)(this->mbuffer), this->mextent);
		}
		stream.close ();
	}
	return (0);
}

/*====================================================================*
 *
 *   signed Write (char const * filename);
 *
 *   write firmware image sequence to the named file;
 *
 *--------------------------------------------------------------------*/

signed CPLFirmware::Write (char const * filename) 

{
	std::ofstream stream;
	stream.open (filename, std::ios::binary);
	if (stream.good ()) 
	{
		stream.write ((char *)(this->mbuffer), this->mextent);
	}
	stream.close ();
	return (0);
}

/*====================================================================*
 *
 *   signed Read (CPLCHannel * channel)
 *
 *   read a firmware image sequence from the local powerline device
 *   into memory using as many VS_RD_MOD messages as needed; 
 *
 *   return 0 on success or -1 on failure;
 *
 *--------------------------------------------------------------------*/

#if 0

signed CPLFirmware::Read (CPLChannel * channel) 

{
	ointellon intellon;
	uint8_t message [ETHER_MAX_LEN];

#ifndef __GNUC__
#pragma pack (push,1)
#endif

	struct __packed vs_rd_mod_request 
	{
		struct header_eth ethernet;
		struct header_int intellon;
		uint8_t MODULEID;
		uint8_t MACCESS;
		uint16_t MLENGTH;
		uint32_t MOFFSET;
		uint8_t MSECRET [16];
	}
	* request = (struct vs_rd_mod_request *) (message);
	struct __packed vs_rd_mod_confirm 
	{
		struct header_eth ethernet;
		struct header_int intellon;
		uint8_t MSTATUS;
		uint8_t RES [3];
		uint8_t MODULEID;
		uint8_t RESERVED;
		uint16_t MLENGTH;
		uint32_t MOFFSET;
		uint32_t CHKSUM;
		uint8_t BUFFER [INT6K_BLOCKSIZE];
	}
	* confirm = (struct vs_rd_mod_confirm *) (message);

#ifndef __GNUC__
#pragma pack (pop)
#endif

	uint16_t extent = 0;
	uint16_t length = oINTELLON_BLOCKSIZE;
	uint32_t offset = 0;
	intellon.ImportPeerAddress (channel->PeerAddress ());
	intellon.ImportHostAddress (channel->HostAddress ());
	intellon.SetMessageType (VS_RD_MOD | MMTYPE_REQ);
	do 
	{
		std::memset (message, 0, sizeof (message));
		request = (struct vs_rd_mod_request *)(intellon.ExportHeader (message));
		confirm = (struct vs_rd_mod_confirm *)(request);
		request->MODULEID = VS_MODULE_MAC;
		request->MLENGTH = HTOLE16 (length);
		request->MOFFSET = HTOLE32 (offset);
		if (channel->SendMessage (message, ETHER_MIN_LEN) <= 0) 
		{
			oerror::error (0, ECANCELED, CPLCHANNEL_CANTSEND);
			return (-1);
		}
		if (channel->ReadMessage (message, sizeof (message)) <= 0) 
		{
			oerror::error (0, ECANCELED, CPLCHANNEL_CANTREAD);
			return (-1);
		}
		if (confirm->MSTATUS) 
		{
			oerror::error (0, ECANCELED, CPLCHANNEL_WONTDOIT);
			return (-1);
		}

#if 1

		if (LE16TOH (confirm->MLENGTH) != length) 
		{
			oerror::error (0, ECANCELED, oINTELLON_BAD_LENGTH);
			return (-1);
		}
		if (LE32TOH (confirm->MOFFSET) != offset) 
		{
			oerror::error (0, ECANCELED, oINTELLON_BAD_LENGTH);
			return (-1);
		}

#else

		if (LE16TOH (confirm->MLENGTH) != length) 
		{
			oerror::error (0, EIO, oINTELLON_BAD_LENGTH);
			this->mlength = INT6K_BLOCKSIZE;
			this->moffset = 0;
			continue;
		}
		if (LE32TOH (confirm->MOFFSET) != this->moffset) 
		{
			oerror::error (0, EIO, oINTELLON_BAD_OFFSET);
			this->mlength = INT6K_BLOCKSIZE;
			this->moffset = 0;
			continue;
		}

#endif

		length = LE16TOH (confirm->MLENGTH);
		offset = LE32TOH (confirm->MOFFSET);
		if (omemory::checksum32 (confirm->MBUFFER, length, confirm->MCHKSUM)) 
		{
			oerror::error (0, ECANCELED, "Bad Message Checksum");
			return (-1);
		}
		if (offset == extent) 
		{
			CPLFirmware::Header * header = (CPLFirmware::Header *)(confirm->BUFFER);
			if (checksum_32 (header, sizeof (CPLFirmware::Header), 0)) 
			{
				oerror::error (0, ECANCELED, "Bad Header Checksum");
				return (-1);
			}
			if (header_nvm->HEADERVERSION != NVM_HEADER_VERSION) 
			{
				oerror::error (0, ECANCELED, "Bad Header Version");
				return (-1);
			}
			extent += sizeof (CPLFirmware::Header);
			extent += LE32TOH (header_nvm->IMAGELENGTH);
			header = LE16TOH (header_nvm->NEXTHEADER);
		}
		if ((offset + length) > extent) 
		{
			length = extent - offset;
		}
		std::memcpy (this->mbuffer + offset, confirm->MBUFFER, length);
		offset += length;
		extent -= length;
	}
	while ((header) || (offset < extent));
	return (0);
}

#endif

/*====================================================================*
 *
 *   signed Write (CPLChannel * channel);
 *
 *   write the firmware image sequence from memory to any powerline 
 *   device using as many VS_WR_MOD messages as needed; 
 *
 *   the runtime firmware must be running for this to work;
 *
 *   return 0 on success or -1 on failure;
 *
 *--------------------------------------------------------------------*/

signed CPLFirmware::Write (CPLChannel * channel) 

{
	ointellon intellon;
	uint8_t message [ETHER_MAX_LEN];

#ifndef __GNUC__
#pragma pack (push,1)
#endif

	struct __packed vs_wr_mod_request 
	{
		uint8_t MODULEID;
		uint8_t RESERVED;
		uint16_t MLENGTH;
		uint32_t MOFFSET;
		uint32_t MCHKSUM;
		uint8_t MBUFFER [oINTELLON_BLOCKSIZE];
	}
	* request;
	struct __packed vs_wr_mod_confirm 
	{
		uint8_t MSTATUS;
		uint8_t MODULEID;
		uint8_t RESERVED;
		uint16_t MLENGTH;
		uint32_t MOFFSET;
	}
	* confirm;

#ifndef __GNUC__
#pragma pack (pop)
#endif

	uint16_t length = oINTELLON_BLOCKSIZE;
	uint16_t extent = this->mextent;
	uint32_t offset = 0;
	intellon.ImportPeerAddress (channel->PeerAddress ());
	intellon.ImportHostAddress (channel->HostAddress ());
	intellon.SetMessageType (VS_WR_MOD | MMTYPE_REQ);
	while (extent) 
	{
		if (length > extent) 
		{
			length = extent;
		}
		std::memset (message, 0, sizeof (message));
		request = (struct vs_wr_mod_request *) (intellon.ExportHeader (message));
		confirm = (struct vs_wr_mod_confirm *) (request);
		std::memcpy (request->MBUFFER, this->mbuffer + offset, length);
		request->MODULEID = VS_MODULE_MAC;
		request->RESERVED = 0;
		request->MLENGTH = HTOLE16 (length);
		request->MOFFSET = HTOLE32 (offset);
		request->MCHKSUM = omemory::checksum32 (request->MBUFFER, length, 0);
		if (channel->SendMessage (message, intellon.BufferLength (sizeof (struct vs_wr_mod_request))) <= 0) 
		{
			oerror::error (0, ECANCELED, CPLCHANNEL_CANTSEND);
			return (-1);
		}
		if (channel->ReadMessage (message, sizeof (message)) <= 0) 
		{
			oerror::error (0, ECANCELED, CPLCHANNEL_CANTREAD);
			return (-1);
		}
		if (confirm->MSTATUS) 
		{
			oerror::error (0, ECANCELED, CPLCHANNEL_WONTDOIT);
			return (-1);
		}

#if 1

		if (LE16TOH (confirm->MLENGTH) != length) 
		{
			oerror::error (0, ECANCELED, oINTELLON_BAD_LENGTH);
			return (-1);
		}
		if (LE32TOH (confirm->MOFFSET) != offset) 
		{
			oerror::error (0, ECANCELED, oINTELLON_BAD_OFFSET);
			return (-1);
		}

#else

		if (LE16TOH (confirm->MLENGTH) != length) 
		{
			oerror::error (0, EIO, oINTELLON_BAD_LENGTH);
			length = oINTELLON_BLOCKSIZE;
			offset = 0;
			continue;
		}
		if (LE32TOH (confirm->MOFFSET) != offset) 
		{
			oerror::error (0, EIO, oINTELLON_BAD_OFFSET);
			length = oINTELLON_BLOCKSIZE;
			offset = 0;
			continue;
		}

#endif

		offset += length;
		extent -= length;
	}
	return (0);
}

/*====================================================================*
 *
 *   signed Flash (CPLChannel *channel);
 *
 *   commit downloaded firmware image sequence to flash memory;
 *
 *--------------------------------------------------------------------*/

signed CPLFirmware::Flash (CPLChannel *channel) 

{
	ointellon intellon;
	uint8_t message [ETHER_MAX_LEN];

#ifndef __GNUC__
#pragma pack (push,1)
#endif

	struct __packed vs_wr_mod_nvm_request 
	{
		uint8_t MODULEID;
		uint8_t RESERVED;
	}
	* request;
	struct __packed vs_wr_mod_nvm_confirm 
	{
		uint8_t MSTATUS;
		uint8_t MODULEID;
	}
	* confirm;

#ifndef __GNUC__
#pragma pack (pop)
#endif

	intellon.ImportPeerAddress (channel->PeerAddress ());
	intellon.ImportHostAddress (channel->HostAddress ());
	intellon.SetMessageType (VS_MOD_NVM | MMTYPE_REQ);
	request = (struct vs_wr_mod_nvm_request *) (intellon.ExportHeader (message));
	confirm = (struct vs_wr_mod_nvm_confirm *) (request);
	request->MODULEID = VS_MODULE_MAC;
	request->RESERVED = 0;
	if (channel->SendMessage (message, ETHER_MIN_LEN) <= 0) 
	{
		oerror::error (0, ECANCELED, CPLCHANNEL_CANTSEND);
		return (-1);
	}
	if (channel->ReadMessage (message, sizeof (message)) <= 0) 
	{
		oerror::error (0, ECANCELED, CPLCHANNEL_CANTREAD);
		return (-1);
	}
	if (confirm->MSTATUS) 
	{
		oerror::error (0, ECANCELED, CPLCHANNEL_WONTDOIT);
		return (-1);
	}
	return (0);
}

/*====================================================================*
 *
 *   CPLFirmware & CPLFirmware::Peek (void const * memory);
 *
 *--------------------------------------------------------------------*/

void CPLFirmware::Peek (void const * memory) const

{
	CPLFirmware::Header const * header = (CPLFirmware::Header const *)(memory);
	static char const * platforms [] = 
	{
		"INT6000",
		"INT6300",
		"INT6400",
		"AR7400",
		(char const *)(0) 
	};
	static char const * functions []= 
	{
		"Generic Image",
		"Synopsis Configuration",
		"Denali Configuration",
		"Denali Applet",
		"Firmware Image",
		"OAS Client",
		"Custom Image",
		"Memory Control",
	};
	std::printf ("\tHeader Version = 0x%08X-%02X\n", LE32TOH (header->HEADERVERSION), header->HEADERMINORVERSION);
	std::printf ("\tHeader Checksum = 0x%08X\n", LE32TOH (header->HEADERCHECKSUM));
	std::printf ("\tHeader Next = 0x%08X\n", LE32TOH (header->NEXTHEADER));
	std::printf ("\tFlash Address = 0x%08X\n", LE32TOH (header->IMAGEROMADDR));
	std::printf ("\tImage Address = 0x%08X\n", LE32TOH (header->IMAGEADDR));
	std::printf ("\tEntry Address = 0x%08X\n", LE32TOH (header->ENTRYPOINT));
	std::printf ("\tImage Checksum = 0x%08X\n", LE32TOH (header->IMAGECHECKSUM));
	std::printf ("\tImage Size = 0x%08X (%d)\n", LE32TOH (header->IMAGELENGTH), LE32TOH (header->IMAGELENGTH));
	if (header->IMAGETYPE < (sizeof (functions) / sizeof (char const *))) 
	{
		std::printf ("\tImage Type = %s\n", functions [header->IMAGETYPE]);
	}
	else 
	{
		std::cout << "\tImage Type = Unknown" << std::endl;
	}
	std::cout << "\tImage Omit = ";
	CPLFirmware::bitmap (platforms, LE16TOH (header->IGNOREMASK));
	std::cout << std::endl;
	std::cout << std::endl;
	return;
}

/*====================================================================*
 *
 *   void bitmap (char const *operands [], unsigned flagword) const;
 *
 *--------------------------------------------------------------------*/

void CPLFirmware::bitmap (char const * operands [], unsigned flagword) const

{
	char const * separator = "";
	while ((*operands) && (flagword))
	{
		if (flagword & 1) 
		{
			std::cout << separator << *operands;
			separator = "|";
		}
		flagword >>= 1;
		operands++;
	}
	return;
}

/*====================================================================*
 *
 *   CPLFirmware & CPLFirmware::Init ();
 *
 *   initialize instance variable;
 *
 *--------------------------------------------------------------------*/

CPLFirmware & CPLFirmware::Init () 

{
	this->mbuffer = (uint8_t *)(0);
	this->mextent = 0;
	return (*this);
}

/*====================================================================*
 *
 *   CPLFirmware (CPLChannel * channel)
 *
 *--------------------------------------------------------------------*/

#if 0

CPLFirmware::CPLFirmware (CPLChannel * channel) 

{
	this->Init ().Read (channel);
	return;
}

#endif

/*====================================================================*
 *
 *   CPLFirmware (char const * filename)
 *
 *--------------------------------------------------------------------*/

CPLFirmware::CPLFirmware (char const * filename) 

{
	this->Init ().Read (filename);
	return;
}

/*====================================================================*
 *
 *   ~CPLFirmware ()
 *
 *--------------------------------------------------------------------*/

CPLFirmware::~CPLFirmware () 

{
	std::cout << "delete mbuffer" << std::endl;
	delete [] this->mbuffer;
	std::cout << "delete mbuffer" << std::endl;
	return;
}

/*====================================================================*
 *   end definition;
 *--------------------------------------------------------------------*/

#endif

