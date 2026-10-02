/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   CPLParameters.cpp - CPLParameters class definition;
 *
 *   read/write a parameter block image from/to a device/file;
 *
 *   Contributor(s):
 *	    Charles Maier <charles.maier@intellon.com>
 *
 *--------------------------------------------------------------------*/

#ifndef CPLPARAMETERS_SOURCE
#define CPLPARAMETERS_SOURCE

/*====================================================================*
 *   system header files;
 *--------------------------------------------------------------------*/

#include <cstring>
#include <fstream>

/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

#include "../classes/CPLParameters.hpp"
#include "../classes/ohomeplug.hpp"
#include "../classes/omemory.hpp"
#include "../classes/oerror.hpp"
#include "../tools/endian.h"

/*====================================================================*
 *
 *   void * Data () const;
 *
 *   return parameter block address as a void pointer; this property
 *   can be used to perform parameter block operations that have not
 *   been implemented by this class;
 *
 *--------------------------------------------------------------------*/

void * CPLParameters::Data () const

{
	return ((void *)(this->mbuffer));
}

/*====================================================================*
 *
 *   size_t Size () const;
 *
 *   return parameter block extent (length) in bytes;
 *
 *--------------------------------------------------------------------*/

size_t CPLParameters::Size () const

{
	return (this->mextent);
}

/*====================================================================*
 *
 *   bool IsValid () const;
 *
 *   return true of the parameter block is valid; check the length
 *   and checksum as the minimum;
 *
 *   this method may be expanded to include other parameter block
 *   validity tests;
 *
 *--------------------------------------------------------------------*/

bool CPLParameters::IsValid () const

{
	if ((!this->mbuffer) || (!this->mextent))
	{
		oerror::error (0, ECANCELED, "No Parameter Block Available");
		return (false);
	}
	if (this->mextent != LE16TOH (this->mheader->PIBLENGTH))
	{
		oerror::error (0, ECANCELED, "Bad Parameter Block Length");
		return (false);
	}
	if (omemory::checksum32 (this->mbuffer, this->mextent, 0))
	{
		oerror::error (0, ECANCELED, "Bad Parameter Block Checksum");
		return (false);
	}
	return (true);
}

/*====================================================================*
 *
 *   void CPLParameters:: SetCAPPriority (int CAPpriority);
 *
 *   setCAPpriority to decide CAP for unicast traffic
 *
 *--------------------------------------------------------------------*/

CPLParameters & CPLParameters::SetCAPPriority (int CAPpriority)

{
	std::cout << "\nCurrent value of unicast CAP is : " << (int) *(mbuffer+0x020C);
	this->mbuffer [0x020C] = CAPpriority;
	return (*this);
}

int CPLParameters::Write_QoS_block (int selectPIB)

{       int QoSoffset = 0x020C;
        int QoSoffset2 = 0x1EB8;
        std::ifstream stream;
        switch (selectPIB)
        { case (0) :
            stream.open ("pib0.pib", std::ios::binary);
            break;
          case (1) :
            stream.open ("pib1.pib", std::ios::binary);
            break;
          case (2) :
            stream.open ("pib2.pib", std::ios::binary);
            break;
          default :
            oerror::error (0, ECANCELED, "Selected PIB doesn't exist");
            return (-1);

        }

        if (stream.good ())
            {
              //  stream.seekg (0, std::ios::end);
             //   this->mextent = 0x0990;
                stream.seekg (QoSoffset, std::ios::beg);
       //         this->mbuffer = new uint8_t [this->mextent];
                stream.read ((char *)((this->mbuffer)+QoSoffset), (1925));
                stream.seekg (QoSoffset2, std::ios::beg);
                stream.read ((char *)((this->mbuffer)+QoSoffset2), (65));
            }
        else
              {     oerror::error (0, ECANCELED, "Bad Stream,can't read");
                    return (-1);
              }

        stream.close ();
        this->mheader = (CPLParameters::Header *) (this->mbuffer);
        return (0);
}

/*====================================================================*
 *
 *   signed CPLParameters::Read (char const * filename);
 *
 *   read parameter block from file;
 *
 *--------------------------------------------------------------------*/

signed CPLParameters::Read (char const * filename)

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
	this->mheader = (CPLParameters::Header *) (this->mbuffer);
	return (0);
}

/*====================================================================*
 *
 *   signed Write (char const * filename);
 *
 *   write parameter block to file;
 *
 *--------------------------------------------------------------------*/

signed CPLParameters::Write (char const * filename)

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
 *   read the current parameter block image from device to memory
 *   using as many VS_RD_MOD messages as needed; the firmware must
 *   be running for this to work;
 *
 *   return 0 on success or -1 on failure;
 *
 *--------------------------------------------------------------------*/

signed CPLParameters::Read (CPLChannel * channel)

{
	ointellon intellon;
	uint8_t message [ETHER_MAX_LEN];

#ifndef __GNUC__
#pragma pack (push,1)
#endif

	struct __packed vs_rd_mod_request
	{
		uint8_t MODULEID;
		uint8_t MACCESS;
		uint16_t MLENGTH;
		uint32_t MOFFSET;
		uint8_t MSECRET [16];
	}
	* request;
	struct __packed vs_rd_mod_confirm
	{
		uint8_t MSTATUS;
		uint8_t RESERVED1 [3];
		uint8_t MODULEID;
		uint8_t RESERVED;
		uint16_t MLENGTH;
		uint32_t MOFFSET;
		uint32_t MCHKSUM;
		uint8_t MBUFFER [oINTELLON_BLOCKSIZE];
	}
	* confirm;

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
		request->MODULEID = VS_MODULE_PIB;
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
			oerror::error (0, ECANCELED, CPLCHANNEL_CANTDOIT,confirm->MSTATUS,CPLParameters::MessageErrorText((VS_RD_MOD | MMTYPE_CNF),confirm->MSTATUS));
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
		if (!offset)
		{
			if (this->mbuffer)
			{
				delete [] this->mbuffer;
			}
			this->mheader = (CPLParameters::Header *) (confirm->MBUFFER);
			this->mextent = extent = LE16TOH (this->mheader->PIBLENGTH);
			this->mbuffer = new uint8_t [this->mextent];
		}
		if (length > extent)
		{
			length = extent;
		}
		std::memcpy (this->mbuffer + offset, confirm->MBUFFER, length);
		offset += length;
		extent -= length;
	}
	while (extent);
	this->mheader = (CPLParameters::Header *) (this->mbuffer);
	return (0);
}

/*====================================================================*
 *
 *   signed Write (CPLChannel * channel);
 *
 *   write the current parameter block image from memory to device
 *   using as many VS_WR_MOD messages as needed; the firmware must
 *   be running for this to work;
 *
 *   return 0 on success or -1 on failure;
 *
 *--------------------------------------------------------------------*/

signed CPLParameters::Write (CPLChannel * channel)

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
		request->MODULEID = VS_MODULE_PIB;
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
            oerror::error (0, ECANCELED, CPLCHANNEL_CANTDOIT, confirm->MSTATUS, CPLParameters::MessageErrorText((VS_WR_MOD | MMTYPE_CNF),confirm->MSTATUS));
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
 *   commit downloaded parameter block to flash memory;
 *
 *--------------------------------------------------------------------*/

signed CPLParameters::Flash (CPLChannel *channel)

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
	request->MODULEID = VS_MODULE_PIB;
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
	    oerror::error (0, ECANCELED, CPLCHANNEL_CANTDOIT, confirm->MSTATUS,CPLParameters::MessageErrorText((VS_MOD_NVM | MMTYPE_CNF),confirm->MSTATUS));
		return (-1);
	}
	return (0);
}

/*====================================================================*
 *
 *   CPLParameters & Lock (void * memory, size_t extent);
 *
 *   recompute and update the parameter block header checksum; this
 *   conceptually locks the parameter block state;
 *
 *--------------------------------------------------------------------*/

CPLParameters & CPLParameters::Lock ()

{
	this->mheader->CHECKSUM = 0;
	this->mheader->CHECKSUM = omemory::checksum32 (this->mbuffer, this->mextent, 0);
	return (*this);
}

/*====================================================================*
 *
 *   CPLParameters & CPLParameters::Init ();
 *
 *   initialize instance variable;
 *
 *--------------------------------------------------------------------*/

CPLParameters & CPLParameters::Init ()

{
	this->mheader = (CPLParameters::Header *)(0);
	this->mbuffer = (uint8_t *)(0);
	this->mextent = 0;
	return (*this);
}

/*====================================================================*
 *
 *   CPLParameters (CPLChannel * channel)
 *
 *--------------------------------------------------------------------*/

CPLParameters::CPLParameters (CPLChannel * channel)

{
	this->Init ().Read (channel);
	return;
}

/*====================================================================*
 *
 *   CPLParameters (char const * filename)
 *
 *--------------------------------------------------------------------*/

CPLParameters::CPLParameters (char const * filename)

{
	this->Init ().Read (filename);
	return;
}

/*====================================================================*
 *
 *   ~CPLParameters ()
 *
 *--------------------------------------------------------------------*/

CPLParameters::~CPLParameters ()

{
	delete [] this->mbuffer;
	return;
}

/*====================================================================*
 *   end definition;
 *--------------------------------------------------------------------*/

#endif

