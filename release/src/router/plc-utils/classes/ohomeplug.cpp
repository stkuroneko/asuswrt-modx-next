/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   ohomeplug.cpp - ohomeplug class implementeation;
 *
 *   implement a HomePlug AV compliant message header consisting of 
 *   Ethernet header, message version and messge type; provide methods
 *   tod encode and decode external memory;
 *
 *   Contributor(s): 
 *	Charles Maier <charles.maier@intellon.com>
 *
 *--------------------------------------------------------------------*/

#ifndef oHOMEPLUG_SOURCE
#define oHOMEPLUG_SOURCE

/*====================================================================*
 *   system header files;
 *--------------------------------------------------------------------*/

#include <cstring>

/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

#include "../classes/ohomeplug.hpp"
#include "../classes/omemory.hpp"
#include "../tools/endian.h"

/*====================================================================*
 *   
 *   size_t HeaderLength () const;
 *   
 *   return the length of an encoded homeplug header in bytes;
 *
 *--------------------------------------------------------------------*/

size_t ohomeplug::HeaderLength () const 

{
	return (oethernet::HeaderLength () + sizeof (this->mversion) + sizeof (this->mmessage));
}

/*====================================================================*
 *   
 *   void * ExportHeader (void * memory) const;
 *
 *   encode external memory with the peer address, host addresse and
 *   ethertype; return the next unencoded memory location;
 *   
 *--------------------------------------------------------------------*/

void * ohomeplug::ExportHeader (void * memory) const 

{
	memory = oethernet::ExportHeader (memory);
	memory = omemory::encode (memory, &this->mversion, sizeof (this->mversion));
	memory = omemory::encode (memory, &this->mmessage, sizeof (this->mmessage));
	if (this->mversion == 1)
	{
		memory = omemory::encode (memory, &this->mfragment, sizeof (this->mfragment));
	}
	return (memory);
}

/*====================================================================*
 *   
 *   void const * ImportHeader (void const * memory);
 *
 *   decode external memory into the peer address, host addresse and
 *   ethertype; return the next undecoded memory location;
 *   
 *--------------------------------------------------------------------*/

void const * ohomeplug::ImportHeader (void const * memory) 

{
	memory = oethernet::ImportHeader (memory);
	memory = omemory::decode (memory, &this->mversion, sizeof (this->mversion));
	memory = omemory::decode (memory, &this->mmessage, sizeof (this->mmessage));
	if (this->mversion == 1)
	{
		memory = omemory::decode (memory, &this->mfragment, sizeof (this->mfragment));
	}
	return (memory);
}

/*====================================================================*
 *   
 *   const byte ohomeplug::MessageVersion () const;
 *
 *   return the message version; 
 *
 *   the message version is the MMV field described in the HomePlug 
 *   AV Specification and the Intellon Technical Reference Manual;
 *   
 *--------------------------------------------------------------------*/

byte ohomeplug::MessageVersion () const 

{
	return (this->mversion);
}

/*====================================================================*
 *   
 *   ohomeplug & ohomeplug::SetMessageVersion (byte version);
 *
 *   change the message version;
 *
 *   the message version is the MMV field described in the HomePlug
 *   AV Specification and the Intellon Firmware Technical Reference
 *   Manual;
 *   
 *--------------------------------------------------------------------*/

ohomeplug & ohomeplug::SetMessageVersion (byte version) 

{
	this->mversion = version;
	return (*this);
}

/*====================================================================*
 *   
 *   const uint16_t ohomeplug::MessageType () const;
 *   
 *   return the vendor specific message type in host byte order;
 *
 *   vendor specific message types are restricted to 0xA000 through 
 *   0xBFFF but we permit any 16-bit value;
 *
 *   the message type is the MMTYPE field described in the HomePlug
 *   AV Specification and the Intellon Firmware Technical Reference 
 *   Manual;
 *
 *--------------------------------------------------------------------*/

uint16_t ohomeplug::MessageType () const 

{
	return (LE16TOH (this->mmessage));
}

/*====================================================================*
 *   
 *   char const * ohomeplug::MessageTypeString (void) const;
 *
 *--------------------------------------------------------------------*/

char const * ohomeplug::MessageTypeString (void) const 

{
	static char buffer [sizeof (this->mmessage) * 3];
	omemory::hexdecode (&this->mmessage, sizeof (this->mmessage), buffer, sizeof (buffer));
	return (buffer);
}

/*====================================================================*
 *   
 *   ohomeplug & ohomeplug::SetMessageType (uint16_t message);
 *   
 *   change the vendor specific message type in little endian order;
 *
 *   vendor specific message types are restricted to 0xA000 through 
 *   0xBFFF but we permit any 16-bit value;
 *
 *   the message type is the MMTYPE field described in the HomePlug
 *   AV Specification and the Intellon Firmware Technical Reference 
 *   Manual;
 *
 *--------------------------------------------------------------------*/

ohomeplug & ohomeplug::SetMessageType (uint16_t message) 

{
	this->mmessage = HTOLE16 (message);
	return (*this);
}

/*====================================================================*
 *
 *   bool IsMessageType (uint16_t messagetype) 
 *
 *   return true if this instance contains the requested HomePlug  
 *   message type; 
 *
 *--------------------------------------------------------------------*/

bool ohomeplug::IsMessageType (uint8_t version, uint16_t message) 

{
	if (ohomeplug::MessageVersion () != version) 
	{
		return (false);
	}
	if (ohomeplug::MessageType () != message) 
	{
		return (false);
	}
	return (true);
}

/*====================================================================*
 *   
 *   const uint16_t ohomeplug::MessageFragment (void) const;
 *   
 *   return the vendor specific message fragment in host byte order;
 *
 *   vendor specific message types are restricted to 0xA000 through 
 *   0xBFFF but we permit any 16-bit value;
 *
 *   the message type is the MMTYPE field described in the HomePlug
 *   AV Specification and the Intellon Firmware Technical Reference 
 *   Manual;
 *
 *--------------------------------------------------------------------*/

uint16_t ohomeplug::MessageFragment (void) const 

{
	return (LE16TOH (this->mfragment));
}

/*====================================================================*
 *   
 *   const char * ohomeplug::MessageFragmentString (void) const;
 *
 *   return the message type as a colon-separated, hexadecimal string
 *   shown in network byte order;
 *
 *--------------------------------------------------------------------*/

char const * ohomeplug::MessageFragmentString (void) const 

{
	static char buffer [sizeof (this->mfragment) * 3];
	omemory::hexdecode (&this->mfragment, sizeof (this->mfragment), buffer, sizeof (buffer));
	return (buffer);
}

/*====================================================================*
 *   
 *   ohomeplug & ohomeplug::SetMessageFragment (uint16_t fragment);
 *   
 *--------------------------------------------------------------------*/

ohomeplug & ohomeplug::SetMessageFragment (uint16_t fragment) 

{
	this->mfragment = HTOLE16 (fragment);
	return (*this);
}

/*====================================================================*
 *   
 *   ohomeplug & SetHeader (void const * memory);
 *
 *   decode external memory into the peer address, host addresse and
 *   ethertype; return the next undecoded memory location;
 *   
 *--------------------------------------------------------------------*/

ohomeplug & ohomeplug::SetHeader (void const * memory) 

{
	ohomeplug::ImportHeader(memory);
	return (*this);
}

/*====================================================================*
 *
 *   ohomeplug();
 *
 *   clear the peer and host hardware addresses and initialize the
 *   ethertype field to the default value in network byte order;
 *
 *--------------------------------------------------------------------*/

ohomeplug::ohomeplug () 

{
	oethernet::SetProtocol (oHOMEPLUG_MTYPE);
	ohomeplug::SetMessageVersion (oHOMEPLUG_MMV);
	ohomeplug::SetMessageType (oHOMEPLUG_MMTYPE);
	ohomeplug::SetMessageFragment (oHOMEPLUG_FMI);
	return;
}

/*====================================================================*
 *
 *   ~ohomeplug();
 *
 *--------------------------------------------------------------------*/

ohomeplug::~ohomeplug () 

{
	return;
}

/*====================================================================*
 *   end definition;
 *--------------------------------------------------------------------*/

#endif

