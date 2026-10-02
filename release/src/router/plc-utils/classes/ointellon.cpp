/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/
/*====================================================================*
 *
 *   ointellon.cpp - ointellon class definition;
 *
 *   implement an Intellon vendor specific HomePlug AV message header
 *   consisting of an Ethernet header, message version, message type 
 *   and vendor OUI; provide methods to encode and decode external 
 *   memory; 
 *
 *   Contributor(s): 
 *	    Charles Maier <charles.maier@intellon.com>
 *
 *--------------------------------------------------------------------*/

#ifndef oINTELLON_SOURCE
#define oINTELLON_SOURCE

/*====================================================================*
 *   system header files;
 *--------------------------------------------------------------------*/

#include <iostream>
#include <cstring>

/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

#include "../classes/ointellon.hpp"
#include "../classes/omemory.hpp"
#include "../tools/endian.h"

/*====================================================================*
 *   class constants;
 *--------------------------------------------------------------------*/

byte const ointellon::LocalcastAddress [ETHER_ADDR_LEN] = 

{
	0x00,
	0xB0,
	0x52,
	0x00,
	0x00,
	0x01 
};

/*====================================================================*
 *   
 *   size_t HeaderLength (void) const;
 *
 *   return the length of an encoded intellon vendor specific header
 *   in bytes;
 *   
 *--------------------------------------------------------------------*/

size_t ointellon::HeaderLength (void) const 

{
	return (ohomeplug::HeaderLength() + sizeof (this->moui));
}

/*====================================================================*
 *   
 *   size_t BufferLength (void) const;
 *
 *   return the length of an encoded intellon vendor specific header
 *   in bytes;
 *   
 *--------------------------------------------------------------------*/

size_t ointellon::BufferLength (size_t extent) const 

{
	return (ohomeplug::HeaderLength () + sizeof (this->moui) + extent);
}

/*====================================================================*
 *   
 *   void * ointellon::ExportHeader (void * memory) constant;
 *
 *   encode external memory with the message version, message type 
 *   and vendor OUI; return the next unencoded memory location;
 *   
 *--------------------------------------------------------------------*/

void * ointellon::ExportHeader (void * memory) const 

{
	memory = ohomeplug::ExportHeader (memory);
	memory = omemory::encode (memory, this->moui, sizeof (this->moui));
	return (memory);
}

/*====================================================================*
 *   
 *   void const * ointellon::ImportHeader (void const * memory);
 *
 *   decode external memory into the message version, message type 
 *   and vendor OUI; return the next undecoded memory location;
 *   
 *--------------------------------------------------------------------*/

void const * ointellon::ImportHeader (void const * memory) 

{
	memory = ohomeplug::ImportHeader (memory);
	memory = omemory::decode (memory, this->moui, sizeof (this->moui));
	return (memory);
}

/*====================================================================*
 *   
 *   byte const * ointellon::VendorOUI (void) const;
 *
 *   return the location fo the vendor OUI; the vendor OUI must not 
 *   be change for Intellon devices;
 *
 *--------------------------------------------------------------------*/

byte const * ointellon::VendorOUI (void) const 

{
	return (this->moui);
}

/*====================================================================*
 *   
 *   char const * ointellon::VendorOUIString (void) const;
 *
 *--------------------------------------------------------------------*/

char const * ointellon::VendorOUIString (void) const 

{
	static char buffer [sizeof (this->moui) * 3];
	omemory::hexdecode (&this->moui, sizeof (this->moui), buffer, sizeof (buffer));
	return (buffer);
}

/*====================================================================*
 *
 *   ointellon & Print ();
 *
 *   print protocol version, vendor message type and vendor OUI on 
 *   stdout; message type and OUI are in hex format;
 *
 *--------------------------------------------------------------------*/

ointellon & ointellon::Print () 

{
	ohomeplug::Print ();
	std::cerr << this->VendorOUIString () << std::endl;
	return (*this);
}

/*====================================================================*
 *
 *   ointellon(void);
 *
 *--------------------------------------------------------------------*/

ointellon::ointellon (void) 

{
	ohomeplug::ImportPeerAddress (this->LocalcastAddress);
	ohomeplug::SetProtocol (oINTELLON_MTYPE);
	ohomeplug::SetMessageVersion (oINTELLON_MMV);
	ohomeplug::SetMessageType (oINTELLON_MMTYPE);
	ohomeplug::SetMessageFragment (oINTELLON_FMI);
	std::memcpy (this->moui, this->LocalcastAddress, sizeof (this->moui));
	return;
}

/*====================================================================*
 *
 *   ~ointellon (void);
 *
 *--------------------------------------------------------------------*/

ointellon::~ointellon (void) 

{
	return;
}

/*====================================================================*
 *   end definition;
 *--------------------------------------------------------------------*/

#endif

