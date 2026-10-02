/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   oethernet.cpp - oethernet class definition;
 *
 *   implement a standard Ethernet header consisting of peer address, 
 *   host address and ethertype; provide methods to encode and decode 
 *   external memory;
 *
 *   Contributor(s): 
 *	    Charles Maier <charles.maier@intellon.com>
 *
 *--------------------------------------------------------------------*/

#ifndef oETHERNET_SOURCE
#define oETHERNET_SOURCE

/*====================================================================*
 *   system header files;
 *--------------------------------------------------------------------*/

#include <cstring>
#include <iostream>

/*====================================================================*
 *   system header files;
 *--------------------------------------------------------------------*/

#include <arpa/inet.h>

/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

#include "../classes/oethernet.hpp"
#include "../classes/omemory.hpp"

/*====================================================================*
 *   class constants;
 *--------------------------------------------------------------------*/

byte const oethernet::EmptycastAddress [ETHER_ADDR_LEN] = 

{
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00 
};

byte const oethernet::BroadcastAddress [ETHER_ADDR_LEN] = 

{
	0xFF,
	0xFF,
	0xFF,
	0xFF,
	0xFF,
	0xFF 
};

/*====================================================================*
 *   
 *   size_t HeaderLength (void) const;
 *   
 *   return the length of an encoded Ethernet header in bytes;
 *
 *--------------------------------------------------------------------*/

size_t oethernet::HeaderLength (void) const 

{
	return (sizeof (this->mpeeraddr) + sizeof (this->mhostaddr) + sizeof (this->mprotocol));
}

/*====================================================================*
 *   
 *   void * ExportHeader (void * memory) const;
 *
 *   encode external memory with an Ethernet header and return the 
 *   address of the next unencoded memory byte;
 *   
 *--------------------------------------------------------------------*/

void * oethernet::ExportHeader (void * memory) const 

{
	memory = oethernet::ExportPeerAddress (memory);
	memory = oethernet::ExportHostAddress (memory);
	memory = oethernet::ExportProtocol (memory);
	return (memory);
}

/*====================================================================*
 *   
 *   void const * ImportHeader (void * memory);
 *
 *   decode external memory containing an Ethernet header and return
 *   the address of the next undecoded memory byte;
 *   
 *--------------------------------------------------------------------*/

void const * oethernet::ImportHeader (void const * memory) 

{
	memory = oethernet::ImportPeerAddress (memory);
	memory = oethernet::ImportHostAddress (memory);
	memory = oethernet::ImportProtocol (memory);
	return (memory);
}

/*====================================================================*
 *   
 *   void * ExportPeerAddress (void * memory) const;
 *
 *   encode external memory with the peer hardware address and return
 *   the address of the next unencoded memory byte;
 *
 *--------------------------------------------------------------------*/

void * oethernet::ExportPeerAddress (void * memory) const 

{
	memory = omemory::encode (memory, this->mpeeraddr, sizeof (this->mpeeraddr));
	return (memory);
}

/*====================================================================*
 *   
 *   void * ExportHostAddress (void * memory) const;
 *   
 *   encode external memory with the host hardware address and return
 *   the address of the next unencoded memory byte;
 *
 *--------------------------------------------------------------------*/

void * oethernet::ExportHostAddress (void * memory) const 

{
	memory = omemory::encode (memory, this->mhostaddr, sizeof (this->mhostaddr));
	return (memory);
}

/*====================================================================*
 *
 *   void * oethernet::ExportProtocol (void * memory) const;
 *
 *   encode external memory with the Ethernet protocol and return
 *   the address of the next unencoded memory byte;
 *
 *--------------------------------------------------------------------*/

void * oethernet::ExportProtocol (void * memory) const 

{
	memory = omemory::encode (memory, &this->mprotocol, sizeof (this->mprotocol));
	return (memory);
}

/*====================================================================*
 *   
 *   void const * ImportPeerAddress (void const * memory);
 *
 *   decode external memory containing the peer hardware address and
 *   return the address of the next undecoded byte;
 *   
 *--------------------------------------------------------------------*/

void const * oethernet::ImportPeerAddress (void const * memory) 

{
	memory = omemory::decode (memory, this->mpeeraddr, sizeof (this->mpeeraddr));
	return (memory);
}

/*====================================================================*
 *   
 *   void const * ImportHostAddress (void const * memory);
 *   
 *   decode external memory containing the host hardware address and
 *   return the address of the next undecoded byte;
 *   
 *--------------------------------------------------------------------*/

void const * oethernet::ImportHostAddress (void const * memory) 

{
	memory = omemory::decode (memory, this->mhostaddr, sizeof (this->mhostaddr));
	return (memory);
}

/*====================================================================*
 *   
 *   void const * ImportProtocol (void const * memory);
 *   
 *   decode external memory containing the Ethernet protocol and
 *   return the address of the next undecoded byte;
 *   
 *--------------------------------------------------------------------*/

void const * oethernet::ImportProtocol (void const * memory) 

{
	memory = omemory::decode (memory, &this->mprotocol, sizeof (this->mprotocol));
	return (memory);
}

/*====================================================================*
 *   
 *   const byte * PeerAddress (void) const;
 *
 *   return the binary peer address location;
 *   
 *--------------------------------------------------------------------*/

const byte * oethernet::PeerAddress (void) const 

{
	return (this->mpeeraddr);
}

/*====================================================================*
 *   
 *   const byte * HostAddress (void) const;
 *
 *   return the binary host address location;
 *   
 *--------------------------------------------------------------------*/

const byte * oethernet::HostAddress (void) const 

{
	return (this->mhostaddr);
}

/*====================================================================*
 *
 *   uint16_t oethernet::Protocol (void) const;
 *
 *   return the Ethernet protocol as an integer in host byte order;
 *
 *   the Ethernet protocol is stored internally in network byte order 
 *   so that it can be encoded/decoded and imported/exported directly 
 *   without modification;
 *
 *--------------------------------------------------------------------*/

uint16_t oethernet::Protocol (void) const 

{
	return (ntohs (this->mprotocol));
}

/*====================================================================*
 *   
 *   oethernet & SetProtocol (uint16_t protocol);
 *   
 *   accept a new Ethernet protocol specified as an integer in host 
 *   byte order; 
 *   
 *   the Ethernet protocol is stored internally in network byte order 
 *   so that it may be encoded/decoded and imported/exported directly 
 *   without modification;
 *
 *--------------------------------------------------------------------*/

oethernet & oethernet::SetProtocol (uint16_t protocol) 

{
	this->mprotocol = htons (protocol);
	return (*this);
}

/*====================================================================*
 *   
 *   char const * PeerAddressString (void) const;
 *
 *   return the peer address string location;
 *   
 *--------------------------------------------------------------------*/

char const * oethernet::PeerAddressString (void) const 

{
	static char buffer [sizeof (this->mpeeraddr) * 3];
	omemory::hexdecode (this->mpeeraddr, sizeof (this->mpeeraddr), buffer, sizeof (buffer));
	return (buffer);
}

/*====================================================================*
 *   
 *   char const * HostAddressString (void) const;
 *   
 *   return the host address string location;
 *   
 *--------------------------------------------------------------------*/

char const * oethernet::HostAddressString (void) const 

{
	static char buffer [sizeof (this->mhostaddr) * 3];
	omemory::hexdecode (this->mhostaddr, sizeof (this->mhostaddr), buffer, sizeof (buffer));
	return (buffer);
}

/*====================================================================*
 *   
 *   char const * ProtocolString (void) const;
 *   
 *   return the protocol string location;
 *   
 *--------------------------------------------------------------------*/

char const * oethernet::ProtocolString (void) const 

{
	static char buffer [sizeof (this->mprotocol) * 3];
	omemory::hexdecode (&this->mprotocol, sizeof (this->mprotocol), buffer, sizeof (buffer));
	return (buffer);
}

/*====================================================================*
 *
 *   oethernet & Print ();
 *
 *   print peer address, host address and ethertype on stdout in hex
 *   format; return the object instance address;
 *
 *--------------------------------------------------------------------*/

oethernet & oethernet::Print () 

{
	std::cerr << oethernet::PeerAddressString () << " ";
	std::cerr << oethernet::HostAddressString () << " ";
	std::cerr << oethernet::ProtocolString () << std::endl;
	return (*this);
}

/*====================================================================*
 *
 *   oethernet (uint16_t protocol);
 *
 *   clear peer and host hardware addresses; set protocol to default
 *   in network byte order; 
 *
 *--------------------------------------------------------------------*/

oethernet::oethernet (uint16_t protocol) 

{
	std::memset (this->mpeeraddr, 0, sizeof (this->mpeeraddr));
	std::memset (this->mhostaddr, 0, sizeof (this->mhostaddr));
	this->mprotocol = htons (protocol);
	return;
}

/*====================================================================*
 *
 *   oethernet (void);
 *
 *   clear peer and host hardware addresses; set protocol to default
 *   value in network byte order;
 *
 *--------------------------------------------------------------------*/

oethernet::oethernet (void) 

{
	std::memset (this->mpeeraddr, 0, sizeof (this->mpeeraddr));
	std::memset (this->mhostaddr, 0, sizeof (this->mhostaddr));
	this->mprotocol = 0;
	return;
}

/*====================================================================*
 *
 *   ~oethernet (void);
 *
 *--------------------------------------------------------------------*/

oethernet::~oethernet (void) 

{
	return;
}

/*====================================================================*
 *   end definition;
 *--------------------------------------------------------------------*/

#endif

