/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   ointerface.hpp - interface for the ointerface class
 *
 *   host interface information;
 *
 *   Contributor(s):
 *	    Charles Maier <charles.maier@intellon.com>
 *
 *--------------------------------------------------------------------*/

#ifndef oINTERFACE_HEADER
#define oINTERFACE_HEADER

/*====================================================================*
 *   system header files;
 *--------------------------------------------------------------------*/

#if defined (__linux__)
#	include <stdint.h>
#	include <net/ethernet.h>
#	include <net/if.h>
#elif defined (__APPLE__)
#	include <sys/socket.h>
#	include <net/if.h>
#	include <netinet/in.h>
#	include <netinet/if_ether.h>
#elif defined (__OpenBSD__)
#	include <sys/socket.h>
#	include <net/if.h>
#	include <netinet/in.h>

// #include <arpa/inet.h>

#	include <netinet/if_ether.h>
#elif defined (WINPCAP)
#	include <net/ethernet.h>
#	include <net/if.h>
#else
#error "Unknown environment"
#endif

/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

#include "../classes/stdafx.hpp"

/*====================================================================*
 *   class datatypes;
 *--------------------------------------------------------------------*/

typedef unsigned char byte;

/*====================================================================*
 *   class declaration;
 *--------------------------------------------------------------------*/

class __declspec (dllexport) ointerface

{
	friend class ointerfaces;
public:
	explicit ointerface (unsigned ifindex);
	explicit ointerface (char const * ifname);
	virtual ~ ointerface ();
	unsigned Index (void) const;
	char const * Name (void) const;
	char const * Description (void) const;
	byte const * HardwareAddress (void) const;
	byte const * InternetAddress (void) const;
	char const * HardwareAddressString (void) const;
	char const * InternetAddressString (void) const;
	ointerface & Description (char const *);
	ointerface & ExportHardwareAddress (void *);
	ointerface & ExportInternetAddress (void *);
	ointerface & Print ();
	bool Disabled () const;
protected:
private:
	ointerface & lookup ();
	unsigned pcap_nametoindex (char const * ifname) const;
	char * pcap_indextoname (unsigned ifindex, char * ifname) const;
	void pcap_gethwaddr ();
	void pcap_getipaddr ();
	unsigned mifindex;
	byte mhwaddr [ETHER_ADDR_LEN];
	byte mipaddr [sizeof (uint32_t)];
	char mhwstring [ETHER_ADDR_LEN * 3];
	char mipstring [sizeof (uint32_t) * 4];
	char mifname [IF_NAMESIZE];
	char miftext [255];
};

/*====================================================================*
 *   end declaration;
 *--------------------------------------------------------------------*/

#endif

