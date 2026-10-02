/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   CPLStation.hpp - CPLStation class definitions and declarations;
 *
 *   this object implements one powerline adapter;
 *
 *   Contributor(s): 
 *	Charles Maier <charles.maier@intellon.com>
 *
 *--------------------------------------------------------------------*/

#ifndef CPLSTATION_HEADER
#define CPLSTATION_HEADER

/*====================================================================*
 *   system header files;
 *--------------------------------------------------------------------*/

#if defined (__linux__)
#	include <net/ethernet.h>
#elif defined (__APPLE__)
#	include <net/ethernet.h>
#elif defined (__OpenBSD__)
#	include <sys/socket.h>
#	include <net/if.h>
#	include <netinet/in.h>
#	include <netinet/if_ether.h>
#elif defined (WINPCAP)
#	include <net/ethernet.h>
#else
#error "Unknown environment"
#endif

/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

#include "../classes/stdafx.hpp"
#include "../classes/CPLChannel.hpp"

/*====================================================================*
 *   class constants;
 *--------------------------------------------------------------------*/

#define CPLSTATION_UNKNOWN 0
#define CPLSTATION_INT6000 1
#define CPLSTATION_INT6300 2
#define CPLSTATION_INT6400 3
#define CPLSTATION_AR7400 4
#define CPLSTATION_AR6405 5
#define CPLSTATION_CHIPSET_MAX CPLSTATION_AR6405

#define CPLSTATION_BRIDGE 0
#define CPLSTATION_REMOTE 1

#define CPLSTATION_STA 0
#define CPLSTATION_CCO 1

/*====================================================================*
 *   class constants;
 *--------------------------------------------------------------------*/

typedef unsigned char byte;

/*====================================================================*
 *   class declaration;
 *--------------------------------------------------------------------*/

class __declspec (dllexport) CPLStation 

{
	friend class CPLNetwork;
public:
	CPLStation ();
	virtual ~ CPLStation ();
	bool IsBridge (void) const;
	unsigned LinkType (void) const;
	unsigned RoleType (void) const;
	char const * LinkName (void) const;
	char const * RoleName (void) const;
	unsigned StationID (void) const;
	byte const * NodeAddress (void) const;
	char const * NodeAddressString () const;
	byte const * HostAddress (void) const;
	char const * HostAddressString () const;
	unsigned TxRate (void) const;
	unsigned RxRate (void) const;
	unsigned HardwareType (void) const;
	char const * HardwareName (void) const;
	char const * FirmwareName (void) const;
	CPLStation & Revision (CPLChannel *);
	CPLStation & Preface ();
	CPLStation & Print ();
	static char const * PrefaceString;
private:
	static char const * chipset [];
	static char const * link [];
	static char const * role [];
	byte mstation;
	byte mlink;
	byte mrole;
	byte mnodeaddr [ETHER_ADDR_LEN];
	byte mhostaddr [ETHER_ADDR_LEN];
	byte mtxrate;
	byte mrxrate;
	byte mhardware;
	char mfirmware [128];
};

/*====================================================================*
 *   end declaration;
 *--------------------------------------------------------------------*/

#endif

