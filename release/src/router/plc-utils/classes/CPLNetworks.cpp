/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   CPLNetworks.cpp - CPLNetworks class definition;
 *
 *   powerline network enumerator; 
 *
 *   the collection of CPLNetworks on a single host interface;
 *
 *   Contributor(s): 
 *	    Charles Maier <charles.maier@intellon.com>
 *
 *--------------------------------------------------------------------*/

#ifndef CPLNETWORKS_SOURCE
#define CPLNETWORKS_SOURCE

/*====================================================================*
 *   system header files;
 *--------------------------------------------------------------------*/

#include <iostream>
#include <cstring>

/*====================================================================*
 *   system header files;
 *--------------------------------------------------------------------*/

#if defined (__linux__)
#	include <sys/socket.h>
#	include <net/ethernet.h>
#	include <net/if.h>
#elif defined (__APPLE__)
#	include <sys/socket.h>
#	include <net/ethernet.h>
#	include <net/if.h>
#elif defined (__OpenBSD__)
#	include <sys/socket.h>
#	include <net/if.h>
#	include <netinet/in.h>
#	include <netinet/if_ether.h>
#elif defined (WINPCAP)
#	include <pcap.h>
#else
#error "Unknown environment"
#endif

/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

#include "../classes/CPLNetworks.hpp"
#include "../classes/CPLChannel.hpp"

/*====================================================================*
 *
 *   bool Empty (void) const;
 *
 *   return true if there are no table networks;
 *
 *--------------------------------------------------------------------*/

bool CPLNetworks::Empty (void) const 

{
	return (!this->mcount);
}

/*====================================================================*
 *
 *   bool End (void) const;
 *
 *   return true once the lasttable network has been reached;
 *
 *--------------------------------------------------------------------*/

bool CPLNetworks::End (void) const 

{
	return (this->mindex >= this->mcount);
}

/*====================================================================*
 *
 *   unsigned Count (void) const;
 *
 *   return the number of table networks;
 *
 *--------------------------------------------------------------------*/

unsigned CPLNetworks::Count (void) const 

{
	return (this->mcount);
}

/*====================================================================*
 *
 *   unsigned Index (void) const;
 *
 *   return the current table network number; 
 *
 *--------------------------------------------------------------------*/

unsigned CPLNetworks::Index (void) const 

{
	return (this->mindex);
}

/*====================================================================*
 *
 *   CPLNetworks & SelectFirst (void);
 *
 *   select first table network;
 *
 *--------------------------------------------------------------------*/

CPLNetworks & CPLNetworks::SelectFirst (void) 

{
	this->mindex = 0;
	return (*this);
}

/*====================================================================*
 *
 *   CPLNetworks & SelectFinal (void);
 *
 *   select final table network;
 *
 *--------------------------------------------------------------------*/

CPLNetworks & CPLNetworks::SelectFinal (void) 

{
	this->mindex = this->mcount - 1;
	return (*this);
}

/*====================================================================*
 *
 *   CPLNetworks & SelectPrev (void) 
 *
 *   select the prev table network unless the current network is the
 *   first network; same as operator --;
 *
 *--------------------------------------------------------------------*/

CPLNetworks & CPLNetworks::SelectPrev (void) 

{
	if (this->mindex > 0) 
	{
		this->mindex--;
	}
	return (*this);
}

/*====================================================================*
 *
 *   CPLNetworks & SelectNext (void) 
 *
 *   select the next table network unless the current network is the
 *   final network; same as operator ++; 
 *
 *--------------------------------------------------------------------*/

CPLNetworks & CPLNetworks::SelectNext (void) 

{
	if (this->mindex < this->mcount) 
	{
		this->mindex++;
	}
	return (*this);
}

/*====================================================================*
 *
 *   CPLNetworks & Select (unsigned index);
 *
 *   select a table network by number; same as operator [];
 *
 *--------------------------------------------------------------------*/

CPLNetworks & CPLNetworks::Select (unsigned index) 

{
	this->mindex = index;
	if (this->mindex > this->mcount) 
	{
		this->mindex = this->mcount;
	}
	return (*this);
}

/*====================================================================*
 *
 *   CPLNetwork & operator = (unsigned index) 
 *
 *   select a table network by number;
 *
 *--------------------------------------------------------------------*/

CPLNetworks & CPLNetworks::operator = (unsigned index) 

{
	return (this->Select (index));
}

/*====================================================================*
 *
 *   CPLNetwork & operator [] (unsigned index) 
 *
 *   select a table network then return a reference to it;
 *
 *--------------------------------------------------------------------*/

CPLNetwork & CPLNetworks::operator [] (unsigned index) 

{
	return (this->Select (index).Selected ());
}

/*====================================================================*
 *
 *   CPLNetwork & Selected (void) const
 *
 *   return a reference to the selected table network; 
 *
 *--------------------------------------------------------------------*/

CPLNetwork & CPLNetworks::Selected (void) const 

{
	return (* this->mtable [this->mindex]);
}

/*====================================================================*
 *
 *   CPLNetwork & Station (void) const
 *
 *   return a reference to the selected table network; 
 *
 *--------------------------------------------------------------------*/

CPLNetwork & CPLNetworks::Network (void) const 

{
	return (* this->mtable [this->mindex]);
}

/*====================================================================*
 *
 *   CPLNetworks & Enumerate (void);
 *
 *   interate through networks and enumerate each on stdout but do  
 *   not change the selected network;
 *
 *--------------------------------------------------------------------*/

CPLNetworks & CPLNetworks::Enumerate (void) 

{
	for (unsigned index = 0; index < this->mcount; index++) 
	{
		this->mtable [index]->Enumerate ();
	}
	return (*this);
}

/*====================================================================*
 *   
 *   CPLNetworks (CPLChannel * channel);
 *
 *--------------------------------------------------------------------*/

CPLNetworks::CPLNetworks (char const * ifname) 

{
	CPLChannel channel (ifname);
	byte bridge [CPLCHANNEL_BRIDGES_MAX][ETHER_ADDR_LEN];
	this->mtable = new CPLNetwork * [CPLCHANNEL_BRIDGES_MAX];
	this->mcount = channel.Bridges (bridge, sizeof (bridge));
	this->mindex = 0;
	while (this->mindex < this->mcount) 
	{
		channel.ImportPeerAddress (bridge [this->mindex]);
		this->mtable [this->mindex] = new CPLNetwork (&channel);
		this->mindex++;
	}
	this->mindex = 0;
	return;
}

/*====================================================================*
 *
 *   ~CPLNetworks () 
 *
 *   delete table after deleting networks;
 *
 *--------------------------------------------------------------------*/

CPLNetworks::~CPLNetworks () 

{
	delete [] this->mtable;
	return;
}

/*====================================================================*
 *   end definition;
 *--------------------------------------------------------------------*/

#endif

