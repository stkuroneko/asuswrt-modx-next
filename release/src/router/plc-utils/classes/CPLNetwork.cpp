/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   CPLNetwork.cpp - CPLNetwork class definition;
 *
 *   powerline station enumerator;  
 *
 *   the collection of CPLStations on a single powerline network;
 *
 *   Contributor(s): 
 *	    Charles Maier <charles.maier@intellon.com>
 *
 *--------------------------------------------------------------------*/

#ifndef CPLNETWORK_SOURCE
#define CPLNETWORK_SOURCE

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

#include "../classes/CPLNetwork.hpp"
#include "../classes/ointellon.hpp"
#include "../classes/ohomeplug.hpp"
#include "../classes/oerror.hpp"

/*====================================================================*
 *
 *   bool Empty (void) const;
 *
 *   return true if there are no stations;
 *
 *--------------------------------------------------------------------*/

bool CPLNetwork::Empty (void) const 

{
	return (!this->mcount);
}

/*====================================================================*
 *
 *   bool End (void) const;
 *
 *   return true if the last station has been reached;
 *
 *--------------------------------------------------------------------*/

bool CPLNetwork::End (void) const 

{
	return (this->mindex >= this->mcount);
}

/*====================================================================*
 *
 *   unsigned Count (void) const;
 *
 *   return the number of stations;
 *
 *--------------------------------------------------------------------*/

unsigned CPLNetwork::Count (void) const 

{
	return (this->mcount);
}

/*====================================================================*
 *
 *   unsigned Index (void) const;
 *
 *   return the current powerline station index;
 *
 *--------------------------------------------------------------------*/

unsigned CPLNetwork::Index (void) const 

{
	return (this->mindex);
}

/*====================================================================*
 *
 *   CPLNetwork & SelectFirst (void);
 *
 *   select first station;
 *
 *--------------------------------------------------------------------*/

CPLNetwork & CPLNetwork::SelectFirst (void) 

{
	this->mindex = 0;
	return (*this);
}

/*====================================================================*
 *
 *   CPLNetwork & SelectFinal (void);
 *
 *   select final station;
 *
 *--------------------------------------------------------------------*/

CPLNetwork & CPLNetwork::SelectFinal (void) 

{
	this->mindex = this->mcount - 1;
	return (*this);
}

/*====================================================================*
 *
 *   CPLNetwork & SelectPrev (void) 
 *
 *   select the prev station unless the current station is the
 *   first station; same as operator --;
 *
 *--------------------------------------------------------------------*/

CPLNetwork & CPLNetwork::SelectPrev (void) 

{
	if (this->mindex > 0) 
	{
		this->mindex--;
	}
	return (*this);
}

/*====================================================================*
 *
 *   CPLNetwork & SelectNext (void) 
 *
 *   select the next station unless the current station is the
 *   final station; same as operator ++; 
 *
 *--------------------------------------------------------------------*/

CPLNetwork & CPLNetwork::SelectNext (void) 

{
	if (this->mindex < this->mcount) 
	{
		this->mindex++;
	}
	return (*this);
}

/*====================================================================*
 *
 *   CPLNetwork & Select (unsigned index);
 *
 *   select an station by number; same as operator [];
 *
 *--------------------------------------------------------------------*/

CPLNetwork & CPLNetwork::Select (unsigned index) 

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
 *   CPLStation & operator = (unsigned index) 
 *
 *   select an station;
 *
 *--------------------------------------------------------------------*/

CPLNetwork & CPLNetwork::operator = (unsigned index) 

{
	return (this->Select (index));
}

/*====================================================================*
 *
 *   CPLStation & operator [] (unsigned index) 
 *
 *   select a station then return an instance of it;
 *
 *--------------------------------------------------------------------*/

CPLStation & CPLNetwork::operator [] (unsigned index) 

{
	return (this->Select (index).Selected ());
}

/*====================================================================*
 *
 *   CPLStation & Selected (void) const
 *
 *   return the selected station; 
 *
 *--------------------------------------------------------------------*/

CPLStation & CPLNetwork::Selected (void) const 

{
	return (* this->mtable [this->mindex]);
}

/*====================================================================*
 *
 *   CPLStation & Station (void) const
 *
 *   return the selected station; 
 *
 *--------------------------------------------------------------------*/

CPLStation & CPLNetwork::Station (void) const 

{
	return (* this->mtable [this->mindex]);
}

/*====================================================================*
 *
 *   CPLNetwork & Enumerate (void);
 *
 *   interate through stations and print each on stdout but do not  
 *   change the selected station;
 *
 *--------------------------------------------------------------------*/

CPLNetwork & CPLNetwork::Enumerate (void) 

{
	for (unsigned index = 0; index < this->mcount; index++) 
	{
		this->mtable [index]->Print ();
	}
	return (*this);
}

/*====================================================================*
 *
 *   void platform (CPLChannel * channel, CPLStation * station);
 *
 *   update the mhardware and mfirmware members using a VS_SW_VER 
 *   management message;
 *
 *--------------------------------------------------------------------*/

void CPLNetwork::platform (CPLChannel * channel, CPLStation * station) 

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

	std::memset (message, 0, sizeof (message));;
	intellon.ImportPeerAddress (station->NodeAddress ());
	intellon.ImportHostAddress (channel->HostAddress ());
	version = (struct version *)(intellon.ExportHeader (message));
	if (channel->SendMessage (message, ETHER_MIN_LEN) > 0) 
	{
		while (channel->ReadMessage (message, sizeof (message)) > 0) 
		{
			intellon.ImportHeader (message);
			if (intellon.IsMessageType (0, (VS_SW_VER | MMTYPE_CNF)))
			{
				station->mhardware = version->MDEVICEID;
				std::memcpy (station->mfirmware, version->MVERSION, version->MVERSIONLENGTH);
				break;
			}
		}
	}
	return;
}

/*====================================================================*
 *   
 *   CPLNetwork (CPLChannel * channel);
 *
 *   instantiate the class with a collection of CPLStations; channel
 *   specifies the interface and station to interrogate;
 *   
 *   interrogate the specified station using a VS_NE_INFO message;
 *   for each neighbor, use a VS_SW_VER message to get the hardware
 *   type and firmware revsion string;
 *
 *   return an empty collection if channel peer address is either an 
 *   Ethernet broadcast address or an Intellon Localcast address; 
 *
 *   all stations are assumed to be ordinary stations unless their
 *   hardware address is the CCO hardware address;
 *
 *   the first station is first assumed to be the host bridge until 
 *   proven otherwise; successive stations are assumed to be remote 
 *   unless the BDA is the host hardware address; if that happens, 
 *   that station is the host bridge and the first station is remote;
 *   the host hardware address is the peer address for confirmation 
 *   messages;
 *
 *--------------------------------------------------------------------*/

CPLNetwork::CPLNetwork (CPLChannel * channel) 

{
	ointellon intellon;
	byte message [ETHER_MAX_LEN];

#ifndef __GNUC__
#pragma pack (push,1)
#endif

	struct __packed station 
	{
		uint8_t MAC [ETHER_ADDR_LEN];
		uint8_t TEI;
		uint8_t BDA [ETHER_ADDR_LEN];
		uint8_t AVGTX;
		uint8_t AVGRX;
	}
	* station;
	struct __packed network 
	{
		uint8_t NID [7];
		uint8_t SNID;
		uint8_t TEI;
		uint8_t ROLE;
		uint8_t CCO_MAC [ETHER_ADDR_LEN];
		uint8_t CCO_TEI;
		uint8_t NUMSTAS;
		struct station station [1];
	}
	* network;
	struct __packed networks 
	{
		uint8_t NUMAVLNS;
		struct network network [1];
	}
	* networks;

#ifndef __GNUC__
#pragma pack (pop)
#endif

	this->mindex = 0;
	this->mcount = 0;
	this->mtable = new CPLStation * [CPLCHANNEL_DEVICES_MAX];
	if (!std::memcmp (channel->PeerAddress (), oethernet::EmptycastAddress, ETHER_ADDR_LEN)) 
	{
		oerror::error (0, ECANCELED, "Emptycast used to instantiate CPLNetwork");
		return;
	}
	if (!std::memcmp (channel->PeerAddress (), oethernet::BroadcastAddress, ETHER_ADDR_LEN)) 
	{
		oerror::error (0, ECANCELED, "Broadcast used to instantiate CPLNetwork");
		return;
	}
	if (!std::memcmp (channel->PeerAddress (), ointellon::LocalcastAddress, ETHER_ADDR_LEN)) 
	{
		oerror::error (0, ECANCELED, "Localcast used to instantiate CPLNetwork");
		return;
	}
	std::memset (message, 0, sizeof (message));
	intellon.ImportPeerAddress (channel->PeerAddress ());
	intellon.ImportHostAddress (channel->HostAddress ());
	intellon.SetMessageType (VS_NW_INFO | MMTYPE_REQ);
	networks = (struct networks *)(intellon.ExportHeader (message));
	if (channel->SendMessage (message, ETHER_MIN_LEN) <= 0) 
	{
		oerror::error (0, errno, CPLCHANNEL_CANTSEND);
		return;
	}
	if (channel->ReadMessage (message, sizeof (message)) <= 0) 
	{
		oerror::error (0, errno, CPLCHANNEL_CANTREAD);
		return;
	}
	intellon.ImportHeader (message);
	network = (struct network *)(&networks->network);
	while (networks->NUMAVLNS--) 
	{
		CPLStation * bridge = new CPLStation;
		bridge->mstation = network->TEI;
		bridge->mlink = CPLSTATION_BRIDGE;
		bridge->mrole = (network->TEI == network->CCO_TEI);
		bridge->mtxrate = 0;
		bridge->mrxrate = 0;
		intellon.ExportPeerAddress (bridge->mhostaddr);
		intellon.ExportHostAddress (bridge->mnodeaddr);
		CPLNetwork::platform (channel, bridge);
		this->mtable [this->mcount++] = bridge;
		station = (struct station *)(&network->station);
		while (network->NUMSTAS--) 
		{
			if (std::memcmp (station->MAC, oethernet::BroadcastAddress, ETHER_ADDR_LEN)) 
			{
				CPLStation * device = new CPLStation;
				device->mstation = station->TEI;
				device->mlink = CPLSTATION_REMOTE;
				if (!std::memcmp (station->BDA, intellon.PeerAddress (), ETHER_ADDR_LEN)) 
				{
					device->mlink = CPLSTATION_BRIDGE;
					bridge->mlink = CPLSTATION_REMOTE;
				}
				device->mrole = (station->TEI == network->CCO_TEI);
				device->mtxrate = station->AVGTX;
				device->mrxrate = station->AVGRX;
				std::memcpy (device->mnodeaddr, station->MAC, sizeof (device->mnodeaddr));
				std::memcpy (device->mhostaddr, station->BDA, sizeof (device->mhostaddr));
				CPLNetwork::platform (channel, device);
				this->mtable [this->mcount++] = device;
			}
			station++;
		}
		network = (struct network *)(station);
	}
	return;
}

/*====================================================================*
 *
 *   ~CPLNetwork () 
 *
 *   delete table after deleting stations;
 *
 *--------------------------------------------------------------------*/

CPLNetwork::~CPLNetwork () 

{
	while (this->mcount--) 
	{
		delete this->mtable [this->mcount];
	}
	delete [] this->mtable;
	return;
}

/*====================================================================*
 *   end definition;
 *--------------------------------------------------------------------*/

#endif

