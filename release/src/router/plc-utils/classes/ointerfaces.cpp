/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   ointerfaces.cpp - ointerfaces class definition;
 *
 *   host interface enumerator;  
 *
 *   Contributor(s): 
 *	    Charles Maier <charles.maier@intellon.com>
 *
 *--------------------------------------------------------------------*/

#ifndef oINTERFACES_SOURCE
#define oINTERFACES_SOURCE

/*====================================================================*
 *   system header files;
 *--------------------------------------------------------------------*/

#include <iostream>

/*====================================================================*
 *   system header files;
 *--------------------------------------------------------------------*/

#if defined (__linux__)
#	include <sys/socket.h>
#	include <net/if.h>
#elif defined (__APPLE__)
#	include <sys/types.h>
#	include <sys/socket.h>
#	include <net/if.h>
#elif defined (__OpenBSD__)
#	include <sys/types.h>
#	include <sys/socket.h>
#	include <net/if.h>
#elif defined (WINPCAP)
#	include <pcap.h>
#endif

/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

#include "../classes/ointerfaces.hpp"

/*====================================================================*
 *
 *   bool Empty (void) const;
 *
 *   return true if there are no interfaces;
 *
 *--------------------------------------------------------------------*/

bool ointerfaces::Empty (void) const 

{
	return (!this->mcount);
}

/*====================================================================*
 *
 *   bool End (void) const;
 *
 *   return true if the last interface has been reached;
 *
 *--------------------------------------------------------------------*/

bool ointerfaces::End (void) const 

{
	return (this->mindex >= this->mcount);
}

/*====================================================================*
 *
 *   unsigned Count (void) const;
 *
 *   return the number of interfaces;
 *
 *--------------------------------------------------------------------*/

unsigned ointerfaces::Count (void) const 

{
	return (this->mcount);
}

/*====================================================================*
 *
 *   unsigned Index (void) const;
 *
 *   return the current interface index;
 *
 *--------------------------------------------------------------------*/

unsigned ointerfaces::Index (void) const 

{
	return (this->mindex);
}

/*====================================================================*
 *
 *   ointerfaces & SelectFirst (void);
 *
 *   select first interfac;
 *
 *--------------------------------------------------------------------*/

ointerfaces & ointerfaces::SelectFirst (void) 

{
	this->mindex = 0;
	return (*this);
}

/*====================================================================*
 *
 *   ointerfaces & SelectFinal (void);
 *
 *   select final interface;
 *
 *--------------------------------------------------------------------*/

ointerfaces & ointerfaces::SelectFinal (void) 

{
	this->mindex = this->mcount - 1;
	return (*this);
}

/*====================================================================*
 *
 *   ointerfaces & SelectPrev (void) 
 *
 *   select the prev interface unless the current interface is the
 *   first interface; same as operator --;
 *
 *--------------------------------------------------------------------*/

ointerfaces & ointerfaces::SelectPrev (void) 

{
	if (this->mindex > 0) 
	{
		this->mindex--;
	}
	return (*this);
}

/*====================================================================*
 *
 *   ointerfaces & SelectNext (void) 
 *
 *   select the next interface unless the current interface is the
 *   final interface; same as operator ++; 
 *
 *--------------------------------------------------------------------*/

ointerfaces & ointerfaces::SelectNext (void) 

{
	if (this->mindex < this->mcount) 
	{
		this->mindex++;
	}
	return (*this);
}

/*====================================================================*
 *
 *   ointerfaces & Select (unsigned index);
 *
 *   select an interface by number; same as operator [];
 *
 *--------------------------------------------------------------------*/

ointerfaces & ointerfaces::Select (unsigned index) 

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
 *   ointerface & operator = (unsigned index) 
 *
 *   select an interface; this has the same effect as calling the
 *   (   select method with argument index.
 *
 *--------------------------------------------------------------------*/

ointerfaces & ointerfaces::operator = (unsigned index) 

{
	return (this->Select (index));
}

/*====================================================================*
 *
 *   ointerface & operator [] (unsigned index) 
 *
 *   select an interface then return an instance of it; this has the
 *   same effect as calling the select method with argument index then
 *   reading the Selected or Interface property;
 *
 *--------------------------------------------------------------------*/

ointerface & ointerfaces::operator [] (unsigned index) 

{
	return (this->Select (index).Selected ());
}

/*====================================================================*
 *
 *   ointerface & Selected (void) const
 *
 *   return the selected interface; this is the same as the Interface
 *   property; 
 *
 *--------------------------------------------------------------------*/

ointerface & ointerfaces::Selected (void) const 

{
	return (* this->mtable [this->mindex]);
}

/*====================================================================*
 *
 *   ointerface & Interface (void) const
 *
 *   return the selected interface; this is the same as the Selected
 *   property; 
 *
 *--------------------------------------------------------------------*/

ointerface & ointerfaces::Interface (void) const 

{
	return (* this->mtable [this->mindex]);
}

/*====================================================================*
 *
 *   ointerfaces & Enumerate (void);
 *
 *   interate through interfaces and print them on stdout; do not
 *   change the selected interface;
 *
 *--------------------------------------------------------------------*/

ointerfaces & ointerfaces::Enumerate (void) 

{
	for (unsigned index = 0; index < this->mcount; index++) 
	{
		ointerface * ifp = this->mtable [index];
		if (!ifp->Disabled ())
		{
			ifp->Print ();
		}
	}
	return (*this);
}

/*====================================================================*
 *
 *   ointerfaces () 
 *
 *   detect host interfaces and constuct a collection of ointerface
 *   objects; omit devices with hardware address 00:00:00:00:00:00;
 *
 *   WinPcap provides a true device description; Linux, MacOSX and
 *   OpenBSD do not so we substiture the device name;
 *
 *--------------------------------------------------------------------*/

ointerfaces::ointerfaces () 

{

#if defined (WINPCAP) 

	char buffer [PCAP_ERRBUF_SIZE];
	pcap_if_t * devices = (pcap_if_t *)(0);
	pcap_if_t * device;
	this->mindex = 0;
	this->mcount = 0;
	if (pcap_findalldevs (&devices, buffer) != -1) 
	{
		for (device = devices; device; device = device->next) 
		{
			this->mcount++;
		}
		this->mtable = new ointerface * [this->mcount];
		for (device = devices; device; device = device->next) 
		{
			ointerface * ifo = new ointerface (device->name);
			ifo->Description (device->description);
			this->mtable [this->mindex++] = ifo;
		}
		pcap_freealldevs (devices);
	}

#else

	struct if_nameindex * ifs = if_nameindex ();
	struct if_nameindex * ifp;
	this->mindex = 0;
	this->mcount = 0;
	for (ifp = ifs; ifp->if_index; ++ifp) 
	{
		this->mcount++;
	}
	this->mtable = new ointerface * [this->mcount];
	for (ifp = ifs; ifp->if_index; ++ifp) 
	{
		ointerface * ifo = new ointerface (ifp->if_name);
		ifo->Description (ifp->if_name);
		this->mtable [this->mindex++] = ifo;
	}
	if_freenameindex (ifs);

#endif

	if (!this->mcount) 
	{
		this->mtable = new ointerface * [1];
	}
	this->mindex = 0;
	return;
}

/*====================================================================*
 *
 *   ~ointerfaces () 
 *
 *   delete the table after deleting all entries;
 *
 *--------------------------------------------------------------------*/

ointerfaces::~ointerfaces () 

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

