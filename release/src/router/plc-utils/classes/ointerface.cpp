/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   ointerface.cpp - ointerface class definition;
 *
 *   host interface information;
 *
 *   Contributor(s): 
 *	    Charles Maier <charles.maier@intellon.com>
 *
 *--------------------------------------------------------------------*/

#ifndef oINTERFACE_SOURCE
#define oINTERFACE_SOURCE

/*====================================================================*
 *   system header files;
 *--------------------------------------------------------------------*/

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cerrno>

/*====================================================================*
 *   system header files (environment dependent);
 *--------------------------------------------------------------------*/

#if defined (__linux__)
#	include <ifaddrs.h>
#	include <sys/ioctl.h>
#	include <sys/socket.h>
#	include <netinet/in.h>
#	include <linux/if_packet.h>
#elif defined (__APPLE__)
#	include <sys/types.h>
#	include <ifaddrs.h>
#	include <net/if_dl.h>
#	include <net/if_types.h>
#	include <fcntl.h>
#	include <sys/ioctl.h>
#	include <net/bpf.h>
#elif defined (__OpenBSD__)
#	include <ifaddrs.h>
#	include <net/if_dl.h>
#	include <net/if_types.h>
#elif defined (WINPCAP)
#	include <pcap.h>
#	include <Packet32.h>
#	include <ntddndis.h>
#else
#error "Unknown environment."
#endif

/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

#include "../classes/ointerface.hpp"
#include "../classes/omemory.hpp"
#include "../classes/oerror.hpp"

/*====================================================================*
 *
 *   unsigned Index (void) const;
 *
 *   return the index of the selected interface; on some systems, the
 *   index is sequential; on others, it is not;
 *
 *--------------------------------------------------------------------*/

unsigned ointerface::Index (void) const 

{
	return (this->mifindex);
}

/*====================================================================*
 *
 *   char const * Name (void) const;
 *
 *   return the NUL terminated interface name string;
 *
 *--------------------------------------------------------------------*/

char const * ointerface::Name (void) const 

{
	return (this->mifname);
}

/*====================================================================*
 *
 *   char const * Description (void) const;
 *
 *   return the NUL terminated interface text string; on some systems
 *   this may be identical to the name string; on other it may not be;
 *
 *--------------------------------------------------------------------*/

char const * ointerface::Description (void) const 

{
	return (this->miftext);
}

/*====================================================================*
 *
 *   byte const * HardwareAddress (void) const;
 *
 *   return the NUL terminated internet address string; the string is
 *   a sequence of hex octets seperated by colons;
 *
 *--------------------------------------------------------------------*/

byte const * ointerface::HardwareAddress (void) const 

{
	return (this->mhwaddr);
}

/*====================================================================*
 *
 *   byte const * InternetAddress (void) const;
 *
 *   return the NUL terminated hardware address string; the string is
 *   a sequence of decimal octets seperated by periods;
 *
 *--------------------------------------------------------------------*/

byte const * ointerface::InternetAddress (void) const 

{
	return (this->mipaddr);
}

/*====================================================================*
 *
 *   char const * HardwareAddressString (void) const;
 *
 *   return the NUL terminated internet address string; the string is
 *   a sequence of hex octets seperated by colons;
 *
 *--------------------------------------------------------------------*/

char const * ointerface::HardwareAddressString (void) const 

{
	return (this->mhwstring);
}

/*====================================================================*
 *
 *   char const * InternetAddressString (void) const;
 *
 *   return the NUL terminated hardware address string; the string is
 *   a sequence of decimal octets seperated by periods;
 *
 *--------------------------------------------------------------------*/

char const * ointerface::InternetAddressString (void) const 

{
	return (this->mipstring);
}

/*====================================================================*
 *
 *   ointerface & ExportHardwareAddress (void * memory);
 *
 *   copy the stored hardware address to external memory; this is a
 *   binary copy operation; return the object instance reference;
 *
 *--------------------------------------------------------------------*/

ointerface & ointerface::ExportHardwareAddress (void * memory) 

{
	std::memcpy (memory, this->mhwaddr, sizeof (this->mhwaddr));
	return (*this);
}

/*====================================================================*
 *
 *   ointerface & ExportInternetAddress (void * memory);
 *
 *   copy the stored internet address to external memory; this is a 
 *   binary copy operation; return the object instance reference;
 *
 *--------------------------------------------------------------------*/

ointerface & ointerface::ExportInternetAddress (void * memory) 

{
	std::memcpy (memory, this->mipaddr, sizeof (this->mipaddr));
	return (*this);
}

/*====================================================================*
 *
 *   ointerface & ointerface::Description (char const * string);
 *
 *   replace interface text string and return the object instance
 *   reference; this string may change whenever the index or name
 *   are changed but changing the text string does not affect the 
 *   other properties;
 *
 *--------------------------------------------------------------------*/

ointerface & ointerface::Description (char const * string) 

{
	omemory::memtext (string, this->miftext, sizeof (this->miftext));
	return (*this);
}

/*====================================================================*
 *
 *   ointerface & Print ();
 *
 *   print interface index, hardware address, internet address, name
 *   and text on stdout; return the object instance reference;
 *
 *--------------------------------------------------------------------*/

ointerface & ointerface::Print () 

{
	std::cout << this->Index () << " ";
	std::cout << this->HardwareAddressString () << " ";
	std::cout << this->InternetAddressString () << " ";
	std::cout << this->Name () << " ";
	std::cout << this->Description () << std::endl;
	return (*this);
}

/*====================================================================*
 *
 *   bool Disabled () const;
 *
 *   return true if the hardware address is all zeros or all ones;
 *
 *--------------------------------------------------------------------*/

bool ointerface::Disabled () const 

{
	byte sample [ETHER_ADDR_LEN];
	std::memset (sample, 0x00, sizeof (sample));
	if (!std::memcmp (sample, this->mhwaddr, sizeof (sample))) 
	{
		return (true);
	}
	std::memset (sample, 0xFF, sizeof (sample));
	if (!std::memcmp (sample, this->mhwaddr, sizeof (sample))) 
	{
		return (true);
	}
	return (false);
}

/*====================================================================*
 *
 *   ointerface & ointerface::lookup ();
 *
 *   lookup hardware and internet addresses once the interface index 
 *   and name are known; 
 *
 *   two methods are provided for Linux; the first one encountered by
 *   the compiler will be used; some Linux systems may not support the
 *   getifaddrs function or may not implement it consistently; 
 *
 *--------------------------------------------------------------------*/

ointerface & ointerface::lookup () 

{

#if defined (__linux__) && 0

/*
 *	The preferred method for Linux at this time;
 */

	int fd;
	if ((fd = std::socket (AF_INET, SOCK_DGRAM, 0)) != -1) 
	{
		struct ifreq ifreq;
		std::memcpy (ifreq.ifr_name, this->mifname, sizeof (ifreq.ifr_name));
		if (ioctl (fd, SIOCGIFHWADDR, &ifreq) != -1) 
		{
			std::memcpy (this->mhwaddr, ifreq.ifr_ifru.ifru_hwaddr.sa_data, sizeof (this->mhwaddr));
		}
		if (ioctl (fd, SIOCGIFADDR, &ifreq) != -1) 
		{
			struct sockaddr_in * sockaddr_in = (struct sockaddr_in *)(&ifreq.ifr_ifru.ifru_addr);
			std::memcpy (this->mipaddr, &sockaddr_in->sin_addr.s_addr, sizeof (this->mipaddr));
		}
		std::close (fd);
	}

#elif defined (__linux__) || defined (__APPLE__) || defined (__OpenBSD__) 

	struct ifaddrs * ifaddrs;
	if (getifaddrs (&ifaddrs) != -1) 
	{
		struct ifaddrs * ifaddr;
		for (ifaddr = ifaddrs; ifaddr; ifaddr = ifaddr->ifa_next) 
		{
			if (std::strcmp (this->mifname, ifaddr->ifa_name)) 
			{
				continue;
			}
			if (!ifaddr->ifa_addr) 
			{
				continue;
			}
			if (ifaddr->ifa_addr->sa_family == AF_INET) 
			{
				struct sockaddr_in * sockaddr_in = (struct sockaddr_in *) (ifaddr->ifa_addr);
				struct in_addr * in_addr = (struct in_addr *)(&sockaddr_in->sin_addr);
				std::memcpy (this->mipaddr, &in_addr->s_addr, sizeof (this->mipaddr));
			}

#if defined (__linux__)

			if (ifaddr->ifa_addr->sa_family == AF_PACKET) 
			{
				struct sockaddr_ll * sockaddr_ll = (struct sockaddr_ll *) (ifaddr->ifa_addr);
				std::memcpy (this->mhwaddr, sockaddr_ll->sll_addr, sizeof (this->mhwaddr));
			}

#elif defined (__APPLE__) || defined (__OpenBSD__)

			if (ifaddr->ifa_addr->sa_family == AF_LINK) 
			{
				struct sockaddr_dl * sockaddr_dl = (struct sockaddr_dl *) (ifaddr->ifa_addr);
				if (sockaddr_dl->sdl_type == IFT_ETHER) 
				{
					std::memcpy (this->mhwaddr, LLADDR (sockaddr_dl), sizeof (this->mhwaddr));
				}
			}

#else
#error "Abandon all hope!"
#endif

		}
		freeifaddrs (ifaddrs);
	}

#elif defined (WINPCAP) 

	ointerface::pcap_gethwaddr ();
	ointerface::pcap_getipaddr ();

#else
#error "Unknown environment."
#endif

	omemory::hexdecode (this->mhwaddr, sizeof (this->mhwaddr), this->mhwstring, sizeof (this->mhwstring));
	omemory::decdecode (this->mipaddr, sizeof (this->mipaddr), this->mipstring, sizeof (this->mipstring));
	return (* this);
}

/*====================================================================*
 *   
 *   unsigned pcap_nametoindex (char const * name) const;
 *
 *   WinPcap version of POSIX if_nametoindex function; return error
 *   in non-pcap environments; this method is a temporary solution;
 *
 *   Microsoft plans to support the if_nametoindex function on Vista 
 *   and future releases;
 *
 *   see The Open Group Base Specifications Issue 6 IEEE Std 1003.1, 
 *   2004 Edition for a description of this method;
 *
 *--------------------------------------------------------------------*/

unsigned ointerface::pcap_nametoindex (char const * name) const 

{

#if defined (WINPCAP)

	char buffer [PCAP_ERRBUF_SIZE];
	pcap_if_t * devices = (pcap_if_t *)(0);
	pcap_if_t * device;
	if (pcap_findalldevs (&devices, buffer) != -1) 
	{
		unsigned index = 1;
		for (device = devices; device; device = device->next) 
		{
			if (std::strcmp (name, device->name)) 
			{
				index++;
				continue;
			}
			pcap_freealldevs (devices);
			return (index);
		}
		pcap_freealldevs (devices);
	}

#endif

	errno = ENXIO;
	return (0);
}

/*====================================================================*
 *
 *   char * pcap_indextoname (unsigned ifindex, char * ifname) const;
 *
 *   WinPcap version of POSIX if_indextoname function; return error 
 *   in non-pcap enviroements; this method is a temporary solution;
 *
 *   Microsoft plans to support the if_indextoname function on Vista 
 *   and future releases;
 *
 *   see The Open Group Base Specifications Issue 6 IEEE Std 1003.1, 
 *   2004 Edition for a description of this method;
 *
 *--------------------------------------------------------------------*/

char * ointerface::pcap_indextoname (unsigned ifindex, char * ifname) const 

{

#if defined (WINPCAP)

	char buffer [PCAP_ERRBUF_SIZE];
	pcap_if_t * devices = (pcap_if_t *)(0);
	pcap_if_t * device;
	if ((ifindex--) && (pcap_findalldevs (&devices, buffer) != -1)) 
	{
		for (device = devices; device; device = device->next) 
		{
			if (!ifindex--) 
			{
				omemory::memtext (device->name, ifname, IF_NAMESIZE);
				pcap_freealldevs (devices);
				return (ifname);
			}
		}
		pcap_freealldevs (devices);
	}

#endif

	errno = ENXIO;
	return ((char *)(0));
}

/*====================================================================*
 *
 *   void pcap_gethwaddr ();
 *
 *   update the hardware address based on interface name in winpcap
 *   environment only; it has no effect in non-pcap environments;
 *
 *   this method is a temporary solution that may become permanent
 *   since there is no POSIX function defined for this;
 *
 *--------------------------------------------------------------------*/

void ointerface::pcap_gethwaddr () 

{

#if defined (WINPCAP)

	LPADAPTER adapter = PacketOpenAdapter ((PCHAR)(this->mifname));
	PPACKET_OID_DATA data = (PPACKET_OID_DATA)(std::malloc (ETHER_ADDR_LEN + sizeof (PACKET_OID_DATA)));
	if (!data) 
	{
		oerror::error (1, 0, "Can't allocate packet: %s", this->mifname);
	}
	data->Oid = OID_802_3_CURRENT_ADDRESS;
	data->Length = ETHER_ADDR_LEN;
	if ((!adapter) || (adapter->hFile == INVALID_HANDLE_VALUE)) 
	{
		oerror::error (1, 0, "Can't access interface: %s", this->mifname);
	}
	std::memset (this->mhwaddr, 0, ETHER_ADDR_LEN);
	if (PacketRequest (adapter, FALSE, data)) 
	{
		std::memcpy (this->mhwaddr, data->Data, data->Length);
	}
	PacketCloseAdapter (adapter);
	std::free (data);

#endif

	return;
}

/*====================================================================*
 *
 *   void pcap_getipaddr ();
 *
 *   update the internet address based on interface name in winpcap
 *   environment only; it has no effect in non-pcap environments;
 *
 *--------------------------------------------------------------------*/

void ointerface::pcap_getipaddr () 

{

#if defined (WINPCAP)

	char buffer [PCAP_ERRBUF_SIZE];
	pcap_if_t * devices = (pcap_if_t *)(0);
	pcap_if_t * device;
	if (pcap_findalldevs (&devices, buffer) == -1) 
	{
		oerror::error (1, errno, "Can't enumerate interfaces");
	}
	for (device = devices; device; device = device->next) 
	{
		if (std::strcmp (this->mifname, device->name)) 
		{
			continue;
		}
		std::memcpy (this->miftext, device->description, std::strlen (device->description));
		if (device->addresses) 
		{
			struct pcap_addr * pcap_addr = device->addresses;
			struct sockaddr_in * sockaddr_in = (struct sockaddr_in *)(pcap_addr->addr);
			struct in_addr * in_addr = (struct in_addr *)(&sockaddr_in->sin_addr);
			std::memcpy (this->mipaddr, &in_addr->s_addr, sizeof (this->mipaddr));
		}
		break;
	}
	pcap_freealldevs (devices);

#endif

	return;
}

/*====================================================================*
 *
 *   ointerface (unsigned ifindex) 
 *
 *   instantiate this instance with a given ifindex;
 *
 *--------------------------------------------------------------------*/

ointerface::ointerface (unsigned ifindex) 

{
	this->mifindex = ifindex;
	std::memset (this->mhwaddr, 0, sizeof (this->mhwaddr));
	std::memset (this->mipaddr, 0, sizeof (this->mipaddr));
	omemory::hexdecode (this->mhwaddr, sizeof (this->mhwaddr), this->mhwstring, sizeof (this->mhwstring));
	omemory::decdecode (this->mipaddr, sizeof (this->mipaddr), this->mipstring, sizeof (this->mipstring));
	omemory::memtext ("none", this->mifname, sizeof (this->mifname));
	omemory::memtext ("none", this->miftext, sizeof (this->miftext));

#if defined (WINPCAP)

	if (!ointerface::pcap_indextoname (this->mifindex, this->mifname)) 

#else

	if (!if_indextoname (this->mifindex, this->mifname)) 

#endif

	{
		oerror::error (1, errno, "%d", this->mifindex);
	}
	omemory::memtext (this->mifname, this->miftext, sizeof (this->miftext));
	ointerface::lookup ();
	return;
}

/*====================================================================*
 *
 *   ointerface (char const * ifname) 
 *
 *   instantiate this instance with a given ifname;
 *
 *--------------------------------------------------------------------*/

ointerface::ointerface (char const * ifname) 

{
	std::memset (this->mhwaddr, 0, sizeof (this->mhwaddr));
	std::memset (this->mipaddr, 0, sizeof (this->mipaddr));
	omemory::hexdecode (this->mhwaddr, sizeof (this->mhwaddr), this->mhwstring, sizeof (this->mhwstring));
	omemory::decdecode (this->mipaddr, sizeof (this->mipaddr), this->mipstring, sizeof (this->mipstring));
	omemory::memtext ("none", this->mifname, sizeof (this->mifname));
	omemory::memtext ("none", this->miftext, sizeof (this->miftext));

#if defined (WINPCAP)

	this->mifindex = ointerface::pcap_nametoindex (ifname);

#else

	this->mifindex = if_nametoindex (ifname);

#endif

	if (this->mifindex) 
	{
		omemory::memtext (ifname, this->mifname, sizeof (this->mifname));
		omemory::memtext (ifname, this->miftext, sizeof (this->miftext));
		ointerface::lookup ();
	}
	return;
}

/*====================================================================*
 *
 *   ~ointerface () 
 *
 *--------------------------------------------------------------------*/

ointerface::~ointerface () 

{
	return;
}

/*====================================================================*
 *   end definition;
 *--------------------------------------------------------------------*/

#endif

