/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   CPLChannel.cpp - CPLChannel class definition;
 *
 *   Ethernet I/O channel managment for powerline applications;
 *
 *   Contributor(s):
 *	    Charles Maier <charles.maier@intellon.com>
 *
 *--------------------------------------------------------------------*/

#ifndef CPLCHANNEL_SOURCE
#define CPLCHANNEL_SOURCE

#define SLOTS 6
#define CARRIERS 1155

/*====================================================================*
 *   system header files;
 *--------------------------------------------------------------------*/

#include <unistd.h>
#include <iostream>
#include <cstring>
#include <cstdlib>

/*====================================================================*
 *   system header files;
 *--------------------------------------------------------------------*/

#if defined (__linux__)
#	include <sys/socket.h>
#	include <sys/ioctl.h>
#	include <sys/poll.h>
#	include <linux/if_packet.h>
#	include <net/ethernet.h>
#	include <net/if_arp.h>
#	include <net/if.h>
#elif defined (__APPLE__)
#	include <sys/types.h>
#	include <sys/socket.h>
#	include <sys/ioctl.h>
#	include <netinet/if_ether.h>
#	include <net/if_dl.h>
#	include <net/bpf.h>
#	include <fcntl.h>
#elif defined (__OpenBSD__)
#	include <sys/types.h>
#	include <sys/socket.h>
#	include <sys/ioctl.h>
#	include <net/bpf.h>
#	include <unistd.h>
#	include <fcntl.h>
#elif defined (WINPCAP) 
#elif defined (LIBPCAP)
#else
#error "Unknown Environment"
#endif

/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

#include "../classes/CPLChannel.hpp"
#include "../classes/ohomeplug.hpp"
#include "../classes/ointellon.hpp"
#include "../classes/omemory.hpp"
#include "../classes/oerror.hpp"

/*====================================================================*
 *
 *   signed Descriptor () const;
 *
 *   return the channel socket file descriptor;
 *
 *--------------------------------------------------------------------*/

signed CPLChannel::Descriptor () const 

{
	return (this->mfd);
}

/*====================================================================*
 *
 *   signed Bridges (void * memory, size_t extent);
 *
 *   encode memory with a consecutive list of bridge device hardware
 *   addresses; return the number of addresses encoded; return -1 on
 *   memory overflow;
 *
 *   this is the start point for device discovery; each bridge could
 *   be the gateway to a separate powerline network;
 *
 *--------------------------------------------------------------------*/

signed CPLChannel::Bridges (void * memory, size_t extent) 

{
	ointellon intellon;
	byte * origin = (byte *)(memory);
	byte * offset = (byte *)(memory);
	byte message [ETHER_MAX_LEN];
	std::memset (memory, 0, extent);
	std::memset (message, 0, sizeof (message));
	intellon.ImportHostAddress (this->HostAddress ());
	intellon.ExportHeader (message);
	if (this->SendMessage (message, ETHER_MIN_LEN) > 0) 
	{
		while (this->ReadMessage (message, sizeof (message)) > 0) 
		{
			if (extent < ETHER_ADDR_LEN) 
			{
				oerror::error (0, EOVERFLOW, "Bridge address lost");
				continue;
			}
			intellon.ImportHeader (message);
			if (intellon.IsMessageType (0, VS_SW_VER| MMTYPE_CNF)) 
			{
				intellon.ExportHostAddress (offset);
				offset += ETHER_ADDR_LEN;
				extent -= ETHER_ADDR_LEN;
			}
		}
	}
	return ((signed)(offset - origin) / ETHER_ADDR_LEN);
}

/*====================================================================*
 *
 *   signed Neighbors (void * memory, size_t extent);
 *
 *   return a list powerline network device addresses on a powerline
 *   network; the list consists of a known device plus all others on
 *   the same powerline network; the device is defined by the channel
 *   peer address and appears first in the list;
 *
 *   the device address must be explicit; it cannot be the emptycast,
 *   broadcast or localcast address;
 *
 *   the first (known) device is omitted here as an expriment despite
 *   what was said above; - charlie maier
 *
 *--------------------------------------------------------------------*/

signed CPLChannel::Neighbors (void * memory, size_t extent) 

{
	ointellon intellon;
	byte * origin = (byte *)(memory);
	byte * offset = (byte *)(memory);
	byte message [ETHER_MAX_LEN];

#ifndef __GNUC__
#pragma pack (push,1)
#endif

	struct __packed station 
	{
		uint8_t DA [ETHER_ADDR_LEN];
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
		uint8_t CCO_MACADDR [ETHER_ADDR_LEN];
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

	std::memset (memory, 0, extent);
	if (!std::memcmp (this->PeerAddress (), oethernet::EmptycastAddress, ETHER_ADDR_LEN)) 
	{
		oerror::error (0, ECANCELED, "Emptycast address used to explore network");
		return (0);
	}
	if (!std::memcmp (this->PeerAddress (), oethernet::BroadcastAddress, ETHER_ADDR_LEN)) 
	{
		oerror::error (0, ECANCELED, "Broadcast address used to explore network");
		return (0);
	}
	if (!std::memcmp (this->PeerAddress (), ointellon::LocalcastAddress, ETHER_ADDR_LEN)) 
	{
		oerror::error (0, ECANCELED, "Localcast address used to explore network");
		return (0);
	}
	std::memset (message, 0, sizeof (message));
	intellon.ImportPeerAddress (this->PeerAddress ());
	intellon.ImportHostAddress (this->HostAddress ());
	intellon.SetMessageType (VS_NW_INFO | MMTYPE_REQ);
	networks = (struct networks *)(intellon.ExportHeader (message));
	if (this->SendMessage (message, ETHER_MIN_LEN) <= 0) 
	{
		oerror::error (0, errno, CPLCHANNEL_CANTSEND);
		return (0);
	}
	if (this->ReadMessage (message, sizeof (message)) <= 0) 
	{
		oerror::error (0, errno, CPLCHANNEL_CANTREAD);
		return (0);
	}
	network = (struct network *)(&networks->network);
	while (networks->NUMAVLNS-- > 0) 
	{
		if (extent < ETHER_ADDR_LEN) 
		{
			oerror::error (0, EOVERFLOW, "Bridge address lost");
			return (-1);
		}

#if 0

		intellon.ImportHeader (message);
		intellon.ExportHostAddress (offset);
		offset += ETHER_ADDR_LEN;
		extent -= ETHER_ADDR_LEN;

#endif

		station = (struct station *)(&network->station);
		while (network->NUMSTAS-- > 0) 
		{
			if (extent < ETHER_ADDR_LEN) 
			{
				oerror::error (0, EOVERFLOW, "Device address lost");
				return (-1);
			}
			if (std::memcmp (station->DA, oethernet::BroadcastAddress, ETHER_ADDR_LEN)) 
			{
				std::memcpy (offset, station->DA, sizeof (station->DA));
				offset += ETHER_ADDR_LEN;
				extent -= ETHER_ADDR_LEN;
			}
			station++;
		}
		network = (struct network *)(station);
	}
	return ((signed)(offset - origin) / ETHER_ADDR_LEN);
}

/*====================================================================*
 *
 *   signed SendMessage (void const * message, signed length);
 *
 *--------------------------------------------------------------------*/

signed CPLChannel::SendMessage (void const * memory, signed extent) 

{
	this->dump (memory, extent);

#if defined (__linux__)

	extent = sendto (this->mfd, memory, extent, 0, (struct sockaddr *) (0), (socklen_t) (0));

#elif defined (__APPLE__) || defined (__OpenBSD__)

	extent = write (this->mfd, memory, extent);

#elif defined (WINPCAP) || defined (LIBPCAP)

	if (pcap_sendpacket (this->msocket, (const u_char *)(memory), extent)) 
	{
		extent = -1;
	}

#else
#error "Unknown Environment"
#endif

	return (extent);
}

/*====================================================================*
 *
 *   signed ReadMessage (void * memory, signed extent);
 *
 *   encode external memory with an incoming Ethernet frame; return
 *   frame length on success, 0 on timeout or -1 on error;
 *
 *   on linux/osx, this method returns as soon as a frame arrives or
 *   once the timeout has expired; consequently, long timeout values
 *   do not affect performance;
 *
 *   on winpcap this method does not return until timeout expires;
 *   consequenty, long timeouts affect performance;
 *
 *--------------------------------------------------------------------*/

signed CPLChannel::ReadMessage (void * memory, signed extent) 

{

#if defined (__linux__)

	struct pollfd pollfd = 
	{
		this->mfd,
		POLLIN,
		0
	};
	int status = poll (&pollfd, 1, this->mtimeout);
	std::memset (memory, 0, extent);
	if (status < 0) 
	{
		oerror::error (0, errno, "poll");
		return (-1);
	}
	if (status > 0) 
	{
		extent = recvfrom (this->mfd, memory, extent, 0, (struct sockaddr *) (0), (socklen_t *)(0));
		if (extent == -1) 
		{
			oerror::error (0, errno, "recvfrom");
			return (-1);
		}
		this->dump (memory, extent);
		return (extent);
	}

#elif defined (__APPLE__) || defined (__OpenBSD__)

	byte buffer [this->bpf_length];
	struct bpf_hdr * bpf_hdr = (struct bpf_hdr *)(buffer);
	std::memset (memory, 0, extent);
	std::memset (buffer, 0, sizeof (buffer));
	extent = read (this->mfd, buffer, sizeof (buffer));
	if (extent < 0) 
	{
		oerror::error (0, errno, "bpf");
		return (-1);
	}
	if (extent > 0) 
	{
		extent = bpf_hdr->bh_caplen;
		std::memcpy (memory, buffer + bpf_hdr->bh_hdrlen, bpf_hdr->bh_caplen);
		this->dump (memory, extent);
		return (extent);
	}

#elif defined (WINPCAP) || defined (LIBPCAP)

	struct pcap_pkthdr * header;
	const byte * data;
	signed status = pcap_next_ex (this->msocket, &header, &data);
	std::memset (memory, 0, extent);
	if (status < 0) 
	{
		oerror::error (0, errno, "pcap_next_ex");
		return (-1);
	}
	if (status > 0) 
	{
		extent = header->caplen;
		std::memcpy (memory, data, header->caplen);
		this->dump (memory, extent);
		return (extent);
	}

#else
#error "Unknown Environment"
#endif

	return (0);
}

/*====================================================================*
 *
 *   CPLChannel & dump (void const * memory, signed extent);
 *
 *   print Ethernet frames in hex dump format on stderr when verbose
 *   flag is set; use this for testing and debugging purposes;
 *
 *--------------------------------------------------------------------*/

CPLChannel & CPLChannel::dump (void const * memory, size_t extent) 

{
	if (oflagword::anyset (CPLCHANNEL_FLAG_VERBOSE)) 
	{
		omemory::hexdump (memory, 0, extent, &std::cerr);
		std::cerr << std::endl;
	}
	return (*this);
}

/*====================================================================*
 *
 *   CPLChannel & open ()
 *
 *   open a raw ethernet socket on the designated interface and apply
 *   a packet filter; the filter accepts HomePlug AV frames addressed
 *   to either this host or the ethernet broadcast address; set the
 *   channel host address to the interface hardware address;
 *
 *   if you don't understand this code then you probably have a life;
 *
 *--------------------------------------------------------------------*/

CPLChannel & CPLChannel::open () 

{

#if defined (__linux__)

	struct ifreq ifreq;
	struct sockaddr_ll sockaddr_ll = 
	{
		PF_PACKET,
		0x0000,
		0x0000,
		ARPHRD_ETHER,
		PACKET_OTHERHOST,
		ETHER_ADDR_LEN,
		{
			0x00,
			0x00,
			0x00,
			0x00,
			0x00,
			0x00,
			0x00,
			0x00
		}
	};
	std::memset (&ifreq, 0, sizeof (ifreq));
	oethernet::ExportProtocol (&sockaddr_ll.sll_protocol);
	if ((this->mfd = socket (sockaddr_ll.sll_family, SOCK_RAW, sockaddr_ll.sll_protocol)) == -1) 
	{
		oerror::error (1, errno, "%s", ifreq.ifr_name);
	}
	std::memcpy (ifreq.ifr_name, this->Name (), sizeof (ifreq.ifr_name));
	if (ioctl (this->mfd, SIOCGIFINDEX, &ifreq) == -1) 
	{
		oerror::error (0, errno, "%s", ifreq.ifr_name);
	}
	sockaddr_ll.sll_ifindex = ifreq.ifr_ifindex;
	if (ioctl (this->mfd, SIOCGIFHWADDR, &ifreq) == -1) 
	{
		oerror::error (0, errno, "%s", ifreq.ifr_name);
	}
	std::memcpy (sockaddr_ll.sll_addr, ifreq.ifr_ifru.ifru_hwaddr.sa_data, sizeof (sockaddr_ll.sll_addr));
	if (bind (this->mfd, (struct sockaddr *) (&sockaddr_ll), sizeof (sockaddr_ll)) == -1) 
	{
		oerror::error (0, errno, "%s", ifreq.ifr_name);
	}
	if (ioctl (this->mfd, SIOCGIFFLAGS, &ifreq) == -1) 
	{
		oerror::error (0, errno, "%s", ifreq.ifr_name);
	}
	ifreq.ifr_flags |= (IFF_UP | IFF_BROADCAST | IFF_MULTICAST);
	ifreq.ifr_flags &= ~(IFF_ALLMULTI | IFF_PROMISC);
	if (ioctl (this->mfd, SIOCSIFFLAGS, &ifreq) == -1) 
	{
		oerror::error (0, errno, "%s", ifreq.ifr_name);
	}

#else

	struct bpf_program bpf_program;
	static struct bpf_insn bpf_insn [] = 
	{
		{
			BPF_LD + BPF_H + BPF_ABS,
			0,
			0,
			12
		},
		{
			BPF_JMP + BPF_JEQ + BPF_K,
			0,
			18,
			0
		},
		{
			BPF_LD + BPF_B + BPF_ABS,
			0,
			0,
			0
		},
		{
			BPF_JMP + BPF_JEQ + BPF_K,
			0,
			10,
			0
		},
		{
			BPF_LD + BPF_B + BPF_ABS,
			0,
			0,
			1
		},
		{
			BPF_JMP + BPF_JEQ + BPF_K,
			0,
			8,
			0
		},
		{
			BPF_LD + BPF_B + BPF_ABS,
			0,
			0,
			2
		},
		{
			BPF_JMP + BPF_JEQ + BPF_K,
			0,
			6,
			0
		},
		{
			BPF_LD + BPF_B + BPF_ABS,
			0,
			0,
			3
		},
		{
			BPF_JMP + BPF_JEQ + BPF_K,
			0,
			4,
			0
		},
		{
			BPF_LD + BPF_B + BPF_ABS,
			0,
			0,
			4
		},
		{
			BPF_JMP + BPF_JEQ + BPF_K,
			0,
			2,
			0
		},
		{
			BPF_LD + BPF_B + BPF_ABS,
			0,
			0,
			5
		},
		{
			BPF_JMP + BPF_JEQ + BPF_K,
			4,
			0,
			0
		},
		{
			BPF_LD + BPF_W + BPF_ABS,
			0,
			0,
			0
		},
		{
			BPF_JMP + BPF_JEQ + BPF_K,
			0,
			4,
			0xFFFFFFFF
		},
		{
			BPF_LD + BPF_H + BPF_ABS,
			0,
			0,
			4
		},
		{
			BPF_JMP + BPF_JEQ + BPF_K,
			0,
			2,
			0xFFFF
		},
		{
			BPF_LD + BPF_W + BPF_LEN,
			0,
			0,
			0
		},
		{
			BPF_RET + BPF_A,
			0,
			0,
			0
		},
		{
			BPF_RET + BPF_K,
			0,
			0,
			0
		}
	};

#if defined (__APPLE__) || defined (__OpenBSD__)

	struct ifreq ifreq;
	struct timeval timer = 
	{
		0,
		0
	};
	const byte * hwaddr = this->HardwareAddress ();
	char filename [FILENAME_MAX];
	unsigned count;
	unsigned state;
	for (count = 0; count < 100; count++) 
	{
		std::snprintf (filename, sizeof (filename), CPLCHANNEL_BPFDEVICE, count);
		if ((this->mfd =::open (filename, O_RDWR)) != -1) 
		{
			break;
		}
	}
	if (this->mfd == -1) 
	{
		oerror::error (1, ECANCELED, "No bpf devices available");
	}
	std::memcpy (ifreq.ifr_name, ointerface::Name (), sizeof (ifreq.ifr_name));
	if (ioctl (this->mfd, BIOCSETIF, &ifreq) == -1) 
	{
		oerror::error (0, errno, "1 %s", ifreq.ifr_name);
		return (*this);
	}
	if (ioctl (this->mfd, BIOCGBLEN, &this->bpf_length) == -1) 
	{
		oerror::error (0, errno, "Can't determine buffer length");
	}
	state = true;
	if (ioctl (this->mfd, BIOCIMMEDIATE, &state) == -1) 
	{
		oerror::error (0, errno, "Can't activate immediate mode");
	}

#if defined (__APPLE__)

	state = false;
	if (ioctl (this->mfd, BIOCSSEESENT, &state) == -1) 
	{
		oerror::error (0, errno, "Can't hide outgoing frames");
	}

#elif defined (__OpenBSD__)

	state = BPF_DIRECTION_OUT;
	if (ioctl (this->mfd, BIOCSDIRFILT, &state) == -1) 
	{
		oerror::error (0, errno, "Can't hide outgoing frames");
	}

#else
#error "Abandon all hope"
#endif

#if defined (__MAC_10_6)

/*
 *	accommodate know bug in BPF on MAC OS X 10.6; shorter times may cause socket
 *	read operations to block indefinitely when no frames are available;
 */

	timer.tv_sec = 1;

#else

	timer.tv_usec = this->mtimeout * 1000;

#endif

	if (ioctl (this->mfd, BIOCSRTIMEOUT, &timer) == -1) 
	{
		oerror::error (0, errno, "Can't set timeout");
	}
	bpf_program.bf_len = sizeof (bpf_insn)/sizeof (struct bpf_insn);
	bpf_program.bf_insns = bpf_insn;
	bpf_insn [1].k = oethernet::Protocol ();
	bpf_insn [3].k = hwaddr [0];
	bpf_insn [5].k = hwaddr [1];
	bpf_insn [7].k = hwaddr [2];
	bpf_insn [9].k = hwaddr [3];
	bpf_insn [11].k = hwaddr [4];
	bpf_insn [13].k = hwaddr [5];
	if (ioctl (this->mfd, BIOCSETF, &bpf_program) == -1) 
	{
		oerror::error (0, errno, "Can't use filter");
	}

#elif defined (WINPCAP) || defined (LIBPCAP)

	const byte * hostaddr = this->HardwareAddress ();
	this->msocket = pcap_open_live (this->Name (), 65536, 0, this->mtimeout, this->merrbuf);
	if (!this->msocket) 
	{
		oerror::error (1, errno, "No such adapter: %s", ointerface::Name ());
	}
	bpf_program.bf_len = sizeof (bpf_insn)/sizeof (struct bpf_insn);
	bpf_program.bf_insns = bpf_insn;
	bpf_insn [1].k = oethernet::Protocol ();
	bpf_insn [3].k = hostaddr [0];
	bpf_insn [5].k = hostaddr [1];
	bpf_insn [7].k = hostaddr [2];
	bpf_insn [9].k = hostaddr [3];
	bpf_insn [11].k = hostaddr [4];
	bpf_insn [13].k = hostaddr [5];
	if (pcap_setfilter (this->msocket, &bpf_program) < 0) 
	{
		oerror::error (0, errno, "Can't use filter: %s", ointerface::Name ());
	}
	if (pcap_setmintocopy (this->msocket, ETHER_MIN_LEN)) 
	{
		oerror::error (0, errno, "Can't open socket: %s", ointerface::Name ());
	}

#else
#error "Unknown Environment"
#endif
#endif

	oethernet::ImportHostAddress (this->HardwareAddress ());
	return (*this);
}

/*====================================================================*
 *
 *   CPLChannel & link ()
 *
 *   find any available powerline bridge and set the channel peer
 *   address; read all responses because this is a local broadcast;
 *   the last response read will be the lucky device;
 *
 *--------------------------------------------------------------------*/

CPLChannel & CPLChannel::link () 

{
	ointellon intellon;
	byte message [ETHER_MAX_LEN];
	std::memset (message, 0, sizeof (message));
	intellon.ImportHostAddress (this->HostAddress ());
	intellon.ExportHeader (message);
	if (this->SendMessage (message, ETHER_MIN_LEN) > 0) 
	{
		while (this->ReadMessage (message, sizeof (message)) > 0) 
		{
			intellon.ImportHeader (message);
			if (intellon.IsMessageType (0, VS_SW_VER|MMTYPE_CNF)) 
			{
				this->ImportPeerAddress (intellon.HostAddress ());
			}
		}
	}
	return (*this);
}

/*====================================================================*
 *
 *   CPLChannel & init ()
 *
 *   initialize class members; set the channel Ethernet header to
 *   the default Intellon header;
 *
 *--------------------------------------------------------------------*/

CPLChannel & CPLChannel::init () 

{
	ointellon intellon;
	this->mfd = -1;
	this->mtimeout = CPLCHANNEL_TIMEOUT;
	this->ImportPeerAddress (intellon.PeerAddress ());
	this->ImportHostAddress (intellon.HostAddress ());
	this->SetProtocol (intellon.Protocol ());
	return (*this);
}

/*====================================================================*
 *
 *   CPLChannel (unsigned ifindex)
 *
 *--------------------------------------------------------------------*/

CPLChannel::CPLChannel (unsigned ifindex): ointerface (ifindex) 

{
	this->init ();
	this->open ();
	this->link ();
	return;
}

/*====================================================================*
 *
 *   CPLChannel (char const * ifname)
 *
 *--------------------------------------------------------------------*/

CPLChannel::CPLChannel (char const * ifname): ointerface (ifname) 

{
	this->init ();
	this->open ();
	this->link ();
	return;
}

/*====================================================================*
 *
 *   ~CPLChannel ()
 *
 *   free sockets and descriptors;
 *
 *--------------------------------------------------------------------*/

CPLChannel::~CPLChannel () 

{

#if defined (__linux__)

	::close (this->mfd);

#elif defined (__APPLE__) || defined (__OpenBSD__)

	::close (this->mfd);

#elif defined (WINPCAP) || defined (LIBPCAP)

	pcap_close (this->msocket);

#else
#error "Unknown Environment"
#endif

	return;
}

/*====================================================================*
 *   end definition;
 *--------------------------------------------------------------------*/

#endif

