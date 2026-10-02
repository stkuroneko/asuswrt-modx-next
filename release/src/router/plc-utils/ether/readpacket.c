/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   ssize_t readpacket (struct channel const * channel, void * memory, ssize_t extent);
 *
 *   channel.h
 *
 *   read one packet from a raw packet channel; 
 *
 *   return the packet size on success, 0 on timeout or -1 on error; 
 *   dump packets on stdout when the channel VERBOSE flag is set; 
 *
 *   constant __MAGIC__ enables code that reads frames from stdin,
 *   instead of the network; you may use it whenever a network or
 *   transmitting device is not available; 
 *   
 *
 *   Contributor(s):
 *	Charles Maier <cmaier@qca.qualcomm.com>
 *	Nathaniel Houghton <nhoughto@qca.qualcomm.com>
 *	Werner Henze <w.henze@avm.de>
 *
 *--------------------------------------------------------------------*/

#ifndef READPACKET_SOURCE
#define READPACKET_SOURCE

#include <stdlib.h>
#include <unistd.h>
#include <memory.h>
#include <errno.h>

#include "../ether/channel.h"
#include "../tools/memory.h"
#include "../tools/error.h" 
#include "../tools/flags.h"

#if defined (__MAGIC__)
#include "../tools/hexload.c"
#endif

ssize_t readpacket (struct channel const * channel, void * memory, ssize_t extent) 

{ 

#if defined (__MAGIC__)

	memset (memory, 0, extent); 
	extent = hexload (memory, extent, stdin); 
	if (_anyset (channel->flags, CHANNEL_VERBOSE)) 
	{ 
		hexdump (memory, 0, extent, stdout); 
	} 
	return (extent); 

#elif defined (__linux__) 

#include <sys/poll.h>

	struct pollfd pollfd = 
	{ 
		channel->fd, 
		POLLIN, 
		0
	}; 
	signed status = poll (& pollfd, 1, channel->capture); 
	memset (memory, 0, extent); 
	if ((status < 0) && (errno != EINTR)) 
	{ 
		error (0, errno, "%s can't poll %s", __func__, channel->ifname); 
		return (- 1); 
	} 
	if (status > 0) 
	{ 
		status = recvfrom (channel->fd, memory, extent, 0, (struct sockaddr *) (0), (socklen_t *) (0)); 
		if (status < 0) 
		{ 
			error (0, errno, "%s can't read %s", __func__, channel->ifname); 
			return (- 1); 
		} 
		if (status > 0) 
		{ 
			extent = status; 
			if (_anyset (channel->flags, CHANNEL_VERBOSE)) 
			{ 
				hexdump (memory, 0, extent, stdout); 
			} 
			return (extent); 
		} 
	} 
#ifdef RTCONFIG_QCA_PLC2	/* ASUS */
    if (channel->bfd >= 0) {
	struct pollfd pollfd = 
	{ 
		channel->bfd, 
		POLLIN, 
		0
	}; 
	status = poll (& pollfd, 1, channel->capture); 
	memset (memory, 0, extent); 
	if ((status < 0) && (errno != EINTR)) 
	{ 
		error (0, errno, "%s can't poll %s", __func__, channel->brname); 
		return (- 1); 
	} 
	if (status > 0) 
	{ 
		status = recvfrom (channel->bfd, memory, extent, 0, (struct sockaddr *) (0), (socklen_t *) (0)); 
		if (status < 0) 
		{ 
			error (0, errno, "%s can't read %s", __func__, channel->brname); 
			return (- 1); 
		} 
		if (status > 0) 
		{ 
			extent = status; 
			if (_anyset (channel->flags, CHANNEL_VERBOSE)) 
			{ 
				hexdump (memory, 0, extent, stdout); 
			} 
			return (extent); 
		} 
	} 
    }
#endif	/* RTCONFIG_QCA_PLC2 ASUS */
#elif defined (__APPLE__) || defined (__OpenBSD__)

	struct bpf_hdr * bpf_packet; 
	struct bpf * bpf = channel->bpf; ; 
	memset (memory, 0, extent); 
	if (bpf->bpf_bufused <= 0) 
	{ 
		bpf->bpf_bufused = read (channel->fd, bpf->bpf_buffer, bpf->bpf_length); 
		bpf->bpf_bp = bpf->bpf_buffer; 
	} 
	if (bpf->bpf_bufused < 0) 
	{ 
		error (0, errno, "bpf"); 
		return (- 1); 
	} 
	if (bpf->bpf_bufused > 0) 
	{ 
		bpf_packet = (struct bpf_hdr *) (bpf->bpf_bp); 
		if ((size_t) (extent) > bpf_packet->bh_caplen) 
		{ 
			extent = bpf_packet->bh_caplen; 
		} 
		if ((size_t) (extent) < bpf_packet->bh_caplen) 
		{ 
			if (_anyset (channel->flags, CHANNEL_VERBOSE)) 
			{ 
				error (0, 0, "Truncated incoming frame (%u -> %zd bytes)", bpf_packet->bh_caplen, extent); 
			} 
		} 
		memcpy (memory, bpf->bpf_bp +  bpf_packet->bh_hdrlen, extent); 
		bpf->bpf_bufused -= BPF_WORDALIGN (bpf_packet->bh_hdrlen +  bpf_packet->bh_caplen); 
		bpf->bpf_bp += BPF_WORDALIGN (bpf_packet->bh_hdrlen +  bpf_packet->bh_caplen); 
		if (_anyset (channel->flags, CHANNEL_VERBOSE)) 
		{ 
			hexdump (memory, 0, extent, stdout); 
		} 
		return (extent); 
	} 

#elif defined (WINPCAP) || defined (LIBPCAP)

	struct pcap_pkthdr * header; 
	const uint8_t * data; 
	signed status = pcap_next_ex (channel->socket, & header, & data); 
	memset (memory, 0, extent); 
	if (status < 0) 
	{ 
		error (0, errno, "pcap_next_ex"); 
		return (- 1); 
	} 
	if (status > 0) 
	{ 
		extent = header->caplen; 
		memcpy (memory, data, extent); 
		if (_anyset (channel->flags, CHANNEL_VERBOSE)) 
		{ 
			hexdump (memory, 0, extent, stdout); 
		} 
		return (extent); 
	} 

#else
#error "Unknown Environment"
#endif

	return (0); 
} 

#endif



