/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   solicit.c - Qualcomm Atheros Network Solicitor;
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

/*====================================================================*
 *   system header files;
 *--------------------------------------------------------------------*/

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <sys/time.h>

/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

#include "../ether/channel.h"
#include "../tools/getoptv.h"
#include "../tools/putoptv.h"
#include "../tools/memory.h"
#include "../tools/number.h"
#include "../tools/symbol.h"
#include "../tools/types.h"
#include "../tools/files.h"
#include "../tools/flags.h"
#include "../tools/error.h"
#include "../tools/timer.h"
#include "../lldp/lldp.h"
#include "../mme/mme.h"

/*====================================================================*
 *   custom source files;
 *--------------------------------------------------------------------*/

#ifndef MAKEFILE
#include "../tools/getoptv.c"
#include "../tools/putoptv.c"
#include "../tools/version.c"
#include "../tools/uintspec.c"
#include "../tools/hexdecode.c"
#include "../tools/hexencode.c"
#include "../tools/hexdump.c"
#include "../tools/hexstring.c"
#include "../tools/decdecode.c"
#include "../tools/decstring.c"
#include "../tools/todigit.c"
#include "../tools/strfbits.c"
#include "../tools/synonym.c"
#include "../tools/memswap.c"
#include "../tools/error.c"
#endif

#ifndef MAKEFILE
#include "../ether/openchannel.c"
#include "../ether/closechannel.c"
#include "../ether/readpacket.c"
#include "../ether/sendpacket.c"
#include "../ether/channel.c"
#endif

#ifndef MAKEFILE
#include "../mme/EthernetHeader.c"
#endif

#ifndef MAKEFILE
#include "../lldp/TLVPack.c"
#include "../lldp/TLVPackOS.c"
#include "../lldp/TLVPick.c"
#include "../lldp/TLVPeek.c"
#include "../lldp/lldp.c"
#endif

/*====================================================================*
 *   program constants;
 *--------------------------------------------------------------------*/

#define SOLICIT_VERBOSE (1 << 0)
#define SOLICIT_SILENCE (1 << 1)

#define PLCDEVICE "PLC"
#define PROFILE "solicit.ini"
#define SECTION "default"

/*====================================================================*
 *  
 *   void solicit (struct channel * channel, struct ethernet_frame * frame, char const * profile, char const * section);
 *  
 *--------------------------------------------------------------------*/

static void solicit (struct channel * channel, struct ethernet_frame * frame, char const * profile, char const * section) 

{ 
	memset (frame, 0, sizeof (* frame)); 
	EthernetHeader (frame, channel->peer, channel->host, ETH_P_LLDP); 
	if (sendpacket (channel, frame, (ETHER_MIN_LEN - ETHER_CRC_LEN)) > 0) 
	{ 
		while (readpacket (channel, frame, sizeof (* frame)) > 0) 
		{ 
			if (! memcmp (frame->frame_dhost, channel->host, sizeof (frame->frame_dhost))) 
			{ 
				TLVPeek (frame->frame_data, sizeof (frame->frame_data)); 
			} 
		} 
	} 
	return; 
} 

/*====================================================================*
 *  
 *   void monitor (struct channel * channel, struct ethernet_frame * frame, char const * profile, char const * section);
 *  
 *--------------------------------------------------------------------*/

static void monitor (struct channel * channel, struct ethernet_frame * frame, char const * profile, char const * section) 

{ 
	struct timeval ts; 
	struct timeval tc; 
	ssize_t length; 
	if (gettimeofday (& ts, NULL) == - 1) 
	{ 
		error (1, errno, CANT_START_TIMER); 
	} 
	while ((length = readpacket (channel, frame, sizeof (* frame))) >= 0) 
	{ 
		if (! memcmp (frame->frame_dhost, channel->peer, sizeof (frame->frame_dhost))) 
		{ 
			TLVPeek (frame->frame_data, sizeof (frame->frame_data)); 
			EthernetHeader (frame, frame->frame_shost, channel->host, ETH_P_LLDP); 
			memset (frame->frame_data, 0, sizeof (frame->frame_data)); 
			if (sendpacket (channel, frame, (ETHER_MIN_LEN - ETHER_CRC_LEN)) <= 0) 
			{ 
				error (0, errno, CHANNEL_CANTSEND); 
			} 
		} 
		if (gettimeofday (& tc, NULL) == - 1) 
		{ 
			error (1, errno, CANT_RESET_TIMER); 
		} 
		if (channel->timeout < 0) 
		{ 
			continue; 
		} 
		if (channel->timeout > MILLISECONDS (ts, tc)) 
		{ 
			continue; 
		} 
		break; 
	} 
	return; 
} 

/*====================================================================*
 *   
 *   int main (int argc, char const * argv[]);
 *   
 *
 *--------------------------------------------------------------------*/

int main (int argc, char const * argv []) 

{ 
	extern struct channel channel; 
	extern struct _term_ const addresses [LLDP_ADDRESSES]; 
	extern byte const broadcast [ETHER_ADDR_LEN]; 
	static char const * optv [] = 
	{ 
		"b:i:p:qs:t:vw:", 
		"", 
		"Qualcomm Atheros Network Solicitor", 
		"b x\tbroadcast address is (x) [" LITERAL (BROADCAST) "]", 

#if defined (WINPCAP) || defined (LIBPCAP)

		"i n\thost interface is (n) [" LITERAL (CHANNEL_ETHNUMBER) "]", 

#else

		"i s\thost interface is (s) [" LITERAL (CHANNEL_ETHDEVICE) "]", 

#endif

		"p s\tconfiguration profile is (s) [" LITERAL (PROFILE) "]", 
		"q\tquiet mode", 
		"s s\tconfiguration section is (s) [" LITERAL (SECTION) "]", 
		"t n\tread timeout is (n) milliseconds [" LITERAL (CHANNEL_TIMEOUT) "]", 
		"v\tverbose mode", 
		"w n\twakeup every (n) milliseconds [" LITERAL (LLDP_TIMER) "]", 
		(char const *) (0)
	}; 
	struct ethernet_frame frame; 
	char const * profile = PROFILE; 
	char const * section = SECTION; 
	signed c; 
	memcpy (channel.peer, broadcast, sizeof (channel.peer)); 
	channel.type = ETH_P_LLDP; 
	channel.timeout = LLDP_TIMER; 
	if (getenv (PLCDEVICE)) 
	{ 

#if defined (WINPCAP) || defined (LIBPCAP)

		channel.ifindex = atoi (getenv (PLCDEVICE)); 

#else

		channel.ifname = strdup (getenv (PLCDEVICE)); 

#endif

	} 
	optind = 1; 
	while (~ (c = getoptv (argc, argv, optv))) 
	{ 
		switch (c) 
		{ 
		case 'b': 
			if (! hexencode (channel.peer, sizeof (channel.peer), synonym (optarg, addresses, SIZEOF (addresses)))) 
			{ 
				error (1, errno, LLDP_BAD_MAC, optarg); 
			} 
			break; 
		case 'i': 

#if defined (WINPCAP) || defined (LIBPCAP)

			channel.ifindex = atoi (optarg); 

#else

			channel.ifname = optarg; 

#endif

			break; 
		case 'p': 
			profile = optarg; 
			break; 
		case 'q': 
			_setbits (channel.flags, CHANNEL_SILENCE); 
			break; 
		case 's': 
			section = optarg; 
			break; 
		case 't': 
			channel.timeout = (unsigned) (uintspec (optarg, 0, UINT_MAX)); 
			break; 
		case 'v': 
			_setbits (channel.flags, CHANNEL_VERBOSE); 
			break; 
		case 'w': 
			channel.timeout = (unsigned) (uintspec (optarg, 0, UINT_MAX)); 
			break; 
		default: 
			break; 
		} 
	} 
	argc -= optind; 
	argv += optind; 
	if (argc) 
	{ 
		error (1, 0, ERROR_TOOMANY); 
	} 
	if (access (profile, R_OK)) 
	{ 
		error (1, errno, FILE_CANTSTAT, profile); 
	} 
	openchannel (& channel); 
	while (true) 
	{ 
		solicit (& channel, & frame, profile, section); 
		monitor (& channel, & frame, profile, section); 
	} 
	closechannel (& channel); 
	exit (0); 
} 

