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
#include <limits.h>
#include <errno.h>

/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

#include "../ether/channel.h"
#include "../tools/getoptv.h"
#include "../tools/putoptv.h"
#include "../tools/memory.h"
#include "../tools/number.h"
#include "../tools/types.h"
#include "../tools/flags.h"
#include "../tools/error.h"
#include "../nda/lldp.h"
#include "../plc/plc.h"

/*====================================================================*
 *   custom source files;
 *--------------------------------------------------------------------*/

#ifndef MAKEFILE
#include "../tools/getoptv.c"
#include "../tools/putoptv.c"
#include "../tools/version.c"
#include "../tools/uintspec.c"
#include "../tools/hexdecode.c"
#include "../tools/hexdump.c"
#include "../tools/hexstring.c"
#include "../tools/decdecode.c"
#include "../tools/decstring.c"
#include "../tools/todigit.c"
#include "../tools/strfbits.c"
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
#include "../plc/Devices.c"
#endif

#ifndef MAKEFILE
#include "../mme/EthernetHeader.c"
#include "../mme/QualcommHeader.c"
#include "../mme/UnwantedMessage.c"
#include "../mme/readmessage.c"
#include "../mme/sendmessage.c"
#endif

#ifndef MAKEFILE
#include "../lldp/TLVPack.c"
#include "../lldp/TLVPackOS.c"
#include "../lldp/TLVPick.c"
#include "../lldp/TLVPeek.c"
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
 *   void solicit (struct channel * channel, struct message * message, char const * profile, char const * section);
 *  
 *--------------------------------------------------------------------*/

static void solicit (struct channel * channel, struct message * message, char const * profile, char const * section) 

{ 

#ifndef __GNUC__
#pragma pack (push,1)
#endif

	struct __packed ms_discover_request 
	{ 
		struct ethernet_hdr ethernet; 
		struct qualcomm_hdr qualcomm; 
		uint8_t MACTION; 
	} 
	* request = (struct ms_discover_request *) (message); 
	struct __packed ms_discover_confirm 
	{ 
		struct ethernet_hdr ethernet; 
		struct qualcomm_hdr qualcomm; 
		uint8_t MDATA [1494]; 
	} 
	* confirm = (struct ms_discover_confirm *) (message); 

#ifndef __GNUC__
#pragma pack (pop)
#endif

	memset (message, 0, sizeof (* message)); 
	EthernetHeader (& request->ethernet, channel->peer, channel->host, channel->type); 
	QualcommHeader (& request->qualcomm, 0, (MS_DISCOVER | MMTYPE_REQ)); 
	if (sendmessage (channel, message, (ETHER_MIN_LEN - ETHER_CRC_LEN)) > 0) 
	{ 
		while (readmessage (channel, message, 0, (MS_DISCOVER | MMTYPE_CNF)) > 0) 
		{ 
			TLVPeek (confirm->MDATA, sizeof (confirm->MDATA)); 
		} 
	} 
	return; 
} 

/*====================================================================*
 *  
 *   void monitor (struct channel * channel, struct message * message, char const * profile, char const * section, unsigned timer);
 *  
 *--------------------------------------------------------------------*/

static void monitor (struct channel * channel, struct message * message, char const * profile, char const * section, unsigned timer) 

{ 

#ifndef __GNUC__
#pragma pack (push,1)
#endif

	struct __packed ms_discover_indicate 
	{ 
		struct ethernet_hdr ethernet; 
		struct qualcomm_hdr qualcomm; 
		uint8_t MDATA [1494]; 
	} 
	* indicate = (struct ms_discover_indicate *) (message); 
	struct __packed ms_discover_response 
	{ 
		struct ethernet_hdr ethernet; 
		struct qualcomm_hdr qualcomm; 
		uint8_t MDATA [1494]; 
	} 
	* response = (struct ms_discover_response *) (message); 

#ifndef __GNUC__
#pragma pack (pop)
#endif

	unsigned timeout = channel->timeout; 
	channel->timeout = timer; 
	while (readmessage (channel, message, 0, (MS_DISCOVER | MMTYPE_IND)) > 0) 
	{ 
		TLVPeek (indicate->MDATA, sizeof (indicate->MDATA)); 
		EthernetHeader (& response->ethernet, indicate->ethernet.OSA, channel->host, channel->type); 
		QualcommHeader (& response->qualcomm, indicate->qualcomm.MMV, (MS_DISCOVER | MMTYPE_RSP)); 
		memset (response->MDATA, 0, sizeof (response->MDATA)); 
		if (sendmessage (channel, message, (ETHER_MIN_LEN - ETHER_CRC_LEN)) <= 0) 
		{ 
			error (0, errno, CHANNEL_CANTSEND); 
		} 
	} 
	channel->timeout = timeout; 
	return; 
} 

/*====================================================================*
 *   
 *   int main (int argc, char const * argv[]);
 *   
 *   parse command line, populate plc structure and perform selected 
 *   operations; show help summary when asked; see getoptv and putoptv
 *   to understand command line parsing and help summary display; see
 *   plc.h for the definition of struct plc; 
 *
 *--------------------------------------------------------------------*/

int main (int argc, char const * argv []) 

{ 
	extern struct channel channel; 
	extern byte const broadcast [ETHER_ADDR_LEN]; 
	static char const * optv [] = 
	{ 
		"i:p:qs:t:vw:", 
		"", 
		"Qualcomm Atheros Network Solicitor", 

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
		"w n\twakeup every (n) milliseconds [" LITERAL (PLC_LONGTIME) "]", 
		(char const *) (0)
	}; 
	struct message message; 
	char const * profile = PROFILE; 
	char const * section = SECTION; 
	unsigned timer = PLC_LONGTIME; 
	signed c; 
	if (getenv (PLCDEVICE)) 
	{ 

#if defined (WINPCAP) || defined (LIBPCAP)

		channel.ifindex = atoi (getenv (PLCDEVICE)); 

#else

		channel.ifname = strdup (getenv (PLCDEVICE)); 

#endif

	} 
	optind = 1; 
	memcpy (channel.peer, broadcast, sizeof (channel.peer)); 
	while (~ (c = getoptv (argc, argv, optv))) 
	{ 
		switch (c) 
		{ 
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
			channel.timeout = (signed) (uintspec (optarg, 0, UINT_MAX)); 
			break; 
		case 'v': 
			_setbits (channel.flags, CHANNEL_VERBOSE); 
			break; 
		case 'w': 
			timer = (unsigned) (uintspec (optarg, 1, UINT_MAX)); 
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
		error (1, errno, "Can't access '%s'", profile); 
	} 
	openchannel (& channel); 
	while (true) 
	{ 
		solicit (& channel, & message, profile, section); 
		monitor (& channel, & message, profile, section, timer); 
	} 
	closechannel (& channel); 
	exit (0); 
} 

