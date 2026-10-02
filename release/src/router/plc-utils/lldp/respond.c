/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   respond.c - Qualcomm Atheros Atheros Network Responder;
 *   
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#define _GETOPT_H

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

#include "../tools/getoptv.h"
#include "../tools/putoptv.h"
#include "../tools/memory.h"
#include "../tools/number.h"
#include "../tools/symbol.h"
#include "../tools/types.h"
#include "../tools/flags.h"
#include "../tools/files.h"
#include "../tools/error.h"
#include "../tools/timer.h"
#include "../tools/config.h"
#include "../ether/channel.h"
#include "../lldp/lldp.h"
#include "../mme/mme.h"

/*====================================================================*
 *   custom source files;
 *--------------------------------------------------------------------*/

#ifndef MAKEFILE
#include "../tools/getoptv.c"
#include "../tools/putoptv.c"
#include "../tools/version.c"
#include "../tools/hexcopy.c"
#include "../tools/hexdump.c"
#include "../tools/hexdecode.c"
#include "../tools/hexencode.c"
#include "../tools/hexstring.c"
#include "../tools/decdecode.c"
#include "../tools/decstring.c"
#include "../tools/uintspec.c"
#include "../tools/todigit.c"
#include "../tools/error.c"
#include "../tools/strfbits.c"
#include "../tools/synonym.c"
#include "../tools/config.c"
#endif

#ifndef MAKEFILE
#include "../ether/channel.c"
#include "../ether/openchannel.c"
#include "../ether/closechannel.c"
#include "../ether/readpacket.c"
#include "../ether/sendpacket.c"
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

#define RESPOND_VERBOSE (1 << 0)
#define RESPOND_SILENCE (1 << 1)

#define PLCDEVICE "PLC"
#define PROFILE "respond.ini"
#define SECTION "default"
#define STANDARD "Standard"
#define SPECIFIC "Specific"

/*====================================================================*
 *
 *   byte * populate1 (byte * memory, size_t extent, char const * profile, char const * section, byte buffer [], size_t length) 
 *
 *   populate memory region with IEEE standard TLVs of interest to
 *   us; not all IEEE 802 TLVs are implemented here; the data source
 *   is static data declarations in one case and a configuration
 *   file in the other case;
 *
 *--------------------------------------------------------------------*/

static byte * populate1 (byte * memory, size_t extent, char const * profile, char const * section, byte buffer [], size_t length) 

{ 
	char SYSTEM_NAME [1024] = 
	{ 
		"System Name"
	}; 

#ifndef PROFILE

	byte * length = memory +  extent; 
	static uint16_t TIME_TO_LIVE = 50000; 
	static byte CHASSIS_ID [] = 
	{ 
		0x04, 
		0xAA, 
		0xBB, 
		0xCC, 
		0xDD, 
		0xEE, 
		0xFF
	}; 
	static byte PORT_ID [] = 
	{ 
		0x03, 
		0x11, 
		0x22, 
		0x33, 
		0x44, 
		0x55, 
		0x66
	}; 
	static byte SYSTEM_CAPABILITIES [] = 
	{ 
		0x00, 
		0xFF, 
		0xFF, 
		0xAB, 
		0xCD
	}; 
	static char PORT_DESCRIPTION [] = "Port Description"; 
	static char SYSTEM_DESCRIPTION [] = "System Description"; 
	gethostname (SYSTEM_NAME, sizeof (SYSTEM_NAME)); 
	memory = TLVPack (memory, length - memory, TLV_IEEE_CHASSIS_ID, sizeof (CHASSIS_ID), CHASSIS_ID); 
	memory = TLVPack (memory, length - memory, TLV_IEEE_PORT_ID, sizeof (PORT_ID), PORT_ID); 
	memory = TLVPack (memory, length - memory, TLV_IEEE_TIME_TO_LIVE, sizeof (TIME_TO_LIVE), & TIME_TO_LIVE); 
	memory = TLVPack (memory, length - memory, TLV_IEEE_PORT_DESCRIPTION, sizeof (PORT_DESCRIPTION), PORT_DESCRIPTION); 
	memory = TLVPack (memory, length - memory, TLV_IEEE_SYSTEM_NAME, strlen (SYSTEM_NAME) +  1, SYSTEM_NAME); 
	memory = TLVPack (memory, length - memory, TLV_IEEE_SYSTEM_DESCRIPTION, sizeof (SYSTEM_DESCRIPTION), SYSTEM_DESCRIPTION); 
	memory = TLVPack (memory, length - memory, TLV_IEEE_SYSTEM_CAPABILITIES, sizeof (SYSTEM_CAPABILITIES), SYSTEM_CAPABILITIES); 

#else

	uint16_t ttl; 
	char const * string; 
	byte * offset = memory; 
	memory += extent; 
	gethostname (SYSTEM_NAME, sizeof (SYSTEM_NAME)); 
	string = configstring (profile, section, "Chassis ID", "00:00:00:00:00:00:00"); 
	offset = TLVPack (offset, memory - offset, TLV_IEEE_CHASSIS_ID, hexcopy (buffer, length, string), buffer); 
	string = configstring (profile, section, "Port ID", "00:00:00:00:00:00:00"); 
	offset = TLVPack (offset, memory - offset, TLV_IEEE_PORT_ID, hexcopy (buffer, length, string), buffer); 
	string = configstring (profile, section, "Time To Live", "0"); 
	ttl = htons (atoi (string)); 
	offset = TLVPack (offset, memory - offset, TLV_IEEE_TIME_TO_LIVE, sizeof (ttl), & ttl); 
	string = configstring (profile, section, "Port Description", "Unspecified port"); 
	offset = TLVPack (offset, memory - offset, TLV_IEEE_PORT_DESCRIPTION, 1 +  strlen (string), string); 
	string = configstring (profile, section, "System Name", SYSTEM_NAME); 
	offset = TLVPack (offset, memory - offset, TLV_IEEE_SYSTEM_NAME, 1 +  strlen (string), string); 
	string = configstring (profile, section, "System Description", "Do nothing quickly and accurately"); 
	offset = TLVPack (offset, memory - offset, TLV_IEEE_SYSTEM_DESCRIPTION, 1 +  strlen (string), string); 
	string = configstring (profile, section, "System Capabilities", "00:00:00:00:00"); 
	offset = TLVPack (offset, memory - offset, TLV_IEEE_SYSTEM_CAPABILITIES, hexcopy (buffer, length, string), buffer); 
	string = configstring (profile, section, "Management URL", "http://www.management.com"); 
	offset = TLVPack (offset, memory - offset, TLV_IEEE_MANAGEMENT_ADDRESS, 1 +  strlen (string), string); 

#endif

	return (offset); 
} 

/*====================================================================*
 *
 *   byte * populate2 (byte * memory, size_t extent, char const * profile, char const * section, byte buffer [], size_t length) 
 *
 *   populate memory region with IEEE organizationally specific TLVs 
 *   of interest to us; Qualcomm Atheros has defined the ones used 
 *   here; the data source here is static data declarations in one
 *   case and a configuration file in the other;
 *
 *--------------------------------------------------------------------*/

static byte * populate2 (byte * memory, size_t extent, char const * profile, char const * section, byte buffer [], size_t length) 

{ 

#ifndef PROFILE

	extern struct channel channel; 
	byte * length = memory +  extent; 
	static char MANUFACTURER [] = "Qualcomm Atheros"; 
	static char HARDWARE_MODEL [] = "QCA7000"; 
	Static char SERIAL_NUMBER [] = "00:B0:52:00:00:55"; 
	static byte PLC_MAC [] = 
	{ 
		0x00, 
		0xB0, 
		0x52, 
		0x00, 
		0xBA, 
		0xBE
	}; 
	static byte WIFI_MAC [] = 
	{ 
		0xAA, 
		0xBB, 
		0xCC, 
		0xDD, 
		0xEE, 
		0xFF
	}; 
	static byte WIFI_IP [] = 
	{ 
		192, 
		168, 
		1, 
		88
	}; 
	memory = TLVPackOS (memory, length - memory, TLV_OS_MANUFACTURER, sizeof (MANUFACTURER), MANUFACTURER); 
	memory = TLVPackOS (memory, length - memory, TLV_OS_HARDWARE_MODEL, sizeof (HARDWARE_MODEL), HARDWARE_MODEL); 
	memory = TLVPackOS (memory, length - memory, TLV_OS_SERIAL_NUMBER, sizeof (SERIAL_NUMBER), SERIAL_NUMBER); 
	memory = TLVPackOS (memory, length - memory, TLV_OS_HOST_MAC, sizeof (channel.host), channel.host); 
	memory = TLVPackOS (memory, length - memory, TLV_OS_WIFI_MAC, sizeof (WIFI_MAC), WIFI_MAC); 
	memory = TLVPackOS (memory, length - memory, TLV_OS_WIFI_IP, sizeof (WIFI_IP), WIFI_IP); 
	memory = TLVPackOS (memory, length - memory, TLV_OS_PLC_MAC, sizeof (PLC_MAC), PLC_MAC); 

#else

	char const * string; 
	byte * offset = memory; 
	memory += extent; 
	string = configstring (profile, section, "Manufacturer", "Unknown"); 
	offset = TLVPackOS (offset, memory - offset, TLV_OS_MANUFACTURER, 1 +  strlen (string), string); 
	string = configstring (profile, section, "Hardware Model", "Unknown"); 
	offset = TLVPackOS (offset, memory - offset, TLV_OS_HARDWARE_MODEL, 1 +  strlen (string), string); 
	string = configstring (profile, section, "Serial Number", "0000-0000-0000-0000"); 
	offset = TLVPackOS (offset, memory - offset, TLV_OS_SERIAL_NUMBER, 1 +  strlen (string), string); 
	string = configstring (profile, section, "Host MAC", "00:00:00:00:00:00"); 
	offset = TLVPackOS (offset, memory - offset, TLV_OS_HOST_MAC, hexcopy (buffer, length, string), buffer); 
	string = configstring (profile, section, "WiFi MAC", "00:00:00:00:00:00"); 
	offset = TLVPackOS (offset, memory - offset, TLV_OS_WIFI_MAC, hexcopy (buffer, length, string), buffer); 
	string = configstring (profile, section, "WiFi IP", "00:00:00:00"); 
	offset = TLVPackOS (offset, memory - offset, TLV_OS_WIFI_IP, hexcopy (buffer, length, string), buffer); 
	string = configstring (profile, section, "PLC MAC", "00:00:00:00:00:00"); 
	offset = TLVPackOS (offset, memory - offset, TLV_OS_PLC_MAC, hexcopy (buffer, length, string), buffer); 

#endif

	return (offset); 
} 

/*====================================================================*
 *
 *   byte * populate (byte * memory, size_t extent, char const * profile, char const * section);
 *
 *   populate a memory region with IEEE 802 standard TLVs then IEEE
 *   802 organizationally specific TLVs; provide the buffer that is 
 *   used to format and encode information before copying it to the
 *   memory region;
 *   
 *   customers may implement their own populate functions, possibly
 *   reading from a MIB or other type of database;
 *
 *--------------------------------------------------------------------*/

static byte * populate (byte * memory, size_t extent, char const * profile, char const * section) 

{ 
	byte buffer [1024]; 
	byte * offset = memory; 
	memory += extent; 
	offset = populate1 (offset, memory - offset, profile, STANDARD, buffer, sizeof (buffer)); 
	offset = populate2 (offset, memory - offset, profile, SPECIFIC, buffer, sizeof (buffer)); 
	return (offset); 
} 

/*====================================================================*
 *
 *   void announce (struct channel * channel, struct ethernet_frame * frame, char const * profile, char const * section);
 *
 *   announce network presence and collect any acknowledgements; 
 * 
 *--------------------------------------------------------------------*/

static void announce (struct channel * channel, struct ethernet_frame * frame, char const * profile, char const * section) 

{ 
	ssize_t length; 
	memset (frame, 0, sizeof (* frame)); 
	EthernetHeader (frame, channel->peer, channel->host, ETH_P_LLDP); 
	length = populate (frame->frame_data, sizeof (frame->frame_data), profile, section) - (byte *) (frame); 
	if (length < (ETHER_MIN_LEN - ETHER_CRC_LEN)) 
	{ 
		length = (ETHER_MIN_LEN - ETHER_CRC_LEN); 
	} 
	if (sendpacket (channel, frame, length) > 0) 
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
 *   listen for discovery requests and respond; 
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
			EthernetHeader (frame, frame->frame_shost, channel->host, ETH_P_LLDP); 
			memset (frame->frame_data, 0, sizeof (frame->frame_data)); 
			length = populate (frame->frame_data, sizeof (frame->frame_data), profile, section) - (byte *) (frame); 
			if (length < (ETHER_MIN_LEN - ETHER_CRC_LEN)) 
			{ 
				length = (ETHER_MIN_LEN - ETHER_CRC_LEN); 
			} 
			if (sendpacket (channel, frame, length) <= 0) 
			{ 
				error (0, errno, CHANNEL_CANTSEND); 
			} 
			continue; 
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
 *   int main (int argc, char * argv[]);
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
		"b:i:p:qt:vw:", 
		PUTOPTV_S_DIVINE, 
		"Qualcomm Atheros Network Responder", 
		"b x\tbroadcast address is (x) [" LITERAL (BROADCAST) "]", 

#if defined (WINPCAP) || defined (LIBPCAP)

		"i n\thost interface is (n) [" LITERAL (CHANNEL_ETHNUMBER) "]", 

#else

		"i s\thost interface is (s) [" LITERAL (CHANNEL_ETHDEVICE) "]", 

#endif

		"p s\tconfiguration profile is (s) [" LITERAL (PROFILE) "]", 
		"q\tsuppress normal output", 
		"s s\tconfiguration section is (s) [" LITERAL (SECTION) "]", 
		"t n\tread timeout is (n) milliseconds [" LITERAL (CHANNEL_TIMEOUT) "]", 
		"v\tverbose frames on stdout", 
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
				error (1, errno, LLDP_BAD_MAC, * argv); 
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
			_clrbits (channel.flags, CHANNEL_SILENCE); 
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
		announce (& channel, & frame, profile, section); 
		monitor (& channel, & frame, profile, section); 
	} 
	closechannel (& channel); 
	return (0); 
} 

