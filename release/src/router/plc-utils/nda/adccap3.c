/*====================================================================*
 *
 *   Copyright (c) 2018 Qualcomm Technologies, Inc.
 *   All Rights Reserved. 
 *   Confidential and Proprietary - Qualcomm Technologies, Inc. 
 *	 *****************************************************************                
 *	 2013 Qualcomm Atheros, Inc.
 *--------------------------------------------------------------------*/

/*====================================================================*
 *
 *   adccap3.c - ADC Capture Utility III
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *      Nathaniel Houghton <nhoughto@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

/*====================================================================*
 *   system header files;
 *--------------------------------------------------------------------*/

#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <limits.h>
#include <ctype.h>
#include <errno.h>
#include <math.h>
#include <sys/time.h>

/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

#include "../tools/getoptv.h"
#include "../tools/putoptv.h"
#include "../tools/number.h"
#include "../tools/symbol.h"
#include "../tools/error.h"
#include "../tools/flags.h"
#include "../mme/mme.h"
#include "../plc/plc.h"

/*====================================================================*
 *   custom source files;
 *--------------------------------------------------------------------*/

#ifndef MAKEFILE
#include "../plc/Devices.c"
#include "../plc/Failure.c"
#include "../plc/ReadMME.c"
#include "../plc/ReadFMI.c"
#include "../plc/SendMME.c"
#endif

#ifndef MAKEFILE
#include "../tools/error.c"
#include "../tools/getoptv.c"
#include "../tools/putoptv.c"
#include "../tools/version.c"
#include "../tools/uintspec.c"
#include "../tools/hexdump.c"
#include "../tools/hexencode.c"
#include "../tools/hexdecode.c"
#include "../tools/hexstring.c"
#include "../tools/todigit.c"
#include "../tools/synonym.c"
#include "../tools/checkfilename.c"
#endif

#ifndef MAKEFILE
#include "../ether/openchannel.c"
#include "../ether/closechannel.c"
#include "../ether/readpacket.c"
#include "../ether/sendpacket.c"
#include "../ether/channel.c"
#endif

#ifndef MAKEFILE
#include "../mme/MMECode.c"
#include "../mme/EthernetHeader.c"
#include "../mme/QualcommHeader1.c"
#include "../mme/UnwantedMessage.c"
#endif

/*====================================================================*
 *   program constants;
 *--------------------------------------------------------------------*/

#define ADCCAP_GAIN 0
#define ADCCAP_ACTION_GRAB 0
#define ADCCAP_ACTION_SYNC 1
#define ADCCAP_ACTION_READ 2
#define ADCCAP_ACTION_AUTO 3

#define ADCCAP_DATAITEMS_12_BIT 6528
#define ADCCAP_DATAITEMS_10_BIT 3456
#define ADCCAP_WAITTIME  0

/*====================================================================*
 *
 *   void print_data (int16_t list [], unsigned size);
 *
 *   print the specified number of signed 12-bit integers on stdout; 
 *   
 *   since the 12-bit vales are stored in a 16-bit variable, we must
 *   shift left to set the 16-bit sign bit and shift right to restore
 *   the original magnitude; 
 *
 *--------------------------------------------------------------------*/

static void print_data (uint16_t list [], unsigned size) 

{ 
	int shift_bits = 4;

	if (size == ADCCAP_DATAITEMS_10_BIT)
		shift_bits = 6;

	while (size--) 
	{ 
		int16_t number = LE16TOH (* list++); 
		number <<= shift_bits; 
		number >>= shift_bits; 
		printf ("%d\n", number); 
	} 
	return; 
} 

/*====================================================================*
 *
 *   signed collect (struct plc * plc, void * memory, unsigned extent) 
 *
 *   collect and print captured ADC data; 
 *
 *--------------------------------------------------------------------*/

static signed collect (struct plc * plc) 

{ 
	struct channel * channel = (struct channel *) (plc->channel); 
	struct message * message = (struct message *) (plc->message); 

#ifndef __GNUC__
#pragma pack (push,1)
#endif

	struct __packed vs_debug_info_request 
	{ 
		struct ethernet_hdr ethernet; 
		struct qualcomm_fmi qualcomm; 
		uint32_t MME_LEN; 
		uint16_t REQ_TYPE; 
		uint32_t RESERVED; 
		uint8_t COMMAND; 
		uint8_t RXGAIN; 
		uint16_t STARTINDEX; 
		uint16_t VALUECOUNT; 
		uint8_t COUPLING_TYPE; 
		uint8_t RESERVED2; 
	} 
	* request = (struct vs_debug_info_request *) (message); 
	struct __packed vs_debug_info_confirm 
	{ 
		struct ethernet_hdr ethernet; 
		struct qualcomm_fmi qualcomm; 
		uint8_t MSTATUS; 
		uint8_t RSVD1; 
		uint32_t MME_LEN; 
		uint16_t REQ_TYPE; 
		uint8_t RSVD2; 
		uint8_t COUPLING; 
		uint8_t COMMAND; 
		uint8_t GAIN; 
		uint16_t STARTINDEX; 
		uint16_t VALUECOUNT; 
		uint16_t ACTUALCOUNT; 
		uint16_t DATA [1]; 
	} 
	* confirm = (struct vs_debug_info_confirm *) (message); 

#ifndef __GNUC__
#pragma pack (pop)
#endif

	memset (message, 0, sizeof (* message)); 
	EthernetHeader (& request->ethernet, channel->peer, channel->host, channel->type); 
	QualcommHeader1 (& request->qualcomm, 1, (VS_DEBUG_INFO | MMTYPE_REQ)); 
	request->REQ_TYPE = HTOLE16 (2); 
	request->COMMAND = plc->action; 
	request->RXGAIN = plc->module; 
	request->COUPLING_TYPE = plc->coupling; 
	plc->packetsize = (ETHER_MIN_LEN - ETHER_CRC_LEN); 
	if (SendMME (plc) <= 0) 
	{ 
		error (1, ECANCELED, CHANNEL_CANTSEND); 
	} 
	if (ReadFMI (plc, 1, (VS_DEBUG_INFO | MMTYPE_CNF)) <= 0) 
	{ 
		error (1, ECANCELED, CHANNEL_CANTREAD); 
	} 
	confirm = (struct vs_debug_info_confirm *) (plc->content); 
	if (confirm->MSTATUS) 
	{ 
		Failure (plc, PLC_WONTDOIT); 
	} 
	print_data (confirm->DATA, LE16TOH (confirm->ACTUALCOUNT)); 
	free (plc->content); 
	plc->content = NULL; 
	return (0); 
} 

/*====================================================================*
 *
 *   signed capture (struct plc * plc) 
 *
 *   send ADC capture request and return; the capbure request may be 
 *   either 'immediate' or 'after sync';
 *
 *--------------------------------------------------------------------*/

signed capture (struct plc * plc) 

{ 
	struct channel * channel = (struct channel *) (plc->channel); 
	struct message * message = (struct message *) (plc->message); 

#ifndef __GNUC__
#pragma pack (push,1)
#endif

	struct __packed vs_debug_info_request 
	{ 
		struct ethernet_hdr ethernet; 
		struct qualcomm_fmi qualcomm; 
		uint32_t MME_LEN; 
		uint16_t REQ_TYPE; 
		uint32_t RESERVED1; 
		uint8_t COMMAND; 
		uint8_t RXGAIN; 
		uint16_t STARTINDEX; 
		uint16_t VALUECOUNT; 
		uint8_t COUPLING_TYPE; 
		uint8_t RESERVED2; 
	} 
	* request = (struct vs_debug_info_request *) (message); 
	struct __packed vs_debug_info_confirm 
	{ 
		struct ethernet_hdr ethernet; 
		struct qualcomm_fmi qualcomm; 
		uint8_t MSTATUS; 
		uint8_t RSVD1; 
		uint32_t MME_LEN; 
		uint16_t REQ_TYPE; 
		uint8_t RSVD2; 
		uint8_t COUPLING_TYPE; 
		uint8_t COMMAND; 
		uint16_t STARTINDEX; 
		uint16_t VALUECOUNT; 
		uint16_t ACTUALCOUNT; 
		uint8_t GAIN; 
	} 
	* confirm = (struct vs_debug_info_confirm *) (message); 

#ifndef __GNUC__
#pragma pack (pop)
#endif

	memset (message, 0, sizeof (* message)); 
	EthernetHeader (& request->ethernet, channel->peer, channel->host, channel->type); 
	QualcommHeader1 (& request->qualcomm, 1, (VS_DEBUG_INFO | MMTYPE_REQ)); 
	request->REQ_TYPE = HTOLE16 (2); 
	request->COMMAND = plc->action; 
	request->RXGAIN = plc->module; 
	request->COUPLING_TYPE = plc->coupling; 
	plc->packetsize = (ETHER_MIN_LEN - ETHER_CRC_LEN); 
	if (SendMME (plc) <= 0) 
	{ 
		error (1, ECANCELED, CHANNEL_CANTSEND); 
	} 
	if (ReadFMI (plc, 1, (VS_DEBUG_INFO | MMTYPE_CNF)) <= 0) 
	{ 
		error (1, ECANCELED, CHANNEL_CANTREAD); 
	} 
	confirm = (struct vs_debug_info_confirm *) (plc->content); 
	if (confirm->MSTATUS) 
	{ 
		Failure (plc, PLC_WONTDOIT); 
	} 
	free (plc->content); 
	plc->content = NULL; 
	return (0); 
} 

/*====================================================================*
 *   
 *   int main (int argc, char const * argv[]);
 *   
 *   plc.hostaction holds the ADC capture operation code;
 *
 *   plc.module holds the RX Gain value; a value of 255 means
 *   "reuse previous RX Gain value";
 *
 *   plc.index holds the ADC data offset;
 *   plc.count holds the ADC data length;
 *
 *--------------------------------------------------------------------*/

int main (int argc, char const * argv []) 

{ 
	extern struct channel channel; 
	extern const struct _term_ devices []; 
	static char const * optv [] = 
	{ 
		"c:ei:g:np:qrst:vw:", 
		"device [device] [> stdout]", 
		"Qualcomm Atheros ADC Capture Utility", 
		"c n\tcoupling is (n) [" LITERAL (PLCOUPLING) "]", 
		"e\tredirect stderr messages to stdout", 

#if defined (WINPCAP) || defined (LIBPCAP)

		"i n\thost interface is (n) [" LITERAL (CHANNEL_ETHNUMBER) "]", 

#else

		"i s\thost interface is (s) [" LITERAL (CHANNEL_ETHDEVICE) "]", 

#endif

		"n\tcapture now", 
		"r\tcollect data (read)", 
		"s\tcapture after sync", 
		"g n\tgain is (n) [" LITERAL (ADCCAP_GAIN) "]", 
		"q\tquiet mode", 
		"t n\tread timeout is (n) milliseconds [" LITERAL (CHANNEL_TIMEOUT) "]", 
		"v\tverbose mode", 
		"w n\twait time is (n) seconds [" LITERAL (ADCCAP_WAITTIME) "]", 
		(char const *) (0)
	}; 
	static const struct _term_ coupling [] = 
	{ 
		{ 
			"alt", 
			"1"
		}, 
		{ 
			"pri", 
			"0"
		} 
	}; 

#include "../plc/plc.c"

	signed timer = ADCCAP_WAITTIME; 
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
	plc.module = ADCCAP_GAIN; 
	while (~ (c = getoptv (argc, argv, optv))) 
	{ 
		switch (c) 
		{ 
		case 'c': 
			plc.coupling = (byte) (uintspec (synonym (optarg, coupling, SIZEOF (coupling)), 0, UCHAR_MAX)); 
			break; 
		case 'e': 
			dup2 (STDOUT_FILENO, STDERR_FILENO); 
			break; 
		case 'g': 
			plc.module = (uint8_t) (uintspec (optarg, 0, 31)); 
			break; 
		case 'i': 

#if defined (WINPCAP) || defined (LIBPCAP)

			channel.ifindex = atoi (optarg); 

#else

			channel.ifname = optarg; 

#endif

			break; 
		case 'n': 
			plc.action = ADCCAP_ACTION_GRAB; 
			break; 
		case 'q': 
			_setbits (channel.flags, CHANNEL_SILENCE); 
			_setbits (plc.flags, PLC_SILENCE); 
			break; 
		case 'r': 
			plc.action = ADCCAP_ACTION_READ; 
			break; 
		case 's': 
			plc.action = ADCCAP_ACTION_SYNC; 
			break; 
		case 't': 
			channel.timeout = (signed) (uintspec (optarg, 0, UINT_MAX)); 
			break; 
		case 'v': 
			_setbits (channel.flags, CHANNEL_VERBOSE); 
			_setbits (plc.flags, PLC_VERBOSE); 
			break; 
		case 'w': 
			timer = (signed) (uintspec (optarg, 0, 30)); 
			break; 
		default: 
			break; 
		} 
	} 
	argc -= optind; 
	argv += optind; 
	openchannel (& channel); 
	if (! (plc.message = malloc (sizeof (* plc.message)))) 
	{ 
		error (1, errno, PLC_NOMEMORY); 
	} 
	if ((argc) && (* argv)) 
	{ 
		if (! hexencode (channel.peer, sizeof (channel.peer), synonym (* argv, devices, SIZEOF (devices)))) 
		{ 
			error (1, errno, PLC_BAD_MAC, * argv); 
		} 
		argc--; 
		argv++; 
	} 
	if ((argc) || (* argv))
	{
		error (1, ENOTSUP, ERROR_TOOMANY);
	}
	else if (timer) 
	{ 
		plc.action = ADCCAP_ACTION_GRAB; 
		capture (& plc); 
		error (0, 0, "pause %d seconds ...", timer); 
		sleep (timer); 
		plc.action = ADCCAP_ACTION_READ; 
		collect (& plc); 
	} 
	else if (plc.action == ADCCAP_ACTION_READ) 
	{ 
		collect (& plc); 
	} 
	else if (plc.action == ADCCAP_ACTION_GRAB) 
	{ 
		capture (& plc); 
	} 
	else if (plc.action == ADCCAP_ACTION_SYNC) 
	{ 
		capture (& plc); 
	} 
	else 
	{ 
		error (1, EINVAL, "Bad command"); 
	} 
	free (plc.content); 
	free (plc.message); 
	closechannel (& channel); 
	exit (0); 
} 

