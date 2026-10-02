/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   plctone.c - Qualcomm Atheros INT6x00 Tone Map Dump Utility
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

/*====================================================================*
 *   system header files;
 *--------------------------------------------------------------------*/

#include <limits.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>

/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

#include "../tools/getoptv.h"
#include "../tools/putoptv.h"
#include "../tools/memory.h"
#include "../tools/symbol.h"
#include "../tools/number.h"
#include "../tools/types.h"
#include "../tools/flags.h"
#include "../tools/files.h"
#include "../tools/error.h"
#include "../plc/plc.h"

/*====================================================================*
 *   custom source files;
 *--------------------------------------------------------------------*/

#ifndef MAKEFILE
#include "../plc/Devices.c"
#include "../plc/Failure.c"
#include "../plc/ReadMME.c"
#include "../plc/SendMME.c"
#include "../plc/mod2bits.c"
#include "../plc/mod2db.c"
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
#include "../mme/QualcommHeader.c"
#include "../mme/UnwantedMessage.c"
#endif

/*====================================================================*
 *
 *   signed thunderbolt_tonemaps (struct plc * plc);
 *
 *   plc.h
 *
 *   See the Atheros HomePlug AV Firmware Technical Reference Manual
 *   for more information;
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

signed thunderbolt_tonemaps (struct plc * plc)

{
	extern uint8_t const mod2bits [PLC_BITS_PER_TONE];
	struct channel * channel = (struct channel *) (plc->channel);
	struct message * message = (struct message *) (plc->message);
	byte tonemap [PLC_TIME_SLOTS] [INT_CARRIERS >> 1];
	uint16_t carriers = 0;
	uint16_t carrier = 0;
	uint8_t slots = 0;
	uint8_t slot = 0;

#ifndef __GNUC__
#pragma pack (push,1)
#endif

	struct __packed vs_tone_slot_char_request
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
		uint8_t MACADDRESS [ETHER_ADDR_LEN];
		uint8_t TMSLOT;
	}
	* request = (struct vs_tone_slot_char_request *) (message);
	struct __packed vs_tone_slot_char_confirm
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
		uint8_t MSTATUS;
		uint8_t TMSLOT;
		uint8_t NUMTMS;
		uint16_t TMNUMACTCARRIERS;
		uint8_t MOD_CARRIER [INT_CARRIERS / 2];
		uint8_t GIL;
		uint8_t AGC;
	}
	* confirm = (struct vs_tone_slot_char_confirm *) (message);

#ifndef __GNUC__
#pragma pack (pop)
#endif

	memset (message, 0, sizeof (* message));
	EthernetHeader (& request->ethernet, channel->peer, channel->host, channel->type);
	QualcommHeader (& request->qualcomm, 0, (VS_RX_TONE_MAP_CHAR | MMTYPE_REQ));
	memcpy (request->MACADDRESS, plc->RDA, sizeof (request->MACADDRESS));
	request->TMSLOT = 0;
	plc->packetsize = (ETHER_MIN_LEN - ETHER_CRC_LEN);
	if (SendMME (plc) <= 0)
	{
		error (PLC_EXIT (plc), errno, CHANNEL_CANTSEND);
		return (-1);
	}
	if (ReadMME (plc, 0, (VS_RX_TONE_MAP_CHAR | MMTYPE_CNF)) <= 0)
	{
		error (PLC_EXIT (plc), errno, CHANNEL_CANTREAD);
		return (-1);
	}
	carriers = LE16TOH (confirm->TMNUMACTCARRIERS);
	slots = confirm->NUMTMS;
	if (! slots)
	{
		error (PLC_EXIT (plc), ECANCELED, "No Tone Maps Available");
		return (-1);
	}
	memset (tonemap, 0, sizeof (tonemap));
	for (slot = 0; slot < slots; slot++)
	{
		EthernetHeader (& request->ethernet, channel->peer, channel->host, channel->type);
		QualcommHeader (& request->qualcomm, 0, (VS_RX_TONE_MAP_CHAR | MMTYPE_REQ));
		memcpy (request->MACADDRESS, plc->RDA, sizeof (request->MACADDRESS));
		request->TMSLOT = slot;
		plc->packetsize = (ETHER_MIN_LEN - ETHER_CRC_LEN);
		if (SendMME (plc) <= 0)
		{
			error (PLC_EXIT (plc), errno, CHANNEL_CANTSEND);
			return (-1);
		}
		if (ReadMME (plc, 0, (VS_RX_TONE_MAP_CHAR | MMTYPE_CNF)) <= 0)
		{
			error (PLC_EXIT (plc), errno, CHANNEL_CANTREAD);
			return (-1);
		}
		if (confirm->MSTATUS)
		{
			Failure (plc, PLC_WONTDOIT);
			return (-1);
		}
		memcpy (& tonemap [slot] [0], confirm->MOD_CARRIER, sizeof (confirm->MOD_CARRIER));
	}
	while (carrier < carriers)
	{
		unsigned value = 0;
		unsigned scale = 0;
		unsigned index = carrier >> 1;
		printf ("% 04d", carrier);
		for (slot = 0; slot < PLC_TIME_SLOTS; slot++)
		{
			value = tonemap [slot] [index];
			if ((carrier & 1))
			{
				value >>= 4;
			}
			value &= 0x0F;
			printf (" %02d", mod2bits [value]);
			value *= value;
			scale += value;
		}
		if (slots)
		{
			scale /= slots;
		}
		if (_anyset (plc->flags, PLC_GRAPH))
		{
			printf (" %03d ", scale);
			while (scale--)
			{
				printf ("#");
			}
		}
		printf ("\n");
		carrier++;
	}
	return (0);
}

/*====================================================================*
 *
 *   signed thunderbolt_snrdata (struct plc * plc);
 *
 *   plc.h
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

signed thunderbolt_snrdata (struct plc * plc)

{
	extern uint8_t const mod2db [PLC_BITS_PER_TONE];
	extern uint8_t const mod2bits [PLC_BITS_PER_TONE];
	struct channel * channel = (struct channel *) (plc->channel);
	struct message * message = (struct message *) (plc->message);
	struct tonemap
	{
		byte GIL;
		byte AGC;
		double SNR;
		double BPC;
		byte DATA [AMP_CARRIERS >> 1];
	}
	tonemap [PLC_TIME_SLOTS];
	double AvgSNR = 0;
	double AvgBPC = 0;
	unsigned carriers = 0;
	unsigned carrier = 0;
	unsigned slots = 0;
	unsigned slot = 0;

#ifndef __GNUC__
#pragma pack (push,1)
#endif

	struct __packed vs_tone_slot_char_request
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
		uint8_t MACADDRESS [ETHER_ADDR_LEN];
		uint8_t TMSLOT;
	}
	* request = (struct vs_tone_slot_char_request *) (message);
	struct __packed vs_tone_slot_char_confirm
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
		uint8_t MSTATUS;
		uint8_t TMSLOT;
		uint8_t NUMTMS;
		uint16_t TMNUMACTCARRIERS;
		uint8_t MOD_CARRIER [(INT_CARRIERS +  1) >> 1];
		uint8_t GIL;
		uint8_t AGC;
	}
	* confirm = (struct vs_tone_slot_char_confirm *) (message);

#ifndef __GNUC__
#pragma pack (pop)
#endif

	memset (message, 0, sizeof (* message));
	EthernetHeader (& request->ethernet, channel->peer, channel->host, channel->type);
	QualcommHeader (& request->qualcomm, 0, (VS_RX_TONE_MAP_CHAR | MMTYPE_REQ));
	plc->packetsize = (ETHER_MIN_LEN - ETHER_CRC_LEN);
	memcpy (request->MACADDRESS, plc->RDA, sizeof (request->MACADDRESS));
	request->TMSLOT = 0;
	if (SendMME (plc) <= 0)
	{
		error (PLC_EXIT (plc), errno, CHANNEL_CANTSEND);
		return (-1);
	}
	if (ReadMME (plc, 0, (VS_RX_TONE_MAP_CHAR | MMTYPE_CNF)) <= 0)
	{
		error (PLC_EXIT (plc), errno, CHANNEL_CANTREAD);
		return (-1);
	}
	carriers = LE16TOH (confirm->TMNUMACTCARRIERS);
	slots = confirm->NUMTMS;
	if (! slots)
	{
		error (PLC_EXIT (plc), ECANCELED, "No Tone Maps Available");
		return (-1);
	}
	memset (tonemap, 0, sizeof (tonemap));
	for (slot = 0; slot < slots; slot++)
	{
		EthernetHeader (& request->ethernet, channel->peer, channel->host, channel->type);
		QualcommHeader (& request->qualcomm, 0, (VS_RX_TONE_MAP_CHAR | MMTYPE_REQ));
		memcpy (request->MACADDRESS, plc->RDA, sizeof (request->MACADDRESS));
		request->TMSLOT = slot;
		plc->packetsize = (ETHER_MIN_LEN - ETHER_CRC_LEN);
		if (SendMME (plc) <= 0)
		{
			error (PLC_EXIT (plc), errno, CHANNEL_CANTSEND);
			return (-1);
		}
		if (ReadMME (plc, 0, (VS_RX_TONE_MAP_CHAR | MMTYPE_CNF)) <= 0)
		{
			error (PLC_EXIT (plc), errno, CHANNEL_CANTREAD);
			return (-1);
		}
		if (confirm->MSTATUS)
		{
			Failure (plc, PLC_WONTDOIT);
			return (-1);
		}
		memcpy (& tonemap [slot].DATA [0], confirm->MOD_CARRIER, sizeof (confirm->MOD_CARRIER));
		tonemap [slot].GIL = confirm->GIL;
		tonemap [slot].AGC = confirm->AGC;
	}
	while (carrier < carriers)
	{
		unsigned value = 0;
		unsigned index = carrier >> 1;
		for (slot = 0; slot < PLC_TIME_SLOTS; slot++)
		{
			value = tonemap [slot].DATA [index];
			if ((carrier & 1))
			{
				value >>= 4;
			}
			value &= 0x0F;
			tonemap [slot].BPC += mod2bits [value];
			tonemap [slot].SNR += mod2db [value];
			AvgBPC += mod2bits [value];
			AvgSNR += mod2db [value];
		}
		carrier++;
	}
	AvgBPC /= carriers;
	AvgBPC /= slots;
	AvgSNR /= carriers;
	AvgSNR /= slots;
	printf (" SNR");
	for (slot = 0; slot < slots; slot++)
	{
		printf (" %8.3f", tonemap [slot].SNR / carriers);
	}
	printf (" %8.3f", AvgSNR);
	printf (" \n");
	printf (" ATN");
	for (slot = 0; slot < slots; slot++)
	{
		printf (" %8.3f", tonemap [slot].SNR / carriers - 60);
	}
	printf (" %8.3f", AvgSNR - 60);
	printf (" \n");
	printf (" BPC");
	for (slot = 0; slot < slots; slot++)
	{
		printf (" %8.3f", tonemap [slot].BPC / carriers);
	}
	printf (" %8.3f", AvgBPC);
	printf (" \n");
	printf (" AGC");
	for (slot = 0; slot < slots; slot++)
	{
		printf (" %02d", tonemap [slot].AGC);
	}
	printf (" \n");
	printf (" GIL");
	for (slot = 0; slot < slots; slot++)
	{
		printf (" %02d", tonemap [slot].GIL);
	}
	printf (" \n");
	return (0);
}

/*====================================================================*
 *
 *   int main (int argc, char const * argv[]);
 *
 *--------------------------------------------------------------------*/

int main (int argc, char const * argv [])

{
	extern struct channel channel;
	static char const * optv [] =
	{
		"ehi:qst:vx",
		"node peer [> stdout]",
		"Qualcomm Atheros INT6x00 Tone Map Dump Utility",
		"e\tredirect stderr to stdout",
		"h\tprint mean-square histogram",

#if defined (WINPCAP) || defined (LIBPCAP)

		"i n\thost interface is (n) [" LITERAL (CHANNEL_ETHNUMBER) "]",

#else

		"i s\thost interface is (s) [" LITERAL (CHANNEL_ETHDEVICE) "]",

#endif

		"q\tquiet mode",
		"s\tcompute signal-to-noise and bits-per-carrier ratios",
		"t n\tread timeout is (n) milliseconds [" LITERAL (CHANNEL_TIMEOUT) "]",
		"v\tverbose mode",
		"x\texit on error",
		(char const *) (0)
	};

#include "../plc/plc.c"

	signed (* function) (struct plc *) = thunderbolt_tonemaps;
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
	while (~ (c = getoptv (argc, argv, optv)))
	{
		switch (c)
		{
		case 'e':
			dup2 (STDOUT_FILENO, STDERR_FILENO);
			break;
		case 'h':
			_setbits (plc.flags, PLC_GRAPH);
			break;
		case 'i':

#if defined (WINPCAP) || defined (LIBPCAP)

			channel.ifindex = atoi (optarg);

#else

			channel.ifname = optarg;

#endif

			break;
		case 'q':
			_setbits (channel.flags, CHANNEL_SILENCE);
			_setbits (plc.flags, PLC_SILENCE);
			break;
		case 's':
			_setbits (plc.flags, PLC_ANALYSE);
			function = thunderbolt_snrdata;
			break;
		case 't':
			channel.timeout = (signed) (uintspec (optarg, 0, UINT_MAX));
			break;
		case 'v':
			_setbits (channel.flags, CHANNEL_VERBOSE);
			_setbits (plc.flags, PLC_VERBOSE);
			break;
		case 'x':
			_setbits (plc.flags, PLC_BAILOUT);
			break;
		default: 
			break;
		}
	}
	argc -= optind;
	argv += optind;
	if (! argc || ! argv)
	{
		error (1, ECANCELED, "No node address given");
	}
	if (! hexencode (channel.peer, sizeof (channel.peer), synonym (* argv, devices, SIZEOF (devices))))
	{
		error (1, errno, PLC_BAD_MAC, * argv);
	}
	argc--;
	argv++;
	if (! argc || ! argv)
	{
		error (1, ECANCELED, "No peer address given");
	}
	if (! hexencode (plc.RDA, sizeof (plc.RDA), synonym (* argv, devices, SIZEOF (devices))))
	{
		error (1, errno, PLC_BAD_MAC, * argv);
	}
	argc--;
	argv++;
	openchannel (& channel);
	if (! (plc.message = malloc (sizeof (* plc.message))))
	{
		error (1, errno, PLC_NOMEMORY);
	}
	function (& plc);
	free (plc.message);
	closechannel (& channel);
	return (0);
}

