/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   chtone.c -
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

/*====================================================================*
 *   system header files;
 *--------------------------------------------------------------------*/

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <limits.h>

/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

#include "../tools/getoptv.h"
#include "../tools/putoptv.h"
#include "../tools/memory.h"
#include "../tools/symbol.h"
#include "../tools/number.h"
#include "../tools/endian.h"
#include "../tools/types.h"
#include "../tools/flags.h"
#include "../tools/files.h"
#include "../tools/error.h"
#include "../tools/tlv.h"
#include "../plc/plc.h"
#include "../mme/mme.h"

/*====================================================================*
 *   custom source files;
 *--------------------------------------------------------------------*/

#ifndef MAKEFILE
#include "../plc/Devices.c"
#include "../plc/Failure.c"
#include "../plc/ReadMME.c"
#include "../plc/ReadFMI.c"
#include "../plc/SendMME.c"
#include "../plc/mod2bits.c"
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
#include "../mme/EthernetHeader.c"
#include "../mme/QualcommHeader1.c"
#include "../mme/UnwantedMessage.c"
#include "../mme/MMECode.c"
#endif

/*====================================================================*
 *   program constants;
 *--------------------------------------------------------------------*/

#define SECRETS 1
#define PRECODES 1

#define CHTONE_TONEMAP (1 << 0)
#define CHTONE_PRIMARY (1 << 1)
#define CHTONE_ALTERNATE (1 << 2)
#define CHTONE_PRECODING (1 << 3)

#define PRECODE_ANGLE_PSI(angle) 	((angle >> 0) & 0x1F) 
#define PRECODE_ANGLE_THETA(angle)	((angle >> 8) & 0x7F) 

/*====================================================================*
 *   program variables;
 *--------------------------------------------------------------------*/

#ifndef __GNUC__
#pragma pack (push,1)
#endif

struct slotinfo

{

#if defined (SECRETS)

	struct secrets
	{
		uint8_t RESERVED1;
		uint8_t RESERVED2;
		uint8_t RESERVED3;
		uint32_t RESERVED4;
		uint8_t RESERVED5;
		uint8_t RESERVED6;
	}
	secrets;

#endif

	struct tonemap
	{
		uint8_t RESERVED [7];
		uint8_t AVG_AGC_GAIN;
		uint32_t NUMCARRIERS;
		uint32_t NUM_BYTES;
		uint8_t DATA [CHEETAH_CARRIERS];
	}
	tonemap0,
	tonemap1;
	struct precode
	{
		uint8_t RESERVED [7];
		uint8_t GROUPING;
		uint32_t NUM_BYTES;
		uint16_t DATA [CHEETAH_PRECODES];
	}
	precode;
}

slotinfo [PLC_TIME_SLOTS];

#ifndef __GNUC__
#pragma pack (pop)
#endif

/*====================================================================*
 *
 *   void CheetahSecrets (const struct slotinfo * slotinfo, uint8_t slots);
 *
 *--------------------------------------------------------------------*/

#if defined (SECRETS) 

static void CheetahSecrets (const struct slotinfo * slotinfo, uint8_t slots)

{
	uint8_t slot;
	printf ("RESERVED1");
	for (slot = 0; slot < PLC_TIME_SLOTS; ++ slot)
	{
		printf (",%d", slotinfo [slot].secrets.RESERVED1);
	}
	printf ("\n");
	printf ("RESERVED2");
	for (slot = 0; slot < PLC_TIME_SLOTS; ++ slot)
	{
		printf (",%d", slotinfo [slot].secrets.RESERVED2);
	}
	printf ("\n");
	printf ("RESERVED3");
	for (slot = 0; slot < PLC_TIME_SLOTS; ++ slot)
	{
		printf (",%d", slotinfo [slot].secrets.RESERVED3);
	}
	printf ("\n");
	printf ("RESERVED4");
	for (slot = 0; slot < PLC_TIME_SLOTS; ++ slot)
	{
		printf (",%d", slotinfo [slot].secrets.RESERVED4);
	}
	printf ("\n");
	printf ("\n");
	return;
}

#endif

/*====================================================================*
 *
 *   void CheetahPrecode (const struct slotinfo * slotinfo, uint8_t slots);
 *
 *--------------------------------------------------------------------*/

static void CheetahPrecode (const struct slotinfo * slotinfo, uint8_t slots)

{
	uint8_t slot;
	uint16_t index;
	printf ("GRP");
	for (slot = 0; slot < PLC_TIME_SLOTS; ++ slot)
	{
		printf (",%3d", slotinfo [slot].precode.GROUPING);
	}
	printf ("\n");
	for (index = 0; index < CHEETAH_PRECODES; ++ index)
	{
		printf ("%03d", index);
		for (slot = 0; slot < slots; ++ slot)
		{
			uint16_t angle = LE16TOH (slotinfo [slot].precode.DATA [index]);
			printf (",%3d", PRECODE_ANGLE_PSI (angle));
		}
		printf ("\n");
	}
	printf ("\n");
	printf ("GRP");
	for (slot = 0; slot < PLC_TIME_SLOTS; ++ slot)
	{
		printf (",%3d", slotinfo [slot].precode.GROUPING);
	}
	printf ("\n");
	for (index = 0; index < CHEETAH_PRECODES; ++ index)
	{
		printf ("%03d", index);
		for (slot = 0; slot < slots; ++ slot)
		{
			uint16_t angle = LE16TOH (slotinfo [slot].precode.DATA [index]);
			printf (",%3d", PRECODE_ANGLE_THETA (angle));
		}
		printf ("\n");
	}
	printf ("\n");
	return;
}

/*====================================================================*
 *
 *   void CheetahTonemap (const struct slotinfo * slotinfo, uint8_t slots);
 *
 *--------------------------------------------------------------------*/

static void CheetahTonemap (const struct slotinfo * slotinfo, uint8_t slots, uint16_t carriers)

{
	uint8_t slot;
	uint16_t carrier;
	for (carrier = 0; carrier < carriers; carrier++)
	{
		uint16_t value = 0;
		uint16_t scale = 0;
		uint16_t index = carrier >> 1;
		printf ("%04d", carrier);
		for (slot = 0; slot < slots; slot++)
		{
			value = slotinfo [slot].tonemap0.DATA [index];
			if ((carrier & 1))
			{
				value >>= 4;
			}
			value &= 0x0F;
			if (value < PLC_BITS_PER_TONE)
			{
				printf (",%02d", mod2bits [value]);
				value *= value;
				scale += value;
			}
		}
		for (slot = 0; slot < slots; slot++)
		{
			value = slotinfo [slot].tonemap1.DATA [index];
			if ((carrier & 1))
			{
				value >>= 4;
			}
			value &= 0x0F;
			if (value < PLC_BITS_PER_TONE)
			{
				printf (",%02d", mod2bits [value]);
				value *= value;
			}
		}
		printf ("\n");
	}
	printf ("\n");
	return;
}

/*====================================================================*
 *
 *   signed CheetahTonemap1 (struct plc * plc, struct slotinfo * slotinfo, uint8_t slots, uint16_t carriers);
 *
 *   plc.h
 *
 *   collect cheetah tonemaps using one or more VS_TONE_MAP_CHAR
 *   messages;
 *
 *--------------------------------------------------------------------*/

static signed CheetahTonemap1 (struct plc * plc, struct slotinfo * slotinfo, uint8_t slots, uint16_t carriers)

{
	struct channel * channel = (struct channel *) (plc->channel);
	struct message * message = (struct message *) (plc->message);

#ifndef __GNUC__
#pragma pack (push,1)
#endif

	struct __packed vs_tonemap_char_request
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_fmi qualcomm;
		uint8_t MME_SUBVER;
		uint8_t RESERVED1 [3];
		uint8_t MACADDRESS [ETHER_ADDR_LEN];
		uint8_t TMSLOT;
		uint8_t TONEMAP_TYPE;
	}
	* request = (struct vs_tonemap_char_request *) (message);
	struct __packed vs_tonemap_char_confirm
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_fmi qualcomm;
		uint8_t MSTATUS;
		uint8_t RESERVED1;
		uint16_t MME_LEN;
		uint8_t MME_SUBVER;
		uint8_t RESERVED2;
		uint8_t MACADDRESS [6];
		uint8_t TMSLOT;
		uint8_t TONEMAP_TYPE;
		uint8_t NUMTMS;
		uint8_t RESERVED3;
		uint16_t TMNUMACTCARRIERS;
		uint32_t RESERVED4;
		uint8_t DATA [1];
	}
	* confirm = (struct vs_tonemap_char_confirm *) (message);

#ifndef __GNUC__
#pragma pack (pop)
#endif

	uint8_t slot;
	memset (slotinfo, 0, sizeof (* slotinfo));
	for (slot = 0; slot < slots; slot++)
	{
		memset (message, 0, sizeof (* message));
		EthernetHeader (& request->ethernet, channel->peer, channel->host, channel->type);
		QualcommHeader1 (& request->qualcomm, 1, (VS_TONE_MAP_CHAR | MMTYPE_REQ));
		plc->packetsize = (ETHER_MIN_LEN - ETHER_CRC_LEN);
		memcpy (request->MACADDRESS, plc->RDA, sizeof (request->MACADDRESS));
		request->TMSLOT = slot;
		request->TONEMAP_TYPE = plc->coupling;
		if (SendMME (plc) <= 0)
		{
			error (1, errno, CHANNEL_CANTSEND);
		}
		if (ReadFMI (plc, 1, (VS_TONE_MAP_CHAR | MMTYPE_CNF)) <= 0)
		{
			error (1, errno, CHANNEL_CANTREAD);
		}
		confirm = (struct vs_tonemap_char_confirm *) (plc->content);
		if (confirm->MSTATUS)
		{
			error (1, 0, "Device refused request for slot %d: %s", slot, MMECode (VS_TONE_MAP_CHAR | MMTYPE_CNF, confirm->MSTATUS));
		}
		slots = confirm->NUMTMS;

#if defined (SECRETS)

		slotinfo [slot].secrets.RESERVED1 = confirm->RESERVED1;
		slotinfo [slot].secrets.RESERVED2 = confirm->RESERVED2;
		slotinfo [slot].secrets.RESERVED3 = confirm->RESERVED3;
		slotinfo [slot].secrets.RESERVED4 = confirm->RESERVED4;

#endif

		if (confirm->TONEMAP_TYPE == 0)
		{
			memcpy (& slotinfo [slot].tonemap0.DATA, confirm->DATA, LE16TOH (confirm->TMNUMACTCARRIERS));
			confirm = (struct vs_tonemap_char_confirm *) (message);
			free (plc->content);
			plc->content = NULL;
			continue;
		}
		if (confirm->TONEMAP_TYPE == 1)
		{
			memcpy (& slotinfo [slot].tonemap1.DATA, confirm->DATA, LE16TOH (confirm->TMNUMACTCARRIERS));
			confirm = (struct vs_tonemap_char_confirm *) (message);
			free (plc->content);
			plc->content = NULL;
			continue;
		}
		if (confirm->TONEMAP_TYPE == 2)
		{
			struct cheetah_chain_header
			{
				uint32_t size;
				uint32_t data;
			}
			* header = (struct cheetah_chain_header *) (confirm->DATA);
			uint32_t length = LE32TOH (header->size);
			uint8_t * offset = (uint8_t *) (& header->data);
			while (length)
			{
				struct TLVNode * node = (struct TLVNode *) (offset);
				uint32_t type = LE32TOH (node->type);
				uint32_t size = LE32TOH (node->size);
				if (type == 0)
				{
					memcpy (& slotinfo [slot].tonemap0, & node->data, size);
				}
				else if (type == 1)
				{
					memcpy (& slotinfo [slot].tonemap1, & node->data, size);
				}
				else if (type == 2)
				{
					memcpy (& slotinfo [slot].precode, & node->data, size);
				}
				length -= TLVSPAN (node);
				offset += TLVSPAN (node);
			}
			confirm = (struct vs_tonemap_char_confirm *) (message);
			free (plc->content);
			plc->content = NULL;
			continue;
		}
		error (1, 0, "Unknown Tonemap Type %d", confirm->TONEMAP_TYPE);
	}

#if defined (SECRETS)

	CheetahSecrets (slotinfo, slots);
	CheetahTonemap (slotinfo, slots, carriers);
	CheetahPrecode (slotinfo, slots);
#else
	CheetahTonemap (slotinfo, slots, carriers);
#endif

	return (0);
}

/*====================================================================*
 *
 *   signed CheetahTonemap2 (struct plc * plc, struct slotinfo * slotinfo, uint8_t slots, uint16_t carriers);
 *
 *   plc.h
 *
 *   collect cheetah tonemaps using one or more VS_RX_TONE_MAP_CHAR
 *   messages;
 *
 *--------------------------------------------------------------------*/

static signed CheetahTonemap2 (struct plc * plc, struct slotinfo * slotinfo, uint8_t slots, uint16_t carriers)

{
	struct channel * channel = (struct channel *) (plc->channel);
	struct message * message = (struct message *) (plc->message);

#ifndef __GNUC__
#pragma pack (push,1)
#endif

	struct __packed vs_rx_tonemap_char_request
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_fmi qualcomm;
		uint8_t MME_SUBVER;
		uint8_t RESERVED1 [3];
		uint8_t MACADDRESS [ETHER_ADDR_LEN];
		uint8_t TMSLOT;
		uint8_t TONEMAP_TYPE;
	}
	* request = (struct vs_rx_tonemap_char_request *) (message);
	struct __packed vs_rx_tonemap_char_confirm
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_fmi qualcomm;
		uint8_t MSTATUS;
		uint8_t RESERVED1;
		uint16_t MME_LEN;
		uint8_t MME_SUBVER;
		uint8_t RESERVED2;
		uint8_t MACADDRESS [6];
		uint8_t TMSLOT;
		uint8_t TONEMAP_TYPE;
		uint8_t NUMTMS;
		uint8_t RESERVED3;
		uint16_t TMNUMACTCARRIERS;
		uint32_t RESERVED4;
		uint8_t GIL;
		uint8_t RESERVED5;
		uint8_t AVG_ACG_GAIN;
		uint8_t RESERVED6;
		uint8_t DATA [1];
	}
	* confirm = (struct vs_rx_tonemap_char_confirm *) (message);

#ifndef __GNUC__
#pragma pack (pop)
#endif

	uint8_t slot;
	memset (slotinfo, 0, sizeof (* slotinfo));
	for (slot = 0; slot < slots; slot++)
	{
		memset (message, 0, sizeof (* message));
		EthernetHeader (& request->ethernet, channel->peer, channel->host, channel->type);
		QualcommHeader1 (& request->qualcomm, 1, (VS_RX_TONE_MAP_CHAR | MMTYPE_REQ));
		plc->packetsize = (ETHER_MIN_LEN - ETHER_CRC_LEN);
		memcpy (request->MACADDRESS, plc->RDA, sizeof (request->MACADDRESS));
		request->TMSLOT = slot;
		request->TONEMAP_TYPE = plc->coupling;
		if (SendMME (plc) <= 0)
		{
			error (1, errno, CHANNEL_CANTSEND);
		}
		if (ReadFMI (plc, 1, (VS_RX_TONE_MAP_CHAR | MMTYPE_CNF)) <= 0)
		{
			error (1, errno, CHANNEL_CANTREAD);
		}
		confirm = (struct vs_rx_tonemap_char_confirm *) (plc->content);
		if (confirm->MSTATUS)
		{
			error (1, 0, "Device refused request for slot %d: %s", slot, MMECode (VS_RX_TONE_MAP_CHAR | MMTYPE_CNF, confirm->MSTATUS));
		}
		slots = confirm->NUMTMS;

#if defined (SECRETS)

		slotinfo [slot].secrets.RESERVED1 = confirm->RESERVED1;
		slotinfo [slot].secrets.RESERVED2 = confirm->RESERVED2;
		slotinfo [slot].secrets.RESERVED3 = confirm->RESERVED3;
		slotinfo [slot].secrets.RESERVED4 = confirm->RESERVED4;
		slotinfo [slot].secrets.RESERVED5 = confirm->RESERVED5;
		slotinfo [slot].secrets.RESERVED6 = confirm->RESERVED6;

#endif

		if (confirm->TONEMAP_TYPE == 0)
		{
			memcpy (& slotinfo [slot].tonemap0.DATA, confirm->DATA, LE16TOH (confirm->TMNUMACTCARRIERS));
			confirm = (struct vs_rx_tonemap_char_confirm *) (message);
			free (plc->content);
			plc->content = NULL;
			continue;
		}
		if (confirm->TONEMAP_TYPE == 1)
		{
			memcpy (& slotinfo [slot].tonemap1.DATA, confirm->DATA, LE16TOH (confirm->TMNUMACTCARRIERS));
			confirm = (struct vs_rx_tonemap_char_confirm *) (message);
			free (plc->content);
			plc->content = NULL;
			continue;
		}
		if (confirm->TONEMAP_TYPE == 2)
		{
			struct cheetah_chain_header
			{
				uint32_t size;
				uint32_t data;
			}
			* header = (struct cheetah_chain_header *) (confirm->DATA);
			uint32_t length = LE32TOH (header->size);
			uint8_t * offset = (uint8_t *) (& header->data);
			while (length)
			{
				struct TLVNode * node = (struct TLVNode *) (offset);
				uint32_t type = LE32TOH (node->type);
				uint32_t size = LE32TOH (node->size);
				if (type == 0)
				{
					memcpy (& slotinfo [slot].tonemap0, & node->data, size);
				}
				else if (type == 1)
				{
					memcpy (& slotinfo [slot].tonemap1, & node->data, size);
				}
				else if (type == 2)
				{
					memcpy (& slotinfo [slot].precode, & node->data, size);
				}
				length -= TLVSPAN (node);
				offset += TLVSPAN (node);
			}
			confirm = (struct vs_rx_tonemap_char_confirm *) (message);
			free (plc->content);
			plc->content = NULL;
			continue;
		}
		error (1, 0, "Unknown Tonemap Type %d", confirm->TONEMAP_TYPE);
	}
	printf (" AGC");
	for (slot = 0; slot < slots; slot++)
	{
		printf (",%02d", slotinfo [slot].tonemap0.AVG_AGC_GAIN);
	}
	for (slot = 0; slot < slots; slot++)
	{
		printf (",%02d", slotinfo [slot].tonemap1.AVG_AGC_GAIN);
	}
	printf ("\n");

#if defined (SECRETS)

	CheetahSecrets (slotinfo, slots);
	CheetahTonemap (slotinfo, slots, carriers);
	CheetahPrecode (slotinfo, slots);

#else

	CheetahTonemap (slotinfo, slots, carriers);

#endif

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
		"c:ei:qrt:vx",
		"node peer [> stdout]",
		"Qualcomm Atheros QCA7500 Tone Map Monitor",
		"c n\tcoupling [" LITERAL (PLCOUPLING) "]",
		"e\tredirect stderr to stdout",

#if defined (WINPCAP) || defined (LIBPCAP)

		"i n\thost interface is (n) [" LITERAL (CHANNEL_ETHNUMBER) "]",

#else

		"i s\thost interface is (s) [" LITERAL (CHANNEL_ETHDEVICE) "]",

#endif

		"q\tquiet mode",
		"r\tdisplay VS_RX_TONE_MAP AGC and tone map data on stdout",
		"t n\tread timeout is (n) milliseconds [" LITERAL (CHANNEL_TIMEOUT) "]",
		"v\tverbose mode",
		"x\texit on error",
		(char const *) (0)
	};
	static const struct _term_ coupling [] =
	{
		{
			"alt",
			"1"
		},
		{
			"mimo",
			"0"
		},
		{
			"pri",
			"0"
		}
	};

#include "../plc/plc.c"

	signed (* function) (struct plc *, struct slotinfo *, uint8_t, uint16_t) = CheetahTonemap1;
	uint16_t carriers = CHEETAH_CARRIERS;
	uint8_t slots = PLC_TIME_SLOTS;
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
		case 'c':
			plc.coupling = (byte) (uintspec (synonym (optarg, coupling, SIZEOF (coupling)), 0, UCHAR_MAX));
			break;
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
		case 'r':
			function = CheetahTonemap2;
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
	function (& plc, slotinfo, slots, carriers);
	free (plc.content);
	free (plc.message);
	closechannel (& channel);
	return (0);
}

