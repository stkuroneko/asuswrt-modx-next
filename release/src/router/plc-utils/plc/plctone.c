/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   plctone.c -
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

#define DIR (sizeof (direction) / sizeof (struct _term_))

/*====================================================================*
 *   program variables;
 *--------------------------------------------------------------------*/
#if 0
static const struct _term_ direction [] =

{
    {
        "tx_rx",
        "0"
    },
    {
        "tx",
        "1"
    },
    {
        "rx",
        "2"
    }
    
};
#endif

/*====================================================================*
 *
 *   signed ToneMaps2 (struct plc * plc);
 *
 *   plc.h
 *
 *   read and print lighting tonemap data on stdout;
 *
 *--------------------------------------------------------------------*/

signed ToneMaps2 (struct plc * plc)

{
	extern uint8_t const mod2bits [PLC_BITS_PER_TONE];
	uint8_t tonemap [PLC_TIME_SLOTS +  1] [AMP_CARRIERS >> 1];
	struct channel * channel = (struct channel *) (plc->channel);
	struct message * message = (struct message *) (plc->message);
	uint16_t extent = 0;
	uint16_t carriers = AMP_CARRIERS;
	uint16_t carrier = 0;
	uint8_t slots = PLC_TIME_SLOTS;
	uint8_t slot = 0;

#ifndef __GNUC__
#pragma pack (push,1)
#endif

	struct __packed vs_tonemap_char_request
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_fmi qualcomm;
		uint8_t MME_SUBVER;
		uint8_t Reserved1 [3];
		uint8_t MACADDRESS [ETHER_ADDR_LEN];
		uint8_t TMSLOT;
		uint8_t COUPLING;
	}
	* request = (struct vs_tonemap_char_request *) (message);
	struct __packed vs_tonemap_char_confirm
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_fmi qualcomm;
		uint8_t MSTATUS;
		uint8_t Reserved1;
		uint16_t MME_LEN;
		struct __packed vs_tonemap_char_header
		{
			uint8_t MME_SUBVER;
			uint8_t Reserved2;
			uint8_t MACADDRESS [6];
			uint8_t TMSLOT;
			uint8_t COUPLING;
			uint8_t NUMTMS;
			uint8_t Reserved4;
			uint16_t TMNUMACTCARRIERS;
			uint16_t Reserved5;
			uint16_t NUMCARRIERS;
			uint16_t Reserved6;
			uint32_t Reserved7;
		}
		header;
		uint8_t MOD_CARRIER [1];
	}
	* confirm = (struct vs_tonemap_char_confirm *) (message);
	struct __packed vs_tonemap_char_fragment
	{
		struct ethernet_hdr ethernet;
		struct homeplug_fmi qualcomm;
		uint8_t MOD_CARRIER [1];
	}
	* fragment = (struct vs_tonemap_char_fragment *) (message);

#ifndef __GNUC__
#pragma pack (pop)
#endif

	memset (tonemap, 0, sizeof (tonemap));
	for (carrier = slot = 0; slot < slots; carrier = 0, slot++)
	{
		memset (message, 0, sizeof (* message));
		EthernetHeader (& request->ethernet, channel->peer, channel->host, channel->type);
		QualcommHeader1 (& request->qualcomm, 1, (VS_TONE_MAP_CHAR | MMTYPE_REQ));
		plc->packetsize = (ETHER_MIN_LEN - ETHER_CRC_LEN);
		memcpy (request->MACADDRESS, plc->RDA, sizeof (request->MACADDRESS));
		request->TMSLOT = slot;
		request->COUPLING = plc->coupling;
		if (SendMME (plc) <= 0)
		{
			error (PLC_EXIT (plc), errno, CHANNEL_CANTSEND);
			return (-1);
		}
		if (ReadMME (plc, 1, (VS_TONE_MAP_CHAR | MMTYPE_CNF)) <= 0)
		{
			error (PLC_EXIT (plc), errno, CHANNEL_CANTREAD);
			return (-1);
		}
		if (confirm->MSTATUS)
		{
			error (1, 0, "Device refused request for slot %d: %s", slot, MMECode (VS_TONE_MAP_CHAR | MMTYPE_CNF, confirm->MSTATUS));
		}
		carriers = LE16TOH (confirm->header.TMNUMACTCARRIERS);
		slots = confirm->header.NUMTMS;
		extent = LE16TOH (confirm->MME_LEN) - sizeof (struct vs_tonemap_char_header);
		if (extent > (AMP_CARRIERS >> 1))
		{
			error (1, EOVERFLOW, "Too many carriers");
		}
		plc->packetsize -= sizeof (struct vs_tonemap_char_confirm);
		plc->packetsize += sizeof (confirm->MOD_CARRIER);
		if (plc->packetsize > extent)
		{
			plc->packetsize = extent;
		}
		memcpy (& tonemap [slot] [carrier], & confirm->MOD_CARRIER, plc->packetsize);
		carrier += plc->packetsize;
		extent -= plc->packetsize;
		while (extent)
		{
			if (ReadMME (plc, 1, (VS_TONE_MAP_CHAR | MMTYPE_CNF)) <= 0)
			{
				error (1, errno, CHANNEL_CANTREAD);
			}
			plc->packetsize -= sizeof (struct vs_tonemap_char_fragment);
			plc->packetsize += sizeof (fragment->MOD_CARRIER);
			if (plc->packetsize > extent)
			{
				plc->packetsize = extent;
			}
			memcpy (& tonemap [slot] [carrier], fragment->MOD_CARRIER, plc->packetsize);
			carrier += plc->packetsize;
			extent -= plc->packetsize;
		}
	}
	for (carrier = 0; carrier < carriers; carrier++)
	{
		uint16_t scale = 0;
		uint16_t value = 0;
		uint16_t index = carrier >> 1;
		printf ("%04d", carrier);
		for (slot = 0; slot < slots; slot++)
		{
			value = tonemap [slot] [index];
			if ((carrier & 1))
			{
				value >>= 4;
			}
			value &= 0x0F;
			printf (",%02d", mod2bits [value]);
			value *= value;
			scale += value;
		}
		if (slots)
		{
			scale /= slots;
		}
		printf (" %03d ", scale);
		if (_anyset (plc->flags, PLC_GRAPH))
		{
			while (scale--)
			{
				printf ("#");
			}
		}
		printf ("\n");
	}
	return (0);
}

/*====================================================================*
 *
 *   signed SignalToNoise2 (struct plc * plc);
 *
 *   plc.h
 *
 *   read lightning tonemap data; compute and print SNR values on
 *   stdout; the computed SNR values are approximate and should not
 *   be used for engineering, evaluation or commericial comparison;
 *
 *--------------------------------------------------------------------*/

signed SignalToNoise2 (struct plc * plc)

{
	extern uint8_t const mod2bits [PLC_BITS_PER_TONE];
	struct channel * channel = (struct channel *) (plc->channel);
	struct message * message = (struct message *) (plc->message);
	byte tonemap [PLC_TIME_SLOTS +  1] [AMP_CARRIERS >> 1];
	uint16_t GIL [PLC_TIME_SLOTS];
	uint16_t AGC [PLC_TIME_SLOTS];
	double SNR [PLC_TIME_SLOTS];
	double BPC [PLC_TIME_SLOTS];
	double AvgSNR;
	double AvgBPC;
	uint16_t extent = 0;
	uint16_t active = 0;
	uint16_t carriers = AMP_CARRIERS;
	uint16_t carrier = 0;
	uint8_t slots = PLC_TIME_SLOTS;
	uint8_t slot = 0;

#ifndef __GNUC__
#pragma pack (push,1)
#endif

	struct __packed vs_rx_tone_map_char_request
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_fmi qualcomm;
		uint8_t MME_SUBVER;
		uint8_t Reserved1 [3];
		uint8_t MACADDRESS [ETHER_ADDR_LEN];
		uint8_t TMSLOT;
		uint8_t COUPLING;
	}
	* request = (struct vs_rx_tone_map_char_request *) (message);
	struct __packed vs_rx_tonemap_char_confirm
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_fmi qualcomm;
		uint8_t MSTATUS;
		uint8_t Reserved1;
		uint16_t MME_LEN;
		uint8_t MME_SUBVER;
		uint8_t Reserved2;
		uint8_t MACADDR [6];
		uint8_t TMSLOT;
		uint8_t COUPLING;
		uint8_t NUMTMS;
		uint8_t Reserved4;
		uint16_t TMNUMACTCARRIERS;
		uint32_t Reserved6;
		uint8_t GIL;
		uint8_t Reserved7;
		uint8_t AGC;
		uint8_t Reserved8;
		uint8_t MOD_CARRIER [1];
	}
	* confirm = (struct vs_rx_tonemap_char_confirm *) (message);
	struct __packed vs_rx_tonemap_char_fragment
	{
		struct ethernet_hdr ethernet;
		struct homeplug_fmi qualcomm;
		uint8_t MOD_CARRIER [1];
	}
	* fragment = (struct vs_rx_tonemap_char_fragment *) (message);

#ifndef __GNUC__
#pragma pack (pop)
#endif

	memset (tonemap, 0, sizeof (tonemap));
	for (carrier = slot = 0; slot < slots; carrier = 0, slot++)
	{
		memset (message, 0, sizeof (* message));
		EthernetHeader (& request->ethernet, channel->peer, channel->host, channel->type);
		QualcommHeader1 (& request->qualcomm, 1, (VS_RX_TONE_MAP_CHAR | MMTYPE_REQ));
		memcpy (request->MACADDRESS, plc->RDA, sizeof (request->MACADDRESS));
		request->TMSLOT = slot;
		request->COUPLING = plc->coupling;
		plc->packetsize = (ETHER_MIN_LEN - ETHER_CRC_LEN);
		if (SendMME (plc) <= 0)
		{
			error (PLC_EXIT (plc), errno, CHANNEL_CANTSEND);
			return (-1);
		}
		if (ReadMME (plc, 1, (VS_RX_TONE_MAP_CHAR | MMTYPE_CNF)) <= 0)
		{
			error (PLC_EXIT (plc), errno, CHANNEL_CANTREAD);
			return (-1);
		}
		if (confirm->MSTATUS)
		{
			error (1, 0, "Device refused request for slot %d: %s", slot, MMECode (VS_RX_TONE_MAP_CHAR | MMTYPE_CNF, confirm->MSTATUS));
		}
		GIL [slot] = confirm->GIL;
		AGC [slot] = confirm->AGC;
		carriers = LE16TOH (confirm->TMNUMACTCARRIERS);
		slots = confirm->NUMTMS;
		extent = LE16TOH (confirm->MME_LEN) - 22;
		if (extent > (AMP_CARRIERS >> 1))
		{
			error (1, EOVERFLOW, "Too many carriers");
		}
		plc->packetsize -= sizeof (struct vs_rx_tonemap_char_confirm);
		plc->packetsize += sizeof (confirm->MOD_CARRIER);
		if (plc->packetsize > extent)
		{
			plc->packetsize = extent;
		}
		memcpy (& tonemap [slot] [carrier], & confirm->MOD_CARRIER, plc->packetsize);
		carrier += plc->packetsize;
		extent -= plc->packetsize;
		while (extent)
		{
			if (ReadMME (plc, 1, (VS_RX_TONE_MAP_CHAR | MMTYPE_CNF)) <= 0)
			{
				error (1, errno, CHANNEL_CANTREAD);
			}
			plc->packetsize -= sizeof (struct vs_rx_tonemap_char_fragment);
			plc->packetsize += sizeof (fragment->MOD_CARRIER);
			if (plc->packetsize > extent)
			{
				plc->packetsize = extent;
			}
			memcpy (& tonemap [slot] [carrier], fragment->MOD_CARRIER, plc->packetsize);
			carrier += plc->packetsize;
			extent -= plc->packetsize;
		}
	}
	carrier = 0;

/*
 *   LOW BANDS;
 */

	memset (BPC, 0, sizeof (BPC));
	memset (SNR, 0, sizeof (SNR));
	AvgBPC = 0;
	AvgSNR = 0;
	while (carrier < INT_CARRIERS)
	{
		unsigned value = 0;
		unsigned scale = 0;
		unsigned index = carrier >> 1;
		printf ("%04d", carrier);
		for (slot = 0; slot < slots; slot++)
		{
			value = tonemap [slot] [index];
			if ((carrier & 1))
			{
				value >>= 4;
			}
			value &= 0x0F;
			if (value > (PLC_BITS_PER_TONE -1))
			{
				error (0, EINVAL, "Index %d Slot %d Value %d", carrier, slot, value);
			}
			printf (",%02d", mod2bits [value]);
			BPC [slot] += mod2bits [value];
			SNR [slot] += mod2db [value];
			AvgBPC += mod2bits [value];
			AvgSNR += mod2db [value];
			value *= value;
			scale += value;
		}
		if (_anyset (plc->flags, PLC_GRAPH))
		{
			printf (" %03d ", scale);
			if (scale)
			{
				scale /= slots;
				while (scale--)
				{
					printf ("#");
				}
				active++;
			}
		}
		printf ("\n");
		carrier++;
	}
	AvgBPC /= active;
	AvgBPC /= slots;
	AvgSNR /= active;
	AvgSNR /= slots;
	printf (" SNR");
	for (slot = 0; slot < slots; slot++)
	{
		printf (",%8.3f", (float) (SNR [slot]) / active);
	}
	printf (",%8.3f", AvgSNR);
	printf (" \n");
	printf (" ATN");
	for (slot = 0; slot < slots; slot++)
	{
		printf (",%8.3f", (float) (SNR [slot]) / active - 60);
	}
	printf (",%8.3f", AvgSNR - 60);
	printf (" \n");
	printf (" BPC");
	for (slot = 0; slot < slots; slot++)
	{
		printf (",%8.3f", (float) (BPC [slot]) / active);
	}
	printf (",%8.3f", AvgBPC);
	printf (" \n");

/*
 *   HIGH BANDS;
 */

	memset (BPC, 0, sizeof (BPC));
	memset (SNR, 0, sizeof (SNR));
	AvgBPC = 0;
	AvgSNR = 0;
	while (carrier < carriers)
	{
		unsigned value = 0;
		unsigned scale = 0;
		unsigned index = carrier >> 1;
		printf ("%04d", carrier);
		for (slot = 0; slot < slots; slot++)
		{
			value = tonemap [slot] [index];
			if ((carrier & 1))
			{
				value >>= 4;
			}
			value &= 0x0F;
			if (value > (PLC_BITS_PER_TONE -1))
			{
				error (0, EINVAL, "Index %d Slot %d Value %d", carrier, slot, value);
			}
			printf (",%02d", mod2bits [value]);
			BPC [slot] += mod2bits [value];
			SNR [slot] += mod2db [value];
			AvgBPC += mod2bits [value];
			AvgSNR += mod2db [value];
			value *= value;
			scale += value;
		}
		if (_anyset (plc->flags, PLC_GRAPH))
		{
			printf (" %03d ", scale);
			if (scale)
			{
				scale /= slots;
				while (scale--)
				{
					printf ("#");
				}
			}
		}
		printf ("\n");
		carrier++;
		active++;
	}
	AvgBPC /= active;
	AvgBPC /= slots;
	AvgSNR /= active;
	AvgSNR /= slots;
	printf (" SNR");
	for (slot = 0; slot < slots; slot++)
	{
		printf (",%8.3f", (float) (SNR [slot]) / active);
	}
	printf (",%8.3f", AvgSNR);
	printf (" \n");
	printf (" ATN");
	for (slot = 0; slot < slots; slot++)
	{
		printf (",%8.3f", (float) (SNR [slot]) / active - 60);
	}
	printf (",%8.3f", AvgSNR - 60);
	printf (" \n");
	printf (" BPC");
	for (slot = 0; slot < slots; slot++)
	{
		printf (",%8.3f", (float) (BPC [slot]) / active);
	}
	printf (",%8.3f", AvgBPC);
	printf (" \n");
	printf (" AGC");
	for (slot = 0; slot < slots; slot++)
	{
		printf (",%02d", AGC [slot]);
	}
	printf (" \n");
	printf (" GIL");
	for (slot = 0; slot < slots; slot++)
	{
		printf (",%02d", GIL [slot]);
	}
	printf (" \n");
	return (0);
}


signed ProcessToneMapOperation (struct plc * plc)

{
    
    struct channel * channel = (struct channel *) (plc->channel);
    struct message * message = (struct message *) (plc->message);
    
#ifndef __GNUC__
#pragma pack (push,1)
#endif
    
    struct __packed vs_tonemap_op_request
    {
        struct ethernet_hdr ethernet;
        struct qualcomm_hdr qualcomm;
        uint8_t Mode;
        uint8_t Reserved1;
        uint8_t MACADDRESS [ETHER_ADDR_LEN];
        uint8_t DIRECTION;
    }
    * request = (struct vs_tonemap_op_request *) (message);
    struct __packed vs_tonemap_op_confirm
    {
        struct ethernet_hdr ethernet;
        struct qualcomm_hdr qualcomm;
        uint8_t MSTATUS;
    }
    * confirm = (struct vs_tonemap_op_confirm *) (message);
    
#ifndef __GNUC__
#pragma pack (pop)
#endif
  
    memset (message, 0, sizeof (* message));
    EthernetHeader (& request->ethernet, channel->peer, channel->host, channel->type);
    QualcommHeader (& request->qualcomm, 0, (VS_TONE_MAP_OPER | MMTYPE_REQ));
    plc->packetsize = (ETHER_MIN_LEN - ETHER_CRC_LEN);
    request->Mode = 0;
    request->DIRECTION = plc->pushbutton;
    memcpy (request->MACADDRESS, plc->RDA, sizeof (request->MACADDRESS));
    
    if (SendMME (plc) <= 0)
    {
        error (PLC_EXIT (plc), errno, CHANNEL_CANTSEND);
        return (-1);
    }
    if (ReadMME (plc, 0, (VS_TONE_MAP_OPER | MMTYPE_CNF)) <= 0)
    {
        error (PLC_EXIT (plc), errno, CHANNEL_CANTREAD);
        return (-1);
    }
    if (confirm->MSTATUS)
    {
        Failure (plc, PLC_WONTDOIT);
        return (-1);
    }
    if (confirm->MSTATUS == 1)
    {
        printf ("Unknown MACADDRESS");
        printf ("\n");
    }
    if (confirm->MSTATUS == 2)
    {
        printf ("No Necessary");
        printf ("\n");
    }
    if (confirm->MSTATUS == 3)
    {
        printf ("Unknown Direction");
        printf ("\n");
    }
    if (confirm->MSTATUS == 4)
    {
        printf ("Unknown Operation Mode");
        printf ("\n");
    }

    
    return (0);
}


/*====================================================================*
 *
 *   int main (int argc, char const * argv[]);
 *
 *   parse command line, populate plc structure and perform selected
 *   operations; show help summary if asked; see getoptv and putoptv
 *   to understand command line parsing and help summary display; see
 *   plc.h for the definition of struct plc;
 *
 *   the command line accepts multiple MAC addresses and the program
 *   performs the specified operations on each address, in turn; the
 *   address order is significant but the option order is not; the
 *   default address is a local broadcast that causes all devices on
 *   the local H1 interface to respond but not those at the remote
 *   end of the powerline;
 *
 *   the default address is 00:B0:52:00:00:01; omitting the address
 *   will automatically address the local device; some options will
 *   cancel themselves if this makes no sense;
 *
 *   the default interface is eth1 because most people use eth0 as
 *   their principle network connection; you can specify another
 *   interface with -i or define environment string PLC to make
 *   that the default interface and save typing;
 *
 *--------------------------------------------------------------------*/

int main (int argc, char const * argv [])

{
	bool tone_map_oper = false;
	extern struct channel channel;
	static char const * optv [] =
	{
		"c:ehi:p:qst:vx",
		"node peer [> stdout]",
		"Qualcomm Atheros Panther/Lynx Tone Map Control/Monitor",
        "c\tclean-up operation(plctone -c[0:1:2] dest mac peer mac)",
        "e\tredirect stderr to stdout",
		"h\tprint mean-square histogram",

#if defined (WINPCAP) || defined (LIBPCAP)

		"i n\thost interface is (n) [" LITERAL (CHANNEL_ETHNUMBER) "]",

#else

		"i s\thost interface is (s) [" LITERAL (CHANNEL_ETHDEVICE) "]",

#endif

		"p n\tcoupling [" LITERAL (PLCOUPLING) "]",
		"q\tquiet mode",
		"s\tcompute signal-to-noise and bits-per-carrier ratios",
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
			"pri",
			"0"
		}
	};
    
#if 1
    static const struct _term_ direction [] =
    {
        {
            "tx/rx",
            "0"
        },
        {
            "tx",
            "1"
        },
        {
            "rx",
            "2"
        }
    };
#endif
    
#include "../plc/plc.c"

	signed (* capture) (struct plc *) = ToneMaps2;
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
    //bool tone_map_oper = false;
    
    while (~ (c = getoptv (argc, argv, optv)))
	{
		switch (c)
		{
		case 'p':

#if 0

			plc.coupling = (unsigned) (uintspec (synonym (optarg, coupling, SIZEOF (coupling)), 0, SIZEOF (coupling)));

#else

			plc.coupling = (unsigned) (uintspec (synonym (optarg, coupling, SIZEOF (coupling)), 0, UCHAR_MAX));

#endif

			break;
                
        case 'c':
                tone_map_oper = true;
                // note using pushbutton field for the direction for now
                //plc.pushbutton = (unsigned) (uintspec (synonym (optarg, direction, DIR), 0, UCHAR_MAX));
				//plc.pushbutton = (unsigned) (uintspec (synonym (optarg, direction, DIR), 0, UCHAR_MAX));
				plc.pushbutton = (unsigned) (uintspec (synonym (optarg, direction, SIZEOF (direction)), 0, UCHAR_MAX));
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
		case 's':
			_setbits (plc.flags, PLC_ANALYSE);
			capture = SignalToNoise2;
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
    
    // clean-up tonemap MME
    if ( tone_map_oper )
    {
       
        // expect peer node address and direction
        argc -= optind;
        argv += optind;
        
        if (! argc || ! argv)
        {
            error (1, ECANCELED, "No peer address given");
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
    }
    
    //tonemap charac MME
    else
    {
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
    }
    
	openchannel (& channel);
	if (! (plc.message = malloc (sizeof (* plc.message))))
	{
		error (1, errno, PLC_NOMEMORY);
	}
    if ( tone_map_oper )
    {
        ProcessToneMapOperation(& plc );
    }
    else
    {
        capture (& plc);
    }
	free (plc.message);
	closechannel (& channel);
	return (0);
}

