/*====================================================================*
 *	Copyright (c) 2018-2020 Qualcomm Technologies, Inc.
 *	All Rights Reserved.
 *	Confidential and Proprietary - Qualcomm Technologies, Inc.
 *====================================================================*/
 
/*====================================================================*
 *
 *   signed Traffic3 (struct plc * plc);
 *
 *   generate data traffic between two devices using MME 
 *	 VS_TRAFFIC_GENERATOR
 *
 *   Contributor(s):
 *			Nisha K(nishk@qti.qualcomm.com)
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
#include "../tools/number.h"
#include "../tools/symbol.h"
#include "../tools/types.h"
#include "../tools/flags.h"
#include "../tools/files.h"
#include "../tools/error.h"
#include "../plc/plc.h"

/*====================================================================*
 *   custom source files;
 *--------------------------------------------------------------------*/

#ifndef MAKEFILE
#include "../plc/chipset.c"
#include "../plc/Devices.c"
#include "../plc/Confirm.c"
#include "../plc/Display.c"
#include "../plc/Failure.c"
#include "../plc/Request.c"
#include "../plc/ReadMME.c"
#include "../plc/SendMME.c"
#include "../plc/LocalDevices.c"
#include "../plc/PLCSelect.c"
#include "../plc/ResetDevice.c"
#include "../plc/PhyRates2.c"
#include "../plc/Traffic3.c"
#include "../plc/WaitForStart.c"
#endif

#ifndef MAKEFILE
#include "../tools/getoptv.c"
#include "../tools/putoptv.c"
#include "../tools/version.c"
#include "../tools/uintspec.c"
#include "../tools/hexdump.c"
#include "../tools/hexencode.c"
#include "../tools/hexdecode.c"
#include "../tools/todigit.c"
#include "../tools/checkfilename.c"
#include "../tools/checksum32.c"
#include "../tools/error.c"
#include "../tools/fdchecksum32.c"
#include "../tools/synonym.c"
#include "../tools/typename.c"
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
#include "../mme/QualcommHeader.c"
#include "../mme/QualcommHeader1.c"
#include "../mme/UnwantedMessage.c"
#include "../mme/MMECode.c"
#endif

/*====================================================================*
 *   program constants;
 *--------------------------------------------------------------------*/

#define PLCRATE_WAIT 0
#define PLCRATE_LOOP 1

/*===========================================================================================*
 *
 *   void manager (struct plc * plc, signed count, signed pause, uint8_t trafficgen_rate);
 *
 *   perform operations in logical order despite any order specfied
 *   on the command line;
 *
 *   operation order is controlled by the order of "if" statements
 *   shown here; the entire sequence can be repeated with optional
 *   pause between each iteration;
 *
 *------------------------------------------------------------------------------------------*/

void manager (struct plc * plc, signed count, signed pause, uint8_t trafficgen_rate)

{

	while (count--)
	{
		if (_anyset (plc->flags, PLC_VERSION))
		{
			VersionInfo2 (plc);
		}
		if (_anyset (plc->flags, PLC_DEV_TRAFFIC))
		{
			Traffic3 (plc, trafficgen_rate);
		}
		if (_anyset (plc->flags, PLC_DEV_TRAFFIC_UNIDI))
		{
			Traffic3_unidi (plc, trafficgen_rate);
		}
		if (_anyset (plc->flags, PLC_NETWORK))
		{
			PhyRates2 (plc);
		}
		if (_anyset (plc->flags, PLC_RESET_DEVICE))
		{
			ResetDevice (plc);
		}
		sleep (pause);
	}
	return;
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
 *   the command line accepts local and remote device address and it
 *   performs the specified operations on it; the address order is significant 
 *   but the option order is not; the default address is a local broadcast 
 *   that causes all devices on the local H1 interface to respond but not 
 *   those at the remote end of the powerline;
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
	extern struct channel channel;
	static char const * optv [] =
	{
		"a:cd:ei:l:o:nqrRtTuvw:x",
		"node peer [> stdout]",
		"Traffic generation utility for 75xx devices",
		"a\trate(Mbps)[" LITERAL (DEFAULT_TRAFFICGEN_RATE) "] of traffic sent to peer device",
		"c\tdisplay coded PHY rates",
		"d n\ttraffic duration is (n) seconds per leg [" LITERAL (PLC_ECHOTIME) "]\n\t0 to stop the traffic",
		"e\tredirect stderr to stdout",
#if defined (WINPCAP) || defined (LIBPCAP)

		"i n\thost interface is (n) [" LITERAL (CHANNEL_ETHNUMBER) "]",

#else

		"i s\thost interface is (s) [" LITERAL (CHANNEL_ETHDEVICE) "]",

#endif

		"l n\tloop (n) times [" LITERAL (PLCRATE_LOOP) "]",
		"n\tnetwork TX/RX information",
		"o n\tread timeout is (n) milliseconds [" LITERAL (CHANNEL_TIMEOUT) "]",
		"q\tquiet mode",
		"r\trequest device information",
		"R\treset device with VS_RS_DEV",
		"t\tgenerate network traffic (one-to-one(peer-to-node)) ",
		"T\tgenerate network traffic (one-to-one(peer-to-node))uni directional" , 
		"u\tdisplay uncoded PHY rates",
		"v\tverbose mode",
		"w n\twait (n) seconds [" LITERAL (PLCRATE_WAIT) "]",
		"x\texit on error",
		(char const *) (0)
	};

#include "../plc/plc.c"

	uint8_t trafficgen_rate = DEFAULT_TRAFFICGEN_RATE;
	signed loop = PLCRATE_LOOP;
	signed wait = PLCRATE_WAIT;
	signed c;
	optind = 1;
	if (getenv (PLCDEVICE))
	{

#if defined (WINPCAP) || defined (LIBPCAP)

		channel.ifindex = atoi (getenv (PLCDEVICE));

#else

		channel.ifname = strdup (getenv (PLCDEVICE));

#endif

	}
	plc.timer = PLC_ECHOTIME;
	
	while (~ (c = getoptv (argc, argv, optv)))
	{
		switch (c)
		{
		case 'a':
			trafficgen_rate = (unsigned) (uintspec (optarg, 0, 50));
			break;
		case 'c':
			_clrbits (plc.flags, PLC_UNCODED_RATES);
			break;
		case 'd':
			plc.timer = (unsigned) (uintspec (optarg, 0, 60));
			break;
		case 'e':
			dup2 (STDOUT_FILENO, STDERR_FILENO);
			break;
		case 'i':

#if defined (WINPCAP) || defined (LIBPCAP)

			channel.ifindex = atoi (optarg);

#else

			channel.ifname = optarg;

#endif

			break;
		case 'l':
			loop = (unsigned) (uintspec (optarg, 0, UINT_MAX));
			break;
		case 'n':
			_setbits (plc.flags, PLC_NETWORK);
			break;
		case 'o':
			channel.timeout = (signed) (uintspec (optarg, 0, UINT_MAX));
			break;
		case 'q':
			_setbits (plc.flags, PLC_SILENCE);
			break;
		case 'r':
			_setbits (plc.flags, PLC_VERSION);
			break;
		case 'R':
			_setbits (plc.flags, PLC_RESET_DEVICE);
			break;
		case 't':
			_setbits (plc.flags, PLC_DEV_TRAFFIC);
			break; 
		case 'T' :
			_setbits (plc.flags, PLC_DEV_TRAFFIC_UNIDI);
			break; 
		case 'u':
			_setbits (plc.flags, PLC_UNCODED_RATES);
			break;
		case 'v':
			_setbits (channel.flags, CHANNEL_VERBOSE);
			_setbits (plc.flags, PLC_VERBOSE);
			break;
		case 'w':
			wait = (unsigned) (uintspec (optarg, 0, 3600));
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

	if (_allclr (plc.flags, (PLC_VERSION | PLC_DEV_TRAFFIC | PLC_RESET_DEVICE | PLC_DEV_TRAFFIC_UNIDI)) || (optind == 1))
	{
		_setbits (plc.flags, PLC_NETWORK);
	}

	if (_anyset(plc.flags, PLC_DEV_TRAFFIC) || _anyset(plc.flags, PLC_DEV_TRAFFIC_UNIDI))
	{
		if (! argc || ! argv)
		{
			error (1, ECANCELED, "No node address given");
		}

		if (! hexencode (plc.RDA, sizeof (plc.RDA), (char const *) (*argv)))
		{
			error (1, errno, PLC_BAD_MAC, *argv);
		}

		argv++;
		argc--;
	}

	openchannel (& channel);
	if (! (plc.message = malloc (sizeof (* plc.message))))
	{
		error (1, errno, PLC_NOMEMORY);
	}

	if (_anyset(plc.flags, PLC_DEV_TRAFFIC_UNIDI) && (! argc || ! argv))
	{
		error (1, ECANCELED, "No peer address given");
	}

	if (! argc)
	{
		manager (& plc, loop, wait, trafficgen_rate);
	}

	if ((argc) && (* argv))
	{
		if (! hexencode (channel.peer, sizeof (channel.peer), (char const *) (*argv)))
		{
			error (1, errno, PLC_BAD_MAC, * argv);
		}
		manager (& plc, loop, wait, trafficgen_rate);
	}
	free (plc.message);
	closechannel (& channel);
	exit (0);
}

