/*====================================================================*
*
*   Copyright (c) 2016 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   pts.c -
 *
 *   
 *
 *--------------------------------------------------------------------*/

/*====================================================================*
 *   system header files;
 *--------------------------------------------------------------------*/

#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <limits.h>
#include <sys/time.h>
#include <memory.h>
#include <errno.h>


#include "../tools/timer.h"

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
#include "../ether/channel.h"
#include "../key/HPAVKey.h"
#include "../key/keys.h"
#include "../ram/sdram.h"
#include "../pib/pib.h"
#include "../nvm/nvm.h"
#include "../plc/plc.h"
#include "../plc/pts.h"
/*====================================================================*
 *   custom source files;
 *--------------------------------------------------------------------*/

#ifndef MAKEFILE
#include "../plc/Attributes2.c"
#include "../plc/Confirm.c"
#include "../plc/Devices.c"
#include "../plc/Display.c"
#include "../plc/FactoryDefaults.c"
#include "../plc/Failure.c"
#include "../plc/FlashDevice2.c"
#include "../plc/FlashFirmware.c"
#include "../plc/FlashParameters.c"
#include "../plc/FlashSoftloader.c"
#include "../plc/HostActionResponse.c"
#include "../plc/Identity1.c"
#include "../plc/Identity2.c"
#include "../plc/LinkStatus.c"
#include "../plc/ModuleCommit.c"
#include "../plc/ModuleRead.c"
#include "../plc/ModuleSession.c"
#include "../plc/ModuleSpec.c"
#include "../plc/ModuleWrite.c"
#include "../plc/NVRAMInfo.c"
#include "../plc/NetInfo2.c"
#include "../plc/PLCSelect.c"
#include "../plc/PushButton.c"
#include "../plc/ReadMFG.c"
#include "../plc/ReadMME.c"
#include "../plc/ReadFirmware2.c"
#include "../plc/ReadParameters2.c"
#include "../plc/Request.c"
#include "../plc/ResetDevice.c"
#include "../plc/RemoteHosts.c"
#include "../plc/SDRAMInfo.c"
#include "../plc/SendMME.c"
#include "../plc/SetNMK.c"
#include "../plc/StartFirmware1.c"
#include "../plc/StationRole.c"
#include "../plc/VersionInfo2.c"
#include "../plc/WaitForReset.c"
#include "../plc/WaitForStart.c"
#include "../plc/WaitForRestart.c"
#include "../plc/WatchdogReport.c"
#include "../plc/chipset.c"
#include "../plc/pts.c"
#endif

#ifndef MAKEFILE
#include "../tools/error.c"
#include "../tools/getoptv.c"
#include "../tools/putoptv.c"
#include "../tools/synonym.c"
#include "../tools/uintspec.c"
#include "../tools/basespec.c"
#include "../tools/version.c"
#include "../tools/hexdump.c"
#include "../tools/hexencode.c"
#include "../tools/hexdecode.c"
#include "../tools/hexstring.c"
#include "../tools/decstring.c"
#include "../tools/decdecode.c"
#include "../tools/hexout.c"
#include "../tools/todigit.c"
#include "../tools/checkfilename.c"
#include "../tools/checksum32.c"
#include "../tools/fdchecksum32.c"
#include "../tools/strfbits.c"
#include "../tools/typename.c"
#endif

#ifndef MAKEFILE
#include "../ether/channel.c"
#include "../ether/openchannel.c"
#include "../ether/closechannel.c"
#include "../ether/readpacket.c"
#include "../ether/sendpacket.c"
#endif

#ifndef MAKEFILE
#include "../ram/nvram.c"
#include "../ram/sdramfile.c"
#include "../ram/sdrampeek.c"
#endif

#ifndef MAKEFILE
#include "../nvm/panther_nvm_file.c"
#endif

#ifndef MAKEFILE
#include "../pib/lightning_pib_peek.c"
#include "../pib/panther_pib_peek.c"
#include "../pib/panther_pib_file.c"
#endif

#ifndef MAKEFILE
#include "../mme/EthernetHeader.c"
#include "../mme/QualcommHeader.c"
#include "../mme/QualcommHeader1.c"
#include "../mme/UnwantedMessage.c"
#include "../mme/MMECode.c"
#endif

#ifndef MAKEFILE
#include "../key/keys.c"
#endif


#define PTS_PROGRAM
int isEqual( uint8_t *MAC1 , uint8_t *MAC2 );
extern int relay (unsigned atn_grd, unsigned atn_line, char const * name );
const char *pts_messages[] = {"\nSetting Attenuator LG=%ddB LN=%ddB",\
	"\ntwo","\nthree"};

/*====================================================================*
 *   program constants;
 *--------------------------------------------------------------------*/

#define PLCTOOL_WAIT 0
#define PLCTOOL_LOOP 1

#define BUTTONS (sizeof (buttons) / sizeof (struct _term_))

/*====================================================================*
 *   program variables;
 *--------------------------------------------------------------------*/
#if 0
static const struct _term_ buttons [] =
{
	{
		"none",
		"0"
	},
	{
		"GN->DUT",
		"1"
	},
	{
		"leave",
		"2"
	},
	{
		"GN<->DUT",
		"3"
	}
};
#endif


// PTS parameters


struct pts pts = { { 
		0x00, 
		0xB0, 
		0x52, 
		0x00, 
		0x00, 
		0x01
	},{ 
		0x00, 
		0xB0, 
		0x52, 
		0x00, 
		0x00, 
		0x01
	}, 1, PTSCTL_PORT, PTSCTL_LINE_ATTN, PTSCTL_LINE_ATTN, 50,0,0,0,0,0, 120, 0, 0 }; 

 

/*====================================================================*
 *
 *   signed Get_GN_MAC (struct plc * plc);
 *
 *   Issue GET_VERSION MME to local device to determine the MAC address of the PLC device
 *	 The local device is considered to be the Golden Node (GN).
 *
 *--------------------------------------------------------------------*/
signed Get_GN_MAC (struct plc * plc)

{
	int i;
	struct channel * channel = (struct channel *) (plc->channel);
	struct message * message = (struct message *) (plc->message);

#ifndef __GNUC__
#pragma pack (push,1)
#endif

	struct __packed vs_sw_ver_request
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
		uint32_t COOKIE;
	}
	* request = (struct vs_sw_ver_request *) (message);
	struct __packed vs_sw_ver_confirm
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
		uint8_t MSTATUS;
		uint8_t MDEVICE_CLASS;
		uint8_t MVERLENGTH;
		char MVERSION [254];
		uint32_t IDENT;
		uint32_t STEPPING_NUM;
		uint32_t COOKIE;
		uint32_t RSVD [6];
	}
	* confirm = (struct vs_sw_ver_confirm *) (message);

#ifndef __GNUC__
#pragma pack (pop)
#endif
	
	memset (message, 0, sizeof (* message));
	EthernetHeader (& request->ethernet, channel->peer, channel->host, channel->type);
	QualcommHeader (& request->qualcomm, 0, (VS_SW_VER | MMTYPE_REQ));
	request->COOKIE = HTOLE32 (plc->cookie);
	plc->packetsize = (ETHER_MIN_LEN - ETHER_CRC_LEN);
	if (SendMME (plc) <= 0)
	{
		error (PLC_EXIT (plc), errno, CHANNEL_CANTSEND);
		return (-1);
	}
	while (ReadMME (plc, 0, (VS_SW_VER | MMTYPE_CNF)) > 0)
	{
	if (confirm->MSTATUS)
		{
			Failure (plc, PLC_WONTDOIT);
			continue;
		}
		// save GN MAC address
		for (i=0;i<ETHER_ADDR_LEN;i++)
		{
			pts.gn[i] = plc->message->ethernet.OSA[i];
		}
	}
	return (0);
}

/*====================================================================*
 *
 *   signed Get_DUT_MAC (struct plc * plc);
 *
 *   Issue GET_VERSION MME to local device to determine the MAC address of the PLC device
 *	 The local device is considered to be the Golden Node (GN).
 *
 *--------------------------------------------------------------------*/
signed Get_DUT_MAC (struct plc * plc)

{
	int i;
	struct channel * channel1 = (struct channel *) (plc->channel1);
	struct message * message = (struct message *) (plc->message);

#ifndef __GNUC__
#pragma pack (push,1)
#endif

	struct __packed vs_sw_ver_request
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
		uint32_t COOKIE;
	}
	* request = (struct vs_sw_ver_request *) (message);
	struct __packed vs_sw_ver_confirm
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
		uint8_t MSTATUS;
		uint8_t MDEVICE_CLASS;
		uint8_t MVERLENGTH;
		char MVERSION [254];
		uint32_t IDENT;
		uint32_t STEPPING_NUM;
		uint32_t COOKIE;
		uint32_t RSVD [6];
	}
	* confirm = (struct vs_sw_ver_confirm *) (message);

#ifndef __GNUC__
#pragma pack (pop)
#endif
	
	memset (message, 0, sizeof (* message));
	EthernetHeader (& request->ethernet, channel1->peer, channel1->host, channel1->type);
	QualcommHeader (& request->qualcomm, 0, (VS_SW_VER | MMTYPE_REQ));
	request->COOKIE = HTOLE32 (plc->cookie);
	plc->packetsize = (ETHER_MIN_LEN - ETHER_CRC_LEN);
	if (SendMME1 (plc) <= 0)
	{
		error (PLC_EXIT (plc), errno, CHANNEL_CANTSEND);
		return (-1);
	}
	while (ReadMME1 (plc, 0, (VS_SW_VER | MMTYPE_CNF)) > 0)
	{
	if (confirm->MSTATUS)
		{
			Failure (plc, PLC_WONTDOIT);
			continue;
		}
		// save DUT MAC address
		for (i=0;i<ETHER_ADDR_LEN;i++)
		{
			pts.dut[i] = plc->message->ethernet.OSA[i];
		}
	}
	return (0);
}
unsigned TestGNToDUT(struct plc * plc )
{
	struct timeval ts;
	struct timeval tc;
	unsigned timer = 0;
	struct channel * channel = (struct channel *) (plc->channel);
	struct message * message = (struct message *) (plc->message);
	
	if (gettimeofday (& ts, NULL) == -1)
	{
		error (1, errno, CANT_START_TIMER);
	}

	// transmit for time duration as specified (-dxx)
	for (timer = 0; timer < pts.timeout; timer = SECONDS (ts, tc))
	{
			// transmit from GN to DUT using host interface (-i)	
			memset (message, 0xAA, sizeof (* message));
			EthernetHeader (message, pts.dut, pts.gn, ETHERTYPE_IP);
	
			// this is a work around for a buffer overrun condition that may happen nder OSX
			if (sendpacket (channel, message, sizeof (* message)) == -1)
			{
				// we may be overrunning the buffer so need to wait a bit
				sleep( 1 );
			}
			// Send netinfo MME to DUT, look for GN MAC address and read RX PHY Rate, save in pts->AVGRX_DUT
			GetDUTPhyRates (plc, &pts );
		
            if( pts.AVGRX_DUT >= pts.phy_rate_limit )
			{
				// test passed
				return( 0 );
			}

			if (gettimeofday (& tc, NULL) == -1)
			{
				error (1, errno, CANT_RESET_TIMER);
			}
	}
	// test failed, did not get min. PHY rate within test time specified
	return( 1 );
}
unsigned TestDUTToGN( struct plc * plc)
{
	struct timeval ts;
	struct timeval tc;
	unsigned timer = 0;
	struct channel * channel1 = (struct channel *) (plc->channel1);
	struct message * message = (struct message *) (plc->message);

	if (gettimeofday (& ts, NULL) == -1)
	{
		error (1, errno, CANT_START_TIMER);
	}


	for (timer = 0; timer < pts.timeout; timer = SECONDS (ts, tc))
	{

        // transmit from GN to DUT using host interface (-i)	
		memset (message, 0xAA, sizeof (* message));
		EthernetHeader (message, pts.gn, pts.dut, ETHERTYPE_IP);
	
		// this is a work around for a buffer overrun condition that may happen nder OSX
		if (sendpacket (channel1, message, sizeof (* message)) == -1)
		{
			// we may be overrunning the buffer so need to wait a bit
			sleep( 1 );
		}

		// send netifo MME to GN, look for DUT MAC address and read RX PHY Rate, save in pts->AVGRX_GN
		GetGNPhyRates (plc, &pts );
        
		if( pts.AVGRX_GN >= pts.phy_rate_limit )
		{
			//test passed
			return( 0 );
		}

		if (gettimeofday (& tc, NULL) == -1)
			{
				error (1, errno, CANT_RESET_TIMER);
			}
	}
	// test failed, did not get min. PHY rate within test time specified
	return( 1 );

}
unsigned TestBiDi(struct plc * plc)
{
	struct timeval ts;
	struct timeval tc;
	unsigned timer = 0;
	struct channel * channel = (struct channel *) (plc->channel);
	struct channel * channel1 = (struct channel *) (plc->channel1);
	struct message * message = (struct message *) (plc->message);

	if (gettimeofday (& ts, NULL) == -1)
	{
		error (1, errno, CANT_START_TIMER);
	}


	for (timer = 0; timer < pts.timeout; timer = SECONDS (ts, tc))
	{
		
           // transmit from GN to DUT using host interface (-i)	
			memset (message, 0xAA, sizeof (* message));
			EthernetHeader (message, pts.dut, pts.gn, ETHERTYPE_IP);
	
			// this is a work around for a buffer overrun condition that may happen nder OSX
			if (sendpacket (channel, message, sizeof (* message)) == -1)
			{
				// we may be overrunning the buffer so need to wait a bit
				sleep( 1 );
			}
			// transmit from DUT to DN using host interface (-j)	
			EthernetHeader (message, pts.gn, pts.dut, ETHERTYPE_IP);
	
			// this is a work around for a buffer overrun condition that may happen nder OSX
			if (sendpacket (channel1, message, sizeof (* message)) == -1)
			{
				// we may be overrunning the buffer so need to wait a bit
				sleep( 1 );
			}
			// Send netinfo MME to DUT, look for GN MAC address and read RX PHY Rate, save in pts->AVGRX_DUT
			GetDUTPhyRates (plc, &pts );
			GetGNPhyRates (plc, &pts );

			// must get min PHY rate as specified from both the DUT and GN
			if( (pts.AVGRX_DUT >= pts.phy_rate_limit) && (pts.AVGRX_GN >= pts.phy_rate_limit) )
			{
				//test passed
				return( 0 );
			}

			if (gettimeofday (& tc, NULL) == -1)
			{
				error (1, errno, CANT_RESET_TIMER);
			}
	}
	// test failed, did not get min. PHY rate within test time specified
	return( 1 );
}

signed ClearToneMaps (struct plc * plc, struct pts * pts)
{

	struct channel * channel = (struct channel *) (plc->channel);
	struct channel * channel1 = (struct channel *) (plc->channel1);

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
    
#ifndef __GNUC__
#pragma pack (pop)
#endif
  
	// channel = GN->DUT
	memset (message, 0, sizeof (* message));
	EthernetHeader (& request->ethernet, pts->gn, channel->host, channel->type);
    
    QualcommHeader (& request->qualcomm, 0, (VS_TONE_MAP_OPER | MMTYPE_REQ));
    plc->packetsize = (ETHER_MIN_LEN - ETHER_CRC_LEN);
    request->Mode = 0; //clean-up tonemap operation
    request->DIRECTION = 0; // clean both TX and RX tonemaps
    
	memcpy (request->MACADDRESS, pts->dut, sizeof (request->MACADDRESS));
	SendMME( plc );
	ReadMME (plc, 0, (VS_TONE_MAP_OPER | MMTYPE_CNF));

	// channel = DUT->GN
	memset (message, 0, sizeof (* message));
	EthernetHeader (& request->ethernet, pts->dut, channel1->host, channel1->type);
    
    QualcommHeader (& request->qualcomm, 0, (VS_TONE_MAP_OPER | MMTYPE_REQ));
    plc->packetsize = (ETHER_MIN_LEN - ETHER_CRC_LEN);
    request->Mode = 0; //clean-up tonemap operation
    request->DIRECTION = 0; // clean both TX and RX tonemaps
    
	memcpy (request->MACADDRESS, pts->gn, sizeof (request->MACADDRESS));
	SendMME1( plc );
	ReadMME1 (plc, 0, (VS_TONE_MAP_OPER | MMTYPE_CNF));

    return (0);
}



/*====================================================================*
 *
 *   void manager (struct plc * plc, signed count, signed pause);
 *
 *   perform operations in logical order despite any order specfied
 *   on the command line; for example read PIB before writing PIB;
 *
 *   operation order is controlled by the order of "if" statements
 *   shown here; the entire operation sequence can be repeated with
 *   an optional pause between each iteration;
 *
 *--------------------------------------------------------------------*/
static void manager (struct plc * plc, signed count, signed pause)

{
	unsigned status = 0;
	char sourcename [ETHER_ADDR_LEN * 3];
	char targetname [ETHER_ADDR_LEN * 3];

	// Discover the GN MAC address
	Get_GN_MAC (plc);

	// Discover the DUT MAC address
	Get_DUT_MAC (plc);
    
    if (_anyset (plc->flags, PLC_VERBOSE))
    {
        hexdecode (pts.gn, ETHER_ADDR_LEN, sourcename, sizeof (sourcename));
        hexdecode (pts.dut, ETHER_ADDR_LEN, targetname, sizeof (targetname));
        printf ("GN = %s DUT = %s\n", sourcename, targetname);
    }

    // see if we need to program the attenuator
    if (_anyset (plc->flags, PLC_PUSH_BUTTON))
    {
        if (_anyset (plc->flags, PLC_VERBOSE))
        {
            printf(pts_messages[0], pts.atn_grnd, pts.atn_line );
        }
        relay( pts.atn_grnd, pts.atn_line, pts.name );
        
    }
    
	// clear the tonemaps, unless "-c1" option set
	if( pts.tonemaps == 0 )
	{
        if (_anyset (plc->flags, PLC_VERBOSE))
        {
            printf ("\nClearing tonemaps between GN and DUT\n");
        }
		ClearToneMaps( plc, &pts );
		
	}

	switch ( pts.traffic )
		{
            case 0:
                if (_anyset (plc->flags, PLC_VERBOSE))
                {
             
                printf("Sending traffic from GN to DUT...\n");
                }
                status = TestGNToDUT( plc );
                
                if (_anyset (plc->flags, PLC_VERBOSE))
                {
                    if( status )
                    {
                        printf("Test FAILED\nMinimum PHY Rate Expected = %dMbps Actual DUT PHY Rate = %dMbps\n", pts.phy_rate_limit, pts.AVGRX_DUT);
                    }
                    else
                    {
                        printf("Test PASSED\nMinimum PHY Rate Expected = %dMbps Actual DUT PHY Rate = %dMbps\n", pts.phy_rate_limit, pts.AVGRX_DUT);
                    }
                }
                break;
			case 1:
                if (_anyset (plc->flags, PLC_VERBOSE))
                {
                
                    printf("Sending traffic from DUT to GN...\n");
                }
                status = TestDUTToGN( plc );
    
                if (_anyset (plc->flags, PLC_VERBOSE))
                {
                    if( status )
                    {
                        printf("Test FAILED\nMinimum Expected PHY Rate = %dMbps Actual GN PHY Rate = %dMbps\n", pts.phy_rate_limit, pts.AVGRX_GN);
                    }
                    else
                    {
                
                        printf("Test PASSED\nMinimum Expected PHY Rate = %dMbps Actual GN PHY Rate = %dMbps\n", pts.phy_rate_limit, pts.AVGRX_GN);
                    }
                }
                break;
			case 2:
                if (_anyset (plc->flags, PLC_VERBOSE))
                {
                    printf ("Sending traffic between GN and DUT\n");
                }
                status = TestBiDi( plc );
                if (_anyset (plc->flags, PLC_VERBOSE))
                {
                    if( status )
                    {
                        printf("Test FAILED...Minimum PHY Rate Expected = %dMbps Actual GN PHY Rate = %dMbps Actual DUT PHY Rate = %dMbps\n", pts.phy_rate_limit, pts.AVGRX_GN, pts.AVGRX_DUT);
                    }
                    else
                    {
                        printf("Test PASSED...Minimum PHY Rate Expected = %dMbps Actual GN PHY Rate = %dMbps Actual DUT PHY Rate = %dMbps\n", pts.phy_rate_limit, pts.AVGRX_GN, pts.AVGRX_DUT);
                    }
                }
                break;
		}

	if (!status)
	{
        if (_anyset (plc->flags, PLC_VERBOSE))
        {
            printf ("Test PASSED returning 0\n" );
        }
        
		exit( 0 );
	}

	
	if( pts.exit_option == 1 )
	{
        if (_anyset (plc->flags, PLC_VERBOSE))
        {
            printf ("Test FAILED bypass error returning 0\n");
        }
		// Bypass failure and return success
		exit( 0 );
	}
        if (_anyset (plc->flags, PLC_VERBOSE))
        {
            printf ("Test FAILED returning 1\n" );
        }
	// Return Failed Status
	exit( 1 );

}

signed GetDUTPhyRates (struct plc * plc, struct pts * pts )

{
	struct channel * channel1 = (struct channel *) (plc->channel1);
	struct message * message = (struct message *) (plc->message);

#ifndef __GNUC__
#pragma pack (push,1)
#endif

	struct __packed vs_nw_info_request
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_fmi qualcomm;
	}
	* request = (struct vs_nw_info_request *) (message);
	struct __packed vs_nw_info_confirm
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_fmi qualcomm;
		uint8_t SUB_VERSION;
		uint8_t Reserved;
		uint16_t DATA_LEN;
		uint8_t DATA [1];
	}
	* confirm = (struct vs_nw_info_confirm *) (message);
	struct __packed station
	{
		uint8_t MAC [ETHER_ADDR_LEN];
		uint8_t TEI;
		uint8_t Reserved [3];
		uint8_t BDA [ETHER_ADDR_LEN];
		uint16_t AVGTX;
		uint8_t COUPLING;
		uint8_t Reserved3;
		uint16_t AVGRX;
		uint16_t Reserved4;
	}
	* station;
	struct __packed network
	{
		uint8_t NID [7];
		uint8_t Reserved1 [2];
		uint8_t SNID;
		uint8_t TEI;
		uint8_t Reserved2 [4];
		uint8_t ROLE;
		uint8_t CCO_MAC [ETHER_ADDR_LEN];
		uint8_t CCO_TEI;
		uint8_t Reserved3 [3];
		uint8_t NUMSTAS;
		uint8_t Reserved4 [5];
		struct station stations [1];
	}
	* network;
	struct __packed networks
	{
		uint8_t Reserved;
		uint8_t NUMAVLNS;
		struct network networks [1];
	}
	* networks = (struct networks *) (confirm->DATA);

#ifndef __GNUC__
#pragma pack (pop)
#endif

	memset (message, 0, sizeof (* message));
	EthernetHeader (& request->ethernet, localcast, channel1->host, channel1->type);
	QualcommHeader1 (& request->qualcomm, 1, (VS_NW_INFO | MMTYPE_REQ));
	plc->packetsize = (ETHER_MIN_LEN - ETHER_CRC_LEN);
	if (SendMME1 (plc) <= 0)
	{
		error (PLC_EXIT (plc), errno, CHANNEL_CANTSEND);
		return (-1);
	}
	while (ReadMME1 (plc, 1, (VS_NW_INFO | MMTYPE_CNF)) > 0)
	{
		network = (struct network *) (& networks->networks);
		while (networks->NUMAVLNS--)
		{
			station = (struct station *) (& network->stations);
			while (network->NUMSTAS--)
			{
				//look for the MAC address of the GN
				if (memcmp (station->MAC, pts->gn, ETHER_ADDR_LEN) == 0)
				{
					// Save the RX PHY rate (coded)
					station->AVGTX = LE16TOH (station->AVGTX);
					station->AVGRX = LE16TOH (station->AVGRX);
					
					// uncoded PHY rates
					//station->AVGTX = ((station->AVGTX * 21) >> 4);
					//station->AVGRX = ((station->AVGRX * 21) >> 4);
					
					
					pts->AVGRX_DUT = station->AVGRX;
					return( 0 );
				}
				station++;
			}
			network = (struct network *) (station);
		}
	}
	return (0);
}


signed GetGNPhyRates (struct plc * plc, struct pts * pts )

{
	
	struct channel * channel = (struct channel *) (plc->channel);
	struct message * message = (struct message *) (plc->message);

#ifndef __GNUC__
#pragma pack (push,1)
#endif

	struct __packed vs_nw_info_request
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_fmi qualcomm;
	}
	* request = (struct vs_nw_info_request *) (message);
	struct __packed vs_nw_info_confirm
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_fmi qualcomm;
		uint8_t SUB_VERSION;
		uint8_t Reserved;
		uint16_t DATA_LEN;
		uint8_t DATA [1];
	}
	* confirm = (struct vs_nw_info_confirm *) (message);
	struct __packed station
	{
		uint8_t MAC [ETHER_ADDR_LEN];
		uint8_t TEI;
		uint8_t Reserved [3];
		uint8_t BDA [ETHER_ADDR_LEN];
		uint16_t AVGTX;
		uint8_t COUPLING;
		uint8_t Reserved3;
		uint16_t AVGRX;
		uint16_t Reserved4;
	}
	* station;
	struct __packed network
	{
		uint8_t NID [7];
		uint8_t Reserved1 [2];
		uint8_t SNID;
		uint8_t TEI;
		uint8_t Reserved2 [4];
		uint8_t ROLE;
		uint8_t CCO_MAC [ETHER_ADDR_LEN];
		uint8_t CCO_TEI;
		uint8_t Reserved3 [3];
		uint8_t NUMSTAS;
		uint8_t Reserved4 [5];
		struct station stations [1];
	}
	* network;
	struct __packed networks
	{
		uint8_t Reserved;
		uint8_t NUMAVLNS;
		struct network networks [1];
	}
	* networks = (struct networks *) (confirm->DATA);

#ifndef __GNUC__
#pragma pack (pop)
#endif

	memset (message, 0, sizeof (* message));
	EthernetHeader (& request->ethernet, localcast, channel->host, channel->type);
	QualcommHeader1 (& request->qualcomm, 1, (VS_NW_INFO | MMTYPE_REQ));
	plc->packetsize = (ETHER_MIN_LEN - ETHER_CRC_LEN);
	if (SendMME (plc) <= 0)
	{
		error (PLC_EXIT (plc), errno, CHANNEL_CANTSEND);
		return (-1);
	}

	while (ReadMME (plc, 1, (VS_NW_INFO | MMTYPE_CNF)) > 0)
	{
		network = (struct network *) (& networks->networks);
		while (networks->NUMAVLNS--)
		{
		station = (struct station *) (& network->stations);
			while (network->NUMSTAS--)
			{
				
				//look for the MAC address of the DUT
				if (memcmp (station->MAC, pts->dut, ETHER_ADDR_LEN) == 0)
				{
					// Save the RX PHY rate (coded)
					station->AVGTX = LE16TOH (station->AVGTX);
					station->AVGRX = LE16TOH (station->AVGRX);
					
					// uncoded PHY rates
					//station->AVGTX = ((station->AVGTX * 21) >> 4);
					//station->AVGRX = ((station->AVGRX * 21) >> 4);
					
					
					pts->AVGRX_GN = station->AVGRX;
					return( 0 );
				}
				station++;
			}
			network = (struct network *) (station);	
		}
	}
	return (0);
}


// transmit from GN to DUT
signed Transmit4 (struct plc * plc, byte source [], byte target [])

{

	struct channel * channel = (struct channel *) (plc->channel);
	struct message * message = (struct message *) (plc->message);
	struct timeval ts;
	struct timeval tc;
	unsigned timer = 0;
	
	memset (message, 0xAA, sizeof (* message));
	EthernetHeader (message, target, source, ETHERTYPE_IP);
	if (gettimeofday (& ts, NULL) == -1)
	{
		error (1, errno, CANT_START_TIMER);
	}
	for (timer = 0; timer < 5; timer = SECONDS (ts, tc))
	{
		// this is a work around for a buffer overrun condition that may happen nder OSX
        if (sendpacket (channel, message, sizeof (* message)) == -1)
        {
            // we may be overrunning the buffer so need to wait a bit
            sleep( 1 );
        }
		if (gettimeofday (& tc, NULL) == -1)
		{
			error (1, errno, CANT_RESET_TIMER);
		}
	}
	return (0);
}
// transmit from DUT to GN
signed Transmit5 (struct plc * plc, byte source [], byte target [])

{

	struct channel * channel1 = (struct channel *) (plc->channel1);
	struct message * message = (struct message *) (plc->message);
	struct timeval ts;
	struct timeval tc;
	unsigned timer = 0;
	
	memset (message, 0x55, sizeof (* message));
	EthernetHeader (message, target, source, ETHERTYPE_IP);

	if (gettimeofday (& ts, NULL) == -1)
	{
		error (1, errno, CANT_START_TIMER);
	}
	// Transmit for at least 5 seconds before returning and asking for the PHY rates
	for (timer = 0; timer < 5; timer = SECONDS (ts, tc))
	{
		// this is a work around for a buffer overrun condition that may happen under OSX
        if (sendpacket (channel1, message, sizeof (* message)) == -1)
        {
            // we may be overrunning the buffer so need to wait a bit
            sleep( 1 );
        }
		if (gettimeofday (& tc, NULL) == -1)
		{
			error (1, errno, CANT_RESET_TIMER);
		}
	}

	return (0);
}

// transmit bi-di
signed Transmit6 (struct plc * plc, byte source [], byte target [])

{
	struct channel * channel = (struct channel *) (plc->channel);
	struct channel * channel1 = (struct channel *) (plc->channel1);
	struct message * message = (struct message *) (plc->message);
	struct timeval ts;
	struct timeval tc;
	unsigned timer = 0;
	if (_allclr (plc->flags, PLC_SILENCE))
	{
		char sourcename [ETHER_ADDR_LEN * 3];
		char targetname [ETHER_ADDR_LEN * 3];
		hexdecode (source, ETHER_ADDR_LEN, sourcename, sizeof (sourcename));
		hexdecode (target, ETHER_ADDR_LEN, targetname, sizeof (targetname));

	}
	memset (message, 0xA5, sizeof (* message));
	
	if (gettimeofday (& ts, NULL) == -1)
	{
		error (1, errno, CANT_START_TIMER);
	}
	for (timer = 0; timer < 5; timer = SECONDS (ts, tc))
	{
		EthernetHeader (message, target, source, ETHERTYPE_IP);

		// this is a work around for a buffer overrun condition observed under OSX
        if (sendpacket (channel, message, sizeof (* message)) == -1)
        {
            // we may be overrunning the buffer so need to wait a bit
            sleep( 1 );
        }
		EthernetHeader (message, source, target, ETHERTYPE_IP);
		if (sendpacket (channel1, message, sizeof (* message)) == -1)
        {
            // we may be overrunning the buffer so need to wait a bit
            sleep( 1 );
        }

		if (gettimeofday (& tc, NULL) == -1)
		{
			error (1, errno, CANT_RESET_TIMER);
		}
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
	extern struct channel channel;
	extern struct channel channel1;

	static char const * optv [] =
	{
		"f:g:n:c:e:i:j:p:d:t:v",
		"device [device] [...]",
		"Qualcomm Atheros Production Test Utility",
		"f f\tport is (f) [" PTSCTL_PORT "]", 
		"g n\tline ground attenuation is (n) [" LITERAL (PTSCTL_GRND_ATTN) "]", 
		"n n\tline neutral attenuation is (n) [" LITERAL (PTSCTL_LINE_ATTN) "]", 
		"c n\tclear tonemap option (pts speed-up) 0=clear tonemaps, 1=tonemaps not cleared [0] ",
		"e n\texit option 0=return 0 for test pass,1 for test failure, 1=always return 0 (test pass) [0] ",
#if defined (WINPCAP) || defined (LIBPCAP)
        "i n\thost interface (GN) is (n) [" LITERAL (CHANNEL_ETHNUMBER) "]",
		"j n\thost interface (DUT) is (n) [" LITERAL (3) "]",
#else
        "i s\thost interface (GN) is (s) [" LITERAL (CHANNEL_ETHDEVICE) "]",
		"j s\thost interface (DUT) is (s) [" LITERAL (3) "]",
#endif
        "p n\tPHY rate test limit (n) Mbps",
		"t n\tMaximum time to run test (n) seconds",
		"d n\tTraffic direction [0|1|2|'GN->DUT'|'DUT->GN'|'GN<->DUT']",
		"v\tOutput Progress Messages",
		(char const *) (0)
	};

#include "../plc/plc.c"

	signed loop = PLCTOOL_LOOP;
	signed wait = PLCTOOL_WAIT;
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
	 if (getenv ("PLC1"))
	{

#if defined (WINPCAP) || defined (LIBPCAP)		
		channel1.ifindex = atoi (getenv ("PLC1"));
#else
		channel1.ifname = strdup (getenv ("PLC1"));
#endif

	}
    plc.timer = PLC_ECHOTIME;
    //optind = 1;
	while (~ (c = getoptv (argc, argv, optv)))
	{
		switch (c)
		{

			case 'd':
			pts.traffic = atoi (optarg);
			//pts.traffic = (unsigned) (uintspec (synonym (optarg, buttons, BUTTONS), 0, UCHAR_MAX));

			// check range
			if ( (pts.traffic  < 0) || (pts.traffic >2) )
			{
				error (1, errno, "Invalid Traffic Direction Type %d", pts.traffic );
			}
			break;

		case 'f':
			pts.name = optarg;
			break;
		case 'g':
			pts.atn_grnd = (unsigned) (uintspec (optarg, 0, 0x7F)); 
			_setbits (plc.flags, PLC_PUSH_BUTTON);
			break;
		case 'n':
			pts.atn_line = (unsigned) (uintspec (optarg, 0, 0x7F));
			_setbits (plc.flags, PLC_PUSH_BUTTON);
			break;
		case 'c':
			pts.tonemaps = atoi (optarg);
			break;
		case 'e':
			pts.exit_option = atoi (optarg);
			break;
		case 'p':
			pts.phy_rate_limit = atoi (optarg);
			break;
		case 't':
			pts.timeout = atoi (optarg);
			break;


		case 'i':
		// GN interface

#if defined (WINPCAP) || defined (LIBPCAP)
			channel.ifindex = atoi (optarg);
#else
			channel.ifname = optarg;
#endif
			break;

		case 'j':
		// DUT interface
#if defined (WINPCAP) || defined (LIBPCAP)
			channel1.ifindex = atoi (optarg);
#else
			channel1.ifname = optarg;
#endif
			break;
	case 'v':
			//_setbits (channel.flags, CHANNEL_VERBOSE);
			_setbits (plc.flags, PLC_VERBOSE);
			break;

		default: 
			break;
		}
	}
	argc -= optind;
	argv += optind;

	openchannel (& channel);
	openchannel (& channel1);
	
	if (! (plc.message = malloc (sizeof (* plc.message))))
	{
		error (1, errno, PLC_NOMEMORY);
	}

	manager (& plc, loop, wait);
	argc--;
	argv++;
	
	free (plc.message);
	closechannel (& channel);
	closechannel (& channel1);
	exit (0);

	
}

