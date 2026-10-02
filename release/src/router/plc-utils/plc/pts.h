/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   pts.h - hold parameters for pts command
 *
 *--------------------------------------------------------------------*/

#ifndef PTS_HEADER
#define PTS_HEADER

/*====================================================================*
 *  system header files;
 *--------------------------------------------------------------------*/

#include <unistd.h>

/*====================================================================*
 *  custom header files;
 *--------------------------------------------------------------------*/

#include "../ether/ether.h"
#include "../tools/types.h"


/*====================================================================*
 *   #defines
 *--------------------------------------------------------------------*/
#define PTSCTL_LINE_ATTN 127
#define PTSCTL_GRND_ATTN 127

#ifdef WIN32
#	define PTSCTL_PORT "com1:"
#else
#	define PTSCTL_PORT "/dev/ttyS0"
#endif



/*====================================================================*
 *   pts error messages;
 *--------------------------------------------------------------------*/



/*====================================================================*
 *   pts structure;
 *--------------------------------------------------------------------*/

typedef struct pts 

{ 
	uint8_t dut [ETHER_ADDR_LEN]; 
	uint8_t gn [ETHER_ADDR_LEN]; 
	signed traffic; //traffic type 0=GN->DUT, 1=DUT->GN, 2=GN,<->DUT
	char const * name; //aten serial port
	signed atn_grnd;	//gn setting
	signed atn_line;	//ln setting
	signed phy_rate_limit; // minimum PHY rate to achive before exit
	uint16_t AVGRX_GN; // RX PHY rate GN
	uint16_t AVGRX_DUT; // RX PHY rate DUT
	uint16_t AVGTX_GN; // TX PHY rate GN
	uint16_t AVGTX_DUT; // TX PHY rate DUT
	uint8_t COUPLING; //MIMO, SISO, Alternate
	uint8_t timeout; // Max time to run before exiting (max 60 seconds-limited by loopback MME)
	signed	tonemaps; //1=clear tonemap after test, 0=donot clear tonemap after test
	signed	exit_option;	// 0=always indicate test pass, exit with 0 return code
							// 1=normal mode, return with 1 on failure, 0 for test passed
	
} 
PTS; 
 

/*====================================================================*
 *   pts functions;
 *--------------------------------------------------------------------*/


signed GetDUTPhyRates (struct plc * , struct pts *  );
signed GetGNPhyRates (struct plc * , struct pts *  );
signed Get_GN_MAC (struct plc * plc);

// transmit from GN to DUT
signed Transmit4 (struct plc * plc, byte source [], byte target []);

// transmit from DUT to GN
signed Transmit5 (struct plc * plc, byte source [], byte target []);

// transmit from DUT to GN and DUT to GN (bi-dir)
signed Transmit6 (struct plc * plc, byte source [], byte target []);

// transmit from DUT to GN
//signed Transmit5 (struct plc * plc, byte source [], byte target [], uint8_t tx_time );

/*====================================================================*
 *   
 *--------------------------------------------------------------------*/

#endif







