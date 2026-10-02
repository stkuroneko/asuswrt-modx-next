/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *   system header files;
 *--------------------------------------------------------------------*/

#include <cstdlib>
#include <iostream>

/*====================================================================*
 *   system header files;
 *--------------------------------------------------------------------*/

#include <sys/types.h>
#ifndef WINPCAP
#include <sys/socket.h>
#endif
#include <net/if.h>

/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

#include "../classes/CPLChannel.hpp"
#include "../classes/CPLStation.hpp"
#include "../classes/CPLNetwork.hpp"
#include "../classes/ointerfaces.hpp"
#include "../classes/omemory.hpp"

/*====================================================================*
 *   custom source files;
 *--------------------------------------------------------------------*/

#ifndef MAKEFILE
#include "../classes/omemory.cpp"
#include "../classes/oerror.cpp"
#include "../classes/oflagword.cpp"
#include "../classes/ointerface.cpp"
#include "../classes/ointerfaces.cpp"
#include "../classes/oethernet.cpp"
#include "../classes/ointellon.cpp"
#include "../classes/ohomeplug.cpp"
#include "../classes/CPLChannel.cpp"
#include "../classes/CPLNetwork.cpp"
#include "../classes/CPLStation.cpp"
#endif

/*====================================================================*
 *   program variables;
 *--------------------------------------------------------------------*/

char const * program_name;

/*====================================================================*
 *   main program;
 *--------------------------------------------------------------------*/

int main (int argc, const char *argv []) 

{
	ointerfaces interfaces;
	byte bridge [CPLCHANNEL_BRIDGES_MAX][ETHER_ADDR_LEN];
	size_t bridges;
	program_name = * argv;
	while (!interfaces.End ()) 
	{
		CPLChannel * channel = new CPLChannel (interfaces.Selected ().Name ());
		std::cout << "interface - " << channel->Description () << std::endl;
		bridges = channel->Bridges (bridge, sizeof (bridge));
		while (bridges--) 
		{
			channel->ImportPeerAddress (bridge [bridges]);
			CPLNetwork * network = new CPLNetwork (channel);
			network->Enumerate ();
			delete network;
		}
		delete channel;
		interfaces.SelectNext ();
	}
	std::exit (0);
}

