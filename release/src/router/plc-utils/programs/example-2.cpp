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
	char buffer [ETHER_ADDR_LEN * 3];
	byte bridge [CPLCHANNEL_BRIDGES_MAX][ETHER_ADDR_LEN];
	byte device [CPLCHANNEL_DEVICES_MAX][ETHER_ADDR_LEN];
	size_t bridges;
	size_t devices;
	program_name = * argv;
	for (interfaces.SelectFirst (); interfaces.Index () < interfaces.Count (); interfaces.SelectNext ()) 
	{
		CPLChannel * channel = new CPLChannel (interfaces.Selected ().Name ());
		std::cout << "interface - " << channel->Description () << std::endl;
		bridges = channel->Bridges (bridge, sizeof (bridge));
		while (bridges--) 
		{
			std::cout << "bridge - " << omemory::hexstring (buffer, sizeof (buffer), bridge [bridges], ETHER_ADDR_LEN) << std::endl;
			channel->ImportPeerAddress (bridge [bridges]);
			devices = channel->Neighbors (device, sizeof (device));
			while (devices--) 
			{
				std::cout << "device - " << omemory::hexstring (buffer, sizeof (buffer), device [devices], ETHER_ADDR_LEN) << std::endl;
			}
			std::cout << std::endl;
		}
		std::cout << std::endl;
		delete channel;
	}
	std::exit (0);
}

