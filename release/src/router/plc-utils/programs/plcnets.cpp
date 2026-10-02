/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   plcnets.cpp - enumerate local powerline networks;
 *
 *   this program uses the ointerfaces and ointerface class to find
 *   host Ethernet interfaces then uses the CPLNetworks, CPLNetwork
 *   and CPLStation classed to detect PLC networks on each interface
 *   display information about each network station;
 *
 *--------------------------------------------------------------------*/

/*====================================================================*
 *   system header files;
 *--------------------------------------------------------------------*/

#include <cstdlib>
#include <iostream>

/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

#include "../classes/ogetoptv.hpp"
#include "../classes/oerror.hpp"
#include "../classes/ointerfaces.hpp"
#include "../classes/CPLNetworks.hpp"

/*====================================================================*
 *   custom source files;
 *--------------------------------------------------------------------*/

#ifndef MAKEFILE
#include "../classes/ogetoptv.cpp"
#include "../classes/oputoptv.cpp"
#include "../classes/oversion.cpp"
#include "../classes/oerror.cpp"
#include "../classes/oflagword.cpp"
#include "../classes/omemory.cpp"
#endif

#ifndef MAKEFILE
#include "../classes/ointerface.cpp"
#include "../classes/ointerfaces.cpp"
#include "../classes/oethernet.cpp"
#include "../classes/ointellon.cpp"
#include "../classes/ohomeplug.cpp"
#include "../classes/CPLChannel.cpp"
#include "../classes/CPLNetworks.cpp"
#include "../classes/CPLNetwork.cpp"
#include "../classes/CPLStation.cpp"
#endif

/*====================================================================*
 *   program constants;
 *--------------------------------------------------------------------*/

#define oPLCNETS_B_VERBOSE (1 << 0)
#define oPLCNETS_B_SILENCE (1 << 1)

/*====================================================================*
 *   main program;
 *--------------------------------------------------------------------*/

int main (int argc, const char *argv []) 

{
	static const char * optv [] = 
	{
		"qv",
		oPUTOPTV_S_FUNNEL,
		"Atheros Powerline Network Enumerator",
		(const char *) (0)
	};
	ogetoptv command;
	ointerfaces interfaces;
	oflagword flagword;
	signed c;
	command.opterr (1);
	command.optmin (0);
	while ((c = command.getoptv (argc, argv, optv)) != -1) 
	{
		switch (c) 
		{
		case 'q':
			flagword.setbits (oPLCNETS_B_SILENCE);
			break;
		case 'v':
			flagword.setbits (oPLCNETS_B_VERBOSE);
			break;
		default:
			break;
		}
	}
	if (command.argc ())
	{
		oerror::error (1, ENOTSUP, "Too many arguments");
	}
	while (!interfaces.End ()) 
	{
		if (!interfaces.Interface ().Disabled ()) 
		{
			std::cout << "Search " << interfaces.Interface ().Name () << " for powerline networks ..." << std::endl;
			CPLNetworks * networks = new CPLNetworks (interfaces.Interface ().Name ());
			while (!networks->End ()) 
			{
				if (flagword.allclear (oPLCNETS_B_SILENCE))
				{
					networks->Network ().Station ().Preface ();
				}
				networks->Network ().Enumerate ();
				networks->SelectNext ();
			}
			delete networks;
		}
		interfaces.SelectNext ();
	}
	return (0);
}

