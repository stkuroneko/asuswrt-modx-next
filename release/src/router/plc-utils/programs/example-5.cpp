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

#include "../classes/ointerfaces.hpp"
#include "../classes/CPLNetworks.hpp"

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
#include "../classes/CPLNetworks.cpp"
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
	program_name = * argv;
	while (!interfaces.End ()) 
	{
		std::cout << "Search interface " << interfaces.Interface ().Name () << " for powerline devices ..." << std::endl;
		CPLNetworks * networks = new CPLNetworks (interfaces.Interface ().Name ());
		while (!networks->End ()) 
		{
			networks->Network ().Station ().Preface ();
			networks->Network ().Enumerate ();
			networks->SelectNext ();
		}
		delete networks;
		interfaces.SelectNext ();
	}
	std::exit (0);
}

