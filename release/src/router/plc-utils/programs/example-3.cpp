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
#include "../classes/CPLNetwork.hpp"
#include "../classes/omemory.hpp"

/*====================================================================*
 *   custom source files;
 *--------------------------------------------------------------------*/

#ifndef MAKEFILE
#include "../classes/omemory.cpp"
#include "../classes/oerror.cpp"
#include "../classes/oflagword.cpp"
#include "../classes/ointerface.cpp"
#include "../classes/oethernet.cpp"
#include "../classes/ointellon.cpp"
#include "../classes/ohomeplug.cpp"
#include "../classes/CPLChannel.cpp"
#include "../classes/CPLStation.cpp"
#include "../classes/CPLNetwork.cpp"
#endif

/*====================================================================*
 *   program variables;
 *--------------------------------------------------------------------*/

char const * program_name;

/*====================================================================*
 *   main program;
 *
 *   make sure you instantiate channel with the correct interface for
 *   your test platform or you will not get any output;
 *
 *--------------------------------------------------------------------*/

int main (int argc, const char *argv []) 

{

#if defined (__APPLE__)

	CPLChannel channel ("en0");

#elif defined (WIN32)

	CPLChannel channel (2);

#elif defined (__OpenBSD__)

	CPLChannel channel ("bce0");

#else

	CPLChannel channel ("eth4");

#endif

	CPLNetwork network (&channel);
	std::cout << "Method 1 - The Easy Way" << std::endl << std::endl;
	network.Enumerate ();
	std::cout << "Method 2 - The Do-it-yourself Way" << std::endl << std::endl;
	if (network.Count ()) 
	{
		network.Select (0).Selected ().Preface ();
	}
	while (network.Index () < network.Count ()) 
	{
		network.Selected ().Print ();
		network.SelectNext ();
	}
	std::cout << std::endl;
	std::cout << "Method 3 - The Hard Way" << std::endl << std::endl;
	if (!network.Empty ()) 
	{
		network [0].Preface ();
	}
	while (!network.End ()) 
	{
		network.Station ().Print ();
		network.SelectNext ();
	}
	std::cout << std::endl;
	std::exit (0);
}

