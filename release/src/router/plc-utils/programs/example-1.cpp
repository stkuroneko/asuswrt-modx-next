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
 *   custom header files;
 *--------------------------------------------------------------------*/

#include "../classes/ointerfaces.hpp"

/*====================================================================*
 *   custom source files;
 *--------------------------------------------------------------------*/

#ifndef MAKEFILE
#include "../classes/ointerface.cpp"
#include "../classes/ointerfaces.cpp"
#include "../classes/omemory.cpp"
#include "../classes/oerror.cpp"
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
	std::cout << "Method 1" << std::endl;
	interfaces.Enumerate ();
	std::cout << "Method 2" << std::endl;
	for (interfaces.SelectFirst (); interfaces.Index () < interfaces.Count (); interfaces.SelectNext ()) 
	{
		interfaces.Selected ().Print ();
	}
	std::cout << "Method 3" << std::endl;
	for (interfaces.SelectFirst (); interfaces.Index () < interfaces.Count (); interfaces.SelectNext ()) 
	{
		ointerface ifp = interfaces.Selected ();
		std::cout << "index=" << ifp.Index () << std::endl;
		std::cout << "hwaddr=" << ifp.HardwareAddressString () << std::endl;
		std::cout << "ipaddr=" << ifp.InternetAddressString () << std::endl;
		std::cout << "name=" << ifp.Name () << std::endl;
		std::cout << "text=" << ifp.Description () << std::endl;
		std::cout << std::endl;
	}
	std::cout << "Method 4" << std::endl;
	for (interfaces = 0; !interfaces.End (); interfaces.SelectNext ()) 
	{
		interfaces.Interface ().Print ();
	}
	std::exit (0);
}

