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
#include "../classes/oerror.hpp"

/*====================================================================*
 *   custom source files;
 *--------------------------------------------------------------------*/

#ifndef MAKEFILE
#include "../classes/ointerfaces.cpp"
#include "../classes/ointerface.cpp"
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
	if (--argc)
	{
		oerror::error (1, ENOTSUP, oERROR_UNWANTED);
	}
	interfaces.Enumerate ();
	return (0);
}

