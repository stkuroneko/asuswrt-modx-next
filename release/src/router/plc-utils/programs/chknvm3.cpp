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

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <iostream>
#include <fstream>

/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

#include "../classes/CPLFirmware.hpp"
#include "../classes/ogetoptv.hpp"

/*====================================================================*
 *   custom source files;
 *--------------------------------------------------------------------*/

#ifndef MAKEFILE
#include "../classes/ogetoptv.cpp"
#include "../classes/oputoptv.cpp"
#include "../classes/oversion.cpp"
#include "../classes/oerror.cpp"
#include "../classes/omemory.cpp"
#include "../classes/ointerface.cpp"
#include "../classes/oethernet.cpp"
#include "../classes/ointellon.cpp"
#include "../classes/ohomeplug.cpp"
#include "../classes/oflagword.cpp"
#include "../classes/CPLFirmware.cpp"
#include "../classes/CPLChannel.cpp"
#endif

/*====================================================================*
 *    
 *   int main (int argc, char const *argv []);
 *   
 *--------------------------------------------------------------------*/

int main (int argc, char const *argv []) 

{
	static char const *optv [] = 
	{
		"",
		oPUTOPTV_S_FUNNEL,
		"Atheros NVM File Validator",
		(char const *) (0) 
	};
	ogetoptv console;
	signed c;
	console.opterr (1).optmin (1);
	while ((c = console.getoptv (argc, argv, optv)) != -1) 
	{
		switch (c) 
		{
		default:
			break;
		}
	}
	while (console.argc () && * console.argv ()) 
	{
		std::cout << * console.argv () << std::endl;
		CPLFirmware firmware (* console.argv ());
		if (!firmware.IsValid ())
		{
			std::cout << "Ratz!" << std::endl;   
		}
		console++;
	}
	return (0);
}

