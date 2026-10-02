/*====================================================================*
 *
 *   oputoptv.cpp - oputoptv class definition;
 *
 *   impelement a standard means of program help menu display;
 *
 *   Motley Tools by Charles Maier <cmaier@cmassoc.net>;
 *   Copyright 2001-2006 by Charles Maier Associates;
 *   Licensed under the Internet Software Consortium License;
 *
 *--------------------------------------------------------------------*/

#ifndef oPUTOPTV_SOURCE
#define oPUTOPTV_SOURCE

/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

#include <iostream>
#include <cstdlib>

/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

#include "../classes/ogetoptv.hpp"
#include "../classes/oputoptv.hpp"

/*====================================================================*
 *
 *   oputoptv & print (char const * optv []);
 *
 *   print help summary on stderr as defined by string vestor optv;
 *
 *   program_name is defined in ogetopt::getoptv() but it could be 
 *   defined in main or another component; 
 *
 *   ogetoptv.hpp is included for the GETOPTV_C_OPTIONS which is 
 *   normally '-' but it could be anything; 
 *
 *   Motley Tools by Charles Maier <cmaier@cmassoc.net>;
 *   Copyright 2001-2006 by Charles Maier Associates;
 *   Licensed under the Internet Software Consortium License;
 *
 *--------------------------------------------------------------------*/

oputoptv & oputoptv::print (char const * optv []) 

{
	extern char const * program_name;
	std::cout << "\n";
	std::cout << " purpose: " << optv [oPUTOPTV_I_PURPOSE] << std::endl << std::endl;
	std::cout << " command: " << program_name << " [options] " << optv [oPUTOPTV_I_COMMAND] << std::endl << std::endl;
	std::cout << " options: [" << optv [oPUTOPTV_I_OPTIONS] << "?!]" << std::endl << std::endl;
	for (int index = oPUTOPTV_I_DETAILS; optv [index] != (char *) (0); index++) 
	{
		std::cout << " " << oGETOPTV_C_OPTIONS << optv [index] << std::endl;
	}
	std::cout << " " << oGETOPTV_C_OPTIONS << oGETOPTV_C_VERSION << "\tversion information" << std::endl;
	std::cout << " " << oGETOPTV_C_OPTIONS << oGETOPTV_C_SUMMARY << "\thelp summary" << std::endl << std::endl;
	return (*this);
}

/*====================================================================*
 *
 *   oputoptv & print (char const * optv[], signed exitcode);
 *
 *   print optv vector on stderr; this presents the user with a help
 *   summary; program_name is defined in ogetoptv::getoptv() but it could be
 *   defined in main or another component; getoptv.h is included above
 *   for GETOPTV_C_OPTIONS which is normally '-' but could be anything; 
 *
 *   Motley Tools by Charles Maier <cmaier@cmassoc.net>;
 *   Copyright 2001-2006 by Charles Maier Associates;
 *   Licensed under the Internet Software Consortium License;
 *
 *--------------------------------------------------------------------*/

oputoptv & oputoptv::print (char const * optv [], signed exitcode) 

{
	oputoptv::print (optv);
	std::exit (exitcode);
}

/*====================================================================*
 *
 *   oputoptv ();
 *
 *--------------------------------------------------------------------*/

oputoptv::oputoptv () 

{
	return;
}

/*====================================================================*
 *
 *   ~oputoptv ();
 *
 *--------------------------------------------------------------------*/

oputoptv::~oputoptv () 

{
	return;
}

/*====================================================================*
 *   end definition;
 *--------------------------------------------------------------------*/

#endif

