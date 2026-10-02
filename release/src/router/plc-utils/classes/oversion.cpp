/*====================================================================*
 *
 *   oversion.cpp - oversion class impelemetnation;
 *
 *   implement a standard means of program version identification; 
 *
 *   Motley Tools by Charles Maier <cmaier@cmassoc.net>;
 *   Copyright 2001-2006 by Charles Maier Associates;
 *   Licensed under the Internet Software Consortium License;
 *
 *--------------------------------------------------------------------*/

#ifndef oVERSION_SOURCE
#define oVERSION_SOURCE

/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

#include <iostream>

/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

#include "../classes/oversion.hpp"

/*====================================================================*
 *
 *   oversion & print (void);
 *
 *   print usage vector on stderr; this presents the user with a help
 *   summary; program_name is defined in ogetoptv::getoptv() but it could be
 *   defined in main or another component; getoptv.h is included above
 *   for GETOPTV_C_OPTIONS which is normally '-' but could be anything; 
 *
 *--------------------------------------------------------------------*/

oversion & oversion::print (void) 

{
	extern char const * program_name;
	std::cerr << program_name << " ";
	std::cerr << PACKAGE << "-";
	std::cerr << VERSION << " ";
	std::cerr << RELEASE << " ";
	std::cerr << "ECMA C++" << " ";
	std::cerr << COMPANY << " ";
	std::cerr << __TIME__ << " ";
	std::cerr << __DATE__ << " ";
	std::cerr << LICENSE << " ";
	std::cerr << std::endl;
	return (*this);
}

/*====================================================================*
 *
 *   oversion ();
 *
 *--------------------------------------------------------------------*/

oversion::oversion () 

{
	return;
}

/*====================================================================*
 *   
 *   ~oversion ();
 *
 *--------------------------------------------------------------------*/

oversion::~oversion () 

{
	return;
}

/*====================================================================*
 *   end definition
 *--------------------------------------------------------------------*/

#endif

