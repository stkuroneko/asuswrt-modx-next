/*====================================================================*
 *
 *   oversion.hpp - declarations of the oversion class.
 *
 *   implement a standard means of program version identification; 
 *
 *   Motley Tools by Charles Maier <cmaier@cmassoc.net>;
 *   Copyright 2001-2006 by Charles Maier Associates;
 *   Licensed under the Internet Software Consortium License;
 *
 *--------------------------------------------------------------------*/

#ifndef oVERSION_HEADER
#define oVERSION_HEADER

/*====================================================================*
 *   custom header files; 
 *--------------------------------------------------------------------*/

#include "../classes/stdafx.hpp"

/*====================================================================*
 *   class constants;
 *--------------------------------------------------------------------*/

#define COMPANY "Qualcomm Atheros, San Jose CA, USA"
#define PROJECT "Qualcomm Atheros Powerline Toolkit"
#define PACKAGE "plc-utils"
#define VERSION "2.1.8"
#define RELEASE "QCAOSR-1558-1"
#define COMPILE __TIME__ " " __DATE__
#define CONTACT "cmaier@qca.qualcomm.com"
#define LICENSE "Clear BSD License"

/*====================================================================*
 *   class declaration;
 *--------------------------------------------------------------------*/

class __declspec (dllexport) oversion 

{
public:
	oversion ();
	virtual ~ oversion ();
	oversion & print ();
private:
};

/*====================================================================*
 *   end declaration;
 *--------------------------------------------------------------------*/

#endif

