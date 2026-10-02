/*====================================================================*
 *
 *   oputoptv.hpp - interface for the oputoptv class.
 *
 *   impelement a standard means of program help menu display;
 *
 *   Motley Tools by Charles Maier <cmaier@cmassoc.net>;
 *   Copyright 2001-2006 by Charles Maier Associates;
 *   Licensed under the Internet Software Consortium License;
 *
 *--------------------------------------------------------------------*/

#ifndef oPUTOPTV_HEADER
#define oPUTOPTV_HEADER

/*====================================================================*
 *   custom header files; 
 *--------------------------------------------------------------------*/

#include "../classes/stdafx.hpp"

/*====================================================================*
 *   string vector indexes; 
 *--------------------------------------------------------------------*/

#define oPUTOPTV_I_OPTIONS 0
#define oPUTOPTV_I_COMMAND 1
#define oPUTOPTV_I_PURPOSE 2
#define oPUTOPTV_I_DETAILS 3

/*====================================================================*
 *   standard strings; 
 *--------------------------------------------------------------------*/

#define oPUTOPTV_S_DEVICE "[device] [device] [...] [> stdout]"
#define oPUTOPTV_S_FILTER "[file] [file] [...] or [< stdin] [> stdout]"
#define oPUTOPTV_S_FUNNEL "[file] [file] [...] [> stdout]"
#define oPUTOPTV_S_SEARCH "[dev:][dir][file[;file...]] [file[;file...]] [>stdout]"
#define oPUTOPTV_S_DIVINE "[> stdout]"

/*====================================================================*
 *   class declaration;
 *--------------------------------------------------------------------*/

class __declspec (dllexport) oputoptv 

{
public:
	oputoptv ();
	virtual ~ oputoptv ();
	oputoptv & print (char const *optv []);
	oputoptv & print (char const *optv [], signed exitcode);
};

/*====================================================================*
 *   end definitions and declaration;
 *--------------------------------------------------------------------*/

#endif

