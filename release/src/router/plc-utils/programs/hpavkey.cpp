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

/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

#include "../classes/oHPAVKey.hpp"
#include "../classes/ogetoptv.hpp"
#include "../classes/oflagword.hpp"
#include "../classes/oerror.hpp"
#include "../tools/types.h"

/*====================================================================*
 *   custom source files;
 *--------------------------------------------------------------------*/

#ifndef MAKEFILE
#include "../classes/ogetoptv.cpp"
#include "../classes/oputoptv.cpp"
#include "../classes/oversion.cpp"
#include "../classes/oerror.cpp"
#include "../classes/omemory.cpp"
#include "../classes/oflagword.cpp"
#endif

#ifndef MAKEFILE
#include "../classes/oHPAVKey.cpp"
#include "../classes/oSHA256.cpp"
#endif

/*====================================================================*
 *    
 *   int main (int argc, const char *argv []);
 *   
 *--------------------------------------------------------------------*/

int main (int argc, const char *argv []) 

{
	static const char *optv [] = 
	{
		"DeMNqv",
		oPUTOPTV_S_FUNNEL,
		"HomePlug AV key generator",
		"D\thash DAK passwords",
		"M\thash NMK passwords",
		"N\thash NID passwords",
		"q\tquiet mode",
		"v\tverbose mode",
		(const char *) (0)
	};
	oHPAVKey key;
	ogetoptv command;
	oflagword flagword;
	signed mode = 0;
	signed c;
	command.opterr (1).optmin (1);
	while ((c = command.getoptv (argc, argv, optv)) != -1) 
	{
		switch (c) 
		{
		case 'e':
			flagword.setbits (oHPAVKEY_B_ENFORCE);
			break;
		case 'D':
			mode = oHPAVKEY_N_DAK;
			break;
		case 'M':
			mode = oHPAVKEY_N_NMK;
			break;
		case 'N':
			mode = oHPAVKEY_N_NID;
			break;
		case 'q':
			flagword.setbits (oHPAVKEY_B_SILENCE);
			break;
		case 'v':
			flagword.setbits (oHPAVKEY_B_VERBOSE);
			break;
		default:
			break;
		}
	}
	while (command.argc () && * command.argv ()) 
	{
		const char * phrase = * command.argv ();
		if (flagword.anyset (oHPAVKEY_B_ENFORCE)) 
		{
			if (key.IllegalPassPhrase (phrase)) 
			{
				command++;
				continue;
			}
		}
		if (mode == oHPAVKEY_N_DAK) 
		{
			key.ComputeDAK (phrase);
			if (flagword.allclear (oHPAVKEY_B_VERBOSE)) 
			{
				phrase = (const char *)(0);
			}
			key.Print (phrase);
		}
		else if (mode == oHPAVKEY_N_NMK) 
		{
			key.ComputeNMK (phrase);
			if (flagword.allclear (oHPAVKEY_B_VERBOSE)) 
			{
				phrase = (const char *)(0);
			}
			key.Print (phrase);
		}
		else if (mode == oHPAVKEY_N_NID) 
		{
			key.ComputeNMK (phrase).ComputeNID (0);
			if (flagword.allclear (oHPAVKEY_B_VERBOSE)) 
			{
				phrase = (const char *)(0);
			}
			key.Print (phrase);
		}
		command++;
	}
	std::exit (0);
}

