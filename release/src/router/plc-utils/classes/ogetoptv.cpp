/*====================================================================*
 *
 *   ogetoptv.cpp - ogetoptv class definition;
 *
 *   this is a posix compliant getoptv() function that supports absolutely
 *   no extensions; visit the posix webpage that specifies this function
 *   to learn more;
 *
 *   <http://www.opengroup.org/onlinepubs/007904975/functions/getoptv.html>
 *
 *   we implemented this function to make console programs for windows and
 *   debian linux act the same; microsoft c++ would not compile the debian
 *   version of getoptv and after trying to fix it we decided to start over;
 *
 *   this function conforms to posix standard in that it does not support
 *   gnu style extensions such as "--option" for arguments or "ab::c" for
 *   options strings; if you don't know what that means then you probably
 *   won't care either; you should not implement these extentions, anyway;
 *
 *   the posix standard says that command line options and their operands
 *   must precede all other arguments; we find this restrictive and allow
 *   option arguments to appear anywhere; this implementation re-arranges
 *   a non-compliant argv[] to be posix compliant on completion;
 *
 *   we have defined characters, instead of coding them, so that microsoft
 *   folks can change '-' to '/' but preserve the posix behaviour;
 *
 *   this implementation calls no functions and so there should not be any
 *   problem with external declarations; a posix compliant unistd.h should
 *   be enough; or use our getoptv.h as an alternative; or you can add the
 *   following declarations in a header file, somwhere:
 *
 *    extern char *optarg;
 *    extern int optopt;
 *    extern int optind;
 *    extern int opterr;
 *
 *   this implementation resets when you call it with optind=0 or optind=1;
 *   the 0 is gnu/debian compliant and the 1 is posix compliant; after that
 *   it runs to completion, unless you reset optind;
 *
 *   the posix site does an excellent job of defining function behaviour and
 *   illustrating its use; if you have questions, see them; you can also cut
 *   and paste this c language code segment to get you started;
 *
 *      static char const *optv [] =
 *      {
 *              ":ab:c"
 *              "command line argument description",
 *              "ogetoptv object demonstration program",
 *              "a\toption needing no operand",
 *              "b s\toption needing an operand (s)",
 *              "c\toption needing no operand",
 *              (char const *) (0)
 *      };
 *      ogetoptv options;
 *      signed c;
 *      options.optind(1).opterr(1);
 *      while ((c = options.getoptv(argc, argv, optv)) != -1)
 *      {
 *         switch(c)
 *         {
 *            case 'a': // optopt is 'a'
 *            case 'b': // optopt is 'b'; optarg is string;
 *            case ':': // optopt is legal but no operand so optarg is null;
 *            case '?': // optopt is illegal and optarg is null;
 *             default: // valid options having no 'case' code;
 *         }
 *      }
 *
 *      while (options.optind < argc)
 *      {
 *         // do stuff to argv[options.optind++].
 *      }
 *
 *   Motley Tools by Charles Maier <cmaier@cmassoc.net>;
 *   Copyright 2001-2006 by Charles Maier Associates;
 *   Licensed under the Internet Software Consortium License;
 *
 *--------------------------------------------------------------------*/

#ifndef oGETOPTV_SOURCE
#define oGETOPTV_SOURCE

/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

#include <iostream>
#include <cstring>
#include <cstdlib>

/*====================================================================*
 *   custom source files;
 *--------------------------------------------------------------------*/

#include "../classes/ogetoptv.hpp"
#include "../classes/oputoptv.hpp"
#include "../classes/oversion.hpp"

/*====================================================================*
 *   application variables;
 *--------------------------------------------------------------------*/

char const * program_name = "unamed program";

/*====================================================================*
 *
 *   signed opterr() const;
 *
 *   return the error message flag state;
 *
 *--------------------------------------------------------------------*/

signed ogetoptv::opterr () const 

{
	return (this->mopterr);
}

/*====================================================================*
 *
 *   ogetoptv & opterr(signed opterr);
 *
 *   set the error message flag state;
 *
 *--------------------------------------------------------------------*/

ogetoptv & ogetoptv::opterr (signed opterr) 

{
	this->mopterr = opterr;
	return (*this);
}

/*====================================================================*
 *
 *   signed optmin () const;
 *
 *   return the minimum argument flag state;
 *
 *--------------------------------------------------------------------*/

signed ogetoptv::optmin () const 

{
	return (this->moptmin);
}

/*====================================================================*
 *
 *   ogetoptv & optmin (signed optmin);
 *
 *   set the minimum argument flag state;
 *
 *--------------------------------------------------------------------*/

ogetoptv & ogetoptv::optmin (signed optmin) 

{
	this->moptmin = optmin;
	return (*this);
}

/*====================================================================*
 *
 *   signed optind() const;
 *
 *   return the index of the next argv[] string; this index defines the
 *   start address for the remainder of argument vector argv[];
 *
 *--------------------------------------------------------------------*/

signed ogetoptv::optind () const 

{
	return (this->moptind);
}

/*====================================================================*
 *
 *   ogetoptv & optind(signed optind);
 *
 *   set the index of the next argv[] string;
 *
 *--------------------------------------------------------------------*/

ogetoptv & ogetoptv::optind (signed optind) 

{
	this->moptind = optind;
	return (*this);
}

/*====================================================================*
 *
 *   signed optopt() const;
 *
 *   return the value of the option character;
 *
 *--------------------------------------------------------------------*/

signed ogetoptv::optopt () const 

{
	return (this->moptopt);
}

/*====================================================================*
 *
 *   char const * optarg() const;
 *
 *   return a pointer to the option string;
 *
 *--------------------------------------------------------------------*/

char const *ogetoptv::optarg () const 

{
	return (this->moptarg);
}

/*====================================================================*
 *
 *   signed argc () const;
 *
 *   return the number of arguments left in argv; it is computed by
 *   subtracting member mpotind from member margc; it can eliminate
 *   the need for the customary "argc-=optind" statement;
 *
 *--------------------------------------------------------------------*/

signed ogetoptv::argc () const 

{
	return (this->margc - this->moptind);
}

/*====================================================================*
 *
 *   char const ** argv () const;
 *
 *   return the start address of the unprocessed portions of argv [];
 *
 *--------------------------------------------------------------------*/

char const ** ogetoptv::argv () const 

{
	return (this->margv + this->moptind);
}

/*====================================================================*
 *
 *   char const * args () const;
 *
 *   return option argument string address;
 *
 *--------------------------------------------------------------------*/

char const * ogetoptv::args () 

{
	return (this->moptarg);
}

/*====================================================================*
 *
 *   signed operator++ (signed);
 *
 *   return the value of member moptind and increment optind if less
 *   than margc; this is not a posix feature; it is an extension;
 *
 *--------------------------------------------------------------------*/

signed ogetoptv::operator++ (signed) 

{
	return (this->moptind < this->margc? this->moptind++: this->moptind);
}

/*====================================================================*
 *
 *   signed getoptv (int argc, char const * argv[], char const * optv []);
 *
 *--------------------------------------------------------------------*/

signed ogetoptv::getoptv (int argc, char const * argv [], char const * optv []) 

{
	extern char const * program_name;
	if ((this->moptind == 0) || (this->moptind == 1)) 
	{
		this->margc = argc;
		this->margv = argv;
		for (program_name = this->mstring = *this->margv; *this->mstring; this->mstring++) 
		{
			if ((*this->mstring == '/') || (*this->mstring == '\\')) 
			{
				program_name = this->mstring + 1;
			}
		}
		this->mstring = (char *) (0);
		if (this->margc == this->moptmin) 
		{
			oputoptv::print (optv);
			std::exit (0);
		}
		this->mcount = this->moptind = 1;
	}
	while ((this->mcount < this->margc) || (this->mstring)) 
	{
		if (this->mstring) 
		{
			if (*this->mstring) 
			{
				this->moptopt = *this->mstring++;
				this->moptarg = (char *)(0);
				for (char const *option = optv [oPUTOPTV_I_OPTIONS]; *option != (char) (0); option++) 
				{
					if (this->moptopt == oGETOPTV_C_OPERAND) 
					{
						continue;
					}
					if (*option == oGETOPTV_C_OPERAND) 
					{
						continue;
					}
					if (*option == this->moptopt) 
					{
						if (*++option != oGETOPTV_C_OPERAND) 
						{
							return (this->moptopt);
						}
						if (*this->mstring) 
						{
							this->moptarg = this->mstring;
							this->mstring = (char *) (0);
							return (this->moptopt);
						}
						if (this->mcount < this->margc) 
						{
							this->moptarg = argv [this->mcount];
							for (this->mindex = this->mcount++; this->mindex > this->moptind; --this->mindex) 
							{
								argv [this->mindex] = argv [this->mindex - 1];
							}
							argv [this->moptind++] = this->moptarg;
							return (this->moptopt);
						}
						if (this->mopterr) 
						{
							std::cerr << program_name << ": option '" << (char) (this->moptopt) << "' has no operand" << std::endl;
							std::exit (this->mopterr);
						}
						if (*optv [oPUTOPTV_I_OPTIONS] == oGETOPTV_C_OPERAND) 
						{
							return (oGETOPTV_C_OPERAND);
						}
						return (oGETOPTV_C_ILLEGAL);
					}
				}
				if (this->mopterr) 
				{
					std::cerr << program_name << ": option '" << (char) (this->moptopt) << "' has no meaning" << std::endl;
					std::exit (this->mopterr);
				}
				return (oGETOPTV_C_ILLEGAL);
			}
			this->mstring = (char *) (0);
		}
		if (this->mcount < this->margc) 
		{
			this->mstring = this->margv [this->mcount];
			if (*this->mstring == oGETOPTV_C_OPTIONS) 
			{
				for (this->mindex = this->mcount; this->mindex > this->moptind; --this->mindex) 
				{
					this->margv [this->mindex] = this->margv [this->mindex - 1];
				}
				this->margv [this->moptind++] = this->mstring++;
				if (*this->mstring == oGETOPTV_C_OPTIONS) 
				{
					this->mstring++;
					if (std::strcmp (this->mstring, "version") == 0) 
					{
						oversion::print ();
						std::exit (0);
					}
					if (std::strcmp (this->mstring, "help") == 0) 
					{
						oputoptv::print (optv);
						std::exit (0);
					}
					if (*this->mstring) 
					{
						this->moptarg = (char *) (0);
						this->moptopt = (char) (0);
						return (-1);
					}
					this->mstring = (char *) (0);
					continue;
				}
				if (*this->mstring == oGETOPTV_C_VERSION) 
				{
					oversion::print ();
					std::exit (0);
				}
				if (*this->mstring == oGETOPTV_C_SUMMARY) 
				{
					oputoptv::print (optv);
					std::exit (0);
				}
			}
			else 
			{
				this->mstring = (char *) (0);
			}
			this->mcount++;
		}
	}
	this->moptarg = (char *) (0);
	this->moptopt = (char) (0);
	return (-1);
}

/*====================================================================*
 *
 *   ogetoptv ();
 *
 *--------------------------------------------------------------------*/

ogetoptv::ogetoptv () 

{
	this->margs = new char [1];
	this->margs [0] = (char) (0);
	this->moptarg = (char *) (0);
	this->moptopt = (char) (0);
	this->mopterr = 1;
	this->moptind = 1;
	this->moptmin = 0;
	return;
}

/*====================================================================*
 *
 *   ~ogetoptv ();
 *
 *--------------------------------------------------------------------*/

ogetoptv::~ogetoptv () 

{
	delete [] this->margs;
	this->moptarg = (char *) (0);
	this->moptopt = (char) (0);
	return;
}

/*====================================================================*
 *   end definition;
 *--------------------------------------------------------------------*/

#endif

