/*====================================================================*
 *
 *   oerror.cpp - oerror class definition;
 *
 *   this class implements the useful GNU error() and error_at_line()
 *   functions with some additions;
 *
 *   Motley Tools by Charles Maier <cmaier@cmassoc.net>;
 *   Copyright 2001-2006 by Charles Maier Associates;
 *   Licensed under the Internet Software Consortium License;
 *
 *--------------------------------------------------------------------*/

#ifndef oERROR_SOURCE
#define oERROR_SOURCE

/*====================================================================*
 *   system header files;
 *--------------------------------------------------------------------*/

#include <iostream>
#include <cstdarg>
#include <cstdlib>
#include <cstring>
#include <cerrno>

/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

#include "../classes/oerror.hpp"

/*====================================================================*
 *
 *   void oerror::print (char const *format, ...);
 *
 *   print error messages using a variable argument list; prefix all
 *   messages with the program_name string; suffix all messages with
 *   the text returned by strerror(error);
 *
 *   Motley Tools by Charles Maier <cmaier@cmassoc.net>;
 *   Copyright 2001-2006 by Charles Maier Associates;
 *   Licensed under the Internet Software Consortium License;
 *
 *--------------------------------------------------------------------*/

void oerror::print (char const *format, ...) 

{
	extern char const * program_name;
	if ((program_name) && (*program_name)) 
	{
		std::cerr << program_name << ": ";
	}
	if ((format) && (*format)) 
	{
		va_list argp;
		va_start (argp, format);
		std::vfprintf (stderr, format, argp);
		va_end (argp);
	}
	std::cerr << std::endl;
	return;
}

/*====================================================================*
 *
 *   void oerror::perror (char const *format, ...);
 *
 *   print an error message using variable argument list; prefix all
 *   messages with program_name; append strerror() message text when
 *   errno is non-zero;
 *
 *   Motley Tools by Charles Maier <cmaier@cmassoc.net>;
 *   Copyright 2001-2006 by Charles Maier Associates;
 *   Licensed under the Internet Software Consortium License;
 *
 *--------------------------------------------------------------------*/

void oerror::error (char const *format, ...) 

{
	extern char const * program_name;
	if ((program_name) && (*program_name)) 
	{
		std::cerr << program_name << ": ";
	}
	if (errno) 
	{
		std::cerr << std::strerror (errno) << ": ";
		errno = 0;
	}
	if ((format) && (*format)) 
	{
		va_list argp;
		va_start (argp, format);
		std::vfprintf (stderr, format, argp);
		va_end (argp);
	}
	std::cerr << std::endl;
	return;
}

/*====================================================================*
 *
 *   void error (int code, errno_t error, char const *format, ...);
 *
 *   print an error message using variable argument list; prefix all
 *   messages with program_name; append strerror() message text when
 *   number is not non-zero; exit with status if status is non-zero;
 *
 *   included for compatibility with the GNU C library;
 *
 *   Motley Tools by Charles Maier <cmaier@cmassoc.net>;
 *   Copyright 2001-2006 by Charles Maier Associates;
 *   Licensed under the Internet Software Consortium License;
 *
 *--------------------------------------------------------------------*/

void oerror::error (int status, errno_t number, char const *format, ...) 

{
	extern char const * program_name;
	if ((program_name) && (*program_name)) 
	{
		std::cerr << program_name << ": ";
	}
	if (number) 
	{
		std::cerr << std::strerror (number) << ": ";
		errno = 0;
	}
	if ((format) && (*format)) 
	{
		va_list arglist;
		va_start (arglist, format);
		std::vfprintf (stderr, format, arglist);
		va_end (arglist);
	}
	std::cerr << std::endl;
	if (status) 
	{
		std::exit (status);
	}
	return;
}

/*====================================================================*
 *
 *   void error_at_line (int status, errno_t number, char const *file, unsigned line, char const *format, ...);
 *
 *   print error messages using a variable argument list; prefix all
 *   messages with the program_name string; suffix messages with the
 *   text returned by strerror(error) if error is not 0; exit with
 *   code if code is not 0; include filename and lineno;
 *
 *   included for compatibility with the GNU C library;
 *
 *   Motley Tools by Charles Maier <cmaier@cmassoc.net>;
 *   Copyright 2001-2006 by Charles Maier Associates;
 *   Licensed under the Internet Software Consortium License;
 *
 *--------------------------------------------------------------------*/

void oerror::error_at_line (int status, errno_t number, char const *file, unsigned line, char const *format, ...) 

{
	extern char const * program_name;
	if ((program_name) && (*program_name)) 
	{
		std::cerr << program_name << ": ";
	}
	if ((file) && (*file)) 
	{
		std::cerr << file << " (" << line << "): ";
	}
	if (number) 
	{
		std::cerr << std::strerror (number) << ": ";
	}
	if ((format) && (*format)) 
	{
		va_list arglist;
		va_start (arglist, format);
		std::vfprintf (stderr, format, arglist);
		va_end (arglist);
	}
	std::cerr << std::endl;
	if (status) 
	{
		std::exit (status);
	}
	return;
}

/*====================================================================*
 *
 *   oerror ();
 *
 *   Motley Tools by Charles Maier <cmaier@cmassoc.net>;
 *   Copyright 2001-2006 by Charles Maier Associates;
 *   Licensed under the Internet Software Consortium License;
 *
 *--------------------------------------------------------------------*/

oerror::oerror () 

{
	extern char const * program_name;
	if ((!program_name) || (!*program_name)) 
	{
		program_name = "unamed program";
	}
	errno = 0;
	return;
}

/*====================================================================*
 *
 *   ~oerror ();
 *
 *   Motley Tools by Charles Maier <cmaier@cmassoc.net>;
 *   Copyright 2001-2006 by Charles Maier Associates;
 *   Licensed under the Internet Software Consortium License;
 *
 *--------------------------------------------------------------------*/

oerror::~oerror () 

{
	extern char const * program_name;
	if (!(program_name) || !(*program_name)) 
	{
		program_name = "unamed program";
	}
	return;
}

/*====================================================================*
 *   end definition;
 *--------------------------------------------------------------------*/

#endif

