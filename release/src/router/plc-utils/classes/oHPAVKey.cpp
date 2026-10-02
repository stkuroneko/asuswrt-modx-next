/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   oHPAVKey.cpp - oHPAVKey class definition;
 *
 *   implement HomePlug AV compliant pass phrase hashing;
 *
 *   Contributor(s): 
 *	Charles Maier <charles.maier@intellon.com>
 *
 *--------------------------------------------------------------------*/

#ifndef ooHPAVKEY_SOURCE
#define ooHPAVKEY_SOURCE

/*====================================================================*
 *   system header files;
 *--------------------------------------------------------------------*/

#include <iostream>

/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

#include "../classes/oHPAVKey.hpp"
#include "../classes/omemory.hpp"
#include "../classes/oerror.hpp"

/*====================================================================*
 *   class constants;
 *--------------------------------------------------------------------*/

unsigned const oHPAVKey::DigestLength = oSHA256::DigestLength;
unsigned const oHPAVKey::DAKLength = 16;
unsigned const oHPAVKey::NMKLength = 16;
unsigned const oHPAVKey::NIDLength = 7;
unsigned const oHPAVKey::MinPhraseLength = 12;
unsigned const oHPAVKey::MaxPhraseLength = 64;
byte const oHPAVKey::MinCharValue = 0x20;
byte const oHPAVKey::MaxCharValue = 0x7E;

/*====================================================================*
 *   
 *   byte * Digest () const;
 *
 *   return the address of the 32-byte digest; HomePlug AV keys only
 *   use part of the digest; this points to the whole thing;
 *
 *--------------------------------------------------------------------*/

byte * oHPAVKey::Digest () const 

{
	return (this->mdigest);
}

/*====================================================================*
 *
 *   oHPAVKey & ExportKey (void * memory);
 *
 *   copy all 32 bytes of the digest to external memory; HomePlug AV
 *   keys only use part of the digest; this copies the whole thing;
 *
 *--------------------------------------------------------------------*/

oHPAVKey & oHPAVKey::ExportKey (void * memory) 

{
	std::memcpy (memory, this->mdigest, this->mlength);
	return (*this);
}

/*====================================================================*
 *
 *   oHPAVKey & ComputeNID (byte level);
 *   
 *   compute the HomePlugAV compliant Network Identification Key by
 *   rehashing the NMK then encoding the security level; this method 
 *   assumes that the digest is already NMK encrypted; 
 *   
 *--------------------------------------------------------------------*/

oHPAVKey & oHPAVKey::ComputeNID (byte level) 

{
	this->mlength = oHPAVKey::NIDLength;
	oSHA256::Write (this->mdigest, oHPAVKey::NMKLength);
	oSHA256::Fetch (this->mdigest);
	oHPAVKey::Hash (4);
	level <<= 4;
	this->mdigest [this->mlength - 1] >>= 4;
	this->mdigest [this->mlength - 1] |= level;
	return (*this);
}

/*====================================================================*
 *   
 *   oHPAVKey & ComputeDAK (char const * string);
 *   
 *   compute the HomePlugAV compliant Device Access Key of the NUL
 *   terminated string argument; return the object instance 
 *   reference;
 *
 *--------------------------------------------------------------------*/

oHPAVKey & oHPAVKey::ComputeDAK (char const * string) 

{
	const byte salt [] = 
	{
		0x08,
		0x85,
		0x6D,
		0xAF,
		0x7C,
		0xF5,
		0x81,
		0x85 
	};
	this->mlength = oHPAVKey::DAKLength;
	oSHA256::Write (string, std::strlen (string));
	oSHA256::Write (salt, sizeof (salt));
	oSHA256::Fetch (this->mdigest);
	oHPAVKey::Hash (999);
	return (*this);
}

/*====================================================================*
 *   
 *   oHPAVKey & ComputeNMK (char const * string);
 *   
 *   compute the HomePlugAV compliant Network Membership Key of the 
 *   the NUL terminated string argument; return the object instance 
 *   reference;
 *
 *--------------------------------------------------------------------*/

oHPAVKey & oHPAVKey::ComputeNMK (char const * string) 

{
	const byte salt [] = 
	{
		0x08,
		0x85,
		0x6D,
		0xAF,
		0x7C,
		0xF5,
		0x81,
		0x86 
	};
	this->mlength = oHPAVKey::NMKLength;
	oSHA256::Write (string, std::strlen (string));
	oSHA256::Write (salt, sizeof (salt));
	oSHA256::Fetch (this->mdigest);
	oHPAVKey::Hash (999);
	return (*this);
}

/*====================================================================*
 *
 *   bool IllegalPassPhrase (char const * phrase) const;
 *
 *   return true if string argument is an illegal HomePlug AV phrase;
 *   this method is provided for applications that do not wan to do
 *   their own pass phrase validation;
 *
 *--------------------------------------------------------------------*/

bool oHPAVKey::IllegalPassPhrase (char const * phrase) const 

{
	char const * string;
	for (string = phrase; *string; string++) 
	{
		if (oHPAVKey::IllegalCharValue (*string)) 
		{
			oerror::error (0, EINVAL, "Phrase \"%s\" has illegal characters", phrase);
			return (true);
		}
	}
	if ((unsigned)(string - phrase) < oHPAVKey::MinPhraseLength) 
	{
		oerror::error (0, EPERM, "Phrase \"%s\" is less than %d characters", phrase, oHPAVKEY_PHRASE_MIN);
		return (true);
	}
	if ((unsigned)(string - phrase) > oHPAVKey::MaxPhraseLength) 
	{
		oerror::error (0, EPERM, "Phrase \"%s\" is more than %d characters", phrase, oHPAVKEY_PHRASE_MAX);
		return (true);
	}
	return (false);
}

/*====================================================================*
 *   
 *   oHPAVKey & Print (char const * phrase);
 *
 *--------------------------------------------------------------------*/

oHPAVKey & oHPAVKey::Print (char const * phrase) 

{
	omemory::hexout (this->mdigest, this->mlength, (char)(0), &std::cout);
	if ((phrase) && (*phrase)) 
	{
		std::cout << " " << phrase;
	}
	std::cout << std::endl;
	return (*this);
}

/*====================================================================*
 *
 *   bool oHPAVKey::IllegalCharValue (unsigned c) const;
 *
 *   return true if character c is an illegal pass phrase character;
 *
 *   this method is provided for applications that want to do their
 *   own pass phrase validation;
 *
 *--------------------------------------------------------------------*/

bool oHPAVKey::IllegalCharValue (unsigned c) const 

{
	return ((c < oHPAVKey::MinCharValue) || (c > oHPAVKey::MaxCharValue));
}

/*====================================================================*
 *
 *   oHPAVKey & Hash (unsigned count);
 *
 *   Encrypt the digest the specified number of times; this is used
 *   to complicate things;
 *
 *--------------------------------------------------------------------*/

oHPAVKey & oHPAVKey::Hash (unsigned count) 

{
	while (count--) 
	{
		this->Write (this->mdigest, oSHA256::DigestLength);
		this->Fetch (this->mdigest);
	}
	return (*this);
}

/*====================================================================*
 *
 *   oHPAVKey ();
 *   
 *   allocate the secret and digest buffers; the secret is the input 
 *   or password and the digest is the output or key;
 *   
 *--------------------------------------------------------------------*/

oHPAVKey::oHPAVKey () 

{
	this->mdigest = new byte [oSHA256::DigestLength];
	this->mlength = 0;
	return;
}

/*====================================================================*
 *
 *   ~oHPAVKey ();
 *   
 *   release secret and digest buffers;
 *   
 *--------------------------------------------------------------------*/

oHPAVKey::~oHPAVKey () 

{
	delete [] this->mdigest;
	return;
}

/*====================================================================*
 *   end definition;
 *--------------------------------------------------------------------*/

#endif

