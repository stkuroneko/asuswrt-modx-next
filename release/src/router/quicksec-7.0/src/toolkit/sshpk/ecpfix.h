/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   Elliptic curve fixed parameters.
*/

#ifndef ECPFIX_H
#define ECPFIX_H

#ifdef SSHDIST_CRYPT_ECP
#ifdef SSHDIST_MATH_ECP
/* Prototypes */
/* Search a parameter set of name "name". Returns true if found. */

bool ssh_ecp_set_param(const char *name, const char **outname,
                          SshECPCurve E, SshECPPoint P, SshMPInteger n,
                          bool *pc);
#endif /* SSHDIST_MATH_ECP */
#endif /* SSHDIST_CRYPT_ECP */
#endif /* ECPFIX_H */
