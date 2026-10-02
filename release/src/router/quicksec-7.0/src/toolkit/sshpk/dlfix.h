/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   Discrete logarithm predefined groups.
*/

#ifndef DLFIX_H
#define DLFIX_H

/* Search a parameter set of name "name". Returns true if found. */
bool ssh_dlp_set_param(const char *name, const char **outname,
                          SshMPInteger p, SshMPInteger q, SshMPInteger g);


bool ssh_dlp_is_predefined_group(SshMPInteger p, SshMPInteger q,
                                    SshMPInteger g);

#endif /* DLFIX_H */
