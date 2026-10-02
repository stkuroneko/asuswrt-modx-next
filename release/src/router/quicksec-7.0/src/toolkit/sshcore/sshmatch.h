/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   Pattern matching utility functions.

   <keywords pattern matching, matching patterns,
   utility functions/pattern matching>
*/

#ifndef SSHMATCH_H
#define SSHMATCH_H

/** Returns true if the given string matches the pattern (which may
    contain ? and * as wildcards), and false if it does not match. */

bool ssh_match_pattern(const char *s, const char *pattern);

/** Returns true if the given port matches the port number pattern
    (which may contain '*' as wildcard for all ports, or '\<xxx',
    '\>xxx' or 'xxx..yyy' formats to specify less than, greater
    than or port range), and zero if it does not match. */

bool ssh_match_port(uint32_t port, const char *pattern);

#endif /* SSHMATCH_H */
