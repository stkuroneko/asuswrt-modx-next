/**
   @copyright
   Copyright (c) 2008 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   Definitions for SSH types for backward compatibility.
*/

#ifndef SSHTYPES_H
#define SSHTYPES_H

#include "public_defs.h"

/** A Boolean type which can take the values TRUE or FALSE */
typedef bool Boolean;

#ifndef TRUE
#define TRUE true
#endif

#ifndef FALSE
#define FALSE false
#endif

typedef uint8_t    SshUInt8;
typedef uint16_t  SshUInt16;
typedef uint32_t  SshUInt32;
typedef uint64_t  SshUInt64;
typedef int8_t      SshInt8;
typedef int16_t    SshInt16;
typedef int32_t    SshInt32;
typedef int64_t    SshInt64;

#endif /* !SSHTYPES_H */
