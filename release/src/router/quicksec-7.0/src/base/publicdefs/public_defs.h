/**
   @copyright
   Copyright (c) 2011 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/*
  This header provides public definitions required by software
  modules. The definitions are considered public, because they are
  required by the public API headers.

  This particular version of the public definitions header is based on
  including relevant standard C99 headers.

*/

#ifndef PUBLIC_DEFS_H
#define PUBLIC_DEFS_H


/*
  typedef uint32_t
  typedef uint16_t
  typedef uint8_t
  typedef uintptr_t
  typedef int32_t
  typedef int16_t
  typedef int8_t
  typedef intptr_t
*/
#include <stdint.h>


/*
  typedef bool
  const bool true
  const bool false
 */
#include <stdbool.h>

/*
  typedef size_t
  NULL
 */
#include <stddef.h>


/*
  INT_MAX, etc
 */
#include <limits.h>

#endif /* PUBLIC_DEFS_H */
