/********************************************************************************
 
    Copyright (c) 2014
    Lantiq Beteiligungs-GmbH & Co. KG
        Lilienthalstrasse 15, 85579 Neubiberg, Germany 
    For licensing information, see the file 'LICENSE' in the root folder of
        this software module.
 
********************************************************************************/

/*  ***************************************************************************** 
 *         File Name    : scapi_basic_types.h                                         
 *         Description  : All basic typedefs 
 *                                                                              
 *  *****************************************************************************/

/*! \file scapi_basic_types.h
    \brief This file contains the type definitions of the basic types	
*/

#ifndef _SCAPI_BASIC_TYPES_H
#define _SCAPI_BASIC_TYPES_H



/*! \brief int8
*/
typedef char int8;

/*! \brief int16
 */
typedef short int int16;

/*! \brief int32
*/
typedef int int32;

/*! \brief uint8
*/
typedef unsigned char uint8;

/*! \brief uint16
*/
typedef unsigned short uint16;

/*! \brief uint32
*/
typedef unsigned int uint32;

/*typedef unsigned long uint64;*/

/*! \brief char8 
*/
typedef char char8;

/*! \brief uchar8
*/
typedef unsigned char uchar8;


/*! \brief EXTERN
    \brief extern
*/
#define	EXTERN			extern
//#define       STATIC                  static
#define IN
#define OUT
#define IN_OUT

/*! \brief PRINT
    \brief printf
*/
#define	PRINT			printf

/* updated by shweta */
/*! \brief nullptr
    \brief Null pointer
*/
#define nullptr(Type)	(Type *)NULL

/* updated by radvajesh*/

#ifndef __IFIN_TR69_TYPES_H__
/*! \brief int64
*/
typedef long long int int64;

/*! \brief uint64
*/
typedef unsigned long long int uint64;

/*! \brief float32
*/
typedef float float32;

/*! \brief float64
*/
typedef double float64;

/*! \brief double32
*/
typedef float double32;

/*! \brief double64
*/
typedef double double64;

/*! \brief long32
*/
typedef long long32;

/*! \brief ulong32
*/
typedef unsigned long ulong32;
#endif				/* __IFIN_TR69_TYPES_H__ */

#endif				/* ] _SCAPI_BASIC_TYPES_H */
