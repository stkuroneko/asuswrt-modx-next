/********************************************************************************
 
        Copyright (c) 2015
        Lantiq Beteiligungs-GmbH & Co. KG
        Lilienthalstrasse 15, 85579 Neubiberg, Germany 
        For licensing information, see the file 'LICENSE' in the root folder of
        this software module.
 
********************************************************************************/

/*  ***************************************************************************** 
 *         File Name    :  scapi_defs.h                                       *
 *         Description  :  This file defines macros used in scapi               *  
 *  *****************************************************************************/


/*! \file scapi_defs.h
    \brief This file defines the constants and macros used in scapi
*/

#ifndef _SCAPI_DEFS_H
#define _SCAPI_DEFS_H

#include <syslog.h>
#include <stdarg.h>
#include <stdio.h>
#include <fcntl.h>

#ifndef IN
#define IN
#endif

#ifndef OUT
#define OUT
#endif

#ifndef INOUT
#define INOUT
#endif 

/* END CUSTOM ERROR CODES */

#define KILO    1e3
#define MEGA    1e6
#define GIGA    1e9

#define LOG10_MAGIC 1.25892541179

#define IW_NUM_OPER_MODE        7

#ifndef SCAPI_MAC_LEN
#define SCAPI_MAC_LEN 32
#endif

#define ENABLE                             1       /*!<  Enabled specifier. */
/*! \def ENABLE
    \brief Macro that defines the Enabled specifier.
*/

#define DISABLE                    0       /*!<  Disabled Specifier */
/*! \def DISABLE
    \brief Macro that defines the Disabled Specifier
*/

#ifndef SCAPI_BLOCK 
#define SCAPI_BLOCK 1
#endif

#ifndef SCAPI_UNBLOCK 
#define SCAPI_UNBLOCK 0
#endif


#ifndef MAX_HOP_EXCEED 
/*! \def MAX_HOP_EXCEED
    \brief Macro that defines the return value for 'maximum hop count' exceeded for trace_route() function
*/ 
#define MAX_HOP_EXCEED -999
#endif
#ifndef DEST_REACHED
/*! \def DEST_REACHED
    \brief Macro that defines the return value if destination is reached for trace_route() function
*/
#define DEST_REACHED 0
#endif

#ifndef IFNAMSIZE
/*! \def IFNAMSIZE
    \brief Macro that defines the maximum length of Interface Name.
*/
#define IFNAMSIZE 15            /*!<  Maximum length of Interface Name */
#endif

/*!\def MAX_TAG_LEN 
   \brief This macro denotes maximum tag length
*/
#define MAX_TAG_LEN                     64

/*! \def MAX_HOST_NAME
    \brief Macro that defines the Maximum Host Name.
*/
#define MAX_HOST_NAME              257  /*!<  Maximum Host Name. */

#ifndef MAX_TR69_ID_LEN
/*! \def MAX_TR69_ID_LEN
    \brief Macro that defines the Maximum TR-069 Identifier Length.
*/
#define MAX_TR69_ID_LEN 256     /*!< Maximum TR-069 Identifier Length. */
#endif

#ifndef MAX_IP_ADDR_LEN
/*! \def MAX_IP_ADDR_LEN
    \brief Macro that defines the maximum IP address length.
*/
#define MAX_IP_ADDR_LEN 16      /*!< Maximum IP address length. */
#endif

/*! \def MAX_DIAGSTATE_LEN
    \brief Macro that defines the Maximum Diagnostic State Length.
*/
#define MAX_DIAGSTATE_LEN          65   /*!<  Maximum Diagnostic State Length. */

/*! \def VALUE_MAX_LEN
    \brief Macro that defines the maximum value sttring length.
*/
#define VALUE_MAX_LEN                                                           64      /*!<  Maximum value sttring length. */

/*! \def MAX_IF_NAME
    \brief Macro that defines the Maximum Interface name.
*/      
#define MAX_IF_NAME                257  /*!<  Maximum Interface name. */

/*! \def MAX_HOST_NAME
    \brief Macro that defines the Maximum Host Name.
*/
#define MAX_HOST_NAME              257  /*!<  Maximum Host Name. */

/* Macro for rmmod.c and insmod.c
*/
#define CONFIG_DEFAULT_MODULES_DIR "/lib/modules/"

/*Macro related to ltq_dumpleases */

#define CONFIG_DHCPD_LEASES_FILE "/var/lib/misc/udhcpd.leases"

/*Macro related to ltq_dumpleases */

#define LEASES_FILE             CONFIG_DHCPD_LEASES_FILE

/*!
	\brief SIZE_INBUF input buffer size in gzip
*/
#ifndef SIZE_INBUF
#define SIZE_INBUF  0x2000 
#endif

/*!
	\brief SIZE_OUTBUF Size of output buffer in gzip
*/
#ifndef SIZE_OUTBUF
#define SIZE_OUTBUF   8192 
#endif 

/*!
	\brief SIZE_BUF_DIST Size of distance buffer
*/
#ifndef SIZE_BUF_DIST
#define SIZE_BUF_DIST 0x2000
#endif

/*!
	\brief SIZE_WINDOW Size of thw window 
*/
#ifndef SIZE_WINDOW
#define SIZE_WINDOW 0x8000
#endif

/*!
	\brief BITS_HASH Maximum number of bits used in hash string
*/
#ifndef BITS_HASH
#define BITS_HASH  13
#endif

/*!
	\brief SIZE_HASH
*/
#ifndef SIZE_HASH
#define SIZE_HASH (unsigned)(1<<BITS_HASH)
#endif

/*!
	\brief MASK_HASH
*/
#ifndef MASK_HASH
#define MASK_HASH (SIZE_HASH-1)
#endif

/*!
	\brief MASK_WINDOW
*/
#ifndef MASK_WINDOW
#define MASK_WINDOW (SIZE_WINDOW-1)
#endif

/*!
	\brief MINLEN_MATCH The length required for minimum match
*/
#ifndef MINLEN_MATCH
#define MINLEN_MATCH  3 
#endif

/*!
	\brief MAXLEN_MATCH The length on the maximum match
*/
#ifndef MAXLEN_MATCH
#define MAXLEN_MATCH  258
#endif

/*!
	\brief BITS
*/
#ifndef BITS
#define BITS 16
#endif
/*!
	\brief LOOKAHEAD_MIN Minimum lookahed
*/
#ifndef LOOKAHEAD_MIN 
#define LOOKAHEAD_MIN (MAXLEN_MATCH+MINLEN_MATCH+1)
#endif

/*!
	\brief DIST_MAX The maximum distance
*/
#ifndef DIST_MAX
#define DIST_MAX  (SIZE_WINDOW-LOOKAHEAD_MIN)
#endif

/*!
	\brief REPEAT_3_6 Previous bit is repeated 3 to six times(The repeat count is two bits)
*/
#ifndef REPEAT_3_6
#define REPEAT_3_6  16
#endif

/*!
	\brief ZERO_REP_3_10
*/
/* Zero length is repeated 3 to 10 times (The repeat count is three bits) */
#ifndef ZERO_REP_3_10
#define ZERO_REP_3_10    17 
#endif

/*!
	\brief ZERO_REP_11_138
*/
/* Zero length is repeated 11 to 138 times  (The repeat count is seven bits) */
#ifndef ZERO_REP_11_138
#define ZERO_REP_11_138  18
#endif

/*!
	\brief BUF_SIZE_LIT
*/
#ifndef BUF_SIZE_LIT
#define BUF_SIZE_LIT  0x2000
#endif

/*!
	\brief MAX_OF(a,b)
*/
#ifndef MAX_OF
#define MAX_OF(a,b) (((a)>(b))?(a):(b))
#endif

/*!
	\brief HASH_HEAD
*/
#ifndef HASH_HEAD
#define HASH_HEAD (xGzipGlobals.punPrev + SIZE_WINDOW)
#endif

/*!
	\brief SIZE_BUF
*/
#ifndef SIZE_BUF
#define SIZE_BUF (8 * sizeof(xGzipGlobals.unBitBuffer))
#endif

/*!
	\brief HASH_SHIFT
*/
#ifndef HASH_SHIFT
#define HASH_SHIFT  ((BITS_HASH+MINLEN_MATCH-1) / MINLEN_MATCH)
#endif

/*!
	\brief VERY_FAR
*/
#ifndef VERY_FAR
#define VERY_FAR 4096
#endif

/*!
	\brief BITS_MAX
*/
/* No code should exceed BITS_MAX bits */
#ifndef BITS_MAX
#define BITS_MAX 15
#endif

/*!
	\brief MAX_BITLEN_BIT
*/
/* No Bit length code must exceed MAX_BITLEN_BIT bits */
#ifndef MAX_BITLEN_BIT 
#define MAX_BITLEN_BIT 7 
#endif

/*!
	\breif LENGTH_CODES
*/
/* maximum number of length codes */
#ifndef LENGTH_CODES
#define LENGTH_CODES 29
#endif

/*!
	\brief LIT
*/
/*Maximum number of literal bytes */
#ifndef LIT
#define LIT  256   
#endif

/*!
	\brief BLOCK_END
*/
/* Indiates end of the block literal */
#ifndef BLOCK_END
#define BLOCK_END 256 
#endif

/*!
	\brief LIT_LEN_CODES
*/
/* Specifies the number of literal amd length codes */
#ifndef LIT_LEN_CODES
#define LIT_LEN_CODES (LIT+1+LENGTH_CODES)
#endif

/*!
	\brief DIST_CODES
*/
/*Maximum number of distance codes */
#ifndef DIST_CODES
#define DIST_CODES   30 
#endif

/*!
	\brief BITLEN_CODES
*/
/* number of codes used to transfer the bit lengths */
#ifndef BITLEN_CODES
#define BITLEN_CODES  19 
#endif

/*!
	\brief BLOCK_STORED
*/
/* Represents the method for Stored block */
#ifndef BLOCK_STORED
#define BLOCK_STORED 0  
#endif

/*!
	\brief TREES_STATIC
*/
/*Represents the methosd static tree */
#ifndef TREES_STATIC
#define TREES_STATIC 1 
#endif

/*!
	\brief TREES_DYN
*/
/* Represents the method dynamic tree */
#ifndef TREES_DYN
#define TREES_DYN    2 
#endif

/*!
	\brief HASH_UPDATE(h,c)
*/
/* The hash value is updated with the given input byte*/
#ifndef HASH_UPDATE
#define HASH_UPDATE(h, c) (h = (((h)<<HASH_SHIFT) ^ (c)) & MASK_HASH)
#endif

/*!
	\brief SIZE_HEAP Heap size
*/
#ifndef SIZE_HEAP
#define SIZE_HEAP (2*LIT_LEN_CODES + 1)
#endif

/*!
	\brief  xGzipGlobal2
*/
#ifndef xGzipGlobal2
#define xGzipGlobal2 (*((struct GzipGlobal2*)(pxPtrToGzipGlobals)))
#endif

/*!
	\brief DIST_CODE(distance)
*/
#ifndef DIST_CODE
#define DIST_CODE(distance) \
	((distance) < 256 ? xGzipGlobal2.unDistCode[distance] : xGzipGlobal2.unDistCode[256 + ((distance)>>7)])
#endif

/*!
	\brief FIND_SMALLER(tree, n, m)
*/
#ifndef FIND_SMALLER
#define FIND_SMALLER(tree, n, m) \
	(tree[n].FreqCode.unFreqCount < tree[m].FreqCode.unFreqCount \
	|| (tree[n].FreqCode.unFreqCount == tree[m].FreqCode.unFreqCount && xGzipGlobal2.unSubTreeDepth[n] <= xGzipGlobal2.unSubTreeDepth[m]))
#endif

/*!
	\brief LEAST
*/
#ifndef LEAST
#define LEAST 1
#endif

/*!
	\brief CONTROLDCTL
*/
#ifndef CONTROLD_SOCK_PATH
#define CONTROLD_SOCK_PATH "/tmp/controld_socket"
#endif

/*!
	\brief REMOVE_PQ(tree, tip)
*/
#ifndef REMOVE_PQ
#define REMOVE_PQ(tree, tip) \
{ \
	tip = xGzipGlobal2.nHeap[LEAST]; \
	xGzipGlobal2.nHeap[LEAST] = xGzipGlobal2.nHeap[xGzipGlobal2.nHeapLen--]; \
	gzip_downHeap(tree, LEAST); \
}
#endif

/*!
	\brief CODE_SEND(c, tree)
*/ 
#ifndef CODE_SEND
#define CODE_SEND(c, tree) gzip_sendValueForBits(tree[c].FreqCode.unCode, tree[c].DataLen.unLen)
#endif

/*!
	\brief BLOCK_FLUSH(eofval)
*/
/* Used to flush the current block */
#ifndef BLOCK_FLUSH
#define BLOCK_FLUSH(eofval) \
	gzip_compressedLenForFile( \
	xGzipGlobals.nBlockStart >= 0L \
	? (char*)&xGzipGlobals.punWindow[(unsigned)xGzipGlobals.nBlockStart] \
	: (char*)NULL, \
	(int32_t)xGzipGlobals.unStringStart - xGzipGlobals.nBlockStart, \
	(eofval) \
	)
#endif

/*!
	/brief STRING_INSERT Acts as a dictionary 
*/
#define STRING_INSERT(str,head_match) \
{ \
    HASH_UPDATE(xGzipGlobals.unHashIndex, xGzipGlobals.punWindow[(str) + MINLEN_MATCH - 1]); \
    xGzipGlobals.punPrev[(str) & MASK_WINDOW] = head_match = HASH_HEAD[xGzipGlobals.unHashIndex]; \
    HASH_HEAD[xGzipGlobals.unHashIndex] = (str); \
}

/*!
	/brief used to determine endianness
*/ 
#if defined(__BIG_ENDIAN__) && __BIG_ENDIAN__
# define BIG_ENDIAN_VAL 1
# define LITTLE_ENDIAN_VAL 0
#elif defined(__BYTE_ORDER) && __BYTE_ORDER == __BIG_ENDIAN
# define BIG_ENDIAN_VAL 1
# define LITTLE_ENDIAN_VAL 0
#elif defined(__BYTE_ORDER) && __BYTE_ORDER == __BIG_ENDIAN
# define BIG_ENDIAN_VAL 1
# define LITTLE_ENDIAN_VAL 0
#elif (defined(__BYTE_ORDER) && __BYTE_ORDER == __LITTLE_ENDIAN) || defined(__386__)
# define BIG_ENDIAN_VAL 0
# define LITTLE_ENDIAN_VAL 1
#else
#error "Cannot determine endianness"
#endif

/*!
	/brief PACK
*/
#ifndef PACK
#define PACK __attribute__ ((__packed__))
#endif

/*!
	/brief Used to convert to little endian
*/
#if BIG_ENDIAN_VAL
# define CONV_LE32(x) bswap_32(x)
#else
# define CONV_LE32(x) (x)
#endif

/*!
	\brief INFLATE_STORED
*/
#ifndef INFLATE_STORED
#define INFLATE_STORED -1
#endif

/*!
	\brief INFLATE_CODE
*/
#ifndef INFLATE_CODE
#define INFLATE_CODE -2
#endif

/*!
	\brief MAX_BYTEBUF
*/
#ifndef MAX_BYTEBUF
#define MAX_BYTEBUF  0x4000
#endif
/*!
	\breif FREE
*/
#ifndef FREE
#define FREE(x) if(x != NULL) free(x);
#endif

/* !
	\brief procd start/stop macros
*/
#define PROCD_START "start"
#define PROCD_STOP "stop"

/* !
	\brief procd respawn on/off macros
*/
#define RESPAWN_PROCD_ON 1
#define RESPAWN_PROCD_OFF 0

#define xstr(s) str(s)
#define str(s) #s

#define MAX_ARP_ENTRY    100 
#define ARP_CACHE       "/proc/net/arp"
#define MAC_CACHE       "/proc/ppa/api/session"
#define ARP_STRING_LEN   256 
#define ARP_BUFFER_LEN  (ARP_STRING_LEN + 1)

/* Format for fscanf() to read the 1st, 4th, and 6th space-delimited fields */
#define ARP_LINE_FORMAT "%" xstr(ARP_STRING_LEN) "s %*s %*s " \
                        "%" xstr(ARP_STRING_LEN) "s %*s " \
                        "%" xstr(ARP_STRING_LEN) "s"

/* !
	\brief macros for cron files
*/
#define CRON_ROOT_FILE "/etc/cron/root"
#define CRON_ROOT_FILE_TEMP "/etc/cron/root_temp"
#define CRON_DIR "/etc/cron/"

/* !
	\brief macros for ADD/DELETE used for setting cronjob
*/
#define ADD_ENTRY         1
#define DELETE_ENTRY      2

#endif //_SCAPI_DEFS_H
