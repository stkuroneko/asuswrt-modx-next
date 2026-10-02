/********************************************************************************
 
        Copyright (c) 2015
        Lantiq Beteiligungs-GmbH & Co. KG
        Lilienthalstrasse 15, 85579 Neubiberg, Germany 
        For licensing information, see the file 'LICENSE' in the root folder of
        this software module.
 
********************************************************************************/

/*  ***************************************************************************** 
 *         File Name    :  scapi_structs.h                                    *
 *         Description  :  This file defines all the structs used by scapi      *  
 *  *****************************************************************************/


/*! \file scapi_structs.h
    \brief This file contains all the structure definitions required for scapi
*/

#ifndef _SCAPI_STRUCTS_H
#define _SCAPI_STRUCTS_H

#include <linux/types.h>
#include <netinet/in.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdbool.h>
#include "list.h"

/* To resolve incompatibility between linux/if.h & net/if.h in packages which are including ltq_api_structs.h*/
/* This is necessary since this file will be included every where APIs are being used. Those files might have already included linux/if.h or net/if.h */
/* Needs to be included at the bottom */
#ifndef _LINUX_IF_H  
#include <net/if.h>
#endif

/*!
    \brief This is the data structure for the Route hops of TraceRoute
*/
typedef struct route_hop_d {
	char8 hophost[MAX_HOST_NAME];	/*!< Host Name */
	char8 hophost_address[MAX_IP_ADDR_LEN];	/*!< Host Address */
	uint32 hop_err_code;	/*!< Hop Error Code */
	char8 hop_rtt_time[64];	/*!< Hop Round Trip Time */
} ROUTE_HOPS_D;

/* 
    \brief This is data struct for storing the results of TraceRoute
*/
typedef struct {
        char8 caDiagState[MAX_DIAGSTATE_LEN];
        int32 iResponseTime;
        int32 iRouteHopsNumberOfEntries;
        ROUTE_HOPS_D *pxRouteHops;
} TraceRouteResp_D;


/*traceroute ends*/

/*!
    \brief This is the data structures required for getting interfaces information from get_ifcs function.
*/
typedef struct 
{       
        char ifname[IFNAMSIZE];
        char ipv4[INET_ADDRSTRLEN];
        char ipv4_netmask[INET_ADDRSTRLEN];
        char ipv6_linklocal[INET6_ADDRSTRLEN];
        char ipv6_netmask[INET6_ADDRSTRLEN];
        int flags;
}Ifc;
/*!
    \brief This is the data structures required for if_config.
*/
struct options {
   const char *name;
   const unsigned char flags;
   const unsigned char arg_flags;
   const unsigned short selector;
};

struct ARG_1_OPT {
   const char *name;
   unsigned short selector;
};

/*!
    \brief This is the data structures required for get_addr.*/

typedef struct{
        const char *name;
        unsigned short ioctl;
        int flags;
}option;

/* 
** Sructure for returning the dumpleases information to the caller of the function
*/
struct dump_lease_info
{
    uint8_t lease_mac[6];
    char ipaddr[18];
    char hostname[20];
    uint32_t expires_seconds;
}dump_lease_info;
 
typedef struct len_and_sockaddr_d {
    socklen_t len;
    union {
        struct sockaddr sa;
        struct sockaddr_in sin;
        struct sockaddr_in6 sin6;
    } u;
} len_and_sockaddr_d;
    
enum {
    LSA_LEN_SIZE_D = offsetof(len_and_sockaddr_d, u), 
    LSA_SIZEOF_SA_D = sizeof(
        union {
            struct sockaddr sa;
            struct sockaddr_in sin;
            struct sockaddr_in6 sin6;
        }
    )
    
};  
/* for NSLookup diagnostics profile */
/*!
    \brief This is the data structure for the NSLookup Diagnostics.
*/

typedef struct nslookup_diagnostics_d {
        char8 diag_state[MAX_DIAGSTATE_LEN];    /*!< Diagnostics State */
        char8 interface[MAX_IF_NAME];   /*!< Interface Name */
        char8 hostname[MAX_HOST_NAME];      /*!< Host Name */
        char8 dnsserver[MAX_HOST_NAME];    /*!< DNS Server Name or IP */
        uint32 num_repetitions;       /*!< Number of Repetitions */
        uint32 timeout;         /*!< Timeout Value */
        uint32 success_count;       /*!<  Number of successfully executed repetitions */
        uint32 result_num_entries;            /*!< Total number of Result entries */
} NSLOOKUP_DIAG_D;

/*!
    \brief This is the data structure for the Results of NSLookup Diagnostics.
*/
typedef struct result_d {
        char8 status[VALUE_MAX_LEN];         /*!<Status of the Result */
        char8 anstype[VALUE_MAX_LEN];      /*!<   */
        char8 hostname_ret[MAX_HOST_NAME];   /*!< Host Name Returned*/
        char8 ipaddresses[256]; /*!<  Comma-separated list of IPAddressesHost Address */
        char8 dnsserver_ip[MAX_IP_ADDR_LEN]; /*!< actual DNS Server IP address */
        uint32 resp_time;    /*!< Response Time */
} RESULT_D;

typedef struct {
    char8 caDiagState[MAX_DIAGSTATE_LEN];
    int32 iResponseTime;
    int32 iResultNumberOfSuccess;
    RESULT_D *pxResult;
} NSLookupResp_D;

/*rmmod related struct*/

typedef struct llist_t {               
        char8 hostname_ret[MAX_HOST_NAME];   /*!< Host Name Returned*/                 
	char *data;          	
	char8 ipaddresses[256]; /*!<  Comma-separated list of IPAddressesHost Address */
	struct llist_t *link; 
        char8 dnsserver_ip[MAX_IP_ADDR_LEN]; /*!< actual DNS Server IP address */       
} llist_t;

/*rmmod related struct*/
typedef struct {
    unsigned char opt_char;
    int param_type;
    unsigned switch_on;
    unsigned switch_off;
    unsigned incongruously;
    unsigned requires;
    void **optarg;
    int *counter;
} t_complementary;

/* ltq_dumpleases related struct */

struct dyn_lease
{
    /* Unix time when lease expires. Kept in memory in host order.
     * When written to file, converted to network order
     * and adjusted (current time subtracted) */
    uint32_t expires;
    /* "nip": IP in network order */
    uint32_t lease_nip;
    /* We use lease_mac[6], since e.g. ARP probing uses
     * only 6 first bytes anyway. We check received dhcp packets
     * that their hlen == 6 and thus chaddr has only 6 significant bytes
     * (dhcp packet has chaddr[16], not [6])
     */
    uint8_t lease_mac[6];
    char hostname[20];
    uint8_t pad[2];
    /* total size is a multiply of 4 */
} PACKED;


/* for proc/net/dev counters*/
/*!
    \brief This is the data structure to store counter values of /proc/net/dev.
*/

typedef struct interface_stats {
    struct interface_stats *next, *prev;
    char if_name[16];                      	/* interface name        */
    unsigned long long rx_pkt_counter;  	/* total packets received       */
    unsigned long long tx_pkt_counter;  	/* total packets transmitted    */
    unsigned long long rx_bytes_counter;    	/* total bytes received         */
    unsigned long long tx_bytes_counter;    	/* total bytes transmitted      */
    unsigned long rx_errors_counter;    	/* bad packets received         */
    unsigned long tx_errors_counter;    	/* packet transmit problems     */
    unsigned long rx_dropped_counter;   	/* no space in linux buffers    */
    unsigned long tx_dropped_counter;   	/* total transmit dropped counter */
    unsigned long rx_multicast_counter; 	/* total multicast received counter */
    unsigned long rx_compressed_counter;	/* received compressed counter */
    unsigned long tx_compressed_counter;	/* transmitted compressed counter */
    unsigned long collisions_counter;		/* collision counter */

    /* detailed rx_errors: */
    unsigned long rx_length_errors_counter;
    unsigned long rx_over_errors_counter;   /* receiver ring buff overflow  */
    unsigned long rx_crc_errors_counter;    /* recved pkt with crc error    */
    unsigned long rx_frame_errors_counter;  /* recv'd frame alignment error */
    unsigned long rx_fifo_errors_counter;   /* recv'r fifo overrun          */
    unsigned long rx_missed_errors_counter; /* receiver missed packet     */
    /* detailed tx_errors */
    unsigned long tx_aborted_errors_counter;
    unsigned long tx_carrier_errors_counter;
    unsigned long tx_fifo_errors_counter;
    unsigned long tx_heartbeat_errors_counter;
    unsigned long tx_window_errors_counter;
} INTERFACE;

/*!
	\brief Structure containing the information related to each block in gzip
*/
typedef struct {
	int32_t nBlockStart;/*!< Specifies the window position of the current block at the begining*/
	unsigned int unHashIndex; /*!< String hash index */
	unsigned int unPrevLength; /*!< The previous match best length */
	unsigned int unStringStart; 
	unsigned int unMatchStart;   
	unsigned int unValidBytesAhead; 
	uint8_t *punListBuffer;
	uint16_t *punDistBuffer;
	uint8_t *punOutBuf;
	uint8_t  *punWindow;
	uint16_t  *punPrev;
	int32_t nIsize;     
	unsigned int unOutCount;    /*!< Number of bytes in output buffer */
	signed char cEOFile;    /*!< set if end of input file */
	unsigned short unBitBuffer;
	int nBitValid;
	uint32_t *punCrc32Table;
	uint32_t unCrc;   /*!< contents of shift register*/
} GzipGlobals;

/*!
	\brief Datainfo structure contains the information regarding the code generated in each block
*/
typedef struct DataInfo {
	union {
		uint16_t unFreqCount;       
		uint16_t unCode;      
	} FreqCode;
	union {
		uint16_t unFartherNode;        /*!< Huffman tree father node*/
		uint16_t unLen;        /*!< Bit string length*/
	} DataLen;
} DataInfo;

/*!
	\brief Structure containing the description of a tree
*/
typedef struct TreeDesc {
	DataInfo *pxDynTree;  
	DataInfo *pxStaticTree;   
	const uint8_t *punExtraBits;  
	int nExtraBase;     
	int nMaxelements; /*!< Maximum elements int the tree */ 
	int nMaxCodeBitLen;  
	int nLongCodeFreq;   
} TreeDesc;

/*!
	\brief structure containing the variables for forming Length and Distance tree
*/
typedef struct GzipGlobal2 {
	uint16_t nHeap[SIZE_HEAP];     /*!< Huffman tree heap */
	int nHeapLen;            /*!< Number of elements */
	int nHeapMaxFreq;            /*!< Number of element of largest frequency */
	DataInfo xDynLitLenTree[SIZE_HEAP];   /*!< literal and length tree */
	DataInfo xDynDistTree[2 * DIST_CODES + 1]; /*!< distance tree */
	DataInfo xStaticLiteralTree[LIT_LEN_CODES + 2];
	DataInfo xStaticDistTree[DIST_CODES];
	DataInfo xBitLenTree[2 * BITLEN_CODES + 1];
	TreeDesc xLenDesc;
	TreeDesc xDistDesc;
	TreeDesc xBitLenDesc;
	uint16_t unBitLenCount[BITS_MAX + 1];
	uint8_t unSubTreeDepth[2 * LIT_LEN_CODES + 1];
	uint8_t unLengthCode[MAXLEN_MATCH - MINLEN_MATCH + 1];
	uint8_t unDistCode[512];
	int nBaseLength[LENGTH_CODES];
	int nBaseDist[DIST_CODES];
	uint8_t unFlagBuf[BUF_SIZE_LIT / 8];
	unsigned int unIndexListBuffer;   /*!< punListBuffer running index*/
	unsigned int unIndexDistBuffer;      /*!< punDistBuffer running index*/
	unsigned int unIndexFlagBuf;     /*!< unFlagBuf running index*/
	uint8_t unCurrFlags;               /*!< the flags which aoe not saved in unFlagBuf */
	uint8_t unCurrFlagBit;            
	int32_t nOptLen;             /*!< current block with optimal trees bit length*/
	int32_t nStaticLen;          /*!< current block with static trees with bit length*/
	int32_t nCompressedLen;      /*!< compressed file total len*/
}GzipGlobal2;
/*!
	/brief Structure used to store the last modification time of the file 
*/
typedef struct unpack_info_t {
	time_t nMtime;
} unpack_info_t;

/*!
	/brief Structure used to form a huffman tree table 
*/
typedef struct HuffTreeTable {
	unsigned char ucExtraBits;    /*!< Extra bits or operation*/
	unsigned char ucNoOfBits;    /*!< Code or subcode number bits */
	union {
		unsigned short unLenDistBase;   /*!< length , literal or distance base */
		struct HuffTreeTable *pxHuffTreeTable;   /*!< Points to the next level of table */
	} Next;
} HuffTreeTable;

/*!
	/brief Structure used for each block which holds the method used for its compression and the related data pertaining to decompression
*/
typedef struct StateTable {
	off_t nGunzipBytesOut;
	uint32_t unGunzipCrc;

	int nGunzipSrcFd;
	unsigned int unGunzipOutbufCount; 

	unsigned char *ucGunzipWindow;

	uint32_t *unGunzipCrcTable;


	unsigned int unGunzipBitBuf; 
	unsigned char ucGunzipBits; /*!< number of bits in bit buffer */

	/*!< compressed data */
	unsigned char *pucByteBuffer;     
	off_t nCompressedBytesRead;         
	unsigned int unByteBufferOffset;   
	unsigned int unByteBufferSize;      

	/*!< gunzip_inflateCodes() data */
	unsigned int unInflateCodesMaskLen; /*!< Bit length and bit distance masks*/
	unsigned int unInflateCodesMaskDist; /*!< Bit length and bit distance masks for bits*/
	unsigned int unInflateCodeBitBuf; 
	unsigned int unInflateCodesNumBit; /*!< bit buffer number of bits*/
	unsigned int unInflateCodesWinPos; /*!< current ucGunzipWindow position */
	HuffTreeTable *pxInflateCodesTableLen;
	HuffTreeTable *pxInflateCodesTableDist;
	unsigned int unInflateCodesBitLen;
	unsigned int unInflateCodesBitDist;
	unsigned int unInflateCodesLenIndex; /*!< length and index*/
	unsigned int unInflateCodesDistIndex;
	unsigned char ucResumeCopy;

	/*!< gunzip_InflateGetNextWindow() data */
	signed char cMethod; /*!< -1 specifies stored, -2 specifies codes */
	signed char cNeedAnotherBlock;
	signed char cEndReached;

	/*!< gunzip_inflateStored() data */
	unsigned int unInflateStoredBitLen;
	unsigned int unInflateStoredBitDist;
	unsigned int unInflateStoredBits;
	unsigned int unInflateStoredWinPos;

	const char *pcErrorMsg;
	jmp_buf nErrorJmp;
}StateTable;

#define MAX_LEN_PARAM_VALUE_D 128 /*!< Parameter Value string length */
#define MAX_LEN_VALID_VALUE_D 1024 /*!< Parameter valid value string length */
#define MAX_LEN_PARAM_NAME_D 256 /*!< Parameter Name string length */
#define MAX_LEN_OBJNAME_D 256 /*!< Object Name string length */

/* \brief ControlDCtl Structure fields.  
 * MAX_LEN_PARAM_VALUE is used for cal set/get
*/
typedef struct {
    char sCmd[MAX_LEN_PARAM_VALUE_D];  /*Command to start the daemon*/
    char sKeyName[MAX_LEN_PARAM_VALUE_D]; 
    int32_t nDelay; /*Delay(sec) by which the daemon respawn .Valid value in between 0 and 30*/
    int32_t nRespawn; /*Respawn option*/
} ControlDArgs_t;

/* \brief for proc/meminfo counters*/
/*!
    \brief This is the data structure to stores values of /proc/meminfo.
*/
typedef struct
{
    uint32_t uTotal;            /*Total memory available in device */
    uint32_t uFree;             /*Free memory available in device */
    uint32_t uBuffers;          /*Buffers consumed in total memory */
    uint32_t uCached;           /*Cache consumed in total memory */
} MemInfo;

/* \brief for proc/cpuinfo counters*/
/*!
    \brief This is the data structure to stores values of /proc/cpuinfo.
*/
typedef struct
{
    uint32_t CpuHz;            /*CPU Clock frequency */

} CPUInfo;

/*! 
 *     \brief Structure containing the call parameters(name,faultcode) 
 *           functions and Callbacks. 
 *           */
typedef struct
{
	char sName[MAX_LEN_OBJNAME_D];/*!< Name of the parameter */
	int RespCode;/*!< Fault response */
}ProcdRespCode;

/*! 
  \brief Structure containing the parameters list(name,value,type) that are passed in related functions and Callbacks.   
  */
typedef struct
{
        char sParamName[MAX_LEN_PARAM_NAME_D];    /*!< Parameter Name */
        char sParamValue[MAX_LEN_PARAM_VALUE_D];  /*!< Parameter Value */
        struct list_head xPlist;                         /*!< Traverse List */
}ProcdParamList;


/*!
  \brief  Structure contains respawn_info parameters
*/
typedef struct respawn_info
{
        bool bRespawn;                  /*!< Enable/Disable*/
        int32_t nRespawnThreshold;    /*!< Respawn threshold*/
        int32_t nRespawnTimeout;      /*!< Respawn timeout*/
        int32_t nRespawnRetry;        /*!< Maximum Respawn retries*/
}ProcdRespawnObj;

/*!
  \brief  Structure contains procd_info parameters
*/
typedef struct procd_info
{
        /*Note : This structure can be updated with more arguments in future*/
        ProcdRespawnObj xRespawn;               /*!< respawn information, respawn automatically if process terminated*/
        ProcdParamList *pxData;                         /*!< name-value pairs */
        ProcdParamList *pxEnv;                  /*!< environment variables*/
        ProcdParamList *pxLimits;                       /*!< ulimit for the process  */
        ProcdParamList *pxTrigger;                      /*!< List of trigger files*/
        int nNice;                              /*!< priority of the process*/
        char sNetdev[MAX_LEN_PARAM_VALUE_D];      /*!< device name  */
        char sServiceName[MAX_LEN_PARAM_VALUE_D]; /*!< Unique service name*/
        char sCommand[MAX_LEN_VALID_VALUE_D];     /*!< Command to be spawned*/
        char sConfFile[MAX_LEN_PARAM_VALUE_D];    /*!< Configuration file name*/
}ProcdObj;

typedef struct {
    char hwAddr[50];
    char device[20];
}macEntry_t;

typedef struct {
    int numOfEntires;
    macEntry_t macEntry[MAX_ARP_ENTRY];
}macTable_t;

typedef struct {
    char ipAddr[ARP_BUFFER_LEN];
    char hwAddr[ARP_BUFFER_LEN];
    char device[ARP_BUFFER_LEN];
}arpEntry_t;

typedef struct {
    int numOfEntires;
    arpEntry_t arpEntry[MAX_ARP_ENTRY];
}arpTable_t;

#endif // _SCAPI_STRUCTS_H
