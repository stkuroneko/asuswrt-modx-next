/********************************************************************************
 
        Copyright (c) 2015
        Lantiq Beteiligungs-GmbH & Co. KG
        Lilienthalstrasse 15, 85579 Neubiberg, Germany 
        For licensing information, see the file 'LICENSE' in the root folder of
        this software module.
 
********************************************************************************/

/*  ***************************************************************************** 
 *         File Name    :  ugw_ipc.h		                                 *
 *         Description  :  This file contains all the data declarations that are
			   shared across the modules     			 *  
 *  *****************************************************************************/

/*! \file ugw_ipc.h 
    \brief This file contains all the data declarations that are shared across the modules
*/

#ifndef __UGW_IPC_H__
#define __UGW_IPC_H__

#ifdef IIP
/*! \def UGW_IPC_FIFO_DIR
    \brief IPC FIFO directory
*/
#define UGW_IPC_FIFO_DIR   "./tmp"
#endif
#ifdef ATA
/*! \def UGW_IPC_FIFO_DIR
    \brief IPC FIFO directory
*/
#define UGW_IPC_FIFO_DIR   "/tmp"
#endif

#define UGW_IPC_FIFO_PERM  0644

/* All modules write to Monitor thru this Fifo */
/*! \def UGW_IPC_MON_FIFO
    \brief All modules write to Monitor thru this Fifo
*/
#define UGW_IPC_MON_FIFO     UGW_IPC_FIFO_DIR"/MonFifo"

/* All modules write to RM thru this Fifo */
/*! \def UGW_IPC_RM_FIFO
    \brief All modules write to RM thru this Fifo
*/
#define UGW_IPC_RM_FIFO     UGW_IPC_FIFO_DIR"/RmFifo"

/* All modules write to RTP thru this Fifo */
/*! \def UGW_IPC_RTP_FIFO
    \brief All modules write to RTP thru this Fifo
*/
#define UGW_IPC_RTP_FIFO    UGW_IPC_FIFO_DIR"/RtpFifo"

/* All modules writes to APP thru this Fifo */
/* For IIP, APP = PA: for ATA, APP = ATA */
/*! \def UGW_IPC_APP_FIFO
    \brief All modules writes to APP thru this Fifo
*/
#define UGW_IPC_APP_FIFO     UGW_IPC_FIFO_DIR"/AppFifo"

/* All modules write to CM thru this Fifo */
/*! \def UGW_IPC_CM_FIFO
    \brief All modules write to CM thru this Fifo
*/
#define UGW_IPC_CM_FIFO     UGW_IPC_FIFO_DIR"/CmFifo"

/* All modules write to FA thru this Fifo */
/*! \def UGW_IPC_FA_FIFO
    \brief All modules write to FA thru this Fifo
*/
#define UGW_IPC_FA_FIFO     UGW_IPC_FIFO_DIR"/FaFifo"

/* All modules write to SS thru this Fifo */
/*! \def UGW_IPC_SS_FIFO
    \brief All modules write to SS thru this Fifo
*/
#define UGW_IPC_SS_FIFO     UGW_IPC_FIFO_DIR"/SsFifo"

/* DHCP writes to CM thru this Fifo */
/*! \def UGW_DHCP_CM_FIFO
    \brief DHCP writes to CM thru this Fifo
*/
#define UGW_DHCP_CM_FIFO   UGW_IPC_FIFO_DIR"/DhcpFifo"

/*! \def UGW_IPC_SUCCESS
    \brief Success.
*/
#define UGW_IPC_SUCCESS 0

/*! \def UGW_IPC_FAIL
    \brief Failure.
*/
#define UGW_IPC_FAIL    -1

/*! \def UGW_IPC_APP_NAME_START
    \brief IPC application - VoIP startup.
*/
#define UGW_IPC_APP_NAME_START  "VoIPStartup"

/*! \def UGW_IPC_APP_NAME_PA
    \brief IPC application - phoneApp
*/
#define UGW_IPC_APP_NAME_PA  "PhoneApp"

/*! \def UGW_IPC_APP_NAME_ATA
    \brief IPC application AtaApp
*/
#define UGW_IPC_APP_NAME_ATA  "AtaApp"

/*! \def UGW_IPC_APP_NAME_CM
    \brief IPC application Config Mode
*/
#define UGW_IPC_APP_NAME_CM    "CfgMod"

/*! \def UGW_IPC_APP_NAME_RM
    \brief IPC application Resource Manager
*/
#define UGW_IPC_APP_NAME_RM    "ResMgr"

/*! \def UGW_IPC_APP_NAME_RTP
    \brief IPC application RTP 
*/
#define UGW_IPC_APP_NAME_RTP   "Rtp"

/*! \def UGW_IPC_APP_NAME_SRTP
    \brief IPC application Srtp
*/
#define UGW_IPC_APP_NAME_SRTP "Srtp"

/*! \def UGW_IPC_APP_NAME_TR69
    \brief IPC application TR69
*/
#define UGW_IPC_APP_NAME_TR69   "TR69UA"

/*! \def UGW_IPC_APP_NAME_FA
    \brief IPC application Fax Agent
*/
#define UGW_IPC_APP_NAME_FA    "FaxAgt"

/*! \def UGW_IPC_APP_NAME_DHCP
    \brief IPC application DHCP
*/
#define UGW_IPC_APP_NAME_DHCP "Dhcp"

/*! \enum e_UGW_IPC_AppId
    \brief This enumeration is used for IPC Application ID.
*/
typedef enum {
	UGW_IPC_APP_ID_START = 1,	/*!< TBD  */
	UGW_IPC_APP_ID_APP = 2,	/*!< TBD  */
	UGW_IPC_APP_ID_CM = 3,	/*!< TBD  */
	UGW_IPC_APP_ID_RM = 4,	/*!< TBD  */
	UGW_IPC_APP_ID_RTP = 5,	/*!< TBD  */
	UGW_IPC_APP_ID_TR69 = 7,	/*!< TBD  */
	UGW_IPC_APP_ID_FA = 8,	/*!< TBD  */
	UGW_IPC_APP_ID_DHCP = 9,	/*!< TBD  */
} e_UGW_IPC_AppId;

/*!
    \brief Structure describing the IPC Message Header.
*/
typedef struct {
	uchar8 ucFrom;		/*!< ID of the module sending the message  */
	uchar8 ucTo;		/*!< ID of the module to which the message is addressed */
	/* ucTo may be just used for strict validation, since
	   the message destined for a module will be in the 
	   module's FIFO anyway
	 */
	uint16 unMsgSize;	/*!< Size of the Message */
	uint32 uiReserved;	/*!< Reserved for future use */

} x_UGW_IPC_MsgHdr;

/*! \def UGW_IPC_HDR_SIZE
    \brief Macro that defines the IPC Header Size.
*/
#define UGW_IPC_HDR_SIZE sizeof(x_UGW_IPC_MsgHdr)

/*! \def UGW_IPC_MAX_MSG_SIZE
    \brief Macro that defines the Maximum IPC message Size.
*/
#define UGW_IPC_MAX_MSG_SIZE (4192 - UGW_IPC_HDR_SIZE)

/*!
    \brief Structure describing the IPC Message.
*/
typedef struct {
	x_UGW_IPC_MsgHdr xHdr;	/*!< Buffer to contain the message */
	char8 acMsg[UGW_IPC_MAX_MSG_SIZE];	/*!< Each module is expected to write a union in the acMsg part  */

} x_UGW_IPC_Msg;

/* Error Codes */

/*! \enum e_UGW_IPC_Error
    \brief This enumeration is used for IPC error codes.
*/
typedef enum {
	UGW_IPC_NO_ERR = 0,	/*!< TBD  */
	UGW_IPC_FIFO_READ_ERR = 1,	/*!< TBD  */
	UGW_IPC_HDR_ERR,	/*!< TBD  */
	UGW_IPC_FIFO_WRITE_ERR,	/*!< TBD  */
	UGW_IPC_MSG_ERR		/*!< TBD  */
} e_UGW_IPC_Error;

/* PUBLIC Functions */

/*!       
   \brief extern integer type function 
   \param[in] iFd FIFO fd
   \param[in] ucFrom Module Id of the addressee
   \param[in] ucTo Module Id of the addressed
   \param[in] unMsgSize Size of message
   \param[in] uiReserved
   \param[in] pcMsg Pointer to message
   \return UGW_IPC_SUCCESS/UGW_IPC_FAIL
*/

EXTERN char8 UGW_IPC_SendMsg(IN int32 iFd,	/* FIFO fd */
			     IN uchar8 ucFrom,	/* Module Id of the addressee */
			     IN uchar8 ucTo,	/* Module Id of the addressed */
			     /* ucFrom and ucTo take one of e_UGW_IPC_AppId values */
			     IN uint16 unMsgSize,	/* Size of message */
			     IN uint32 uiReserved, IN char8 * pcMsg);	/* Pointer to message */

/*!
   \brief Function to receive IPC Receive Message. 
   \param[in] iFd TBD
   \param[out] pucFrom TBD
   \param[out] pucTo TBD
   \param[out] punMsgSize TBD
   \param[out] puiReserved TBD
   \param[out] pcMsg TBD
   \param[out] pErr TBD
   \return UGW_IPC_SUCCESS/UGW_IPC_FAIL
*/

EXTERN char8
UGW_IPC_RecvMsg(IN int32 iFd,
		OUT uchar8 * pucFrom,
		OUT uchar8 * pucTo,
		OUT uint16 * punMsgSize,
		OUT uint32 * puiReserved, OUT char8 * pcMsg, OUT char8 * pErr);

#endif				/* __UGW_IPC_H__ */

/*! \def UGW_OS_ReadFifo 
    \brief read data from FIFO
 */
#define UGW_OS_ReadFifo(iFd, pcRead, iSize) read(iFd, pcRead, iSize)

/*! \def UGW_OS_WriteFifo 
    \brief write data to FIFO
 */
#define UGW_OS_WriteFifo(iFd, pcWrite, iSize) write(iFd, pcWrite, iSize)
