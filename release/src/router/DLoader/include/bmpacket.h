/******************************************************************************
** File Name:      bmpacket.h                                            *
** Author:         Apple Gao                                                 *
** DATE:           07/07/2004                                                *
** Copyright:      Spreatrum, Incoporated. All Rights Reserved.              *
** Description:    This files contains dll interface.                        *
******************************************************************************

  ******************************************************************************
  **                        Edit History                                       *
  ** ------------------------------------------------------------------------- *
  ** DATE				NAME				DESCRIPTION                       *
  ** 07/07/2004			Apple Gao			Create.							  * 
******************************************************************************/

/**---------------------------------------------------------------------------*
**                         Dependencies                                      *
**---------------------------------------------------------------------------*/

#ifndef _BMDATAPACKET_H
#define	_BMDATAPACKET_H

#define PART_PACKET     2
#define GOOD_PACKET     1
#define ERROR_PACKET    0 

int decode_bmmsg( unsigned char* lpSrcMsg, 
    int nSrcMsgLen,
    unsigned char** lppDestMsg,
    int *pnDestMsg ,
    int bCrc );

int encode_bmmsg(  unsigned char* lpSrcMsg, 
    int nSrcMsgLen,
    unsigned char** lppDestMsg,
    int *pnDestMsg,
    int bCrc );


int  GetVerifyType(char* buf_ptr,unsigned int len);

#endif // _LOGELSIDEDPS_H