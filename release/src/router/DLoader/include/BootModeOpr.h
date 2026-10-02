/******************************************************************************
** File Name:      BootModeOpr.h                                            *
** Author:         Apple Gao                                                 *
** DATE:           07/08/2004                                                *
** Copyright:      Spreatrum, Incoporated. All Rights Reserved.              *
** Description:    This files contains dll interface.                        *
******************************************************************************

  ******************************************************************************
  **                        Edit History                                       *
  ** ------------------------------------------------------------------------- *
  ** DATE				NAME				DESCRIPTION                       *
  ** 07/08/2004			Apple Gao			Create.							  *
******************************************************************************/

#ifndef _BOOTMODEOPR_H
#define	_BOOTMODEOPR_H

/**---------------------------------------------------------------------------*
**                         Dependencies                                      *
**---------------------------------------------------------------------------*/

#include "TTYComm2.h"
#include "Global.h"
#include "SpLog.h"
#include <pthread.h>

#define MAX_RECV_LEN  (0x8000)   //32K Bytes
#define MAX_BM_PKG_SIZE     65536  // 64K

class  CBootModeOpr: public IProtocolObserver
{
public:
    CBootModeOpr();
    virtual ~CBootModeOpr();
	virtual int OnChannelEvent( uint32_t event,
                            void* lpEventData );
	virtual int OnChannelData(void* lpData,
                           uint32_t ulDataSize,
                           uint32_t reserved =0 );

public:
    BOOL CheckBaud( DWORD dwTimeout = 1000 );
    BOOL Connect( DWORD dwTimeout = 1000 );
    BOOL Excute( DWORD dwTimeout = 1000 );
    BOOL Reset( DWORD dwTimeout = 1000 );
    BOOL ReadFlash(  DWORD dwBase,DWORD dwLength, DWORD dwTimeout = 1000  );
    BOOL   ReadPartitionFlash( DWORD dwBase,DWORD dwLength,
		                       DWORD dwOffset,DWORD dwTimeout = 1000 );
    BOOL   StartData( __uint64 llBase,__uint64 llLength ,
                      LPBYTE lpDownLoadData, DWORD dwCheckSum=0, DWORD dwTimeout = 1000, BOOL bIs64Bit = FALSE );
	BOOL   StartData( LPBYTE pID, DWORD nIDLen,__uint64 llLength ,
					  LPBYTE lpDownLoadData, DWORD dwCheckSum = 0, DWORD dwTimeout = 1000, BOOL bIs64Bit = FALSE );
    BOOL   EndData( DWORD dwTimeout  = 1000 );
    BOOL   MidstData( DWORD dwLength, LPBYTE lpDownLoadData,
		              DWORD dwTimeout = 1000, DWORD dwTotal = 0  );
    BOOL   ReadChipType( DWORD dwTimeout = 1000 );
    BOOL   ReadNVItem( DWORD dwStartAddr, DWORD dwEndAddr, 
                       unsigned short uiItemID, DWORD dwTimeout = 1000 );
    BOOL   ChangeBaud( DWORD dwTimeout = 1000 );
    BOOL   EraseFlash( DWORD dwBase,DWORD dwLength , DWORD dwTimeout = 1000 );
    BOOL   EraseFlash(  LPBYTE pID, DWORD nIDLen,DWORD dwLength, 
		                DWORD dwTimeout = 1000 );
    BOOL   Repartition( DWORD dwTimeout = 1000 );
    BOOL   Repartition( LPBYTE pPartitionInfo, DWORD dwSize, DWORD dwTimeout = 1000 );       
	BOOL   SendExtTable( LPBYTE pExtTable, DWORD dwSize, DWORD dwTimeout = 1000 );
    BOOL   AllocRecvBuffer( DWORD dwSize );
    LPBYTE GetRecvBuffer( ); 
    DWORD  GetRecvBufferSize();
    void   FreeRecvBuffer();    
    BOOL Initialize( void* lpOpenParam,
                     BOOL bBigEndian,
                     DWORD dwCookie);

    void   Uninitialize();    
    DWORD  GetLastErrorCode();     
    void   SetLastErrorCode(DWORD dwErrorCode);
    void   Log( LPCTSTR lpszLog );    
    void   GetLastErrorDescription( DWORD dwErrorCode,LPTSTR lpszErrorDescription, int nSize );    
    void   SetIsCheckCrc( BOOL bCheckCrc );
    void   StopOpr();
	//BOOL   SupportNotTransCode();
    ICommChannel*  GetChannelPtr( );
    void   SetChannel( ICommChannel* pChannel );    
    BOOL   ReadFlashType( DWORD dwTimeout = 1000 );
	BOOL   ReadFlashInfo( DWORD dwTimeout = 1000 );
    //BOOL DownFlashSpec( DWORD dwLength, LPBYTE lpDownLoadData, DWORD dwTimeout = 1000 );
    BOOL SetDebugLogState(DWORD dwState);
	void   SetStartDataInfo(BOOL bHasCheckSum);// @hongliang.xin 2009-3-17 add checksum at "StartData"	
	BOOL   ReadSectorSize( DWORD dwTimeout = 1000 );	
	BOOL   DoBeforeCheckBaud();
	BOOL   DoAfterChackBaud();
	BOOL   KeepCharge( DWORD dwTimeout = 1000 );	
    BOOL   StartRead( LPBYTE pID, DWORD nIDLen, __uint64 llLength,DWORD dwTimeout = 1000, BOOL bIs64Bit = FALSE );
    BOOL   EndRead( DWORD dwTimeout  = 1000 );
    BOOL   MidstRead( DWORD dwLength,__uint64 llOffset,DWORD dwTimeout = 1000, BOOL bIs64Bit = FALSE);

    BOOL   EnableCheckBaudCrc(BOOL bEnable);
    BOOL    GetCheckBaudCrcType();
	BOOL   PowerOff( DWORD dwTimeout  = 1000 );
    BOOL   EnableFlash( DWORD dwTimeout  = 1000 );
	BOOL   ReadTransceiverType(DWORD dwTimeout  = 1000);

    DWORD  DoNVCheckSum(LPBYTE pDataBuf,DWORD dwSize);
protected:
    //BOOL SendData( BM_PACKAGE* lpPkg,DWORD dwTimeout = 1000 );
    BOOL   SendData( LPBYTE lpData, int iDataSize, 
                BOOL bCRC = TRUE, DWORD dwTimeout = 1000 );

    BOOL   SendCommandData( pkt_type_s nCmdType , DWORD dwTimeout = 1000 );
    BOOL   SendPacketData( pkt_type_s nCmdType, 
                           const int nSendDataLen,
                           LPBYTE lpPacketData,
                           UINT uiDataLen,
                           DWORD dwTimeout = 1000 );
    
private:
    BOOL DisconnectChannel( );
    BOOL ConnectChannel(  void * lpOpenParam );

    BOOL OpenLogFile( DWORD dwCookie );

    void CloseLogFile();

    void LogOpr( LPCTSTR lpszOperation, BOOL bSuccess );

    BOOL ProcessData(void* lpData, uint32_t iDataLen );

    WORD *MakePartitionID(LPBYTE pID,DWORD nIDLen);

private:
    ICommChannel*				                m_pChannel;
	LPBYTE              m_pOrgData;
	LPBYTE              m_pOutData;
    BOOL                                m_bBigEndian;
    LPBYTE                              m_lpCurrRead;
    LPBYTE                              m_lpReceiveBuffer;
    DWORD                               m_dwReceiveLen;
    DWORD                               m_dwBufferSize;
    pkt_type_s                          m_iLastSentPktType;
    DWORD                               m_dwLastPktSize;
    BOOL                                m_bCheckCrc;

    DWORD                               m_dwLastErrorCode;
    BOOL                                m_bOperationSuccess;

    BYTE                                m_RecvData[ MAX_RECV_LEN ];
    ULONG                               m_ulRecvDataLen;

    DWORD                               m_dwRecvThreadID;
    HANDLE                              m_hRecvThreadState;
    HANDLE                              m_hRecvThread;

    //FILE                             *m_pLogFile;
    CSpLog                              m_log;
    DWORD                               m_dwCookie;


    pthread_mutex_t                     m_csRecvBbuffer;
    pthread_mutex_t                     m_csLastError;

//    HANDLE                            m_hOprEvent;
    pthread_mutex_t                     m_muReadBuf;
    pthread_cond_t                      m_cdOprEvent;
    UINT                                m_uiReadOffset;

	// @hongliang.xin 2009-3-17 for "StartData"
	BOOL								m_bHasCheckSum;
	DWORD                               m_dwBaud;

	BOOL					m_bEnableCheckBaudCrc;
	int                 			m_nCheckBaudCrc;

};



#endif // _BOOTMODEOPR_H
