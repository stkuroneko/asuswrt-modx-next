// BootModeOpr.cpp : Defines the entry point for the DLL application.
//
#include <time.h>
#include "BootModeOpr.h"

#include "OptionHelpper.h"

#include "ExePathHelper.h"

#include "confile.h"

#include <errno.h>



extern "C"
{
#include "bmpacket.h"
#include "crc16.h"
}

#define  WM_RCV_CHANNEL_DATA              WM_APP + 301 // channel data received
#define  WM_CHANNEL_CLOSE                 WM_RCV_CHANNEL_DATA + 1

#define LOG_FILENAME_PREFIX     _T("BootModeOpr_")
#define MAX_LOG_LEN             256

extern COptionHelpper ohObject;
/////////////////////////////////////////////////////////////////////////////
// CBootModeOpr
CBootModeOpr::CBootModeOpr()
{
	m_pOrgData = NULL;
	m_pOutData = NULL;
	m_pOrgData = new BYTE[MAX_BM_PKG_SIZE];
	m_pOutData = new BYTE[MAX_BM_PKG_SIZE*2+4];
	//m_lpCurrRead = NULL;
	m_bCheckCrc  = TRUE;
	m_bBigEndian = TRUE;

	memset( m_RecvData, 0,MAX_RECV_LEN );
	m_ulRecvDataLen = 0;
	m_iLastSentPktType = BSL_PKT_TYPE_MAX;
	m_dwLastErrorCode = 0;
	m_bOperationSuccess = FALSE;
	//m_pLogFile  = NULL;
	m_pChannel = NULL;

	m_dwRecvThreadID = 0;
	m_hRecvThread = NULL;
	m_hRecvThreadState = NULL;
	//    m_hOprEvent = NULL;

	m_lpReceiveBuffer = NULL;
	m_dwReceiveLen = 0;
	m_dwBufferSize = 0;
	m_dwLastPktSize = 0;
	m_uiReadOffset = 0;
	m_dwCookie = 0;

	m_bHasCheckSum  = FALSE;

	m_dwBaud = DEFAULT_BAUDRATE;
	m_bEnableCheckBaudCrc = FALSE;
	m_nCheckBaudCrc		= -1;



	m_csRecvBbuffer = PTHREAD_MUTEX_INITIALIZER;
	m_csLastError = PTHREAD_MUTEX_INITIALIZER;

	m_muReadBuf = PTHREAD_MUTEX_INITIALIZER;
	m_cdOprEvent = PTHREAD_COND_INITIALIZER;

	/*pthread_mutex_init(&m_csRecvBbuffer,NULL);  
	pthread_mutex_init(&m_csLastError,NULL);  
	pthread_mutex_init(&m_muReadBuf,NULL);  
	pthread_cond_init(&m_cdOprEvent,NULL);*/


}

CBootModeOpr::~CBootModeOpr()
{
    FreeRecvBuffer();

	/*pthread_mutex_destroy(&m_csRecvBbuffer);
	pthread_mutex_destroy(&m_csLastError);
	pthread_mutex_destroy(&m_muReadBuf);
	pthread_cond_destroy(&m_cdOprEvent);*/
	SAFE_DELETE_ARRAY(m_pOrgData);
	SAFE_DELETE_ARRAY(m_pOutData);

}

BOOL CBootModeOpr::Initialize( void* lpOpenParam,
                               BOOL bBigEndian,
                               DWORD dwCookie)
{
	OpenLogFile( dwCookie );

	m_pChannel = new CTTYComm2();

	if(m_pChannel == NULL)
	{
	    m_log.LogRawStr(SPLOGLV_INFO,"Create channel object fail.");
	    CloseLogFile();
	    return FALSE;
	}

	m_pChannel->SetObserver((IProtocolObserver*)this);

	//InitTTYSignal();

	m_bBigEndian = bBigEndian;
	memset( m_RecvData,0, MAX_RECV_LEN );
	m_ulRecvDataLen = 0;
	m_iLastSentPktType = BSL_PKT_TYPE_MAX;
	m_dwLastErrorCode = 0;
	m_bOperationSuccess = FALSE;

	//m_pChannel->SetProperty( 0,PPI_Endian,(void*)m_bBigEndian );


	return ConnectChannel( lpOpenParam );
}

void CBootModeOpr::Uninitialize()
{
    DisconnectChannel();

    //UninitTTYSignal();

    //m_lpCurrRead       = NULL;
    m_bCheckCrc  = TRUE;

    memset( m_RecvData,0, MAX_RECV_LEN );
    m_ulRecvDataLen = 0;

    m_iLastSentPktType = BSL_PKT_TYPE_MAX;

    CloseLogFile();

  //ReleaseBmChannel(m_pChannel);
  if(m_pChannel)
  {
        delete m_pChannel;
        m_pChannel = NULL;
  }


 //   CoUninitialize();
}

BOOL CBootModeOpr::CheckBaud( DWORD dwTimeout /* = 1000  */)
{
    BYTE btSendData[ PACHET_HDR_LEN*2 ];
    memset( btSendData, 0x7E, PACHET_HDR_LEN*2);

	int nSize = ohObject.Get7ENumOnce();
	if(nSize<0)
	{
		nSize = 1;
	}
	if(nSize > PACHET_HDR_LEN*2 )
	{
		nSize = PACHET_HDR_LEN*2;
	}

    //Clear received data, maybe there exist dirty data.
    //m_pChannel->SetProperty(0,PPI_CLEAR_KEEP_PACKAGE,(LPCVOID)true);
    //m_pChannel->Clear();
    //m_pChannel->SetProperty(0,PPI_CLEAR_KEEP_PACKAGE,(LPCVOID)false);
    //BOOL bSuccess = SendPacketData( BSL_CMD_CHECK_BAUD,nSize,NULL,nSize,dwTimeout );

    m_pChannel->Clear();
    BOOL bSuccess = SendData( btSendData,nSize,FALSE,dwTimeout );

    if( m_dwLastErrorCode == BSL_UART_SEND_ERROR)
    {
        _sleep( 500);
    }
    LogOpr( _T("Check Baudrate"), bSuccess );

    return bSuccess;
}

BOOL CBootModeOpr::Connect( DWORD dwTimeout /* = 1000  */)
{
   BOOL bSuccess = SendCommandData( BSL_CMD_CONNECT, dwTimeout  );
   LogOpr( _T("Connect to Module"), bSuccess );

   return bSuccess;
}

BOOL CBootModeOpr::Excute( DWORD dwTimeout /* = 1000  */ )
{
    BOOL bSuccess = SendCommandData( BSL_CMD_EXEC_DATA , dwTimeout );
    LogOpr( _T("Excute  downloaded file"), bSuccess );

    return bSuccess;
}

BOOL CBootModeOpr::Reset( DWORD dwTimeout /* = 1000  */ )
{
    BOOL bSuccess = SendCommandData( BSL_CMD_NORMAL_RESET , dwTimeout );
    LogOpr( _T("Reset"), bSuccess );

    return bSuccess;
}

BOOL CBootModeOpr::PowerOff( DWORD dwTimeout /* = 1000*/ )
{
	BOOL bSuccess = SendCommandData( BSL_CMD_POWER_OFF , dwTimeout );
	LogOpr( _T("Power Off"), bSuccess );
	return bSuccess;
}

BOOL CBootModeOpr::EnableFlash( DWORD dwTimeout /* = 1000*/ )
{
    BOOL bSuccess = SendCommandData( BSL_CMD_ENABLE_WRITE_FLASH , dwTimeout );
    LogOpr( _T("Enable Flash Done"), bSuccess );
    return bSuccess;
}
BOOL CBootModeOpr::ReadChipType( DWORD dwTimeout /* = 1000  */ )
{
    BOOL bSuccess = SendCommandData( BSL_CMD_READ_CHIP_TYPE , dwTimeout );
    LogOpr( _T("Read Chip Type"), bSuccess);

    return bSuccess;
}

BOOL CBootModeOpr::ReadFlashType( DWORD dwTimeout /* = 1000 */ )
{
    BOOL bSuccess = SendCommandData( BSL_CMD_READ_FLASH_TYPE, dwTimeout );
    LogOpr( _T("Read Flash Type"),bSuccess );
    return bSuccess;
}

BOOL CBootModeOpr::ReadFlashInfo( DWORD dwTimeout /* = 1000 */ )
{
	BOOL bSuccess = SendCommandData( BSL_CMD_READ_FLASH_INFO, dwTimeout );
	 LogOpr( _T("Read Flash Info"),bSuccess );
	 return bSuccess;
}

BOOL CBootModeOpr::ReadTransceiverType( DWORD dwTimeout /* = 1000 */ )
{
	BOOL bSuccess = SendCommandData( BSL_CMD_READ_RF_TRANSCEIVER_TYPE, dwTimeout );
	 LogOpr( _T("Read Transceiver Type"),bSuccess );
	 if (bSuccess)
	{	
		LPBYTE lpReadBuffer = GetRecvBuffer();
		DWORD dwSize = GetRecvBufferSize();
		if( lpReadBuffer && dwSize == sizeof( DWORD) )
		{
			TCHAR szInfo[MAX_PATH] = {0};
			_stprintf(szInfo,_T("RF Chip ID : 0x%04X"),*(DWORD*)lpReadBuffer);
			Log(szInfo);
		}
		
	}
	 return bSuccess;
}

BOOL CBootModeOpr::EndData( DWORD dwTimeout /* = 1000  */ )
{
    BOOL bSuccess = SendCommandData( BSL_CMD_END_DATA, dwTimeout );
    if( !bSuccess &&  m_dwLastErrorCode == BSL_REP_DOWN_DEST_ERROR )
    {
        Log( _T("End Data:Doownload error in previous command") );
    }
    else
    {
        LogOpr( _T("End Data"), bSuccess );
    }
    
    return bSuccess;
}

BOOL CBootModeOpr::ChangeBaud( DWORD dwTimeout /* = 1000  */ )
{
   switch (m_dwBaud)
    {
    case 115200:
    case 230400:
    case 460800:
    case 921600:
        break;
    default:
        m_dwBaud=115200;
	  break;
    }

   if( DEFAULT_BAUDRATE == m_dwBaud )
    {
        return TRUE;
    }

    UINT uiDataLen = sizeof( DWORD );
    LPBYTE lpPackData = new BYTE[uiDataLen];
    if( lpPackData == NULL )
        return FALSE;

    *(DWORD *)&lpPackData[ 0 ] = m_dwBaud;

    BOOL bSuccess = SendPacketData( BSL_CMD_CHANGE_BAUD,
                        uiDataLen  + PACHET_HDR_LEN ,
                        lpPackData, uiDataLen, dwTimeout  );
    delete []lpPackData;

    _TCHAR szOpr[ MAX_LOG_LEN ] = {0};
    _stprintf( szOpr, _T("FDL:Change Baudrate( %d )"), m_dwBaud );
    LogOpr( szOpr, bSuccess );

    if( bSuccess )
    {
        bSuccess = m_pChannel->SetProperty( 0, CH_PROP_BAUD, (void*)&m_dwBaud );
        _sleep( 500 );
    }

    _stprintf( szOpr, _T("BMPlatform:Change Baudrate( %d )"), m_dwBaud );
    LogOpr( szOpr, bSuccess );

    return bSuccess;
}

BOOL CBootModeOpr::ReadFlash( DWORD dwBase,DWORD dwLength,
                             DWORD dwTimeout /* = 1000  */  )
{
    UINT uiDataLen =  START_BSL_PKT_LEN - PACHET_HDR_LEN;
    LPBYTE lpPackData = new BYTE[uiDataLen];
    if( lpPackData == NULL )
        return FALSE;

    m_uiReadOffset = dwBase % 4;
    dwLength += m_uiReadOffset;

  BOOL bRetried = FALSE;

ReadFlash_Retry:

    *(DWORD *)&lpPackData[ 0 ] = dwBase;
    *(DWORD *)&lpPackData[ sizeof(DWORD) ] = dwLength;
    m_dwLastPktSize = dwLength;

    //m_lpCurrRead = NULL;

    BOOL bSuccess = SendPacketData( BSL_CMD_READ_FLASH, START_BSL_PKT_LEN,
        lpPackData, uiDataLen , dwTimeout  );

  if( !bSuccess && !bRetried )
  {
    // log the current failed information
    _TCHAR szOpr[ MAX_LOG_LEN ];
    _stprintf( szOpr,_T("%s( Base:0x%08X, Size:0x%08X )"), _T("Read Flash"), dwBase, dwLength );
    LogOpr( szOpr, bSuccess );

    bRetried = TRUE;
    // Clear channel dirty data and prepare for repeat reading.
    Log( _T("Clear channel buffer and retry ReadFlash."));
    m_pChannel->Clear();
    goto ReadFlash_Retry;
  }

    delete []lpPackData;

    _TCHAR szOpr[ MAX_LOG_LEN ];
    _stprintf( szOpr,_T("%s( Base:0x%08X, Size:0x%08X )"), _T("Read Flash"), dwBase, dwLength );
    LogOpr( szOpr, bSuccess );

    return bSuccess;
}

// dwBase gives partition id,dwOffset gives offset in this partition
BOOL CBootModeOpr::ReadPartitionFlash( DWORD dwBase,DWORD dwLength,DWORD dwOffset,DWORD dwTimeout /* = 1000 */)
{
    UINT uiDataLen =  START_BSL_PKT_LEN - PACHET_HDR_LEN + sizeof( DWORD );
    LPBYTE lpPackData = new BYTE[uiDataLen];
    if( lpPackData == NULL )
        return FALSE;

    m_uiReadOffset = 0;
  BOOL bRetried = FALSE;

ReadPartitionFlash_Retry:

    *(DWORD *)&lpPackData[ 0 ] = dwBase;
    *(DWORD *)&lpPackData[ sizeof(DWORD) ] = dwLength;
    *(DWORD *)&lpPackData[ sizeof( DWORD ) * 2 ] = dwOffset;
    m_dwLastPktSize = dwLength;

    //m_lpCurrRead = NULL;

    BOOL bSuccess = SendPacketData( BSL_CMD_READ_FLASH, START_BSL_PKT_LEN + sizeof( DWORD ),
        lpPackData, uiDataLen , dwTimeout  );

  if( !bSuccess && !bRetried )
  {
    // log the current failed information
    _TCHAR szOpr[ MAX_LOG_LEN ];
    _stprintf( szOpr,_T("%s( Base:0x%08X, Size:0x%08X, Offset:0x%08X )"), _T("Read Flash"), dwBase, dwLength,dwOffset );
    LogOpr( szOpr, bSuccess );

    bRetried = TRUE;
    // Clear channel dirty data and prepare for repeat reading.
    Log( _T("Clear channel buffer and retry ReadPartitionFlash."));
    m_pChannel->Clear();
    goto ReadPartitionFlash_Retry;
  }

  delete []lpPackData;

    _TCHAR szOpr[ MAX_LOG_LEN ];
    _stprintf( szOpr,_T("%s( Base:0x%08X, Size:0x%08X, Offset:0x%08X )"), _T("Read Flash"), dwBase, dwLength,dwOffset );
    LogOpr( szOpr, bSuccess );

    return bSuccess;
}

BOOL CBootModeOpr::ReadNVItem( DWORD dwStartAddr, DWORD dwEndAddr,
                              unsigned short uiItemID, DWORD dwTimeout /* = 1000  */ )
{
    BYTE lpSendData[ READ_NVITEM_PKT_LEN + PACHET_HDR_LEN] = {0};

    //Fill The Packet Type
    *(short *)&lpSendData[PKT_TYPE_POS]   = BSL_CMD_READ_NVITEM;
    *(short *)&lpSendData[PKT_LEN_POS]    = READ_NVITEM_PKT_LEN ;

    if( m_bBigEndian )
    {
        DWORD dwSoruceValue, dwDestValue;
        dwSoruceValue =  dwStartAddr;
        dwDestValue   = 0;
        CONVERT_INT( dwSoruceValue, dwDestValue);
        *(DWORD *)&lpSendData[PKT_DATA_POS] = dwDestValue;

        dwSoruceValue = dwEndAddr;
        dwDestValue   = 0;
        CONVERT_INT( dwSoruceValue, dwDestValue);
        *(DWORD *)&lpSendData[PKT_DATA_POS+sizeof( DWORD) ] = dwDestValue;

        unsigned short uiSourceValue, uiDestValue;
        uiSourceValue =  uiItemID;
        uiDestValue   = 0;
        CONVERT_SHORT( uiSourceValue, uiDestValue);
        *(unsigned short *)&lpSendData[ PKT_DATA_POS + 2 * sizeof( DWORD) ] = uiDestValue;
    }
    else
    {
        *(DWORD *)&lpSendData[ PKT_DATA_POS ] = dwStartAddr;
        *(DWORD *)&lpSendData[ PKT_DATA_POS + sizeof( DWORD)  ] = dwEndAddr;
        *(unsigned short *)&lpSendData[ PKT_DATA_POS + 2 * sizeof( DWORD)  ] = uiItemID;
    }

  //BM_PACKAGE bp;
  //bp.header.type = BSL_CMD_READ_NVITEM;
  //bp.header.len = READ_NVITEM_PKT_LEN;
  //bp.data = lpSendData;

    //BOOL bSuccess = SendData( &bp,dwTimeout );

    BOOL bSuccess = SendData(lpSendData,
                             READ_NVITEM_PKT_LEN + PACHET_HDR_LEN,
                             TRUE,
                             dwTimeout);

    _TCHAR szOpr[ MAX_LOG_LEN ];
    _stprintf( szOpr,_T("%s( Start:0x%08X, End:0x%08X, Item ID:%d )"), _T("Read NV Item"),
        dwStartAddr, dwEndAddr, uiItemID );
    LogOpr( szOpr, bSuccess );

    return bSuccess;
}

BOOL CBootModeOpr::EraseFlash( DWORD dwBase,DWORD dwLength , DWORD dwTimeout /* = 1000  */ )
{
    DWORD dwSize = dwLength;
    if( (dwSize != 0xFFFFFFFF) && (dwSize % 2)  )
    {
        dwSize++;
    }

    UINT uiDataLen =  2 * sizeof(DWORD) ;
    LPBYTE lpPackData = new BYTE[uiDataLen];
    if( lpPackData == NULL )
        return FALSE;

    *(DWORD *)&lpPackData[ 0 ] = dwBase;
    *(DWORD *)&lpPackData[ sizeof(DWORD) ] = dwSize;

    BOOL bSuccess = SendPacketData( BSL_CMD_ERASE_FLASH,
        ERASE_FLASH_PKT_LEN, lpPackData,
        uiDataLen , dwTimeout );
    delete []lpPackData;

    _TCHAR szOpr[ MAX_LOG_LEN ];
    _stprintf( szOpr,_T("%s( Base:0x%08X, Size:0x%08X)"), _T("Erase Flash"), dwBase, dwLength );
    LogOpr( szOpr, bSuccess );

    return bSuccess;
}

BOOL CBootModeOpr::EraseFlash( LPBYTE pID,DWORD nIDLen,DWORD dwLength , DWORD dwTimeout /* = 1000  */ )
{
    DWORD dwSize = dwLength;
    if( (dwSize != 0xFFFFFFFF) && (dwSize % 2)  )
    {
        dwSize++;
    }

    UINT uiDataLen =  PACHET_HDR_LEN + nIDLen +  sizeof(DWORD) ;
    LPBYTE lpPackData = new BYTE[uiDataLen];
    if( lpPackData == NULL )
        return FALSE;

    WORD *pWID = MakePartitionID(pID,nIDLen);
    memcpy(lpPackData + PACHET_HDR_LEN, pWID, nIDLen);
    *(DWORD *)&lpPackData[ PACHET_HDR_LEN + nIDLen ] = dwSize;

    SAFE_DELETE_ARRAY(pWID);

    *(short *)&lpPackData[PKT_TYPE_POS]   = BSL_CMD_ERASE_FLASH;
    *(short *)&lpPackData[PKT_LEN_POS]    = (short)(uiDataLen-PACHET_HDR_LEN);

    BOOL bSuccess = SendData(lpPackData,uiDataLen,TRUE,dwTimeout);
    delete []lpPackData;

    _TCHAR szOpr[ MAX_LOG_LEN ];
    _stprintf( szOpr,_T("%s( Partion:\"%s\", Size:0x%08X)"), _T("Erase Flash"), (*pID)==0?_T("_ALL_"):(char*)pID, dwLength );
    LogOpr( szOpr, bSuccess );

    return bSuccess;
}

BOOL CBootModeOpr::StartData( __uint64 llBase,
                              __uint64 llLength , 
                              LPBYTE lpDownLoadData,
                              DWORD dwCheckSum/* = 0*/,
                              DWORD dwTimeout /* = 1000  */,
                              BOOL bIs64Bit/* = FALSE*/ )
{
    __uint64 llSize = llLength;
    if( llSize % 2 )
    {
        llSize++;
    }
	
  _TCHAR szOpr[ MAX_LOG_LEN ] = {0};

	if(llSize == 0)
  {
    m_dwLastErrorCode = BSL_REP_SIZE_ZERO;
    _stprintf( szOpr,_T("Start Data: ( Base:0x%08llX ) size is zero."),llBase);
    LogOpr( szOpr, FALSE );
    return FALSE;
  }

  

    UINT uiDataLen =  bIs64Bit ? 2 * sizeof(__int64) : 2 * sizeof(DWORD) ;
	if(0 != dwCheckSum)
    {
    uiDataLen += sizeof(DWORD);
    }
	int nSendDataLen = PACHET_HDR_LEN + uiDataLen;
	
	LPBYTE lpPackData = m_pOrgData;
    memset(lpPackData,0,nSendDataLen);
    if (bIs64Bit)// addr(8) + Len(8) + [CS(4)]
    {
        *(__uint64 *)&lpPackData[ 0 ] = llBase;
        *(__uint64 *)&lpPackData[ sizeof(__int64) ] = llSize;
        if(0 != dwCheckSum)
        {
            *(DWORD *)&lpPackData[ sizeof(__int64)*2 ] = dwCheckSum;
        }
    }
    else    // addr(4) + Len(4) + [CS(4)]
    {
        *(DWORD *)&lpPackData[ 0 ] = (DWORD)llBase;
        *(DWORD *)&lpPackData[ sizeof(DWORD) ] = (DWORD)llSize;
        if(0 != dwCheckSum)
        {
            *(DWORD *)&lpPackData[ sizeof(DWORD)*2 ] = dwCheckSum;
        }
    }
     
    BOOL bSuccess = SendPacketData( BSL_CMD_START_DATA,
                        nSendDataLen, lpPackData, 
                        uiDataLen , dwTimeout );
    
	if(0 == dwCheckSum)
	{
    _stprintf( szOpr,_T("%s( Base:0x%08X, Size:0x%08llX)"), _T("Start Data"), llBase, llLength );
	}
	else
	{
    _stprintf( szOpr,_T("%s( Base:0x%08X, Size:0x%08llX, CheckSum:0x%08llX)"), _T("Start Data"),
			       llBase, llLength, dwCheckSum);
	}
    LogOpr( szOpr, bSuccess );
    
    return bSuccess;
}

BOOL CBootModeOpr::StartData( LPBYTE pID, DWORD nIDLen,
                             __uint64 llLength ,
                             LPBYTE lpDownLoadData, 
                             DWORD dwCheckSum/* = 0*/,
                             DWORD dwTimeout/* = 1000*/,
                             BOOL bIs64Bit/* = FALSE*/ )
{
    __uint64 llSize = llLength;
    if( llSize % 2 )
    {
        llSize++;
    }

    _TCHAR szOpr[ MAX_LOG_LEN ] = {0};

    if(llSize == 0)
    {
        m_dwLastErrorCode = BSL_REP_SIZE_ZERO;
        _stprintf( szOpr,_T("Start Data: (Partition: %s) size is zero."),(char*)pID);
        LogOpr( szOpr, FALSE );
        return FALSE;
    }

    UINT uiDataLen =  bIs64Bit ? nIDLen + 2* sizeof(__int64): nIDLen + sizeof(DWORD) ;
	if(0 != dwCheckSum)
	{
		uiDataLen += sizeof(DWORD);
	}	

	int nSendDataLen = PACHET_HDR_LEN + uiDataLen;
	LPBYTE lpPackData = m_pOrgData;
    memset(lpPackData,0,nSendDataLen);
	WORD *pWID = MakePartitionID(pID,nIDLen);
    memcpy(lpPackData+PACHET_HDR_LEN,pWID,nIDLen);
    if (bIs64Bit)// ID(72) + Len(8) + Rev(8) + [CS(4)]
    {
        *(__uint64 *)&lpPackData[ PACHET_HDR_LEN + nIDLen ] = llSize;
        if(0 != dwCheckSum)
        {
            *(DWORD *)&lpPackData[ PACHET_HDR_LEN + nIDLen+ 2*sizeof(__int64) ] = dwCheckSum;
        }
    }
    else    // ID(72) + Len(4)+ [CS(4)]
    {
        *(DWORD *)&lpPackData[ PACHET_HDR_LEN + nIDLen ] = (DWORD)llSize;

        if(0 != dwCheckSum)
        {
            *(DWORD *)&lpPackData[ PACHET_HDR_LEN + nIDLen+sizeof(DWORD) ] = dwCheckSum;
        }
	}	

    *(short *)&lpPackData[PKT_TYPE_POS]   = BSL_CMD_START_DATA;
    *(short *)&lpPackData[PKT_LEN_POS]    = (short)(uiDataLen);

    BOOL bSuccess = SendData(lpPackData,nSendDataLen,TRUE,dwTimeout);

    
	if(0 == dwCheckSum)
	{
        _stprintf( szOpr,_T("%s( Partition:\"%s\", Size:0x%08llX)"), _T("Start Data"),  (char*)pID, llLength );
	}
	else
	{
        _stprintf( szOpr,_T("%s( Partition:\"%s\", Size:0x%08llX, CheckSum:0x%08X)"), _T("Start Data"),
              (char*)pID, llLength, dwCheckSum);
	}
    LogOpr( szOpr, bSuccess );

    return bSuccess;
}

BOOL CBootModeOpr::MidstData( DWORD dwLength,
               LPBYTE lpDownLoadData,
                             DWORD dwTimeout /* = 1000  */,
               DWORD dwTotal /*= 0*/)
{
    //BM_PACKAGE bp;
    //bp.header.type = BSL_CMD_MIDST_DATA;
    //bp.header.len = (unsigned short)dwLength;
    //bp.data = lpDownLoadData;

    Log("MidstData: +++");

    DWORD dwRealLen = dwLength%2==0? dwLength : (dwLength+1);

    LPBYTE pSendData =  new BYTE[dwRealLen+PACHET_HDR_LEN];
    if(pSendData == NULL)
    {
        Log("MidstData: ---");
        return FALSE;
    }

    

    BOOL bRetried = FALSE;

MidstData_Retry:
    memset(pSendData,0xFF,dwRealLen+PACHET_HDR_LEN);
    memcpy(pSendData+PACHET_HDR_LEN,lpDownLoadData,dwLength);

    *(short *)&pSendData[PKT_TYPE_POS]   = BSL_CMD_MIDST_DATA;
    *(short *)&pSendData[PKT_LEN_POS]    = (short)dwRealLen ;

    //BOOL bState = SendData( &bp,dwTimeout );
    BOOL bState = SendData( pSendData,dwRealLen+PACHET_HDR_LEN,TRUE,dwTimeout );

    if( !bState && !bRetried && m_dwLastErrorCode == BSL_REP_VERIFY_ERROR )
    {
        // log the current failed information
        char strLog[MAX_PATH] = {0};
        _stprintf(strLog,_T("Download (0x%08X)"),dwTotal);
        LogOpr( strLog, bState );

        bRetried = TRUE;
        // Clear channel dirty data and prepare for repeat reading.
        m_log.LogRawStr(SPLOGLV_INFO, _T("Clear channel buffer and retry MidstData."));
        m_pChannel->Clear();
        goto MidstData_Retry;
    }

    //Added by wei.zhang here to free the memory when pSendData is no longer used.
    SAFE_DELETE_ARRAY(pSendData);

    //m_lpCurrRead += dwLength;

    if( m_dwLastErrorCode == BSL_REP_DOWN_DEST_ERROR )
    {
        Log( _T("Download:Download error in previous command") );
    }
    else
    {
        char strLog[MAX_PATH] = {0};
        _stprintf(strLog,_T("Download (0x%08X)"),dwTotal);
        LogOpr( strLog, bState );
    }

    Log("MidstData: ---");
    return bState;
}

BOOL CBootModeOpr::Repartition( DWORD dwTimeout )
{
    BOOL bSuccess = SendCommandData( BSL_CMD_REPARTITION , dwTimeout );
    LogOpr( _T("Repartition"), bSuccess );

    return bSuccess;
}

 BOOL CBootModeOpr::SendExtTable( LPBYTE pExtTable, DWORD dwSize, DWORD dwTimeout )
 {
     DWORD dwRealLen = dwSize%2==0? dwSize : (dwSize+1);

    LPBYTE pSendData =  new BYTE[dwRealLen+PACHET_HDR_LEN];
    if(pSendData == NULL)
    {
        return FALSE;
    }

    memset(pSendData,0x0,dwRealLen+PACHET_HDR_LEN);
    memcpy(pSendData+PACHET_HDR_LEN,pExtTable,dwSize);

    *(unsigned short *)&pSendData[PKT_TYPE_POS]   = BSL_CMD_EXTTABLE;
    *(unsigned short *)&pSendData[PKT_LEN_POS]    = (unsigned short)dwRealLen ;

    BOOL bSuccess = SendData( pSendData,dwRealLen+PACHET_HDR_LEN,TRUE,dwTimeout );

    //free the memory when pSendData is no longer used.
    SAFE_DELETE_ARRAY(pSendData);

    LogOpr( _T("SendExtTable"), bSuccess);

    return bSuccess;
 }

BOOL CBootModeOpr::Repartition( LPBYTE pPartitionInfo, DWORD dwSize, DWORD dwTimeout )
{
    //BM_PACKAGE bp;
    //bp.header.type = (unsigned short)BSL_CMD_REPARTITION;
    //bp.header.len = (unsigned short)dwSize;
    //bp.data = pPartitionInfo;

    //BOOL bSuccess = SendData(&bp, dwTimeout);

    DWORD dwRealLen = dwSize%2==0? dwSize : (dwSize+1);

    LPBYTE pSendData =  new BYTE[dwRealLen+PACHET_HDR_LEN];
    if(pSendData == NULL)
    {
        return FALSE;
    }

    memset(pSendData,0x0,dwRealLen+PACHET_HDR_LEN);
    memcpy(pSendData+PACHET_HDR_LEN,pPartitionInfo,dwSize);

    *(unsigned short *)&pSendData[PKT_TYPE_POS]   = BSL_CMD_REPARTITION;
    *(unsigned short *)&pSendData[PKT_LEN_POS]    = (unsigned short)dwRealLen ;

    BOOL bSuccess = SendData( pSendData,dwRealLen+PACHET_HDR_LEN,TRUE,dwTimeout );

    //Added by wei.zhang here to free the memory when pSendData is no longer used.
    SAFE_DELETE_ARRAY(pSendData);

    LogOpr( _T("Pepartiton"), bSuccess);

    return bSuccess;
}


BOOL CBootModeOpr::SendCommandData( pkt_type_s nCmdType, DWORD dwTimeout /* = 1000  */ )
{

  BYTE btSendData[PACHET_HDR_LEN];

  memset(&btSendData, 0, PACHET_HDR_LEN);
  *(short *)&btSendData[PKT_TYPE_POS] = (short)nCmdType;
  return SendData( btSendData, PACHET_HDR_LEN , TRUE, dwTimeout );
/*
  BM_PACKAGE bp;
  bp.header.type = (unsigned short)nCmdType;
  bp.header.len = 0;
  bp.data = NULL;

  return SendData( &bp,dwTimeout );
*/
}

BOOL CBootModeOpr::SendPacketData( pkt_type_s nCmdType,
                                  const int nSendDataLen,
                                  LPBYTE lpPacketData,
                                  UINT uiDataLen,
                                  DWORD dwTimeout /* = 1000  */ )
{
/*  if( m_bBigEndian && NULL != lpPacketData )
  {
    for( UINT i = 0; i < uiDataLen / sizeof( DWORD ); i++ )
    {
            DWORD dwSoruceValue, dwDestValue;

            dwSoruceValue =  *(DWORD *)&lpPacketData[ i * sizeof( DWORD) ];
            dwDestValue   = 0;
            CONVERT_INT( dwSoruceValue, dwDestValue);
            *(DWORD *)&lpPacketData[ i * sizeof( DWORD) ] = dwDestValue;
        }
    }

  BM_PACKAGE bp;
  bp.header.type = (unsigned short)nCmdType;
  bp.header.len = (unsigned short)uiDataLen;
  bp.data = lpPacketData;

    return SendData( &bp, dwTimeout );
*/
    LPBYTE lpSendData = new BYTE[nSendDataLen];
    if(lpSendData == NULL)
    {
        Log("SendPacketData: out of memory.");
        return FALSE;
    }

    memset(lpSendData, 0, nSendDataLen);
    *(short*)&lpSendData[PKT_TYPE_POS] = (short)nCmdType;
    *(short*)&lpSendData[PKT_LEN_POS]  = (short)uiDataLen;

    if(m_bBigEndian)
    {
        for(UINT i = 0; i< uiDataLen/sizeof(DWORD); i++)
        {
            DWORD dwSourceValue, dwDestValue;
            dwSourceValue = *(DWORD*)&lpPacketData[i*sizeof(DWORD)];
            dwDestValue = 0;
            CONVERT_INT(dwSourceValue,dwDestValue);
            *(DWORD*)&lpSendData[PKT_DATA_POS+i*sizeof(DWORD)] = dwDestValue;
        }
    }
    else
    {
        memcpy(lpSendData+PKT_DATA_POS,lpPacketData,uiDataLen);
    }

    BOOL bRet = SendData(lpSendData, nSendDataLen,TRUE,dwTimeout);
    delete [] lpSendData;
    return bRet;
}

BOOL CBootModeOpr::AllocRecvBuffer( DWORD dwSize )
{
    pthread_mutex_lock( &m_csRecvBbuffer);
    if( m_lpReceiveBuffer != NULL )
    {
        if( m_dwBufferSize == dwSize )
        {
            memset( m_lpReceiveBuffer,0, m_dwBufferSize );
            m_dwReceiveLen = 0;
        }
        else
        {
            delete[] m_lpReceiveBuffer;
            m_lpReceiveBuffer = NULL;
            m_dwReceiveLen = 0;
            m_dwBufferSize = 0;
        }
    }
    if( m_lpReceiveBuffer == NULL )
    {
        m_lpReceiveBuffer = new BYTE [ dwSize ];
        if( m_lpReceiveBuffer == NULL )
        {
            pthread_mutex_unlock( &m_csRecvBbuffer);
            return FALSE;
        }
        m_dwReceiveLen = 0;
        m_dwBufferSize = dwSize;
    }

    pthread_mutex_unlock( &m_csRecvBbuffer);

    return TRUE;
}

LPBYTE CBootModeOpr::GetRecvBuffer()
{
    return m_lpReceiveBuffer;
}

DWORD CBootModeOpr::GetRecvBufferSize()
{
    return m_dwReceiveLen;
}

void CBootModeOpr::FreeRecvBuffer()
{
    pthread_mutex_lock( &m_csRecvBbuffer);
    if( m_lpReceiveBuffer != NULL )
    {
        delete[] m_lpReceiveBuffer;
        m_lpReceiveBuffer = NULL;
        m_dwReceiveLen = 0;
        m_dwBufferSize = 0;
    }
    pthread_mutex_unlock( &m_csRecvBbuffer);

}

BOOL CBootModeOpr::ConnectChannel( void * lpOpenParam )
{
//    m_pChannel->SetReceiver( WM_RCV_CHANNEL_DATA, TRUE, (LPVOID)m_dwRecvThreadID );
  DWORD dwPort = *((DWORD*)lpOpenParam);
  DWORD dwBaud = *((DWORD*)(lpOpenParam+4));
  char *pDevPath = (char*)(lpOpenParam+8);
  m_dwBaud = dwBaud;

  CHANNEL_ATTRIBUTE ca;
  ca.ChannelType = CHANNEL_TYPE_TTY;
  ca.tty.dwPortNum = dwPort;
  ca.tty.dwBaudRate = ohObject.GetDefaultBaudrate();
  ca.tty.pDevPath = pDevPath;

    BOOL bOK  = m_pChannel->Open( &ca );

    if( !bOK )
    {
        m_log.LogFmtStr(SPLOGLV_ERROR,_T("Open Channel \"%s\" fail."),pDevPath );
        return FALSE;
    }

    m_log.LogFmtStr(SPLOGLV_INFO,_T("Open Channel \"%s\" success."),pDevPath );
    return TRUE;
}

BOOL CBootModeOpr::DisconnectChannel()
{
    if( m_pChannel == NULL )
        return FALSE;

    m_log.LogRawStr(SPLOGLV_INFO,"Close channel.");
    m_pChannel->Close();
//  m_pChannel = NULL;
    return TRUE;
}

DWORD CBootModeOpr::GetLastErrorCode()
{
    return m_dwLastErrorCode;
}

void CBootModeOpr::SetLastErrorCode(DWORD dwErrorCode)
{
    m_dwLastErrorCode = dwErrorCode;
}

void CBootModeOpr::GetLastErrorDescription(
                                           DWORD dwErrorCode,
                                           LPTSTR lpszErrorDescription,
                                           int nSize )
{
    if( lpszErrorDescription == NULL || nSize == 0 )
        return;

    _TCHAR szErrorIniFile[MAX_PATH];

    //GetModuleFilePath( g_theApp.m_hInstance, szErrorIniFile );

    GetExePath helper;
    std::string strModuleDir = helper.getExeDir();
    _stprintf( szErrorIniFile, _T("/%sBMError.ini"), strModuleDir.c_str());

    _TCHAR szKey[ 10 ] = {0};
    _stprintf(szKey,_T("%d"),dwErrorCode);

    INI_CONFIG* config = ini_config_create_from_file(szErrorIniFile,0);
    if(config != NULL)
    {
       char *pRet = ini_config_get_string(config,_T("ErrorDescription"),szKey,_T("Unknown Error"));

        strcpy(lpszErrorDescription,pRet);

        ini_config_destroy(config);
    }
    else
    {
        strcpy(lpszErrorDescription,_T("Unknown Error"));
    }

    return;
}

BOOL CBootModeOpr::OpenLogFile( DWORD dwCookie )
{
    CloseLogFile();

  int nLogFlag = ohObject.GetLogFlag();
  if(0 == nLogFlag)
  {
    return TRUE;
  }

    m_dwCookie = dwCookie;
    _TCHAR szLogFileName[ MAX_PATH ] = {0};

    _stprintf( szLogFileName, _T("%sTTY_%d.log"),
                        LOG_FILENAME_PREFIX,
                        dwCookie);

   if( m_log.Open(szLogFileName,SPLOGLV_VERBOSE))
    {
        //GetModuleFileName( NULL,szLogFileName, MAX_PATH );
        GetExePath helper;
        std::string strDir = helper.getExeDir();
        std::string strName = helper.getExeName();

        m_log.LogFmtStr(SPLOGLV_ERROR,"===%s%s", strDir.c_str(), strName.c_str() );
        return true;
    }

    return FALSE;
}

void CBootModeOpr::CloseLogFile()
{
    m_log.Close();
}

void CBootModeOpr::Log( LPCTSTR lpszLog )
{
    m_log.LogRawStr(SPLOGLV_INFO,(char*)lpszLog);
}

void CBootModeOpr::LogOpr( LPCTSTR lpszOperation, BOOL bSuccess )
{
    _TCHAR szLog[ MAX_LOG_LEN ] = {0};
    strcpy( szLog, lpszOperation );
    if( bSuccess )
    {
        strcat( szLog, _T(": Success.") );
        Log( szLog );
    }
    else
    {
        _TCHAR szDescription[ MAX_LOG_LEN ] = {0};
        DWORD dwErrorCode = m_dwLastErrorCode;
        GetLastErrorDescription( m_dwLastErrorCode, szDescription, MAX_LOG_LEN );
        _stprintf( szLog, _T("%s: Fail. [%d:%s]"), szLog, dwErrorCode, szDescription );
        Log( szLog );
        //fflush( m_pLogFile );
    }

}

void CBootModeOpr::SetIsCheckCrc( BOOL bCheckCrc  )
{
    m_bCheckCrc = bCheckCrc;
  //m_pChannel->SetProperty( 0,PPI_BM_CRC_Type,(void*)m_bCheckCrc );
}

void CBootModeOpr::StopOpr()
{
    //pthread_cond_signal(&m_cdOprEvent);

	pthread_mutex_lock(&m_muReadBuf);

	pthread_cond_signal(&m_cdOprEvent);
	pthread_mutex_unlock(&m_muReadBuf);

	if(m_pChannel)
	{
		m_pChannel->Close();
	}

	//::EnterCriticalSection(&m_csLastError);
	pthread_mutex_lock(&m_csLastError);
	m_dwLastErrorCode = BSL_USER_CANCEL;
	pthread_mutex_unlock(&m_csLastError);
	//::LeaveCriticalSection(&m_csLastError);

	//  SetEvent( m_hOprEvent );
}

ICommChannel* CBootModeOpr::GetChannelPtr()
{
  return m_pChannel;
}

void CBootModeOpr::SetChannel( ICommChannel* pChannel  )
{
    m_pChannel = pChannel;
}

void  CBootModeOpr::SetStartDataInfo(BOOL bHasCheckSum)
{
  m_bHasCheckSum  = bHasCheckSum;
}

DWORD CBootModeOpr::DoNVCheckSum(LPBYTE pDataBuf,DWORD dwSize)
{
	//////////////////////////////////////////////////////////////////////////
	//make crc and add to the first two byte of data
	//notice: pDataBuf is bigendian, and do CRC not including the first WORD
	WORD wUpdateCrc = crc16(0,pDataBuf+sizeof(WORD),dwSize-sizeof(WORD));
	*pDataBuf = HIBYTE(wUpdateCrc);
	*(pDataBuf+1) = LOBYTE(wUpdateCrc);
					
	
	DWORD dwSum = 0;
	for(UINT i= 0; i< dwSize; i++)
	{
		dwSum += (BYTE)(*(pDataBuf+i));
	}

	return dwSum;
}

BOOL CBootModeOpr::ReadSectorSize( DWORD dwTimeout/* = 1000*/ )
{
    BOOL bSuccess = SendCommandData( BSL_CMD_READ_SECTOR_SIZE, dwTimeout );
    LogOpr( _T("Read sector size"),bSuccess );
    return bSuccess;
}

BOOL CBootModeOpr::DoBeforeCheckBaud()
{
  //int nPacCap = 1;
  //m_pChannel->SetProperty(0,PPI_INTERNAL_PACKAGE_CAPACITY,(void*)nPacCap);
  return TRUE;

}

BOOL CBootModeOpr::DoAfterChackBaud()
{
  //int nPacCap = 0;
  //m_pChannel->SetProperty(0,PPI_INTERNAL_PACKAGE_CAPACITY,(void*)nPacCap);
  return TRUE;
}

int CBootModeOpr::OnChannelEvent( uint32_t event,
                            void* lpEventData )
{

    return 0;
}

int CBootModeOpr::OnChannelData(void* lpData,
                           uint32_t ulDataSize,
                           uint32_t reserved )
{
	Log("OnChannelData: +++");
	m_bOperationSuccess = ProcessData(lpData,ulDataSize);

	if(
		m_bOperationSuccess ||
	   	m_dwLastErrorCode != BSL_REP_INCOMPLETE_DATA
	   )
	{
		m_log.LogRawStr(SPLOGLV_INFO,"OnChannelData: signal+++");
		pthread_mutex_lock(&m_muReadBuf);
		//pthread_cond_broadcast(&m_cdOprEvent);
		pthread_cond_signal(&m_cdOprEvent);
		pthread_mutex_unlock(&m_muReadBuf);
		m_log.LogRawStr(SPLOGLV_INFO,"OnChannelData: signal---");
	}
	m_log.LogFmtStr(SPLOGLV_INFO,"OnChannelData: ---, m_bOperationSuccess = %d, m_dwLastErrorCode = %d",
	                m_bOperationSuccess,m_dwLastErrorCode);

	return 0;
}

BOOL CBootModeOpr::ProcessData(void* lpData,
                           uint32_t iDataLen )
{
	if(
		m_dwLastErrorCode!=0 &&
	   	m_dwLastErrorCode != BSL_REP_INCOMPLETE_DATA &&
	   	m_dwLastErrorCode != BSL_PHONE_WAIT_INPUT_TIMEOUT
	   )
	{
		m_log.LogFmtStr(SPLOGLV_ERROR,_T("m_dwLastErrorCode = 0x%X"),  m_dwLastErrorCode);
		//release the memory here to avoid memory leak by wei.zhang
		m_pChannel->FreeMem(lpData);
		return FALSE;
	}

	int iRecvDataLen = 0;
	LPBYTE lpRecvData =NULL;
	int iDecodeDataLen = 0;
	LPBYTE lpDecodeData = NULL;
	BOOL bReturnCode = TRUE;

	lpRecvData = (LPBYTE)lpData;
	iRecvDataLen = iDataLen;

	if(iRecvDataLen > MAX_RECV_LEN)
	{
		m_pChannel->FreeMem(lpData);
		Log(_T("The received packet too long."));
		m_dwLastErrorCode = BSL_REP_TOO_MUCH_DATA;
	}

	if( (m_ulRecvDataLen + iRecvDataLen) > MAX_RECV_LEN)
	{
		memset(m_RecvData, 0, MAX_RECV_LEN);
		m_ulRecvDataLen=0;
		Log(_T("receiving packet occurs error."));
	}

	memcpy( m_RecvData + m_ulRecvDataLen, lpRecvData, iRecvDataLen);
	m_ulRecvDataLen += iRecvDataLen;

	int nRet = 0;
	if(m_bEnableCheckBaudCrc && m_nCheckBaudCrc == -1)
	{
		//use crc check
		nRet = decode_bmmsg( m_RecvData, m_ulRecvDataLen,&lpDecodeData,&iDecodeDataLen,TRUE);
		if (GOOD_PACKET != nRet) //use checksum check
		{
			if( NULL != lpDecodeData)
			{

				free(lpDecodeData);
				lpDecodeData = NULL;
				iDecodeDataLen = 0;
			}
			nRet = decode_bmmsg( m_RecvData, m_ulRecvDataLen,&lpDecodeData,&iDecodeDataLen,FALSE);
			if (GOOD_PACKET == nRet)
			{
				m_nCheckBaudCrc = 2;
				m_bCheckCrc = FALSE;
			}
		}
		else
		{
			m_nCheckBaudCrc = 1;
			m_bCheckCrc = TRUE;
		}

	}
	else
	{
		nRet = decode_bmmsg( m_RecvData, m_ulRecvDataLen,
	                         &lpDecodeData,&iDecodeDataLen,m_bCheckCrc);
	}

	

	if( nRet > PART_PACKET && (UINT)(nRet-PART_PACKET) >= m_ulRecvDataLen)
	{
		m_log.LogFmtStr(SPLOGLV_ERROR, _T("decode_bmmsg error: nRet[%d],m_ulRecvDataLen[0x%08X]"),
		                nRet,m_ulRecvDataLen);
		nRet = ERROR_PACKET;
	}

	if(nRet >= PART_PACKET)
	{
		if(nRet>PART_PACKET)
		{
		    m_ulRecvDataLen -= nRet - PART_PACKET;
		    memmove(m_RecvData, m_RecvData + nRet - PART_PACKET, m_ulRecvDataLen);
		}
		m_pChannel->FreeMem(lpData);
		m_dwLastErrorCode = BSL_REP_INCOMPLETE_DATA;
		m_log.LogRawStr(SPLOGLV_ERROR,"decode_bmmsg return >= PART_PACKET");
		return FALSE;
	}

	memset(m_RecvData,0, MAX_RECV_LEN);
	m_ulRecvDataLen = 0;
	m_pChannel->FreeMem(lpData);

	if(nRet == ERROR_PACKET)
	{
		m_dwLastErrorCode = BSL_REP_DECODE_ERROR;
		m_log.LogRawStr(SPLOGLV_ERROR,"decode_bmmsg return ERROR_PACKET");
		return FALSE;
	}

	P_Packet_Header tmpPktHeader = (P_Packet_Header)lpDecodeData;

	//Convert the data header
	if( TRUE == m_bBigEndian)
	{
	    short SourceValue, DestValue;
	    SourceValue = tmpPktHeader->PacketType;
	    DestValue = 0;
	    CONVERT_SHORT(SourceValue,DestValue);
	    tmpPktHeader->PacketType = DestValue;

	    SourceValue = tmpPktHeader->DataSize;
	    DestValue = 0;
	    CONVERT_SHORT(SourceValue,DestValue);
	    tmpPktHeader->DataSize = DestValue;
	}

	m_dwLastErrorCode = tmpPktHeader->PacketType;
	bReturnCode = FALSE;

	//According the Response message type implement operation
	if(
		tmpPktHeader->PacketType == BSL_REP_ACK ||
	   	tmpPktHeader->PacketType == BSL_REP_VER
	    )
	{
		m_bOperationSuccess=bReturnCode = TRUE;
	}
	else if( tmpPktHeader->PacketType == BSL_REP_READ_FLASH)
	{
		m_bOperationSuccess=bReturnCode = TRUE;
		if(
				NULL != lpDecodeData &&
				( 
					m_iLastSentPktType == BSL_CMD_READ_FLASH ||
					m_iLastSentPktType == BSL_CMD_READ_MIDST
				)
		      )
		{
			if(
				iDecodeDataLen <= PACHET_HDR_LEN ||
			       m_dwLastPktSize != (iDecodeDataLen - PACHET_HDR_LEN)
			   )
			{
				//delete []lpDecodeData;
				//wei.zhang here to match malloc with free to manage the memory.
				free(lpDecodeData);
				lpDecodeData = NULL;
				m_dwLastErrorCode= BSL_REP_OPERATION_FAILED;
				m_log.LogRawStr(SPLOGLV_ERROR,"iDecodeDataLen <= PACHET_HDR_LEN");
				return FALSE;
			}
			pthread_mutex_lock(&m_csRecvBbuffer);
			if(m_lpReceiveBuffer != NULL)
			{
				if( (m_dwReceiveLen + iDecodeDataLen - PACHET_HDR_LEN -m_uiReadOffset )<=m_dwBufferSize)
				{
					memcpy(m_lpReceiveBuffer + m_dwReceiveLen,
					       lpDecodeData + PACHET_HDR_LEN + m_uiReadOffset,
					       iDecodeDataLen - PACHET_HDR_LEN - m_uiReadOffset);
					m_dwReceiveLen += (iDecodeDataLen - PACHET_HDR_LEN - m_uiReadOffset);
					m_uiReadOffset = 0;
				}
			}
			pthread_mutex_unlock(&m_csRecvBbuffer);
		}
	}
	else if(
		tmpPktHeader->PacketType == BSL_REP_READ_CHIP_TYPE      	||
            	tmpPktHeader->PacketType == BSL_REP_READ_NVITEM         	||
           	tmpPktHeader->PacketType == BSL_REP_READ_FLASH_TYPE     	||
            	tmpPktHeader->PacketType == BSL_REP_READ_SECTOR_SIZE    	||
            	tmpPktHeader->PacketType == BSL_CHIPID_NOT_MATCH        	||
            	tmpPktHeader->PacketType == BSL_REP_READ_FLASH_INFO	 	||
            	tmpPktHeader->PacketType == BSL_REP_RF_TRANSCEIVER_TYPE
            )
	{
		m_bOperationSuccess=bReturnCode = TRUE;
		if( NULL != lpDecodeData && m_lpReceiveBuffer != NULL)
		{
			pthread_mutex_lock(&m_csRecvBbuffer);
			m_dwReceiveLen = 0;
			if( (iDecodeDataLen - PACHET_HDR_LEN) == m_dwBufferSize)
			{
				memcpy(m_lpReceiveBuffer, lpDecodeData + PACHET_HDR_LEN, m_dwBufferSize);
				m_dwReceiveLen = m_dwBufferSize;
			}
			pthread_mutex_unlock(&m_csRecvBbuffer);
		}
	}

	if( NULL != lpDecodeData)
	{
		//delete []lpDecodeData;\
		//wei.zhang here to match malloc with free to manage the memory.
		free(lpDecodeData);
		lpDecodeData = NULL;
	}

	return bReturnCode;
}

BOOL CBootModeOpr::SendData(LPBYTE lpData,
                            int iDataSize,
                            BOOL bCRC,
                            DWORD dwTimeout)
{
	Log("SendData: +++");
	LPBYTE lpSendData = NULL;
	int    iSendDataLen = 0;
	int    iSendDataLen1 = 0;
	int    iSendDataLen2 = 0;

	BOOL bSplit = FALSE;

	//_TCHAR szOpr[MAX_LOG_LEN] = {0};

	m_iLastSentPktType = (pkt_type_s)(lpData[PKT_TYPE_POS]);
	if(m_iLastSentPktType == BSL_CMD_MIDST_DATA || m_iLastSentPktType == BSL_CMD_END_DATA)
	{
		if(m_dwLastErrorCode == BSL_REP_DOWN_DEST_ERROR)
		{
		    Log("SendData: ---");
		  return FALSE;
		}
	}

	if(TRUE == m_bBigEndian)
	{
		P_Packet_Header tmpPktHeader = (P_Packet_Header)lpData;

		short SourceValue, DestValue;
		SourceValue = tmpPktHeader->PacketType;
		DestValue = 0;
		CONVERT_SHORT(SourceValue,DestValue);
		tmpPktHeader->PacketType = DestValue;

		SourceValue = tmpPktHeader->DataSize;
		DestValue = 0;
		CONVERT_SHORT(SourceValue,DestValue);
		tmpPktHeader->DataSize = DestValue;
	}

	if(bCRC)
	{
		if(!encode_bmmsg(lpData,iDataSize,&lpSendData, &iSendDataLen, m_bCheckCrc))
		{
		  Log(_T("Encode message fail."));
		  Log("SendData: ---");
		  return FALSE;
		}
	}
	else
	{
		lpSendData = lpData;
		iSendDataLen = iDataSize;
	}

	//ResetEvent(m_hOprEvent);
	pthread_mutex_lock(&m_muReadBuf);

	m_dwLastErrorCode = 0;
	m_bOperationSuccess = FALSE;

	if(iSendDataLen % 64 == 0)
	{
		bSplit = TRUE;
		iSendDataLen1 = iSendDataLen -1;
		iSendDataLen2 = 1;
	}

	Log("SendData: call write +++");

	if(bSplit)
	{
		if( iSendDataLen1 != (int)(m_pChannel->Write(lpSendData, iSendDataLen1)))
		{
			  if((bCRC) && (lpSendData))
			  {
				    //delete [] lpSendData;
				    //wei.zhang here to match malloc with free to manage the memory.
				    free(lpSendData);
				    lpSendData = NULL;
			  }
			  m_dwLastErrorCode = BSL_UART_SEND_ERROR;
			  Log(_T("Write channel fail."));
			  Log("SendData: call write ---");
			  pthread_mutex_unlock(&m_muReadBuf);
			  Log("SendData: ---");
			  return FALSE;
		}

		m_pChannel->Drain();

		if( iSendDataLen2 != (int)(m_pChannel->Write(lpSendData+iSendDataLen1, iSendDataLen2)))
		{
			if((bCRC) && (lpSendData))
			{
				//delete [] lpSendData;
				//wei.zhang here to match malloc with free to manage the memory.
				free(lpSendData);
				lpSendData = NULL;
			}
			m_dwLastErrorCode = BSL_UART_SEND_ERROR;
			Log(_T("Write channel fail."));
			Log("SendData: call write ---");
			pthread_mutex_unlock(&m_muReadBuf);
			Log("SendData: ---");
			return FALSE;
		}
	}
	else
	{
		if( iSendDataLen != (int)(m_pChannel->Write(lpSendData, iSendDataLen)))
		{
			if((bCRC) && (lpSendData))
			{
				//delete [] lpSendData;
				//wei.zhang here to match malloc with free to manage the memory.
				free(lpSendData);
				lpSendData = NULL;
			}
			m_dwLastErrorCode = BSL_UART_SEND_ERROR;
			Log(_T("Write channel fail."));
			Log("SendData: call write ---");
			pthread_mutex_unlock(&m_muReadBuf);
			Log("SendData: ---");
			return FALSE;
		}
	}

	m_pChannel->Drain();
	Log("SendData: call write ---");

	if(bCRC && lpSendData)
	{
		//delete [] lpSendData;
		//wei.zhang here to match malloc with free to manage the memory.
		free(lpSendData);
		lpSendData = NULL;
	}


	struct timespec ts;

	clock_gettime(CLOCK_REALTIME, &ts);

	ts.tv_sec += dwTimeout/1000;
	ts.tv_nsec += (dwTimeout%1000)*1000000;

	if(ts.tv_nsec>=1000000000)
	{
	    ts.tv_sec++;
	    ts.tv_nsec -= 1000000000;
	}

	Log("SendData: wait+++");
	int nRet = pthread_cond_timedwait(&m_cdOprEvent,&m_muReadBuf,&ts);
    m_log.LogFmtStr(SPLOGLV_INFO,"SendData: wait---[%d]",nRet);
	//Log("SendData: wait---");
	//m_log.LogFmtStr(SPLOGLV_INFO,_T("pthread_cond_timedwait time: %d, return %d,%s"),  dwTimeout, nRet, strerror(nRet));
	//WaitForSingleObject(m_hOprEvent, dwTimeout);


	memset(m_RecvData,0, MAX_RECV_LEN);
	m_ulRecvDataLen = 0;

	pthread_mutex_unlock(&m_muReadBuf);

	if(m_dwLastErrorCode == 0)
	{
		m_dwLastErrorCode = BSL_PHONE_WAIT_INPUT_TIMEOUT;
	}
	
	Log("SendData: ---");
	return m_bOperationSuccess;
}

BOOL CBootModeOpr::KeepCharge( DWORD dwTimeout /*= 1000*/)
{
    BOOL bSuccess = SendCommandData(BSL_CMD_KEEP_CHARGE, dwTimeout);
    LogOpr( _T("Keep charge"), bSuccess);
    return bSuccess;
}

BOOL CBootModeOpr::StartRead( LPBYTE pID, DWORD nIDLen, __uint64 llLength,DWORD dwTimeout /*= 1000 */, BOOL bIs64Bit/* = FALSE*/)
{
    _TCHAR szOpr[MAX_LOG_LEN] = {0};

	if(llLength == 0)
	{
		m_dwLastErrorCode = BSL_REP_SIZE_ZERO;
        _stprintf(szOpr, _T("Start read: (Partition:\"%s\") read length is zero."),(char*)pID);
        LogOpr(szOpr,FALSE);
		return FALSE;
	}
	
    UINT uiDataLen =  bIs64Bit? nIDLen + 2*sizeof(__int64) : nIDLen + sizeof(DWORD);
	int nSendDataLen = PACHET_HDR_LEN + uiDataLen;
	LPBYTE lpPackData = m_pOrgData;
	memset(lpPackData,0,nSendDataLen);
    WORD *pWID = MakePartitionID(pID,nIDLen);

	memcpy(lpPackData + PACHET_HDR_LEN,pWID,nIDLen); 
    if(bIs64Bit)	// ID(72) + Len(8) + Rev(8)
    {
        *(__uint64 *)&lpPackData[ PACHET_HDR_LEN + nIDLen ] = llLength;	
    }
    else	// ID(72) + Len(4)
    {
        *(DWORD *)&lpPackData[ PACHET_HDR_LEN + nIDLen ] = (DWORD)llLength;	
    }
	SAFE_DELETE_ARRAY(pWID);
    
    *(short *)&lpPackData[PKT_TYPE_POS]   = BSL_CMD_READ_START;
    *(short *)&lpPackData[PKT_LEN_POS]    = (short)(uiDataLen);
    BOOL bSuccess = SendData(lpPackData,nSendDataLen,TRUE,dwTimeout);
	

    _stprintf(szOpr, _T("Start Read ( Partition:\"%s\", Size:0x%08llX)"), (char*)pID, llLength);

    LogOpr(szOpr,bSuccess);

    return bSuccess;
}

BOOL CBootModeOpr::EndRead( DWORD dwTimeout)
{
    BOOL bSuccess = SendCommandData( BSL_CMD_READ_END, dwTimeout);
    LogOpr(_T("End read"), bSuccess);
    return bSuccess;
}

BOOL CBootModeOpr::MidstRead( DWORD dwLength, __uint64 llOffset,DWORD dwTimeout/* = 1000*/, BOOL bIs64Bit /*= FALSE*/)
{
    UINT uiDataLen =  bIs64Bit ? sizeof(DWORD)+sizeof(__int64): 2*sizeof( DWORD );
	LPBYTE lpPackData = m_pOrgData;
	int nSendDataLen = PACHET_HDR_LEN + uiDataLen;
	memset(lpPackData,0,nSendDataLen);

	m_uiReadOffset = 0;
	BOOL bRetried = FALSE;

ReadPartitionFlash_Retry:
    *(DWORD *)&lpPackData[ PACHET_HDR_LEN ] = dwLength;
    if (bIs64Bit)   //Len(4) + offset(8)
    {
        *(__uint64 *)&lpPackData[ PACHET_HDR_LEN + sizeof(DWORD) ] = llOffset;
    }
    else    //Len(4) + offset(4)
    {
        *(DWORD *)&lpPackData[ PACHET_HDR_LEN + sizeof(DWORD) ] = (DWORD)llOffset;
    }
	m_dwLastPktSize = dwLength;

    *(short *)&lpPackData[PKT_TYPE_POS]   = BSL_CMD_READ_MIDST;
    *(short *)&lpPackData[PKT_LEN_POS]    = (short)uiDataLen;

	BOOL bSuccess = SendData( lpPackData,nSendDataLen, TRUE, dwTimeout );

	if( !bSuccess && !bRetried )
	{
	   // log the current failed information
        _TCHAR szOpr[MAX_LOG_LEN] = {0};
        _stprintf(szOpr, _T("Midst read flash (size:0x%08X, offset:0x%08llX)"),dwLength,llOffset);
        LogOpr(szOpr,bSuccess);
   
	   bRetried = TRUE;
	   // Clear channel dirty data and prepare for repeat reading.
	   Log( _T("Clear channel buffer and retry MidstRead."));
	   m_pChannel->Clear();
	   goto ReadPartitionFlash_Retry;
	}


    _TCHAR szOpr[MAX_LOG_LEN] = {0};
    _stprintf(szOpr, _T("Midst read flash (size:0x%08X, offset:0x%08llX)"),dwLength,llOffset);
    LogOpr(szOpr,bSuccess);
    return bSuccess;
}

WORD * CBootModeOpr::MakePartitionID(LPBYTE pID,DWORD nIDLen)
{
    DWORD nLen = nIDLen/2;
    WORD * p = new WORD[nLen];
    memset(p,0,sizeof(WORD)*nLen);

    if(pID != NULL)
    {
        wchar_t * pWBuf = new wchar_t[nLen];
        memset(pWBuf,0,sizeof(wchar_t)*nLen);
        mbstowcs(pWBuf,(char*)pID,nLen);

        for(UINT i = 0; i< nLen; i++)
        {
            p[i] = (WORD)(pWBuf[i]);
        }

        SAFE_DELETE_ARRAY(pWBuf);
    }

    return p;
}

BOOL CBootModeOpr::EnableCheckBaudCrc(BOOL bEnable)
{
	m_bEnableCheckBaudCrc = bEnable;
	m_nCheckBaudCrc 		= -1;
	return TRUE;
}

BOOL CBootModeOpr::GetCheckBaudCrcType()
{
	int  nCRC =	m_nCheckBaudCrc;
	pthread_mutex_lock(&m_csRecvBbuffer);
	if( m_lpReceiveBuffer != NULL )
	{
		if( m_dwBufferSize >= 4)
		{
			*((DWORD*)m_lpReceiveBuffer) = (DWORD)nCRC;
			m_dwReceiveLen = 4;
		}
	}
	pthread_mutex_unlock(&m_csRecvBbuffer);
	
	return TRUE;

}

