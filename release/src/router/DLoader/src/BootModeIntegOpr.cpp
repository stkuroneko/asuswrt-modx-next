// BootModeIntegOpr.cpp : implementation file
//

#include "BootModeIntegOpr.h"

#include "OptionHelpper.h"
#include "errno.h"
#include <sys/mman.h>
#include "BootModeitf.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

#define DEFAULT_CHECK_BAUD_TIMES      3
#define DEFAULT_TIME_OUT              1000
#define MAX_ERASEFLASH_TIMEOUT        5000
#define SECTION_SIZE                  0x10000

// Do repartition always
#define REPAR_STRATEGY_DO_ALWAYS        0   
// Stop actions and report error when incompatible partition error occured
#define REPAR_STRATEGY_STOP             1
// Ignore incompatible partition error
#define REPAR_STRATEGY_IGNORE           2
// Do repartion action when imcompatible partition error occured
#define REPAR_STRATEGY_DO               3

extern COptionHelpper ohObject;

/////////////////////////////////////////////////////////////////////////////
// CBootModeIntegOpr
CBootModeIntegOpr::CBootModeIntegOpr()
{
    m_bCheckBaudRate    = FALSE;
    m_bStopOpr          = FALSE;
    m_dwOprCookie       = 0;
    m_pReceiver = NULL;
	m_bNeedRepartion    = TRUE; 
    m_bRepartionDone    = FALSE;
}

CBootModeIntegOpr::~CBootModeIntegOpr()
{
}

BEGIN_DISP_MAP(CBootModeIntegOpr)
	DISP_FUNC(CBootModeIntegOpr, "CheckBaud", CheckBaud)
	DISP_FUNC(CBootModeIntegOpr, "Connect", Connect)
	DISP_FUNC(CBootModeIntegOpr, "Download", Download)
    DISP_FUNC(CBootModeIntegOpr, "DownloadEx", DownloadEx)
	DISP_FUNC(CBootModeIntegOpr, "DownloadByID", DownloadByID)
    DISP_FUNC(CBootModeIntegOpr, "DownloadByIDEx", DownloadByIDEx)
	DISP_FUNC(CBootModeIntegOpr, "EraseFlash", EraseFlash)
	DISP_FUNC(CBootModeIntegOpr, "ReadFlash", ReadFlash)
	DISP_FUNC(CBootModeIntegOpr, "ReadFlashByID", ReadFlashByID)	
	DISP_FUNC(CBootModeIntegOpr, "Excute", Excute)
	DISP_FUNC(CBootModeIntegOpr, "Reset", Reset)
    DISP_FUNC(CBootModeIntegOpr, "ReadChipType", ReadChipType)
    DISP_FUNC(CBootModeIntegOpr, "ReadNVItem", ReadNVItem)
    DISP_FUNC(CBootModeIntegOpr, "ChangeBaud", ChangeBaud)
    DISP_FUNC(CBootModeIntegOpr, "EraseFlash2", EraseFlash2)
	DISP_FUNC(CBootModeIntegOpr, "EraseFlashByID", EraseFlashByID)
	DISP_FUNC(CBootModeIntegOpr, "Repartition", Repartition)
	DISP_FUNC(CBootModeIntegOpr, "ForceRepartition", ForceRepartition)
	DISP_FUNC(CBootModeIntegOpr, "RepartitionByID", RepartitionByID)
	DISP_FUNC(CBootModeIntegOpr, "ForceRepartitionByID", ForceRepartitionByID)
	DISP_FUNC(CBootModeIntegOpr, "ExecNandInit", ExecNandInit)
    DISP_FUNC(CBootModeIntegOpr, "ReadFlashType",ReadFlashType)
	DISP_FUNC(CBootModeIntegOpr, "ReadSectorSize", ReadSectorSize)
	DISP_FUNC(CBootModeIntegOpr, "ReadFlashAndSave", ReadFlashAndSave)
	DISP_FUNC(CBootModeIntegOpr, "ReadFlashAndSaveByID", ReadFlashAndSaveByID)
	DISP_FUNC(CBootModeIntegOpr, "ReadFlashAndDirectSave", ReadFlashAndDirectSave)
	DISP_FUNC(CBootModeIntegOpr, "ReadFlashAndDirectSaveByID", ReadFlashAndDirectSaveByID)
    DISP_FUNC(CBootModeIntegOpr, "ReadFlashAndSaveByIDEx", ReadFlashAndSaveByIDEx)
	DISP_FUNC(CBootModeIntegOpr, "DoNothing", DoNothing)
	DISP_FUNC(CBootModeIntegOpr, "SetCRC", SetCRC)
	DISP_FUNC(CBootModeIntegOpr, "ResetCRC", ResetCRC)
	DISP_FUNC(CBootModeIntegOpr, "CheckBaudRom", CheckBaudRom)
	DISP_FUNC(CBootModeIntegOpr, "ConnectRom", ConnectRom)
	DISP_FUNC(CBootModeIntegOpr, "KeepCharge", KeepCharge)
	DISP_FUNC(CBootModeIntegOpr, "ReadFlashInfo",ReadFlashInfo)
	DISP_FUNC(CBootModeIntegOpr, "SendExtTable", SendExtTable)
	DISP_FUNC(CBootModeIntegOpr, "GetCheckBaudCrcType",GetCheckBaudCrcType)
	DISP_FUNC(CBootModeIntegOpr, "Connect2",Connect2)
	DISP_FUNC(CBootModeIntegOpr, "PowerOff",PowerOff)
    DISP_FUNC(CBootModeIntegOpr, "EnableFlash", EnableFlash)    
    DISP_FUNC(CBootModeIntegOpr, "ReadTransceiverType", ReadTransceiverType)
END_DISP_MAP(CBootModeIntegOpr)

/////////////////////////////////////////////////////////////////////////////
// CBootModeIntegOpr message handlers

BOOL CBootModeIntegOpr::_CheckBaud(void * pFileInfo,BOOL bRom)
{
    BOOL bRet = FALSE;
    int nTimes = 0;
    BMFileInfo* pBMFileInfo = (BMFileInfo*)pFileInfo;
    int   nMaxTimes = ohObject.GetCheckBaudTimes( pBMFileInfo->szFileType );
	DWORD dwTimeout = ohObject.GetTimeout( bRom ? _T("CheckBaudRom"): _T("Check Baud"));
	
    m_bmOpr.DoBeforeCheckBaud();
    while( !m_bStopOpr )
    {
        if( nMaxTimes != 0 )
        {
            if( nTimes > nMaxTimes )
            {
                m_bCheckBaudRate = FALSE;
                bRet = FALSE;
                break;
            }
        }
		
        nTimes++;
        
        if(!m_bCheckBaudRate)
        {
            PostMessageToUplevel( BM_CHECK_BAUDRATE, 
                (WPARAM)m_dwOprCookie, (LPARAM)0 );
            m_bCheckBaudRate = TRUE;
        } 		
        
        if(   m_bCheckBaudRate 
            && !m_bmOpr.CheckBaud( dwTimeout ) ) // Failed
        {           
			if(bRom)
			{
				m_bCheckBaudRate = TRUE;
				continue;
			}
			else
			{
				if(m_bmOpr.GetLastErrorCode() == BSL_PHONE_WAIT_INPUT_TIMEOUT)
				{
					m_bCheckBaudRate = TRUE;
					continue;
				}
				else
				{
					bRet = FALSE;
					m_bCheckBaudRate = FALSE;
					break;
				}
			}
        } 
        
        // Success
        bRet = TRUE;		
        m_bCheckBaudRate = FALSE;        
        break;
    }

	m_bmOpr.DoAfterChackBaud();
    
    return bRet;
}
BOOL CBootModeIntegOpr::CheckBaud(void * pFileInfo) 
{
	return _CheckBaud(pFileInfo,FALSE);
}

BOOL CBootModeIntegOpr::CheckBaudRom(void * pFileInfo) 
{
	return _CheckBaud(pFileInfo,TRUE);
}

BOOL CBootModeIntegOpr::_Connect(void * pFileInfo,BOOL bRom) 
{    
    if( !_CheckBaud( pFileInfo,bRom ) )
    {
        return FALSE;
    }
    
    PostMessageToUplevel( BM_CONNECT, 
        (WPARAM)m_dwOprCookie, (LPARAM)0 );

    int nTimeout = ohObject.GetTimeout( _T("Connect") );
    
    if( !m_bmOpr.Connect( nTimeout ) && bRom)
    {
		if(bRom)
		{
			// Boot code in module has a 
			// bug,it possibly make connect
			// failed at first time,so we
			// try once more.
			if( !m_bmOpr.Connect( nTimeout ) )
			{
				return FALSE;
			}
		}
		else
		{
			return FALSE;
		}
    }
	
    return TRUE;
}

BOOL CBootModeIntegOpr::Connect(void * pFileInfo) 
{
	return _Connect(pFileInfo,FALSE);
}

BOOL CBootModeIntegOpr::ConnectRom(void * pFileInfo) 
{
	return _Connect(pFileInfo,TRUE);
}

BOOL CBootModeIntegOpr::Connect2(void* pFileInfo)
{
	UNUSED_ALWAYS( pFileInfo );
	PostMessageToUplevel( BM_CONNECT, 
		(WPARAM)m_dwOprCookie, (LPARAM)0 );

	int nTimeout = ohObject.GetTimeout( _T("Connect") );

	if( !m_bmOpr.Connect( nTimeout ))
	{		
		// Boot code in module has a 
		// bug,it possibly make connect
		// failed at first time,so we
		// try once more.
		if( !m_bmOpr.Connect( nTimeout ) )
		{
			return FALSE;
		}		
	}

	return TRUE;
}

BOOL CBootModeIntegOpr::Download(void * pFileInfo) 
{
	return _Download(pFileInfo,FALSE,FALSE);
}

BOOL CBootModeIntegOpr::DownloadEx(void* pFileInfo)
{
    return _Download(pFileInfo,FALSE,TRUE);
}

BOOL CBootModeIntegOpr::DownloadByID(void * pFileInfo) 
{

    BOOL bOK = FALSE;
    if (m_bRepartionDone)
    {
        bOK = _Download(pFileInfo,TRUE,FALSE);
    }
    else
    {
        m_bmOpr.SetLastErrorCode(BSL_REP_INCOMPATIBLE_PARTITION);      
    }   
    return bOK;  	
}

BOOL CBootModeIntegOpr::DownloadByIDEx(void * pFileInfo) 
{
    BOOL bOK = FALSE;
    if (m_bRepartionDone)
    {
        bOK = _Download(pFileInfo,TRUE,TRUE);
    }
    else
    {
        m_bmOpr.SetLastErrorCode(BSL_REP_INCOMPATIBLE_PARTITION);
    }
    return bOK;  	
}

BOOL CBootModeIntegOpr::EraseFlash(void * pFileInfo) 
{
    BMFileInfo* pBMFileInfo = (BMFileInfo*)pFileInfo;
    
    PostMessageToUplevel( BM_ERASE_FLASH, (WPARAM)m_dwOprCookie, (LPARAM)0 );
    DWORD dwTimeout = ohObject.GetTimeout( _T("Erase Flash") );
    if( dwTimeout <= MAX_ERASEFLASH_TIMEOUT )
    {
        dwTimeout = (DWORD)(pBMFileInfo->llOprSize / SECTION_SIZE * dwTimeout + dwTimeout);
    }
    
    if( !m_bmOpr.StartData( 
        pBMFileInfo->llBase, 
        pBMFileInfo->llOprSize, 
        NULL,
        0,
        dwTimeout  )  )
    {
        return FALSE;
    }
    if( !m_bmOpr.EndData() )
    {
        return FALSE;
    }
    return TRUE;
}

BOOL CBootModeIntegOpr::EraseFlash2( void * pFileInfo  )
{
    BMFileInfo* pBMFileInfo = (BMFileInfo*)pFileInfo;

    PostMessageToUplevel( BM_ERASE_FLASH, (WPARAM)m_dwOprCookie, (LPARAM)0 );
    DWORD dwTimeout = ohObject.GetTimeout( _T("Erase Flash") );
    if( dwTimeout <= MAX_ERASEFLASH_TIMEOUT )
    {
        dwTimeout = (DWORD)(pBMFileInfo->llOprSize / SECTION_SIZE * dwTimeout + dwTimeout);
    }
    
    if( !m_bmOpr.EraseFlash( 
        (DWORD)(pBMFileInfo->llBase), 
        (DWORD)(pBMFileInfo->llOprSize), dwTimeout )  )
    {
        return FALSE;
    }

    return TRUE;    
}


BOOL CBootModeIntegOpr::EraseFlashByID( void * pFileInfo  )
{
    BMFileInfo* pBMFileInfo = (BMFileInfo*)pFileInfo;
	
    PostMessageToUplevel( BM_ERASE_FLASH, (WPARAM)m_dwOprCookie, (LPARAM)0 );
    DWORD dwTimeout = ohObject.GetTimeout( _T("Erase Flash") );
    if( dwTimeout <= MAX_ERASEFLASH_TIMEOUT )
    {
        dwTimeout = (DWORD)(pBMFileInfo->llOprSize / SECTION_SIZE * dwTimeout + dwTimeout);
    }
    
    if( !m_bmOpr.EraseFlash( 
        (LPBYTE)pBMFileInfo->szRepID,
		MAX_REP_ID_LEN*2,
        (DWORD)(pBMFileInfo->llOprSize), dwTimeout  )  )
    {
        return FALSE;
    }
	
    return TRUE;    
}

BOOL CBootModeIntegOpr::ReadFlash(void * pFileInfo) 
{
    BMFileInfo* pBMFileInfo = (BMFileInfo*)pFileInfo;

    // Read NV_LENGTH byte from module
    m_bmOpr.AllocRecvBuffer( (DWORD)(pBMFileInfo->llOprSize) );

    DWORD dwBase = (DWORD)(pBMFileInfo->llBase);
    DWORD dwLeft = (DWORD)(pBMFileInfo->llOprSize);
    DWORD dwMaxLength = pBMFileInfo->dwMaxLength;    
    DWORD dwSize = dwMaxLength;   
	DWORD dwReadFlashTimeout = ohObject.GetTimeout( _T("Read Flash") );

    PostMessageToUplevel( BM_READ_FLASH, 
        (WPARAM)m_dwOprCookie, (LPARAM)100 );
    
    if( dwBase & 0x80000000 )
    {
       DWORD dwOffset = 0;
       while(dwLeft > 0 && !m_bStopOpr )
       {
            if(dwLeft > dwMaxLength )
            {
                dwSize = dwMaxLength ;                
            }
            else
            {
                dwSize = dwLeft;
            }
        
            if( !m_bmOpr.ReadPartitionFlash( dwBase,dwSize,dwOffset,
				dwReadFlashTimeout ) )
            {
                m_bmOpr.FreeRecvBuffer();
                return FALSE;
            }
            dwOffset += dwSize;
            dwLeft -= dwSize;
            PostMessageToUplevel( BM_READ_FLASH_PROCESS, 
                (WPARAM)m_dwOprCookie, 
                (LPARAM)((pBMFileInfo->llOprSize - dwLeft)*100/pBMFileInfo->llOprSize) );        
        }
    }
    else
    {
        while(dwLeft > 0 && !m_bStopOpr )
        {
            if(dwLeft > dwMaxLength )
            {
                dwSize = dwMaxLength ;                
            }
            else
            {
                dwSize = dwLeft;
            }
        
            if( !m_bmOpr.ReadFlash( dwBase,dwSize, 
                dwReadFlashTimeout ) )
            {
                m_bmOpr.FreeRecvBuffer();
                return FALSE;
            }
            dwBase += dwSize;
            dwLeft -= dwSize;
            PostMessageToUplevel( BM_READ_FLASH_PROCESS, 
                (WPARAM)m_dwOprCookie, 
                (LPARAM)((pBMFileInfo->llOprSize - dwLeft)*100/pBMFileInfo->llOprSize) );        
        }
    }

    if( m_bStopOpr )
        return FALSE;
    return TRUE;
}

BOOL CBootModeIntegOpr::ReadFlashByID(void * pFileInfo) 
{
    BMFileInfo* pBMFileInfo = (BMFileInfo*)pFileInfo;

	DWORD dwReadStartTimeout = ohObject.GetTimeout( _T("StartRead") );

	if(!m_bmOpr.StartRead((LPBYTE)pBMFileInfo->szRepID,MAX_REP_ID_LEN*2,pBMFileInfo->llOprSize,dwReadStartTimeout))
	{
		return FALSE;
	}
	
    // Read NV_LENGTH byte from module
    m_bmOpr.AllocRecvBuffer( (DWORD)(pBMFileInfo->llOprSize));
	
    //DWORD dwBase = pBMFileInfo->dwBase;
    __uint64 llLeft = pBMFileInfo->llOprSize;
    DWORD dwMaxLength = pBMFileInfo->dwMaxLength;    
    DWORD dwSize = dwMaxLength;   
	
    PostMessageToUplevel( BM_READ_FLASH, 
        (WPARAM)m_dwOprCookie, (LPARAM)100 );
    
	DWORD dwReadMidstTimeout = ohObject.GetTimeout( _T("MidstRead") );
 
    __uint64 llOffset = 0;
	while(llLeft > 0 && !m_bStopOpr )
	{
        if(llLeft > dwMaxLength )
        {
            dwSize = dwMaxLength ;                
        }
        else
        {
            dwSize = (DWORD)llLeft;
        }
		
        if( !m_bmOpr.MidstRead( dwSize,llOffset,
			dwReadMidstTimeout ) )
        {
            m_bmOpr.FreeRecvBuffer();
            return FALSE;
        }
        llOffset += dwSize;
        llLeft -= dwSize;
        PostMessageToUplevel( BM_READ_FLASH_PROCESS, 
            (WPARAM)m_dwOprCookie, 
           (LPARAM)((pBMFileInfo->llOprSize - llLeft)*100/pBMFileInfo->llOprSize)  );        
    }
	
    if( m_bStopOpr )
        return FALSE;

	DWORD dwReadEndTimeout = ohObject.GetTimeout( _T("EndRead") );
	m_bmOpr.EndRead( dwReadEndTimeout );	
    return TRUE;
}

BOOL CBootModeIntegOpr::Excute(void * pFileInfo) 
{
    UNUSED_ALWAYS( pFileInfo );

    return m_bmOpr.Excute( ohObject.GetTimeout( _T("Excute") ) );
}

BOOL CBootModeIntegOpr::ChangeBaud( void * pFileInfo )
{
    UNUSED_ALWAYS( pFileInfo );

    PostMessageToUplevel( BM_CHANGE_BAUD,  (WPARAM)m_dwOprCookie, (LPARAM)0 );     
    
    return m_bmOpr.ChangeBaud( ohObject.GetTimeout( _T("ChangeBaud") ) );
}

BOOL CBootModeIntegOpr::Reset(void * pFileInfo) 
{
    UNUSED_ALWAYS( pFileInfo );
    PostMessageToUplevel( BM_RESET, 
        (WPARAM)m_dwOprCookie, 
        (LPARAM)0 );      
	return m_bmOpr.Reset(ohObject.GetTimeout( _T("Reset")) );
}

BOOL CBootModeIntegOpr::PowerOff(void* pFileInfo)
{
	UNUSED_ALWAYS( pFileInfo );  
	PostMessageToUplevel( BM_POWEROFF,(WPARAM)m_dwOprCookie,NULL );
	return m_bmOpr.PowerOff( );
}
BOOL CBootModeIntegOpr::ReadChipType( void * pFileInfo )
{
    UNUSED_ALWAYS( pFileInfo );
    m_bmOpr.AllocRecvBuffer( sizeof(DWORD) );
    
    PostMessageToUplevel( BM_READ_CHIPTYPE,  (WPARAM)m_dwOprCookie, (LPARAM)0 );      
    
     if( !m_bmOpr.ReadChipType( 
            ohObject.GetTimeout( _T("Read ChipType") ) ) )
     {
         m_bmOpr.FreeRecvBuffer();
         return FALSE;
     }
     return TRUE;
}

BOOL CBootModeIntegOpr::ReadNVItem( void * pFileInfo  )
{
    BMFileInfo* pBMFileInfo = (BMFileInfo*)pFileInfo;

    m_bmOpr.AllocRecvBuffer( READ_NVITEM_REP_DATA_LEN );   

    PostMessageToUplevel( BM_READ_NVITEM,  (WPARAM)m_dwOprCookie, (LPARAM)0 );      
    
    if( !m_bmOpr.ReadNVItem( (DWORD)pBMFileInfo->llBase, 
            (DWORD)(pBMFileInfo->llBase + pBMFileInfo->llOprSize), 
            (unsigned short)(ohObject.GetNVItemID()),
            ohObject.GetTimeout( _T("Read NVItem") ) ) )
    {
        m_bmOpr.FreeRecvBuffer();
        return FALSE;
    }
    LPBYTE lpRecvBuffer = m_bmOpr.GetRecvBuffer();
    DWORD dwRecvSize = m_bmOpr.GetRecvBufferSize();
    if( dwRecvSize < READ_NVITEM_REP_DATA_LEN )
    {
        m_bmOpr.FreeRecvBuffer(); 
        return FALSE;
    }

    DWORD dwSoruceValue, dwDestValue;
    dwSoruceValue =  *(DWORD*)&lpRecvBuffer[0];    
    dwDestValue   = 0;
    CONVERT_INT( dwSoruceValue, dwDestValue);
    DWORD dwReadStart = dwDestValue;
        
    unsigned short uiSourceValue, uiDestValue;        
    uiSourceValue =  *(unsigned short*)&lpRecvBuffer[ sizeof( DWORD )];
    uiDestValue   = 0;
    CONVERT_SHORT( uiSourceValue, uiDestValue);
    DWORD dwReadLength = uiDestValue;

    if( dwReadStart == -1 || dwReadLength == -1 )
    {
        m_bmOpr.FreeRecvBuffer();
        Log( _T("Read NV Item: NOT find the NVITEM ID.") );
        return FALSE;
    }
/*

    if( dwReadStart % 4 == 2 )
    {
        dwReadStart = dwReadStart  -2 ;
        dwReadLength += 2;   
    }
    else
    {
        dwReadLength += 1;
    }
*/    
    BMFileInfo fileinfo;
    memset( &fileinfo, 0, sizeof( BMFileInfo) );
    fileinfo.llBase = dwReadStart;
    fileinfo.llOprSize = dwReadLength;
    fileinfo.dwMaxLength = 0x1000;
    return ReadFlash( (void*)&fileinfo );    
}

BOOL CBootModeIntegOpr::Repartition( void * pFileInfo  )
{
    UNUSED_ALWAYS( pFileInfo );
    
	if(m_bNeedRepartion)
	{
        PostMessageToUplevel( BM_REPARTITION,(WPARAM)m_dwOprCookie,NULL );
		m_bRepartionDone = m_bmOpr.Repartition( ohObject.GetTimeout( _T("Repartition") ) ) ;
	}
	else
	{
		m_bNeedRepartion = TRUE; // recover to initial value
        m_bRepartionDone = TRUE;		
	}

    return m_bRepartionDone;
}

BOOL CBootModeIntegOpr::ForceRepartition( void * pFileInfo  )
{
    UNUSED_ALWAYS( pFileInfo );
    PostMessageToUplevel( BM_REPARTITION,(WPARAM)m_dwOprCookie,NULL );
    m_bRepartionDone = m_bmOpr.Repartition( ohObject.GetTimeout( _T("Repartition") ) );
	return m_bRepartionDone ;
}

BOOL CBootModeIntegOpr::RepartitionByID( void * pFileInfo )
{
    BMFileInfo* pBMFileInfo = (BMFileInfo*)pFileInfo;

	if(m_bNeedRepartion)
	{
    	 PostMessageToUplevel( BM_REPARTITION,(WPARAM)m_dwOprCookie,NULL );
		m_bRepartionDone =  m_bmOpr.Repartition((LPBYTE)pBMFileInfo->lpCode,(DWORD)pBMFileInfo->llCodeSize, ohObject.GetTimeout( _T("Repartition") ) ) ;
	}
	else
	{
		m_bNeedRepartion = TRUE; // recover to initial value
		m_bRepartionDone = TRUE;
	}
    return m_bRepartionDone;
}

BOOL CBootModeIntegOpr::ForceRepartitionByID( void * pFileInfo )
{
    BMFileInfo* pBMFileInfo = (BMFileInfo*)pFileInfo;
    PostMessageToUplevel( BM_REPARTITION,(WPARAM)m_dwOprCookie,NULL );
    m_bRepartionDone = m_bmOpr.Repartition((LPBYTE)pBMFileInfo->lpCode,(DWORD)pBMFileInfo->llCodeSize, ohObject.GetTimeout( _T("Repartition") ) ) ;
	return m_bRepartionDone;
}

BOOL CBootModeIntegOpr::ReadFlashType( void * pFileInfo )
{
    UNUSED_ALWAYS( pFileInfo );
    m_bmOpr.AllocRecvBuffer( sizeof(DWORD)*4 );
    if( !m_bmOpr.ReadFlashType( ohObject.GetTimeout( _T("ReadFlashType") ) ) )
    {
        m_bmOpr.FreeRecvBuffer();
        return FALSE;
    }
    else
    {
        return TRUE;
    }
}

BOOL CBootModeIntegOpr::ReadTransceiverType(void * pFileInfo)
{
    UNUSED_ALWAYS( pFileInfo );
    m_bmOpr.AllocRecvBuffer(4);
    if( !m_bmOpr.ReadTransceiverType( ohObject.GetTimeout( _T("ReadTransceiverType") ) ) )
    {
        m_bmOpr.FreeRecvBuffer();
        return FALSE;
    }
    else
    {
        return TRUE;
    }
}

BOOL CBootModeIntegOpr::ReadFlashInfo(void * pFileInfo)
{
    UNUSED_ALWAYS( pFileInfo );
    m_bmOpr.AllocRecvBuffer( sizeof(DWORD)*3 );
    if( !m_bmOpr.ReadFlashInfo( ohObject.GetTimeout( _T("ReadFlashInfo") ) ) )
    {
        m_bmOpr.FreeRecvBuffer();
        return FALSE;
    }
    else
    {
        return TRUE;
    }
}
BOOL CBootModeIntegOpr::EnableFlash(void * pFileInfo)
{
    UNUSED_ALWAYS( pFileInfo );
    return m_bmOpr.EnableFlash(ohObject.GetTimeout( _T("EnableFlash")));
}

BOOL CBootModeIntegOpr::GetCheckBaudCrcType(void * pFileInfo)
{
	UNUSED_ALWAYS( pFileInfo );
	m_bmOpr.AllocRecvBuffer( 4 );
	if( !m_bmOpr.GetCheckBaudCrcType() )
	{
		m_bmOpr.FreeRecvBuffer();
		return FALSE;
	}
	else
	{
		return TRUE;
	}
}

BOOL CBootModeIntegOpr::SendExtTable(void * pFileInfo)
{
	BMFileInfo* pBMFileInfo = (BMFileInfo*)pFileInfo;
	return m_bmOpr.SendExtTable((LPBYTE)pBMFileInfo->lpCode,(DWORD)pBMFileInfo->llCodeSize, ohObject.GetTimeout( _T("SendExtTable") ) ) ;
}

BOOL CBootModeIntegOpr::ExecNandInit( void * pFileInfo )
{
	UNUSED_ALWAYS(pFileInfo);
    m_bRepartionDone = FALSE;
	m_bmOpr.AllocRecvBuffer( sizeof(DWORD) );
    BOOL bExcRet = m_bmOpr.Excute( ohObject.GetTimeout( _T("ExecNandInit") ) );
    
	if( bExcRet )
	{
		m_bmOpr.FreeRecvBuffer();	
		m_bNeedRepartion = FALSE;
        m_bRepartionDone = TRUE;
		return bExcRet;
	}
    m_bNeedRepartion = FALSE;
	DWORD dwError = m_bmOpr.GetLastErrorCode(); 
    BOOL bOK = FALSE;
    
    if (BSL_REP_INCOMPATIBLE_PARTITION == dwError)
    {
        m_bNeedRepartion = TRUE;
        bOK = TRUE;
		/*if (m_bmOpr.SupportNotTransCode())
		{
			m_bmOpr.DisableTransCode(ohObject.GetTimeout( _T("DisableTransCode") ));
		}*/
    }
    
    if(BSL_CHIPID_NOT_MATCH != dwError)
    {
        m_bmOpr.FreeRecvBuffer();
    }

	return bOK;
	
}

void CBootModeIntegOpr::PostMessageToUplevel( opr_status_msg msgID,
                                        WPARAM wParam, LPARAM lParam  )
{
    m_pReceiver->OnMessage(msgID,wParam,lParam);
}

BOOL CBootModeIntegOpr::Initialize(void* pOpenArgument,
                                   BOOL bBigEndian,
                                   DWORD dwOprCookie,
                                   void* pReceiver)
{
    m_bCheckBaudRate = FALSE;
    m_bStopOpr = FALSE;
	m_bNeedRepartion = TRUE;
	m_bRepartionDone = FALSE;
    m_pReceiver = (IBMProcObserver*)pReceiver;

    //SetMessageReceiver( bRcvThread, (LPVOID)pReceiver, dwOprCookie );
    return m_bmOpr.Initialize( pOpenArgument,
                                bBigEndian,
                                dwOprCookie);
}

void CBootModeIntegOpr::Uninitialize() 
{
    m_bmOpr.Uninitialize();
    m_bCheckBaudRate   = TRUE;
}

void CBootModeIntegOpr::Log(LPCTSTR lpszLog) 
{
    m_bmOpr.Log( lpszLog );
}

void * CBootModeIntegOpr::GetRecvBuffer()
{
    return (void*)m_bmOpr.GetRecvBuffer();
}

void CBootModeIntegOpr::FreeRecvBuffer() 
{
    m_bmOpr.FreeRecvBuffer();
}

void CBootModeIntegOpr::StopOpr() 
{
    if (!m_bStopOpr)
    {
        m_bStopOpr = TRUE;
        m_bmOpr.StopOpr();
    }
    
}

long CBootModeIntegOpr::GetRecvBufferSize() 
{
	return m_bmOpr.GetRecvBufferSize();
}

ICommChannel * CBootModeIntegOpr::GetChannelPtr()
{
    return m_bmOpr.GetChannelPtr();
}

void CBootModeIntegOpr::SetChannel(ICommChannel * pChannel)
{
    m_bmOpr.SetChannel( pChannel );
}

long CBootModeIntegOpr::GetIDsOfNames(LPCTSTR lpszFunName)
{
	for(int i=0;i<(m_oprCount-1);i++)
	{
    	if(strcmp(m_oprEntries[i].lpszName,lpszFunName)==0)
		{
			return i;
		}
	}

	return -1;
}

BOOL CBootModeIntegOpr::Invoke(long id,void * pFileInfo)
{
	if(id<0 || id>=m_oprCount)
		return FALSE;

	return (this->*(m_oprEntries[id].pFun))(pFileInfo);
}

BOOL CBootModeIntegOpr::ReadSectorSize( void * pFileInfo )
{
	UNUSED_ALWAYS( pFileInfo );
    m_bmOpr.AllocRecvBuffer( sizeof(DWORD) );
    if( !m_bmOpr.ReadSectorSize( ohObject.GetTimeout( _T("ReadSectorSize") ) ) )
    {
        m_bmOpr.FreeRecvBuffer();
        return FALSE;
    }
    else
    {
        return TRUE;
    }
}

BOOL CBootModeIntegOpr::ReadFlashAndSave( void * pFileInfo )
{
	return _ReadFlashAndSave(pFileInfo,FALSE,FALSE);
}

BOOL CBootModeIntegOpr::ReadFlashAndSaveByID( void * pFileInfo )
{
	return _ReadFlashAndSave(pFileInfo,TRUE,FALSE);
}

BOOL CBootModeIntegOpr::ReadFlashAndDirectSave( void * pFileInfo )
{
	return _ReadFlashAndSave(pFileInfo,FALSE,FALSE,TRUE);
}

BOOL CBootModeIntegOpr::ReadFlashAndDirectSaveByID( void * pFileInfo )
{
	return _ReadFlashAndSave(pFileInfo,TRUE,FALSE,TRUE);
}

BOOL CBootModeIntegOpr::ReadFlashAndSaveByIDEx( void* pFileInfo )
{
    return _ReadFlashAndSave(pFileInfo,TRUE,TRUE);
}

DWORD CBootModeIntegOpr::GetOprLastErrorCode()
{
	return m_bmOpr.GetLastErrorCode();
}

BOOL CBootModeIntegOpr::ReadFlashToFile(void * pFileInfo, FILE *pFile)
{
    BMFileInfo* pBMFileInfo = (BMFileInfo*)pFileInfo;
    

    DWORD dwBase = (DWORD)(pBMFileInfo->llBase);
    DWORD dwLeft = (DWORD)(pBMFileInfo->llOprSize);
    DWORD dwMaxLength = pBMFileInfo->dwMaxLength;    
    DWORD dwSize = dwMaxLength;    
	DWORD dwReadFlashTimeout = ohObject.GetTimeout( _T("Read Flash") );

    PostMessageToUplevel( BM_READ_FLASH, 
        (WPARAM)m_dwOprCookie, (LPARAM)100 );
    
    if( dwBase & 0x80000000 )
    {
       DWORD dwOffset = 0;
       while(dwLeft > 0 && !m_bStopOpr )
       {		    
            if(dwLeft > dwMaxLength )
            {
                dwSize = dwMaxLength ;                
            }
            else
            {
                dwSize = dwLeft;
            }

			m_bmOpr.AllocRecvBuffer( dwSize );
        
            if( !m_bmOpr.ReadPartitionFlash( dwBase,dwSize,dwOffset, 
                 dwReadFlashTimeout) )
            {
                m_bmOpr.FreeRecvBuffer();
                return FALSE;
            }
            dwOffset += dwSize;
            dwLeft -= dwSize;

			//write to file
			DWORD dwWrite = fwrite(m_bmOpr.GetRecvBuffer(),m_bmOpr.GetRecvBufferSize(),1,pFile);
			m_bmOpr.FreeRecvBuffer();
			if(dwWrite != 1)
			{
				_TCHAR szTmp[MAX_PATH]={0};
				_stprintf(szTmp,_T("Read flash data to file failed, [ErrorCode:0x%X]: \"%s\"."),errno,strerror(errno));
				Log(szTmp);	
				return FALSE;
			}

            PostMessageToUplevel( BM_READ_FLASH_PROCESS, 
                (WPARAM)m_dwOprCookie, 
                 (LPARAM)((pBMFileInfo->llOprSize - dwLeft)*100/pBMFileInfo->llOprSize) );        
        }
    }
    else
    {
        while(dwLeft > 0 && !m_bStopOpr )
        {
            if(dwLeft > dwMaxLength )
            {
                dwSize = dwMaxLength ;                
            }
            else
            {
                dwSize = dwLeft;
            }
        
			m_bmOpr.AllocRecvBuffer( dwSize );

            if( !m_bmOpr.ReadFlash( dwBase,dwSize, 
                dwReadFlashTimeout ) )
            {
                m_bmOpr.FreeRecvBuffer();
                return FALSE;
            }
            dwBase += dwSize;
            dwLeft -= dwSize;

			//write to file
			DWORD dwWrite = fwrite(m_bmOpr.GetRecvBuffer(),m_bmOpr.GetRecvBufferSize(),1,pFile);
			m_bmOpr.FreeRecvBuffer();
			if(dwWrite!=1)
			{
				_TCHAR szTmp[MAX_PATH]={0};
				_stprintf(szTmp,_T("Write flash data to file failed, [ErrorCode:0x%X]: \"%s\"."),errno,strerror(errno));
				Log(szTmp);	
				return FALSE;
			}


            PostMessageToUplevel( BM_READ_FLASH_PROCESS, 
                (WPARAM)m_dwOprCookie, 
                (LPARAM)((pBMFileInfo->llOprSize - dwLeft)*100/pBMFileInfo->llOprSize) );        
        }
    }

    if( m_bStopOpr )
        return FALSE;
    return TRUE;
}


BOOL CBootModeIntegOpr::ReadFlashToFileByID(void* pFileInfo, FILE *pFile, BOOL bIs64Bit/* = FALSE*/)
{
    BMFileInfo* pBMFileInfo = (BMFileInfo*)pFileInfo;
    
	DWORD dwReadStartTimeout = ohObject.GetTimeout( _T("StartRead") );
	

    if (0 == pBMFileInfo->llOprSize)
    {
        _TCHAR szTmp[MAX_PATH]={0};
	    _stprintf(szTmp,_T("[%s] read size is zero."),pBMFileInfo->szFileID);
        Log(szTmp);	
        return FALSE;
    }
	if(!m_bmOpr.StartRead((LPBYTE)pBMFileInfo->szRepID,MAX_REP_ID_LEN*2,pBMFileInfo->llOprSize,dwReadStartTimeout,bIs64Bit))
	{
		return FALSE;
	}

    __uint64 llLeft = pBMFileInfo->llOprSize;
    DWORD dwMaxLength = pBMFileInfo->dwMaxLength;    
    DWORD dwSize = dwMaxLength;    

    PostMessageToUplevel( BM_READ_FLASH, (WPARAM)m_dwOprCookie, (LPARAM)100 );
    
    DWORD dwMidstReadTimeout = ohObject.GetTimeout( _T("MidstRead") );
  
   __uint64 llOffset = 0;
   while(llLeft > 0 && !m_bStopOpr )
   {		    
        if(llLeft > dwMaxLength )
        {
            dwSize = dwMaxLength ;                
        }
        else
        {
            dwSize = (DWORD)llLeft;
        }

		m_bmOpr.AllocRecvBuffer( dwSize );
    
        if( !m_bmOpr.MidstRead( dwSize,llOffset, 
             dwMidstReadTimeout,bIs64Bit) )
        {
            m_bmOpr.FreeRecvBuffer();
            return FALSE;
        }
        llOffset += dwSize;
        llLeft -= dwSize;

		//write to file
        DWORD dwWrite = fwrite(m_bmOpr.GetRecvBuffer(),m_bmOpr.GetRecvBufferSize(),1,pFile);
		m_bmOpr.FreeRecvBuffer();
		if(dwWrite!=1)
		{
			_TCHAR szTmp[MAX_PATH]={0};
			_stprintf(szTmp,_T("Write flash data to file failed, [ErrorCode:0x%X]: \"%s\"."),errno,strerror(errno));
			Log(szTmp);	
			return FALSE;
		}

        PostMessageToUplevel( BM_READ_FLASH_PROCESS, 
            (WPARAM)m_dwOprCookie, 
            (LPARAM)((pBMFileInfo->llOprSize - llLeft)*100/pBMFileInfo->llOprSize) );        
    }
    
    if( m_bStopOpr )
        return FALSE;

	DWORD dwEndReadTimeout = ohObject.GetTimeout( _T("EndRead") );
	m_bmOpr.EndRead( dwEndReadTimeout);

    return TRUE;
}

BOOL CBootModeIntegOpr::DoNothing(void * pFileInfo)
{
	UNUSED_ALWAYS(pFileInfo);
	return TRUE;
}

BOOL CBootModeIntegOpr::SetCRC(void * pFileInfo) 
{
	UNUSED_ALWAYS(pFileInfo);
	m_bmOpr.SetIsCheckCrc( TRUE );
	return TRUE;    
}

BOOL CBootModeIntegOpr::ResetCRC(void * pFileInfo) 
{
	UNUSED_ALWAYS(pFileInfo);
	m_bmOpr.SetIsCheckCrc( FALSE );
	return TRUE;    
}


BOOL CBootModeIntegOpr::KeepCharge(void * pFileInfo)
{
	UNUSED_ALWAYS( pFileInfo );    	
	PostMessageToUplevel( BM_KEEPCHARGE,(WPARAM)m_dwOprCookie,NULL );
	DWORD dwTimeout = ohObject.GetTimeout( _T("KeepCharge") );
	return m_bmOpr.KeepCharge( dwTimeout );
}
unsigned int CBootModeIntegOpr::_CheckSum32(unsigned int nChkSum, unsigned char const *pDataBuf, unsigned int nLen)
{
    for(unsigned int i= 0; i< nLen; ++i)
    {
        nChkSum += (BYTE)(*(pDataBuf+i));
    }
    return nChkSum;
}

BOOL CBootModeIntegOpr::_DoCheckSum(PBMFileInfo pBMFileInfo)
{
    
    DWORD dwCheckSum    = 0;
    BOOL bOK            = TRUE;  
    //NV data
    if(strncasecmp(  pBMFileInfo->szFileID,_T("NV"),2) == 0  || 
        strncasecmp(pBMFileInfo->szFileID,_T("_CHECK_NV"),9)==0 )
    {        
        pBMFileInfo->dwCheckSum =m_bmOpr.DoNVCheckSum((LPBYTE)pBMFileInfo->lpCode,(DWORD)(pBMFileInfo->llCodeSize));
        bOK = pBMFileInfo->dwCheckSum==0 ? FALSE :TRUE;
        return bOK;
    }
    if( !ohObject.IsNeedDoChkSum() ||
        strncasecmp(pBMFileInfo->szFileType,_T("FDL"),3)== 0 ||
        strcasecmp(pBMFileInfo->szFileType,_T("NAND_FDL"))== 0
       )
    {
        pBMFileInfo->dwCheckSum = 0;
        return TRUE;
    }

    return bOK;
}
BOOL CBootModeIntegOpr::_Download(void * pFileInfo,BOOL bByID, BOOL bIs64Bit/* = FALSE*/)
{	
	/* 
	 * need not send this message, because it will be mis-understand.
    PostMessageToUplevel( BM_ERASE_FLASH, 
        (WPARAM)m_dwOprCookie, (LPARAM)0 );
	*/

    BMFileInfo* pBMFileInfo = (BMFileInfo*)pFileInfo;
    DWORD dwTimeout = ohObject.GetTimeout( _T("Erase Flash") );
    if( dwTimeout <= MAX_ERASEFLASH_TIMEOUT )
    {
        dwTimeout = (DWORD)(pBMFileInfo->llCodeSize / SECTION_SIZE * dwTimeout + dwTimeout);
    }
    PostMessageToUplevel( BM_DOWNLOAD, (WPARAM)m_dwOprCookie, (LPARAM)100 );
    if (0 == pBMFileInfo->llCodeSize)
    {
		_TCHAR szTmp[MAX_PATH]={0};
	    _stprintf(szTmp,_T("[%s] file size is zero."),pBMFileInfo->szFileID);
        Log(szTmp);		
        return FALSE;
    }

    if (!_DoCheckSum(pBMFileInfo))
    {
		_TCHAR szTmp[MAX_PATH]={0};
	    _stprintf(szTmp,_T("[%s] _DoCheckSum fail."),pBMFileInfo->szFileID);
        Log(szTmp);	
        return FALSE;
    }
	//printf("Fid\leID=%s,CheckSum = 0x%X\n",pBMFileInfo->szFileID,pBMFileInfo->dwCheckSum);

	if(!bByID)
	{
		if(!m_bmOpr.StartData( 
			pBMFileInfo->llBase, 
			pBMFileInfo->llCodeSize, 
			(LPBYTE)pBMFileInfo->lpCode,
            pBMFileInfo->dwCheckSum,
			dwTimeout,
            bIs64Bit) )
		{
			return FALSE;
		}
	}
	else
	{
		if(!m_bmOpr.StartData( 
			(LPBYTE)pBMFileInfo->szRepID, 
			MAX_REP_ID_LEN*2,
			pBMFileInfo->llCodeSize, 
			(LPBYTE)pBMFileInfo->lpCode,
            pBMFileInfo->dwCheckSum,
			dwTimeout,
            bIs64Bit) )
		{
			return FALSE;
		}
	}	

	DWORD dwDownloadTimeout = ohObject.GetTimeout( _T("Download") );	

	__uint64 llLeft = pBMFileInfo->llCodeSize;
    DWORD dwMaxLength = pBMFileInfo->dwMaxLength;
    DWORD dwSize = dwMaxLength;	

	BOOL bNeedRemap = FALSE;
	LPBYTE pCurData = (LPBYTE)pBMFileInfo->lpCode;
	DWORD  dwLeft2  = pBMFileInfo->dwFirstMapSize;
	__uint64  llCurOffset = 0;
	DWORD  dwCurMapSize = pBMFileInfo->dwFirstMapSize;
	LPBYTE pMapBase = NULL;

    DWORD dwDownloaded= 0;
	_TCHAR strInfo[MAX_PATH] = {0};
	sprintf(strInfo,_T("CodeSize = 0x%llX,dwLeft2 = %d,bChangeCode=%d"),llLeft,dwLeft2,pBMFileInfo->bChangeCode);
	m_bmOpr.Log(strInfo);

	if(
		!pBMFileInfo->bChangeCode 	&&
		pBMFileInfo->dwFirstMapSize < pBMFileInfo->llCodeSize &&
		pBMFileInfo->fdFile != -1
	    )
	{
		bNeedRemap = TRUE;
	}
	else
	{
		dwLeft2 = llLeft;  // no file map
	}

	sprintf(strInfo,_T("dwDownloadTimeout = %d,NeedRemap = %d"),dwDownloadTimeout,bNeedRemap);
	m_bmOpr.Log(strInfo);

	do
	{
		while( dwLeft2 > 0 && !m_bStopOpr )
		{
			if(dwLeft2 >= dwMaxLength )
			{
				dwSize = dwMaxLength ;
			}
			else
			{
				dwSize = dwLeft2;
				if(bNeedRemap && (( dwCurMapSize + llCurOffset ) < pBMFileInfo->llCodeSize))
				{
					break;
				}
			}

			//sprintf(strErr2,_T("dwCodeSize: %lld,dwLeft: %d, dwSize:%d"),pBMFileInfo->llCodeSize ,dwLeft , dwSize);
			//m_bmOpr.Log(strErr2);

			if( !m_bmOpr.MidstData( dwSize, pCurData, dwDownloadTimeout, pBMFileInfo->llCodeSize - llLeft + dwSize) )
			{
				if(pMapBase!=NULL)
				{
					//::UnmapViewOfFile(pMapBase);
					munmap(pMapBase,dwCurMapSize);
					pMapBase = NULL;
				}
				return FALSE;
			}
			dwLeft2 -= dwSize;
			llLeft  -= dwSize;
			pCurData += dwSize;

			PostMessageToUplevel( BM_DOWNLOAD_PROCESS, 
			(WPARAM)m_dwOprCookie, 
			(LPARAM)((pBMFileInfo->llCodeSize - llLeft )*100/pBMFileInfo->llCodeSize));
		
		}

		if(bNeedRemap && llLeft != 0)
		{
			if(pMapBase!=NULL)
			{
				munmap(pMapBase,dwCurMapSize);
				pMapBase = NULL;
			 }

			llCurOffset += dwCurMapSize;
			DWORD dwLeft2Tail = (((dwLeft2 + 0x10000 - 1) / 0x10000)*0x10000);
			if(dwLeft2 != 0)
			{
				llCurOffset -=  dwLeft2Tail;
			}

			if((llLeft + dwLeft2) < MAX_MAP_SIZE)
			{
				dwCurMapSize =  llLeft + dwLeft2Tail;
			}
			else
			{
				dwCurMapSize = MAX_MAP_SIZE;
			}

			if( (llCurOffset + dwCurMapSize) > pBMFileInfo->llCodeSize )
			{
				dwCurMapSize =  pBMFileInfo->llCodeSize - llCurOffset;
			}


			pMapBase = NULL;
			pCurData = NULL;

			//pMapBase = (LPBYTE)::MapViewOfFile(pBMFileInfo->hFDLCodeMapView,FILE_MAP_READ,0,dwCurOffset,dwCurMapSize);
			pMapBase = (LPBYTE)mmap(NULL,dwCurMapSize,PROT_READ,MAP_SHARED,pBMFileInfo->fdFile,llCurOffset);
			if(pMapBase == NULL)
			{
				_TCHAR strErr[MAX_PATH] = {0};
				//sprintf(strErr,_T("MapViewOfFile failed, [ERROR:0x%X]."),GetLastError());
				sprintf(strErr,_T("MapViewOfFile failed, [ERROR:0x%X]: \"%s\"."),errno,strerror(errno));
				m_bmOpr.Log(strErr);
				return FALSE;
			}
			else
			{
				_TCHAR strErr[MAX_PATH] = {0};
				DWORD dwDlt = 0;
				pCurData = pMapBase;
				if(dwLeft2 != 0)
				{
					dwDlt = dwLeft2Tail - dwLeft2;
					pCurData += dwDlt;
				}
				dwLeft2 = dwCurMapSize - dwDlt;

				sprintf(strErr,_T("MapCurSize=%d,MapCurOffset =0x%llX."),dwCurMapSize,llCurOffset);
				m_bmOpr.Log(strErr);
			}
        	}

   	 }while(llLeft != 0);

	if(pMapBase!=NULL)
	{
		munmap(pMapBase,dwCurMapSize);
		pMapBase = NULL;
	}

    if( m_bStopOpr )
    {
        return FALSE;
    }
    if( !m_bmOpr.EndData( ohObject.GetTimeout( _T("EndData") ) ) )
	{
		 return FALSE;
	}
    return TRUE;
}


BOOL CBootModeIntegOpr::_ReadFlashAndSave( void * pFileInfo , BOOL bByID, BOOL bIs64Bit/* = FALSE*/,BOOL bDirectSave/* = FALSE*/)
{
	BMFileInfo* pBMFileInfo = (BMFileInfo*)pFileInfo;
	
    if(strlen(pBMFileInfo->szFileName) == 0)
	{
		Log(_T("File name to save falsh data is empty."));
		return FALSE;
	}
	
	_TCHAR szFileName[MAX_PATH]={0};
	_TCHAR szFileNameTmp[MAX_PATH]={0};
	if (bDirectSave)
	{
		_tcscpy(szFileName,pBMFileInfo->szFileName);
	}
	else
	{
	    strcpy(szFileNameTmp,pBMFileInfo->szFileName);

	    _TCHAR *pFind = strrchr(szFileNameTmp,_T('//'));
		if(pFind != NULL)
		{
	        _TCHAR *pFindDot = strrchr(szFileNameTmp,_T('.'));
			if(pFindDot == NULL || pFindDot <= pFind )
			{
	        _stprintf(szFileName,_T("%s_TTY%d"),szFileNameTmp,m_dwOprCookie);
			}
			else// if(pFindDot > pFind)
			{
				*pFindDot = _T('\0');
	        _stprintf(szFileName,_T("%s_TTY%d.%s"),
					szFileNameTmp,
					m_dwOprCookie,
					pFindDot+1);
			}
		}
		else
		{
	        _stprintf(szFileName,_T("%s_TTY%d"),szFileNameTmp,m_dwOprCookie);
		}	
	}
	
    FILE *pFile = fopen(szFileName,"wb");
    if( pFile == NULL )
	{
		
		_TCHAR szTmp[MAX_PATH]={0};
        _stprintf(szTmp,_T("Create file [%s] failed, [ErrorCode:0x%X]: \"%s\"."),szFileName, errno, strerror(errno));
		Log(szTmp);
		return FALSE;
	}	
	
	BOOL bOK = FALSE;
	
	if(!bByID)
	{
        bOK = ReadFlashToFile(pFileInfo,pFile);
	}
	else
	{
        bOK = ReadFlashToFileByID(pFileInfo,pFile,bIs64Bit);
	}
	
    fclose(pFile);

	if(bOK)
	{		
		Log(_T("Save readed flash data success."));
		return TRUE;
	}
	else
	{
		remove(szFileName);
		Log(_T("Save readed flash data failed."));
		return FALSE;
	}	
}

void CBootModeIntegOpr::EnablePortSecondEnum(BOOL bEnable)
{
	m_bmOpr.EnableCheckBaudCrc(bEnable);
}

