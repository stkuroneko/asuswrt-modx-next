// BootModeObj.cpp : Defines the initialization routines for the DLL.
//

#include "BootModeObj.h"
#include "OptionHelpper.h"
#include <string.h>
#include <pthread.h>

extern COptionHelpper ohObject;

#define DEFAULT_MAX_LENGTH          0x3000
#define MAX_UINT_SLEEP_TIME         500

typedef void *(*PTHREAD_START_ROUTINE) (void *);


/////////////////////////////////////////////////////////////////////////////
// CBootModeObj
CBootModeObj::CBootModeObj()
{
    m_hBMThread        = NULL;
    m_bExitThread      = FALSE;

    m_mapObserverRegs.clear();
    m_dwOprCookie  = 0;

    m_dwWaitTime = 0;
    m_dwNextObserverCookie = 1;

    m_dwOprCookie = 0;

    m_CS = PTHREAD_MUTEX_INITIALIZER;

}

CBootModeObj::~CBootModeObj()
{
    m_mapObserverRegs.clear();
}

BOOL CBootModeObj::GenerateEndNotification( DWORD dwOprCookie , DWORD dwResult )
{
	DWORD dwErrorCode = 1;
	if(dwResult == 1) // success
	{
		dwErrorCode = 0;
	}

	std::map<DWORD,IBMOprObserver*>::iterator it;
	DWORD dwCookie = 0;
	IBMOprObserver* pReg = NULL;

	for(it = m_mapObserverRegs.begin(); it != m_mapObserverRegs.end(); it++)
	{
		dwCookie = it->first;
		pReg = it->second;

		if( pReg == NULL)// || dwCookie!=dwOprCookie)
			continue;

		ULONG hr = pReg->OnEnd( dwOprCookie ,dwErrorCode );
		if( FAILED(hr) )
		{
			 return FALSE;
		}
		break;
	}
	return TRUE;
}

BOOL CBootModeObj::GenerateStartNotification( DWORD dwOprCookie, DWORD dwResult  )
{
	DWORD dwErrorCode = 1; //fail
	if(dwResult == 1) // success
	{
		dwErrorCode = 0;
	}

    std::map<DWORD,IBMOprObserver*>::iterator it;
    DWORD dwCookie = 0;
    IBMOprObserver* pReg = NULL;

    for(it = m_mapObserverRegs.begin(); it != m_mapObserverRegs.end(); it++)
    {
        dwCookie = it->first;
        pReg = it->second;

        if( pReg == NULL )//||dwCookie!=dwOprCookie)
            continue;

        ULONG  hr = pReg->OnStart( dwOprCookie , dwErrorCode );
        if( FAILED(hr) )
        {
            return FALSE;
        }
		break;
    }
    return TRUE;
}


BOOL CBootModeObj::GenerateEndFileOprNotification( DWORD dwOprCookie,
												  LPCTSTR lpszFileId,
                                                  LPCTSTR lpszFileType,
                                                  DWORD dwResult )
{
	DWORD dwErrorCode = 1; // fail
	if(dwResult == 1) // success
	{
		dwErrorCode = 0;
	}

    std::map<DWORD,IBMOprObserver*>::iterator it;
    DWORD dwCookie = 0;
    IBMOprObserver* pReg = NULL;

    for(it = m_mapObserverRegs.begin(); it != m_mapObserverRegs.end(); it++)
    {
        dwCookie = it->first;
        pReg = it->second;

        if( pReg == NULL)// ||dwCookie!=dwOprCookie )
            continue;

        ULONG  hr = pReg->OnFileOprEnd( dwOprCookie, lpszFileId,lpszFileType, dwErrorCode );
        if( FAILED(hr) )
        {
            return FALSE;
        }
		break;
    }
    return TRUE;

}

BOOL CBootModeObj::GenerateStartFileOprNotification( DWORD dwOprCookie,
													LPCTSTR lpszFileId,
                                                    LPCTSTR lpszFileType  )
{
	std::map<DWORD,IBMOprObserver*>::iterator it;
	DWORD dwCookie = 0;
	IBMOprObserver* pReg = NULL;

	for(it = m_mapObserverRegs.begin(); it != m_mapObserverRegs.end(); it++)
	{
		dwCookie = it->first;
		pReg = it->second;

		if( pReg == NULL)// ||dwCookie!=dwOprCookie )
		    continue;

		ULONG  hr = pReg->OnFileOprStart( dwOprCookie, lpszFileId,
		                lpszFileType, (void *)&m_BMFileImpl );
		if( FAILED(hr) )
		{
		    return FALSE;
		}
		break;
	}
	return TRUE;
}

BOOL CBootModeObj::GenerateEndOprNotification( DWORD dwOprCookie,
											  LPCTSTR lpszFileId,
                                              LPCTSTR lpszFileType,
                                              LPCTSTR lpszOperationType,
                                              DWORD dwResult )
{
	DWORD dwErrorCode = 1;
	if(dwResult == 1) // success
	{
		dwErrorCode = 0;
	}
	else // get operation error code
	{
		dwErrorCode = m_OprDriver.GetOprLastErrorCode();
	}

	std::map<DWORD,IBMOprObserver*>::iterator it;
	DWORD dwCookie = 0;
	IBMOprObserver* pReg = NULL;

	for(it = m_mapObserverRegs.begin(); it != m_mapObserverRegs.end(); it++)
	{
		dwCookie = it->first;
		pReg = it->second;

		if( pReg == NULL)// ||  dwCookie!=dwOprCookie)
		    continue;

		ULONG  hr = pReg->OnOperationEnd( dwOprCookie,lpszFileId, lpszFileType,
		            lpszOperationType, dwErrorCode , (void *)&m_BMFileImpl );
		if( FAILED(hr) )
		{
		    return FALSE;
		}
		break;
	}
	return TRUE;
}

BOOL CBootModeObj::GenerateStartOprNotification( DWORD dwOprCookie,
												LPCTSTR lpszFileID,
                                                LPCTSTR lpszFileType,
                                                LPCTSTR lpszOperationType )
{
    std::map<DWORD,IBMOprObserver*>::iterator it;
    DWORD dwCookie = 0;
    IBMOprObserver* pReg = NULL;

    for(it = m_mapObserverRegs.begin(); it != m_mapObserverRegs.end(); it++)
    {
        dwCookie = it->first;
        pReg = it->second;

        if( pReg == NULL)// ||  dwCookie!=dwOprCookie)
            continue;

        ULONG  hr = pReg->OnOperationStart( dwOprCookie, lpszFileID,lpszFileType,
            lpszOperationType, (void*)(&m_BMFileImpl) );
        if( FAILED(hr) )
        {
            return FALSE;
        }
		break;
    }
    return TRUE;
}

void CBootModeObj::EndProc(  BOOL bEndSuccess  )
{
	BOOL bEndNotify = FALSE;
	DWORD dwEnd = bEndSuccess;

	//When downloaded fail,RD need to power off device.
	DWORD dwErrorCode = m_OprDriver.GetOprLastErrorCode();
	if ( 
	        !bEndSuccess                        && 
	        BSL_USER_CANCEL != dwErrorCode      &&
	        0 != dwErrorCode                    &&
	        ohObject.IsEnablePowerOff()
	   )
	{
	    int dispid;
	    dispid = m_OprDriver.GetIDsOfNames( _T("PowerOff") );
	    if( -1 != dispid )
	    {
		char strLog[MAX_PATH] = {0};
		 BOOL bResult = m_OprDriver.Invoke( dispid, NULL ); 
		 sprintf(strLog,_T("PowerOff operation %s."),bResult ? _T("Successful") : _T("Failed") );
		 Log( strLog );

	    }
	    
	}

	if( m_bExitThread )
	{
		Log( _T("m_bExitThread = TRUE."));
		m_OprDriver.Uninitialize();
		bEndNotify = GenerateEndNotification( m_dwOprCookie, dwEnd );
		if( bEndNotify && bEndSuccess )
		{
			Log( _T("Finish Successful."));
		}
		else
		{
			Log( _T("Finish Failed."));
		}
		return;
	}

    if( m_dwWaitTime == 0 )
    {
		Log( _T("m_dwWaitTime == 0."));
		m_OprDriver.Uninitialize();
		m_bExitThread = TRUE;
		bEndNotify = GenerateEndNotification( m_dwOprCookie, dwEnd );
    }
    else
    {
		Log( _T("Download files move to the first."));
		m_BMFileImpl.MoveFirst();
		ICommChannel* pChannel;
		ULONG hr = GetCommunicateChannelPtr( (LPVOID*)&pChannel );
		if( SUCCEEDED(hr) )
		{
			DWORD dwBaud = DEFAULT_BAUDRATE;
			pChannel->SetProperty(0,CH_PROP_BAUD,(void*)&dwBaud);
		}
		//@hongliang.xin 2010-1-25  not used
		//      dwEnd |= FACTORY_MODE;
		bEndNotify = GenerateEndNotification( m_dwOprCookie, dwEnd );
		UINT uiSleepCount = m_dwWaitTime / MAX_UINT_SLEEP_TIME;
		for( unsigned int i = 0; i < uiSleepCount && !m_bExitThread; i++)
		{
		    _sleep( MAX_UINT_SLEEP_TIME );
		}
		// @hongliang.xin 2010-7-19
		if(!m_bExitThread && (m_dwWaitTime % MAX_UINT_SLEEP_TIME) != 0 )
		{
			_sleep( m_dwWaitTime % MAX_UINT_SLEEP_TIME );
		}
	}
	if( bEndNotify && bEndSuccess )
	{
		Log( _T("Finish Successful."));
	}
	else
	{
		Log( _T("Finish Failed."));
	}

}

BOOL CBootModeObj::CreateBMThread( )
{
	Log( _T("Create boot mode thread."));
	/*m_hBMThread = (HANDLE)_beginthreadex(NULL,
								0,
	                            (PBEGINTHREADEX_THREADFUNC)GetBMThreadFunc,
	                            this,
	                            NULL,
	                            NULL);*/

	//m_hBMThread = CreateThread( NULL, 0, (LPTHREAD_START_ROUTINE)GetBMThreadFunc, this, 0, NULL );
	m_bExitThread = FALSE;

	int nRet = pthread_create(&m_hBMThread,
	                          NULL,
	                          (PTHREAD_START_ROUTINE)GetBMThreadFunc,
	                          this);

	if(nRet==-1)
	{
	    Log( _T("Create boot mode thread failed."));
	    return FALSE;
	}

	return TRUE;
}

void CBootModeObj::DestroyBMThread()
{
	if(m_hBMThread != NULL )
	{
		m_bExitThread = TRUE;

		m_OprDriver.StopOpr();

		Log( _T("End boot mode thread."));

		//WaitForSingleObject( m_hBMThread, INFINITE );

		pthread_join(m_hBMThread,NULL);

		//CloseHandle( m_hBMThread );
		m_hBMThread = NULL;
	}
}


void *CBootModeObj::GetBMThreadFunc( void * lpParam )
{
	CBootModeObj *pThis = (CBootModeObj *)lpParam;
	return pThis->BMThreadFunc();
}

void * CBootModeObj::BMThreadFunc( )
{
	m_BMFileImpl.MoveFirst();
	char strLog[MAX_PATH] = {0};

	//add by hongliang.xin 2009-3-2
	UINT varTimes;
	ohObject.GetProperty(0,_T("CheckNVTimes"),&varTimes);
	UINT nCheckNVTimes = varTimes;	// check nv and redownload times
	UINT nReadNVCount = 0; // checked nv times, begin to check NV after downloaded all files
	BOOL bCheckNVSuccess = TRUE; // check nv success flag


	while( !m_bExitThread )
	{
		//if( m_BMFileImpl.GetCurFileIndex() == 0)
		//	m_OprDriver.OnBegin();

		if( m_BMFileImpl.GetCurFileIndex() == 0 &&
		    !GenerateStartNotification( m_dwOprCookie, 1 ) )
		{
			Log( _T("Fail at start notification.") );
			EndProc( FALSE );
			continue;
		}

		BMFileInfo* pFileInfo = m_BMFileImpl.GetCurrentBMFileInfo();

		

		if( !GenerateStartFileOprNotification( m_dwOprCookie, pFileInfo->szFileID,pFileInfo->szFileType) )
		{
			GenerateEndFileOprNotification( m_dwOprCookie, pFileInfo->szFileID,pFileInfo->szFileType ,FALSE);
			sprintf(strLog, _T("Fail at start [ID:%s] %s  file notification"),pFileInfo->szFileID,pFileInfo->szFileType );
			Log( strLog );
			EndProc( FALSE );
			continue;
		}
		std::vector<std::string> aryKeyAndData;
		if( !ohObject.GetFileOperations( pFileInfo->szFileType,aryKeyAndData ) )
		{
			sprintf(strLog,_T("Can not read file operations for file type %s "), pFileInfo->szFileType );
			Log( strLog );
			EndProc( FALSE );
			continue;
		}
		DWORD dwMaxLength = ohObject.GetPacketLength( pFileInfo->szFileType );
		if( 
			strcasecmp(pFileInfo->szFileType,_T("PAGE")) == 0       ||
			strcasecmp(pFileInfo->szFileType,_T("PAGE_OOB")) == 0
		    )
		{
			DWORD dwMax = m_BMFileImpl.GetCurMaxLength();
			if(dwMax != 0 && dwMaxLength <= 24)
			{
				dwMaxLength *= dwMax;
			}
		}
		//printf( "\nBMThreadFunc dwMaxLength=0x%x\n", dwMaxLength );

		m_BMFileImpl.SetCurMaxLength( dwMaxLength );

		BOOL result = TRUE;
		BOOL bIsCheckNV = FALSE;

		if(strcasecmp(pFileInfo->szFileType,_T("CHECK_NV")) == 0)
		{
			bIsCheckNV = TRUE;
			nReadNVCount = 0;
			bCheckNVSuccess = TRUE;
		}

		int i = 0;

		for( i = 0; i < aryKeyAndData.size(); i++ )
		{

			sprintf(strLog,_T("[%s]step%d: %s "),pFileInfo->szFileID, i+1,aryKeyAndData[i].c_str());
			Log( strLog );
			if(bIsCheckNV)
			{
				if(nCheckNVTimes == 0) {result = TRUE; break;}
				if(0 == i) {bCheckNVSuccess = TRUE; nReadNVCount++;}
			}
			std::string strName = aryKeyAndData[i];
		       int dispid;
			dispid = m_OprDriver.GetIDsOfNames( strName.c_str() );
		        if( dispid == -1 )
		        {
				sprintf(strLog, _T("%s---%s operation is not implemented"),pFileInfo->szFileType, aryKeyAndData[i].c_str());
				Log( strLog );
				continue;
		        }

			if( !GenerateStartOprNotification( m_dwOprCookie,pFileInfo->szFileID,
			    	pFileInfo->szFileType, aryKeyAndData[i].c_str() ) )
			{
				GenerateEndOprNotification( m_dwOprCookie, pFileInfo->szFileID,
				pFileInfo->szFileType, aryKeyAndData[i].c_str() , FALSE ) ;
				sprintf(strLog, _T("Fail at start [ID:%s]%s---%s operation"),
				pFileInfo->szFileID, pFileInfo->szFileType, aryKeyAndData[i].c_str() );
				Log( strLog );
				break;
			}

			result = m_OprDriver.Invoke( dispid, (void *)pFileInfo );
			sprintf(strLog,_T("[%s]step%d: ret=%d "),pFileInfo->szFileID, i+1,result);
			Log( strLog );

			if( !GenerateEndOprNotification( m_dwOprCookie,pFileInfo->szFileID,pFileInfo->szFileType, aryKeyAndData[i].c_str() , result ) )
			{
				sprintf(strLog, _T("Fail at end %s---%s operation"),pFileInfo->szFileType, aryKeyAndData[i].c_str() );
				Log( strLog );

				if(0 == i && bIsCheckNV) //read flash and check NV failed
				{
					bCheckNVSuccess = FALSE;
					sprintf(strLog, _T("Check NV failed and download %s again"), pFileInfo->szFileID );
					Log( strLog );
				}
				else
				{
					break;
				}
			}

		        if( !result )
		        {
				sprintf(strLog, _T("Fail at %s---%s operation"),pFileInfo->szFileType, aryKeyAndData[i].c_str()  );
				Log( strLog );

				if( bIsCheckNV && (nReadNVCount <= nCheckNVTimes))
				{
					// read or download NV failed
					// recheck and download again
					sprintf(strLog, _T("Recheck and download %s again"), pFileInfo->szFileID );
					Log( strLog );
					if( i == 2 ) //download
					{
						i = -2; // i= i+2;  turn back
					}
				}
				else
				{
					break;
				}
		        }
			else
			{
			    	/**
				 * @hongliang.xin 2009-3-2
				 * "i==0  && bCheckNVSuccess" means read NV and check successs
				 * notice: maybe uplevel need not backup NV, so callback always return S_OK
				 * so that there is no check action in uplevel actually
				 */
				if(bIsCheckNV)
				{
					if (0 == i && bCheckNVSuccess)
					{
						i=aryKeyAndData.size(); // set NV BMFiles process over
						sprintf(strLog, _T("Check %s success"), pFileInfo->szFileID );
						Log( strLog );
						break; //check success, end the rest process
					}

					if( 1 == i && (nReadNVCount <= nCheckNVTimes) )
					{
						i = -1; // i= i+2;  turn back
					}

				}//else bCheckNVSuccess == false, download again
			}

	    	}

		BOOL bSuccessful = TRUE;
		if( i < aryKeyAndData.size())
		{
			bSuccessful = FALSE;
		}

		if( !GenerateEndFileOprNotification( m_dwOprCookie, pFileInfo->szFileID,pFileInfo->szFileType, bSuccessful )  )
		{
			sprintf(strLog, _T("Fail at end %s file notification"),pFileInfo->szFileType );
			Log( strLog );
			EndProc( FALSE );
			continue;
		}

		if( !bSuccessful )
		{
			EndProc( FALSE );
			continue;
		}

		if( ohObject.IsEnablePortSecondEnum() && 
			_tcsicmp(pFileInfo->szFileID,_T("FDLA")) == 0 &&
			_tcsicmp(pFileInfo->szFileType,_T("FDL1")) == 0)
		{
			EndProc( TRUE );
			continue;
		}
		m_BMFileImpl.MoveNext();
		if( m_BMFileImpl.IsEOF() )
		{
			// All file have been downloaded
			EndProc( TRUE );
		}
	}
	return 0L;
}

void CBootModeObj::Log( LPCTSTR lpszLog )
{
    m_OprDriver.Log( lpszLog );
}

STDMETHODIMP CBootModeObj::StartBootModeOperation(   void* lpBMFileInfo,
                                                     UINT uFileCount,
                                                     void* pOpenArgument,
                                                     BOOL bBigEndian,
                                                     DWORD dwOprCookie,
                                                     void* pReceiver)
{
    m_dwOprCookie = dwOprCookie;

    BOOL result = m_OprDriver.Initialize( pOpenArgument,
                                          bBigEndian,
                                          dwOprCookie,
                                          pReceiver);

    if( !result )
    {
        //GenerateStartNotification( m_dwOprCookie, 0 );
        Log( _T("The channel occurs error. ") );
        return BM_E_CHANNEL_FAILED;
    }

	if(!m_BMFileImpl.InitBMFiles( (PBMFileInfo)lpBMFileInfo,uFileCount))
    {
        //GenerateStartNotification( m_dwOprCookie, 0 );
		Log(m_BMFileImpl.GetLastErrMsg());
        Log( _T("Load files failed. ") );
        return BM_E_FILEINFO_ERROR;
    }


    if(!CreateBMThread( ))
    {
        GenerateStartNotification( m_dwOprCookie, 0 );
        Log( _T("Create download  thread fail. ") );
		m_OprDriver.Uninitialize();
        m_BMFileImpl.ClearUpBMFiles();
        return BM_E_CREATETHREAD_FAILED;
    }

    Log( _T("Start Boot Mode Operation success.") );
    return BM_S_OK;
}

STDMETHODIMP CBootModeObj::StopBootModeOperation()
{
	DestroyBMThread();

	Log( _T("Stop Boot Mode Operation") );

	m_OprDriver.Uninitialize();

	m_BMFileImpl.ClearUpBMFiles();

	//    SAFE_FREE(m_pOprDriver);

	return BM_S_OK;
}

STDMETHODIMP CBootModeObj::SetWaitTimeForNextChip( DWORD dwWaitTime /* = CHANGE_CHIP_TIMEOUT  */)
{
    m_dwWaitTime = dwWaitTime ;

    return BM_S_OK;
}

STDMETHODIMP CBootModeObj::SetCommunicateChannelPtr( LPVOID pCommunicateChannel  )
{
	m_OprDriver.SetChannel((ICommChannel*)pCommunicateChannel);
    return BM_S_OK;
}

STDMETHODIMP CBootModeObj::GetCommunicateChannelPtr( LPVOID* ppCommunicateChannel )
{
    ICommChannel *pChannel = m_OprDriver.GetChannelPtr();
    *ppCommunicateChannel = (LPVOID)pChannel;

    if( pChannel ==  NULL )
    {
        return BM_E_FAILED;
    }
    return BM_S_OK ;
}

STDMETHODIMP CBootModeObj::SubscribeOperationObserver(IBMOprObserver* pSink,
                                                      ULONG uFlags,
                                                      DWORD* lpdwCookie )
{
    pthread_mutex_lock(&m_CS);
    DWORD dwCookie = m_dwNextObserverCookie;
    IBMOprObserver* p = NULL;
    std::map<DWORD,IBMOprObserver*>::iterator it;
    do{
        p = NULL;
        it = m_mapObserverRegs.find( dwCookie);
        if( it ==  m_mapObserverRegs.end())
            break;
        p = it->second;
        dwCookie++;
        if( dwCookie == 0 )
            dwCookie++;
    }while( dwCookie != m_dwNextObserverCookie );

    if( p != NULL )
    {
        Log( _T("Subscribe Operation Observer fail."));
        pthread_mutex_unlock(&m_CS);
        return BM_E_REG_OBSERVER_FAILED;
    }

    m_mapObserverRegs[dwCookie] = pSink;

    m_dwNextObserverCookie = dwCookie + 1;
    if( m_dwNextObserverCookie == 0 )
        m_dwNextObserverCookie++;

    *lpdwCookie = dwCookie;
    Log( _T("Subscribe Operation Observer success."));
    pthread_mutex_unlock(&m_CS);

    return BM_S_OK;
}

STDMETHODIMP CBootModeObj::UnsubscribeOperationObserver( DWORD dwCookie )
{
	pthread_mutex_lock( &m_CS);

	IBMOprObserver* pObserver = NULL;

	std::map<DWORD,IBMOprObserver*>::iterator it;

	it = m_mapObserverRegs.find( dwCookie);

	if( it ==  m_mapObserverRegs.end())
	{
	    pthread_mutex_unlock( &m_CS);
	    return BM_E_FAILED;
	}


	m_mapObserverRegs.erase(it);
	/*  can not invoke log, maybe some object is not created */
	//  Log( _T("Unsubscribe Operation Observer."));
	pthread_mutex_unlock( &m_CS);
	return BM_S_OK;
}

STDMETHODIMP_(const LPBYTE) CBootModeObj::GetReadBuffer(  )
{
    void* rlt = m_OprDriver.GetRecvBuffer();
    return (const LPBYTE)rlt;
}

STDMETHODIMP_( DWORD) CBootModeObj::GetReadBufferSize(  )
{
    long dwSize = m_OprDriver.GetRecvBufferSize();
    return dwSize;
}

STDMETHODIMP_(void) CBootModeObj::EnablePortSecondEnum(BOOL bEnable)
{
	m_OprDriver.EnablePortSecondEnum(bEnable);
}


