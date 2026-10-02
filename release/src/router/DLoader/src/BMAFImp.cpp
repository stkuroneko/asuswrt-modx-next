// BMAFImp.cpp: implementation of the CBMAFImp class.
//
//////////////////////////////////////////////////////////////////////
#pragma warning(push,3)
#include <vector>
#include <algorithm>
#pragma warning(pop)

#include "BMAFImp.h"
#include "XmlConfigParse.h"
#include "BMFile.h"
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mman.h>
#include "ExePathHelper.h"
extern "C"
{
   #include "confile.h"
}


#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

/////////////////////////////////////////////////////
/////////////////////////////////////////////////////
/*
static BOOL GetAbsolutePath(CString &strAbsoluteFilePath,LPCTSTR lpszFilePath )
{
    TCHAR szFileName[_MAX_FNAME];
    TCHAR szDir[_MAX_DIR];
    TCHAR szDirve[_MAX_DRIVE];

    _tsplitpath( lpszFilePath,szDirve,NULL,NULL,NULL);
    if( szDirve[0] == _T('\0') )
    {//do it if strHelpTopic is ralatively
        GetModuleFileName( AfxGetApp()->m_hInstance, szFileName,_MAX_FNAME);
        _tsplitpath( szFileName , szDirve , szDir , NULL , NULL );
        strAbsoluteFilePath = szDirve;
        strAbsoluteFilePath += szDir;
        if( lpszFilePath[0] == _T('\\') || lpszFilePath[0] == _T('/') )
            lpszFilePath++;

        strAbsoluteFilePath += lpszFilePath;
    }
    else
    {
        strAbsoluteFilePath = lpszFilePath;
    }
    return true;
}
*/
//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CBMAFImp::CBMAFImp()
{
	m_nFileCount = 0 ;
	m_nBMFileCount = 0;
	m_arrBMFileInfo.clear();
	m_bInitBMFiles = FALSE;

	m_dwWaitTime = 0;
	m_dwRepartitionFlag = 1;
	m_bLog = HasLog();
	m_strSpecConfig = _T("");

	m_dwReadFlashBRFlag = 0;

	m_strFileType = _T("");

	m_dwPacketLength = 0x1000;

	m_arrBMFileInfoEx.clear();
	m_bEnablePortSecondEnum = FALSE;
	m_bPowerOff = FALSE;

	if(m_bLog)
	{
	    m_bLog = StartLog();
	}
}

CBMAFImp::~CBMAFImp()
{
    BMAF_StopAllWork();
}
/**
 * stop one port work
 *
 * @param lpszProductName: the product name;
 * @param ppszFileList: the download files;
 * @param dwFileCount: the number of download files;
 * @param pOpenArgument: the download channel(port) param;
 * @param bBigEndian: if bigendian;
 * @param dwOprCookie: the port identify;
 * @param bRcvThread:
 * @param pReceiver:
 * @param lpbstrProgID:
 *
 * @return Returns S_OK if successful,Otherwise returns error code;
 */
HRESULT CBMAFImp::BMAF_StartOneWork(LPCTSTR lpszProductName,
                                    LPCTSTR *ppszFileList,
                                    DWORD  dwFileCount,
                                    void*  pOpenArgument,
                                    BOOL bBigEndian,
                                    DWORD dwOprCookie,
                                    void* pReceiver)
{
/*  if(m_bLog && !m_log.IsOpenLog())
    {
        if(!StartLog())
            return BMAF_E_STRART_LOG_FAIL;
    }
*/
    if(!RegBootModeObj(dwOprCookie))
        return BMAF_E_REG_BMOBJ_FAIL;

    if(!RegBMPObserver(dwOprCookie))
        return BMAF_E_REG_BMPOBSERVER_FAIL;

    if(!m_bInitBMFiles)
    {
        m_strProductName = lpszProductName;
        m_arrFile.clear();

        for(UINT i= 0;i< dwFileCount;i++)
            m_arrFile.push_back(ppszFileList[i]);

        m_nFileCount = (UINT) dwFileCount;

        if(!InitBMFiles(dwOprCookie))
          return BMAF_E_INIT_BMFILES_FAIL;
        m_bInitBMFiles = TRUE;
    }

    if(m_nBMFileCount == 0)
        return BM_S_OK;

    return StartOneWork(bBigEndian,
                        pOpenArgument,
                        dwOprCookie,
                        pReceiver );



}

/**
 * stop all port work
 *
 * @return Returns S_OK if successful,Otherwise returns S_FAIL;
 */
HRESULT CBMAFImp::BMAF_StopAllWork()
{

    std::map<DWORD,_BOOTMODEOBJ_T * >::iterator it;

    it = m_mapBootModeObj.begin();
    DWORD dwCookie = 0;
    PBOOTMODEOBJ_T  pStruct = NULL;
    for(;it!=m_mapBootModeObj.end();it++)
    {
        dwCookie = it->first;
        pStruct = it->second;
        pStruct->pSnapin->StopBootModeOperation();
        pStruct->pSnapin->UnsubscribeOperationObserver( pStruct->dwCookie );

        delete pStruct;
    }

    m_mapBootModeObj.clear();
    ClearBMFiles();

    m_arrFile.clear();
    m_nFileCount =0;

    int nCount = m_arrFileInfo.size();
    for(int i=0;i<nCount;i++)
    {
        //Modified by wei.zhang to match the new and delete
        delete  m_arrFileInfo[i];
    }
    m_arrFileInfo.clear();


    m_bInitBMFiles = FALSE;

    StopLog();

    return BM_S_OK;
}

/**
 * stop one port work
 *
 * @param dwOprCookie: the port identify;
 *
 * @return Returns S_OK if successful,Otherwise returns S_FAIL;
 */
HRESULT CBMAFImp::BMAF_StopOneWork( DWORD dwOprCookie )
{
    PBOOTMODEOBJ_T pBMO = NULL;
    HRESULT hr;
    hr = BMAF_GetBootModeObjInfo(dwOprCookie,(void**)&pBMO);
    if(FAILED(hr))
        return hr;

    if( !pBMO->bStop )
    {
		pBMO->pSnapin->StopBootModeOperation();
		pBMO->pSnapin->UnsubscribeOperationObserver( pBMO->dwCookie );
		pBMO->bStop = TRUE;
    }
    return BM_S_OK;
}

/**
 * Get struct BOOTMODEOBJ_T information
 *
 * @param dwOprCookie: the port identify;
 * @param ppBootModeObjT: the pointer of struct BOOTMODEOBJ_T
 *
 * @return Returns S_OK if successful,Otherwise returns S_FAIL;
 */
HRESULT CBMAFImp::BMAF_GetBootModeObjInfo(DWORD dwOprCookie, void** ppBootModeObjT)
{
    PBOOTMODEOBJ_T pBMO = NULL;
    std::map<DWORD,_BOOTMODEOBJ_T * >::iterator  it;
    it = m_mapBootModeObj.find(dwOprCookie);

    if(it != m_mapBootModeObj.end())
        *ppBootModeObjT = (void*)(it->second);
    else
        *ppBootModeObjT = 0;

    return BM_S_OK;
}


/**
 * Subscribe Callback observer
 *
 * @param dwOprCookie: the port identify;
 * @param pSink: pointer of IBMOprObserver;
 * @param uFlags: not used for extent future;
 *
 * @return Returns S_OK ;
 */
HRESULT CBMAFImp::BMAF_SubscribeObserver(DWORD dwOprCookie,
                                        IBMOprObserver* pSink,
                                        ULONG uFlags)

{
    UNUSED_ALWAYS(uFlags);

    //pthread_mutex_lock( &m_CS);

    IBMOprObserver* pBMOprObs = NULL;
    std::map< DWORD,IBMOprObserver*>::iterator it;
    it = m_mapObserverRegs.find(dwOprCookie);

    if( it != m_mapObserverRegs.end())
    {
        //pthread_mutex_unlock( &m_CS);
        return BM_S_OK;   // already subscribe
    }

    m_mapObserverRegs[dwOprCookie] = pSink;

    //pthread_mutex_unlock( &m_CS);

    if(m_bLog && !m_log.IsOpen())
        StartLog();
    if(m_bLog && m_log.IsOpen())
    {
        m_log.LogFmtStr(SPLOGLV_INFO,_T("[PORT:%d] Subscribe Operation Observer succeed."),dwOprCookie);
    }
    return BM_S_OK;
}
/**
 * Unsubscribe Callback observer
 *
 * @param dwOprCookie: the port identify;
 *
 * @return Returns S_OK;
 */
HRESULT CBMAFImp::BMAF_UnsubscribeObserver(DWORD dwOprCookie)
{
    //pthread_mutex_lock( &m_CS);

    std::map< DWORD,IBMOprObserver*>::iterator it;
    it = m_mapObserverRegs.find(dwOprCookie);

    if( it == m_mapObserverRegs.end() )
    {
        //pthread_mutex_unlock( &m_CS);
        return BM_E_FAILED;
    }

    m_mapObserverRegs.erase( it );

    //pthread_mutex_unlock( &m_CS);
    //Log( "Unsubscribe Operation Observer.");
    return BM_S_OK;
}
/**
 * Set property for download
 *
 * @param dwPropertyID: the property identify;
 * @param dwPropertyValue: the property value;
 *
 * @return Returns S_OK if successful,Otherwise returns S_FALSE;
 */
HRESULT CBMAFImp::BMAF_SetProperty(DWORD dwPropertyID, void* dwPropertyValue)
{
	switch(dwPropertyID)
	{
		case BMAF_TIME_WAIT_FOR_NEXT_CHIP:
			m_dwWaitTime = *(DWORD*)dwPropertyValue;
			break;
		case BMAF_NAND_REPARTION_FLAG:
			m_dwRepartitionFlag = *(DWORD*)dwPropertyValue;
			break;
		case BMAF_SPECIAL_CONFIG_FILE:
			m_strSpecConfig = (char*)dwPropertyValue;
			break;
		case BMAF_READ_FLASH_BEFORE_REPARTITION:
			m_dwReadFlashBRFlag = *(DWORD*)dwPropertyValue;
			break;
		case BMAF_SPEC_FILE_TYPE:
			m_strFileType  = (char*)dwPropertyValue;
			break;
		case BMAF_ENABLE_PORT_SECOND_ENUM:
			m_bEnablePortSecondEnum = *(BOOL*)dwPropertyValue;
			break;
		case BMAF_POWER_OFF_DEVICE:
			m_bPowerOff = *(BOOL*)dwPropertyValue;
		default:
			return BM_S_FALSE;
			break;
	}

	return BM_S_OK;
}
/**
 * Get property for download
 *
 * @param dwPropertyID: the property identify;
 * @param dwPropertyValue: the property value to store;
 *
 * @return Returns S_OK if successful,Otherwise returns S_FALSE;
 */
HRESULT CBMAFImp::BMAF_GetProperty(DWORD dwPropertyID, void** lpdwPropertyValue)
{
    switch(dwPropertyID) {
    case BMAF_TIME_WAIT_FOR_NEXT_CHIP:
        *lpdwPropertyValue = (void*)&m_dwWaitTime;
        break;
    case BMAF_NAND_REPARTION_FLAG:
        *lpdwPropertyValue = (void*)&m_dwRepartitionFlag;
        break;
    case BMAF_SPECIAL_CONFIG_FILE:
        *lpdwPropertyValue = (void*)m_strSpecConfig.c_str();
        break;
    case BMAF_READ_FLASH_BEFORE_REPARTITION:
        *lpdwPropertyValue = (void*)&m_dwReadFlashBRFlag;
        break;
    case BMAF_SPEC_PACKET_LENGTH:
        *lpdwPropertyValue = (void*)&m_dwPacketLength;
        break;
    default:
        return BM_S_FALSE;
        break;
    }

    return BM_S_OK;
}
/**
 * Set Communicate channel pointer
 *
 * @param dwOprCookie: the port identify;
 * @param pCommunicateChannel: Communicate channel pointer;
 *
 * @return Returns S_OK if successful,Otherwise returns S_FALSE;
 */
HRESULT CBMAFImp::BMAF_SetCommunicateChannelPtr(DWORD dwOprCookie,
                                                LPVOID pCommunicateChannel )
{
    PBOOTMODEOBJ_T pBMO = NULL;
    BMAF_GetBootModeObjInfo(dwOprCookie,(void**)&pBMO);
    if(NULL == pBMO)
        return BM_S_FALSE;
    return pBMO->pSnapin->SetCommunicateChannelPtr(pCommunicateChannel);
}
/**
 * Get Communicate channel pointer
 *
 * @param dwOprCookie: the port identify;
 * @param pCommunicateChannel: Communicate channel pointer;
 *
 * @return Returns S_OK if successful,Otherwise returns S_FALSE;
 */
HRESULT CBMAFImp::BMAF_GetCommunicateChannelPtr(DWORD dwOprCookie,
                                                /*[out]*/LPVOID* ppCommunicateChannel )
{
    PBOOTMODEOBJ_T pBMO = NULL;
    BMAF_GetBootModeObjInfo(dwOprCookie,(void**)&pBMO);
    if(NULL == pBMO)
        return BM_S_FALSE;
    return pBMO->pSnapin->GetCommunicateChannelPtr(ppCommunicateChannel);
}
/**
 * Release this
 *
 * @return Returns S_OK;
 */
HRESULT CBMAFImp::BMAF_Release()
{
    delete this;
    return BM_S_OK;
}
/////////////////////////////////////////////////////

HRESULT CBMAFImp::StartOneWork(BOOL bBigEndian,
                         void* pPortArgument,
                         DWORD dwOprCookie,
                         void* pReceiver)
{
	HRESULT hr = 0;
	IBootModeHandler* pBootModehandler =m_pBootModeObj->pSnapin;

	// Set repartition flags,only used by nand flash
	pBootModehandler->SetRepartitionFlag( m_dwRepartitionFlag );

	pBootModehandler->SetReadFlashBefRepFlag( m_dwReadFlashBRFlag );

	pBootModehandler->SetProperty(0,_T("PRODUCT"), (void*)m_strProductName.c_str());

	pBootModehandler->SetProperty(0,_T("EnablePortSecondEnum"), (void*)&m_bEnablePortSecondEnum);
	pBootModehandler->SetProperty(0,_T("PowerOff"), (void*)&m_bPowerOff);

    if(m_strFileType.length())
    {
        m_dwPacketLength = pBootModehandler->GetPacketLength(m_strFileType.c_str()) ;
    }
    else
    {
        m_dwPacketLength = 0x1000;
    }


    BMFileInfo *pBMFileInfo = new BMFileInfo[m_nBMFileCount];
    if(pBMFileInfo == NULL)
        return BMAF_E_OUTOFMEMORY;
    memset(pBMFileInfo,0,m_nBMFileCount*sizeof(BMFileInfo));
    for(UINT i=0;i<m_nBMFileCount;i++)
    {
        memcpy(pBMFileInfo+i,m_arrBMFileInfo[i],sizeof(BMFileInfo));
    }

    hr = pBootModehandler->StartBootModeOperation( (void*)pBMFileInfo,
                                            (DWORD)m_nBMFileCount,
                                            pPortArgument,
                                            bBigEndian,
                                            dwOprCookie,
                                            pReceiver);

    if(SUCCEEDED( hr ))
    {
		pBootModehandler->SetWaitTimeForNextChip( m_dwWaitTime );
    }
    else
    {
		UnregBMPObserver(dwOprCookie);
    }

    delete []pBMFileInfo;

    if(m_pBootModeObj != NULL)
		m_pBootModeObj->bStop = FALSE;

    return hr;
}


//////////////////////////////////////////////
BOOL CBMAFImp::InitBMFiles(DWORD dwOprCookie)
{

    if(m_nFileCount == 0)
        return TRUE;

    if(m_strSpecConfig.length() == 0)
    {
        return FALSE;
    }

    CXmlConfigParse xcp;

    if(!xcp.Init(m_strSpecConfig.c_str(),1))
    {
        if(m_bLog)
        {
            m_log.LogRawStr(SPLOGLV_ERROR,_T("Read xml configure file failed!"));
        }
        return FALSE;
    }


    UINT nCount =0;
    UINT nRealCount = 0;
    UINT i=0;

    PFILE_INFO_T pFileInfo = NULL;
    PPRODUCT_INFO_T pProd = NULL;
    pProd = xcp.GetProdInfo(m_strProductName.c_str());
    if(pProd == NULL)
    {
        if(m_bLog)
        {
             m_log.LogRawStr(SPLOGLV_ERROR,_T("Not found product configure!"));
        }
        return FALSE;
    }

    BOOL bMultiFiles = FALSE;
    if(pProd->tChips.bEnable && pProd->tChips.dwCount != 0)
    {
        bMultiFiles = TRUE;
    }

    nCount = pProd->dwFileCount;
    for(i=0;i<nCount;i++)
    {
        pFileInfo = new FILE_INFO_T;
        memcpy(pFileInfo,pProd->pFileInfoArr + i,sizeof(FILE_INFO_T));
        if(pFileInfo->dwFlag != FILE_OMIT_FALG)
        {
            m_arrFileInfo.push_back(pFileInfo);
            ++nRealCount;
        }
        else
        {
            delete pFileInfo;
            pFileInfo = NULL;
        }
    }

    m_nBMFileCount = nRealCount;

    //输入的文件个数应该与配置文件的个数减去忽略的文件后的个数相同
    if(m_nFileCount != m_nBMFileCount )
    {
        if(m_bLog)
             m_log.LogRawStr(SPLOGLV_ERROR,_T("The number of input files not match the number of files in xml config minusing the omitting files"));
        return FALSE;
    }

    nCount =0;
    i=0;

    IBMOprObserver *pObserver = NULL;

    std::map< DWORD,IBMOprObserver*>::iterator it;
    it = m_mapObserverRegs.find(dwOprCookie);
    if(it != m_mapObserverRegs.end())
    {
        pObserver = it->second;
    }

    pFileInfo = NULL;
    BMFileInfo * pBMFileInfoArr = new BMFileInfo[MAX_RET_FILE_NUM];
    memset(pBMFileInfoArr,0,MAX_RET_FILE_NUM * sizeof(BMFileInfo));
    BMFileInfo * pBMFileInfo = NULL;
    DWORD dwBMFileInfoCount = 0;
    DWORD dwFlag = 0;

    BOOL bOK = TRUE;

    for( i = 0; i<m_nFileCount;i++)
    {
        pFileInfo = m_arrFileInfo[i];
        pBMFileInfo = NULL;
        memset(pBMFileInfoArr,0,MAX_RET_FILE_NUM * sizeof(BMFileInfo));
        dwBMFileInfoCount = 0;
        dwFlag = 0;
        //从GUI上忽略的文件
        if(strcasecmp(m_arrFile[i].c_str(),FILE_OMIT) == 0)
        {
            continue;
        }

        if(pObserver)
        {
            HRESULT hr = pObserver->OnFilePrepare(dwOprCookie,
                m_strProductName.c_str(),
                m_arrFile[i].c_str(),
                (void*)pFileInfo,
                (void*)pBMFileInfoArr,
                &dwBMFileInfoCount,
                &dwFlag);
            if(FAILED(hr))
            {
                if(m_bLog)
                    m_log.LogRawStr(SPLOGLV_ERROR,_T("OnFilePrepare: Failed"));
                bOK = FALSE;
                break;
            }
            if(dwFlag)  //回调已经处理，dwBMFileInfoCount 反映处理的情况
            {
                for(UINT j = 0; j<dwBMFileInfoCount; j++ )
                {
                    pBMFileInfo = new BMFileInfo;
                    memcpy(pBMFileInfo,pBMFileInfoArr+j,sizeof(BMFileInfo));
                    m_arrBMFileInfo.push_back(pBMFileInfo);
                    nCount++;
                    m_arrBMFileFlag.push_back(pBMFileInfo->bLoadCodeFromFile);
                }
            }
        }

        if(dwFlag == 0)
        {
            pBMFileInfo = new BMFileInfo;
            InitBMFileDefault(pBMFileInfo,i,bMultiFiles);
            m_arrBMFileInfo.push_back(pBMFileInfo);
            nCount++;
            m_arrBMFileFlag.push_back(pBMFileInfo->bLoadCodeFromFile);
        }
    }

    if(!bOK)
    {
        m_nBMFileCount = nCount;
        delete [] pBMFileInfoArr;
        ClearBMFiles();
        return bOK;
    }

    // do extend files
    {
        bOK = TRUE;
        pBMFileInfo = NULL;
        memset(pBMFileInfoArr,0,MAX_RET_FILE_NUM * sizeof(BMFileInfo));
        dwBMFileInfoCount = 0;
        dwFlag = 0;
        if(pObserver)
        {
            HRESULT hr = pObserver->OnFilePrepare(dwOprCookie,
                m_strProductName.c_str(),
                NULL,
                0,
                (void*)pBMFileInfoArr,
                &dwBMFileInfoCount,
                &dwFlag);
            if(FAILED(hr))
            {
                if(m_bLog)
                    m_log.LogRawStr(SPLOGLV_ERROR,_T("OnFilePrepare: Failed"));
                bOK = FALSE;
            }
            if(bOK && dwFlag)  //回调已经处理，dwBMFileInfoCount 反映处理的情况
            {
                for(UINT j = 0; j<dwBMFileInfoCount; j++ )
                {
                    pBMFileInfo = new BMFileInfo;
                    memcpy(pBMFileInfo,pBMFileInfoArr+j,sizeof(BMFileInfo));
                    m_arrBMFileInfo.push_back(pBMFileInfo);
                    nCount++;
                    m_arrBMFileFlag.push_back(pBMFileInfo->bLoadCodeFromFile);
                }
            }
        }
    }

    m_nBMFileCount = nCount;
    delete [] pBMFileInfoArr;

    if(!bOK)
    {
        ClearBMFiles();
        return bOK;
    }

    // Open file mapping objects
    for( i=0; i < m_nBMFileCount; i++)
    {
        pBMFileInfo = m_arrBMFileInfo[i];

        if( pBMFileInfo->bLoadCodeFromFile /*&& !pBMFileInfo->bChangeCode*/)
        {
            if(!LoadBMFileInfo( pBMFileInfo ) )
            {
                m_log.LogFmtStr(SPLOGLV_ERROR, _T("Load BMFile[%s] failed"),pBMFileInfo->szFileID);

                ClearBMFiles();

                return FALSE;
            }

            pBMFileInfo->bLoadCodeFromFile = FALSE;
        }

    }
    return TRUE;

}
void CBMAFImp::InitBMFileDefault(PBMFileInfo lpBMFileInfo, int nFileIndex, BOOL bMultiFiles /*= FALSE*/)
{
    FILE_INFO_T * pFileInfo = NULL;
    pFileInfo = m_arrFileInfo[nFileIndex];

    memset(lpBMFileInfo,0,sizeof(BMFileInfo));
    strcpy(lpBMFileInfo->szFileID,pFileInfo->szID);
    strcpy(lpBMFileInfo->szFileType,pFileInfo->szType);
    strcpy(lpBMFileInfo->szFileName,m_arrFile[nFileIndex].c_str());
    strcpy(lpBMFileInfo->szRepID,pFileInfo->arrBlock[0].szRepID);
    lpBMFileInfo->llBase = pFileInfo->arrBlock[0].llBase;

    if(pFileInfo->dwFlag == 0/*_tcsicmp( lpBMFileInfo->szFileID, _T("FLASH") )==0*/)
    {
        lpBMFileInfo->bLoadCodeFromFile = FALSE;
        lpBMFileInfo->llOprSize = pFileInfo->arrBlock[0].llSize;
    }
    else
    {
        lpBMFileInfo->bLoadCodeFromFile = TRUE;
        lpBMFileInfo->llCodeSize = pFileInfo->arrBlock[0].llSize;

        if(strcasecmp(pFileInfo->szID,_T("FDL")) != 0  && strcasecmp(pFileInfo->szID,_T("FDL2")) != 0)
        {
            if(bMultiFiles)
            {
                lpBMFileInfo->bChangeCode = TRUE;
            }
        }

        if(strncasecmp(pFileInfo->szID,_T("NV"),2) == 0)
        {
            lpBMFileInfo->bChangeCode = TRUE;
        }
    }
}

BOOL CBMAFImp::RegBootModeObj(DWORD dwOprCookie)
{
	HRESULT hr = 0;
	 std::map<DWORD,_BOOTMODEOBJ_T * >::iterator  it;
	it = m_mapBootModeObj.find(dwOprCookie);

	if(it != m_mapBootModeObj.end() && it->second)
	//if( m_mapBootModeObj.find(dwOprCookie) !=  m_mapBootModeObj.end())
	{
		m_pBootModeObj = it->second;
	    	m_pBootModeObj->bStop         	= TRUE;
	    	m_pBootModeObj->bFirstStart   	= FALSE;
	}
	else
	{
	    m_pBootModeObj = new BOOTMODEOBJ_T;
	    memset(m_pBootModeObj,0,sizeof(BOOTMODEOBJ_T));

	    IBootModeHandler * pBootModeHandler = NULL;
	    CreateBMObj(&pBootModeHandler);

	    m_pBootModeObj->pSnapin = pBootModeHandler;
	    m_pBootModeObj->bStop = FALSE;
	    m_pBootModeObj->dwCookie = 0; //没有注册Observer
	    m_pBootModeObj->bFirstStart = TRUE;

	    m_mapBootModeObj[dwOprCookie] = m_pBootModeObj;
	}
	if(m_bLog)
	{
	    m_log.LogFmtStr(SPLOGLV_INFO,_T("[PORT:%d] Register BootModeObj succeed."),dwOprCookie);
	}
	return TRUE;

}

BOOL CBMAFImp::UnregBootModeObj(DWORD dwOprCookie)
{

    std::map<DWORD,_BOOTMODEOBJ_T * >::iterator it;
    it = m_mapBootModeObj.find(dwOprCookie);
    if(  it ==m_mapBootModeObj.end() )
    {
        return FALSE;
    }
    m_pBootModeObj = it->second;
//Added by wei.zhang here to destroy the memory of boot mode object
    DestroyBMObj(&m_pBootModeObj->pSnapin);
    delete m_pBootModeObj;
    m_pBootModeObj = NULL;
    m_mapBootModeObj.erase( it);
    return TRUE;
}
BOOL CBMAFImp::RegBMPObserver(DWORD dwOprCookie)
{
    IBMOprObserver* pObserver=NULL;

    std::map<DWORD,IBMOprObserver*>::iterator it;
    it = m_mapObserverRegs.find(dwOprCookie);

    if(it == m_mapObserverRegs.end())
        return TRUE;

    pObserver = it->second;

    DWORD dwCookie = dwOprCookie;

    HRESULT hr = m_pBootModeObj->pSnapin->SubscribeOperationObserver( pObserver, NULL, &dwCookie );
    if(FAILED( hr ) )
    {
        if(m_bLog)
        {
            m_log.LogFmtStr(SPLOGLV_ERROR,_T("Subscribe operation observer failed.[ErrorCode:0x%08X]"),hr);
        }
        return FALSE;
    }
    PBOOTMODEOBJ_T pBootModeObj = NULL;
    std::map<DWORD,_BOOTMODEOBJ_T * >::iterator it2;
    it2 = m_mapBootModeObj.find(dwOprCookie);
    if(it2 != m_mapBootModeObj.end())
    {
        pBootModeObj = it2->second;
        pBootModeObj->dwCookie = dwCookie; //表明注册
    }


    return TRUE;

}
BOOL CBMAFImp::UnregBMPObserver(DWORD dwOprCookie)
{
	PBOOTMODEOBJ_T pBMO = NULL;
	if(FAILED(BMAF_GetBootModeObjInfo(dwOprCookie,(void**)&pBMO)))
		return FALSE;

	pBMO->pSnapin->UnsubscribeOperationObserver( pBMO->dwCookie );
	return TRUE;
}

BOOL CBMAFImp::StartLog( void )
{
    return m_log.Open("BMFrmame.log",SPLOGLV_VERBOSE);
}

void CBMAFImp::StopLog( void )
{
    m_log.Close();
}

BOOL CBMAFImp::LoadBMFileInfo(PBMFileInfo lpBMFileInfo)
{
	 if( lpBMFileInfo == NULL )
	    return FALSE;

	if( FALSE == lpBMFileInfo->bLoadCodeFromFile )
	{
	    return TRUE;
	}

	 if( strlen(lpBMFileInfo->szFileName) == 0)
	{
	    m_log.LogFmtStr(SPLOGLV_ERROR,_T("LoadBMFileInfo: BMFile [%s] is empty."),lpBMFileInfo->szFileID);
	    return FALSE;
	}
	 m_log.LogFmtStr(SPLOGLV_INFO,_T("Load %s : %s ."),lpBMFileInfo->szFileID,lpBMFileInfo->szFileName);

	int fd = -1;
	__int64 llFileSize = 0;   

	fd = open(lpBMFileInfo->szFileName,O_RDONLY|O_LARGEFILE,00777);

	if( fd == -1)
	{
	    m_log.LogFmtStr(SPLOGLV_ERROR,_T("LoadBMFileInfo: BMFile [%s] open failed, [ERR:0x%X]:\"%s\"."),
	             lpBMFileInfo->szFileName, errno, strerror(errno));
	    return FALSE;
	}

	//struct stat buf = {0};
	//fstat(fd,&buf);
	//dwSize = buf.st_size;

	llFileSize = lseek64(fd,0,SEEK_END);

	if( llFileSize == INVALID_FILE_SIZE)
	{
	    m_log.LogFmtStr(SPLOGLV_ERROR,_T("LoadBMFileInfo: GetFileSize [%s] failed, [ERR:0x%X]:\"%s\"."),
	             lpBMFileInfo->szFileName, errno,strerror(errno));
	    close(fd);
	    return FALSE;
	}

	 if ( -1 == lseek64(fd,0,SEEK_SET) )        
	 {            
	 	printf(_T("SetFilePointer to FILE_BEGIN fail,error code: %d,\"%s\"\n"),errno,strerror(errno));    
		close(fd);
		return FALSE;  
	}

	lpBMFileInfo->lpCode = NULL;

	DWORD dwMapSize = llFileSize;

	if( dwMapSize > MAX_MAP_SIZE )
	{
	    dwMapSize = MAX_MAP_SIZE;
	}

	lpBMFileInfo->dwFirstMapSize = dwMapSize;

	void* lpCode = mmap( NULL, dwMapSize, PROT_READ,MAP_SHARED, fd, 0);
	if( lpCode == NULL)
	{
	    m_log.LogFmtStr(SPLOGLV_ERROR,_T("LoadBMFileInfo: mmap [%s] failed, [ERR:0x%X]:\"%s\"."),
	             lpBMFileInfo->szFileName, errno,strerror(errno));
	    close(fd);
	    return FALSE;
	}

	lpBMFileInfo->llCodeSize = llFileSize;
      m_log.LogFmtStr(SPLOGLV_INFO,_T("LoadBMFileInfo [%s] bChangeCode=%d, ."),lpBMFileInfo->szFileID,lpBMFileInfo->bChangeCode );
	if ( lpBMFileInfo->llCodeSize >= 0x100000000 && NULL == strstr (lpBMFileInfo->szFileType,_T("_64")) )
	{
		strcat(lpBMFileInfo->szFileType,_T("_64"));
	}
	if( lpBMFileInfo->bChangeCode )
	{
		if(dwMapSize != llFileSize)
		{
			munmap( lpCode, llFileSize);
			lpCode = NULL;
			lpCode = mmap( NULL, dwMapSize, PROT_READ,MAP_SHARED, fd, llFileSize);
			if( lpCode == NULL)
			{
			    m_log.LogFmtStr(SPLOGLV_ERROR,_T("LoadBMFileInfo: mmap [%s] failed, [ERR:0x%X]:\"%s\"."),
			     lpBMFileInfo->szFileName, errno,strerror(errno));
			    close(fd);
			    return FALSE;
			}
		}

		lpBMFileInfo->lpCode = new BYTE[ llFileSize ];
		if(lpBMFileInfo->lpCode!= NULL)
		{
			memcpy( lpBMFileInfo->lpCode, lpCode, llFileSize);
		}
		munmap(lpCode,llFileSize);
		close(fd);

		if(lpBMFileInfo->lpCode == NULL)
		{
		    m_log.LogFmtStr(SPLOGLV_ERROR,_T("LoadBMFileInfo: memory is not enough."));
		    return FALSE;
		}
	}
	else
	{
		lpBMFileInfo->lpCode = lpCode;
		lpBMFileInfo->fdFile = fd;
	}

	return TRUE;
}

void CBMAFImp::UnloadBMFileInfo( PBMFileInfo lpBMFileInfo, BOOL bLoadByFrame )
{
	if( lpBMFileInfo == NULL )
	    return;

	if( bLoadByFrame)
	{
		if( lpBMFileInfo->bChangeCode )
		{
			if( lpBMFileInfo->lpCode != NULL )
			{
			    delete [](LPBYTE)lpBMFileInfo->lpCode;
			    //added by wei.zhang here to avoid memory leak
			    lpBMFileInfo->lpCode = NULL;
			}
		}
		else
		{
			if( lpBMFileInfo->lpCode != NULL )
			{
			    munmap(lpBMFileInfo->lpCode,lpBMFileInfo->dwFirstMapSize);
			}
			if( lpBMFileInfo->fdFile != -1 )
			{
			    close(lpBMFileInfo->fdFile);
			    lpBMFileInfo->fdFile = -1;
			}

		}
	}
}

void CBMAFImp::ClearBMFiles()
{
	UINT  nCount = m_arrBMFileInfo.size();
	for(UINT i = 0; i < nCount ; i++ )
	{
		UnloadBMFileInfo( m_arrBMFileInfo[i],m_arrBMFileFlag[i] );
		//modified by wei.zhang here to match the new and delete
		delete m_arrBMFileInfo[i];
		m_arrBMFileInfo[i] = NULL;
	}

	m_arrBMFileInfo.clear();
	m_nBMFileCount = 0;

	m_arrBMFileFlag.clear();
}
BOOL CBMAFImp::HasLog( void )
{
    INI_CONFIG *config;

    GetExePath helper;
    std::string strPath = helper.getExeDir();
    strPath += "BMTimeout.ini";
    strPath.insert(0,"/");
    config = ini_config_create_from_file(strPath.c_str(),0);
    if(config == NULL)
        return FALSE;

    int nRet = ini_config_get_int(config,_T("Log"),_T("EnableFrameLog"),0);
    ini_config_destroy(config);
    return nRet;
}

