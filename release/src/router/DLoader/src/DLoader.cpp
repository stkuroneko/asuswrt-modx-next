#include "DLoader.h"
#include "BMFile.h"
#include "Calibration.h"
#include "ExePathHelper.h"
#include "MasterImgGen.h"
#include "PhaseCheckBuild.h"
#include <stdarg.h>

#include <dirent.h>
#include <fcntl.h>
#include "XRandom.h"






extern "C"
{
   #include "confile.h"
}


#define NV_LENGTH      0x10000
#define OPR_SUCCESS     (0)
#define OPR_FAIL        (1)


IBMOprObserver::IBMOprObserver()
{

}
IBMOprObserver::~IBMOprObserver()
{

}

CDLoader::CDLoader()
{
	m_pMasterImg 		= NULL;
	m_bEnd 			= FALSE;
	m_pPartitionData 	= NULL;
	m_dwPartitionSize 	= 0;
	m_pExtTblData 		= NULL;
	m_dwExtTblSize 		= 0;
	m_nSNLength		= 14;
	m_bDual_SN			= FALSE;
	m_bPortSecondEnum    = FALSE;
	m_bPacHasKey		= FALSE;
	m_bDownloadPass        = FALSE;
	m_nEnumPortTimeOut   = 5000;
	m_nReplacePolicy		= 0;
	m_nBackupProdnvMiscdata = 0;
	m_mapMultiNVInfo.clear();
	LoadConfigFile();
}
PORT_DATA* CDLoader::CreatePortData( DWORD dwPort )
{
	PORT_DATA * pPortData = NULL;
	MAP_PORT_DATA::iterator it;
	
	it = m_mapPortData.find(dwPort);
	if( it != m_mapPortData.end() )
	{
		pPortData = it->second;
		pPortData->Clear();
	}
	else
	{
		pPortData = new PORT_DATA;
		m_mapPortData[dwPort] = pPortData;
	}
	
	return pPortData;
}
PORT_DATA * CDLoader::GetPortDataByPort(DWORD dwPort)
{

	PORT_DATA * pPortData = NULL;
	MAP_PORT_DATA::iterator it;
	
	it = m_mapPortData.find(dwPort);
	if( it != m_mapPortData.end() )
	{
		pPortData = it->second;
	}
	return pPortData;
}
BOOL CDLoader::AcquireBarcode(DWORD dwPort)
{
	BOOL bRet 				= FALSE;
	PORT_DATA * pPortData 	= NULL;

	
	do
	{
		pPortData = CreatePortData( dwPort );	
		if(NULL == pPortData)						break;

		int nSize = PRODUCTION_INFO_SIZE;
		if(NULL == pPortData->lpPhaseCheck)
		{
			pPortData->lpPhaseCheck = new BYTE[nSize];
		}
		if(NULL == pPortData->lpPhaseCheck)		break;

		memset(pPortData->lpPhaseCheck,0xFF,nSize);
		CXRandom 			m_cRandom;
		string 				strSN;
		CPhaseCheckBuild 	ccb;
		if(m_strInputSN.empty())
		{
			strSN = m_cRandom.GetRandomNumbers(m_nSNLength);
		}
		else
		{	
			strSN = m_strInputSN;
		}
		sprintf(pPortData->szSN,_T("%s"),strSN.c_str());
		
		if(m_bDual_SN )
		{
			string 	strSN2;
			strSN2 = m_cRandom.GetRandomNumbers(m_nSNLength);
			bRet = ccb.Cnst8KBuffer(strSN.c_str(), pPortData->lpPhaseCheck, nSize, strSN2.c_str());
		}
		else
		{
			bRet = ccb.Cnst8KBuffer(strSN.c_str(), pPortData->lpPhaseCheck, nSize);
		}
		
		//printf("\nSN=%s",strSN.c_str());
		
	}while(0);
	return bRet;
}
void CDLoader::LoadConfigFile()
{

	INI_CONFIG *config 	= NULL;
	GetExePath helper;
	std::string strIniPath = helper.getExeDir();
	strIniPath.insert(0,"/");
	strIniPath += "DLoader.ini";

	config = ini_config_create_from_file(strIniPath.c_str(),0);
	if (NULL == config)
	{
		return ;
	}
	m_nSNLength = ini_config_get_int(config,_T("SN"), _T("SN_LENGTH"), 14);
	m_bDual_SN  = (BOOL)ini_config_get_int(config,_T("SN"), _T("Dual_SN"), 0);
	m_nEnumPortTimeOut = ini_config_get_int(config,_T("SecondEnumPort"), _T("EnumPortTimeOut"), 5000);

	m_strDlDev = ini_config_get_string(config,_T("Device"),_T("DLDev"),_T("/dev/ttyUSB"));

	m_strEntryModeCmd = ini_config_get_string(config,_T("EntryMode"),_T("EntryCmd"),_T("./adb shell reboot autodloader"));

	m_nReplacePolicy = ini_config_get_int(config,_T("ReplaceDLFile"), _T("ReplacePolicy"), 0);
	m_nBackupProdnvMiscdata =  ini_config_get_int(config,_T("Options"), _T("BackupProdnvMiscData"), 0);
	ini_config_destroy(config);
}
CDLoader::~CDLoader()
{
	//dtor
	SAFE_DELETE_ARRAY(m_pMasterImg);
	//SAFE_DELETE_ARRAY(m_pNVFileBuf);
	//m_dwNVFileSize = 0;

	ClearNVBuffer();
	ClearMultiNVMap();

	MAP_BMPOBJ::iterator itObj;
	for(itObj = m_mapBMObj.begin();itObj !=m_mapBMObj.end(); itObj++ )
	{
	    _BMOBJ* p = itObj->second;
	    if(p)
	    {
	        p->Clear();
	        delete p;
	    }
	}
	m_mapBMObj.clear();

	MAP_PORT_DATA::iterator itPortData;
	for(itPortData = m_mapPortData.begin();itPortData !=m_mapPortData.end(); itPortData++ )
	{
		PORT_DATA* p = itPortData->second;
		if(p)
		{
			p->Clear();
		}
	}
	m_mapPortData.clear();

	SAFE_DELETE_ARRAY(m_pPartitionData);
	SAFE_DELETE_ARRAY(m_pExtTblData);
}

STDMETHODIMP(CDLoader::OnStart)(  DWORD dwOprCookie,
                     DWORD dwResult )
{
	m_ProcMonitor.OnMessage(BM_BEGIN,dwOprCookie, 0);
	if(m_Settings.IsNeedPhaseCheck())
	{
		if (!AcquireBarcode(dwOprCookie) )
		{
			_BMOBJ * pbj = NULL;

			MAP_BMPOBJ::iterator it;

			it = m_mapBMObj.find(dwOprCookie);
			if( it == m_mapBMObj.end()  ||  (pbj = it->second)== NULL )
			{
			    	return BM_S_FALSE;
			}

			sprintf(pbj->szErrorMsg,_T("AcquireBarcode fail!"));
			return BM_S_FALSE;
		}
	}
	return BM_S_OK;
}
STDMETHODIMP(CDLoader::OnEnd)(  DWORD dwOprCookie,
                   DWORD dwResult )
{
	_BMOBJ * pbj = NULL;
	MAP_BMPOBJ::iterator it;

	it = m_mapBMObj.find(dwOprCookie);
	if( it == m_mapBMObj.end()  ||  (pbj = it->second)== NULL )
	{
		return BM_S_FALSE;
	}

	BOOL bSucceed = TRUE;

	LPARAM lParam = NULL;
	if( dwResult != OPR_SUCCESS )
	{
		bSucceed = FALSE;
		lParam = (LPARAM)(LPCTSTR)pbj->szErrorMsg;
	}
	m_bDownloadPass = bSucceed;
	
	if (bSucceed  &&  1 == pbj->nStage)
	{
		//printf("\nSecond enum port,  Waiting...");
	}
	else
	{
		m_ProcMonitor.OnMessage(BM_END,dwOprCookie, lParam);
	}

    /*PBOOTMODEOBJ_T pStruct = NULL;
	m_BMAF.BMAF_GetBootModeObjInfo(dwOprCookie,(void**)&pStruct);
	if (pStruct)
	{
		//pStruct->pSnapin->StopBootModeOperation();
		//pStruct->pSnapin->UnsubscribeOperationObserver(pStruct->dwCookie );
		pStruct->bStop = TRUE;
    }*/
	m_bEnd = TRUE;

	return BM_S_OK;
}
STDMETHODIMP(CDLoader::OnOperationStart)(  DWORD dwOprCookie,
                              const char* cbstrFileID,
                              const char* cbstrFileType,
                              const char* cbstrOperationType,
                              void * pBMFileInterface )
{
	_BMOBJ * pbj = NULL;

	MAP_BMPOBJ::iterator it;

	it = m_mapBMObj.find(dwOprCookie);
	if( it == m_mapBMObj.end()  ||  (pbj = it->second)== NULL )
	{
	    return BM_S_FALSE;
	}

	if( 
		strncasecmp( cbstrFileID, _T("_BKF_"), 5) == 0						&&
		
	      (
	             (  
		             	strcasecmp( cbstrFileType, _T("ReadFlash") ) == 0 		&& 
		             	strcasecmp( cbstrOperationType,_T("ReadFlash")) == 0 
	             )
	             || 
	             ( 
	         		strcasecmp( cbstrFileType, _T("ReadFlash2")) == 0 		&&
	         		strcasecmp( cbstrOperationType,_T("ReadFlashByID")) == 0
	         	)
	       ) 
	 )
	{
		std::string strID = cbstrFileID+5;
		PFILE_INFO_T pFileInfo = NULL;
		if(m_Settings.GetFileInfo(strID.c_str(),(void**)&pFileInfo) == -1)
		{
			sprintf(pbj->szErrorMsg,_T("Can not find %s!"), strID.c_str());
			return BM_S_FALSE;
		}

		BOOTMODEOBJ_T *pBMO = NULL;
		m_BMAF.BMAF_GetBootModeObjInfo(dwOprCookie, (void**)&pBMO);
		DWORD dwPacketLen =pBMO->pSnapin->GetPacketLength(pFileInfo->szType);
		if(dwPacketLen == 0)
		{
		 	dwPacketLen = 0x1000;
		}

		IBMFile* pBMFile = (IBMFile*)pBMFileInterface;
		pBMFile->SetCurMaxLength(dwPacketLen);
	}


	if(  strcasecmp( cbstrFileID, _T("PhaseCheck")) == 0 && 
		(
			(
				strcasecmp( cbstrFileType , _T("CODE")) == 0 &&
			 	strcasecmp( cbstrOperationType ,_T("Download")) == 0
			) 
			|| 
			(
				strcasecmp( cbstrFileType , _T("CODE2")) == 0 && 
				strcasecmp( cbstrOperationType ,_T("DownloadByID")) == 0
			)
		)
	)
	{
	       if(m_Settings.IsNeedPhaseCheck())
	       {
	       	IBMFile* pBMFile = (IBMFile*)pBMFileInterface;
			DWORD dwPhaseCheckSize  = pBMFile->GetCurCodeSize();
			if(dwPhaseCheckSize == 0  || dwPhaseCheckSize > PRODUCTION_INFO_SIZE )
			{
			  	dwPhaseCheckSize = PRODUCTION_INFO_SIZE;
			}
			
			PORT_DATA* pPortData = NULL;
			pPortData = GetPortDataByPort(dwOprCookie);
			if(pPortData)
			{
				pBMFile->SetCurCode(pPortData->lpPhaseCheck, dwPhaseCheckSize);
				printf("\n%-20s %s","SN",pPortData->szSN);
			}
			else
			{
				sprintf(pbj->szErrorMsg,_T("Cannot find phasecheck info!"));
				return BM_S_FALSE;
			}
	       }
		else
		{
			int nID = m_Settings.IsBackupFile(_T("PhaseCheck"));
			if(nID != -1)
			{
				IBMFile* pBMFile = (IBMFile*)pBMFileInterface;
				pBMFile->SetCurCode(pbj->tFileBackup[nID].pBuf, pbj->tFileBackup[nID].dwSize);
			}
			else
			{
				sprintf(pbj->szErrorMsg,_T("Cannot find phasecheck backcup file!"));
				return BM_S_FALSE;
			}
		}

	}
	if(_tcsicmp( cbstrFileID, _T("PhaseCheck")) != 0 ) 
	{
		int nID = m_Settings.IsBackupFile(cbstrFileID);//for backup file
		if(nID != -1)
		{
			IBMFile* pBMFile = (IBMFile*)pBMFileInterface;
			pBMFile->SetCurCode(pbj->tFileBackup[nID].pBuf, pbj->tFileBackup[nID].dwSize);
		}
	}

	return BM_S_OK;
}
STDMETHODIMP(CDLoader::OnOperationEnd)(  DWORD dwOprCookie,
                            const char* cbstrFileID,
                            const char* cbstrFileType,
                            const char* cbstrOperationType,
                            DWORD dwResult,
                            void* pBMFileInterface )
{
	HRESULT 			hr 		= NULL;
	PBOOTMODEOBJ_T 	pStruct 	= NULL;
	_BMOBJ * 			pbj 		= NULL;
	MAP_BMPOBJ::iterator 	it;
	
	it = m_mapBMObj.find(dwOprCookie);
	if( it == m_mapBMObj.end()  ||  (pbj = it->second)== NULL )
	{
		return BM_S_FALSE;
	}

	if(OPR_SUCCESS != dwResult)
	{
		if( OPR_FAIL != dwResult)
		{
			GetOprErrorCodeDescription(dwResult,pbj->szErrorMsg,_MAX_PATH);
			//printf("[%s] fail,Error=%d [%s] \n",cbstrFileID,dwResult,pbj->szErrorMsg);
		}
		return BM_S_FALSE;
	}

	hr = m_BMAF.BMAF_GetBootModeObjInfo(dwOprCookie,(void**)&pStruct);
	if( FAILED(hr) )
	{
		return BM_S_FALSE;
	}

		
	if(  _tcsicmp( cbstrFileID, _T("CheckBaud")) == 0 
		&& _tcsicmp( cbstrOperationType,_T("GetCheckBaudCrcType")) == 0 )
	{ 
		
		LPBYTE lpReadBuffer = NULL; 
		DWORD dwReadSize = 0;

		lpReadBuffer = pStruct->pSnapin->GetReadBuffer();
		dwReadSize = pStruct->pSnapin->GetReadBufferSize();   

		if(lpReadBuffer != NULL && dwReadSize >= 4)
		{
			int nCrcType = (int)(*(DWORD*)lpReadBuffer);
			if(nCrcType == -1)
			{
				_tcscpy(pbj->szErrorMsg,_T("Can not confirm crc type"));
				return BM_S_FALSE;
			}
			else
			{
				pbj->nStage = nCrcType == 1? 1: 2;
				return BM_S_OK;
			}
		}
		else
		{
			_tcscpy(pbj->szErrorMsg,_T("Can not confirm crc type"));
			return BM_S_FALSE;
		}				

	}

	if(
		(
			strncasecmp(  cbstrFileType, _T("CODE"),4) == 0 		||
	     		 strcasecmp( cbstrFileType, _T("READ_CHIPID")) == 0 
	        ) &&
	      	strcasecmp( cbstrOperationType,_T("ReadChipType")) == 0 
	    )
	{
		LPBYTE lpReadBuffer = NULL;
		DWORD dwReadSize = 0;

		lpReadBuffer = pStruct->pSnapin->GetReadBuffer();
		dwReadSize = pStruct->pSnapin->GetReadBufferSize();

		if( lpReadBuffer == NULL || dwReadSize < sizeof( DWORD) )
		{
		    return BM_S_FALSE;
		}

		DWORD dwSoruceValue, dwDestValue;
		dwSoruceValue =  *(DWORD *)&lpReadBuffer[ 0 ];
		dwDestValue   = 0;
		CONVERT_INT( dwSoruceValue, dwDestValue);
		pbj->dwChipID = dwDestValue;

		return BM_S_OK;
	}

	if( 
		(
			strcasecmp( cbstrFileType, _T("CHECK_MCPTYPE")) == 0  ||
	        	strcasecmp( cbstrFileType, _T("READFLASHTYPE")) == 0 
	        )&&
	    	strcasecmp(cbstrOperationType,_T("ReadFlashType")) == 0 
	    )
	{

		LPBYTE lpReadBuffer = NULL;
		DWORD dwReadSize = 0;

		lpReadBuffer = pStruct->pSnapin->GetReadBuffer();
		dwReadSize = pStruct->pSnapin->GetReadBufferSize();

		if( lpReadBuffer == NULL || dwReadSize < sizeof( DWORD)*4 )
		{
		    strcpy(pbj->szErrorMsg,_T("Read flash type failed."));
		    return BM_S_FALSE;
		}
		LPDWORD pDw = (LPDWORD)lpReadBuffer;
		CONVERT_INT((*pDw),    pbj->aFlashType[0]);  // MID
		CONVERT_INT((*(pDw+1)),pbj->aFlashType[1]);  // DID
		CONVERT_INT((*(pDw+2)),pbj->aFlashType[2]);  // EID
		CONVERT_INT((*(pDw+3)),pbj->aFlashType[3]);  // SUPPORT, not used now.

		return BM_S_OK;
	}

	if( _tcsicmp( cbstrFileType, _T("READ_RF_CHIP_TYPE")) == 0 &&
		_tcsicmp( cbstrOperationType,_T("ReadTransceiverType")) == 0 )
	{
		LPBYTE lpReadBuffer = NULL; 
		DWORD dwReadSize = 0;
		lpReadBuffer = pStruct->pSnapin->GetReadBuffer();
		dwReadSize = pStruct->pSnapin->GetReadBufferSize();

		if( lpReadBuffer == NULL || dwReadSize < sizeof( DWORD) )
		{
			_tcscpy(pbj->szErrorMsg,_T("Read RF chip type failed."));
			return BM_S_FALSE;
		}
		pbj->dwRFChipType = *(DWORD*)lpReadBuffer;
		return BM_S_OK;
	}


	/************************************************************************/
	/*  nand page block                                                    */
	/************************************************************************/

	if( 
		strcasecmp(cbstrFileType, _T("READ_FLASHINFO")) == 0   		&&
	    	strcasecmp(cbstrOperationType,_T("ReadFlashInfo")) == 0
	   )
	{
		LPBYTE lpReadBuffer = NULL;
		DWORD dwReadSize = 0;

		lpReadBuffer = pStruct->pSnapin->GetReadBuffer();
		dwReadSize = pStruct->pSnapin->GetReadBufferSize();

		if( lpReadBuffer == NULL || dwReadSize < sizeof( DWORD)*3)
		{
			strcpy(pbj->szErrorMsg,_T("Read flash info failed."));
			return BM_S_FALSE;
		}

		LPDWORD pDw = (LPDWORD)lpReadBuffer;

		DWORD dwFlag = 0;
		DWORD dwBlock = 0;
		DWORD dwPage = 0;
		CONVERT_INT((*pDw),    dwFlag);   	// FLAG
		CONVERT_INT((*(pDw+1)),dwBlock);  // BLOCK
		CONVERT_INT((*(pDw+2)),dwPage);   // PAGE

		if(dwFlag !=0)
		{
			sprintf(pbj->szErrorMsg,_T("Unsupported flash info flag [0x%X]."), dwFlag);
			return BM_S_FALSE;
		}

		BOOL bBlockK = FALSE;
		if(dwBlock >= 1024)
		{
			bBlockK = TRUE;
			dwBlock = dwBlock / 1024;
		}
		BOOL bPageK = FALSE;
		if(dwPage >= 1024)
		{
			bPageK = TRUE;
			dwPage = dwPage / 1024;
		}

		//Check MCP Type;
		std::string strBlockPageSize =Format(_T("_b%d%s_p%d%s"),dwBlock,bBlockK?_T("k"):_T(""),dwPage,bPageK?_T("k"):_T(""));	

		MAP_STRINT::iterator it;
		it = m_mapPBInfo.find(strBlockPageSize);
	    if( it == m_mapPBInfo.end()  ||  it->second== 0 )
		{
			sprintf(pbj->szErrorMsg,_T("Unsupported block-page, [%s]."),strBlockPageSize.c_str());
		    	return BM_S_FALSE;
		}
		_tcscpy(pbj->szBlockPageSize,strBlockPageSize.c_str());
		return BM_S_OK;

	 }
	/************************************************************************/
	/*  backup NV                                                           */
	/************************************************************************/
	if( 
		(
			strcasecmp( cbstrFileID, _T("NV")) == 0		 	&&
	     		m_Settings.IsBackupNV() 					 	&&
	    		strncasecmp( cbstrFileType, _T("NV"), 2 ) == 0 	&&
	    		strncasecmp( cbstrOperationType,_T("ReadFlash"),9) == 0 
	    	) ||
	       (
	   		 strncasecmp( cbstrFileID, _T("_BKF_NV"),7) == 0 		&&
	    		 strncasecmp( cbstrFileType, _T("ReadFlash"),9) == 0 	&&
	    		 strncasecmp(cbstrOperationType,_T("ReadFlash"),9) == 0
	       )
	  )
	{
		IBMFile* pBMFile = (IBMFile*)pBMFileInterface;
		LPBYTE lpReadBuffer = NULL;
		DWORD dwReadSize = 0;
		DWORD dwCodeSize = 0;
		LPVOID pDestCode = NULL;

		lpReadBuffer = pStruct->pSnapin->GetReadBuffer();
		dwReadSize = pStruct->pSnapin->GetReadBufferSize();

		if( lpReadBuffer == NULL || dwReadSize == 0)
		{
			strcpy(pbj->szErrorMsg,_T("Read Flash (NV) failed."));
			return BM_S_FALSE;
		}

		if( strncasecmp(cbstrFileType, _T("NV"), 2 ) == 0 )
		{
			const LPVOID pSrcCode = pBMFile->GetCurCode();
			dwCodeSize = pBMFile->GetCurCodeSize();
			pDestCode = pSrcCode;
		}
		else
		{
			std::string strNVID = cbstrFileID;
			if(_tcsnicmp( cbstrFileID, _T("_BKF_NV"),7) == 0)
			{
				strNVID = cbstrFileID+5;
			}

			int nIndex = m_Settings.GetDLNVIDIndex(strNVID.c_str());
			if(nIndex == -1)
			{
				return BM_S_FALSE;
			}

			PFILE_INFO_T pFileInfo = NULL;
			m_Settings.GetFileInfo(strNVID.c_str(),(void**)&pFileInfo);
			if(m_Settings.IsEnableRFChipType() && pFileInfo != NULL && pFileInfo->isSelByRf== 1)
			{
				BACKUP_INFO_PTR pNVInfo = m_mapMultiNVInfo[std::make_pair(pbj->dwRFChipType,strNVID)];
				if (NULL == pNVInfo)
				{
					std::string strRfChip;
					m_Settings.GetRFChipName(pbj->dwRFChipType,strRfChip);
					sprintf(pbj->szErrorMsg,_T("Not find [id:%d,name:%s] RF nv."),pbj->dwRFChipType,strRfChip.c_str());
					return BM_S_FALSE;
				}
				pbj->tNVBackup[nIndex].Clear();
				pbj->tNVBackup[nIndex].dwSize = pNVInfo->dwSize;				
				pbj->tNVBackup[nIndex].pBuf = new BYTE[pNVInfo->dwSize];

				if(pbj->tNVBackup[nIndex].pBuf != NULL)
				{
					memcpy(pbj->tNVBackup[nIndex].pBuf, pNVInfo->pBuf,pNVInfo->dwSize);
				}
				else
				{
					_tcscpy(pbj->szErrorMsg,_T("Multi nv memory full!"));		
					return BM_S_FALSE;
				}
			}
			//dwCodeSize = pbj->dwBufSize;
			//pDestCode = (LPVOID)(pbj->pBuf);
			dwCodeSize = pbj->tNVBackup[nIndex].dwSize;
			pDestCode = (LPVOID)(pbj->tNVBackup[nIndex].pBuf);
		}
		//////////////////////////////////////////////////////////////////////////
		// Check NV struct, lpReadBuffer will be changed if it is the driver level endian
		BOOL _bBigEndian = TRUE;
		if(!XCheckNVStructEx(lpReadBuffer,dwReadSize,_bBigEndian,TRUE))
		{
		    _tcscpy(pbj->szErrorMsg,_T("NV data read in phone is crashed."));
		    return BM_S_FALSE;
		}

		//check NV Struct in nv file
            if(!XCheckNVStructEx((LPBYTE)pDestCode,dwCodeSize,_bBigEndian,FALSE))
            {
                _tcscpy(pbj->szErrorMsg,_T("NV data in nvitem.bin is crashed."));
                return BM_S_FALSE;
            }

		PNV_BACKUP_ITEM_T pNvBkpItem = NULL;
		int nCount = m_Settings.GetNvBkpItemCount();
		BOOL bReplace = FALSE;
		BOOL bContinue = FALSE;
		for(int k=0;k<nCount;k++)
		{
	            bReplace = FALSE;
	            bContinue = FALSE;

	            pNvBkpItem = m_Settings.GetNvBkpItemInfo(k);

	            int nNvBkpFlagCount = pNvBkpItem->dwFlagCount;
	            if(nNvBkpFlagCount > MAX_NV_BACKUP_FALG_NUM)
	            {
	               	 nNvBkpFlagCount = MAX_NV_BACKUP_FALG_NUM;
	            }
	            for(int m=0;m<nNvBkpFlagCount;m++)
	            {
		                if(_tcscmp(pNvBkpItem->nbftArray[m].szFlagName,_T("Replace"))==0)
		                {
						if(pNvBkpItem->nbftArray[m].dwCheck == 1)
			                        bReplace = TRUE;
		                }
		                else if(_tcscmp(pNvBkpItem->nbftArray[m].szFlagName,_T("Continue"))==0)
		                {
			                    if(pNvBkpItem->nbftArray[m].dwCheck == 1)
			                        bContinue = TRUE;
		                }
	            }

	            if(_tcscmp(pNvBkpItem->szItemName,_T("Calibration"))==0)
	            {
#ifndef _SPUPGRADE
				if(pNvBkpItem->wIsBackup == 1)
#endif
				{
					WORD wNVItemID = (WORD)(pNvBkpItem->dwID&0xFFFF);
		                    if(wNVItemID == 0xFFFF)
		                    {
		                        wNVItemID = GSM_CALI_ITEM_ID;
		                    }
					DWORD dwErrorRCID = GSMCaliPreserve( wNVItemID,(LPBYTE)pDestCode, dwCodeSize, lpReadBuffer, dwReadSize,
					                                      bReplace, bContinue);
					if(  dwErrorRCID !=0  )
					{
					    sprintf(pbj->szErrorMsg, _T("Preserve calibration fail [%s]."), GetErrorDesc( dwErrorRCID ).c_str());
					    return BM_S_FALSE;
					}
				}
				continue;
	            }
	            else if(_tcscmp(pNvBkpItem->szItemName,_T("TD_Calibration"))==0)
	            {
#ifndef _SPUPGRADE
				if(pNvBkpItem->wIsBackup == 1)
#endif
				{
					WORD wNVItemID = (WORD)(pNvBkpItem->dwID&0xFFFF);
					if(wNVItemID == 0xFFFF)
					{
					    wNVItemID = XTD_CALI_ITEM_ID;
					}
					DWORD dwErrorRCID = XTDCaliPreserve(wNVItemID, (LPBYTE)pDestCode, dwCodeSize, lpReadBuffer, dwReadSize,
					                                     bReplace,bContinue);
					if(  dwErrorRCID !=0  )
					{
					    sprintf(pbj->szErrorMsg,_T("Preserve TD calibration fail [%s]."),
					            GetErrorDesc( dwErrorRCID ).c_str() );
					    return BM_S_FALSE;
					}
				}
			}
	            else if(_tcscmp(pNvBkpItem->szItemName,_T("LTE_Calibration"))==0)
	            {
#ifndef _SPUPGRADE
	                if(pNvBkpItem->wIsBackup == 1)
#endif
	                {
	                    WORD wNVItemID = (WORD)(pNvBkpItem->dwID&0xFFFF);
	                    if(wNVItemID == 0xFFFF)
	                    {
	                        wNVItemID = LTE_CALI_ITEM_ID;
	                    }

	                    DWORD dwErrorRCID = XPreserveNVItem( wNVItemID,(LPBYTE)pDestCode, dwCodeSize,
	                        lpReadBuffer, dwReadSize, bReplace, bContinue);
	                    if(  dwErrorRCID !=0  )
	                    {
	                        sprintf(pbj->szErrorMsg, _T("Preserve %s fail [%s]."),
	                                pNvBkpItem->szItemName,
	                                GetErrorDesc( dwErrorRCID ).c_str());
	                        return BM_S_FALSE;
	                    }
	                }
	           }
	            else if(_tcscmp(pNvBkpItem->szItemName,_T("IMEI"))==0)
	            {
#ifndef _SPUPGRADE
	                if(pNvBkpItem->wIsBackup == 1)
#endif
	                {
	                    int nIMEIIdx = 0;
	                    std::vector<UINT> agIDs;
	                    m_Settings.GetIMEIIDs(agIDs);
	                    DWORD dwErrorRCID = XPreserveIMEIs(  agIDs, (LPBYTE)pDestCode,dwCodeSize,
	                                                          lpReadBuffer, dwReadSize, nIMEIIdx, bReplace, bContinue);
	                    if(  dwErrorRCID !=0  )
	                    {
	                        sprintf(pbj->szErrorMsg,_T("Preserve IMEI%d fail [%s]."),
	                                nIMEIIdx+1,
	                                GetErrorDesc( dwErrorRCID ).c_str());
	                        return BM_S_FALSE;
	                    }
	                }
	                continue;
	            }
	            else
	            {
#ifdef _SPUPGRADE
	                if(_tcscmp(pNvBkpItem->szItemName,_T("MMITest"))==0 || _tcscmp(pNvBkpItem->szItemName,_T("MMITest Result"))==0)
	                {
	                    bContinue = TRUE;
	                }
#endif
	                if(pNvBkpItem->wIsBackup == 1 && pNvBkpItem->dwID != 0xFFFFFFFF)
	                {
	                    DWORD dwErrorRCID = XPreserveNVItem( (WORD)(pNvBkpItem->dwID),(LPBYTE)pDestCode, dwCodeSize,
	                                                         lpReadBuffer, dwReadSize, bReplace, bContinue);
	                    if(  dwErrorRCID !=0  )
	                    {
	                        sprintf(pbj->szErrorMsg, _T("Preserve %s fail [%s]."),
	                                pNvBkpItem->szItemName,
	                                GetErrorDesc( dwErrorRCID ).c_str());
	                        return BM_S_FALSE;
	                    }
	                }
	                continue;
	            }
        	}


	        /* record IMEI */
	        {
	            DWORD dwIMEIOffset=0;
	            DWORD dwIMEILen =0;
	            char szIMEI[100]={0};
	            BOOL bBigEndian = TRUE;
	            if (XFindNVOffsetEx(GSM_IMEI_ITEM_ID,(LPBYTE)pDestCode,dwCodeSize,dwIMEIOffset,dwIMEILen,bBigEndian,FALSE))
	            {
	                BYTE bIMEI[100] ={0};
	                memcpy(bIMEI,((LPBYTE)pDestCode) + dwIMEIOffset,dwIMEILen);
	                BCDToWString(bIMEI,dwIMEILen,szIMEI,100);

	                if(strlen(szIMEI) <= X_SN_LEN)
	                {
	                    strcpy(pbj->szIMEI,szIMEI);
	                }
	                else
	                {
	                    memcpy(pbj->szIMEI,szIMEI,X_SN_LEN);
	                }
	            }
        	}
    	}

	/************************************************************************/
	/* read nv 3 times if nv readed from phone is not correct               */
	/* check it by the nv memory in _BMOBJ.pBuf,if they are same            */
	/* it is validate                                                       */
	/************************************************************************/
	if( _tcsicmp(cbstrFileID,_T("_CHECK_NV_")) == 0
	    && _tcsnicmp( cbstrFileType, _T("CHECK_NV"), 2 ) == 0 &&
	    _tcsnicmp( cbstrOperationType,_T("ReadFlash"),9) == 0 )
	{
		std::string strNVID = cbstrFileID + 7;
		int nIndex = m_Settings.GetDLNVIDIndex(strNVID.c_str());
		if(nIndex == -1)
		    return BM_S_FALSE;

		BOOL bValidate = TRUE;
		if(pbj->tNVBackup[nIndex].pBuf == NULL || pbj->tNVBackup[nIndex].dwSize == 0)
		{
		    return BM_S_FALSE;
		}

		LPBYTE lpReadBuffer = NULL;
		DWORD dwReadSize = 0;

		lpReadBuffer = pStruct->pSnapin->GetReadBuffer();
		dwReadSize = pStruct->pSnapin->GetReadBufferSize();

		if( lpReadBuffer == NULL )
		{
		    return BM_S_FALSE;
		}

		BOOL _bBigEndian = TRUE;
		XCheckNVStructEx(lpReadBuffer,dwReadSize,_bBigEndian,TRUE);

		// omit the first 2 crc bytes and 2 timestamp bytes.
		if(memcmp(pbj->tNVBackup[nIndex].pBuf+4,
		          lpReadBuffer+4,
		          pbj->tNVBackup[nIndex].dwSize-4) != 0)
		{
		    bValidate = FALSE;
		}

		IBMFile* pBMFile = (IBMFile*)pBMFileInterface;
		pBMFile->SetCurCode((const LPVOID)(pbj->tNVBackup[nIndex].pBuf),
		                    pbj->tNVBackup[nIndex].dwSize);

		if(bValidate)
		{
		    return BM_S_OK;
		}

   	 }

	if( _tcsnicmp( cbstrFileID, _T("_BKF_"), 5) == 0 			&&
	    	_tcsnicmp( cbstrFileID, _T("_BKF_NV"),7) != 0 		 	&&
	    	_tcsnicmp( cbstrFileType , _T("ReadFlash"),9) == 0 	&&
	    	_tcsnicmp( cbstrOperationType ,_T("ReadFlash"),9) == 0 )
	{
		int nID = m_Settings.IsBackupFile(cbstrFileID+5);
		if(nID != -1)
		{
			LPBYTE lpReadBuffer = NULL;
			DWORD dwReadSize = 0;

			lpReadBuffer = pStruct->pSnapin->GetReadBuffer();
			dwReadSize = pStruct->pSnapin->GetReadBufferSize();

			if( lpReadBuffer == NULL )
			{
				return BM_S_FALSE;
			}
			pbj->tFileBackup[nID].dwSize = dwReadSize;
			pbj->tFileBackup[nID].pBuf = new BYTE[dwReadSize];
			if( pbj->tFileBackup[nID].pBuf == NULL )
			{
				return BM_S_FALSE;
			}
			memcpy(pbj->tFileBackup[nID].pBuf,lpReadBuffer,dwReadSize);
			return BM_S_OK;
		}
	}

	return BM_S_OK;
}
STDMETHODIMP(CDLoader::OnFileOprStart)( DWORD dwOprCookie,
                           const char* cbstrFileID,
                           const char* cbstrFileType,
                           void * pBMFileInterface )
{

	m_ProcMonitor.OnMessage(BM_FILE_BEGIN, dwOprCookie, NULL );

	//PFILE_INFO_T pFileInfo = NULL;
	IBMFile* pBMFile = (IBMFile*)pBMFileInterface;

	_BMOBJ * pbj = NULL;
	MAP_BMPOBJ::iterator it;

	it = m_mapBMObj.find(dwOprCookie);
	if( it == m_mapBMObj.end()  ||  (pbj = it->second)== NULL )
	{
		return BM_S_FALSE;
	}

	
	if(_tcscmp(OLE2T(cbstrFileID),_T("FDLA")) == 0  && _tcscmp(OLE2T(cbstrFileType),_T("FDL1")) == 0 && pbj->nStage == 2)
	{
		pBMFile->SetCurFileType(_T("DONOTHING"));
	}
	/************************************************************************/
	/* for rf chips nv file									               					 */
	/************************************************************************/
	if (m_Settings.IsEnableRFChipType() && _tcsnicmp(OLE2T(cbstrFileID),_T("NV"),2) == 0)
	{
		std::string strNVID(cbstrFileID);
		PFILE_INFO_T pFileInfo = NULL;
		m_Settings.GetFileInfo(strNVID.c_str(),(void**)&pFileInfo);
		if( pFileInfo && pFileInfo->isSelByRf==1 && m_Settings.GetNvBkpItemCount()	 && !m_Settings.IsBackupNV() )
		{
			BACKUP_INFO_PTR pNVInfo = m_mapMultiNVInfo[std::make_pair(pbj->dwRFChipType,strNVID)];
			if (NULL == pNVInfo)
			{
				std::string strRfChip;
				m_Settings.GetRFChipName(pbj->dwRFChipType,strRfChip);
				sprintf(pbj->szErrorMsg,_T("Not find [id:%d,name:%s] RF nv file."),pbj->dwRFChipType,strRfChip.c_str());
				return BM_S_FALSE;
			}
			
			if(!pBMFile->SetCurFileName(pNVInfo->szNVFile))
			{
				_tcscpy(pbj->szErrorMsg,_T("Set nv file fail!"));		
				return BM_S_FALSE;
			}
		}
	}
	
	/************************************************************************/
	/* for page block file									                					 */
	/************************************************************************/
	if(m_Settings.IsMapPBFileBuf())
	{
		PFILE_INFO_T pFileInfo = NULL;

		if( -1 != m_Settings.GetFileInfo(cbstrFileID,(void**)&pFileInfo) &&
			pFileInfo != NULL && 
			pFileInfo->isSelByFlashInfo == 1 &&
			pFileInfo->dwFlag != 0
		    )		
		{
			std::string strKey = pbj->szBlockPageSize;
			//printf("PageBlock=%s\n",strKey.c_str());
			if(strKey.empty())
			{
				sprintf(pbj->szErrorMsg,_T("Not read block-page size yet!"));
				return BM_S_FALSE;
			}

			EXT_IMG_INFO_PTR pImg = NULL;
			pImg = m_mapPBFileBuf[std::make_pair(strKey,cbstrFileID)];
			if(pImg != NULL)
			{
				pBMFile->SetFileHandle(pImg->fd);
				pBMFile->SetCurCode(pImg->pBuf,pImg->dwSize,pImg->dwFirstMapSize);
			}	
			else
			{
				sprintf(pbj->szErrorMsg,_T("Not find block-page [%s] matched file!"),strKey.c_str());
				return BM_S_FALSE;
			}

		}
	}

	/************************************************************************/
	/* for nv backup									                    */
	/************************************************************************/
	if(
		_tcsnicmp(OLE2T(cbstrFileID),_T("NV"),2) == 0 	&&
		m_Settings.IsReadFlashInFDL2()					&& 
		m_Settings.IsBackupNVFile(OLE2T(cbstrFileID))	&& 
		m_Settings.IsBackupNV()							&&
		_tcsnicmp(OLE2T(cbstrFileType),_T("CODE"),4) == 0
	    )//for nv backup
	{
		int nIndex = m_Settings.GetDLNVIDIndex(cbstrFileID);
		if(nIndex == -1 || nIndex >= MAX_BACKUP_FILE_NUM)
		    return BM_S_FALSE;
		if(pbj->tNVBackup[nIndex].pBuf == NULL || pbj->tNVBackup[nIndex].dwSize == 0)
		{
		    return BM_S_FALSE;
		}
		pBMFile->SetCurCode((const LPVOID)(pbj->tNVBackup[nIndex].pBuf), pbj->tNVBackup[nIndex].dwSize);
	}

	/************************************************************************/
	/* for file backup									                    */
	/************************************************************************/
	int nID = m_Settings.IsBackupFile(cbstrFileID);//for file backup
	if(nID != -1)
	{
		pBMFile->SetCurCode((const LPVOID)(pbj->tFileBackup[nID].pBuf),pbj->tFileBackup[nID].dwSize);
	}

	if( _tcsnicmp(cbstrFileID,_T("_CHECK_NV"),9) == 0 )
	{
		std::string strFileID = cbstrFileID + 5;

		int nIndex = m_Settings.GetDLNVIDIndex(strFileID.c_str());
		if(nIndex == -1 || nIndex >= MAX_BACKUP_FILE_NUM)
		    return BM_S_FALSE;
		if(pbj->tNVBackup[nIndex].pBuf == NULL || pbj->tNVBackup[nIndex].dwSize == 0)
		{
		    return BM_S_FALSE;
		}

		pBMFile->SetCurCode((const LPVOID)(pbj->tNVBackup[nIndex].pBuf),pbj->tNVBackup[nIndex].dwSize);
	}
    return BM_S_OK;
}
STDMETHODIMP(CDLoader::OnFileOprEnd)(    DWORD dwOprCookie,
                            const char* cbstrFileID,
                            const char* cbstrFileType,
                            DWORD dwResult )
{
    return BM_S_OK;
}

STDMETHODIMP(CDLoader::OnFilePrepare)(DWORD dwOprCookie,
                         const char* bstrProduct,
                         const char* bstrFileName,
                         void * lpFileInfo,
                         /*[out]*/ void *    pBMFileInfoArr,
                         /*[out]*/ DWORD*    lpBMFileInfoCount,
                         /*[out]*/ DWORD*    lpdwFlag )
{
	_BMOBJ * pbj = NULL;
	MAP_BMPOBJ::iterator it;
	it = m_mapBMObj.find(dwOprCookie);
	if( it == m_mapBMObj.end()  ||  (pbj = it->second)== NULL )
	{
	    return BM_S_FALSE;
	}

	*lpdwFlag = 0;
	PBMFileInfo pBMFileInfo = (PBMFileInfo)pBMFileInfoArr;
	if(lpFileInfo == NULL)
	{
	    int nFlashOprCount = 0;
	    if(
			(!m_Settings.IsNandFlash())	 &&
	        	  m_Settings.IsBackupNV() 	 &&
	         	  m_Settings.IsNeedCheckNV()
	         )
		{

			PFILE_INFO_T pNVFileInfo = NULL;
			if( 
				m_Settings.GetFileInfo(_T("NV"),(void**)&pNVFileInfo) != -1 &&
			    		pNVFileInfo != NULL
			    )
			{
				PBMFileInfo pBMFileInfoCur = pBMFileInfo+nFlashOprCount;
				_tcscpy(pBMFileInfoCur->szFileID,_T("_CHECK_NV_"));
				_tcscpy(pBMFileInfoCur->szFileType, _T("CHECK_NV"));
				pBMFileInfoCur->llBase = pNVFileInfo->arrBlock[0].llBase;
				pBMFileInfoCur->llOprSize = pNVFileInfo->arrBlock[0].llSize? pNVFileInfo->arrBlock[0].llSize : m_Settings.GetMaxNVLength();
				pBMFileInfoCur->bChangeCode = TRUE;
				pBMFileInfoCur->bLoadCodeFromFile = FALSE;

				m_ProcMonitor.AddStepDescription(pBMFileInfoCur->szFileID);

				nFlashOprCount++;
			}
		}

		if( m_Settings.IsReset())
		{
			PBMFileInfo pBMFileInfoCur = pBMFileInfo+nFlashOprCount;
			_tcscpy(pBMFileInfoCur->szFileID,_T("_RESET_"));
			_tcscpy(pBMFileInfoCur->szFileType, _T("Reset"));
			pBMFileInfoCur->llBase = 0x0;
			pBMFileInfoCur->llOprSize = 0x0;
			pBMFileInfoCur->bChangeCode = FALSE;
			pBMFileInfoCur->bLoadCodeFromFile = FALSE;

			m_ProcMonitor.AddStepDescription( pBMFileInfoCur->szFileID);

			nFlashOprCount++;
		}

		if( m_Settings.IsPowerOff())
		{
			PBMFileInfo pBMFileInfoCur = pBMFileInfo+nFlashOprCount;
			_tcscpy(pBMFileInfoCur->szFileID,_T("_POWEROFF_"));
			_tcscpy(pBMFileInfoCur->szFileType, _T("PowerOff"));
			pBMFileInfoCur->llBase = 0x0;
			pBMFileInfoCur->llOprSize = 0x0;
			pBMFileInfoCur->bChangeCode = FALSE;
			pBMFileInfoCur->bLoadCodeFromFile = FALSE;

			m_ProcMonitor.AddStepDescription( pBMFileInfoCur->szFileID);

			nFlashOprCount++;
		}

		*lpdwFlag = 1;
		*lpBMFileInfoCount= nFlashOprCount;

		return BM_S_OK;
	}

	PFILE_INFO_T pFileInfo = (PFILE_INFO_T)lpFileInfo;

	do
	{
		if( _tcsicmp(pFileInfo->szType,_T("MasterImage"))==0 )
		{
			_tcscpy(pBMFileInfo->szFileID,pFileInfo->szID);
			_tcscpy(pBMFileInfo->szFileType, _T("CODE"));
			_tcscpy(pBMFileInfo->szFileName,OLE2T(bstrFileName));
			pBMFileInfo->llBase = pFileInfo->arrBlock[0].llBase;
			IMAGE_PARAM imageparam;
			pBMFileInfo->bLoadCodeFromFile = FALSE;
			pBMFileInfo->bChangeCode = TRUE;
			memset( &imageparam,0,sizeof( IMAGE_PARAM ) );
			_tcscpy( imageparam.szPath,OLE2T(bstrFileName) );
			CMasterImgGen mig;
			DWORD dweMasterImageSize = 0;
			pBMFileInfo->lpCode = mig.MakeMasterImageSingle( &dweMasterImageSize,1,&imageparam,m_Settings.GetFlashPageType() );
			pBMFileInfo->llCodeSize = dweMasterImageSize;
			if(pBMFileInfo->lpCode == NULL)
			{
				sprintf(pbj->szErrorMsg,_T("Make master image faile! [%s]"),pFileInfo->szID);
				return BM_S_FALSE;
			}
			m_pMasterImg = (LPBYTE)pBMFileInfo->lpCode;

			*lpdwFlag = 1;
			*lpBMFileInfoCount =1;
			m_ProcMonitor.AddStepDescription( pFileInfo->szID);
			break;
		}

		if( _tcsnicmp(pFileInfo->szID,_T("NV"),2)==0 )
		{
			_tcscpy(pBMFileInfo->szFileName,OLE2T(bstrFileName));
			_tcscpy(pBMFileInfo->szFileID,pFileInfo->szID);
			_tcscpy(pBMFileInfo->szRepID,pFileInfo->arrBlock[0].szRepID);

			// need to calculate the CRC16 and add to the head of NV
			// so the bChangeCode must be TRUE;
			pBMFileInfo->bChangeCode = TRUE;

			if( 
				_tcsnicmp(pFileInfo->szType,_T("NV"),2)==0 &&
				( 
					m_Settings.IsReadFlashInFDL2()	|| 
					!m_Settings.IsBackupNV()		|| 
					!m_Settings.IsBackupNVFile(pFileInfo->szID) 
				)
			   )
			{
				_tcscpy(pBMFileInfo->szFileType, m_Settings.HasPartitionInfo()?_T("CODE2"):_T("CODE"));
			}
			else
			{
				_tcscpy(pBMFileInfo->szFileType, pFileInfo->szType);
			}
			pBMFileInfo->bLoadCodeFromFile = TRUE;
			pBMFileInfo->llBase = pFileInfo->arrBlock[0].llBase;
			pBMFileInfo->llOprSize = pFileInfo->arrBlock[0].llSize? pFileInfo->arrBlock[0].llSize : m_Settings.GetMaxNVLength();	

			m_ProcMonitor.AddStepDescription( pFileInfo->szID);

			int nInfoCount = 1;

			if(m_Settings.IsNVOrgDownload())
			{
				int nPos = m_Settings.GetNVOrgBasePosition();
				if(nPos<=0 || nPos >= 5)
				{
					sprintf(pbj->szErrorMsg,_T("NV orignal base position [%d] is not correct,must be [1-4]!"),nPos);
					return BM_S_FALSE;
				}
				PBMFileInfo pBMFileInfo2 = pBMFileInfo + nInfoCount;
				_tcscpy(pBMFileInfo2->szFileName,OLE2T(bstrFileName));
				pBMFileInfo2->bLoadCodeFromFile = TRUE;
				pBMFileInfo2->bChangeCode = FALSE;
				_stprintf(pBMFileInfo2->szFileID,_T("_ORG_%s"),pFileInfo->szID);
				_tcscpy(pBMFileInfo2->szFileType, m_Settings.HasPartitionInfo()?_T("CODE2"):_T("CODE"));
				_tcscpy(pBMFileInfo2->szRepID, pFileInfo->arrBlock[nPos].szRepID);
				pBMFileInfo2->llBase = pFileInfo->arrBlock[nPos].llBase;

				m_ProcMonitor.AddStepDescription( pBMFileInfo2->szFileID);
				nInfoCount++;
			}

			*lpdwFlag = 1;
			*lpBMFileInfoCount =nInfoCount;

			break;
		}

		if(_tcsicmp(pFileInfo->szID,_T("FDL")) == 0 && !m_Settings.IsNandFlash())
		{
			// For FDL
			_tcscpy(pBMFileInfo->szFileName,OLE2T(bstrFileName));
			_tcscpy(pBMFileInfo->szFileID,pFileInfo->szID);
			pBMFileInfo->bChangeCode = FALSE;
			pBMFileInfo->bLoadCodeFromFile = TRUE;
			pBMFileInfo->llBase = pFileInfo->arrBlock[0].llBase;
			_tcscpy(pBMFileInfo->szFileType, pFileInfo->szType);
			m_ProcMonitor.AddStepDescription(pBMFileInfo->szFileID);

			int nInfoCount = 1;

			 //  set ExtTable info
			if(m_Settings.HasExtTblInfo())
			{
				// added ExtTable function
				PBMFileInfo pBMFileInfo2 = pBMFileInfo + nInfoCount;
				pBMFileInfo2->bLoadCodeFromFile = FALSE;
				_tcscpy(pBMFileInfo2->szFileType, _T("EXTTABLE"));
				_tcscpy(pBMFileInfo2->szFileID,_T("_EXTTABLE_"));
				pBMFileInfo2->lpCode 		= m_pExtTblData;
				pBMFileInfo2->llCodeSize =m_dwExtTblSize;
				m_ProcMonitor.AddStepDescription(pBMFileInfo2->szFileID);
				++nInfoCount;
			} 

			if(!AddBackupFiles(pBMFileInfo,nInfoCount,pbj,pFileInfo))
			{
				return BM_S_FALSE;
			}

			if (m_bPacHasKey || m_Settings.IsNeedEnableWriteFlash() || m_Settings.IsEnableRFChipType()) 
	             {
	                PBMFileInfo pBMFileInfoCur = pBMFileInfo+nInfoCount;
	                _tcscpy(pBMFileInfoCur->szFileID,_T("_EnableFlash_"));
	                _tcscpy(pBMFileInfoCur->szFileType, _T("Enable_Flash"));	
	                pBMFileInfoCur->llBase = 0x0;
	                pBMFileInfoCur->llOprSize = 0x0;
	                pBMFileInfoCur->bChangeCode = FALSE;
	                pBMFileInfoCur->bLoadCodeFromFile = FALSE;
			   m_ProcMonitor.AddStepDescription(pBMFileInfoCur->szFileID);
	                ++nInfoCount;
	             }
			if( m_Settings.IsEraseAll() && AddEraseAll(pBMFileInfo+nInfoCount))
			{
				nInfoCount++;
			}

			*lpdwFlag = 1;
			*lpBMFileInfoCount =nInfoCount;
			break;
		}

		if(_tcsicmp(pFileInfo->szID,_T("FDL")) == 0 && m_Settings.IsNandFlash() && m_bPortSecondEnum)
		{

			// For CheckBaud
			_tcscpy(pBMFileInfo->szFileID,_T("CheckBaud"));
			pBMFileInfo->bChangeCode = FALSE;
			pBMFileInfo->bLoadCodeFromFile = FALSE;
			pBMFileInfo->llBase =0;
			_tcscpy(pBMFileInfo->szFileType,_T("CheckBaud"));
			m_ProcMonitor.AddStepDescription(pBMFileInfo->szFileID);


			// For FDL
			PBMFileInfo pBMFileInfo2 = pBMFileInfo + 1;
			_tcscpy(pBMFileInfo2->szFileName,OLE2T(bstrFileName));
			_tcscpy(pBMFileInfo2->szFileID,_T("FDLA"));
			pBMFileInfo2->bChangeCode = FALSE;
			pBMFileInfo2->bLoadCodeFromFile = TRUE;
			pBMFileInfo2->llBase = pFileInfo->arrBlock[0].llBase;
			_tcscpy(pBMFileInfo2->szFileType,  _T("FDL1"));
			m_ProcMonitor.AddStepDescription( _T("FDL1"));
			*lpdwFlag = 1;
			*lpBMFileInfoCount =2;	
			
		}

		if(_tcsicmp(pFileInfo->szID,_T("Fdl2")) == 0 && m_Settings.IsNandFlash())
		{
			int nInfoCount = 0;
			if(m_Settings.IsKeepCharge())
			{
				PBMFileInfo pBMFileInfo2 = pBMFileInfo + nInfoCount;
				_tcscpy(pBMFileInfo2->szFileType, _T("KeepCharge"));
				_tcscpy(pBMFileInfo2->szFileID, _T("KeepCharge"));
				pBMFileInfo2->llBase = 0x0;
				pBMFileInfo2->llOprSize = 0x0;
				pBMFileInfo2->bChangeCode = FALSE;
				pBMFileInfo2->bLoadCodeFromFile = FALSE;
				 m_ProcMonitor.AddStepDescription(pBMFileInfo2->szFileID);
				 nInfoCount++;
			}

			// For Fdl2
			if( m_bPortSecondEnum)
			{
				PBMFileInfo pBMFileInfo2 = pBMFileInfo + nInfoCount;
				_tcscpy(pBMFileInfo2->szFileName,OLE2T(bstrFileName));
				_tcscpy(pBMFileInfo2->szFileID,_T("FDLB"));
				pBMFileInfo2->bChangeCode = FALSE;
				pBMFileInfo2->bLoadCodeFromFile = TRUE;
				pBMFileInfo2->llBase = pFileInfo->arrBlock[0].llBase;
				_tcscpy(pBMFileInfo2->szFileType,_T("FDL2"));
				m_ProcMonitor.AddStepDescription(_T("FDL2"));
				nInfoCount++;
			}
			else
			{
				PBMFileInfo pBMFileInfo2 = pBMFileInfo + nInfoCount;
				_tcscpy(pBMFileInfo2->szFileName,OLE2T(bstrFileName));
				_tcscpy(pBMFileInfo2->szFileID,pFileInfo->szID);
				pBMFileInfo2->bChangeCode = FALSE;
				pBMFileInfo2->bLoadCodeFromFile = TRUE;
				pBMFileInfo2->llBase = pFileInfo->arrBlock[0].llBase;
				_tcscpy(pBMFileInfo2->szFileType, pFileInfo->szType);
				m_ProcMonitor.AddStepDescription(pBMFileInfo2->szFileID);
				nInfoCount++;
			}

			//  set ExtTable info
			if(m_Settings.HasExtTblInfo())
			{
				// added ExtTable function
				PBMFileInfo pBMFileInfo2 = pBMFileInfo + nInfoCount;
				pBMFileInfo2->bLoadCodeFromFile = FALSE;
				_tcscpy(pBMFileInfo2->szFileType, _T("EXTTABLE"));
				_tcscpy(pBMFileInfo2->szFileID,_T("_EXTTABLE_"));
				pBMFileInfo2->lpCode 		= m_pExtTblData;
				pBMFileInfo2->llCodeSize =m_dwExtTblSize;	
				m_ProcMonitor.AddStepDescription(pBMFileInfo2->szFileID);
				++nInfoCount;
			} 

			if(m_Settings.IsMapPBFileBuf())
			{
				// add ReadFlashInfo function
				PBMFileInfo pBMFileInfo2 = pBMFileInfo + nInfoCount;
				pBMFileInfo2->bLoadCodeFromFile = FALSE;
				pBMFileInfo2->bChangeCode = FALSE;
				_tcscpy(pBMFileInfo2->szFileType, _T("READ_FLASHINFO"));
				_tcscpy(pBMFileInfo2->szFileID,_T("ReadFlashInfo"));
				 m_ProcMonitor.AddStepDescription(pBMFileInfo2->szFileID);

				nInfoCount++;	
			}

			if (m_Settings.IsEnableRFChipType())
			{
				// add Read RF Chip type function
				PBMFileInfo pBMFileInfo3 = pBMFileInfo + nInfoCount;
				pBMFileInfo3->bLoadCodeFromFile = FALSE;
				_tcscpy(pBMFileInfo3->szFileType, _T("READ_RF_CHIP_TYPE"));
				_tcscpy(pBMFileInfo3->szFileID,_T("ReadRFChipID"));
				m_ProcMonitor.AddStepDescription(pBMFileInfo3->szFileID);
				++nInfoCount;	
			}

			if(m_Settings.IsReadFlashInFDL2() && m_Settings.IsBackupNV())
			{
				//printf("Entry IsReadFlashInFDL2\n");
				std::vector<std::string> agNVID;
				int nNVCount = m_Settings.GetDLNVID(agNVID);
				for(int i = 0;i<nNVCount; i++)
				{
					std::string strFileID = agNVID[i];
					PFILE_INFO_T pBackupFileInfo = NULL;
					if( 
						m_Settings.GetFileInfo(strFileID.c_str(),(void**)&pBackupFileInfo) != -1 &&
						pBackupFileInfo != NULL && 
						_tcsnicmp(pBackupFileInfo->szType,_T("NV"),2) == 0
					    )
					{
						PBMFileInfo pBMFileInfo2 = pBMFileInfo + nInfoCount;
						pBMFileInfo2->bLoadCodeFromFile = FALSE;
						_tcscpy(pBMFileInfo2->szFileType, m_Settings.HasPartitionInfo()?_T("ReadFlash2"):_T("ReadFlash"));
						_stprintf(pBMFileInfo2->szFileID,_T("_BKF_%s"),pBackupFileInfo->szID);
						_tcscpy(pBMFileInfo2->szRepID, pBackupFileInfo->arrBlock[0].szRepID);
						pBMFileInfo2->llBase = pBackupFileInfo->arrBlock[0].llBase;
						pBMFileInfo2->llOprSize = pBackupFileInfo->arrBlock[0].llSize? pBackupFileInfo->arrBlock[0].llSize : m_Settings.GetMaxNVLength();

						m_ProcMonitor.AddStepDescription(pBMFileInfo2->szFileID);
						nInfoCount++;
					}
				}
			}

			if(!AddBackupFiles(pBMFileInfo,nInfoCount,pbj,pFileInfo))
			{
				 return BM_S_FALSE;
			}

			if (m_bPacHasKey ||m_Settings.IsNeedEnableWriteFlash() || m_Settings.IsEnableRFChipType()) 
	            {
	                PBMFileInfo pBMFileInfoCur = pBMFileInfo+nInfoCount;
	                _tcscpy(pBMFileInfoCur->szFileID,_T("_EnableFlash_"));
	                _tcscpy(pBMFileInfoCur->szFileType, _T("Enable_Flash"));	
	                pBMFileInfoCur->llBase = 0x0;
	                pBMFileInfoCur->llOprSize = 0x0;
	                pBMFileInfoCur->bChangeCode = FALSE;
	                pBMFileInfoCur->bLoadCodeFromFile = FALSE;
			   m_ProcMonitor.AddStepDescription(pBMFileInfoCur->szFileID);
	                ++nInfoCount;
	            }


			if( m_Settings.IsEraseAll() && AddEraseAll(pBMFileInfo+nInfoCount))
			{
				nInfoCount++;
			}

			if( m_Settings.GetRepartitionFlag() == REPAR_STRATEGY_ALWAYS)
			{
				PBMFileInfo pBMFileInfo2 = pBMFileInfo + nInfoCount;
				pBMFileInfo2->bLoadCodeFromFile = FALSE;

				if(m_Settings.HasPartitionInfo())
				{
					_tcscpy(pBMFileInfo2->szFileType,_T("FORCE_REPARTITION2"));
					pBMFileInfo2->lpCode = m_pPartitionData;
					pBMFileInfo2->llCodeSize = m_dwPartitionSize;
				}
				else
				{
					_tcscpy(pBMFileInfo2->szFileType,_T("REPARTITION"));
				}
				/*_tcscpy(pBMFileInfo2->szFileType,m_Settings.HasPartitionInfo()?_T("FORCE_REPARTITION2"):_T("FORCE_REPARTITION"));
				pBMFileInfo2->lpCode = m_pPartitionData;
				pBMFileInfo2->llCodeSize = m_dwPartitionSize;*/
				_tcscpy(pBMFileInfo2->szFileID,_T("_REPARTITION_"));
				m_ProcMonitor.AddStepDescription(pBMFileInfo2->szFileID);
				nInfoCount++;
			}

			*lpdwFlag = 1;
			*lpBMFileInfoCount =nInfoCount;

			break;

		}

		if(m_Settings.NeedBackupMiscAndProdnvFile() &&  m_nBackupProdnvMiscdata== 0)
		{
		 	PFILE_INFO_T pTmpFileInfo = NULL;
		      if( 
			  	m_Settings.GetFileInfo(pFileInfo->szID, (void**)&pTmpFileInfo) != -1 && pTmpFileInfo != NULL &&
			  	(_tcsicmp(pTmpFileInfo->arrBlock[0].szRepID,_T("miscdata")) == 0 ||_tcsicmp(pTmpFileInfo->arrBlock[0].szRepID,_T("prodnv")) == 0)
			  )
			{
				*lpdwFlag = 1;
				*lpBMFileInfoCount =0;
				break;
			}
		}
		
		if( _tcsicmp(pFileInfo->szID,_T("PhaseCheck"))==0 )
		{
			if(
				m_Settings.IsNeedPhaseCheck() ||
				m_Settings.IsBackupFile(_T("PhaseCheck")) != -1
			)
			{
				_tcscpy(pBMFileInfo->szFileName,OLE2T(bstrFileName));
				_tcscpy(pBMFileInfo->szFileID,_T("PhaseCheck"));

				pBMFileInfo->bChangeCode = FALSE;
				_tcscpy(pBMFileInfo->szFileType, pFileInfo->szType);
				_tcscpy(pBMFileInfo->szRepID, pFileInfo->arrBlock[0].szRepID);

				DWORD dwPhaseCheckSize = pFileInfo->arrBlock[0].llSize;
				if(
					pFileInfo->arrBlock[0].llSize == 0 ||
				    	pFileInfo->arrBlock[0].llSize > PRODUCTION_INFO_SIZE
				    )
				{
					dwPhaseCheckSize = PRODUCTION_INFO_SIZE;
				}

				pBMFileInfo->bLoadCodeFromFile = FALSE;
				pBMFileInfo->llBase = pFileInfo->arrBlock[0].llBase;
				pBMFileInfo->llCodeSize = dwPhaseCheckSize;
				pBMFileInfo->lpCode = NULL;

				*lpdwFlag = 1;
				*lpBMFileInfoCount =1;
				m_ProcMonitor.AddStepDescription(pBMFileInfo->szFileID);
			}
			else
			{
				*lpdwFlag = 1;
				*lpBMFileInfoCount =0;
			}

			break;
		}

        	/// deal with backup items that are not checked by the user, except "phasecheck"
		{
		    PFILE_INFO_T pFileInfo = NULL;
		    if(m_Settings.GetFileInfo(pFileInfo->szID, (void**)&pFileInfo) != -1)
		    {
		        if( 
					pFileInfo->isBackup == 1								&& 
		           		 (bstrFileName == NULL || _tcslen(bstrFileName) == 0)	&& 
		        		m_Settings.IsBackupFile(pFileInfo->szID) == -1 
		           )
		        {
		            *lpdwFlag = 1;
		            *lpBMFileInfoCount =0;
		            break;
		        }
		    }
		}

	}while(0);
	// use for GUI display
	if(*lpdwFlag == 0 )
	{
	    m_ProcMonitor.AddStepDescription(pFileInfo->szID);
	}
	pFileInfo = NULL;
	pBMFileInfo = NULL;

	return BM_S_OK;
}


void CDLoader::GetOprErrorCodeDescription(
                                           DWORD dwErrorCode,
                                           LPTSTR lpszErrorDescription,
                                           int nSize )
{
    if( lpszErrorDescription == NULL || nSize == 0 )
        return;

    _TCHAR szErrorIniFile[MAX_PATH] = {0};

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

DWORD CDLoader::BCDToWString(LPBYTE pBcd,DWORD dwSize,LPTSTR szStr,DWORD dwStrLen)
{
    if(dwStrLen < dwSize * 2 )
        return 0;

    _TCHAR szValue[ 4 ] = { 0 };

    for(UINT i=0;i<dwSize;i++)
    {
        _stprintf(szValue, _T("%02x"), *pBcd);
        if(i==0)
        {
            szStr[i]=szValue[0];
        }
        else
        {
            szStr[2*i-1]=szValue[1];
            szStr[2*i]=szValue[0];
        }

        pBcd++;
    }

    return dwSize*2-1;
}
void CDLoader::SetReplaceDLFiles(std::map<std::string,std::string>& mapReplaceDLFile)
{
	m_Settings.SetReplaceDLFiles(mapReplaceDLFile);
}

BOOL CDLoader::LoadPacket(const char *szPac)
{
	//printf("Enter %s...\n", __func__);
	if(!m_Settings.LoadPacket(szPac))
	{
	    printf("Load pac failed. \n");
	    system("nvram set mobile_upgrade_md5=1");
	    return FALSE;
	}
    //printf("%s success...\n", __func__);

	return TRUE;
}
BOOL CDLoader::InitDownload()
{
	printf("Enter %s.\n", __func__);
	m_bEnd = FALSE;
	std::string strError = "";
	m_Settings.SetReplacePolicy(m_nReplacePolicy);
	m_Settings.SetBackupFilePolicy(m_nBackupProdnvMiscdata);
	ClearMultiNVMap();
	if(!m_Settings.LoadSettings(strError))
	{
		printf("Load settings failed: %s \n",strError.c_str());
		m_bEnd = TRUE;
		return FALSE;
	}

	if(!m_Settings.LoadConfig())
	{
	    printf("Load configure failed. \n");
	    m_bEnd = TRUE;
	    return FALSE;
	}

	if(!CheckDLFiles())
	{
	    printf("Check download files failed. \n");
	    m_bEnd = TRUE;
	    return FALSE;
	}
	// get multi-nv files for different rf chip name.
	if (!InitMultiNVBuffer())
	{
		printf("Init multi NV buffer failed. \n");
		m_bEnd = TRUE;
		return FALSE;
	}
	
	if(!InitNVBuffer())
	{
	    printf("Init NV buffer failed. \n");
	    m_bEnd = TRUE;
	    return FALSE;
	}

	if(!InitPartitionData())
	{
	    printf("Init partition data failed. \n");
	    m_bEnd = TRUE;
	    return FALSE;
	}

	if(!InitExtTblData())
	{
		printf("Init exttable data failed. \n");
		m_bEnd = TRUE;
		return FALSE;
	}

	if(!InitMapPBFileBuf())
	{
	    printf("Init pageblock data failed. \n");
	    m_bEnd = TRUE;
	    return FALSE;
	}

	if(!CheckPacKey())
	{
	    printf("CheckPacKey failed. \n");
	    m_bEnd = TRUE;
	    return FALSE;
	}

	CheckPort2ndEnum();

	//printf("%s: OK!!!\n", __func__);
	return TRUE;
}

BOOL CDLoader::StartDownload(const char *szDev, UINT baudrate, UINT nPort)
{
	//printf("%s...\n", __func__);

	int nRep = m_Settings.GetRepartitionFlag();
	DWORD dwWaitTime = 0;
	 BOOL  bEnablePowerOff    = m_Settings.IsPowerOff();
	m_BMAF.BMAF_SetProperty(BMAF_TIME_WAIT_FOR_NEXT_CHIP,(void*)&(dwWaitTime));
	m_BMAF.BMAF_SetProperty(BMAF_NAND_REPARTION_FLAG, (void*)&nRep );
	m_BMAF.BMAF_SetProperty(BMAF_SPECIAL_CONFIG_FILE, (void*)m_Settings.m_strSpecConfig.c_str() );
	m_BMAF.BMAF_SetProperty(BMAF_ENABLE_PORT_SECOND_ENUM, (void*)&m_bPortSecondEnum);	
	m_BMAF.BMAF_SetProperty(BMAF_POWER_OFF_DEVICE,(void*)&bEnablePowerOff);

	BYTE btOpenArgument[ 8+256 ] = {0};
	*(DWORD *)&btOpenArgument[ 0 ] = nPort;
	*(DWORD *)&btOpenArgument[ 4 ] = baudrate;
	strcpy((char*)(btOpenArgument+8),szDev);

	m_bDownloadPass = FALSE;

	//printf("%s: set all Property OK!\n", __func__);

	m_BMAF.BMAF_SubscribeObserver( nPort,this, NULL );

	std::vector<std::string> agDLFiles;
	int nCount = m_Settings.GetDownloadFile(agDLFiles);

	LPCTSTR *ppFileList = new LPCTSTR[nCount];
	if(ppFileList == NULL)
	{
	    m_bEnd = TRUE;
	    return FALSE;
	}
	for(int i = 0; i<nCount; i++)
	{
	    ppFileList[i] = agDLFiles[i].c_str();
	}
	_BMOBJ     * pStruct = NULL;
	MAP_BMPOBJ::iterator it;
	it = m_mapBMObj.find(nPort);
	if( it != m_mapBMObj.end() )
	{
	    pStruct = it->second;
	    pStruct->Clear();
	}
	else
	{
	    pStruct = new _BMOBJ;
	    if( pStruct == NULL ) //lint !e774
	    {
			SAFE_DELETE_ARRAY(ppFileList);
			printf("StartDownload: out of memory!\n");
			return FALSE;
	    }

	    pStruct->dwCookie = nPort;
	    pStruct->dwIsUart = FALSE;

	    m_mapBMObj[nPort] = pStruct;
	}

	//printf("%s: ReadFlashInFDL2...\n", __func__);
	if(m_Settings.IsReadFlashInFDL2())
	{
	    //printf("%s: ReadFlashInFDL2... OK\n", __func__);
		std::vector<std::string> agNVID;
		int nNVCount = m_Settings.GetDLNVID(agNVID);

	    //printf("%s: NV nNVCount = %d\n", __func__, nNVCount);
		for(int i = 0; i<nNVCount; i++)
		{

			std::string strNVID = agNVID[i];
			BACKUP_INFO_PTR pNVInfo = NULL;
			MAP_NVFILE::iterator it;
			it = m_mapNVFileInfo.find(strNVID);
			if(it != m_mapNVFileInfo.end() && it->second!= NULL)
			{
				pNVInfo = it->second;

				if(pNVInfo->dwSize == 0 || pNVInfo->pBuf == NULL)
				{
					SAFE_DELETE_ARRAY(ppFileList);
					printf(_T("[error]: %s file is empty"),strNVID.c_str());
					return FALSE;
				}
				pStruct->tNVBackup[i].dwSize = pNVInfo->dwSize;
				pStruct->tNVBackup[i].pBuf = new BYTE[pNVInfo->dwSize];

				if(pStruct->tNVBackup[i].pBuf != NULL)
				{
					memcpy(pStruct->tNVBackup[i].pBuf, pNVInfo->pBuf,pNVInfo->dwSize);
				}
				else
				{
					SAFE_DELETE_ARRAY(ppFileList);
					printf(_T("[error]: out of memory\n"));
					return FALSE;
				}
			}
		}
	}

	//printf("%s: 1844 line\n", __func__);

    HRESULT hr = m_BMAF.BMAF_StartOneWork( m_Settings.GetCurProduct().c_str(),
        ppFileList,
        nCount,
        (void*)btOpenArgument,
        TRUE,
       // FALSE,
        nPort,
        (void*)&m_ProcMonitor);

    SAFE_DELETE_ARRAY(ppFileList);

    BOOL bReturn = TRUE;
    BOOL bFirst = TRUE;
    PBOOTMODEOBJ_T pBMO = NULL;
    m_BMAF.BMAF_GetBootModeObjInfo(nPort,(void**)&pBMO);
    bFirst = pBMO->bFirstStart;

    std::string strErrMsg;

    switch( (DWORD)hr )
    {
    case BM_E_FAILED:
    case BM_S_FALSE:
        strErrMsg = _T("Start failed!\n");
        bReturn =  FALSE;
        break;
    case BM_E_CHANNEL_FAILED:
        strErrMsg = _T("Open channel failed!\n");
        bReturn =  FALSE;
        break;
    case BMAF_E_INIT_BMFILES_FAIL:
        strErrMsg = pStruct->szErrorMsg; // prepare file fail, mainly for making master image
        if(strErrMsg.length() == 0)
        {
            strErrMsg = _T("Init BMFiles failed!\n");
        }
        bReturn =  FALSE;
        break;

    default:
        if(FAILED(hr))
        {
            bReturn =  FALSE;
        }
        break;
    }

    if(!bReturn )
    {
        if(strErrMsg.length()!= 0)
        {
            printf("%s", strErrMsg.c_str() );
        }
        m_BMAF.BMAF_StopOneWork( nPort);
        m_BMAF.BMAF_UnsubscribeObserver( nPort );
        m_bEnd = TRUE;
        return FALSE;
    }

    //printf("[%s] OK!!!!!\n", __func__);
    return TRUE;
}
BOOL CDLoader::StopDownload(UINT nPort)
{
	HRESULT hr;
	PBOOTMODEOBJ_T pStruct = NULL;
	hr = m_BMAF.BMAF_GetBootModeObjInfo(nPort,(void**)&pStruct);
	//BOOL bSuc = TRUE;
	if( SUCCEEDED(hr) && pStruct != NULL )
	{
	 	m_BMAF.BMAF_StopOneWork(nPort);
	}

	ClearMapPBFileBuf();

	m_bEnd = TRUE;

	return TRUE;
}

BOOL CDLoader::CheckDLFiles()
{
	//printf("%s: Check...\n", __func__);
    std::string strError = _T("");
    std::vector<std::string> agDLFiles;
    int nCount = m_Settings.GetDownloadFile(agDLFiles);
    for(int i=0; i< nCount; i++)
    {
        std::string strFile = agDLFiles[i];
        if(strFile.length() != 0 &&
           _tcsicmp(strFile.c_str(),FILE_OMIT)!=0)
        {
            struct stat stat_file;

            if(stat(strFile.c_str(),&stat_file) == -1)
            {
                strError += strFile;
                strError += _T("\n");
            }
            else if(stat_file.st_size == 0)
            {
                strError += strFile;
                strError += _T("\n");
            }
        }
    }

    if(strError.length() != 0)
    {
        printf("there are empty files:\n%s\n", strError.c_str());
        return FALSE;
    }

    return TRUE;
}

BOOL CDLoader::InitNVBuffer()
{
    ClearNVBuffer();

    if(!m_Settings.IsReadFlashInFDL2())
    {
        return TRUE;
    }

    std::vector<std::string> agNVID;
    int nNVCount = m_Settings.GetDLNVID(agNVID);

    if(nNVCount == 0 )
    {
        return TRUE;
    }

    std::string strNVFileType;
    std::string strNVFileName;
    PFILE_INFO_T pNVFile = NULL;
    std::vector<std::string> agDLFiles;
    m_Settings.GetDownloadFile(agDLFiles);

    for(int i = 0; i< nNVCount; i++)
    {
        std::string strID = agNVID[i];
        int nIdx = m_Settings.GetFileInfo(strID.c_str(),(void**)&pNVFile);

        if(nIdx == -1) return FALSE;

        strNVFileName = agDLFiles[nIdx];

        if(strNVFileName.length() == 0 || _tcsicmp(strNVFileName.c_str(),FILE_OMIT) == 0)
        {
            return FALSE;
        }

        FILE *pFile = fopen(strNVFileName.c_str(),"rb");
        if(pFile == NULL)
            return FALSE;

        BACKUP_INFO_PTR pNVInfo = new BACKUP_INFO;
        m_mapNVFileInfo[strID] = pNVInfo;
        fseek(pFile,0,SEEK_END);
        pNVInfo->dwSize = ftell(pFile);
        fseek(pFile,0,SEEK_SET);
        if(pNVInfo->dwSize != 0 )
        {
            pNVInfo->pBuf = new BYTE[pNVInfo->dwSize];
            fread(pNVInfo->pBuf,1,pNVInfo->dwSize,pFile);
        }
        fclose(pFile);
    }

    return TRUE;
}

void CDLoader::ClearNVBuffer()
{
    MAP_NVFILE::iterator it;
    for(it = m_mapNVFileInfo.begin(); it !=m_mapNVFileInfo.end(); it++ )
    {
        BACKUP_INFO_PTR p = it->second;
        if(p)
        {
            p->Clear();
            delete p;
        }
    }
    m_mapNVFileInfo.clear();
}

void CDLoader::ClearMultiNVMap()
{
	MAP_MULTI_NVFILE::iterator it;
	for(it = m_mapMultiNVInfo.begin();  it !=m_mapMultiNVInfo.end(); it++ )
	{
	    BACKUP_INFO_PTR p = it->second;
	    if(p)
	    {
	        p->Clear();
	        delete p;
	    }
	}
	m_mapMultiNVInfo.clear();
}
BOOL CDLoader::InitPartitionData()
{
	if(!m_Settings.HasPartitionInfo())
	{
		return TRUE;
	}
	SAFE_DELETE_ARRAY(m_pPartitionData);
	m_dwPartitionSize = 0;
	m_pPartitionData = m_Settings.GetPartitionData(m_dwPartitionSize);
	return (m_pPartitionData != NULL);	
}
BOOL CDLoader::InitExtTblData()
{
	if(!m_Settings.HasExtTblInfo())
	{
		return TRUE;
	}
	SAFE_DELETE_ARRAY(m_pExtTblData);
	m_dwExtTblSize = 0;
	m_pExtTblData = m_Settings.GetExtTblData(m_dwExtTblSize);
	return (m_pExtTblData != NULL);
	
}

BOOL CDLoader::AddReadSN(PBMFileInfo pBMFileInfo)
{
	PFILE_INFO_T pPhaseCheckFileInfo = NULL;
	if( 
		m_Settings.GetFileInfo(_T("PhaseCheck"),(void**)&pPhaseCheckFileInfo)!= -1 &&
		pPhaseCheckFileInfo != NULL
	    )
	{
		pBMFileInfo->bLoadCodeFromFile = FALSE;
		_tcscpy(pBMFileInfo->szFileID,_T("ReadSN"));
		_tcscpy(pBMFileInfo->szRepID,pPhaseCheckFileInfo->arrBlock[0].szRepID);
		if(m_Settings.HasPartitionInfo())
		{
		    _tcscpy(pBMFileInfo->szFileType,_T("ReadSN2"));
		}
		else
		{
		    _tcscpy(pBMFileInfo->szFileType,_T("ReadSN"));
		}

		m_ProcMonitor.AddStepDescription(pBMFileInfo->szFileID);

		DWORD dwPhaseCheckSize = pPhaseCheckFileInfo->arrBlock[0].llSize;
		if( dwPhaseCheckSize == 0 || dwPhaseCheckSize > PRODUCTION_INFO_SIZE)
		{
		    dwPhaseCheckSize = PRODUCTION_INFO_SIZE;
		}

		pBMFileInfo->llBase = pPhaseCheckFileInfo->arrBlock[0].llBase;
		pBMFileInfo->llOprSize = dwPhaseCheckSize;
		return TRUE;
	}

	return TRUE;
}

BOOL CDLoader::AddEraseAll(PBMFileInfo pBMFileInfo)
{
	_tcscpy(pBMFileInfo->szFileID,_T("ERASE_ALL"));
	_tcscpy(pBMFileInfo->szFileType, m_Settings.HasPartitionInfo()?_T("EraseFlash2"):_T("EraseFlash"));
	_tcscpy(pBMFileInfo->szRepID, _T("erase_all"));
	pBMFileInfo->llBase = 0x0;
	pBMFileInfo->llOprSize = 0xFFFFFFFF;
	pBMFileInfo->bChangeCode = FALSE;
	pBMFileInfo->bLoadCodeFromFile = FALSE;
	m_ProcMonitor.AddStepDescription(pBMFileInfo->szFileID);
	return TRUE;
}

BOOL CDLoader::AddBackupFiles(PBMFileInfo pBMFileInfo, int &nCount, _BMOBJ *pbj, PFILE_INFO_T pFileInfo)
{
	BOOL bReadPhaseCheck = FALSE;

	std::vector<std::string> agBackupFileID;
	agBackupFileID.clear();
	m_Settings.GetBackupFiles(agBackupFileID);
	for(uint32_t i = 0; i< agBackupFileID.size(); i++)
	{
		std::string strFileID = agBackupFileID[i];
		PFILE_INFO_T pBackupFileInfo = NULL;
		if(
			m_Settings.GetFileInfo(strFileID.c_str(),(void**)&pBackupFileInfo) != -1  && 
			pBackupFileInfo != NULL
		    )
		{

			PBMFileInfo pBMFileInfo2 = pBMFileInfo + nCount;
			pBMFileInfo2->bLoadCodeFromFile = FALSE;
			_tcscpy(pBMFileInfo2->szFileType, m_Settings.HasPartitionInfo()?_T("ReadFlash2"):_T("ReadFlash"));
			_stprintf(pBMFileInfo2->szFileID,_T("_BKF_%s"),pBackupFileInfo->szID);
			_tcscpy(pBMFileInfo2->szRepID, pBackupFileInfo->arrBlock[0].szRepID);
			pBMFileInfo2->llBase = pBackupFileInfo->arrBlock[0].llBase;
			pBMFileInfo2->llOprSize = pBackupFileInfo->arrBlock[0].llSize;
			if( pBMFileInfo2->llOprSize == 0 )
			{
				if(_tcsicmp(strFileID.c_str(),_T("PhaseCheck")) == 0)
				{
					pBMFileInfo2->llOprSize = PRODUCTION_INFO_SIZE;
				}
				else
				{
					sprintf(pbj->szErrorMsg,_T("[%s] Backup size is zero!"),pFileInfo->szID);
					return FALSE;
				}
			}
			m_ProcMonitor.AddStepDescription(pBMFileInfo2->szFileID);
			nCount++;

			if(_tcsicmp(strFileID.c_str(),_T("PhaseCheck"))==0)
			{
				bReadPhaseCheck = TRUE;
			}
		}
	}

	/// only research and upgrade can read sn.
	if(
		!bReadPhaseCheck &&
		m_Settings.IsDoReport() && 
		AddReadSN(pBMFileInfo + nCount)
	   )
	{
		nCount++;
	}
	return TRUE;
}

void CDLoader::ClearMapPBFileBuf()
{
	MAP_FILEBUF_PB::iterator it;
    for(it = m_mapPBFileBuf.begin(); it != m_mapPBFileBuf.end(); ++it)
	{
		EXT_IMG_INFO_PTR pImg = it->second;
		if(pImg != NULL)
		{
			pImg->clear();
			delete pImg;
			it->second = NULL;
		}
	}
    m_mapPBFileBuf.clear();
    m_mapPBInfo.clear();
}
BOOL CDLoader::InitMultiNVBuffer()
{
	if(!m_Settings.IsEnableRFChipType())
	{
		return TRUE;
	}
	std::vector<std::string> agChipName;
	std::vector<DWORD> agChipID;
    int nRFCount = m_Settings.GetAllRFChipName(agChipName,agChipID);
	
	PFILE_INFO_T pFileInfo = NULL;   
	int nCount = m_Settings.GetAllFileInfo((void**)&pFileInfo);
	BOOL bRet = FALSE;
	int i=0;

    //printf("[%s]: Count = %d\n", __func__, nCount);
	for(i = 0; i< nCount; ++i)
	{
	    std::string strFileType = pFileInfo[i].szType;
	    std::string strFileID = pFileInfo[i].szID;
	    std::string strFile = m_Settings.GetDownloadFilePath(strFileID.c_str());
#if 0
        printf("========== %d =========\n", i);
        printf("strFileType = %s\n", strFileType.c_str());
        printf("strFileID = %s\n", strFileID.c_str());
        printf("strFile = %s\n", strFile.c_str());
#endif
	    if(
	            strFile.length() == 0 					||
	            _tcsicmp(strFile.c_str(),FILE_OMIT) == 0 	||
	            pFileInfo[i].isSelByRf != 1
	            )
	    {
            //printf("strFile.length() = %d\n", strFile.length());
            //printf("_tcsicmp(strFile.c_str(),FILE_OMIT) = %d\n", _tcsicmp(strFile.c_str(),FILE_OMIT));
            //printf("pFileInfo[i].isSelByRf = %d, right is 1\n", pFileInfo[i].isSelByRf);
            //printf("continue...\n");
	        continue;
	    }


        //printf("_tcsnicmp >>>\n");
		if (_tcsnicmp(strFileID.c_str(),_T("NV"),2))
		{
			printf(_T("This version just support multi nv,But this is %s file."),strFileID.c_str());
			return FALSE;
		}

	    std::vector<std::string> agFilePathInfo;
	    if(!GetFilePathInfo(strFile.c_str(),agFilePathInfo))
	    {
	        printf(_T("GetFilePathInfo [%s] is invalid!\n"),strFile.c_str());
	        ClearMultiNVMap();
	        return FALSE;
	    }

		std::string strFileName = agFilePathInfo[1];
		std::string strFilePre;	//prefix_RFNAME_*nvitem.bin ->prefix
		std::string strRFChips;


        //printf("[%s]: strFileName = %s\n", __func__, strFileName);
		for(int i = 0; i< nRFCount; ++i)
		{
			std::string strChipName = _T("_") + agChipName[i] + _T("_");

			int nIndex = strFileName.find(strChipName.c_str());
			if (nIndex != -1 && -1 != strFileName.find(g_sz_NVITEM))
			{
				strFilePre = strFileName.substr(0,nIndex);
				break;
			}
		}

		if(strFilePre.empty())
		{
			std::string strTmp = _T("");
			for(int j = 0; j< nRFCount; j++)
			{
				strTmp += agChipName[j];
				strTmp += _T("\n");
			}

			printf(_T("There are no nv files matching with \"prefix_rfname_*nvitem.bin\":\n%s"),strTmp.c_str());

			return FALSE;	
		}

		std::string strExt =    agFilePathInfo[2];
		//prefix_RFNAME_*nvitem.bin ->RFNAME
		std::string strFind1st = Format(_T("%s_"),strFilePre.c_str()) ;
		std::string strFind2nd = Format(_T("_%s%s"),g_sz_NVITEM,strExt.c_str()) ;

		GetExePath helper;
		std::string strCurrentDir = helper.getExeDir();
		strCurrentDir.insert(0,"/");
		DIR*dir;
		chdir(agFilePathInfo[0].c_str());
		dir=opendir(agFilePathInfo[0].c_str());
		dirent *ptr;
		struct stat stStatBuf;

        printf("readdir...\n");
		while( ptr=readdir(dir) )
	        {
	            if( stat(ptr->d_name,&stStatBuf) ==-1 )
	            {
	                continue;
	            }
	            if( stStatBuf.st_mode &S_IFREG)
	            {
	            	std::string strFindFileName( ptr->d_name);
	                if(_tcsnicmp( ptr->d_name,strFind1st.c_str(),strFind1st.size()) == 0 && -1!=strFindFileName.find(strFind2nd.c_str()))
	                {

					//prefix_RFNAME_*nvitem.bin ->RFNAME
					std::string strRFName = strFindFileName.substr(strFind1st.length(),strFindFileName.find(strFind2nd.c_str())-strFind1st.length());
					if (-1 != strRFName.find(_T("_")))
					{
						strRFName = strRFName.substr(0,strRFName.find(_T("_")));
					}
					DWORD dwRFChipID = 0;
					if (m_Settings.GetRFChipID(strRFName.c_str(),dwRFChipID))
					{
						std::string strFindFile =Format(_T("%s/%s"),agFilePathInfo[0].c_str(),ptr->d_name);

						BACKUP_INFO_PTR pNVInfo = new BACKUP_INFO;
						if (NULL == pNVInfo)
						{
							printf(_T("New buf fail in InitMultiNVBuffer."));
							return FALSE;	
						}

						FILE *pFile = fopen(strFindFile.c_str(),"rb");
						if(pFile == NULL)
						{
							printf(_T("Load file [%s] fail\n."),strFindFile.c_str());
						    return FALSE;
						}
						fseek(pFile,0,SEEK_END);
						pNVInfo->dwSize = ftell(pFile);
						fseek(pFile,0,SEEK_SET);
						if(pNVInfo->dwSize != 0 )
						{
						    	pNVInfo->pBuf = new BYTE[pNVInfo->dwSize];
						    	fread(pNVInfo->pBuf,1,pNVInfo->dwSize,pFile);
						}
						fclose(pFile);
						_tcscpy(pNVInfo->szNVFile,strFindFile.c_str());
						m_mapMultiNVInfo[std::make_pair(dwRFChipID,strFileID)] = pNVInfo;
					}
	                }
			}

	    }
	    closedir(dir);
	    chdir(strCurrentDir.c_str());
	}
    
    // Allen 2020-9-10

	return TRUE;
}

BOOL CDLoader::InitMapPBFileBuf()
{
	BOOL bRet = FALSE;
	/*clear m_mapPBFileBuf map*/
	ClearMapPBFileBuf();

	if(!m_Settings.IsMapPBFileBuf())
	{
		return TRUE;
	}

	PFILE_INFO_T pFileInfo = NULL;   
	int nCount = m_Settings.GetAllFileInfo((void**)&pFileInfo);

	int i=0;

	int nPBFileCount = 0;
    for(i = 0; i< nCount; ++i)
    {
        std::string strFileType = pFileInfo[i].szType;
        std::string strFileID = pFileInfo[i].szID;
        std::string strFile = m_Settings.GetDownloadFilePath(strFileID.c_str());
        if(
                strFile.length() == 0 					||
                _tcsicmp(strFile .c_str(),FILE_OMIT) == 0 	||
                pFileInfo[i].isSelByFlashInfo != 1
                )
        {
            continue;
        }

        std::vector<std::string> agFilePathInfo;
        if(!GetFilePathInfo(strFile.c_str(),agFilePathInfo))
        {
            printf(_T("GetFilePathInfo [%s] is invalid!\n"),strFile.c_str());
            ClearMapPBFileBuf();
            return FALSE;
        }
        std::string strFileName = agFilePathInfo[1];

        int  nIndex = strFileName.find(_T("_b"));
        if(nIndex == -1)
        {
            printf(_T("The name of file [%s] is invalid!\nFile name must be \"xxx_bnk_pmk.yyy\", n and m is a number.\n"),strFile.c_str());
            ClearMapPBFileBuf();
            return FALSE;
        }

        ++nPBFileCount;

        std::string strExt =    agFilePathInfo[2];
        std::string strFilePre = strFileName.substr(0,nIndex);
        //std::string strFind = Format(_T("%s/%s_b*%s"),agFilePathInfo[0].c_str(),strFilePre.c_str(),strExt.c_str()) ;
        std::string strFind = Format(_T("%s_b"),strFilePre.c_str()) ;




        //char buf[200];
        //getcwd(buf, sizeof(buf)-1);
        GetExePath helper;
	std::string strCurrentDir = helper.getExeDir();
	strCurrentDir.insert(0,"/");
        DIR*dir;
        chdir(agFilePathInfo[0].c_str());
        dir=opendir(agFilePathInfo[0].c_str());
        dirent *ptr;
        struct stat stStatBuf;
        while( ptr=readdir(dir) )
        {
            if( stat(ptr->d_name,&stStatBuf) ==-1 )
            {
                continue;
            }
            if( stStatBuf.st_mode &S_IFREG)
            {
                if(_tcsnicmp( ptr->d_name,strFind.c_str(),strFind.size()) == 0 )
                {
                    std::string strFindFileName(ptr->d_name);
                    std::string strPBInfo =strFindFileName.substr(0,strFindFileName.size() - strExt.size());
                    strPBInfo = strPBInfo.substr(strFilePre.size(),strPBInfo.size()-strFilePre.size());

                    std::string strFindFile =Format(_T("%s/%s"),agFilePathInfo[0].c_str(),ptr->d_name);
                    EXT_IMG_INFO_PTR pImg = LoadPageBlockFile(strFindFile.c_str());
                    if( NULL == pImg)
                    {
                        ClearMapPBFileBuf();
                        closedir(dir);
                        chdir(strCurrentDir.c_str());
                        return FALSE;
                    }

                    m_mapPBFileBuf[std::make_pair(strPBInfo,strFileID)] = pImg;



                    DWORD dwPBCount = 0;
                    MAP_STRINT::iterator itPBInfo;

                    itPBInfo = m_mapPBInfo.find(strPBInfo);

                    if(itPBInfo !=m_mapPBInfo.end())
                    {
                        dwPBCount = itPBInfo->second + 1;
                    }
                    else
                    {
                        dwPBCount = 1;
                    }
                    m_mapPBInfo[strPBInfo]=dwPBCount;

                }

            }

        }
        closedir(dir);
        chdir(strCurrentDir.c_str());
    }


    return TRUE;
}
EXT_IMG_INFO_PTR CDLoader::LoadPageBlockFile(LPCTSTR lpszFile)
{
	EXT_IMG_INFO_PTR pImg = NULL;
	int 	fd = -1;
	DWORD 	dwFileSize = 0;
	BOOL 	bRet = FALSE;
	do
	{
		if( lpszFile == NULL )		break;
		fd = open(lpszFile,O_RDONLY,00777);
		if( fd == -1)
		{
			printf("CDLoader::LoadPageBlockFile [%s] open failed.\n",lpszFile);
		   	break;
		}

		dwFileSize = lseek(fd,0,SEEK_END);
		lseek(fd,0,SEEK_SET);

		if( dwFileSize == INVALID_FILE_SIZE)
		{
			printf("CDLoader::LoadPageBlockFile GetFileSize [%s] failed.\n",lpszFile);
			break;
		}
		pImg = new EXT_IMG_INFO;
		if( NULL == pImg )
		{
		    	break;
		}
		pImg->bIsFileMap = TRUE;
		pImg->fd = fd;
		pImg->dwSize = dwFileSize;
		_tcscpy(pImg->szFilePath,lpszFile);
		//printf("CDLoader::LoadPageBlockFile [%s] size=%d....\n",lpszFile,dwFileSize);
		///
		DWORD dwMapSize = dwFileSize;

		if( dwMapSize > MAX_MAP_SIZE )
		{
		    dwMapSize = MAX_MAP_SIZE;
		}
		void* lpCode = mmap( NULL, dwMapSize, PROT_READ,MAP_SHARED, fd, 0);
		if( lpCode == NULL)
		{
			printf("CDLoader::LoadPageBlockFile mmap [%s] failed",lpszFile);
			break;
		}
		pImg->pBuf = (LPBYTE)lpCode;

		pImg->dwFirstMapSize=dwMapSize;

		/*void* lpCode = mmap( NULL, dwFileSize, PROT_READ,MAP_SHARED, fd, 0);
		if( lpCode == NULL)
		{
			printf("CDLoader::LoadPageBlockFile mmap [%s] failed",lpszFile);
			break;
		}

		pImg->pBuf = new BYTE[ dwFileSize ];
		if(pImg->pBuf == NULL)
		{
			printf("CDLoader::new buffer failed");
			break;
		}
		memcpy( pImg->pBuf, lpCode, dwFileSize);
		
		munmap(lpCode,dwFileSize);
		close(fd);
		*/
		bRet = TRUE;
		
	}while(0);

	if(!bRet)
	{
		if(-1 != fd)
		{
			close(fd);
			fd = -1;
		}
		if(pImg)
		{
			pImg->clear();
			delete pImg;
			pImg = NULL;
		}
	}

	return pImg;
}

std::string CDLoader::Format(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);

    const size_t SIZE = 1024;
    char buffer[SIZE] = { 0 };
    vsnprintf(buffer, SIZE, fmt, ap);

    va_end(ap);

    return std::string(buffer);
}

BOOL CDLoader::GetFilePathInfo(LPCTSTR szFile,std::vector<std::string> &agInfo)
{
	
	BOOL bRet = FALSE;
	agInfo.clear();
    std::string strFile(szFile);
	int nPos = strFile.rfind('/');
    if( -1 != nPos && strFile.size()>nPos+1 )
	{
	    std::string strPath = strFile.substr(0,nPos);
	    std::string strName = strFile.substr(nPos+1,strFile.size()-strPath.size());
	    std::string strExt;
	    int nPos = strName.rfind('.');
        if(-1 != nPos )
	    {
	      strExt = strName.substr(nPos);
	      strName = strName.substr(0,nPos);
          agInfo.push_back(strPath);
          agInfo.push_back(strName);
          agInfo.push_back(strExt);
          bRet = TRUE;
	    }
	}
	return bRet;
}

void CDLoader::CheckPort2ndEnum()
{	
	printf("%s: Check...\n", __func__);
	m_bPortSecondEnum 	= FALSE;
	PFILE_INFO_T pFileInfo 	= NULL;
	DWORD 	dwSize 			= 0;
	BYTE*	pBuf 			= NULL;
	FILE *	pFile 			= NULL;
	const char szFlag[] 	= "##PORT-SECOND-ENUM##";
	std::string strFDLFile = m_Settings.GetDownloadFilePath(_T("FDL"));
	do
	{

		pFile = fopen(strFDLFile.c_str(),"rb");
        	if(pFile == NULL)						break;	
		fseek(pFile,0,SEEK_END);
       	dwSize = ftell(pFile);
		if(dwSize == 0 )						break;
      		fseek(pFile,0,SEEK_SET);
		pBuf = new BYTE[dwSize];
		if(NULL == pBuf)						break;
		 fread(pBuf,1,dwSize,pFile);
	}while(0);

	if (pFile)
	{
		fclose(pFile);
		pFile = NULL;
	}
	if(pBuf)
	{
		BYTE* lpPos = NULL;
		lpPos = std::search( pBuf,pBuf + dwSize,szFlag,szFlag + strlen( szFlag ));
		if(lpPos < (pBuf + dwSize) )
		{
			m_bPortSecondEnum = TRUE;
		}		
    		delete [] pBuf;
	}

}

BOOL CDLoader::LoadFileFromLocal(LPCTSTR pszFileName, LPBYTE &pBuf, DWORD &dwSize, __int64 llSize ,  __int64 llOffset )
{	
    FILE *pFile = fopen(pszFileName,_T("rb"));
    if(pFile == NULL)
        return FALSE;
	if (llSize)
	{
		dwSize = (DWORD)llSize;
	}
	else
	{
		fseek(pFile,0,SEEK_END);
		dwSize = ftell(pFile);
		fseek(pFile,0,SEEK_SET);
	}

	if (llOffset)
	{
		fseek(pFile,(long)llOffset,SEEK_SET);
	}

    pBuf = new BYTE[dwSize];
    if(pBuf == NULL)
        return FALSE;

    DWORD dwRead = fread(pBuf,1,dwSize,pFile);
    fclose(pFile);

    if(dwRead != dwSize)
    {
        SAFE_DELETE_ARRAY(pBuf);
        return FALSE;
    }

    return TRUE;
}

BOOL CDLoader::CheckPacKey()
{
    BOOL bRet    = TRUE;
    LPBYTE pBuf  = NULL;  
    DWORD dwSize = 0;
    DUT_KEY_T stDutKey;
    m_bPacHasKey = FALSE;
    do 
    {
        std::string strFile = m_Settings.GetDownloadFilePath(_T("UBOOTLoader"));
	  struct stat stat_file;
        if(stat(strFile.c_str(),&stat_file) == -1)
        {
            break;
        }
        if (!LoadFileFromLocal(strFile.c_str(),pBuf,dwSize))
        {
            break;
        }
        if (GetDUTKeyInfo(pBuf,dwSize,stDutKey))
        {
            std::string strError;
            if ('1' == stDutKey.ver[0] && 0 == stDutKey.ver[1] && 0 == stDutKey.ver[2] && 0 == stDutKey.ver[3] && strlen(stDutKey.szDUTKey) )
            {
                m_bPacHasKey = TRUE;
            }
            else
            {
                bRet = FALSE;
		   printf(_T("This download tool just support 0.0.0.1 DUT key version,but this DUT key version is %c.%c.%c.%c,Please upgrade download tool.\n"),
                    stDutKey.ver[3],stDutKey.ver[2],stDutKey.ver[1],stDutKey.ver[0]);

            }
        }
    } while (0);
    
    SAFE_DELETE_ARRAY(pBuf);
    return bRet;
    
}

BOOL CDLoader::GetDUTKeyInfo(LPBYTE pBuf, DWORD dwSize,DUT_KEY_T& stDutKey)
{
    BOOL bRet = FALSE;
    const char szStartFlag[] = "###DUT_KEY_BEGIN$$$";
    const char szEndFlag[]   = "###DUT_KEY_END$$$";
    memset(&stDutKey,0,sizeof(DUT_KEY_T));
    if (NULL == pBuf || dwSize < sizeof(DUT_KEY_T))
    {
        return FALSE;
    }
    BYTE* lpPos = NULL;
    BYTE* lpBeginPos = NULL;
    BYTE* lpEndPos = NULL;
    BYTE* lpTmpPos = pBuf;

    do 
    {
        lpPos = std::search( lpTmpPos,lpTmpPos + dwSize,szStartFlag,szStartFlag + strlen( szStartFlag ) );
        if(lpPos < (lpTmpPos + dwSize) )
        {
            lpBeginPos = lpPos;
            lpPos = std::search( lpBeginPos,lpBeginPos + (dwSize-(lpBeginPos-pBuf)),szEndFlag,szEndFlag + strlen( szEndFlag )  );
            if(lpPos < (lpBeginPos + (dwSize-(lpBeginPos-pBuf))))
            {
                lpEndPos = lpPos;
                if (lpEndPos - lpBeginPos < sizeof(DUT_KEY_T)+ strlen(szStartFlag))
                {
                    break;
                }
                memcpy(&stDutKey,lpBeginPos+strlen( szStartFlag ),sizeof(DUT_KEY_T));
                bRet = TRUE;
                break;

            }
        }
    } while(lpPos < (lpTmpPos + dwSize));

    return bRet;
}
