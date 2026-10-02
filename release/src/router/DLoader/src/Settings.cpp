#include "Settings.h"
#include "BinPack.h"
#include "XmlConfigParse.h"
#include <algorithm>
#include "ExePathHelper.h"
#include "Calibration.h"
extern "C"
{
   #include "confile.h"
}


CSettings::CSettings()
{
	//ctor
	m_strCurProduct 	= "";
	m_strSpecConfig 	= "";
	m_strReleaseDir 	= "";
	m_strPrdVersion 	= "";
	m_pCurProductInfo 	= NULL;

	m_bReset 			= FALSE;
	m_bKeepCharge 		= FALSE;
	m_bRepart 			= TRUE;
	m_bNvBkFlg 			= TRUE;
	m_bFileBkFlg 			= TRUE;
	m_bNeedPhaseCheck	= FALSE;
	m_bOmaDM 			= TRUE;
	m_bPowerOff			= FALSE;
	m_bEnableWriteFlash 	= FALSE;
	m_dwMaxNVLength		= 0x40000;
	m_nReplacePolicy		= 0;
	m_nBackupProdnvMiscdata=0;
	LoadConfigFile();
}

CSettings::~CSettings()
{
    //dtor
    if(m_pCurProductInfo)
    {
        m_pCurProductInfo->Clear();
        delete m_pCurProductInfo;
    }
}

void CSettings::LoadConfigFile()
{

	INI_CONFIG *config 	= NULL;
	GetExePath helper;
	std::string strIniPath = helper.getExeDir();
	strIniPath.insert(0,"/");
	strIniPath += "BMFileType.ini";

	config = ini_config_create_from_file(strIniPath.c_str(),0);
	if (NULL == config)
	{
		return ;
	}
	m_dwMaxNVLength = ini_config_get_int(config,_T("DownloadNV"),_T("MaxReadLength"), 0x40000);
	m_bEnableWriteFlash = ini_config_get_int(config,_T("ReadDUTInfo"),_T("EnableWriteFlash"), 0);
	g_nGSMCaliVaPolicy =  ini_config_get_int(config,_T("DownloadNV"),_T("GSMCaliVaPolicy"), 0);
	ini_config_destroy(config);
}

BOOL CSettings::LoadSettings(std::string &strErrorMsg)
{
    return TRUE;
}

void CSettings::SetReplaceDLFiles(std::map<std::string,std::string>& mapReplaceDLFile)
{
	printf("[%s]: enter.\n", __func__);
	if( 0 == mapReplaceDLFile.size() )
	{
	    printf("[%s]: mapReplaceDLFile.size = 0. error return\n", __func__);
		return;
	}
	
	std::map<std::string,std::string>::iterator it;
	for(it = m_mapDLFiles.begin(); it != m_mapDLFiles.end(); it++)
	{
		TCHAR szID[MAX_PATH] = {0};
		std::string strID = it->first;
		std::string strOrgFile = it->second;
		if(0 == m_nReplacePolicy)
		{
			if( _tcsicmp(strID.c_str(),_T("FDL")) && _tcsicmp(strID.c_str(),_T("FDL2")) )
			{
				m_mapDLState[strID] = FALSE;
			}
		}

		strcpy(szID,strID.c_str());		
		std::map<std::string,std::string>::iterator iter;
		iter = mapReplaceDLFile.find(strupr(szID));
		if( iter!= mapReplaceDLFile.end() )
		{
			std::string strNewFile = iter->second;
			if(!strNewFile.empty())
			{
				printf("ORG %s = %s.\n",strID.c_str(),strOrgFile.c_str());
				m_mapDLFiles[strID] = strNewFile;
				printf("NEW %s = %s.\n",strID.c_str(),strNewFile.c_str());
			} else {
				printf("[%s]: strNewFile is empty.\n", __func__);
            }
			m_mapDLState[strID] = TRUE;
		}
	}

}

BOOL CSettings::LoadPacket(LPCTSTR pFileName)
{
    CBinPack bp;

    BIN_PACKET_HEADER_T bph;

    FILE_T *paFile = NULL;
    BOOL bOK = bp.Unpacket(pFileName,NULL,bph,&paFile);
    m_strReleaseDir = bp.GetReleaseDir();
    m_strSpecConfig = bp.GetConfigFilePath();

    if(!bOK)
    {
        if(paFile != NULL)
        {
            delete [] paFile;
            paFile = NULL;
        }
        return FALSE;
    }

   // printf("clear mapDLFiles.clear mapDLState.clear mapDLSize.clear =================================================\n ");
#if 1
    m_mapDLFiles.clear();
    m_mapDLState.clear();
    m_mapDLSize.clear();
#endif

    m_strCurProduct = (char*)bph.szPrdName;

    char * pStr = strstr((char*)bph.szPrdName,"PAC_");
    if(pStr != NULL)
    {
        m_strCurProduct = ((char*)bph.szPrdName) + 4;
    }

    m_strPrdVersion = (char*)bph.szPrdVersion;

    std::string strAlias= (char*)bph.szPrdAlias;

    if(strAlias.length() != 0)
    {
        pStr = strstr((char*)bph.szPrdName,"PAC_");
        if(pStr != NULL)
        {
            strAlias = ((char*)bph.szPrdName) + 4;
        }
    }

    FILE_T * pFT = NULL;


    BOOL bNvFileSelected = FALSE;
    BOOL bFlashSelected = FALSE;
    BOOL bPhaseCheckSelected = FALSE;
    BOOL bExistPhaseCheck = FALSE;
    BOOL bFlashExisted = FALSE;

    int nAllowOmit = 0;
    int nRealFileCount = 0;

    int nNVIndex = -1;

    for(int i = 0; i< bph.nFileCount; i++)
    {
        pFT = paFile + i;
	  __int64 liImageSize = pFT->dwHiFileSize;
	  liImageSize = liImageSize << 32;
	  liImageSize = liImageSize |pFT->dwLoFileSize;
        std::string strID = (char*)pFT->szFileID;
        transform(strID.begin(), strID.end(), strID.begin(), toupper);
        m_mapDLFiles[strID] = (char*)pFT->szFileName;
        m_mapDLState[strID] = pFT->nCheckFlag;
        m_mapDLSize[strID] = liImageSize;
        const char *pID = strID.c_str();
#if 0
        printf("[%s]: i = %d, ID = %s\n", __func__, i, pID);
        printf("m_mapDLFiles =  %s\n", (char*)pFT->szFileName);
        printf("m_mapDLState =  %d\n", pFT->nCheckFlag);
        printf("m_mapDLSize =  %lld\n", liImageSize);
        printf("[%s]: i = %d, ID = %s\n", __func__, i, pID);
        printf("%s\t%d\t%lld\n", (char*)pFT->szFileName, pFT->nCheckFlag, liImageSize);
#endif

        if(pFT->dwCanOmitFlag == 1)
        {
            nAllowOmit++;
        }

        if(strstr(pID, _T("NV")) == pID)
        {
            nNVIndex = i;
        }
        else if(strcasecmp(pID,_T("PhaseCheck")) == 0)
        {
            bExistPhaseCheck = TRUE;
        }
	 else if(strstr(pID, _T("FLASH")) == pID)
        {
            bFlashExisted = TRUE;
        }


        if(pFT->nCheckFlag && (_tcslen((char*)pFT->szFileName) != 0 || pFT->nFileFlag == 0 ))
        {
            nRealFileCount++;


            if(strstr(pID,_T("NV")) == pID)
            {
                bNvFileSelected = TRUE;
            }
            else if(strstr(pID,_T("FLASH")) ==pID)
            {
                bFlashSelected = TRUE;
            }
            else if(strcasecmp(strID.c_str(),_T("PhaseCheck")) == 0)
            {
                bPhaseCheckSelected = TRUE;
            }

            if(pFT->dwCanOmitFlag == 1)
            {
                nAllowOmit--;
            }
        }
        else
        {
            m_mapDLFiles[strID] =_T("");
        }
    }

    bp.ReleaseMem(paFile);

    BOOL bAllFileDown = FALSE;

    if( (bph.nFileCount - nRealFileCount) == nAllowOmit )
    {
        bAllFileDown = TRUE;
    }

    BOOL bRepartition = FALSE;
    if (bph.dwNandStrategy == REPAR_STRATEGY_ALWAYS || bph.dwNandStrategy ==REPAR_STRATEGY_DO)
        bRepartition = TRUE;

#if defined(_SPUPGRADE) || defined(_DOWNLOAD_FOR_PRODUCTION)
    BOOL bNand = (BOOL)(bph.dwFlashType);
#endif

    if(bFlashExisted && !bFlashSelected)
    {
        printf(_T("Configure dangerouse: have not selected to earase runtime-nv.\nPlease select right packet!"));
        return FALSE;
    }

#if defined(_SPUPGRADE)
    BOOL bBackupNV = (BOOL)(bph.dwIsNvBackup);

    if(!bNvFileSelected)
    {
        printf(_T("Configure dangerouse: have not selected NV file to dwonload.\nPlease select right packet!"));
        return FALSE;
    }

    /* bNvFileSelected = TRUE */
    if( !bBackupNV )
    {
        printf(_T("Configure dangerouse: have not selected any NV item to backup.\nPlease select right packet!"));
        return FALSE;
    }


    if(!bAllFileDown)
    {
        if(bNand && bRepartition)
        {
            printf(_T("Configure dangerouse: have selected repartition,\nbut not selected all files to download.\nPlease select right packet!"));
            return FALSE;
        }
        else
        {
            // allow to download part files. but prompt the warning.
            printf(_T("Configure dangerouse: have not selected all files to dwonload."));
        }
    }
    else
    {
        if(bNand && bRepartition && !bBackupNV)
        {
            printf(_T("Configure dangerouse: have selected repartition,\nbut not selected all files to download.\nPlease select right packet!"));
            return FALSE;
        }
    }

#endif

#if defined(_DOWNLOAD_FOR_PRODUCTION)
    /* bph.dwIsNvBackup must be false(0) */
    if (bp.IsExistEmptyFile() && !bAllFileDown)
    {
        printf(_T("Configure dangerouse: exist empty file in package which should not occur in production download.\nPlease select right packet!"));
        return FALSE;
    }
    if (bExistPhaseCheck && !bPhaseCheckSelected)
    {
        printf(_T("Configure dangerouse: no PhaseCheck information in package which should not occur in production download.\nPlease select right packet!"));
        return FALSE;
    }
    if(!bAllFileDown)
    {
        if(bNand && bRepartition)
        {
            printf(_T("Configure dangerouse: have selected repartition,\nbut not selected all files to download.\nPlease select right packet!"));
            return FALSE;
        }
        else
        {
            // allow to download part files. but prompt the warning.
            printf(_T("Configure dangerouse: have not selected all files to dwonload."));
        }
    }

#endif

    memcpy(&m_bph,&bph,sizeof(bph));


    if(strAlias.length() == 0)
        printf(_T("%s : %s\n\n"),m_strCurProduct.c_str(),m_strPrdVersion.c_str());
    else
        printf(_T("%s : %s\n\n"),strAlias.c_str(),m_strPrdVersion.c_str());

    return TRUE;
}

BOOL CSettings::LoadConfig()
{
	CXmlConfigParse parse;
	if(!parse.Init(m_strSpecConfig.c_str(),0))
	{
	    printf(_T("LoadConfig: init failed.\n"));
	    return FALSE;
	}

	PPRODUCT_INFO_T pTmp =  parse.GetProdInfo(m_strCurProduct.c_str());

	if(pTmp == NULL)
	    return FALSE;

	m_pCurProductInfo = new PRODUCT_INFO_T;

	m_pCurProductInfo->DeepCopy(pTmp);

	if(m_pCurProductInfo != NULL)
	{
		if(m_pCurProductInfo->dwOmaDMFlag != 0)
		{
			std::string strFile;
			std::map<std::string,std::string>::iterator itFile;
        		itFile = m_mapDLFiles.find("FDL2");
			if(itFile !=m_mapDLFiles.end())
			{
				strFile = itFile->second;
				m_bOmaDM = GetFdl2Flag(strFile.c_str(),FDL2F_OMADM);
			}				
			
		}
	}
	

	InitBackupFiles(m_pCurProductInfo->pFileInfoArr,m_pCurProductInfo->dwFileCount);

#if 0
	PRODUCT_INFO_T t;
	t.DeepCopy(pTmp);
	t.Clear();
#endif

	return TRUE;

}

BOOL CSettings::GetFdl2Flag(LPCTSTR lpszFilePath,UINT nType)
{

	if(lpszFilePath == NULL || _tcslen(lpszFilePath) == 0)
	{
		return TRUE;
	}
	FILE *pFile 	= NULL;
	BOOL  bOK 	= FALSE;
	LPBYTE lpContent	= NULL;
	int nLen		=0;
	do
	{
		pFile = fopen(lpszFilePath,"rb");
		if(NULL == pFile)
		{
			break;
		}
		fseek(pFile,0,SEEK_END);
		nLen = ftell(pFile);
		fseek(pFile,0,SEEK_SET);
		lpContent = new BYTE[nLen];
		if(lpContent == NULL)
		{
			break;
		}
		DWORD dwRead = fread(lpContent,1, nLen,pFile);
		if(dwRead != nLen)
		{
			break;
		}
		const char szOmadm[] = "#$DEVICE_MANAGER$#";
		const char szPreload[] = "#*PRELOADSUPPORT*#";
		const char szKernelImg2[]="#*DEMANDPAGING*#";
		const char szRomDisk[]= "#*USBCOMAUTORUN*#";

	   	BYTE* lpPos = NULL;
		if(nType == FDL2F_OMADM)
		{
			lpPos = std::search( lpContent,lpContent + nLen,szOmadm,szOmadm + strlen( szOmadm ) - 1 );
		}
		else if(nType == FDL2F_PRELOAD)
		{
			lpPos = std::search( lpContent,lpContent + nLen,szPreload,szPreload + strlen( szPreload ) - 1 );
		}
		else if(nType == FDL2F_KERNELIMG2)
		{
			lpPos = std::search( lpContent,lpContent + nLen,szKernelImg2,szKernelImg2 + strlen( szKernelImg2 ) - 1 );
		}
		else if(nType == FDL2F_ROMDISK)
		{
			lpPos = std::search( lpContent,lpContent + nLen,szRomDisk,szRomDisk + strlen( szRomDisk ) - 1 );
		}
		else
		{
			break;
		}
		if( lpPos != lpContent + nLen )
		{
			bOK = TRUE;
		}

	}while(0);

	
	if(NULL != lpContent)
	{
		delete []lpContent;
		lpContent = NULL;
	}
	if(NULL != pFile)
	{
		fclose(pFile);
		pFile = NULL;
	}

	return bOK;
	
}

int  CSettings::GetDownloadFile( std::vector<std::string>& agFile )
{
    agFile.clear();
    if(m_pCurProductInfo == NULL)
        return 0;

    UINT nCount = m_pCurProductInfo->dwFileCount;
    for(UINT i = 0;i<nCount;i++)
    {
        std::string strID = m_pCurProductInfo->pFileInfoArr[i].szID;
	 transform(strID.begin(), strID.end(), strID.begin(), toupper);
        BOOL bCheck = FALSE;
        std::string strFile;

        std::map<std::string,std::string>::iterator it;
        it = m_mapDLFiles.find(strID);
        if(it != m_mapDLFiles.end() )
        {
            strFile = it->second;
        }

        std::map<std::string,UINT>::iterator it2;
        it2 = m_mapDLState.find(strID);
        if(it2 != m_mapDLState.end() )
        {
            bCheck  = it2->second;
        }

        if(bCheck)
        {
            agFile.push_back(strFile);
        }
        else
        {
            agFile.push_back(FILE_OMIT);
        }
    }
    return nCount;
}

int	CSettings::GetAllRFChipName(std::vector<std::string>& agChipNames,std::vector<DWORD> &agChipIDs)
{
	agChipNames.clear();
	agChipIDs.clear();
	if(IsEnableRFChipType())
	{
		for(UINT i = 0 ; i< m_pCurProductInfo->tRfChips.dwCount; ++i)
		{
			agChipNames.push_back(m_pCurProductInfo->tRfChips.pChips[i].szName);
			agChipIDs.push_back(m_pCurProductInfo->tRfChips.pChips[i].dwID);
		}
	}

	return agChipNames.size();
}

BOOL     CSettings::GetRFChipName(const DWORD& dwChipID, std::string& strName)
{
	strName.clear();
	if(IsEnableRFChipType())
	{
		for(UINT i = 0 ; i< m_pCurProductInfo->tRfChips.dwCount; i++)
		{
			if(dwChipID==m_pCurProductInfo->tRfChips.pChips[i].dwID)
			{
				strName = m_pCurProductInfo->tRfChips.pChips[i].szName;
				return TRUE;
			}			
		}
	}
	return FALSE;
}
 BOOL	CSettings::GetRFChipID(const std::string& strName,DWORD& dwChipID)
{
	BOOL bOK = FALSE;
	if(IsEnableRFChipType())
	{
		for(UINT i = 0 ; i< m_pCurProductInfo->tRfChips.dwCount; i++)
		{
			if(0 == _tcsicmp(strName.c_str(),m_pCurProductInfo->tRfChips.pChips[i].szName))
			{
				dwChipID = m_pCurProductInfo->tRfChips.pChips[i].dwID;
				return TRUE;
			}			
		}
	}
	return bOK;
}
 
int  CSettings::GetRepartitionFlag()
{
    return REPAR_STRATEGY_ALWAYS;
}
int  CSettings::GetFlashPageType()
{
    return (int)m_bph.dwFlashType;
}

int  CSettings::GetFileInfo(LPCTSTR lpszFileID, void** ppFileInfo)
{
    if(lpszFileID == NULL)
    {
        return -1;
    }

    int nCount = 0;
    PFILE_INFO_T pFileInfo = NULL;

    if(m_pCurProductInfo == NULL)
    {
        return -1;
    }
    nCount = m_pCurProductInfo->dwFileCount;
    pFileInfo= m_pCurProductInfo->pFileInfoArr;


    int i=0;
    for(i = 0;i<nCount;i++)
    {
        if( strcasecmp(pFileInfo[i].szID,lpszFileID)==0)
        {
            if(ppFileInfo!= NULL)
                *ppFileInfo = (void*)(pFileInfo+i);
            break;
        }
    }

    if(i>=nCount)
        return -1;
    else
        return i;
}

std::string CSettings::GetDownloadFilePath(LPCTSTR lpszFileID)
{
    std::string strID = lpszFileID;
    std::string  strPath;
    BOOL    bCheck = FALSE;

    transform(strID.begin(), strID.end(), strID.begin(), toupper);
    std::map<std::string,UINT>::iterator it2;
    it2 = m_mapDLState.find(strID);
    if(it2 != m_mapDLState.end() )
    {
        bCheck  = it2->second;
    }

    if(bCheck)
    {
        std::map<std::string,std::string>::iterator it;
        it = m_mapDLFiles.find(strID);
        if(it != m_mapDLFiles.end() )
        {
            strPath = it->second;
        } else {
            printf("[%s]: m_mapDLFiles not find.\n");
        }
        return strPath;
    }
    else
    {
        return FILE_OMIT;
    }
}

int CSettings::GetNvBkpItemCount()
{
    if(m_pCurProductInfo)
    {
        return m_pCurProductInfo->dwNvBackupItemCount;
    }
    else
    {
        return 0;
    }
}

PNV_BACKUP_ITEM_T CSettings::GetNvBkpItemInfo(int nIndex)
{
	if(m_pCurProductInfo && nIndex>=0 && nIndex < m_pCurProductInfo->dwNvBackupItemCount)
	{
		return m_pCurProductInfo->paNvBackupItem + nIndex;
	}
	else
	{
		return 0;
	}
}

BOOL CSettings::IsNandFlash()
{
    if(m_pCurProductInfo && m_pCurProductInfo->dwFlashType >0)
    {
        return TRUE;
    }
    else
    {
        return FALSE;
    }
}

BOOL CSettings::IsBackupNV()
{
	if(!m_bNvBkFlg)
	{
		return FALSE;
	}
	std::vector<std::string> agID;
	int nCount = GetDLNVID(agID);
	if(nCount == 0)
		return FALSE;

	int nNvBkpItmChkCount = 0;

	for(int i = 0; i< m_pCurProductInfo->dwNvBackupItemCount; i++)
	{
		if(m_pCurProductInfo->paNvBackupItem[i].wIsBackup)
		{
		    	nNvBkpItmChkCount++;
		}
	}

	return ( nNvBkpItmChkCount > 0);
}
BOOL CSettings::IsNvBaseChange()
{
    if(m_pCurProductInfo != NULL &&
        m_pCurProductInfo->dwNvBaseChangeFlag == 0)
        return FALSE;
    else
        return TRUE;
}

BOOL CSettings::IsReadFlashInFDL2()
{
    if(!IsNandFlash())
        return FALSE;

    std::vector<std::string> agID;
    if(!IsBackupNV() && GetBackupFiles(agID) == 0)
        return FALSE;

    if(!m_bRepart)
        return FALSE;

    return TRUE;
}

BOOL CSettings::IsNVSaveToLocal()
{
    return FALSE;
}

std::string CSettings::GetNVSavePath()
{
    return "";
}

BOOL CSettings::IsBackupLang()
{
    return FALSE;
}
BOOL CSettings::IsHasLang()
{
    return FALSE;
}
WORD CSettings::GetLangNVItemID()
{
    return 0;
}

BOOL CSettings::IsNVOrgDownload()
{
    if(m_pCurProductInfo == NULL)
        return FALSE;
    if(m_pCurProductInfo->dwNVOrgFlag != 0 && IsOmaDM())
        return TRUE;
    else
        return FALSE;
}
int CSettings::GetNVOrgBasePosition()
{
    if(m_pCurProductInfo == NULL)
        return -1;

    return m_pCurProductInfo->dwNVOrgBasePosition;
}

BOOL CSettings::IsOmaDM()
{
    return m_bOmaDM;//m_pCurProductInfo->dwOmaDMFlag;
}

int CSettings::GetAllFileID(std::vector<std::string> &agFileID)
{
    agFileID.clear();
    for(int i = 0; i< m_pCurProductInfo->dwFileCount; i++)
    {
        agFileID.push_back(m_pCurProductInfo->pFileInfoArr[i].szID);
    }

    return agFileID.size();
}

BOOL CSettings::IsEraseAll()
{
    return FALSE;
}

BOOL CSettings::IsReset()
{
    return m_bReset;
}

void CSettings::SetResetFlag(BOOL bReset)
{
    m_bReset = bReset;
}

BOOL CSettings::IsNeedCheckNV()
{
    return FALSE;
}

int CSettings::GetBackupFiles(std::vector<std::string> &agID)
{
       if(!m_bFileBkFlg)
       {
       	return 0;
       }
	int nCount = _GetBackupFiles(agID,FALSE);
	for(int i =0;i< nCount; i++)
	{
		BOOL bRemove = FALSE;

		BOOL bCheck = TRUE;
		std::string strID = agID[i];
		transform(strID.begin(), strID.end(), strID.begin(), toupper);

		std::map<std::string,UINT>::iterator it;
		it = m_mapDLState.find(strID);
		if(it != m_mapDLState.end() )
		{
		    bCheck  = it->second;
		    bRemove = !bCheck;
		}
		else
		{
		    bRemove = TRUE;
		}

		if(bRemove)
		{
			std::vector<std::string>::iterator it2;
			it2 = agID.begin()+i;
			agID.erase(it2);
			nCount--;
			i--;
		}
	}

	return agID.size();
}

int CSettings::IsBackupFile(LPCTSTR lpszFileID)
{
    if(!m_bFileBkFlg)
    {
    	 return -1;
    }
    std::vector<std::string> agID;
    int nCount = GetBackupFiles(agID);

    for(int i=0; i< nCount; i++)
    {
        if(strcasecmp(agID[i].c_str(),lpszFileID) == 0)
            return i;
    }
    return -1;
}

BOOL CSettings::IsNeedRebootByAT()
{
    return FALSE;
}

void CSettings::GetIMEIIDs(std::vector<UINT> &agID)
{
    /*
    IMEI1=0x5
    IMEI2=0x179
    IMEI3=0x186
    IMEI4=0x1E4
    */
    agID.clear();
    agID.push_back(0x5);
    agID.push_back(0x179);
    agID.push_back(0x186);
    agID.push_back(0x1E4);
}
DWORD CSettings::GetMaxNVLength()
{
    return m_dwMaxNVLength;//0x40000;
}

void CSettings::DelTmpDir()
{
    if(m_strReleaseDir.length() != 0)
    {
        delete_dir(m_strReleaseDir.c_str());
    }
}

int CSettings::GetDLNVID(std::vector<std::string> &agID)
{
    agID.clear();
    if( NULL == m_pCurProductInfo)
    {
        return 0;
    }

    std::vector<std::string> agNVID;
    int nNVCount = _GetBackupFiles(agNVID,TRUE);

    UINT nCount = m_pCurProductInfo->dwFileCount;
    for(UINT i = 0;i<nCount;i++)
    {
        std::string strID = m_pCurProductInfo->pFileInfoArr[i].szID;
	 transform(strID.begin(), strID.end(), strID.begin(), toupper);
        BOOL bCheck = FALSE;
        std::string strFile;

        std::map<std::string,UINT>::iterator itState;
        std::map<std::string,std::string>::iterator itFile;

        itState = m_mapDLState.find(strID);
        itFile = m_mapDLFiles.find(strID);

        if(itState !=m_mapDLState.end())
        {
            bCheck = itState->second;
        }

        if(itFile !=m_mapDLFiles.end())
        {
            strFile = itFile->second;
        }

        if(bCheck)
        {
            if(strncasecmp(strID.c_str(),_T("NV"),2) == 0 )
            {
                if( strFile.length() != 0 &&
                    strcasecmp(strFile.c_str(),FILE_OMIT) != 0)
                {
                    for(int j=0; j< nNVCount; j++)
                    {
                        if(strcasecmp(strID.c_str(),agNVID[j].c_str()) == 0)
                        {
                            agID.push_back(strID);
                            break;
                        }
                    }
                }
            }
        }
    }

    return agID.size();
}
int CSettings::GetDLNVIDIndex(LPCTSTR lpszFileID)
{
    std::vector<std::string> agID;
    int nCount = GetDLNVID(agID);
    for(int i = 0; i<nCount; i++)
    {
        if(strcasecmp(agID[i].c_str(),lpszFileID) == 0)
            return i;
    }

    return -1;
}

BOOL CSettings::IsKeepCharge()
{
    return m_bKeepCharge;
}
BOOL CSettings::IsPowerOff()
{
	return m_bPowerOff;
}


void CSettings::SetKeepChargeFlag(BOOL bKeepCharge)
{
	 m_bKeepCharge = bKeepCharge;
}

void CSettings::SetPowerOff(BOOL bPowerOff)
{
	m_bPowerOff = bPowerOff;
}

BOOL CSettings::IsBackupNVFile(LPCTSTR lpszFileID)
{

    if(GetDLNVIDIndex(lpszFileID) == -1)
        return FALSE;
    return TRUE;
}
BOOL CSettings::HasExtTblInfo()
{
	return (m_pCurProductInfo && m_pCurProductInfo->dwExtTblCount > 0);
}
LPBYTE CSettings::GetExtTblData(DWORD &dwSize)
{
	dwSize = 0;
	if( m_pCurProductInfo == NULL || m_pCurProductInfo->dwExtTblCount == 0 )
	{
		return NULL;
	}
	DWORD dwExtTblCount =m_pCurProductInfo->dwExtTblCount;

	dwSize = EXTTABLE_COUNT_LEN + sizeof(EXTTBL_HEADER_T)*dwExtTblCount;
	dwSize += m_pCurProductInfo->dwExtTblDataSize;

	LPBYTE pBuf = new BYTE[dwSize];
	if (NULL == pBuf)
	{
		return NULL;
	}

	int nOffset = EXTTABLE_COUNT_LEN;
	memcpy(pBuf,&m_pCurProductInfo->dwExtTblCount,EXTTABLE_COUNT_LEN);
	memcpy(pBuf+nOffset,m_pCurProductInfo->pExtTblHeader,sizeof(EXTTBL_HEADER_T)*dwExtTblCount);

	nOffset += sizeof(EXTTBL_HEADER_T)*dwExtTblCount;
	for (int i=0; i < (int)dwExtTblCount; ++i)
	{
		EXTTBL_HEADER_T* pHeaderItem = m_pCurProductInfo->pExtTblHeader + i;
		EXTTBL_DATA_PTR pSrcItem = m_pCurProductInfo->pExtTblData + i;
		std::string strTag((char*)(pHeaderItem->byTag),4);
		transform(strTag.begin(), strTag.end(), strTag.begin(), tolower);// toupper

		memcpy(pBuf+nOffset,pSrcItem->pData,pSrcItem->dwSize);

		if(0 == strTag.compare("paty"))
		{
			int nPtnItem = pSrcItem->dwSize/sizeof(PARTITION_INFO_T);
			PARTITION_INFO_PTR pPtnInfo =(PARTITION_INFO_T*)(pBuf+nOffset);
			for (int n=0; n < nPtnItem; ++n)
			{
				PARTITION_INFO_PTR pCurItem =  pPtnInfo +n;
				ConvertPtnInfoID(pCurItem);
			}
		}
		nOffset += pSrcItem->dwSize;
	}


	return pBuf;
}

BOOL CSettings::ConvertPtnInfoID(PARTITION_INFO_PTR pPart)
{
	wchar_t wID1[MAX_REP_ID_LEN] = {0};
	wchar_t wID2[MAX_REP_ID_LEN] = {0};
	mbstowcs(wID1,pPart->szID1,MAX_REP_ID_LEN);
	mbstowcs(wID2,pPart->szID2,MAX_REP_ID_LEN);
	WORD *pID1Buf = (WORD *)pPart->szID1;
	WORD *pID2Buf = (WORD *)pPart->szID2;
	for(int i = 0; i< MAX_REP_ID_LEN; i++)
	{
		pID1Buf[i] =  (WORD)wID1[i];
		pID2Buf[i] =  (WORD)wID2[i];
	}

	return TRUE;
}
BOOL CSettings::HasPartitionInfo()
{
    return (m_pCurProductInfo && m_pCurProductInfo->dwPartitionCount > 0);
}

LPBYTE CSettings::GetPartitionData(DWORD &dwSize)
{
	dwSize = 0;
	if( m_pCurProductInfo == NULL || m_pCurProductInfo->dwPartitionCount == 0 )
	{
		return NULL;
	}
	dwSize = sizeof(PARTITION_T)*m_pCurProductInfo->dwPartitionCount;
	LPBYTE pBuf = new BYTE[dwSize];
	memcpy(pBuf, m_pCurProductInfo->pPartitions,dwSize);

	for(UINT i = 0; i< m_pCurProductInfo->dwPartitionCount ; i++)
	{
		PARTITION_T *pCur = ((PARTITION_T*)pBuf) + i;
		ConvertPartID(pCur);
	}

	return pBuf;
}

void CSettings::InitBackupFiles(FILE_INFO_T *pFileInfo, int nCount)
{
	m_vBackupFiles.clear();
	int nItemCount = 0;
	for(int i =0; i< nCount; i++)
	{
		FILE_INFO_T *pCur = pFileInfo + i;
		if(pCur->isBackup == 1 && strncasecmp(pCur->szID,_T("NV"),2) != 0)//file backup
		{
			m_vBackupFiles.push_back(*pCur);
			nItemCount++;
		}
		else if( strncasecmp(pCur->szID,_T("NV"),2)==0 && strncasecmp(pCur->szType,_T("NV"),2)==0)//nv backup
		{
			if(pCur->isBackup == 255 || pCur->isBackup == 1)
			{
			    m_vBackupFiles.push_back(*pCur);
			    m_vBackupFiles[nItemCount].isBackup = 1;
			    nItemCount++;
			}
		}
	}
}

int CSettings::_GetBackupFiles(std::vector<std::string> &agID, BOOL bNV)//bNV=1:NV ,0:FILE
{
	agID.clear();

	for(UINT i = 0; i< m_vBackupFiles.size(); i++)
	{
		if(m_vBackupFiles[i].isBackup == 1)
		{
			if (bNV)
			{
				if(strncasecmp(m_vBackupFiles[i].szID,_T("NV"),2) == 0)
				{
					agID.push_back(m_vBackupFiles[i].szID);
				}
			}
			else
			{
				if(strncasecmp(m_vBackupFiles[i].szID,_T("NV"),2) != 0)
				{	
					if(m_nBackupProdnvMiscdata==0)
					{
						if(_tcsicmp(m_vBackupFiles[i].arrBlock[0].szRepID,_T("miscdata")) == 0 ||
							_tcsicmp(m_vBackupFiles[i].arrBlock[0].szRepID,_T("prodnv")) == 0	)
						{
							continue;
						}
					}

					agID.push_back(m_vBackupFiles[i].szID);
				}
			}
		}

	}

	return agID.size();
}

BOOL CSettings::IsNeedPhaseCheck()
{
	return m_bNeedPhaseCheck;
}

BOOL CSettings::IsDoReport()
{
    return FALSE;
}

BOOL CSettings::ConvertPartID(PARTITION_T *pPart)
{
	wchar_t wID[MAX_REP_ID_LEN] = {0};
	mbstowcs(wID,pPart->szID,MAX_REP_ID_LEN);
	WORD *pBuf = (WORD *)pPart->szID;
	for(int i = 0; i< MAX_REP_ID_LEN; i++)
	{
	    pBuf[i] =  (WORD)wID[i];
	}

	return TRUE;
}


BOOL CSettings::IsMapPBFileBuf()
{

	BOOL bHasPBFile = FALSE;
	if(m_pCurProductInfo == NULL)
		return FALSE;
	UINT nCount = m_pCurProductInfo->dwFileCount;
	for(UINT i = 0;i<nCount;++i)
	{
		std::string strID = m_pCurProductInfo->pFileInfoArr[i].szID;
		transform(strID.begin(), strID.end(), strID.begin(), toupper);
		BOOL bCheck = FALSE;
		std::string strFile;

		std::map<std::string,UINT>::iterator itState;
		std::map<std::string,std::string>::iterator itFile;

		itState = m_mapDLState.find(strID);
		itFile = m_mapDLFiles.find(strID);

		if(itState !=m_mapDLState.end())
		{
		    bCheck = itState->second;
		}

		if(itFile !=m_mapDLFiles.end())
		{
		    strFile = itFile->second;
		}
		if( bCheck &&m_pCurProductInfo->pFileInfoArr[i].isSelByFlashInfo==1	)
		{
			bHasPBFile = TRUE;
			break;
		}
	}
	return bHasPBFile;
}

 BOOL    CSettings::IsEnableRFChipType()
{
	BOOL bOK = FALSE;
	if( m_pCurProductInfo != NULL &&
		m_pCurProductInfo->tRfChips.bEnable &&
		0 != m_pCurProductInfo->tRfChips.dwCount)
	{

        //printf("[%s]: bEnable = %d, dwCount = %d\n", __func__, m_pCurProductInfo->tRfChips.bEnable, m_pCurProductInfo->tRfChips.dwCount);

		bOK = TRUE;
	}
	return bOK;
}
int CSettings::GetAllFileInfo(void** ppFileInfo)
{
	if(m_pCurProductInfo == NULL)
	{
		return -1;
	}
	int nCount = 0;

    PFILE_INFO_T pFileInfo = NULL;


    nCount = m_pCurProductInfo->dwFileCount;
    pFileInfo= m_pCurProductInfo->pFileInfoArr;

    *ppFileInfo = pFileInfo;

	return nCount;
}


