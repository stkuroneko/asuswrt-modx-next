// XmlConfigParse.cpp: implementation of the CXmlConfigParse class.
//
//////////////////////////////////////////////////////////////////////

#include "XmlConfigParse.h"
#include "tinyxml.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

#define FILE_OMIT_FLAG  2

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CXmlConfigParse::CXmlConfigParse()
{
	//m_xmlConfig.Close();
	m_mapProductInfo.clear();
	m_mapProductEnable.clear();
	m_aProductList.clear();
	m_pCurProduct = NULL;
	m_bOK = FALSE;
	m_strBaseConfig = _T("");
	m_mapPrdCfg.clear();
}

CXmlConfigParse::CXmlConfigParse(LPCTSTR lpcstrFileName)
{
	if(!Init(lpcstrFileName))
	{
		return;
	}
	m_pCurProduct = NULL;
}

CXmlConfigParse::~CXmlConfigParse()
{
	Clear();
}

void CXmlConfigParse::Clear()
{
	m_bOK = FALSE;
	m_pCurProduct = NULL;
	PPRODUCT_INFO_T pProd;
    PRODUCT_MAP::iterator it;
	for(it = m_mapProductInfo.begin(); it != m_mapProductInfo.end(); it++)
	{
		pProd = it->second;

		if(pProd != NULL)
		{
			pProd->Clear();
			delete pProd;
		}
	}
	m_mapProductInfo.clear();
	m_mapProductEnable.clear();
	m_aProductList.clear();
	m_mapPrdCfg.clear();
}


BOOL CXmlConfigParse::Init(LPCTSTR lpszFileName,int nFlag /*= 0*/)
{
	if(!lpszFileName)
	{
		return FALSE;
	}

	m_strBaseConfig = lpszFileName;

 /*   if(nFlag == 0)
	{
		Clear();
		char szPath[_MAX_PATH] = {0};
		strcpy(szPath,lpszFileName);
		char *pCur = strrchr(szPath,'/');
		if(pCur != NULL)
		{
		    *pCur = '\0';
		}
		m_bOK = LoadAllProductInfo(szPath);
	}
	else*/
	{
		m_bOK = _LoadProductInfo(lpszFileName,FALSE);
	}



	return m_bOK;

}
/**
 * Get the number of products
 *
 * @return Returns dwCount,the number of products
 */
DWORD CXmlConfigParse::GetProductCount()
{
	return m_aProductList.size();
}

/**
 * Get product names
 *
 * @param pProductNameList: store the names;
 * @param dwSize: original pProductNameList spaces size;
 * @param dwRealSize: real used size;
 */
void CXmlConfigParse::GetProductNameList(LPTSTR pProductNameList,DWORD dwSize,DWORD &dwRealSize)
{
	int  nCount = m_aProductList.size();
	std::string strName;
	dwRealSize = 0;
	memset(pProductNameList,0,dwSize*sizeof(_TCHAR));
	for( int i = 0; i < nCount; i++)
	{
		strName= m_aProductList[i];
		dwRealSize+=strName.length();
		if(dwRealSize >= dwSize)
		{
			break;
		}
		strcat(pProductNameList,strName.c_str());
		pProductNameList[dwRealSize]=_T(';');
		dwRealSize++; //+';'
		//arrProductNameList.Add(strAttValue);
	}
	pProductNameList[dwRealSize] = _T('\0');
}

PPRODUCT_INFO_T CXmlConfigParse::GetProdInfo(LPCTSTR lpszProductName)
{
    m_pCurProduct = NULL;

    PRODUCT_MAP::iterator it;

    it = m_mapProductInfo.find(lpszProductName);

	if(it == m_mapProductInfo.end())
	{
		m_pCurProduct = NULL;
	}
	else
	{
	    m_pCurProduct = it->second;
	}

	return m_pCurProduct;
}

/**
 * Release this
 */
void CXmlConfigParse::Release()
{
	Clear();
	delete this;
}

BOOL CXmlConfigParse::Success()
{
	return m_bOK;
}
/*
BOOL CXmlConfigParse::LoadAllProductInfo(LPCTSTR lpszConfigBase)
{
	CString strWildPath = lpszConfigBase;
	strWildPath += _T("\\*.xml");
	CFileFind finder;
	BOOL bFound;
	bFound = finder.FindFile(strWildPath);
	CStringArray aFilePath;
	CObArray aTime;
	CString strPath;
	CString strName;
	CString strBaseConfg = m_strBaseConfig;
	int nFind = strBaseConfg.ReverseFind(_T('\\'));
    strBaseConfg = strBaseConfg.Right(strBaseConfg.GetLength() - nFind -1);
//	CTime *pCurTime;
	CTime lmCurTime;
	int i=0;
	while(bFound)
	{
		bFound = finder.FindNextFile();
	    strName = finder.GetFileName();
		if(strName.CompareNoCase(_T("BMAConfigSchema.xml")) == 0 ||
			strName.CompareNoCase(strBaseConfg)== 0)
		{
			continue;
		}
		else if(strName.Right(4).CompareNoCase(_T(".xml")) == 0)
		{
			strPath = finder.GetFilePath();
			finder.GetLastWriteTime(lmCurTime);

			int nCount = aFilePath.GetSize();
			if(nCount == 0)
			{
				aFilePath.Add(strPath);
				//pCurTime= new CTime(lmCurTime);
				aTime.Add((CObject *)&lmCurTime);
			}
			else
			{
				for(i=0; i<nCount;i++)
				{
					if(lmCurTime>= *(CTime*)aTime[i])
					{
						aTime.InsertAt(i,(CObject *)&lmCurTime);
						aFilePath.InsertAt(i,strPath);
						break;
					}
				}
				if(i>=nCount)
				{
					aTime.Add((CObject *)&lmCurTime);
					aFilePath.Add(strPath);
				}

			}

		}
	}
	aFilePath.Add(m_strBaseConfig);

    int nFileCount = aFilePath.GetSize();

	if(nFileCount == 0)
		return FALSE;

    BOOL bOk = TRUE;
	for(i=0;i<nFileCount;i++)
	{
		bOk = _LoadProductInfo(aFilePath.GetAt(i));
		if(!bOk)
			return FALSE;
	}

	return TRUE;
}
*/
/*
BOOL CXmlConfigParse::_Init(LPCTSTR lpszConfigName)
{
	// Open file
	CString strText;
	CString strNotes;
	CFile file;
	if ( !file.Open( lpszConfigName, CFile::modeRead ) )
	{
		AfxMessageBox( _T("Unable to open xml config file") );
		return FALSE;
	}
	int nFileLen = (int)file.GetLength();

	// Allocate buffer for binary file data
	char* pBuffer = new char[nFileLen + 1];
	memset(pBuffer,0,nFileLen + 1);
	nFileLen = file.Read( pBuffer, nFileLen );
	file.Close();
	pBuffer[nFileLen] = '\0';


	_TCHAR *pBufferU = NULL;
	if(pBuffer[0] != (UCHAR)0xFF || pBuffer[1] != (UCHAR)0xFE)//not unicode
	{
		pBufferU = new _TCHAR[nFileLen+1];
		memset(pBufferU,0,sizeof(_TCHAR)*(nFileLen + 1));
		MultiByteToWideChar(CP_ACP,0,pBuffer,nFileLen+1,pBufferU,nFileLen+1);
		strText.Empty();
		strText = pBufferU;
	}
	else
	{
		strText = (LPTSTR)pBuffer;
	}

	delete [] pBuffer;
	pBuffer = NULL;
	if(pBufferU != NULL)
	{
		delete [] pBufferU;
		pBufferU = NULL;
	}

	CString strXmlRet;
	strXmlRet = m_xmlConfig.Load(strText);
	strText.Empty();

	if(strXmlRet.IsEmpty())
	{
		return FALSE;
	}
	return TRUE;
}
*/
BOOL CXmlConfigParse::_LoadProductInfo(LPCTSTR lpszConfigName,BOOL bChangePrdName/*= FALSE*/)
{
	TiXmlDocument doc;
	if(!doc.LoadFile(lpszConfigName))
	{
		printf("doc.LoadFile [%s] fail. \n",lpszConfigName);
		return FALSE;
	}
	TiXmlElement * pRoot = doc.RootElement();

	PPRODUCT_INFO_T pProuctInfo = NULL;
	PPRODUCT_INFO_T pFindProuctInfo = NULL;

	TiXmlNode *lpChild = pRoot->FirstChild(_T("ProductList"));

	if(lpChild == NULL) //check
		return FALSE;

	std::string strValue;
	std::string strCurSchemeName;
	const char *pStrValue;
	int  nValue;
	int  nNvBkpItem;
	int i,j,k;
	UINT uEnable;

	TiXmlNode * pProductNode = NULL;
	TiXmlNode * pFindNode = NULL;
	PRODUCT_MAP::iterator itProduct;
	PRODUCT_ENABLE_MAP::iterator itEnable;

	for(pProductNode = lpChild->FirstChild(_T("Product"));
	    pProductNode != NULL;
	    pProductNode = pProductNode->NextSibling(_T("Product")) )
	{
		TiXmlElement * pProductEle = pProductNode->ToElement();

		pStrValue = pProductEle->Attribute("name");

		if(pStrValue==NULL || strlen(pStrValue) == 0)
		{
			continue;
		}

		strValue = pStrValue;

		if(bChangePrdName)
		{
			StrTrim(strValue);
			strValue.insert(0,_T("PAC_"));
		}

		nValue = 1;
		pStrValue = pProductEle->Attribute(_T("enable"),&nValue);


		pFindProuctInfo = NULL;
		if(!bChangePrdName)
		{
			itProduct = m_mapProductInfo.find(strValue);
			//already exist
			if(itProduct != m_mapProductInfo.end())
			{
				continue;
			}
			uEnable = 1;

			itEnable = m_mapProductEnable.find(strValue);
			if(itEnable != m_mapProductEnable.end() && itEnable->second == 0 )
			{
				continue;
			}
			else
			{
				m_mapProductEnable[strValue] = nValue;
				if(nValue == 0) //
				{
					continue;
				}
			}
		}
		else // PAC file config must be high level
		{
			//already exist,must remove it and use this one
			itProduct = m_mapProductInfo.find(strValue);
			if(itProduct!= m_mapProductInfo.end())
			{
			    pFindProuctInfo = itProduct->second;
				if(pFindProuctInfo != NULL)
				{
					pFindProuctInfo->Clear();
					delete pFindProuctInfo;
					pFindProuctInfo = NULL;
				}

				m_mapProductInfo.erase(strValue);
			}

			m_mapProductEnable[strValue] = 1;
		}


		pProuctInfo = new PRODUCT_INFO_T;

		m_aProductList.push_back(strValue);
		m_mapProductInfo[strValue] = pProuctInfo;
		m_mapPrdCfg[strValue]=lpszConfigName;
		strcpy(pProuctInfo->szProductName,strValue.c_str());

		pFindNode = pProductEle->FirstChild(_T("SchemeName"));

		if(pFindNode)
		{
		    strCurSchemeName = pFindNode->FirstChild()->Value();
		}

		pFindNode = pProductNode->FirstChild(_T("FlashTypeID"));
		if(pFindNode)
		{
		    sscanf( pFindNode->FirstChild()->Value(), _T("%d"), &nValue);
		    pProuctInfo->dwFlashType = nValue;
		}

		pFindNode = pProductNode->FirstChild(_T("Mode"));
		if(pFindNode)
		{
		    sscanf( pFindNode->FirstChild()->Value(), _T("%d"), &nValue);
		    pProuctInfo->dwMode = nValue;
		}

		pFindNode = pProductNode->FirstChild(_T("ProductComment"));
		if(pFindNode)
		{
		    if(pFindNode->FirstChild())
		    {
		        strncpy(pProuctInfo->szComment,pFindNode->FirstChild()->Value(),MAX_PATH+1);
		    }
		}


		pFindNode = pProductNode->FirstChild(_T("NvBaseAddrChangeFlag"));
		if(pFindNode)
		{
		    nValue = 0;
		    sscanf( pFindNode->FirstChild()->Value(), _T("%d"), &nValue);
		    pProuctInfo->dwNvBaseChangeFlag = nValue;
		}

		pFindNode = pProductNode->FirstChild(_T("NvNewBasePosition"));
		if(pFindNode)
		{
		    nValue = 0;
		    sscanf( pFindNode->FirstChild()->Value(), _T("%d"), &nValue);
		    pProuctInfo->dwNvNewBasePosition = nValue;
		}

		pFindNode = pProductNode->FirstChild(_T("NVOrgFlag"));
		if(pFindNode)
		{
		    nValue = 0;
		    sscanf( pFindNode->FirstChild()->Value(), _T("%d"), &nValue);
		    pProuctInfo->dwNVOrgFlag = nValue;
		}

		pFindNode = pProductNode->FirstChild(_T("NVOrgBasePosition"));
		if(pFindNode)
		{
		    nValue = 0;
		    sscanf( pFindNode->FirstChild()->Value(), _T("%d"), &nValue);
		    pProuctInfo->dwNVOrgBasePosition = nValue;
		}

		pFindNode = pProductNode->FirstChild(_T("OmaDMFlag"));
		if(pFindNode)
		{
		    nValue = 0;
		    sscanf( pFindNode->FirstChild()->Value(), _T("%d"), &nValue);
		    pProuctInfo->dwOmaDMFlag = nValue;
		}

		pFindNode = pProductNode->FirstChild(_T("RebootByAT"));
		if(pFindNode)
		{
		    nValue = 0;
		    sscanf( pFindNode->FirstChild()->Value(), _T("%d"), &nValue);
		    pProuctInfo->bRebootByAT = nValue;
		}


		// for NV backup
		TiXmlNode *lpNvBackup = NULL;
		TiXmlElement *lpNvBackupEle = NULL;
		lpNvBackup = pProductNode->FirstChild(_T("NVBackup"));
		if(lpNvBackup != NULL) // if "NVBackup" exist
		{
			lpNvBackupEle = lpNvBackup->ToElement();
			nValue = 0;
			lpNvBackupEle->Attribute(_T("backup"),&nValue);
			pProuctInfo->dwNvBackupFlag = nValue;
			if(nValue != 0)
			{
				nNvBkpItem = 0;
				TiXmlNode * lpNvBackupItem = NULL;
				for(lpNvBackupItem = lpNvBackup->FirstChild(_T("NVItem"));
				    	lpNvBackupItem;
				     	lpNvBackupItem = lpNvBackupItem->NextSibling(_T("NVItem")))
				{
				    nNvBkpItem++;
				}

				pProuctInfo->dwNvBackupItemCount = nNvBkpItem;

				if(nNvBkpItem != 0)
				{
					pProuctInfo->paNvBackupItem = new NV_BACKUP_ITEM_T[nNvBkpItem];
					memset(pProuctInfo->paNvBackupItem,0,sizeof(NV_BACKUP_ITEM_T)*nNvBkpItem);
					j = 0;
					for(lpNvBackupItem = lpNvBackup->FirstChild(_T("NVItem"));
						lpNvBackupItem;
						lpNvBackupItem = lpNvBackupItem->NextSibling(_T("NVItem")),j++)
					{
						PNV_BACKUP_ITEM_T pNBIT = pProuctInfo->paNvBackupItem + j;

						lpNvBackupEle = lpNvBackupItem->ToElement();
						strValue = lpNvBackupEle->Attribute(_T("name"));
						strcpy(pNBIT->szItemName,strValue.c_str());

						nValue = 0;
						strValue = lpNvBackupEle->Attribute(_T("backup"),&nValue);
						pNBIT->wIsBackup = (WORD)nValue;


						pFindNode = lpNvBackupItem->FirstChild(_T("ID"));
						if(pFindNode)
						{
							sscanf(pFindNode->FirstChild()->Value(),_T("0x%x"),&(pNBIT->dwID));
						}

						pFindNode = lpNvBackupItem->FirstChild(_T("BackupFlag"));
						if(pFindNode)
						{
							lpNvBackupEle = pFindNode->ToElement();
							nValue = 0;
							lpNvBackupEle->Attribute(_T("use"),&nValue);
							pNBIT->wIsUseFlag = (WORD)nValue;
						}

						if(pNBIT->wIsUseFlag == 1)
						{
							TiXmlNode * lpxnFlag= lpNvBackupItem->FirstChild(_T("BackupFlag"));
							if(lpxnFlag == NULL)
							{
								delete [] pProuctInfo->paNvBackupItem;
								pProuctInfo->paNvBackupItem = NULL;
								delete pProuctInfo;
								pProuctInfo = NULL;
								return FALSE;
							}


							pNBIT->dwFlagCount = 0;
							//TRACE(_T("%s: NvFlagCount:%d\n"),pProuctInfo->szProductName,nNvFlagCount);
							k = 0;
							for(TiXmlNode * lpxnFlagItem = lpxnFlag->FirstChild(_T("NVFlag"));
							 	lpxnFlagItem && k < MAX_NV_BACKUP_FALG_NUM;
							 	lpxnFlagItem = lpxnFlagItem->NextSibling(_T("NVFlag")),k++)
							{
								lpNvBackupEle = lpxnFlagItem->ToElement();
								strcpy(pNBIT->nbftArray[k].szFlagName,lpNvBackupEle->Attribute(_T("name")));

								nValue = 0;
								lpNvBackupEle->Attribute(_T("check"),&nValue);
								pNBIT->nbftArray[k].dwCheck = (DWORD)nValue;
								pNBIT->dwFlagCount++;
							}
						}

					}
				}
			}
		}
//////////////////////////////////////////////////////////////////////////
		// for Chips
		/*
		 *  <Chips enable="0">
		 *		<ChipItem id="0x222" name="L2"/>
		 *		<ChipItem id="0x777" name="L7"/>
		 *  </Chips>
		*/
		TiXmlNode *  lpChip = NULL;
		lpChip = pProductNode->FirstChild(_T("Chips"));
		if(lpChip != NULL) // if "Chips" exist
		{
			TiXmlElement *pEle = lpChip->ToElement();
			nValue = 0;
			pEle->Attribute(_T("enable"),&nValue);
			pProuctInfo->tChips.bEnable = nValue;

			if(nValue != 0)
			{
				UINT nChipCount = 0;
				TiXmlNode * lpChipItem = NULL;
				for(lpChipItem = lpChip->FirstChild(_T("ChipItem"));
				    lpChipItem;
				     lpChipItem = lpChipItem->NextSibling(_T("ChipItem")))
				{
				    nChipCount++;
				}
				pProuctInfo->tChips.dwCount = nChipCount;

				if(nChipCount != 0)
				{
					pProuctInfo->tChips.pChips = new CHIPITEM_T[nChipCount];
					memset(pProuctInfo->tChips.pChips,0,sizeof(CHIPITEM_T)*nChipCount);

					j = 0;
					for(lpChipItem = lpChip->FirstChild(_T("ChipItem"));
					lpChipItem;
					lpChipItem =  lpChipItem->NextSibling(_T("ChipItem")), j++)
					{
						CHIPITEM_PTR pChipItem = pProuctInfo->tChips.pChips + j;
						pEle = lpChipItem->ToElement();

						nValue = 0;
						pEle->Attribute(_T("id"),&nValue);
						pChipItem->dwID = (DWORD)nValue;

						strcpy(pChipItem->szName,pEle->Attribute(_T("name")));
					}
				}
			}
		}

		// for RF
		/*
		 *  <RF enable="1">
		 *		<Transceiver id="0x0" name="BOCA"/>
		 *		<Transceiver id="0x1" name="NAVAJO"/>
		 *  </RF>
		*/
		lpChip = pProductNode->FirstChild(_T("RF"));
		if(lpChip != NULL) // if "Chips" exist
		{
			TiXmlElement *pEle = lpChip->ToElement();
			nValue = 0;
			pEle->Attribute(_T("enable"),&nValue);
			pProuctInfo->tRfChips.bEnable = nValue;
			int nRfChipCount = 0;
			if(nValue != 0)
			{
				UINT nChipCount = 0;
				TiXmlNode * lpChipItem = NULL;
				for(lpChipItem = lpChip->FirstChild(_T("Transceiver"));
				    lpChipItem;
				     lpChipItem = lpChipItem->NextSibling(_T("Transceiver")))
				{
				    ++nRfChipCount;
				}
				pProuctInfo->tRfChips.dwCount = nRfChipCount;

				if(nRfChipCount != 0)
				{
					pProuctInfo->tRfChips.pChips = new CHIPITEM_T[nRfChipCount];
					memset(pProuctInfo->tRfChips.pChips,0,sizeof(CHIPITEM_T)*nRfChipCount);

					j = 0;
					for(lpChipItem = lpChip->FirstChild(_T("Transceiver"));
					lpChipItem;
					lpChipItem =  lpChipItem->NextSibling(_T("Transceiver")), j++)
					{
						CHIPITEM_PTR pChipItem = pProuctInfo->tRfChips.pChips + j;
						pEle = lpChipItem->ToElement();

						nValue = 0;
						strValue = pEle->Attribute(_T("id"));
						if(strncasecmp(strValue.c_str(),"0x",2) == 0)
						{
							sscanf( strValue.c_str(), _T("0x%X"), &nValue);
						}
						else 
						{
							pEle->Attribute(_T("id"),&nValue);
						}
						pChipItem->dwID = (DWORD)nValue;

						strcpy(pChipItem->szName,pEle->Attribute(_T("name")));
					}
				}
			}
		}
//////////////////////////////////////////////////////////////////////////

		// for Partitions
		// <Partitions>
		//      <Partition id="modem" size="20"/>
		//      <Partition id="dsp" size="10"/>
		// </Partitions>
		TiXmlNode *  lpPartitions = NULL;
		lpPartitions = pProductNode->FirstChild(_T("Partitions"));
		if(lpPartitions != NULL) // if "Partitions" exist
		{
			UINT nPartitionCount = 0;
			TiXmlNode * lpPartitionItem = NULL;
			for(lpPartitionItem = lpPartitions->FirstChild(_T("Partition"));
			     lpPartitionItem;
			     lpPartitionItem = lpPartitionItem->NextSibling(_T("Partition")))
			{
			    nPartitionCount++;
			}
			pProuctInfo->dwPartitionCount = nPartitionCount;

			if(nPartitionCount != 0)
			{
				pProuctInfo->pPartitions = new PARTITION_T[nPartitionCount];
				memset(pProuctInfo->pPartitions,0,sizeof(PARTITION_T)*nPartitionCount);

				j = 0;
				for(lpPartitionItem = lpPartitions->FirstChild(_T("Partition"));
				    lpPartitionItem;
				    lpPartitionItem =  lpPartitionItem->NextSibling(_T("Partition")), j++)
				{
					PARTITION_T* pPart = pProuctInfo->pPartitions + j;
					TiXmlElement * pEle = lpPartitionItem->ToElement();


					strValue = pEle->Attribute(_T("size"));
					if(strncasecmp(strValue.c_str(),"0x",2) == 0)
					{
					    sscanf( strValue.c_str(), _T("0x%X"), &pPart->dwSize);
					}
					else
					{
					    nValue = 0;
					    pEle->Attribute(_T("size"),&nValue);
					    pPart->dwSize = (DWORD)nValue;
					}
					strcpy(pPart->szID,pEle->Attribute(_T("id")));
				}
			}
		}

//////////////////////////////////////////////////////////////////////////
		// Start for ExtTable  @polo.jiang on 20141001
		/*
		 *  <ExtTable>
		 *		<PartitionType tag="paty">
		 *			<!--type: 0,IMG_RAW; 1,IMG_NV; 2,IMG_SPARSE -->
		 *			<Partition id="fixnv1"		id2="fixnv2"	type="1"  size="0xFFFFFFFF"/>
		 *			<Partition id="system"		id2=""			type="0"  />
         *		    <Partition id="userdata"	id2=""          type="2"/>
		 *		</PartitionType>
		 *		<OtherType tag="pat2">
		 *			<Other />
		 *		</OtherType>
		 *  </ExtTable>
		*/
		TiXmlNode *  lpExtTblNode = NULL;
		lpExtTblNode = pProductNode->FirstChild(_T("ExtTable"));
		if(lpExtTblNode != NULL) // if "Partitions" exist
		{
			int nExtTblCounts = lpExtTblNode->GetChildCount();
			if (0 == nExtTblCounts)
			{
				return TRUE;
			}
			pProuctInfo->pExtTblHeader	= new EXTTBL_HEADER_T[nExtTblCounts];
			pProuctInfo->pExtTblData		= new EXTTBL_DATA_T[nExtTblCounts];
			if(NULL == pProuctInfo->pExtTblHeader || NULL == pProuctInfo->pExtTblData)
			{
				if (pProuctInfo->pExtTblHeader)
				{
					delete []pProuctInfo->pExtTblHeader;
					pProuctInfo->pExtTblHeader = NULL;
				}
				if (pProuctInfo->pExtTblData)
				{
					delete []pProuctInfo->pExtTblData;
					pProuctInfo->pExtTblData = NULL;
				}
				return FALSE;							
			}

			memset(pProuctInfo->pExtTblHeader,0,sizeof(EXTTBL_HEADER_T)*nExtTblCounts);
			memset(pProuctInfo->pExtTblData,0,sizeof(EXTTBL_DATA_T)*nExtTblCounts);

			pProuctInfo->dwExtTblCount		= nExtTblCounts;
			pProuctInfo->dwExtTblDataSize	= 0;
			int	nOffset							= EXTTABLE_COUNT_LEN;	// 4Byte table-count;
			int	nIndex							= 0;
			// Start to get PartitionType info 

			TiXmlNode *  lpPtnType = NULL;
			lpPtnType = lpExtTblNode->FirstChild(_T("PartitionType"));
			if(lpPtnType != NULL) // if "PartitionType" exist
			{
				EXTTBL_HEADER_T* 	pItemHeader= pProuctInfo->pExtTblHeader+nIndex;
				EXTTBL_DATA_T* 		pItemData	= pProuctInfo->pExtTblData+nIndex;
				TiXmlElement *		lpTpyeEle 	= NULL;
				nOffset						+= sizeof(EXTTBL_HEADER_T);


				lpTpyeEle = lpPtnType->ToElement();
				pStrValue = lpTpyeEle->Attribute("tag");
				int nTagLen = strlen(pStrValue);
				for (int n=0 ; n<4 && n<nTagLen; ++n)
				{
					pItemHeader->byTag[n] = pStrValue[n];
				}		

				//Start to get PartitionType items
				int nPtnItemCount = lpPtnType->GetChildCount();
				pItemHeader->dwOffset = nOffset;
				pItemHeader->dwSize	  = sizeof(PARTITION_INFO_T)*nPtnItemCount;

				if ( 0 != nPtnItemCount )
				{
					pItemData->dwSize = sizeof(PARTITION_INFO_T)*nPtnItemCount;
					pItemData->pData  = (LPBYTE) new PARTITION_INFO_T[nPtnItemCount];
					if ( NULL == pItemData->pData )
					{
						pProuctInfo->Clear();
						return FALSE;
					}
					memset(pItemData->pData,0,pItemData->dwSize);
					pProuctInfo->dwExtTblDataSize += pItemData->dwSize;

					PARTITION_INFO_T* pPtnInfo = (PARTITION_INFO_T*)(pItemData->pData);
					TiXmlNode * lpPtnItem = NULL;
					int i = 0;
					for(lpPtnItem = lpPtnType->FirstChild(_T("Partition"));
					lpPtnItem;
					lpPtnItem =  lpPtnItem->NextSibling(_T("Partition")),++i)
					{
						PARTITION_INFO_T* pPart = pPtnInfo + i;
						TiXmlElement * pEle = lpPtnItem->ToElement();
						strcpy(pPart->szID1,pEle->Attribute(_T("id")));
						strcpy(pPart->szID2,pEle->Attribute(_T("id2")));
						if( pEle->Attribute(_T("size")) )
						{
							strValue = pEle->Attribute(_T("size") );
							if(strncasecmp(strValue.c_str(),"0x",2) == 0)
							{
								sscanf( strValue.c_str(), _T("0x%X"), &pPart->dwSize);
							}
							else 
							{
								nValue = 0;
								pEle->Attribute(_T("size"),&nValue);
								pPart->dwSize = (DWORD)nValue;
							}
						}
							
						strValue = pEle->Attribute(_T("type"));
						if ( strValue.length() >0 )
						{
							pPart->type = (BYTE)(strValue.c_str()[0] -'0');
						}
					}
					nOffset += sizeof(PARTITION_INFO_T)*nPtnItemCount;
				}
				//End get PartitionType items
				++nIndex;
			}	
			//End get PartitionType info 
			//when need to add other info,just modified nOffset,nIndex and pProuctInfo->dwExtTblDataSize parts.
		}
		//	end for ExtTable @ polo.jiang on 20141001
//////////////////////////////////////////////////////////////////////////


		/// for SchemeList
		TiXmlNode* lpSchemeListNode = pRoot->FirstChild( _T("SchemeList") );
		TiXmlNode* xnSchemeNodeItem = lpSchemeListNode->FirstChild(_T("Scheme"));
		for(;xnSchemeNodeItem; xnSchemeNodeItem = xnSchemeNodeItem->NextSibling(_T("Scheme")))
		{

			TiXmlElement *pEle = xnSchemeNodeItem->ToElement();
			strValue= pEle->Attribute(_T("name"));

			if(strValue == strCurSchemeName)
			{
				pProuctInfo->dwFileCount = 0;
				TiXmlNode* xnFileItem = xnSchemeNodeItem->FirstChild(_T("File"));

				for(;xnFileItem; xnFileItem = xnFileItem->NextSibling(_T("File")))
				{
		            		pProuctInfo->dwFileCount++;
				}

				if(pProuctInfo->dwFileCount > 0)
				{
					pProuctInfo->pFileInfoArr = new FILE_INFO_T[pProuctInfo->dwFileCount];
					memset(pProuctInfo->pFileInfoArr,0,sizeof(FILE_INFO_T)*pProuctInfo->dwFileCount);
					k = 0;
					xnFileItem = xnSchemeNodeItem->FirstChild(_T("File"));
					for(;xnFileItem; xnFileItem = xnFileItem->NextSibling(_T("File")),k++)
					{
						PFILE_INFO_T pFIT = pProuctInfo->pFileInfoArr + k;
						pEle = xnFileItem->ToElement();

						nValue = 255;
						pEle->Attribute(_T("backup"), &nValue);
						pFIT->isBackup = (BYTE)nValue;

						nValue = 0;
						pEle->Attribute(_T("selbyflash"), &nValue);
						pFIT->isSelByFlashInfo = (BYTE)nValue;

						nValue = 0;
						pEle->Attribute(_T("selbyrf"), &nValue);
						pFIT->isSelByRf = (BYTE)nValue;

						
						pFindNode = xnFileItem->FirstChild(_T("ID"));
						if(pFindNode)
						{
						    strcpy(pFIT->szID,pFindNode->FirstChild()->Value());
						}

		                		pFindNode = xnFileItem->FirstChild(_T("IDAlias"));
						if(pFindNode)
						{
						    strcpy(pFIT->szIDAlias,pFindNode->FirstChild()->Value());
						}
						else
						{
						    strcpy(pFIT->szIDAlias,pFIT->szID);
						}


						pFindNode = xnFileItem->FirstChild(_T("Type"));
						if(pFindNode)
						{
						    strcpy(pFIT->szType,pFindNode->FirstChild()->Value());
						}

		                		pFindNode = xnFileItem->FirstChild(_T("Flag"));
						if(pFindNode)
						{
						    pFIT->dwFlag = (DWORD)atoi(pFindNode->FirstChild()->Value());
						}

		                		pFindNode = xnFileItem->FirstChild(_T("CheckFlag"));
						if(pFindNode)
						{
						    pFIT->dwCheckFlag = (DWORD)atoi(pFindNode->FirstChild()->Value());
						}

		                		pFindNode = xnFileItem->FirstChild(_T("Description"));
						if(pFindNode)
						{
						    strcpy(pFIT->szFileDescript,pFindNode->FirstChild()->Value());
						}

						TiXmlNode * nxBlockItem;
						nxBlockItem = xnFileItem->FirstChild(_T("Block"));
						pFIT->dwBlockCount = 0;

						int t = 0;

						for(; nxBlockItem && t<MAX_BLOCK_NUM;
		                    		nxBlockItem = nxBlockItem->NextSibling(_T("Block")),t++)
						{
							strValue = nxBlockItem->FirstChild(_T("Base"))->FirstChild()->Value();
							sscanf( strValue.c_str(), _T("0x%llX"), &(pFIT->arrBlock[t].llBase));

							strValue = nxBlockItem->FirstChild(_T("Size"))->FirstChild()->Value();
							sscanf( strValue.c_str(), _T("0x%llX"), &(pFIT->arrBlock[t].llSize));

							pEle = nxBlockItem->ToElement();
							if(  pEle->Attribute(_T("id"))!= NULL)
							{
							    strcpy(pFIT->arrBlock[t].szRepID,pEle->Attribute(_T("id")));
							}
							pFIT->dwBlockCount++;
						}
					}
				}
				break;
			}
		}
	}

	return TRUE;
}

/*
void  CXmlConfigParse::_Close()
{
	m_xmlConfig.Close();
}
*/
LPCTSTR  CXmlConfigParse::GetConfigFile(LPCTSTR lpszProductName)
{
	static std::string strConfigFile = _T("");

    PRODUCT_CONFIG_FILE_MAP::iterator it  = m_mapPrdCfg.find(lpszProductName);

	if(it == m_mapPrdCfg.end())
	{
		return NULL;
	}

	strConfigFile = it->second;

	return strConfigFile.c_str();
}
