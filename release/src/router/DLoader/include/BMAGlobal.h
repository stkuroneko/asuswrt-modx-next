#ifndef __BMAGLOBAL__H_
#define __BMAGLOBAL__H_

#pragma warning(push,3)
#include <vector>
#include <map>
#include <string>
#pragma warning(pop)

#include "BootModeitf.h"
#include "typedef.h"
#include "string.h"
#include "Global.h"

#define MAX_TEXT_LENGTH 			100
#define MAX_BLOCK_NUM   				5
#define FILE_OMIT_FALG 				2
#define MAX_NV_BACKUP_FALG_NUM 	5
#define MAX_RET_FILE_NUM 			50
#define EXTTABLE_COUNT_LEN			4

typedef struct _BLOCK_T
{
    _BLOCK_T()
    {
        memset(this,0,sizeof(_BLOCK_T));
    }

    __uint64 llBase;
    __uint64 llSize;
    _TCHAR szRepID[MAX_REP_ID_LEN*2];
}BLOCK_T, *PBLOCK_T;

typedef struct _FILE_INFO_T
{
    _FILE_INFO_T()
    {
        memset(this,0,sizeof(_FILE_INFO_T));
    }

    _TCHAR      szID[MAX_PATH];  // internal ID
    _TCHAR      szType[MAX_PATH]; // BMFILE type
    DWORD       dwFlag;
    BLOCK_T     arrBlock[MAX_BLOCK_NUM];
    DWORD       dwBlockCount;
    DWORD       dwCheckFlag;
    _TCHAR      szIDAlias[MAX_PATH]; //use for GUI display
    _TCHAR      szFilePath[MAX_PATH]; //use for GUI display
    _TCHAR      szFileDescript[MAX_PATH+2];//use for GUI display
    BYTE        isBackup;
    BYTE        isSelByFlashInfo;
    BYTE 		isSelByRf;
    BYTE        reserved1;
} FILE_INFO_T, *PFILE_INFO_T;


typedef std::vector<PFILE_INFO_T> FILE_INFO_ARR;

typedef struct _NV_BACKUP_FLAG_T
{
    _NV_BACKUP_FLAG_T()
    {
        memset(this,0,sizeof(_NV_BACKUP_FLAG_T));
    }

    _TCHAR szFlagName[MAX_PATH];
    DWORD  dwCheck;
}NV_BACKUP_FLAG_T,*PNV_BACKUP_FLAG_T;

typedef struct _NV_BACKUP_ITEM_T
{
    _NV_BACKUP_ITEM_T()
    {
        memset(this,0,sizeof(_NV_BACKUP_ITEM_T));
    }
    _TCHAR szItemName[MAX_PATH];
    WORD   wIsBackup;
    WORD   wIsUseFlag;
    DWORD  dwID;
    DWORD  dwFlagCount;
    NV_BACKUP_FLAG_T nbftArray[MAX_NV_BACKUP_FALG_NUM];
}NV_BACKUP_ITEM_T,*PNV_BACKUP_ITEM_T;


typedef struct _LINKED_FILE_T
{
    _LINKED_FILE_T()
    {
        memset(this,0,sizeof(_LINKED_FILE_T));
    }
    _TCHAR szFileID[MAX_PATH];
    DWORD  dwDLFlag;
}LINKED_FILE_T,*LINKED_FILE_PTR;

typedef std::vector<LINKED_FILE_PTR> LINKED_FILE_ARR;


typedef struct _SPECIAL_STRING_T
{
    _SPECIAL_STRING_T()
    {
        memset(this,0,sizeof(_SPECIAL_STRING_T));
    }
    _TCHAR szName[MAX_PATH];
    _TCHAR szContent[MAX_PATH];
    _TCHAR szIncluedFileID[MAX_PATH];
    LINKED_FILE_ARR * pLinkedFileIDs;

    void Clear()
    {
        if(pLinkedFileIDs != NULL)
        {
            LINKED_FILE_ARR &lfa = *pLinkedFileIDs;
            for(UINT i=0; i< lfa.size();i++)
            {

                if(lfa[i] != NULL)
                {
                    delete lfa[i];
                }
            }
            pLinkedFileIDs->clear();

            delete pLinkedFileIDs;
        }
        memset(this,0,sizeof(_SPECIAL_STRING_T));
    }
}SPECIAL_STRING_T,*SPECIAL_STRING_PTR;

typedef std::vector<SPECIAL_STRING_PTR> SPECIAL_STRING_ARR;

typedef struct _CHIPITEM_T
{
    DWORD dwID;
    TCHAR szName[50];
}CHIPITEM_T,* CHIPITEM_PTR;

typedef struct _CHIPS_T
{
    BOOL  bEnable;
    DWORD dwCount;
    CHIPITEM_PTR pChips;
}CHIPS_T;

typedef struct _PARTITION
{
    char  szID[MAX_REP_ID_LEN*2];
    DWORD  dwSize;
}PARTITION_T;

typedef struct _PARTITION_INFO_T
{
	char	szID1[MAX_REP_ID_LEN*2];          	// Unicode string
	char	szID2[MAX_REP_ID_LEN*2];          	// Unicode string
	DWORD	dwSize;							// size 
	BYTE	type;							// 0:IMG_RAW,1: IMG_NV,2,IMG_SPARSE
	BYTE	reserved1;
	BYTE	reserved2;
	BYTE	reserved3;

}PARTITION_INFO_T,*PARTITION_INFO_PTR;

typedef struct _EXTTBL_HEADER_T
{
	BYTE	byTag[4];
	DWORD   dwOffset;
	DWORD	dwSize;
}EXTTBL_HEADER_T;

typedef struct _EXTTBL_DATA_T
{
	DWORD	dwSize;
	LPBYTE	pData;
	_EXTTBL_DATA_T()
    {
        memset(this,0,sizeof(_EXTTBL_DATA_T));
    }
}EXTTBL_DATA_T,*EXTTBL_DATA_PTR;

typedef struct _PRODUCT_INFO_T
{
	_TCHAR              szProductName[MAX_PATH];
	FILE_INFO_T        *pFileInfoArr;
	DWORD               dwFileCount;
	DWORD               dwFlashType;
	DWORD               dwMode;
	DWORD               dwNvBackupFlag;
	DWORD               dwNvBackupItemCount;
	NV_BACKUP_ITEM_T   *paNvBackupItem;
	DWORD               dwNvBaseChangeFlag;
	DWORD               dwNvNewBasePosition;
	_TCHAR              szComment[MAX_PATH+1];
	DWORD               dwNVOrgFlag;
	DWORD               dwNVOrgBasePosition;
	DWORD               dwOmaDMFlag;
	SPECIAL_STRING_ARR *pSpecialStrings;
	CHIPS_T             tChips;
	BYTE                bRebootByAT;
	BYTE                reserved1;
	BYTE                reserved2;
	BYTE                reserved3;
	PARTITION_T        *pPartitions;
	DWORD               dwPartitionCount;
	DWORD               dwExtTblCount;
	EXTTBL_HEADER_T*	pExtTblHeader;
	EXTTBL_DATA_T*		pExtTblData;
	DWORD              	dwExtTblDataSize;
	CHIPS_T             tRfChips;

	_PRODUCT_INFO_T()
	{
	    memset(this,0,sizeof(_PRODUCT_INFO_T));
	}

	void Clear()
	{
		if(pFileInfoArr != NULL)
		{
		   	 delete [] pFileInfoArr;
		}

		if(paNvBackupItem != NULL)
		{
		    	delete [] paNvBackupItem;
		}

		if(pSpecialStrings != NULL)
		{
			SPECIAL_STRING_ARR &ssa = *pSpecialStrings;
			for(UINT i=0; i< ssa.size();i++)
			{
			    if(ssa[i] != NULL)
			    {
			        ssa[i]->Clear();
			        delete ssa[i];
			    }
			}
			pSpecialStrings->clear();

			delete pSpecialStrings;
		}

		if(tChips.pChips != NULL)
		{
		   	 delete [] tChips.pChips;
		}

		if(tRfChips.pChips != NULL)
		{
		   	 delete [] tRfChips.pChips;
		}

		if(pPartitions != NULL)
		{
		    	delete [] pPartitions;
		}
		if (pExtTblHeader)
		{
			delete [] pExtTblHeader;
		}
		if (pExtTblData)
		{
			for (DWORD i=0; i<this->dwExtTblCount; ++i)
			{
				EXTTBL_DATA_PTR pItemData = pExtTblData+i;
				if (pItemData->pData)
				{
					delete [] pItemData->pData;
				}
			}
			delete []pExtTblData;
		}
		memset(this,0,sizeof(_PRODUCT_INFO_T));
	}

	BOOL DeepCopy(_PRODUCT_INFO_T *pSrc)
	{
		this->Clear();
		if(pSrc == NULL)
		{
		    return FALSE;
		}
		memcpy(this,pSrc,sizeof(_PRODUCT_INFO_T));

		if(this->dwFileCount!=0)
		{
		    this->pFileInfoArr = new FILE_INFO_T[this->dwFileCount];
		    if(this->pFileInfoArr == NULL)
		    {
		        memset(this,0,sizeof(_PRODUCT_INFO_T));
		        return FALSE;
		    }

		    memcpy(this->pFileInfoArr,pSrc->pFileInfoArr,sizeof(FILE_INFO_T)*(this->dwFileCount));
		}

		if(this->dwNvBackupItemCount != 0)
		{
		    this->paNvBackupItem = new NV_BACKUP_ITEM_T[this->dwNvBackupItemCount];
		    if(this->paNvBackupItem == NULL)
		    {
		        if(this->pFileInfoArr != NULL)
		        {
		            delete [] this->pFileInfoArr;
		            this->pFileInfoArr = NULL;
		        }
		        memset(this,0,sizeof(_PRODUCT_INFO_T));
		        return FALSE;
		    }
		    memcpy(this->paNvBackupItem,pSrc->paNvBackupItem,sizeof(NV_BACKUP_ITEM_T)*(this->dwNvBackupItemCount));
		}

		// need deal with this
		this->pSpecialStrings = NULL;

		if(this->tChips.dwCount != 0)
		{
		    this->tChips.pChips = new CHIPITEM_T[this->tChips.dwCount];
		    if(this->tChips.pChips == NULL)
		    {
		        Clear();
		        return FALSE;
		    }
		    else
		    {
		        memcpy(this->tChips.pChips,pSrc->tChips.pChips, sizeof(CHIPITEM_T)*this->tChips.dwCount);
		    }
		}

		if(this->tRfChips.dwCount != 0)
		{
		    this->tRfChips.pChips = new CHIPITEM_T[this->tRfChips.dwCount];
		    if(this->tRfChips.pChips == NULL)
		    {
		        Clear();
		        return FALSE;
		    }
		    else
		    {
		        memcpy(this->tRfChips.pChips,pSrc->tRfChips.pChips, sizeof(CHIPITEM_T)*this->tRfChips.dwCount);
		    }
		}
		if(this->dwPartitionCount != 0)
		{
		    this->pPartitions = new PARTITION_T[this->dwPartitionCount];
		    if(this->pPartitions == NULL)
		    {
		        Clear();
		        return FALSE;
		    }
		    else
		    {
		        memcpy(this->pPartitions,pSrc->pPartitions, sizeof(PARTITION_T)*this->dwPartitionCount);
		    }
		}
		if ( this->dwExtTblCount != 0 )
		{
			this->pExtTblHeader = new EXTTBL_HEADER_T[this->dwExtTblCount];
			this->pExtTblData	= new EXTTBL_DATA_T[this->dwExtTblCount];
			if (NULL == this->pExtTblHeader || NULL == this->pExtTblData)
			{
				Clear();
				return FALSE;
			}
			else
			{
				memcpy(this->pExtTblHeader,pSrc->pExtTblHeader, sizeof(EXTTBL_HEADER_T)*this->dwExtTblCount);
				memcpy(this->pExtTblData,pSrc->pExtTblData, sizeof(EXTTBL_DATA_T)*this->dwExtTblCount);
			}
			BOOL bOk = TRUE;
			for (DWORD i=0; i<this->dwExtTblCount; ++i)
			{
				EXTTBL_DATA_PTR pDestInfo = this->pExtTblData+i;
				EXTTBL_DATA_PTR pSrcInfo  = pSrc->pExtTblData+i;
				if (pDestInfo->dwSize)
				{
					pDestInfo->pData = new BYTE[pSrcInfo->dwSize];
					if (NULL == pDestInfo->pData)
					{
						bOk = FALSE;
						break;
					}
					memcpy(pDestInfo->pData,pSrcInfo->pData, pSrcInfo->dwSize);
				}
			}
			if(!bOk)
			{
				Clear();
				return FALSE;
			}
		}
	    return TRUE;
	}

}PRODUCT_INFO_T,*PPRODUCT_INFO_T;


typedef std::map<std::string, PPRODUCT_INFO_T>   PRODUCT_MAP;


typedef struct _BOOTMODEOBJ_T
{
    _BOOTMODEOBJ_T()
    {
        memset(this,0,sizeof(_BOOTMODEOBJ_T));
    }

    IBootModeHandler* pSnapin;
    DWORD             dwCookie;
    BOOL              bStop;
    BOOL              bFirstStart;

}BOOTMODEOBJ_T, *PBOOTMODEOBJ_T;

static const TCHAR FILE_OMIT[] = _T("OMIT");

/* Start flash infomation define */
typedef struct _EMC_TIMING_T
{
    _EMC_TIMING_T()
    {
        memset(this,0,sizeof(_EMC_TIMING_T));
    }


    DWORD dwRdTime;
    DWORD dwRdHoldTime;
    DWORD dwWrTime;
    DWORD dwWrHoldTime;
    DWORD dwW2wTrTime;
    DWORD dwW2rTrTime;
    DWORD dwR2wTrTime;
    DWORD dwR2rTrTime;

}EMC_TIMING_T,*PEMC_TIMING_T;

typedef struct _BLOCK_SPEC_T
{
    _BLOCK_SPEC_T()
    {
        memset(this,0,sizeof(_BLOCK_SPEC_T));
    }

    DWORD dwSectorStartAddr;
    DWORD dwSectorSize;
    DWORD dwSectorEndAddr;
    DWORD dwReserved; //保留字段

}BLOCK_SPEC_T,*PBLOCK_SPEC_T;

typedef struct _FLASH_SPEC_T
{
    _FLASH_SPEC_T()
    {
        memset(this,0,sizeof(_FLASH_SPEC_T));
    }

    DWORD dwFlashID;
    DWORD dwDeviceID;
    DWORD dwExtendID;
    DWORD dwVersion;        //结构的版本
    DWORD dwDriverSort;     // amd = 0,intel = 1,sst = 2
    DWORD dwWriteBufLen;
    DWORD dwFlashSize;
    EMC_TIMING_T etMemTiming;
    DWORD dwReserved[10];      //保留字段
    DWORD dwRealBlockNum;
    BLOCK_SPEC_T bsBlockStruct[10];

}FLASH_SPEC_T,*PFLASH_SPEC_T;
/* End flash infomation define */

typedef enum
{
    BMAF_TIME_WAIT_FOR_NEXT_CHIP = 0,
    BMAF_NAND_REPARTION_FLAG,
    BMAF_SPECIAL_CONFIG_FILE,
    BMAF_READ_FLASH_BEFORE_REPARTITION,
    BMAF_SPEC_FILE_TYPE,
    BMAF_SPEC_PACKET_LENGTH,
    BMAF_ENABLE_PORT_SECOND_ENUM,
    BMAF_POWER_OFF_DEVICE
}BMAF_PROPERTY_ID_E;

//BMAF error
#define BMAF_E_STRART_LOG_FAIL          ((DWORD)0x80048001L)
#define BMAF_E_COM_INIT_FAIL            ((DWORD)0x80048002L)
#define BMAF_E_REG_BMOBJ_FAIL           ((DWORD)0x80048003L)
#define BMAF_E_REG_BMPOBSERVER_FAIL     ((DWORD)0x80048004L)
#define BMAF_E_INIT_BMFILES_FAIL        ((DWORD)0x80048005L)
#define BMAF_E_OUTOFMEMORY              ((DWORD)0x80048006L)
#define BMAF_E_REG_DLL_FAIL             ((DWORD)0x80048007L)


#endif //__BMAGLOBAL__H_
