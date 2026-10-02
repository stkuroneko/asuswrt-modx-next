#ifndef CDLOADER_H
#define CDLOADER_H
#include "BootModeitf.h"
#include <sys/mman.h>
#include <map>
#include <string>
#include "ProcMonitor.h"
#include "BMAFImp.h"
#include "Settings.h"

#define PRODUCTION_INFO_SIZE    (0x2000)         //8K
#define X_SN_LEN                (64)

struct PORT_DATA
{
	DWORD	dwPort;
	LPBYTE	lpPhaseCheck;
	HANDLE	hSNEvent;
	char   	szSN[X_SN_LEN+1];
	PORT_DATA()
	{
		memset(this,0, sizeof(PORT_DATA));
	}
	void Clear()
	{
		SAFE_DELETE_ARRAY(lpPhaseCheck);
		memset(this,0, sizeof(PORT_DATA));
	}
};

#define  MAX_RECEIVE_SIZE   0x0800

typedef struct _BACKUP_INFO
{
	TCHAR szNVFile[MAX_PATH];
	BYTE* pBuf;
	DWORD dwSize;
	_BACKUP_INFO()
	{
		memset(this,0, sizeof(_BACKUP_INFO));
	}
	void Clear()
	{
		SAFE_DELETE_ARRAY(pBuf);
		memset(this,0, sizeof(_BACKUP_INFO));
	}

}BACKUP_INFO,*BACKUP_INFO_PTR;

#define MAX_BACKUP_FILE_NUM 10


struct _BMOBJ
{
	_BMOBJ()
	{
		memset(this,0, sizeof(_BMOBJ));
	}

	void Clear()
	{
		//SAFE_DELETE_ARRAY(pBuf);
		for(int i =0; i< MAX_BACKUP_FILE_NUM;i++)
		{
			SAFE_DELETE_ARRAY(tFileBackup[i].pBuf);
			SAFE_DELETE_ARRAY(tNVBackup[i].pBuf);
		}

		memset(this,0, sizeof(_BMOBJ));
	}

	DWORD dwCookie;
	DWORD dwIsUart;
	DWORD dwChipID;
	DWORD aFlashType[4];
	//DWORD dwBufSize;
	DWORD dwPage;
	DWORD dwOob;
	//BYTE* pBuf;
	char  szSN[X_SN_LEN+1];
	char  szIMEI[X_SN_LEN+1];
	TCHAR szErrorMsg[_MAX_PATH*2];
	TCHAR szMcpInfo[_MAX_PATH];
	TCHAR szBlockPageSize[64];			//_bxk_pxk || _bxx_pxx  
	BACKUP_INFO tFileBackup[MAX_BACKUP_FILE_NUM];
	BACKUP_INFO tNVBackup[MAX_BACKUP_FILE_NUM];
	int  nStage; 	// 1:need second enum, 0/2: done!
	DWORD  dwRFChipType;
};

typedef struct _EXT_IMG_INFO
{
	_EXT_IMG_INFO()
	{
		memset(this,0, sizeof(_EXT_IMG_INFO));
		fd=-1;
	}
	DWORD dwSize;
	DWORD dwFirstMapSize;
	BYTE *pBuf;
	TCHAR szFilePath[MAX_PATH];
	BOOL   bIsFileMap;
	int   fd;

	void clear()
	{
		if(!bIsFileMap)
		{
			if(pBuf != NULL)
			{
				delete [] pBuf;
			}
		}
		else
		{
            if( pBuf)
			{
                munmap((void *)pBuf, dwFirstMapSize );
			}
			if( fd  != -1 )
			{
				close(fd);
			}
		}

		memset(this,0, sizeof(_EXT_IMG_INFO));
		fd = -1;
	}
}EXT_IMG_INFO,*EXT_IMG_INFO_PTR;

typedef struct _DUT_KEY_T
{
    _DUT_KEY_T()
    {
        memset(this,0,sizeof(_DUT_KEY_T));
        ver[0] = '1';
    }
    BYTE  ver[4];
    char  szDUTKey[MAX_PATH];	// key
    BYTE  Reserved[760];        // unused
}DUT_KEY_T,*PDUT_KEY_T;

typedef std::map<DWORD,EXT_IMG_INFO_PTR> MAP_EXTIMG;

typedef std::map<std::pair<DWORD,std::string>,EXT_IMG_INFO_PTR> MAP_FILEBUF;

typedef std::map<std::pair<std::string,std::string>,EXT_IMG_INFO_PTR> MAP_FILEBUF_PB; //page block
typedef std::map<std::string, DWORD> MAP_STRINT;

typedef std::map<DWORD, _BMOBJ* > MAP_BMPOBJ;

typedef std::map<std::string,BACKUP_INFO_PTR> MAP_NVFILE;
typedef std::map<std::pair<DWORD,std::string>,BACKUP_INFO_PTR> MAP_MULTI_NVFILE;
typedef std::map<DWORD,PORT_DATA*> MAP_PORT_DATA;

struct BMFileInfo_TAG;
static _TCHAR g_sz_NVITEM[]	= _T("nvitem");

class CDLoader: public IBMOprObserver
{
public:
	CDLoader();
	virtual ~CDLoader();
	//
	STDMETHOD(OnStart)(  DWORD dwOprCookie,
		                 DWORD dwResult );
	STDMETHOD(OnEnd)(  DWORD dwOprCookie,
		               DWORD dwResult );
	STDMETHOD(OnOperationStart)(  DWORD dwOprCookie,
								  const char* cbstrFileID,
		                          const char* cbstrFileType,
					              const char* cbstrOperationType,
	                              void * pBMFileInterface );
	STDMETHOD(OnOperationEnd)(  DWORD dwOprCookie,
								const char* cbstrFileID,
								const char* cbstrFileType,
								const char* cbstrOperationType,
								DWORD dwResult,
								void* pBMFileInterface );
	STDMETHOD(OnFileOprStart)( DWORD dwOprCookie,
							   	const char* cbstrFileID,
							   	const char* cbstrFileType,
	                           				void * pBMFileInterface );
	STDMETHOD(OnFileOprEnd)( DWORD dwOprCookie,
								const char* cbstrFileID,
								const char* cbstrFileType,
								DWORD dwResult );

	STDMETHOD(OnFilePrepare)(DWORD dwOprCookie,
							 const char* bstrProduct,
							 const char* bstrFileName,
							 void * lpFileInfo,
							 /*[out]*/ void *    pBMFileInfoArr,
							 /*[out]*/ DWORD*    lpBMFileInfoCount,
							 /*[out]*/ DWORD*    lpdwFlag );

	BOOL InitDownload();
	BOOL LoadPacket(const char *szPac);
	void SetReplaceDLFiles(std::map<std::string,std::string>& mapReplaceDLFile);
	BOOL StartDownload(const char *szDev, UINT baudrate, UINT nPort);
	BOOL StopDownload(UINT nPort);

	BOOL CheckDLFiles();

	void GetOprErrorCodeDescription(DWORD dwErrorCode,
									LPTSTR lpszErrorDescription,
									int nSize );
	DWORD BCDToWString(LPBYTE pBcd,DWORD dwSize,LPTSTR szStr,DWORD dwStrLen);

	BOOL IsEnd(){return m_bEnd;}
	BOOL IsDownloadPass(){return m_bDownloadPass;}

	void SetEnd(BOOL bEnd = TRUE){m_bEnd = bEnd; }
	BOOL GetFilePathInfo(LPCTSTR szFile,std::vector<std::string> &agInfo);
	PORT_DATA* 		CreatePortData( DWORD dwPort );
	PORT_DATA * 	GetPortDataByPort(DWORD dwPort);
	BOOL 			AcquireBarcode(DWORD dwPort);
	void			SetSNString(const char *szSN){m_strInputSN = string(szSN);}
	string			GetDLDevCfg(){return m_strDlDev;}
	string			GetEntryCmd(){return m_strEntryModeCmd;}


protected:
	BOOL 				InitNVBuffer();
	void 				ClearNVBuffer();
	void 				ClearMultiNVMap();
	BOOL 				InitPartitionData();
	BOOL 				InitExtTblData();

	BOOL 				AddEraseAll(PBMFileInfo pBMFileInfo);
	BOOL 				AddReadSN(PBMFileInfo pBMFileInfo);
	BOOL 				AddBackupFiles(PBMFileInfo pBMFileInfo, int &nCount, _BMOBJ *pbj, PFILE_INFO_T pFileInfo);
	void 				ClearMapPBFileBuf();
	BOOL 				InitMapPBFileBuf();
	BOOL 				InitMultiNVBuffer();

	std::string  			Format(const char *fmt, ...);
	EXT_IMG_INFO_PTR 	LoadPageBlockFile(LPCTSTR lpszFile);
	void 				LoadConfigFile();
	void 				CheckPort2ndEnum();
	BOOL 				LoadFileFromLocal(LPCTSTR pszFileName, LPBYTE &pBuf,DWORD &dwSize, __int64 llSize = 0,  __int64 llOffset = 0);
	BOOL 				GetDUTKeyInfo(LPBYTE pBuf, DWORD dwSize,DUT_KEY_T& stDutKey);
	BOOL 				CheckPacKey();

public:
	CSettings    	m_Settings;
	LPBYTE		m_pPartitionData;
	DWORD      	m_dwPartitionSize;
	LPBYTE 		m_pExtTblData;
	DWORD 		m_dwExtTblSize;	
	BOOL            m_bPortSecondEnum;
	BOOL            m_bPacHasKey ;

	 int     		m_nEnumPortTimeOut;
protected:
	CProcMonitor 		m_ProcMonitor;
	CBMAFImp    		m_BMAF;
	MAP_BMPOBJ   		m_mapBMObj;
	MAP_PORT_DATA		m_mapPortData;	
private:
	LPBYTE       		m_pMasterImg;
	MAP_NVFILE 			m_mapNVFileInfo;	 
	MAP_MULTI_NVFILE	m_mapMultiNVInfo;
	MAP_STRINT        	m_mapPBInfo;
	MAP_FILEBUF_PB     	m_mapPBFileBuf;
	volatile BOOL       m_bEnd;
	int					m_nReplacePolicy;
	int					m_nBackupProdnvMiscdata;
	int				 	m_nSNLength;
	BOOL				m_bDual_SN;
	string				m_strInputSN;
	string				m_strDlDev;
	string				m_strEntryModeCmd;
	BOOL				m_bDownloadPass;
};

#endif // CDLOADER_H
