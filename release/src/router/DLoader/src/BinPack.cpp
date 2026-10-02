// BinPack.cpp: implementation of the CBinPack class.
//
//////////////////////////////////////////////////////////////////////
#include "BinPack.h"
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
extern "C"
{
#include "crc16.h"
}

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

#define MAX_RW_SIZE   (0xA00000)   //10M

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

// version 1.0.0
const _TCHAR CBinPack::m_szVersion[24] = _T("BP_R1.0.0");
const _TCHAR SZ_BINPAC_VER2[24] = _T("BP_R2.0.1"); //support safe pac and 64bit size

CBinPack::CBinPack()
{
	//m_hFile = INVALID_HANDLE_VALUE;
	m_strReleaseDir = _T("");
	m_strCfgPath = _T("");
	//m_pXMLDoc = NULL;   //lint !e63
	//m_pFileNodeList = NULL; //lint !e63
	#ifdef _DOWNLOAD_FOR_PRODUCTION
	m_bIsExistEmptyFile = FALSE;
	#endif
	/*lint -e1401*/
}
/*lint -restore*/

CBinPack::~CBinPack()
{
	/*lint -save -e1740 */
}
/*lint -restore */


/** Unpacket the packet to bin files into one specified directory
  *
  * @param lpszReleaseDirPath: the directory to release bin files
  *                            If it equals NULL, program will create the directory to system temp directory.
  *                            Suggest to set it null.
  * @param bph: store the packet header
  * @param ppFileArray: store the bin files information into FILE_T struct
  *                     it must be release by the "ReleaseMem" function
  * @return: true,if unpacket successfully;false,otherwise
  */
BOOL CBinPack::Unpacket(LPCTSTR lpszFileName,
                        LPCTSTR lpszReleaseDirPath,
                        BIN_PACKET_HEADER_T &bph,
                        FILE_T ** ppFileArray)
{
	if(ppFileArray == NULL)
	{
		printf(_T("CBinPacket::Unpacket, Invalidate params\n"));
		return FALSE;
	}

	FILE *pFile = fopen(lpszFileName,"rb");

	if(pFile == NULL )
	{
	    printf(_T("CBinPacket::Unpacket, open file \"%s\" failed.\n"),lpszFileName);
	    return FALSE;
	}


	*ppFileArray = NULL;

	if ( -1 == fseeko64(pFile,0,SEEK_END) )        
	{            
		printf(_T("SetFilePointer to end fail,error code: %d,\"%s\"\n"),errno,strerror(errno));     
		fclose(pFile);
		return FALSE;       
	}

	__int64 llPacketSize =  ftello64(pFile);       
	if(-1 == llPacketSize)        
	{            
		printf(_T("GetFileSize [%s] failed,error code: %d,\"%s\"\n"),lpszFileName,errno,strerror(errno));           
		fclose(pFile);
		return FALSE;  
	}
	
	 if ( -1 == fseeko64(pFile,0,SEEK_SET) )        
	 {            
	 	printf(_T("SetFilePointer to FILE_BEGIN fail,error code: %d,\"%s\"\n"),errno,strerror(errno));    
		fclose(pFile);
		return FALSE;  
	}

	//check packet size, it must large than the header struct
      if( llPacketSize < (__int64)sizeof(BIN_PACKET_HEADER_T) )
	{
		printf(_T("CBinPacket::Unpacket, Bin packet's size is too small,maybe it has been destructed!\n"));
		fclose(pFile);
		return FALSE;
	}

	UINT uReadSize = 0;
	WORD wCRC1 = 0;
	WORD wCRC2 = 0;

	uReadSize = fread(&bph,1,sizeof(BIN_PACKET_HEADER_T),pFile);

	BOOL bCRC = FALSE;

	if(bph.dwMagic == PAC_MAGIC)
	{
		bCRC = TRUE;
		wCRC1 = crc16(wCRC1,(BYTE*)&bph,sizeof(bph)-sizeof(WORD));
		if(wCRC1 != 0)
		{
			printf(_T("CBinPacket::Unpacket, CRC Error!\nPAC file may be damaged!"));
			fclose(pFile);
			return FALSE;
		}
	}

#ifdef _DOWNLOAD_FOR_PRODUCTION
    bph.dwIsNvBackup = FALSE; //The Backup NV Function should be disable in Production Line.
#endif

    WinwcharToChar(bph.szPrdName,sizeof(bph.szPrdName));
    WinwcharToChar(bph.szPrdVersion,sizeof(bph.szPrdVersion));
    WinwcharToChar(bph.szPrdAlias,sizeof(bph.szPrdAlias));

    char *pStr =(char*)bph.szPrdName;
	//if(strstr(pStr, _T("PAC_")) !=  pStr)
	//{
	//    std::string str = pStr;
    //    memset(bph.szPrdName,0,sizeof(bph.szPrdName));
    //    sprintf((char*)bph.szPrdName,"PAC_%s",str.c_str());
	//}

	WinwcharToChar(bph.szVersion,sizeof(bph.szVersion));
	// check packet version
	if( 
		uReadSize !=sizeof(BIN_PACKET_HEADER_T) || 
		(strcmp((char*)bph.szVersion, m_szVersion)!=0 && strcmp((char*)bph.szVersion, SZ_BINPAC_VER2)!=0)
	)
	{
		printf(_T("CBinPacket::Unpacket, Bin packet version is not support! pac ver :%s"),(char*)bph.szVersion);
		fclose(pFile);
		return FALSE;
	}

	// check packet size recorded by itself
	__int64 liPacInfoSize = bph.dwHiSize;
	liPacInfoSize = liPacInfoSize << 32;
	liPacInfoSize = liPacInfoSize |bph.dwLoSize;
	
	if( liPacInfoSize != llPacketSize )
	{
		printf(_T("CBinPacket::Unpacket, Bin packet's size is not correct,maybe it has been destructed!\n"));
		printf(_T("bph Size=0x%llX,llPacketSize=0x%llX\n"),liPacInfoSize,llPacketSize);
		fclose(pFile);
		return FALSE;
	}

	// check the number of files packeted by the packet
	if(bph.nFileCount == 0)
	{
		printf(_T("CBinPacket::Unpacket, There is no files in packet!"));
		fclose(pFile);
		return FALSE;
	}
//[[ create temp download file directory
	char strReleaseDir[MAX_PATH] = {0};
	if(lpszReleaseDirPath != NULL)
	{
		sprintf(strReleaseDir,_T("%s/_DownloadFiles%d"),
               lpszReleaseDirPath,GetCycleCount());
        //printf("Allen: [%s]: lpszReleaseDirPath = %s\nGetCycleCount = %llu.\n", __func__, lpszReleaseDirPath, GetCycleCount());
	}
	else
	{
	    /*
	    char *pTmp = getenv("tmp");
		if(pTmp==NULL)
		{
			printf(_T("CBinPacket::Unpacket, Can not get temp path!"));
			fclose(pFile);
			return FALSE;
		}
		*/

        //printf("[%s] /tmp/_DownloadFiles%d.\n", __func__, GetCycleCount());
		sprintf(strReleaseDir,_T("/tmp/_DownloadFiles%d"),
                GetCycleCount());
        //printf("[%s] /overlay/sean/_DownloadFiles.\n", __func__);
		//sprintf(strReleaseDir,_T("/overlay/sean/_DownloadFiles"));
		//sprintf(strReleaseDir,_T("/tmp/_DownloadFiles"));
        //printf("Allen: [%s] GetCycleCount = %llu.\n", __func__, GetCycleCount());
    }
    m_strReleaseDir = strReleaseDir;
    //printf("[%s]: strReleaseDir =  %s \n", __func__, strReleaseDir);

    struct stat file_stat = {0};

    int nRet = stat(strReleaseDir, &file_stat);
	if(nRet== 0 && S_ISDIR(file_stat.st_mode))
	{
		DeleteDirectory(strReleaseDir);
	}

    if(access(strReleaseDir, NULL)!=0 )
    {
        if(mkdir(strReleaseDir, 0755)==-1)
        {
            printf(_T("CBinPacket::Unpacket, create folder fail!"));
            fclose(pFile);
            return  false;
        }
    }

	strcat(strReleaseDir,"/");
//]] create temp download file directory

    uReadSize = 0;
	FILE_T * paFile = new FILE_T[(UINT)bph.nFileCount];
	if(paFile == NULL)
	{
		delete [] paFile;
		printf(_T("CBinPacket::Unpacket, Out of memory!"));
		fclose(pFile);
		return FALSE;
	}
	memset(paFile,0,sizeof(FILE_T)*((UINT)bph.nFileCount));

	uReadSize = fread(paFile,1,(UINT)bph.nFileCount * sizeof(FILE_T),pFile);
	if(uReadSize != ((UINT)bph.nFileCount) * sizeof(FILE_T))
	{
		delete [] paFile;
		printf(_T("CBinPacket::Unpacket, Read pakcet failed,maybe it has been destructed!"));
		return FALSE;
	}

	if(bCRC)
	{
		wCRC2 = crc16(wCRC2,(BYTE*)paFile,(UINT)bph.nFileCount * sizeof(FILE_T));
	}
      FILE_T * pFT = NULL;
	int nOtherFileNum = 0;

    //printf("FileCount = %d\n", bph.nFileCount);            
	for(int i = 0; i < bph.nFileCount; i++)
	{
		pFT = paFile + i;

        //printf("file %d\n", i);            

             WinwcharToChar(pFT->szFileName,sizeof(pFT->szFileName));
		WinwcharToChar(pFT->szFileID,sizeof(pFT->szFileID));
		WinwcharToChar(pFT->szFileVersion,sizeof(pFT->szFileVersion));
		__int64 liImageSize = pFT->dwHiFileSize;
		liImageSize = liImageSize << 32;
		liImageSize = liImageSize |pFT->dwLoFileSize;
#if 0
        printf("szFileName = %s\n", pFT->szFileName);
        printf("szFileID = %s\n", pFT->szFileID);
        printf("szFileVersion = %s\n", pFT->szFileVersion);
        printf("liImageSize =  %lld\n", liImageSize);
#endif

		// check file size if validate
		if(liImageSize <0 || liImageSize>=llPacketSize)
		{
			delete [] paFile;
			printf(_T("CBinPacket::Unpacket, Read pakcet failed,maybe it has been destructed!"));
			fclose(pFile);
			return FALSE;
		}

		if(liImageSize == 0)
		{
#ifdef _DOWNLOAD_FOR_PRODUCTION
			if (pFT->nFileFlag != 0 && pFT->dwCanOmitFlag == 0)  //It needs a file
			{
				m_bIsExistEmptyFile = TRUE;
			}
#endif
			continue;
		}

		std::string strFilePath = strReleaseDir;
		strFilePath += (char*)pFT->szFileName;

		char szF[512] = {0};
		strcpy(szF,strFilePath.c_str());

		int kk = 0;
		while(access(szF, F_OK) == 0) // file is exsited
		{
		    szF[0] = 0;
		    sprintf(szF,"%s%s(%d)",strReleaseDir,(char*)pFT->szFileName,++kk);
		}

		strFilePath = szF;

		memset(pFT->szFileName,0,sizeof(pFT->szFileName));

		strcpy((char*)pFT->szFileName,strFilePath.c_str());

		if(i == bph.nFileCount-1 )
		{
			m_strCfgPath = strFilePath;
		}

		// other files,such as UDISK_IMG
		if(strlen((char*)pFT->szFileID)==0)
		{
			nOtherFileNum++;
		}

		DWORD dwWritten = 0;

		FILE *pf =  fopen(strFilePath.c_str(), "wb");

		if (pf == NULL)
		{
			delete [] paFile;
            printf(_T("CBinPacket::Unpacket, Release bin file failed!"));
			fclose(pFile);
			return FALSE;
		}

		__int64 liLeft = liImageSize;
		DWORD  dwRWSize = MAX_RW_SIZE;
		LPBYTE pBuf = new BYTE[MAX_RW_SIZE];
		BOOL   bFlag = FALSE;

		while(liLeft>0)
		{
			memset(pBuf,0,MAX_RW_SIZE);
			if(liLeft<MAX_RW_SIZE)
			{
				dwRWSize = (DWORD)liLeft;
			}

			fread(pBuf,1,dwRWSize,pFile);
			if(bCRC)
			{
				wCRC2 = crc16(wCRC2,(BYTE*)pBuf,dwRWSize);
			}

			if(i == bph.nFileCount-1 )
			{
				if(dwRWSize == liLeft)
				{
					if(pBuf[dwRWSize-1] == 0)
					{
						dwRWSize--;
						bFlag = TRUE;
					}
				}
			}

			dwWritten = 0;
			dwWritten = fwrite(pBuf, 1, dwRWSize, pf);
			if(dwWritten != dwRWSize)
			{
				fclose(pf);
				delete [] paFile;
				delete [] pBuf;
				printf(_T("CBinPacket::Unpacket, Write bin file failed!"));
				fclose(pFile);
				return FALSE;
			}

			if(bFlag )
			{
				dwRWSize++;
			}

			liLeft -= dwRWSize;
            //printf("OK!\n");
		}

		delete [] pBuf;
		fclose(pf);
	}

	bph.nFileCount = bph.nFileCount-nOtherFileNum;

	*ppFileArray = new FILE_T[(UINT)bph.nFileCount];
	memcpy(*ppFileArray,paFile,sizeof(FILE_T)*(UINT)bph.nFileCount);
	delete [] paFile;

	if(bCRC)
	{
		wCRC2 = crc16(wCRC2,(BYTE*)&bph.wCRC2,sizeof(WORD));
		if(wCRC2 != 0)
		{
			printf(_T("CBinPacket::Unpacket, CRC Error, PAC file may be damaged!"));

			return FALSE;
		}
	}

    //printf("%s OK\n", __func__);
	return TRUE;
}

/** Release the memory newed by Unpacket function
  *
  * @param paFile: point to FILE_T buffer
  */
void CBinPack::ReleaseMem(FILE_T * paFile)
{
	if(paFile != NULL)
	{
		delete [] paFile;
	}
}

/** Delete the directory,all its sub directories and files
  *
  * @param paFile: the directory name
  */
BOOL CBinPack::DeleteDirectory(LPCTSTR lpszDirName)// DeleteDirectory(_T("c:\\aaa"))
{
	if(lpszDirName== NULL)
		return TRUE;

    if(delete_dir(lpszDirName) == 0)
        return TRUE;
    else
        return FALSE;

}
/** Get released directory
  *
  * @return: the path of released path
  */
std::string CBinPack::GetReleaseDir()
{
	return m_strReleaseDir;
}
/**  Remove released directory
  *
  * @param lpszDir: directory path
  * @return: true,if remove successful; false,otherwise
  */
BOOL CBinPack::RemoveReleaseDir(LPCTSTR lpszDir)
{
	if(lpszDir == NULL)
		return TRUE;

	return DeleteDirectory(lpszDir);
}

/** Remove released directory
  *
  * @return: true,if remove successful; false,otherwise
  */
BOOL CBinPack::RemoveReleaseDir()
{
	return DeleteDirectory(m_strReleaseDir.c_str());
}

std::string CBinPack::GetConfigFilePath()
{
	return m_strCfgPath;
}

void CBinPack::WinwcharToChar(WORD *pBuf, int nSize)
{
    wchar_t * pWBuf = new wchar_t[nSize];
    memset(pWBuf,0,nSize*sizeof(wchar_t));

    for(int i = 0; i< nSize/2; i++)
    {
        pWBuf[i] = pBuf[i];
    }
    memset(pBuf,0,nSize);

    wcstombs((char*)pBuf,pWBuf,nSize);

    delete []  pWBuf;
}
