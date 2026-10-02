// BinPack.h: interface for the CBinPack class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_BINPACK_H__8A419B31_D187_415E_A4B6_9F8E1E15AE69__INCLUDED_)
#define AFX_BINPACK_H__8A419B31_D187_415E_A4B6_9F8E1E15AE69__INCLUDED_

//lint ++flb

#include "typedef.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <string>

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#define _MAX_BLOCK_NUM   5
#define _MAX_NV_BACKUP_FALG_NUM 5
#define PAC_MAGIC       (0xFFFAFFFA)

/************************************************************************/
/* File address infomation                                              */
/************************************************************************/
struct _X_BLOCK_T
{
	_X_BLOCK_T()
    {
        memset(this,0,sizeof(_X_BLOCK_T));
    }

	DWORD dwBase;
	DWORD dwSize;
};

/************************************************************************/
/* File infomation                                                      */
/************************************************************************/
struct _X_FILE_INFO_T
{
	_X_FILE_INFO_T()
    {
        memset(this,0,sizeof(_X_FILE_INFO_T));
    }

	_TCHAR		szID[MAX_PATH];
	_TCHAR		szType[MAX_PATH];
	DWORD		dwFlag;
	_X_BLOCK_T	arrBlock[_MAX_BLOCK_NUM];
	DWORD		dwBlockCount;
	DWORD       dwCheckFlag;
};

struct _X_NV_BACKUP_FLAG_T
{
	_TCHAR szFlagName[MAX_PATH];
	DWORD  dwCheck;
};

struct _X_NV_BACKUP_ITEM_T
{
	_X_NV_BACKUP_ITEM_T()
    {
        memset(this,0,sizeof(_X_NV_BACKUP_ITEM_T));
    }
	_TCHAR szItemName[MAX_PATH];
	WORD   wIsBackup;
	WORD   wIsUseFlag;
	DWORD  dwID;
	DWORD  dwFlagCount;
	_X_NV_BACKUP_FLAG_T nbftArray[_MAX_NV_BACKUP_FALG_NUM];
};
/************************************************************************/
/* FILE_T struct storing file information                               */
/************************************************************************/

typedef struct _FILE_T
{
	_FILE_T()
	{
		memset(this,0,sizeof(_FILE_T));
		dwSize = sizeof(_FILE_T);
	}

    DWORD  dwSize;				// size of this struct itself
	WORD   szFileID[256];		// file ID,such as FDL,Fdl2,NV and etc.
	WORD   szFileName[256];     // file name,in the packet bin file,it only stores file name
	                            // but after unpacketing, it stores the full path of bin file
	WORD   szFileVersion[252];  // Reserved now; V1->V2 : 256*2 --> 252*2
	DWORD  dwHiFileSize;        // hight file size
	DWORD  dwHiDataOffset;      // hight file size
	DWORD  dwLoFileSize;           // file size
	int    nFileFlag;           // if "0", means that it need not a file, and
	                            // it is only an operation or a list of operations, such as file ID is "FLASH"
	                            // if "1", means that it need a file
	DWORD  nCheckFlag;          // if "1", this file must be downloaded;
	                            // if "0", this file can not be downloaded;
	DWORD  dwLoDataOffset;        // the offset from the packet file header to this file data
	DWORD  dwCanOmitFlag;		// if "1", this file can not be downloaded and not check it as "All files"
								//   in download and spupgrade tool.
	DWORD  dwAddrNum;
	DWORD  dwAddr[5];
	DWORD  dwReserved[249];     // Reserved for future,not used now
}FILE_T/*, *PFILE_T*/;

/************************************************************************/
/* BIN_PACKET_HEADER_T struct storing packet header information         */
/************************************************************************/
typedef struct _BIN_PACKET_HEADER_T
{
	_BIN_PACKET_HEADER_T()
	{
		memset(this,0,sizeof(_BIN_PACKET_HEADER_T));
		dwMagic = PAC_MAGIC;
	}
	WORD   szVersion[22];		// packet struct version; V1->V2 : 24*2 -> 22*2
	DWORD  dwHiSize;			// the whole packet hight size;
	DWORD  dwLoSize;            // the whole packet low size;
	WORD   szPrdName[256];		// product name
	WORD   szPrdVersion[256];   // product version
	int    nFileCount;          // the number of files that will be downloaded, the file may be an operation
	DWORD  dwFileOffset;		// the offset from the packet file header to the array of FILE_T struct buffer
	DWORD  dwMode;
	DWORD  dwFlashType;
	DWORD  dwNandStrategy;
	DWORD  dwIsNvBackup;
	DWORD  dwNandPageType;
	WORD   szPrdAlias[100];    // product alias
	DWORD  dwOmaDmProductFlag;
	DWORD  dwIsOmaDM;
	DWORD  dwIsPreload;
    DWORD  dwReserved[200];
	DWORD  dwMagic;
	WORD   wCRC1;
	WORD   wCRC2;
}BIN_PACKET_HEADER_T,*PBIN_PACKET_HEADER_T;

/************************************************************************/
/* Class CBinPack, it packets the bin files and unpackets the packet    */
/************************************************************************/
class CBinPack
{
public:
	CBinPack();
	virtual ~CBinPack();

public:
/** Packet bin files into one file with certain struct
  *
  * @param lpszPrdName: the product name
  * @param lpszPrdVersion: the version of the product
  * @param lpszCfgFile: the name of configure file (*.xml)
  * @param pFileArray: point to an array of FILE_T struct
  * @param nFileCount: the number of FILE_T in the buffer pointer by pFileArray
  * @param nFlag: not used now
  * @return: true,if packet successfully;false,otherwise
  */
/*	BOOL Packet(LPCTSTR lpszFileName,
                const PBIN_PACKET_HEADER_T pbph,
                LPCTSTR lpszCfgFile,
                FILE_T * pFileArray,
			    BOOL bNVBackup,
			    _X_NV_BACKUP_ITEM_T *pnbi,
			    int nNBICount,int nFlag);
*/
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
	BOOL Unpacket(LPCTSTR lpszFileName,
                  LPCTSTR lpszReleaseDirPath,
                  BIN_PACKET_HEADER_T &bph,
                  FILE_T ** ppFileArray);

/** Release the memory newed by Unpacket function
  *
  * @param paFile: point to FILE_T buffer
  */
	void ReleaseMem(FILE_T * paFile);

/** Get released directory
  *
  * @return: the path of released path
  */
	std::string GetReleaseDir();

/** Remove released directory
  *
  * @param lpszDir: directory path
  * @return: true,if remove successful; false,otherwise
  */
	BOOL RemoveReleaseDir(LPCTSTR lpszDir);

/** Remove released directory
  *
  * @return: true,if remove successful; false,otherwise
  */
	BOOL RemoveReleaseDir();

/** Get xml configure file path
  *
  * @return: the path of xml configure
  */
   std::string GetConfigFilePath();

/*  Check If there is empty file in pac files
 *
 *  @Return: TRUE: Exist more the one empty file;
 *           FALSE: Doesn't exist empty file;
   */
#ifdef _DOWNLOAD_FOR_PRODUCTION
   BOOL IsExistEmptyFile(){
	   return m_bIsExistEmptyFile;
   };
#endif
private:

/** Delete the directory,all its sub directories and files
  *
  * @param paFile: the directory name
  */
	BOOL DeleteDirectory(LPCTSTR lpszDirName);

	void WinwcharToChar(WORD *pBuf, int nSize);

	static const _TCHAR m_szVersion[24]; // the version of packet struct itself

	std::string m_strReleaseDir;
	std::string m_strCfgPath;

#ifdef _DOWNLOAD_FOR_PRODUCTION
	BOOL m_bIsExistEmptyFile;
#endif

};
//lint --flb
#endif // !defined(AFX_BINPACK_H__8A419B31_D187_415E_A4B6_9F8E1E15AE69__INCLUDED_)
