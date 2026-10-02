// BMFileImpl.cpp: implementation of the CBMFileImpl class.
//
//////////////////////////////////////////////////////////////////////

#include "BMFileImpl.h"
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mman.h>

/*
static BOOL GetAbsolutePath(CString &strAbsoluteFilePath,LPCTSTR lpszFilePath )
{
    _TCHAR szFileName[_MAX_FNAME];
    _TCHAR szDir[_MAX_DIR];
    _TCHAR szDirve[_MAX_DRIVE];

    _tsplitpath( lpszFilePath,szDirve,NULL,NULL,NULL);
    if( szDirve[0] == _T('\0') ){//do it if strHelpTopic is ralatively
        GetModuleFileName( AfxGetApp()->m_hInstance, szFileName,_MAX_FNAME);
        _tsplitpath( szFileName , szDirve , szDir , NULL , NULL );
        strAbsoluteFilePath = szDirve;
        strAbsoluteFilePath += szDir;
        if( lpszFilePath[0] == _T('\\') || lpszFilePath[0] == _T('/') )
            lpszFilePath++;

        strAbsoluteFilePath += lpszFilePath;
    }else{
        strAbsoluteFilePath = lpszFilePath;
    }
    return true;
}
*/
IBMFile::~IBMFile()
{
}

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CBMFileImpl::CBMFileImpl()
{
    m_pBMFile = NULL;
    m_uFileCount = 0;
    m_uCurFile = 0;
	memset(m_szErrMsg,0,sizeof(m_szErrMsg));

}

CBMFileImpl::~CBMFileImpl()
{
	if(NULL != m_pBMFile)
	{
		delete []m_pBMFile;
		m_pBMFile = NULL;
	}
}

DWORD CBMFileImpl::GetCurCodeBase()
{
    return m_curBMFileInfo.llBase;
}

void CBMFileImpl::SetCurCodeBase( DWORD dwCodeBase)
{
    m_curBMFileInfo.llBase = dwCodeBase;
}

DWORD CBMFileImpl::GetCurOprSize()
{
    return (DWORD)m_curBMFileInfo.llOprSize;
}

void CBMFileImpl::SetCurOprSize( DWORD dwOprSize )
{
    m_curBMFileInfo.llOprSize = dwOprSize;
}

DWORD CBMFileImpl::GetCurMaxLength()
{
    return m_curBMFileInfo.dwMaxLength;
}

void CBMFileImpl::SetCurMaxLength( DWORD dwMaxLength )
{
	//printf( "\SetCurMaxLength dwMaxLength=0x%x\n", dwMaxLength );
    m_curBMFileInfo.dwMaxLength = dwMaxLength;
}

const _TCHAR * CBMFileImpl::GetCurFileType()
{
    return m_curBMFileInfo.szFileType;
}

BOOL CBMFileImpl::GetCurIsChangeCode()
{
    return m_curBMFileInfo.bChangeCode;
}

BOOL CBMFileImpl::GetCurIsLoadFromFile()
{
    return m_curBMFileInfo.bLoadCodeFromFile;
}

DWORD CBMFileImpl::GetCurCodeSize()
{
    return (DWORD)m_curBMFileInfo.llCodeSize;
}

const LPVOID CBMFileImpl::GetCurCode()
{
    return m_curBMFileInfo.lpCode;
}
BOOL CBMFileImpl::SetFileHandle( int nFd )
{
    if( -1 == nFd )
	{
		// Invalid parameter
		return FALSE;
	}
	m_curBMFileInfo.fdFile = nFd;
    return TRUE;
}
BOOL CBMFileImpl::SetCurCode( const LPVOID lpCode, DWORD dwCodeSize,DWORD dwFirstMapSize /*=0*/  )
{
	if( NULL == lpCode )
	{
		// Invalid parameter
		return FALSE;
	}

	if( m_curBMFileInfo.bChangeCode )
	{
		//printf("SetCurCode m_curBMFileInfo.bChangeCode = TRUE.\n");
		if( 
			m_curBMFileInfo.lpCode != NULL 			&&
		       dwCodeSize != m_curBMFileInfo.llCodeSize 
		    )
		{
			delete (LPBYTE)m_curBMFileInfo.lpCode;
			m_curBMFileInfo.lpCode = NULL;
		}
		if( m_curBMFileInfo.lpCode == NULL )
		{
			m_curBMFileInfo.lpCode = new BYTE[ dwCodeSize ];
		}
		if( m_curBMFileInfo.lpCode == NULL )
		{
			return FALSE;
		}
		m_curBMFileInfo.llCodeSize = dwCodeSize;
		memcpy( m_curBMFileInfo.lpCode, lpCode, dwCodeSize );
	}
	else
	{
		//printf("SetCurCode m_curBMFileInfo.bChangeCode = FALSE.\n");
		m_curBMFileInfo.lpCode = lpCode;
		m_curBMFileInfo.llCodeSize = dwCodeSize;
		m_curBMFileInfo.dwFirstMapSize = dwFirstMapSize ? dwFirstMapSize :dwCodeSize;
	}

    	//printf("[%s] dwCodeSize = %d.\n",m_curBMFileInfo.szFileID,m_curBMFileInfo.dwCodeSize);
	return TRUE;
}

const _TCHAR* CBMFileImpl::GetCurFileName()
{
    return m_curBMFileInfo.szFileName;
}

BOOL CBMFileImpl::SetCurFileName( const _TCHAR* lpszFileName, int nFileNameLen )
{
	UNUSED_ALWAYS(nFileNameLen);
	if( m_curBMFileInfo.bLoadCodeFromFile )
	{
	    UnloadBMFileInfo( &m_curBMFileInfo );
	}
	m_curBMFileInfo.bLoadCodeFromFile = TRUE;
	strcpy(m_curBMFileInfo.szFileName, lpszFileName);
	return LoadBMFileInfo( &m_curBMFileInfo );
}

BOOL CBMFileImpl::InitBMFiles( PBMFileInfo lpBMFileInfo, UINT uFileCount  )
{
	memset(m_szErrMsg,0,sizeof(m_szErrMsg));
    m_uFileCount = uFileCount;
    m_pBMFile = new BMFileInfo[uFileCount];
    if( NULL == m_pBMFile  )
    {
		_stprintf(m_szErrMsg,_T("InitBMFiles: memory is not enough."));
        return FALSE;
    }

    memcpy( m_pBMFile, lpBMFileInfo, uFileCount * sizeof( BMFileInfo ) );

    // Open file mapping objects
    for(UINT i=0; i < m_uFileCount; i++)
    {
        if( !LoadBMFileInfo( &m_pBMFile[i] ) )
        {
            ClearUpBMFiles();
            return FALSE;
        }
    }

    return TRUE;
}

void CBMFileImpl::ClearUpBMFiles()
{
    if( m_pBMFile == NULL )
        return;

    for(UINT i = 0; i < m_uFileCount ; i++ )
    {
        UnloadBMFileInfo( &m_pBMFile[i] );
    }

    delete[] m_pBMFile;
    m_pBMFile = NULL;
    m_uFileCount = 0;

    ClearCurBMFileInfo();
}

void CBMFileImpl::MoveFirst()
{
    m_uCurFile = 0;
    SetCurBMFileInfo();
}

void CBMFileImpl::MoveLast()
{
    m_uCurFile = m_uFileCount - 1;
    SetCurBMFileInfo();
}

void CBMFileImpl::MovePrev()
{
    --m_uCurFile;
    SetCurBMFileInfo();
}

void CBMFileImpl::MoveNext()
{
    ++m_uCurFile;
    SetCurBMFileInfo();
}

BOOL CBMFileImpl::IsEOF()
{
    return m_uCurFile == m_uFileCount;
}

UINT CBMFileImpl::GetCurFileIndex()
{
    return m_uCurFile;
}

BMFileInfo* CBMFileImpl::GetCurrentBMFileInfo()
{
    return &m_curBMFileInfo;
}

void CBMFileImpl::SetCurBMFileInfo()
{
    if( IsEOF() )
    {
        return;
    }
    ClearCurBMFileInfo();

    memcpy( &m_curBMFileInfo, &m_pBMFile[m_uCurFile], sizeof( BMFileInfo ));

    if( m_curBMFileInfo.bChangeCode && m_pBMFile[m_uCurFile].lpCode != NULL )
    {
        DWORD dwCodeSize = m_curBMFileInfo.llCodeSize;
        m_curBMFileInfo.lpCode = new BYTE[ dwCodeSize ];
        if( m_curBMFileInfo.lpCode == NULL )
        {
            m_curBMFileInfo.llCodeSize = 0;
        }
        else
        {
            memcpy( m_curBMFileInfo.lpCode , m_pBMFile[m_uCurFile].lpCode, dwCodeSize );
        }
    }
}

void CBMFileImpl::ClearCurBMFileInfo()
{
    if( m_curBMFileInfo.bChangeCode && m_curBMFileInfo.lpCode != NULL )
    {
        //Modified by wei here to match the new[] and []delete
        delete [](LPBYTE)m_curBMFileInfo.lpCode;
    }

    memset( &m_curBMFileInfo, 0, sizeof( BMFileInfo ));

}

BOOL CBMFileImpl::LoadBMFileInfo( PBMFileInfo lpBMFileInfo )
{
    if( lpBMFileInfo == NULL )
        return FALSE;

    if( FALSE == lpBMFileInfo->bLoadCodeFromFile )
    {
        return TRUE;
    }

     if( strlen(lpBMFileInfo->szFileName) == 0)
    {
		_stprintf(m_szErrMsg,_T("LoadBMFileInfo: BMFile [%s] is empty."),lpBMFileInfo->szFileID);
        return FALSE;
    }

    int fd = -1;
    __int64 llFileSize = 0;   


    fd = open(lpBMFileInfo->szFileName,O_RDONLY|O_LARGEFILE,00777);

    if( fd == -1)
    {
		_stprintf(m_szErrMsg,_T("LoadBMFileInfo: BMFile [%s] open failed, [ERR:0x%X]:\"%s\"."),
			     lpBMFileInfo->szFileName, errno, strerror(errno));
        return FALSE;
    }

    //struct stat buf = {0};
    //fstat(fd,&buf);
    //dwSize = buf.st_size;

	llFileSize = lseek64(fd,0,SEEK_END);

	if( llFileSize == INVALID_FILE_SIZE)
	{
		_stprintf(m_szErrMsg,_T("LoadBMFileInfo: GetFileSize [%s] failed, [ERR:0x%X]:\"%s\"."),
			     lpBMFileInfo->szFileName, errno,strerror(errno));
	    close(fd);
	    return FALSE;
	}

	if ( -1 == lseek64(fd,0,SEEK_SET) )        
	 {            
	 	printf(_T("CBMFileImpl SetFilePointer to FILE_BEGIN fail,error code: %d,\"%s\"\n"),errno,strerror(errno));    
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
		_stprintf(m_szErrMsg,_T("LoadBMFileInfo: mmap [%s] failed, [ERR:0x%X]:\"%s\"."),
			     lpBMFileInfo->szFileName, errno,strerror(errno));
        close(fd);
        return FALSE;
    }

   	lpBMFileInfo->llCodeSize = llFileSize;
	if ( lpBMFileInfo->llCodeSize >= 0x100000000 && NULL == strstr (lpBMFileInfo->szFileType,_T("_64")) )
	{
		strcat(lpBMFileInfo->szFileType,_T("_64"));
	}

    if( lpBMFileInfo->bChangeCode )
    {
		if(dwMapSize != llFileSize)
		{
			munmap( lpCode, dwMapSize);
			lpCode = NULL;
			lpCode = mmap( NULL, dwMapSize, PROT_READ,MAP_SHARED, fd, llFileSize);
			if( lpCode == NULL)
			{
				_stprintf(m_szErrMsg,_T("LoadBMFileInfo: mmap [%s] failed, [ERR:0x%X]:\"%s\"."),
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
			_stprintf(m_szErrMsg,_T("LoadBMFileInfo: memory is not enough."));
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

void CBMFileImpl::UnloadBMFileInfo( PBMFileInfo lpBMFileInfo )
{
    if( lpBMFileInfo == NULL )
        return;

    if( lpBMFileInfo->bLoadCodeFromFile )
    {
        if( lpBMFileInfo->bChangeCode )
        {
            if( lpBMFileInfo->lpCode != NULL )
            {
                delete (LPBYTE)lpBMFileInfo->lpCode;
            }
        }
        else
        {
            if( lpBMFileInfo->lpCode != NULL )
			{
                //::UnmapViewOfFile( lpBMFileInfo->lpCode  );
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

BOOL CBMFileImpl::SetCurBMFileInfo(LPCTSTR lpszFileID)
{
	UINT i=0;
	for(i = 0; i<m_uFileCount; i++)
	{
		if(strcasecmp(m_pBMFile[i].szFileID,lpszFileID) == 0)
		{
			break;
		}
	}
	if(i>=m_uFileCount)
	{
		return FALSE;
	}
	m_uCurFile = i;

    ClearCurBMFileInfo();
    memcpy( &m_curBMFileInfo, &m_pBMFile[m_uCurFile], sizeof( BMFileInfo ));

    if( m_curBMFileInfo.bChangeCode && m_pBMFile[m_uCurFile].lpCode != NULL )
    {
        DWORD dwCodeSize = m_curBMFileInfo.llCodeSize;
        m_curBMFileInfo.lpCode = new BYTE[ dwCodeSize ];
        if( m_curBMFileInfo.lpCode == NULL )
        {
            m_curBMFileInfo.llCodeSize = 0;
        }
        else
        {
            memcpy( m_curBMFileInfo.lpCode , m_pBMFile[m_uCurFile].lpCode, dwCodeSize );
        }
    }
	return TRUE;
}

LPTSTR CBMFileImpl::GetLastErrMsg()
{
	return m_szErrMsg;
}

void CBMFileImpl::SetCurFileType(const _TCHAR* lpszFileType)
{
	if(lpszFileType == NULL)
		return;

	_tcscpy(m_curBMFileInfo.szFileType,lpszFileType);
}
