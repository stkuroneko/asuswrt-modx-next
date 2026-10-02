#include "SpLog.h"
#include "ExePathHelper.h"
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#define LOG_DIRECTORY               ( "Log")
#define BINARY_EXTENSION            (".bin")
#define TEXT_EXTENSION              (".log")

#define GetFileNameWithoutExtension(_fn)      {       \
    char* pPos = strrchr((_fn), '.');   \
    if (NULL != pPos) {     \
    *pPos = '\0';   \
    }   \
}

char * PathFindExtension(char * path)
{
    char * pFileExt = strrchr(path,'.');
    if(pFileExt != NULL)
         pFileExt += 1;
    return pFileExt;
}

char * PathFindFileName(char * path)
{
    char * pFileName = strrchr(path,'/');
    if(pFileName == NULL)
        pFileName = path;
    else
        pFileName += 1;
    return pFileName;
}

char * PathRemoveFileSpec(char * path)
{
    char * pFileDir = strrchr(path,'/');
    if(pFileDir != NULL)
         *pFileDir = 0;
    else
        pFileDir = path;
    return pFileDir;
}


CSpLog::CSpLog()
{
    //ctor
    m_pTxtFile = NULL;
    m_uLogLevel = 0;
    m_nLineMaxChars = 16;
    memset(m_szModuleName,0,sizeof(m_szModuleName));
    memset(m_szLogDirPath,0,sizeof(m_szLogDirPath));
    memset(m_szDefLogName,0,sizeof(m_szDefLogName));
    memset(m_szLgFilePath,0,sizeof(m_szLgFilePath));
    memset(m_szLocalTime,0,sizeof(m_szLocalTime));
    memset(m_szLogBuffer,0,sizeof(m_szLogBuffer));

    m_mutex = PTHREAD_MUTEX_INITIALIZER;

    GetExePath helper;
    std::string strModuleName = helper.getExeName();
    std::string strModuleDir = helper.getExeDir();
    strcpy(m_szModuleName, strModuleName.c_str());
    strcpy(m_szDefLogName, m_szModuleName);
    snprintf(m_szLogDirPath, (_MAX_PATH-1), "/%s%s/", strModuleDir.c_str(), LOG_DIRECTORY);

    m_nLogNum = 0;
    memset(m_szUserLogName,0,sizeof(m_szUserLogName));
}

CSpLog::~CSpLog()
{
    //dtor
    Close();
    m_pTxtFile = NULL;
}
 void CSpLog::AutoLock()
{
	if(m_uLogLevel == SPLOGLV_SPLIT)
	{
		 CAutoCS cs( m_mutex );
	}
}
bool CSpLog::Open(char* path,
                   uint32_t uLogLevel/*=SPLOGLV_INFO*/ )
{

    AutoLock();
    Close();
    m_uLogLevel = uLogLevel;

	if(m_uLogLevel == 0)
	{
		return true;
	}

    if(path || strlen(path)!= 0)
    {
        if(strcmp(path,m_szUserLogName) != 0)
        {
            strcpy(m_szUserLogName,path);
            m_nLogNum = 0;
        }
    }
    else
    {
        memset(m_szUserLogName,0,sizeof(m_szUserLogName));
    }

    memset(m_szLgFilePath, 0,sizeof(m_szLgFilePath));
    GetLogFilePath(m_szUserLogName, m_szLgFilePath, true);

    
    if(m_uLogLevel == SPLOGLV_SPLIT)
    {
        m_pTxtFile = fopen(m_szLgFilePath,"wb");
    }
    else
    {
        m_pTxtFile = fopen(m_szLgFilePath,"a+b");
    }

    if(m_pTxtFile == NULL)
    {
        return false;
    }

    return true;

}

bool CSpLog::Close(void)
{
	AutoLock();
	if(m_pTxtFile != NULL)
	{
	    fclose(m_pTxtFile);
	    m_pTxtFile = NULL;
	}

    	return true;
}


bool CSpLog::LogRawStr(uint32_t uLogLevel,
                        const char*  str)
{
    if(!IsOpen())
        return true;

	if(m_uLogLevel == SPLOGLV_DATA)
	{
		if(uLogLevel != SPLOGLV_DATA)
		{
			return true;
		}
	}
	else
	{
		if( uLogLevel > m_uLogLevel)
		{
			return true;
		}
	}

    return LogString(str);
}


bool CSpLog::LogFmtStr(uint32_t uLogLevel, const char* strFmt, ...)
{
    if(!IsOpen())
        return true;

	if(m_uLogLevel == SPLOGLV_DATA)
	{
		if(uLogLevel != SPLOGLV_DATA)
		{
			return true;
		}
	}
	else
	{
		if( uLogLevel > m_uLogLevel)
		{
			return true;
		}
	}

    char   szString[MAX_STRING_IN_BYTES] = {0};
    va_list  args;
    va_start(args, strFmt);
    vsnprintf(szString, sizeof(szString), strFmt, args);
    va_end(args);

    return LogString(szString);
}

bool CSpLog::LogBufData(uint32_t uLogLevel,
                        const uint8_t *pBufData,
                        uint32_t dwBufSize,
                        uint32_t uFlag /*=LOG_WRITE*/,
                        const uint32_t * pUserNeedSize /*=NULL*/)
{
    if(!IsOpen())
        return true;

    if(m_uLogLevel == SPLOGLV_DATA)
	{
		if(uLogLevel != SPLOGLV_DATA)
		{
			return true;
		}
	}
	else
	{
		if( uLogLevel > m_uLogLevel)
		{
			return true;
		}
	}

	//pthread_mutex_lock(&m_mutex);

    // Example: [2009-05-27 15:06:47:0453] --> 110625(0x0001b021) Bytes
    AutoLock();
    char szPrefix[50] = {0};
    if(pUserNeedSize == NULL)
    {
	    switch(uFlag)
	    {
	    case LOG_READ:
	        snprintf(szPrefix, sizeof(szPrefix)-1, "%s %d(0x%08x) Bytes", "<--", dwBufSize, dwBufSize);
	        break;
	    case LOG_WRITE:
	        snprintf(szPrefix, sizeof(szPrefix)-1, "%s %d(0x%08x) Bytes", "-->", dwBufSize, dwBufSize);
	        break;
	    case LOG_ASYNC_READ:
	        snprintf(szPrefix, sizeof(szPrefix)-1, "%s %d(0x%08x) Bytes", "<<-", dwBufSize, dwBufSize);
	        break;
	    default:
	        snprintf(szPrefix, sizeof(szPrefix)-1, "%s %d(0x%08x) Bytes", "---", dwBufSize, dwBufSize);
	        break;
	    }
    }
    else
    {
    	switch(uFlag)
	    {
	    case LOG_READ:
	        snprintf(szPrefix, sizeof(szPrefix)-1, "%s %d(0x%08x)/%d(0x%08x) Bytes", "<--",
	                dwBufSize, dwBufSize,*pUserNeedSize,*pUserNeedSize);
	        break;
	    case LOG_WRITE:
	        snprintf(szPrefix, sizeof(szPrefix)-1, "%s %d(0x%08x)/%d(0x%08x) Bytes", "-->",
	        	dwBufSize, dwBufSize,*pUserNeedSize,*pUserNeedSize);
	        break;
	    case LOG_ASYNC_READ:
	        snprintf(szPrefix, sizeof(szPrefix)-1, "%s %d(0x%08x)/%d(0x%08x) Bytes", "<<-",
	        	dwBufSize, dwBufSize,*pUserNeedSize,*pUserNeedSize);
	        break;
	    default:
	        snprintf(szPrefix, sizeof(szPrefix)-1, "%s %d(0x%08x)/%d(0x%08x) Bytes", "---",
	        	dwBufSize, dwBufSize,*pUserNeedSize,*pUserNeedSize);
	        break;
	    }
    }
    if ( !LogString(szPrefix) )
    {
        //pthread_mutex_unlock(&m_mutex);
        return false;
    }

    if( 0 == dwBufSize)
    {
        //pthread_mutex_unlock(&m_mutex);
    	return true;
    }

    // Blank alignment
    char szBlankAlign[50] = {0};
    //if (m_bDspTime)
    {
        memset(szBlankAlign, 0x20, strlen(m_szLocalTime)+1);
    }

    // Line number
    uint32_t nMaxLine = dwBufSize % m_nLineMaxChars ? (dwBufSize/m_nLineMaxChars+1) : dwBufSize/m_nLineMaxChars;
    uint32_t nLineNo  = 0;
    const uint8_t *pChar = pBufData;
    do
    {
        //
        char szLine[MAX_LINE_HEX_BYTES*5+100] = {0};
        char szBuff[MAX_LINE_HEX_BYTES*3+20]  = {0};
        char szAsci[MAX_LINE_HEX_BYTES*2]     = {0};

        //if (m_bDspIndex)
        {
            // Example: 00000010h:
            snprintf(szBuff, sizeof(szBuff)-1, "%08xh: ", nLineNo*m_nLineMaxChars);
        }

        for (uint32_t n=0; n<m_nLineMaxChars; n++, pChar++)
        {
            char szHex[5] = {0};
            sprintf(szHex, "%02X ", *pChar);
            strcat(szBuff, szHex);

            //if (m_bDspAscii)
            {
                // ASCII
                szAsci[n] = isprint(*pChar) ? *pChar : '.';
            }

            if (dwBufSize == (nLineNo*m_nLineMaxChars+n+1))
            {
                // Reaching the last byte
                if (n < m_nLineMaxChars)
                {
                    // Last line
                    for (uint32_t j=n+1; j<m_nLineMaxChars; j++)
                    {
                        strcat(szBuff, "   ");
                    }
                }

                break;
            }
        }

        snprintf(szLine, sizeof(szLine)-1, "%s%s; %s\r\n", szBlankAlign, szBuff, szAsci);

        // Writing
        uint32_t nLen = strlen(szLine);
        if( fwrite(szLine,1,nLen,m_pTxtFile) != nLen)
        {
            fflush(m_pTxtFile);
            //pthread_mutex_unlock(&m_mutex);
            return false;
        }
        fflush(m_pTxtFile);

    } while(++nLineNo < nMaxLine);

    //pthread_mutex_unlock(&m_mutex);

    if(m_uLogLevel == SPLOGLV_SPLIT && ftell(m_pTxtFile)>10*1024*1024)
    {
        Open(m_szUserLogName,m_uLogLevel);
    }

    return true;
}

bool CSpLog::LogString(const char* str)
{
	AutoLock();
    if(m_pTxtFile == NULL || str == NULL)
        return false;

    char szLogBuffer[MAX_STRING_IN_BYTES+LOCALTIME_STRING_MAX_LEN] = {0};

    // Log local time as "[2009-05-25 12:30:52:0136]...
    snprintf(szLogBuffer, sizeof(szLogBuffer)-1, "%s %s\r\n", GetLocalTime(), str);

    uint32_t nLen = strlen(szLogBuffer);

    if( fwrite(szLogBuffer,1,nLen,m_pTxtFile) == nLen)
    {
       fflush(m_pTxtFile);

       if(m_uLogLevel == SPLOGLV_SPLIT && ftell(m_pTxtFile)>10*1024*1024)
       {
            Open(m_szUserLogName,m_uLogLevel);
       }

       return true;
    }
    else
        return false;
}


// --------------------------------------------------------------------------------
//  Get the log file path
//
void CSpLog::GetLogFilePath(const char * lpszOrgFilePath,
                             char* lpszDstFilePath,
                             bool bIsTxtLogFile)
{

    char szLogFileName[_MAX_PATH] = {0};
    char szOrgFilePath[_MAX_PATH] = {0};
    //char szFileExtName[_MAX_PATH] = {0};

    if ( 0 == strlen(lpszOrgFilePath ))
    {
        snprintf(szOrgFilePath, (_MAX_PATH-1), "%s", m_szDefLogName);
    }
    else
    {
        snprintf(szOrgFilePath, (_MAX_PATH-1), "%s", lpszOrgFilePath);
    }

    // get file name without extension name
    strcpy(szLogFileName, PathFindFileName(szOrgFilePath));
    GetFileNameWithoutExtension(szLogFileName);

    // get file extension name
    // GetLogExtension(szOrgFilePath, szFileExtName, bIsTxtLogFile);

    if ( strrchr(szOrgFilePath,'/') == NULL )
    {
        // relative path...

        // create directories
        CreateMultiDirectory(m_szLogDirPath);

        // append date & time suffix
        /*
        time_t now;
        timeval tpTime;
        gettimeofday(&tpTime,0);
        now = time(0);
        tm *t= localtime(&now);

        snprintf(lpszDstFilePath, (_MAX_PATH-1), "%s%s_%04d_%02d_%02d_%02d_%02d_%02d_%03d%s", \
            m_szLogDirPath, szLogFileName, \
            t->tm_year, t->tm_mon, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec, (int)(tpTime.tv_usec/1000), \
            ".log");
        */
        time_t now;
        now = time(0);
        tm *t= localtime(&now);

//here added by wei.zhang to put the month adding 1.
        snprintf(lpszDstFilePath, (_MAX_PATH-1), "%s%s_%04d_%02d_%02d_[%d].log", \
            m_szLogDirPath, szLogFileName, \
            t->tm_year+1900, t->tm_mon+1, t->tm_mday,\
            m_nLogNum);
    }
    else
    {
        // absolute path...
        PathRemoveFileSpec(szOrgFilePath);
        snprintf(lpszDstFilePath, (_MAX_PATH-1), "%s/%s_[%d].log", szOrgFilePath, szLogFileName, m_nLogNum);
    }
    m_nLogNum++;
}

bool CSpLog::CreateMultiDirectory(const char* lpszPathName)
{
    if (NULL == lpszPathName)
    {
        return false;
    }

    int nLen = strlen(lpszPathName);
    if (nLen < 2)
    {
        return false;
    }

    char szPathName[_MAX_PATH] = {0};
    strncpy(szPathName, lpszPathName, _MAX_PATH-1);

#ifdef _WIN32
    if ( _T('\\') == szPathName[_tcslen(szPathName)-1] )
    {
        // Removes the trailing backslash
        szPathName[_tcslen(szPathName)-1] = _T('\0');
    }

    DWORD dwFileAttr = GetFileAttributes(szPathName);
    if (   (dwFileAttr != (DWORD)-1)
        && (dwFileAttr&FILE_ATTRIBUTE_DIRECTORY) )
    {
        return true;
    }
#else
    if ( '/' == szPathName[strlen(szPathName)-1] )
    {
        // Removes the trailing backslash
        szPathName[strlen(szPathName)-1] = '\0';
    }

    struct stat buf = {0};


    if(lstat(szPathName, &buf) == 0 )
    {
        if(S_ISDIR(buf.st_mode))
            return true;
    }

#endif

    char szTmpPath[_MAX_PATH] = {0};
    char* lpDest = strrchr(szPathName, '/');
    if (NULL != lpDest)
    {
        strncpy(szTmpPath, szPathName, lpDest-szPathName);
    }
    else
    {
        return false;
    }

    if ( CreateMultiDirectory(szTmpPath) )
    {
        // Create directory ...
        // @hongliang.xin 2010-10-15 enhance the code
#ifdef _WIN32
 		if(!CreateDirectory(szPathName, NULL))
 		{
 			if(GetLastError() != ERROR_ALREADY_EXISTS)
 			{
 				return FALSE;
 			}
 		}
#else
        if(access(szPathName, NULL)!=0 )
        {
            if(mkdir(szPathName, 0755)==-1)
            {
                return  false;
            }
        }
#endif
 		return true;
    }
    else
    {
        return false;
    }
}

bool CSpLog::IsOpen()
{
    AutoLock();
    return (m_pTxtFile!= NULL);
}

