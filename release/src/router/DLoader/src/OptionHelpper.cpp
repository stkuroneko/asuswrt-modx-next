// OptionHelpper.cpp: implementation of the COptionHelpper class.
//
//////////////////////////////////////////////////////////////////////

#include "OptionHelpper.h"
#include "Global.h"
#include "ExePathHelper.h"

COptionHelpper ohObject;

#define DEFAULT_CHECK_BAUDRATE_TIMES 3
#define DEFAULT_MAX_LENGTH 0x3000
#define INVALID_OPTION_VALUE -1
//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

COptionHelpper::COptionHelpper()
{
	m_nCheckBaudTimes = INVALID_OPTION_VALUE;
	m_nRepartitionFlag = INVALID_OPTION_VALUE;
	m_nReadFlashBRFlag = INVALID_OPTION_VALUE;
	m_strProduct = _T("");
	m_bChangeTimeOutSetting = FALSE;
	m_bChangePacketLenSetting = FALSE;

	GetExePath helper;
	m_strBMFiletype = helper.getExeDir();
	m_strBMFiletype.insert(0,"/");
	m_strBMTimeout = m_strBMFiletype;

	m_strBMFiletype += "BMFileType.ini";
	m_strBMTimeout += "BMTimeout.ini";
	m_bEnableSecondEnum = FALSE;
	m_bPowerOff = FALSE;


	m_iniBMFiletype = ini_config_create_from_file(m_strBMFiletype.c_str(),0);
	m_iniBMTimeout = ini_config_create_from_file(m_strBMTimeout.c_str(),0);
}

COptionHelpper::~COptionHelpper()
{
    ini_config_destroy(m_iniBMFiletype);
    ini_config_destroy(m_iniBMTimeout);
}

int COptionHelpper::GetCheckBaudTimes( const _TCHAR* lpszFileType )
{
    if( INVALID_OPTION_VALUE != m_nCheckBaudTimes )
    {
        // It is changed by client,do not load from ini file
        return m_nCheckBaudTimes;
    }


    return ini_config_get_int(m_iniBMTimeout,
                              _T("Check Baud Times"),
                              lpszFileType,
                              DEFAULT_CHECK_BAUDRATE_TIMES);
}

int COptionHelpper::GetTimeout( const _TCHAR* lpszOperation )
{
	int nTimeout = 1000;
	nTimeout = ini_config_get_int(m_iniBMTimeout,
                              _T("Timeout"),
                              lpszOperation,
                              1000);
	if(m_bChangeTimeOutSetting && strlen(m_strProduct.c_str()) != 0)
	{
		nTimeout = ini_config_get_int(m_iniBMTimeout,
                                 m_strProduct.c_str() ,
                                 lpszOperation,
                                nTimeout);
	}

    return nTimeout;
}

int COptionHelpper::Get7ENumOnce()
{
	return ini_config_get_int(m_iniBMTimeout,
                            _T("CheckBaudSetting") ,
                           _T("7ENumPerTime"),
                           1);
}

int COptionHelpper::GetPacketLength( const _TCHAR* lpszFileType )
{
    int nLen =  ini_config_get_int( m_iniBMFiletype,
                                   _T("Max Length"),
                                   lpszFileType,
                                   DEFAULT_MAX_LENGTH);


	if(m_bChangePacketLenSetting && strlen(m_strProduct.c_str()) != 0)
	{
        nLen = ini_config_get_int( m_iniBMFiletype,
                               m_strProduct.c_str(),
                               lpszFileType,
                               nLen);
	}

	return nLen;
}

int COptionHelpper::GetRepartitionFlag()
{
    if( INVALID_OPTION_VALUE != m_nRepartitionFlag )
    {
        // It is changed by client,do not load from ini file
        return m_nRepartitionFlag;
    }

    return ini_config_get_int( m_iniBMFiletype,
                               _T("Repartition"),
                               _T("strategy"),
                               1);
}

BOOL COptionHelpper::GetFileOperations( const _TCHAR* lpszFileType,
                                       std::vector<std::string> &agOperations)
{
    for(int i = 0; i< 100; i++)
    {
        char szKey[10] = {0};
        sprintf(szKey,"%d",i+1);
        char * pOpr = ini_config_get_string(m_iniBMFiletype,
                                            lpszFileType,
                                            szKey,
                                            NULL);



        if(pOpr == NULL)
            break;
        else
        {
            std::string strOpr(pOpr);
            agOperations.push_back(strOpr);
        }

    }

    return agOperations.size();
}

void COptionHelpper::SetCheckBaudTimes( int nTimes )
{
    m_nCheckBaudTimes = nTimes;
}

void COptionHelpper::SetRepartitionFlag( int nFlag )
{
    m_nRepartitionFlag = nFlag;
}

void COptionHelpper::SetReadFlashBefRepFlag(int nFlag)
{
	m_nReadFlashBRFlag = nFlag;
}

int COptionHelpper::GetNVItemID()
{
    return ini_config_get_int(m_iniBMFiletype,
                              _T("NVItem"),
                              _T("ItemID"),
                              0);
}

int COptionHelpper::GetLogFlag()
{

    return ini_config_get_int(m_iniBMTimeout,
                              _T("Log"),
                              _T("Enable"),
                              0);
}

int COptionHelpper::GetReadFlashBefRepFlag()
{
    if( INVALID_OPTION_VALUE != m_nReadFlashBRFlag )
    {
        // It is changed by client,do not load from ini file
        return m_nReadFlashBRFlag;
    }

    return ini_config_get_int(m_iniBMFiletype,
                              _T("ReadFlashBeforeRepartition"),
                              _T("strategy"),
                              0);

}

BOOL COptionHelpper::SetProperty(LONG lFlags, const _TCHAR* lpszName,const void * pvarValue)
{
	BOOL bOK = FALSE;
	if(strcmp(lpszName,_T("PRODUCT"))== 0)
	{

		if(strstr((_TCHAR*)pvarValue,_T("PAC_")) == (_TCHAR*)pvarValue)
		{
			m_strProduct = ((_TCHAR*)pvarValue) + 4;
		}
		else
		{
		    m_strProduct = (_TCHAR*)pvarValue;
		}

		// judge if the customer product time out is set
		m_bChangeTimeOutSetting = ini_config_find_section(m_iniBMTimeout,m_strProduct.c_str());

		m_bChangePacketLenSetting = ini_config_find_section(m_iniBMFiletype,m_strProduct.c_str());

		bOK = TRUE;
	}
	else if(strcmp(lpszName,_T("EnablePortSecondEnum"))== 0)
	{
		m_bEnableSecondEnum = *((BOOL*)pvarValue);
	}
	else if (strcmp(lpszName,_T("PowerOff"))== 0)
    {
            m_bPowerOff = *((BOOL*)pvarValue);
    }

	return bOK;
}
BOOL COptionHelpper::GetProperty(LONG lFlags, const _TCHAR* lpszName,void * pvarValue)
{
	BOOL bOK = FALSE;
	if(strcmp(lpszName,_T("CheckNVTimes"))== 0)
	{

		//_TCHAR szSection[MAX_PATH];
		DWORD dwTimes = ini_config_get_int(m_iniBMFiletype,
                                      _T("DownloadNV"),
                                     _T("CheckNVTimes"),
                                      0);

		*(DWORD*)pvarValue = dwTimes;

		bOK = TRUE;
	}

	return bOK;
}

UINT COptionHelpper::GetDefaultBaudrate()
{

    return ini_config_get_int(m_iniBMTimeout,
                               _T("Baudrate"),
                               _T("default"),
                              DEFAULT_BAUDRATE
                              );
}

BOOL COptionHelpper::IsEnablePortSecondEnum()
{
	return m_bEnableSecondEnum;
}

BOOL COptionHelpper::IsEnablePowerOff()
{
    return m_bPowerOff;
}

BOOL COptionHelpper::IsSupportZroPkg()
{
    return ini_config_get_int(m_iniBMFiletype, _T("Misc"), _T("SupportZroPkg"), 1);
}

BOOL COptionHelpper::IsNeedDoChkSum()
{   
   return ini_config_get_int(m_iniBMFiletype, _T("Misc"), _T("DoCheckSum"), 0);
}