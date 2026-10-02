// PhaseCheckBuild.cpp: implementation of the CPhaseCheckBuild class.
//
//////////////////////////////////////////////////////////////////////

#include "PhaseCheckBuild.h"

#include "ExePathHelper.h"
extern "C"
{
   #include "confile.h"
}


//
#define T_SECT_VERSION          	( "VERSION" )
#define T_KEY_MAGIC             	( "MAGIC NUMBER" )
#define T_SECT_STATION          	( "STATION" )
#define T_KEY_STATION_NUM	( "STATION NUMBER" )
#define T_KEY_STATION           	( "STATION" )
#define T_SECT_STATE_FLAG 	( "STATE FLAG" )
#define T_KEY_PASS_VALUE  	( "PASS VALUE" )

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CPhaseCheckBuild::CPhaseCheckBuild()
{
	memset(&m_phaseBuf05, 0,sizeof(m_phaseBuf05));
	memset(&m_phaseBuf09, 0,sizeof(m_phaseBuf09));
	memset(&m_phaseBuf15, 0,sizeof(m_phaseBuf15));
	m_eMagic = SP09;
}

CPhaseCheckBuild::~CPhaseCheckBuild()
{

}

BOOL CPhaseCheckBuild::LoadConfigFile()
{

	INI_CONFIG *config 	= NULL;
	GetExePath helper;
	std::string strIniPath = helper.getExeDir();
	strIniPath.insert(0,"/");
	strIniPath += "PhaseCheck.ini";

	config = ini_config_create_from_file(strIniPath.c_str(),0);
	if (NULL == config)
	{
		return FALSE;
	}
	// Version: Magic
	char szMagic[20] = {0};
	char *pRet = ini_config_get_string(config,T_SECT_VERSION,T_SECT_VERSION,"SP09");
	strcpy(szMagic,pRet);

	if (0 == strcasecmp(szMagic, "SP09"))
	{
		int passValue = ini_config_get_int(config,T_SECT_STATE_FLAG, T_KEY_PASS_VALUE,0);
		// SP09
		m_eMagic = SP09;
		//  Xiaoping.Jing, 2010-06-11: [[[
		//  为了减少Flash擦除次数，此处将结构的测试标示位默认初始化为0xFF
		memset(&m_phaseBuf09, 0,sizeof(m_phaseBuf09));
		if (0 == passValue)
		{
			m_phaseBuf09.SignFlag   	= PASS_0_FAIL_1;
			m_phaseBuf09.iTestSign  	= 0xFFFF;
			m_phaseBuf09.iItem      	= 0x7FFF;
			strcpy(m_phaseBuf09.szLastFailDescription, "PASS");
		}
		//  ]]]

		m_phaseBuf09.Magic      	= SP09_SPPH_MAGIC_NUMBER;    
		m_phaseBuf09.StationNum = (BYTE)ini_config_get_int(config,T_SECT_STATION, T_KEY_STATION_NUM,5);
		if (   0 == m_phaseBuf09.StationNum || m_phaseBuf09.StationNum > SP09_MAX_STATION_NUM ) 
		{        
			ini_config_destroy(config);
			return FALSE;
		}

		for (int i=0; i<m_phaseBuf09.StationNum; i++)
		{
			char szKey[20] = {0};
			sprintf(szKey, "%s %d", T_KEY_STATION, i+1);
			pRet = ini_config_get_string(config,T_SECT_STATION,szKey,"");
			strcpy(m_phaseBuf09.StationName[i], pRet); 
		}

    }
    else if (0 == strcasecmp(szMagic, "SP15")) // Bug: 449541
    {
        int passValue = ini_config_get_int(config,T_SECT_STATE_FLAG, T_KEY_PASS_VALUE,0);
        // SP15
        m_eMagic = SP15;
		memset(&m_phaseBuf15, 0,sizeof(m_phaseBuf15));
        if (0 == passValue)
        {
            m_phaseBuf15.SignFlag   = PASS_0_FAIL_1;
            m_phaseBuf15.iTestSign  = (unsigned long)-1;
            m_phaseBuf15.iItem      = (unsigned long)-1;
        }
        else
        {
            m_phaseBuf15.SignFlag   = PASS_1_FAIL_0;
        }
        strcpy(m_phaseBuf15.szLastFailDescription, "PASS");
        //  ]]]
        
        m_phaseBuf15.Magic      = SP15_SPPH_MAGIC_NUMBER;    
        m_phaseBuf15.StationNum = (BYTE)ini_config_get_int(config,T_SECT_STATION, T_KEY_STATION_NUM,5);
        if (   0 == m_phaseBuf15.StationNum 
            || m_phaseBuf15.StationNum > SP15_MAX_STATION_NUM ) 
        {        
        	ini_config_destroy(config);
            return FALSE;
        }
        
        for (int i=0; i<m_phaseBuf15.StationNum; i++)
        {
		char szKey[20] = {0};
		sprintf(szKey, "%s %d", T_KEY_STATION, i+1);

		pRet = ini_config_get_string(config,T_SECT_STATION,szKey,"");
		strcpy(m_phaseBuf15.StationName[i], pRet); 
            
        }
        
    }
    else if (0 == strcasecmp(szMagic, "SP05"))
    {
		// SP05
		m_eMagic = SP05;
		memset(&m_phaseBuf05, 0,sizeof(m_phaseBuf05));

		m_phaseBuf05.header.Magic 		= SP05_SPPH_MAGIC_NUMBER;
		m_phaseBuf05.header.StationNum	= (BYTE)ini_config_get_int(config,T_SECT_STATION, T_KEY_STATION_NUM, 5);
		if (   0 == m_phaseBuf05.header.StationNum || m_phaseBuf05.header.StationNum > SP05_MAX_SUPPORT_STATION ) 
		{        
			ini_config_destroy(config);
		    	return FALSE;
		}

		for (int i=0; i<m_phaseBuf05.header.StationNum; i++)
		{
			char szKey[20] = {0};
			sprintf(szKey, "%s %d", T_KEY_STATION, i+1);
			pRet = ini_config_get_string(config,T_SECT_STATION,szKey,"");
			strcpy(m_phaseBuf05.items[i].TestStationName, pRet); 

		}
	}
	else
	{
	    // Invalid magic
	    ini_config_destroy(config);
	    return FALSE;
	}
	ini_config_destroy(config);

	return TRUE;
}

BOOL CPhaseCheckBuild::CnstPhaseInfo(const char *sn, LPBYTE lpData, int nDataLen, int *pnRetLen)
{
    if ( NULL == lpData )
    {
        //
        return FALSE;
    }

    if ( !LoadConfigFile() )
    {
        //
        return FALSE;
    }

    if (SP09 == m_eMagic)
    {
        if ( nDataLen < SP09_MAX_PHASE_BUFF_SIZE )
        {
            return FALSE;
        }

        if (NULL != sn)
        {
            int nInpSnLen = strlen(sn);
            memset((void *)&m_phaseBuf09.SN1, 0,SP09_MAX_SN_LEN); // NEWMS00178259
            memcpy(m_phaseBuf09.SN1, sn, (nInpSnLen > (SP09_MAX_SN_LEN-1)) ? (SP09_MAX_SN_LEN-1) : nInpSnLen);
        }

        if (NULL != pnRetLen)
        {
            *pnRetLen = SP09_MAX_PHASE_BUFF_SIZE;
        }

        memcpy(lpData, &m_phaseBuf09, SP09_MAX_PHASE_BUFF_SIZE);
    }
    else if (SP15 == m_eMagic) // Bug: 449541
    {
        if ( nDataLen < SP15_MAX_PHASE_BUFF_SIZE )
        {
            return FALSE;
        }
        
        if (NULL != sn)
        {
            int Len = strlen(sn);
            memset((void *)&m_phaseBuf15.SN1,0, SP15_MAX_SN_LEN); 
            memset((void *)&m_phaseBuf15.SN2,0, SP15_MAX_SN_LEN); 
            memcpy(m_phaseBuf15.SN1, sn, (Len > (SP15_MAX_SN_LEN-1)) ? (SP15_MAX_SN_LEN-1) : Len);
        }
        
        if (NULL != pnRetLen)
        {
            *pnRetLen = SP15_MAX_PHASE_BUFF_SIZE;
        }
        
        memcpy(lpData, &m_phaseBuf15, SP15_MAX_PHASE_BUFF_SIZE);
    }
    else
    {
        if ( nDataLen < SP05_MAX_PHASE_BUFF_SIZE )
        {
            return FALSE;
        }

        if (NULL != sn)
        {
            int nInpSnLen = strlen(sn);
            memset((void *)&m_phaseBuf05.header.SN, 0,SP05_SN_LEN); // NEWMS00178259
            memcpy(m_phaseBuf05.header.SN, sn, (nInpSnLen > (SP05_SN_LEN-1)) ? (SP05_SN_LEN-1) : nInpSnLen);
        }

        if (NULL != pnRetLen)
        {
            *pnRetLen = SP05_MAX_PHASE_BUFF_SIZE;
        }

        memcpy(lpData, &m_phaseBuf05, SP05_MAX_PHASE_BUFF_SIZE);
    }
    

    return TRUE;
}

BOOL CPhaseCheckBuild::CnstPhaseInfo(const char *sn1, const char *sn2, LPBYTE lpData, int nDataLen, int *pnRetLen)
{
	if ( NULL == lpData )
	{
		//
		return FALSE;
	}

	if ( !LoadConfigFile() )
	{
	        //
	        return FALSE;
	}

	if (SP09 == m_eMagic)
	{
		if ( nDataLen < SP09_MAX_PHASE_BUFF_SIZE )
		{
		    return FALSE;
		}

		if (NULL != sn1)
		{
		    int nInpSnLen = strlen(sn1);
		    memset((void *)&m_phaseBuf09.SN1, 0,SP09_MAX_SN_LEN); // NEWMS00178259
		    memcpy(m_phaseBuf09.SN1, sn1, (nInpSnLen > (SP09_MAX_SN_LEN-1)) ? (SP09_MAX_SN_LEN-1) : nInpSnLen);
		}

		if (NULL != sn2)
		{
		    int nInpSnLen = strlen(sn2);
		    memset((void *)&m_phaseBuf09.SN2, 0,SP09_MAX_SN_LEN); // NEWMS00178259
		    memcpy(m_phaseBuf09.SN2, sn2, (nInpSnLen > (SP09_MAX_SN_LEN-1)) ? (SP09_MAX_SN_LEN-1) : nInpSnLen);
		}

		if (NULL != pnRetLen)
		{
		    *pnRetLen = SP09_MAX_PHASE_BUFF_SIZE;
		}


		memcpy(lpData, &m_phaseBuf09, SP09_MAX_PHASE_BUFF_SIZE);
    }
    else if (SP15 == m_eMagic) // Bug: 449541
    {
        if ( nDataLen < SP15_MAX_PHASE_BUFF_SIZE )
        {
            return FALSE;
        }
        
        if (NULL != sn1)
        {
            int Len = strlen(sn1);
            memset((void *)&m_phaseBuf15.SN1, 0,SP15_MAX_SN_LEN); 
            memcpy(m_phaseBuf15.SN1, sn1, (Len > (SP15_MAX_SN_LEN-1)) ? (SP15_MAX_SN_LEN-1) : Len);
        }
        
        if (NULL != sn2)
        {
            int Len = strlen(sn2);
            memset((void *)&m_phaseBuf15.SN2,0, SP15_MAX_SN_LEN); 
            memcpy(m_phaseBuf15.SN2, sn2, (Len > (SP15_MAX_SN_LEN-1)) ? (SP15_MAX_SN_LEN-1) : Len);
        }
        
        if (NULL != pnRetLen)
        {
            *pnRetLen = SP15_MAX_PHASE_BUFF_SIZE;
        }
        
        memcpy(lpData, &m_phaseBuf15, SP15_MAX_PHASE_BUFF_SIZE);
    }
	else
	{
		if ( nDataLen < SP05_MAX_PHASE_BUFF_SIZE )
		{
		    return FALSE;
		}

		if (NULL != sn1)
		{
		    int nInpSnLen = strlen(sn1);
		    memset((void *)&m_phaseBuf05.header.SN, 0, SP05_SN_LEN); // NEWMS00178259
		    memcpy(m_phaseBuf05.header.SN,  sn1,  (nInpSnLen > (SP05_SN_LEN-1)) ? (SP05_SN_LEN-1) : nInpSnLen);
		}

		if (NULL != sn2)
		{
		    int nInpSnLen = strlen(sn2);
		    memset((void *)&m_phaseBuf05.header.SN2, 0,SP05_SN_LEN); // NEWMS00178259
		    memcpy(m_phaseBuf05.header.SN2, sn2,  (nInpSnLen > (SP05_SN_LEN-1)) ? (SP05_SN_LEN-1) : nInpSnLen);
		}

		if (NULL != pnRetLen)
		{
		    *pnRetLen = SP05_MAX_PHASE_BUFF_SIZE;
		}


		memcpy(lpData, &m_phaseBuf05, SP05_MAX_PHASE_BUFF_SIZE);
	}


	return TRUE;
}

BOOL CPhaseCheckBuild::Cnst8KBuffer(const char *sn/*IN*/, LPBYTE lpData/*OUT*/, int nDataLen,const char *sn2 /* =NULL*/)
{
	if (NULL == lpData || nDataLen < MAX_PRODUCTIONINFO_SIZE )
	{
	    //
	    return FALSE;
	}

	memset(lpData, 0xFF, nDataLen);
	BOOL bOK = FALSE;
	if(NULL == sn2)
	{
		bOK = CnstPhaseInfo(sn, lpData, nDataLen, NULL);
	}
	else
	{
		bOK = CnstPhaseInfo(sn, sn2,lpData, nDataLen, NULL);
	}

	if ( !bOK)
	{
	    //
	    return FALSE;
	}
    
	//  Xiaoping: 严格判断DOWNLOAD站位名称，如果有DOWNLOAD站，则设置PASS[[[ 
	if (SP09 == m_eMagic)
	{
	    for (int nIndex=0; nIndex<m_phaseBuf09.StationNum; nIndex++)
	    {
	        if (0 == strcasecmp(m_phaseBuf09.StationName[nIndex], "DOWNLOAD"))
	        {
	            if (PASS_0_FAIL_1 == m_phaseBuf09.SignFlag)
	            {
	                // 0: pass, 0: tested
	                m_phaseBuf09.iItem     &= (USHORT)(0x7FFF & (~(USHORT)(1<<nIndex)));
	                m_phaseBuf09.iTestSign &= (USHORT)(0xFFFF & (~(USHORT)(1<<nIndex)));  //标志已经测试
	            }
	            else
	            {
	                // 1: pass, 1: tested
	                m_phaseBuf09.iItem     |= (1 << nIndex);
	            //  m_phaseBuf09.iTestSign |= (1 << nIndex);  //标志已经测试
	            }


	        //  Xiaoping.Jing, 2010-07-05, 修正Download下载完成之后没有将Download标志设置为PASS的BUG [[[
	            memcpy(lpData, &m_phaseBuf09, SP09_MAX_PHASE_BUFF_SIZE);
	        //  ]]]

	            break;
	        }
	    }
	}
	else if (SP15 == m_eMagic)
       {
           //
           for (int nIndex=0; nIndex<m_phaseBuf15.StationNum; nIndex++)
           {
               if (0 == strcasecmp(m_phaseBuf15.StationName[nIndex], "DOWNLOAD"))
               {
                   if (PASS_0_FAIL_1 == m_phaseBuf15.SignFlag)
                   {
                       // 0: pass, 0: tested
                       m_phaseBuf15.iItem     &= (ULONG)(0xFFFFFFFF & (~(ULONG)(1<<nIndex)));
                       m_phaseBuf15.iTestSign &= (ULONG)(0xFFFFFFFF & (~(ULONG)(1<<nIndex)));  //??????
                   }
                   else
                   {
                       // 1: pass, 1: tested
                       m_phaseBuf15.iItem     |= (1 << nIndex);
                   }
                  
                   memcpy(lpData, &m_phaseBuf15, SP15_MAX_PHASE_BUFF_SIZE);
                   break;
               }
           }
       }
	else
	{
	    for (int nIndex=0; nIndex<m_phaseBuf05.header.StationNum; nIndex++)
	    {
	        if (0 == strcasecmp(m_phaseBuf05.items[nIndex].TestStationName, "DOWNLOAD"))
	        {
	            memcpy(m_phaseBuf05.items[nIndex].TestState, "PASS", 4);

	        //  Xiaoping.Jing, 2010-07-05, 修正Download下载完成之后没有将Download标志设置为PASS的BUG [[[
	            memcpy(lpData, &m_phaseBuf05, SP05_MAX_PHASE_BUFF_SIZE);
	        //  ]]]

	            break;
	        }
	    }
	}
	//  ]]]


	return TRUE;
}

BOOL CPhaseCheckBuild::FindSnFrom8K(const BYTE *lpData, int nDataLen, BYTE *sn, int nSnLen)
{
/*
#define  CONVERT_INT(Src,Dst)   {\
                                 (Dst)  = MAKELONG(MAKEWORD(HIBYTE(HIWORD(Src)),LOBYTE(HIWORD(Src))),\
                                                   MAKEWORD(HIBYTE(LOWORD(Src)),LOBYTE(LOWORD(Src))));\
                                }
*/

	if (   NULL == lpData || nDataLen < MAX_PRODUCTIONINFO_SIZE )
	{
		//
		return FALSE;
	}

    if (SP05_SPPH_MAGIC_NUMBER == *((unsigned long *)lpData))
	{			
		LPSP05_PHASE_CHECK_T pPhaseCheckData = (LPSP05_PHASE_CHECK_T)lpData;
		memcpy(sn, pPhaseCheckData->header.SN, nSnLen>SP05_SN_LEN ?SP05_SN_LEN:nSnLen);

        return TRUE;
	}
	else if (SP09_SPPH_MAGIC_NUMBER == *((unsigned long *)lpData))
	{
    /*********************************************************************** 
        Lookup the latest data block
        block size must be equal or multiple than SP09_MAX_PHASE_BUFF_SIZE
      
    **********************************************************************/
    
        const int BLOCK_SIZE  = SP09_MAX_PHASE_BUFF_SIZE;
        int nTotalBlockNum = MAX_PRODUCTIONINFO_SIZE/BLOCK_SIZE;
        LPBYTE lpBuff = (LPBYTE)(lpData+MAX_PRODUCTIONINFO_SIZE-BLOCK_SIZE);
        for (int nIndex=0; nIndex<nTotalBlockNum-1; nIndex++)
        {
            
            if (SP09_SPPH_MAGIC_NUMBER == *((unsigned long *)lpBuff))
            {
                // Find the last data block
                break;
            }
            
            lpBuff -= BLOCK_SIZE;
        }
        
        LPSP09_PHASE_CHECK_T lpPhaseInfo = (LPSP09_PHASE_CHECK_T)(lpBuff);
        memcpy(sn, lpPhaseInfo->SN1, nSnLen>SP09_MAX_SN_LEN?SP09_MAX_SN_LEN:nSnLen);
        
        return TRUE;
    }
    else if (SP15_SPPH_MAGIC_NUMBER == *((unsigned long *)lpData)) // Bug: 449541
	{
        const int BLOCK_SIZE  = SP15_MAX_PHASE_BUFF_SIZE;
        int nTotalBlockNum = MAX_PRODUCTIONINFO_SIZE/BLOCK_SIZE;
        LPBYTE lpBuff = (LPBYTE)(lpData+MAX_PRODUCTIONINFO_SIZE-BLOCK_SIZE);
        for (int nIndex=0; nIndex<nTotalBlockNum-1; nIndex++)
        {       
            if (SP15_SPPH_MAGIC_NUMBER == *((unsigned long *)lpBuff))
            {
                // Find the last data block
                break;
            }
            
            lpBuff -= BLOCK_SIZE;
        }
        
        LPSP15_PHASE_CHECK_T lpPhaseInfo = (LPSP15_PHASE_CHECK_T)(lpBuff);
        memcpy(sn, lpPhaseInfo->SN1, nSnLen>SP15_MAX_SN_LEN?SP15_MAX_SN_LEN:nSnLen);
        
        return TRUE;
    }
    


#if 0
		DWORD dwIndex = *((DWORD*)(lpData+(MAX_PRODUCTIONINFO_SIZE-4)));		
		CONVERT_INT(dwIndex, dwIndex);

		int nIndex = 0;

		/************************************************************************/
		//  if dwIndex == 0xFFFFFFFF, nIndex = 0
		//  if dwIndex == 0xFFFFFFFE, nIndex = 1                                
		/************************************************************************/
	
		if (dwIndex != 0xFFFFFFFF)
		{
			for(int i = 0; i< 32; i++)
			{
				nIndex = ((dwIndex & (1<<(31-i)) )>> (31-i));
				if(nIndex == 0)
				{
					nIndex = (32-i);
					break;
				}
			}
		}
		// the range of  nIndex is [0,30], the last one 31 is not used.
		if (nIndex >= 0 && nIndex <= 30)
		{
			LPSP09_PHASE_CHECK_T pPhaseCheckData = (LPSP09_PHASE_CHECK_T)lpData;
			pPhaseCheckData += nIndex;
			memcpy(sn, pPhaseCheckData->SN1, nSnLen);

            return TRUE;
		}

	}
    else
    {
        return FALSE;
    }
#endif

    return FALSE;
}
