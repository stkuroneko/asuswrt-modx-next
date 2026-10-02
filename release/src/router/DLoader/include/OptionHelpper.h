// OptionHelpper.h: interface for the COptionHelpper class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_OPTIONHELPPER_H__CBDB797D_51F4_445D_AF7B_6DFD23D35CB4__INCLUDED_)
#define AFX_OPTIONHELPPER_H__CBDB797D_51F4_445D_AF7B_6DFD23D35CB4__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include "typedef.h"
#include <string>
#include <vector>
extern "C"
{
#include "confile.h"
}



class COptionHelpper
{
public:
	COptionHelpper();
	virtual ~COptionHelpper();

public:
    void SetCheckBaudTimes( int nTimes );
    void SetRepartitionFlag( int nFlag );
	void SetReadFlashBefRepFlag(int nFlag);
	BOOL SetProperty(LONG lFlags, const _TCHAR* lpszName,const void * pvarValue);
	BOOL GetProperty(LONG lFlags, const _TCHAR* lpszName,void * pvarValue);

public:
    int GetCheckBaudTimes( const _TCHAR* lpszFileType );
    int GetTimeout( const _TCHAR* lpszOperation );
    int GetPacketLength(const _TCHAR* lpszFileType );
    int GetRepartitionFlag();
    BOOL GetFileOperations( const _TCHAR* lpszFileType,std::vector<std::string> &agOperations );
    int  GetNVItemID();
	int  GetLogFlag();
	int  GetReadFlashBefRepFlag();
	int  Get7ENumOnce();
	UINT GetDefaultBaudrate();
	BOOL IsEnablePortSecondEnum();
    BOOL IsEnablePowerOff();
    BOOL IsSupportZroPkg();
    BOOL IsNeedDoChkSum();

protected:
    int m_nCheckBaudTimes;
    int m_nRepartitionFlag;
	int m_nReadFlashBRFlag;
	std::string m_strProduct;
	BOOL m_bChangeTimeOutSetting;
	BOOL m_bChangePacketLenSetting;

	std::string m_strBMFiletype;
	std::string m_strBMTimeout;

	INI_CONFIG *m_iniBMFiletype;
	INI_CONFIG *m_iniBMTimeout;
	BOOL 		m_bEnableSecondEnum;
	BOOL		m_bPowerOff;
};

#endif // !defined(AFX_OPTIONHELPPER_H__CBDB797D_51F4_445D_AF7B_6DFD23D35CB4__INCLUDED_)
