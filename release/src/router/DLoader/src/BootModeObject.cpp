// BootModeObject.cpp : Implementation of CBootModeObject
#include "BootModeObject.h"
#include "OptionHelpper.h"

IBootModeHandler::IBootModeHandler()
{

}

IBootModeHandler::~IBootModeHandler()
{

}
/////////////////////////////////////////////////////////////////////////////
// CBootModeObject
CBootModeObject::CBootModeObject()
{

}

CBootModeObject::~CBootModeObject()
{

}

STDMETHODIMP CBootModeObject::StartBootModeOperation(
                                                     void* lpBMFileInfo,
                                                     UINT uFileCount,
                                                     void* pOpenArgument,
                                                     BOOL bBigEndian,
                                                     DWORD dwOprCookie,
                                                     void* pReceiver)
{

    return m_BootModeObj.StartBootModeOperation( lpBMFileInfo,
        uFileCount, pOpenArgument, bBigEndian,
        dwOprCookie, pReceiver);

}

STDMETHODIMP CBootModeObject::StopBootModeOperation()
{
    return m_BootModeObj.StopBootModeOperation();
}

STDMETHODIMP CBootModeObject::SetWaitTimeForNextChip(DWORD dwWaitTime)
{
    return m_BootModeObj.SetWaitTimeForNextChip( dwWaitTime );
}

STDMETHODIMP CBootModeObject::SetCommunicateChannelPtr( LPVOID pCommunicateChannel )
{
    return m_BootModeObj.SetCommunicateChannelPtr( pCommunicateChannel );
}

STDMETHODIMP CBootModeObject::GetCommunicateChannelPtr( LPVOID* ppCommunicateChannel )
{

    return m_BootModeObj.GetCommunicateChannelPtr( ppCommunicateChannel );
}

STDMETHODIMP CBootModeObject::SubscribeOperationObserver(IBMOprObserver* pSink,
                                                         ULONG uFlags,
                                                         DWORD* lpdwCookie )
{
    return m_BootModeObj.SubscribeOperationObserver( pSink, uFlags, lpdwCookie );
}

STDMETHODIMP CBootModeObject::UnsubscribeOperationObserver( DWORD dwCookie )
{
    return m_BootModeObj.UnsubscribeOperationObserver( dwCookie );
}

STDMETHODIMP_(const LPBYTE) CBootModeObject::GetReadBuffer(  )
{
    return m_BootModeObj.GetReadBuffer(  );
}

STDMETHODIMP_( DWORD) CBootModeObject::GetReadBufferSize(  )
{
    return m_BootModeObj.GetReadBufferSize(  );
}

STDMETHODIMP CBootModeObject::SetCheckBaudTimes( DWORD dwTimes )
{
	extern COptionHelpper ohObject;
    ohObject.SetCheckBaudTimes( dwTimes );

	return BM_S_OK;
}

STDMETHODIMP CBootModeObject::SetRepartitionFlag( DWORD dwFlag )
{

    extern COptionHelpper ohObject;
    ohObject.SetRepartitionFlag( dwFlag );

    return BM_S_OK;
}

STDMETHODIMP CBootModeObject::SetReadFlashBefRepFlag( DWORD dwFlag )
{
    extern COptionHelpper ohObject;
    ohObject.SetReadFlashBefRepFlag( dwFlag );

    return BM_S_OK;
}
STDMETHODIMP_( DWORD)  CBootModeObject::GetPacketLength(const char* bstrFileType)
{
    extern COptionHelpper ohObject;

	return ohObject.GetPacketLength(bstrFileType);
}

STDMETHODIMP CBootModeObject::GetProperty( LONG  lFlags, const _TCHAR* cbstrName,  void *  pvarValue )
{
    extern COptionHelpper ohObject;
    if(ohObject.GetProperty(lFlags,cbstrName,pvarValue))
	{
		return BM_S_OK;
	}
	else
	{
		return BM_S_FALSE;
	}
}

STDMETHODIMP CBootModeObject::SetProperty( LONG lFlags, const _TCHAR* cbstrName,  const void * pcvarValue )
{

	if(_tcsicmp(cbstrName,_T("EnablePortSecondEnum")) == 0)
	{
		BOOL bEnable = *(BOOL*)pcvarValue;
		m_BootModeObj.EnablePortSecondEnum(bEnable);
	}
    extern COptionHelpper ohObject;
    if(ohObject.SetProperty(lFlags,cbstrName,pcvarValue))
	{
		return BM_S_OK;
	}
	else
	{
		return BM_S_FALSE;
	}
}

BOOL CreateBMObj(IBootModeHandler **pObj)
{
    *pObj = new CBootModeObject();

    if(*pObj != NULL)
    {
        return TRUE;
    }
    else
    {
        return FALSE;
    }
}

//added by wei.zhang here to destroy the BMObj
BOOL DestroyBMObj(IBootModeHandler **pObj)
{
    SAFE_DELETE(*pObj);
    return TRUE;
}


