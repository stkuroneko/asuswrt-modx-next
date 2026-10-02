// BootModeObject.h : Declaration of the CBootModeObject

#ifndef __BOOTMODEOBJECT_H_
#define __BOOTMODEOBJECT_H_

#include "BootModeObj.h"

/////////////////////////////////////////////////////////////////////////////
// CBootModeObject
class CBootModeObject: public IBootModeHandler
{
public:
    CBootModeObject();
    virtual ~CBootModeObject();

// IBootModeObject
public:
    // IBootModeHandler
    STDMETHOD(SetWaitTimeForNextChip)(/*[in]*/ DWORD dwWaitTime);

    STDMETHOD(StopBootModeOperation)();

    STDMETHOD(StartBootModeOperation)(
        /*[in]*/ void* lpBMFileInfo,
        /*[in]*/ UINT uFileCount,
        /*[in]*/ void* pOpenArgument,
        /*[in]*/ BOOL bBigEndian,
        /*[in]*/ DWORD dwOprCookie,
        /*[in]*/ void* pReceiver);

    STDMETHOD( SetCommunicateChannelPtr)( /*[in]*/LPVOID pCommunicateChannel );


    STDMETHOD( GetCommunicateChannelPtr)( /*[out]*/LPVOID* ppCommunicateChannel );


    //IBMOprSubscriber
    STDMETHOD(SubscribeOperationObserver) (IBMOprObserver* pSink,
        ULONG uFlags,
        DWORD* lpdwCookie );

    STDMETHOD(UnsubscribeOperationObserver) (DWORD dwCookie);

    //IBMOprBuffer
    STDMETHOD_(const LPBYTE, GetReadBuffer) () ;

    STDMETHOD_( DWORD, GetReadBufferSize) ();

    // IBMSettings
    STDMETHOD( SetCheckBaudTimes ) ( DWORD dwTimes );

    STDMETHOD( SetRepartitionFlag ) ( DWORD dwFlag );

    STDMETHOD( SetReadFlashBefRepFlag ) ( DWORD dwFlag );

    STDMETHOD_( DWORD, GetPacketLength ) ( const char* bstrFileType );

	STDMETHOD( GetProperty )( LONG  lFlags, const char *cbstrName,  void *  pvarValue );

    STDMETHOD( SetProperty )( LONG lFlags, const char * cbstrName,  const void * pcvarValue );
private:
    CBootModeObj     m_BootModeObj;
};
/*lint restore*/

#endif //__BOOTMODEOBJECT_H_
