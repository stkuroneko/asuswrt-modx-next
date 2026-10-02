/******************************************************************************
** File Name:      BootModeObj.h                                            *
** Author:         Apple Gao                                                 *
** DATE:           07/22/2004                                                *
** Copyright:      Spreatrum, Incoporated. All Rights Reserved.              *
** Description:    This files contains dll interface.                        *
******************************************************************************

******************************************************************************
**                        Edit History                                       *
** ------------------------------------------------------------------------- *
** DATE				NAME				DESCRIPTION                          *
** 07/21/2004		Apple Gao			Create.							     *
******************************************************************************/

#ifndef _BOOTMODEOBJ_H
#define	_BOOTMODEOBJ_H


/**---------------------------------------------------------------------------*
**                         Dependencies                                      *
**---------------------------------------------------------------------------*/
#include "Global.h"
#include "BMFileImpl.h"
#include "ICommChannel.h"
#include "BootModeIntegOpr.h"
#include "BootModeitf.h"
#include <map>
#include <pthread.h>


class CBootModeObj
{
public:
    CBootModeObj();
    virtual ~CBootModeObj();

public:
    STDMETHOD(SetWaitTimeForNextChip)(/*[in]*/ DWORD dwWaitTime = CHANGE_CHIP_TIMEOUT );

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
    STDMETHOD_(const LPBYTE, GetReadBuffer) ( ) ;

    STDMETHOD_( DWORD, GetReadBufferSize) ( );

     STDMETHOD_(void, EnablePortSecondEnum)(BOOL bEnable);

protected:

    static void* GetBMThreadFunc(void* lpParam);
    void* BMThreadFunc();

    BOOL CreateBMThread();
    void DestroyBMThread();

    BOOL GenerateStartOprNotification( DWORD dwOprCookie, LPCTSTR lpszFileId, LPCTSTR lpszFileType,
                            LPCTSTR lpszOperationType );

    BOOL GenerateEndOprNotification( DWORD dwOprCookie,LPCTSTR lpszFileId, LPCTSTR lpszFileType,
                            LPCTSTR lpszOperationType, DWORD dwResult  );

    BOOL GenerateStartFileOprNotification( DWORD dwOprCookie, LPCTSTR lpszFileId, LPCTSTR lpszFileType );

    BOOL GenerateEndFileOprNotification( DWORD dwOprCookie, LPCTSTR lpszFileId, LPCTSTR lpszFileType, DWORD dwResult );

    BOOL GenerateStartNotification( DWORD dwOprCookie , DWORD dwResult );

    BOOL GenerateEndNotification( DWORD dwOprCookie , DWORD dwResult );

    void EndProc( BOOL bEndSuccess );

    void Log( LPCTSTR lpszLog );

    //int EnumKeys(char* pSection,CStringArray* pKeys);

private:
//    COleDispatchDriver  m_OprDriver;
	CBootModeIntegOpr   m_OprDriver;

    pthread_t           m_hBMThread;
    BOOL                m_bExitThread;

    CBMFileImpl         m_BMFileImpl;

    DWORD               m_dwOprCookie;

    DWORD               m_dwWaitTime;

    std::map<DWORD,IBMOprObserver*> m_mapObserverRegs;

    DWORD               m_dwNextObserverCookie;
    pthread_mutex_t     m_CS;
};
#endif // _BOOTMODEOBJ_H
