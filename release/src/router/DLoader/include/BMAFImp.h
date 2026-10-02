// BMAFImp.h: interface for the CBMAFImp class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_BMAFIMP_H__1B3BBC67_6C5E_4791_AE5F_197CC742869D__INCLUDED_)
#define AFX_BMAFIMP_H__1B3BBC67_6C5E_4791_AE5F_197CC742869D__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

//#include "IBMAFramework.h"
#include "BMAGlobal.h"
#include "Global.h"
#include "SpLog.h"

#define HRESULT ULONG


/////////////////////////////////////////////////////////
class CBMAFImp //: public IBMAFramework//, public CCmdTarget
{
public:
    CBMAFImp();
    virtual ~CBMAFImp();
//Implement the interface IBMAFramework
public:
    virtual HRESULT BMAF_StartOneWork(  LPCTSTR lpszProductName,
                                        LPCTSTR *ppszFileList,
                                        DWORD  dwFileCount,
                                        void*  pOpenArgument,
                                        BOOL bBigEndian,
                                        DWORD dwOprCookie,
                                        void* pReceiver );
    virtual HRESULT BMAF_StopAllWork();
    virtual HRESULT BMAF_StopOneWork(DWORD dwOprCookie);
    virtual HRESULT BMAF_GetBootModeObjInfo(DWORD dwOprCookie, void** ppBootModeObjT);
    virtual HRESULT BMAF_SubscribeObserver(DWORD dwOprCookie,
                                            IBMOprObserver* pSink,
                                            ULONG uFlags );
    virtual HRESULT BMAF_UnsubscribeObserver(DWORD dwOprCookie);
    virtual HRESULT BMAF_SetProperty(DWORD dwPropertyID, void* dwPropertyValue);
    virtual HRESULT BMAF_GetProperty(DWORD dwPropertyID, void** lpdwPropertyValue);
    virtual HRESULT BMAF_SetCommunicateChannelPtr(DWORD dwOprCookie,LPVOID pCommunicateChannel );
    virtual HRESULT BMAF_GetCommunicateChannelPtr(DWORD dwOprCookie, /*[out]*/LPVOID* ppCommunicateChannel );
    virtual HRESULT BMAF_Release();

private:
    BOOL InitBMFiles(DWORD dwOprCookie);
    void InitBMFileDefault(PBMFileInfo lpBMFileInfo, int nFileIndex, BOOL bMultiFiles /*= FALSE*/);
    BOOL LoadBMFileInfo(PBMFileInfo lpBMFileInfo );
    void UnloadBMFileInfo( PBMFileInfo lpBMFileInfo, BOOL bLoadByFrame );
    void ClearBMFiles();
    BOOL RegBootModeObj(DWORD dwOprCookie);
    BOOL UnregBootModeObj(DWORD dwOprCookie);
    BOOL RegBMPObserver(DWORD dwOprCookie);
    BOOL UnregBMPObserver(DWORD dwOprCookie);

    BOOL    StartLog( void);
    void    StopLog( void );
    BOOL    HasLog( void );


    HRESULT StartOneWork(   BOOL bBigEndian,
                    void* pPortArgument,
                    DWORD dwOprCookie,
                    void* pReceiver
                    );


//Attribute

private:
    std::vector<std::string>    m_arrFile;
    std::string         m_strProductName;
    std::string          m_strSpecConfig;
    FILE_INFO_ARR       m_arrFileInfo;

    std::string          m_strFileType;
    BOOL                m_bEnablePortSecondEnum;
    BOOL 			m_bPowerOff;


    UINT            m_nFileCount;
    UINT            m_nBMFileCount;
    std::vector<BMFileInfo *> m_arrBMFileInfo;
    std::vector<UINT> m_arrBMFileFlag;
    std::map< DWORD,IBMOprObserver*> m_mapObserverRegs;
    std::map<DWORD,_BOOTMODEOBJ_T * > m_mapBootModeObj;

    BOOTMODEOBJ_T    *m_pBootModeObj;

    pthread_mutex_t    m_CS;
    DWORD               m_dwRepartitionFlag;
    DWORD               m_dwWaitTime;
    DWORD               m_dwReadFlashBRFlag;
    CSpLog              m_log;
    BOOL                m_bLog; //读配置文件，如果为TRUE，则产生log，否则不产生log，默认为不产生

    DWORD               m_dwPacketLength;

    std::vector<BMFileInfo *> m_arrBMFileInfoEx;

    BOOL m_bInitBMFiles;
};

#endif // !defined(AFX_BMAFIMP_H__1B3BBC67_6C5E_4791_AE5F_197CC742869D__INCLUDED_)
