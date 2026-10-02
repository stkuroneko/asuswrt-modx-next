#if !defined(AFX_BOOTMODEINTEGOPR_H__2D9F1612_91A5_4C80_BBD8_B54D552EC426__INCLUDED_)
#define AFX_BOOTMODEINTEGOPR_H__2D9F1612_91A5_4C80_BBD8_B54D552EC426__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000
// BootModeIntegOpr.h : header file
//
#include "BootModeOpr.h"

class IBMProcObserver;

class CBootModeIntegOpr;

typedef BOOL (CBootModeIntegOpr::*OPR_PFUN)(void *);

typedef struct _BM_OPR_ENTRY{
    LPCTSTR  lpszName;
    OPR_PFUN pFun;
}BM_OPR_ENTRY;

#define DECLARE_DISP_MAP() \
private:\
    const static BM_OPR_ENTRY m_oprEntries[];\
    const static long  m_oprCount;


#define BEGIN_DISP_MAP(theClass) \
    const BM_OPR_ENTRY theClass::m_oprEntries[] = \
    {

#define DISP_FUNC(theClass, szExternalName, pfnMember) \
    { _T(szExternalName), \
        (OPR_PFUN)&theClass::pfnMember},
    //(OPR_PFUN)(BOOL (theClass::*)(void *))&pfnMember },

#define END_DISP_MAP(theClass) \
    {_T(""),(OPR_PFUN)NULL} }; \
const long theClass::m_oprCount = sizeof(theClass::m_oprEntries)/sizeof(theClass::m_oprEntries[0]);

/////////////////////////////////////////////////////////////////////////////
// CBootModeIntegOpr command target

class CBootModeIntegOpr
{
// Implementation
public:
	CBootModeIntegOpr();
	virtual ~CBootModeIntegOpr();

// Operations
public:
	long  GetIDsOfNames(LPCTSTR lpszFunName);
	BOOL  Invoke(long id,void* pFileInfo);	
	DWORD GetOprLastErrorCode();	

public:
	//[[ Special notice
	// If you want to add a boot mode operation, this operation must be like
	// BOOL XXXXX(void*pFileInfo);
	// after you add this operation, you must add DISP_FUN map in the cpp file.
	BOOL CheckBaud(void* pFileInfo);
	BOOL Connect(void* pFileInfo);
	BOOL Download(void* pFileInfo);
    BOOL DownloadEx(void* pFileInfo);
	BOOL DownloadByID(void* pFileInfo);
    BOOL DownloadByIDEx(void* pFileInfo);
	BOOL EraseFlash(void* pFileInfo);
	BOOL ReadFlash(void* pFileInfo);
	BOOL ReadFlashByID(void* pFileInfo);
	BOOL Excute(void* pFileInfo);
	BOOL Reset(void* pFileInfo);
    BOOL ReadChipType( void* pFileInfo );
    BOOL ReadNVItem( void* pFileInfo );
    BOOL ChangeBaud( void* pFileInfo );
    BOOL EraseFlash2( void* pFileInfo );
	BOOL EraseFlashByID( void* pFileInfo );
    BOOL Repartition( void * pFileInfo );
	BOOL ForceRepartition( void* pFileInfo );
	BOOL RepartitionByID( void* pFileInfo );
	BOOL ForceRepartitionByID( void* pFileInfo );
    BOOL ExecNandInit( void* pFileInfo );
    BOOL ReadFlashType( void* pFileInfo );	
	BOOL ReadSectorSize( void* pFileInfo );
	BOOL ReadFlashAndSave( void* pFileInfo );
	BOOL ReadFlashAndSaveByID( void* pFileInfo );
	BOOL ReadFlashAndDirectSave( void* pFileInfo );
	BOOL ReadFlashAndDirectSaveByID( void* pFileInfo );
    BOOL ReadFlashAndSaveByIDEx( void* pFileInfo );
	BOOL DoNothing(void * pFileInfo);
	BOOL SetCRC(void * pFileInfo);
	BOOL ResetCRC(void * pFileInfo);
	BOOL CheckBaudRom(void * pFileInfo);
	BOOL ConnectRom(void * pFileInfo);
	BOOL KeepCharge(void * pFileInfo);
	BOOL ReadFlashInfo(void * pFileInfo);
	BOOL SendExtTable(void * pFileInfo);
	BOOL GetCheckBaudCrcType(void * pFileInfo);
	BOOL Connect2(void* pFileInfo);
	BOOL PowerOff(void* pFileInfo);
    BOOL EnableFlash(void * pFileInfo);
	BOOL ReadTransceiverType(void * pFileInfo);
	
	//]] Special notice


    BOOL Initialize(void* pOpenArgument,
                         BOOL bBigEndian,
                          DWORD dwOprCookie,
                          void* pReceiver);
	void Uninitialize();
	void Log(LPCTSTR lpszLog);
    void* GetRecvBuffer();
	void FreeRecvBuffer();
	void StopOpr();
	long GetRecvBufferSize();
    ICommChannel * GetChannelPtr();
    void SetChannel(ICommChannel* pChannel);
    BOOL SetDebugLogState(long lState);
    void EnablePortSecondEnum(BOOL bEnable);

	DECLARE_DISP_MAP()

private:
/*
    void SetMessageReceiver( BOOL bRcvThread,  const LPVOID pReceiver,DWORD dwCookie);
*/
    void PostMessageToUplevel( opr_status_msg msgID, 
                               WPARAM wParam, LPARAM lParam );
    BOOL ReadFlashToFile(void* pFileInfo, FILE *pFile);
    BOOL ReadFlashToFileByID(void* pFileInfo, FILE *pFile, BOOL bIs64Bit = FALSE);

	BOOL _CheckBaud(void * pFileInfo,BOOL bRom);
	BOOL _Connect(void * pFileInfo,BOOL bRom);
	BOOL _Download(void * pFileInfo,BOOL bByID, BOOL bIs64Bit = FALSE);
	BOOL _ReadFlashAndSave( void * pFileInfo, BOOL bByID, BOOL bIs64Bit = FALSE,BOOL bDirectSave = FALSE);
    BOOL _DoCheckSum(PBMFileInfo pBMFileInfo);
    unsigned int _CheckSum32(unsigned int nChkSum, unsigned char const *pDataBuf, unsigned int nLen);

private:
    CBootModeOpr  m_bmOpr;
    BOOL          m_bCheckBaudRate;    
    DWORD         m_dwOprCookie;    
    // Indicates the up-level receiver is a thread or a window
    //BOOL    m_bRcvThread;
    // ID of the up-level receiving thread
    //DWORD   m_dwRcvThreadID;
    // Handle of the up-level receiving window
    //HWND    m_hRcvWindow;

    IBMProcObserver    *m_pReceiver;
    volatile BOOL m_bStopOpr;	
	BOOL		  m_bNeedRepartion;
    BOOL		  m_bRepartionDone;
};

/////////////////////////////////////////////////////////////////////////////

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_BOOTMODEINTEGOPR_H__2D9F1612_91A5_4C80_BBD8_B54D552EC426__INCLUDED_)
