#ifndef _BOOTMODEITF_H__
#define _BOOTMODEITF_H__

#include "typedef.h"
#include "Global.h"


#define STDMETHOD(x) virtual ULONG x
#define STDMETHOD_(t,x) virtual t x
#define PURE =0
#define FAILED(x)  (x)!=0
#define SUCCEEDED(x)  (x)==0
#define STDMETHODIMP ULONG
#define STDMETHODIMP_(t) t

class IBMOprObserver;
/**
 * IBootModeHandler interface defines the integrity operations at Boot mode.
 *
 *
 */
class IBootModeHandler
{
public:
     IBootModeHandler();
     virtual ~IBootModeHandler() = 0;

    /**
     * Start the operation at boot mode
     *
     * @param lpDLFileInfo: the array of Download files information;
     * @param pOpenArgument: the argument of open the channel communication
     * @param lpbstrProgID: the prog id of implement the interface of the channel communication
     * @param bRcvThread : Thread or window
     * @param pReceiver : Set the up-level application' receiver which receives the message
     *                    If bRcvThread is TRUE, pReceiver is a thread ID;
     *                    Otherwise a window handle
     *
     * @return Returns S_OK if successful,Otherwise returns S_FAIL;
     */
    STDMETHOD(StartBootModeOperation)(  /*[in]*/ void* lpDLFileInfo,
				        /*[in]*/ UINT uFileCount,
				        /*[in]*/ void* pOpenArgument,
				        /*[in]*/ BOOL bBigEndian,
		                /*[in]*/ DWORD dwOprCookie,
		                /*[in]*/ void* pReceiver ) PURE;

    /**
     * Stop the operation at boot mode
     *
     * @return Returns S_OK if successful,Otherwise returns S_FAIL;
     */
    STDMETHOD(StopBootModeOperation)() PURE;

    /**
     * In factory, when the current chip have finished, it'll wait for next chip
     *
     * @param dwWaitTime: the wait time (in milliseconds).
     *
     * @return Returns S_OK if successful,Otherwise returns S_FAIL;
     */
    STDMETHOD(SetWaitTimeForNextChip)(/*[in]*/ DWORD dwWaitTime) PURE;

    /**
     * Set the communication channel pointer
     *
     * @param pCommunicateChannel: point to the communication channel.
     *
     * @return The return value is ignored.
     */
    STDMETHOD( SetCommunicateChannelPtr)( /*[in]*/LPVOID pCommunicateChannel )PURE;

    /**
     * get the communication channel pointer
     *
     * @param ppCommunicateChannel: point to the communication channel pointer.
     *
     * @return Returns S_OK if successful,Otherwise returns S_FAIL;
     */
    STDMETHOD( GetCommunicateChannelPtr)( /*[out]*/LPVOID* ppCommunicateChannel )PURE;

	/**
	 * Subscribe an observer object to receive notification .
	 *
	 * @param pSink Points to the sink object which will receive the notification.
	 *
	 * @param uFlags :reserved
	 *
	 * @param lpdwCookie Points to the cookie assigned to the sink, which can be used to unregister the sink.
	 *
     * @return Returns S_OK if successful,Otherwise returns S_FAIL;
     */
    STDMETHOD(SubscribeOperationObserver) (IBMOprObserver* pSink,
					ULONG uFlags,
					DWORD* lpdwCookie ) PURE;

	/**
	 * Unsubscribe an observer object subscribed previously with SubscribeOperationObserver().
	 *
	 * @param dwCook The cookie returned by SubscribeOperationObserver().
	 *
     * @return Returns S_OK if successful,Otherwise returns S_FAIL;
     */
    STDMETHOD(UnsubscribeOperationObserver) (DWORD dwCookie) PURE;

    	/**
	 * Get the read buffer from boot mode platform.
	 *
     * @return : point to the read buffer.
     */
    STDMETHOD_(const LPBYTE, GetReadBuffer) ( ) PURE;

    /**
	 * Get the read buffer from boot mode platform.
     *
     * @return : read buffer size
     */
    STDMETHOD_( DWORD, GetReadBufferSize) ( ) PURE;

    	/**
	 * Set retry times of CheckBaud operation.
	 *
     * @param dwTimes   Retry times,0 means infinite
     *
     * @return Returns S_OK if successful,Otherwise returns S_FAIL;
     */
    STDMETHOD( SetCheckBaudTimes ) ( DWORD dwTimes ) PURE;

    /**
	 * Set repartition strategy flag
     *
     * @param dwFlag    strategy flag
     *
     * @return Returns S_OK if successful,Otherwise returns S_FAIL;
     */
    STDMETHOD( SetRepartitionFlag ) ( DWORD dwFlag ) PURE;

	/**
	 * Set read flash before repartition flag
     *
     * @param dwFlag    strategy flag
     *
     * @return Returns S_OK if successful,Otherwise returns S_FAIL;
     */
    STDMETHOD( SetReadFlashBefRepFlag ) ( DWORD dwFlag ) PURE;

    /**
	 * Get packet length of file type
     *
     * @param bstrFileType    file type
     *
     * @return Returns packet length;
     */
    STDMETHOD_( DWORD, GetPacketLength ) ( const char* bstrFileType ) PURE;

	/**
     * Get a property value of.
     *
     * @param lFlags: reserved
     *
     * @param cbstrName: The name for which the value is to be set.
     * This must point to a valid BSTR. The pointer is treated as read-only.
     *
     * @param pvarValue:This parameter cannot be NULL and must point to an uninitialized
     * VARIANT. If no error is returned, the VARIANT is initialized using VariantInit,
     * and then set to contain the property value.  The caller must call VariantClear
     * on this pointer when the value is no longer required. If an error code is returned,
     * the VARIANT pointed to by pValue is left unmodified.
     *
     * @return Returns BM_S_OK if successful,Otherwise returns S_FAIL;
     */
     STDMETHOD( GetProperty )( LONG  lFlags, const char* cbstrName,  void *  pvarValue ) PURE;

    /**
     * Put a property value.
     *
     * @param lFlags: reserved
     *
     * @param cbstrName: The name for which the value is to be set.
     * This must point to a valid BSTR. The pointer is treated as read-only.
     *
     * @param pcvarValue: Points to a VARIANT that is treated as read-only.
     * The value in the VARIANT becomes the named property value.
     *
     * @return Returns S_OK if successful,Otherwise returns S_FAIL;
     */
     STDMETHOD( SetProperty )( LONG lFlags, const char* cbstrName,  const void * pcvarValue ) PURE;

};


class IBMOprObserver
{
public:
     IBMOprObserver();
     virtual ~IBMOprObserver() = 0;
   /**
    * Invoked when start work at boot mode platform.
    *
    * @param dwOprCookie: identifiers of working channel .
    *
    * @param dwResult :show  whether the start work is success .
    *
    * @return The return value is ignored.
    */
    STDMETHOD(OnStart)(  DWORD dwOprCookie,
		                 DWORD dwResult ) PURE;

    /**
    * Invoked when end work at boot mode platform.
    *
    * @param dwOprCookie: identifiers of working channel .
    *
    * @param dwResult :show  whether the end work is success .
    *
    * @return The return value is ignored.
    */
    STDMETHOD(OnEnd)(  DWORD dwOprCookie,
		               DWORD dwResult ) PURE;

    /**
    * Invoked when start some operation at boot mode platform.
    *
    * @param dwOprCookie: identifiers of working channel .
    *
    * @param bstrFileID: identifiers of file .
    *
    * @param cbstrFileType : show the current file type,such as FDL, NV.
    *
    * @param cbstrOperationType: show the current operation type,such as Dowmload, ReadFlash.
    *
    * @param pBMFileInterface: the pointer of BMFile Interface.
    *
    * @return The return value is ignored.
    */
    STDMETHOD(OnOperationStart)(  DWORD dwOprCookie,
								  const char* cbstrFileID,
		                          const char* cbstrFileType,
    				              const char* cbstrOperationType,
                                  void * pBMFileInterface ) PURE;

    /**
    * Invoked when end some operation at boot mode platform.
    *
    * @param dwOprCookie: identifiers of working channel .
    *
    * @param bstrFileID: identifiers of file .
    *
    * @param cbstrFileType : show the current file type,such as FDL, NV.
    *
    * @param cbstrOperationType: show the current operation type,such as Dowmload, ReadFlash.
    *
    * @param dwResult :show  whether the operation is success .
    *
    * @param pBMFileInterface: the pointer of BMFile Interface.
    *
    * @return Returns S_OK if successful,Otherwise returns S_FAIL;
    */
    STDMETHOD(OnOperationEnd)(  DWORD dwOprCookie,
								const char* cbstrFileID,
								const char* cbstrFileType,
    							const char* cbstrOperationType,
								DWORD dwResult,
								void* pBMFileInterface ) PURE;

    /**
    * Invoked when start some file operation at boot mode platform.
    *
    * @param dwOprCookie: identifiers of working channel .
    *
    * @param bstrFileID: identifiers of file .
    *
    * @param cbstrFileType : show the current file type,such as FDL, NV.
    *
    * @param pBMFileInterface: the pointer of BMFile Interface.
    *
    * @return Returns S_OK if successful,Otherwise returns S_FAIL;
    */
    STDMETHOD(OnFileOprStart)( DWORD dwOprCookie,
							   const char* cbstrFileID,
							   const char* cbstrFileType,
                               void * pBMFileInterface )PURE;

    /**
    * Invoked when end some file operation at boot mode platform.
    *
    * @param dwOprCookie: identifiers of working channel .
    *
    * @param bstrFileID: identifiers of file .
    *
    * @param cbstrFileType : show the current file type,such as FDL, NV.
    *
    * @return Returns S_OK if successful,Otherwise returns S_FAIL;
    */
    STDMETHOD(OnFileOprEnd)(    DWORD dwOprCookie,
								const char* cbstrFileID,
								const char* cbstrFileType,
								DWORD dwResult )PURE;

	/**
    * Invoked when prepare some file operation at boot mode application framework.
    *
    * @param dwOprCookie: identifiers of working channel .
    *
    * @param bstrProduct: identifiers of product name .
    *
    * @param bstrFileName: file path to download .
    *
    * @param lpFileInfo : a pointer to FILE_INFO_T struct.
    *
    * @param pBMFileInfoArr: return the pointer of BMFileInfo structs .
    *
    * @param lpBMFileInfoCount: return the number of BMFileInfo structs .
    *
    * @param lpdwFlag: if nothing is done return 0, else return 1.
    *
    * @return Returns S_OK if successful,Otherwise returns S_FAIL;
    */
    STDMETHOD(OnFilePrepare)(DWORD dwOprCookie,
							 const char* bstrProduct,
							 const char* bstrFileName,
							 void * lpFileInfo,
							 /*[out]*/ void *    pBMFileInfoArr,
							 /*[out]*/ DWORD*    lpBMFileInfoCount,
							 /*[out]*/ DWORD*    lpdwFlag )PURE;
};


class IBMProcObserver
{
public:
    IBMProcObserver();
    virtual ~IBMProcObserver() = 0;
    virtual int OnMessage(UINT msgID,UINT wParam, void* lParam)=0;
};

BOOL CreateBMObj(IBootModeHandler **pObj);
BOOL DestroyBMObj(IBootModeHandler **pObj);

#endif //_BOOTMODEITF_H__
