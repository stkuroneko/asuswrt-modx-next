#ifndef _ICOMMUNICATIONCHANNEL_H__
#define _ICOMMUNICATIONCHANNEL_H__

#include <stdint.h>

//only for pc_lint zero warning
//lint ++flb

//////////////////////////////////////////////////////////////////////////
//define events
#define CHE_NO_EVENT			((uint32_t)-1)
// define for socket
#define SC_CLIENT_CLOSED		(0)
#define SC_CLIENT_CONNECT		(1)

#define CHE_SC_CLIENT_CLOSED    (0)
#define CHE_SC_CLIENT_CONNECT	(1)
#define CHE_SC_SERVER_CLOSED	(2)
// define for UART
#define CHE_DEVICE_PLUGOUT      (3)
#define CHE_DEVICE_PLUGIN       (4)

// define for File
#define CHE_FILE_READ_OVER      (5)
#define CHE_FILE_READ_STOP      (6)
//////////////////////////////////////////////////////////////////////////
#define CH_EVNET_DATA_SIZE      (sizeof(uint32_t)*2)

#define SC_TYPE_SERVER     (0)
#define SC_TYPE_CLIENT     (1)

#define INVALID_VALUE      ((uint32_t)-1)


typedef enum _CHANNEL_TYPE
{
    CHANNEL_TYPE_COM      = 0,
    CHANNEL_TYPE_SOCKET   = 1,
	CHANNEL_TYPE_FILE     = 2,
    CHANNEL_TYPE_USBMON   = 3,        // USB monitor
    CHANNEL_TYPE_TTY      = 4
}CHANNEL_TYPE;

typedef enum _CHANNEL_PROPERTIES {
	// common property
	CH_PROP_DEBUGMODE = 0,
	CH_PROP_LAST_ERROR,

	// for uart
	CH_PROP_BAUD = 100,
	CH_PROP_WATCH_DEV_CHANGE,

	// for socket
	CH_PROP_SOCKET_CLIENTS_COUNT = 200,
	CH_PROP_SOCKET_CLIENTS_INFO,
	CH_PROP_SOCKET_CLIENTS_INFO2,

	// for file
	CH_PROP_FILE_PACK_SIZE = 300,
	CH_PROP_FILE_PACK_FREQ
}CHANNEL_PROPERTIES;

// channel attributes
typedef struct _CHANNEL_ATTRIBUTE
{
    CHANNEL_TYPE ChannelType;

    union {
        // ComPort
        struct {
            uint32_t  dwPortNum;
            uint32_t  dwBaudRate;
        } Com;

        // Socket
        struct {
			uint32_t dwPort;
			uint32_t dwIP;
			uint32_t dwFlag; //[in]: 0, Server; 1, Client; [out]: client ID.
        } Socket;

		// File
        struct {
			uint32_t  dwPackSize;
			uint32_t  dwPackFreq;
			wchar_t  *pFilePath;
        } File;

        // TTY
        struct {
            uint32_t  dwPortNum;
            uint32_t  dwBaudRate;
            char      *pDevPath;
        } tty;

    };

} CHANNEL_ATTRIBUTE, * PCHANNEL_ATTRIBUTE;

typedef const PCHANNEL_ATTRIBUTE PCCHANNEL_ATTRIBUTE;

typedef struct _CHANNEL_INFO
{
	uint32_t          dwClientCount;
	PCHANNEL_ATTRIBUTE pClients;
}CHANNEL_INFO,*CHANNEL_INFO_PTR;

class IProtocolObserver
{
public:
	/**
	*  Called when some channel event happened
	*  @param [in] event		: event id
	*  @param [in] lpEventData	: event data pointer( a PRT_BUFF pointer),different event has different event data,can be null
	*
	*  @return value is not used now
	*/
	virtual int OnChannelEvent( uint32_t event,void* lpEventData ) = 0;

	/**
	*  Called when some data packages received
	*  @param [in] lpData		: data pointer( a PRT_BUFF pointer )
	*  @param [in] ulDataSize	: data size
	*
	*  @return value is not used now
	*/
	virtual int OnChannelData(void* lpData, uint32_t ulDataSize,uint32_t reserved =0 ) = 0;
};

class ICommChannel
{
public:
    virtual~ICommChannel()=0;
/**
 *  InitLog
 *  @param [in] pszLogName: log file name, if it is NULL or _T(""), program will set default
 *  @param [in] uiLogType : log format type
 *  @param [in] uiLogLevel: see LOG_LEVEL enum
 *  @param [in] pLogUtil  : set the sub-class pointer of CLogUtil, to do special log content
 *  @param [in] pszBinLogFileExt: binary log file extension, if you set uiLogType both text
 *                          and binary,and want to change the binary log file extension,you must
 *							set this param, otherwise ".bin" extension is set default.
 *
 *  @return: TRUE if init success, FALSE otherwise
 *
 *  @remarks: this method need not be called before Open always, because program will auto to
 *            log information by configure file settings. "ChannelConfig.ini"
 */
	//virtual BOOL	InitLog( LPCWSTR pszLogName, UINT uiLogType,
	//		                 UINT uiLogLevel=INVALID_VALUE, ISpLog * pLogUtil=NULL,
	//						 LPCWSTR pszBinLogFileExt = NULL )=0;
	virtual bool	InitLog( char * pszLogName,
			                 uint32_t uiLogLevel=INVALID_VALUE)=0;
/**
 *  Set receiver for reading data with async way
 *  @param [in] ulMsgId		: message ID
 *  @param [in] bRcvThread	: TRUE, received by thread, FALSE, by window
 *  @param [in] pReceiver	: receiver based on bRcvThread
 *
 *  @return TRUE if set success, FALSE otherwise
 *
 *  @remarks: if you call this method after Open, and you set pReceiver to NULL,it will stop
 *            auto-read thread. if set pReceiver to not NULL, and not call this method before
 *            Open, this will start auto-read thread.
 */
	//virtual BOOL	SetReceiver( ULONG  ulMsgId,
	//			                 BOOL    bRcvThread,
    //                      	     LPCVOID pReceiver )=0;
/**
 *  Get receiver
 *  @param [out] ulMsgId	: message ID
 *  @param [out] bRcvThread	: TRUE, received by thread, FALSE, by window
 *  @param [out] pReceiver	: receiver based on bRcvThread
 *
 *  @return void
 */
	//virtual void	GetReceiver( ULONG  &ulMsgId,
	//		             BOOL &bRcvThread,
	//		             LPVOID &pReceiver )=0;
/**
 *  Open channel
 *  @param [in] pOpenArgument : channel parameters
 *
 *  @return TRUE if open success, FALSE otherwise
 */
	virtual bool	Open( PCCHANNEL_ATTRIBUTE pOpenArgument )=0;
/**
 *  Close channel
 *
 *  @return void
 */
	virtual void	Close()=0;
/**
 *  clear channel in&out data buffer
 *
 *  @return TRUE if clear success, FALSE otherwise
 */
	virtual bool	Clear()=0;

	virtual bool   Drain()=0;
/**
 *  Read data from channel with sync way
 *  @param [out] lpData		: store read data
 *  @param [in] dwDataSize	: lpData allocated size by outside
 *  @param [in] dwTimeOut	: time out
 *  @param [in] dwReserved  : reserved, for UART;
 *                            low word is client ID, high word is reserved for server socket
 *
 *  @return real read data size
 */
	virtual uint32_t	Read( uint8_t* lpData, uint32_t ulDataSize,
	                         uint32_t dwTimeOut, uint32_t dwReserved = 0 )=0;
/**
 *  Write data to channel
 *  @param [in] lpData		: store writing data
 *  @param [in] dwDataSize	: lpData allocated size by outside
 *  @param [in] dwReserved  : reserved, for UART;
 *                            low word is client ID, high word is reserved for server socket
 *
 *  @return real written data size
 */
	virtual uint32_t	Write( uint8_t* lpData, uint32_t ulDataSize,uint32_t dwReserved = 0  )=0;
/**
 *  Free memory allocated by program, only used after async read data
 *  @param [in] pMemBlock	: memory pointer
 *
 *  @return void
 */
	virtual void	FreeMem( void* pMemBlock )=0;
/**
 *  Get property of this program
 *  @param [in] lFlags		: reserved
 *  @param [in] dwPropertyID: property name
 *  @param [out] pValue		: property value pointer
 *
 *  @return TRUE if get success,  FALSE otherwise
 */
	virtual bool	GetProperty( int32_t lFlags, uint32_t dwPropertyID,
		                         void* pValue )=0;
/**
 *  Get property of this program
 *  @param [in] lFlags		: reserved
 *  @param [in] dwPropertyID: property name
 *  @param [in] pValue		: property value pointer
 *
 *  @return TRUE if set success,  FALSE otherwise
 */
	virtual bool 	SetProperty( int32_t lFlags, uint32_t dwPropertyID,
                                 void* pValue )=0;

   /**
	*  Add a Observer
	*  @param [in] lpObserver		: pointer to IProtocolObserver
	*
	*  @return internal observer id,used for calling RemoveObserver
	*/
	virtual bool SetObserver( IProtocolObserver * lpObserver ) = 0;
};

#ifdef _WIN32

#ifdef  CHANNEL_EXPORTS
	#define CHANNEL_API extern "C" __declspec(dllexport)
#else
	#define CHANNEL_API extern "C" __declspec(dllimport)
#endif

#else

#define CHANNEL_API

#endif


/**
 *  Create channel object, export function
 *  @param [out] pChannel	: the pointer to hold the implement class object of ICommChannel
 *  @param [in] PortType	: channel type
 *
 *  @return TRUE if create success,  FALSE otherwise
 */
CHANNEL_API bool CreateChannel( ICommChannel ** pChannel, CHANNEL_TYPE PortType );
/**
 *  Release channel object, export function
 *  @param [out] pChannel	: the pointer to hold the implement class of ICommChannel
  *
 *  @return void
 */
CHANNEL_API void ReleaseChannel( ICommChannel *pChannel);



//error define
#define CH_S_OK                         ((uint32_t)0x00000000L)
#define CH_S_FALSE                      ((uint32_t)0x00000001L)
#define CH_E_FAILED                     ((uint32_t)0x80096002L)
#define CH_E_INVALIDARG                 ((uint32_t)0x80096003L)
#define CH_E_OUTOFMEMORY                ((uint32_t)0x80096004L)
#define CH_E_TIMEOUT                 	((uint32_t)0x80096005L)
#define CH_E_NOT_CONNECT                ((uint32_t)0x80096006L)
#define CH_E_CLIENTID_NOT_EXIST         ((uint32_t)0x80096007L)
#define CH_E_OPEN_LOG_FAILED            ((uint32_t)0x80096008L)
#define CH_E_LOAD_CONFIG_FAILED         ((uint32_t)0x80096009L)

//only for pc_lint zero warning
//lint --flb

#endif // _ICOMMUNICATIONCHANNEL_H__
