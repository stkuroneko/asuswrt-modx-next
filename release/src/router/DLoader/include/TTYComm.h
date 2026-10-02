#ifndef TTYCOMM_H
#define TTYCOMM_H

#include "SpLog.h"
#include "ICommChannel.h"
#include "MemoryMgr.h"

#include <signal.h>
#include <termios.h>

bool InitTTYSignal();
void UninitTTYSignal();

class CTTYComm: public ICommChannel
{
    public:
        CTTYComm();
        virtual ~CTTYComm();
        virtual bool	InitLog( char * pszLogName,
			                      uint32_t uiLogLevel=INVALID_VALUE);
        virtual bool      Open( PCCHANNEL_ATTRIBUTE pOpenArgument );
        virtual void      Close();
        virtual bool      Clear();
        virtual bool      Drain();
        virtual uint32_t Read( uint8_t* lpData,
                        uint32_t ulDataSize,
                        uint32_t dwTimeOut,
                        uint32_t dwReserved = 0 );

        virtual uint32_t Write(uint8_t* lpData,
                        uint32_t ulDataSize,
                        uint32_t dwReserved = 0  );

        virtual void	  FreeMem( void* pMemBlock );

        virtual bool	  GetProperty( int32_t lFlags,
                               uint32_t dwPropertyID,
                               void* pValue );

        virtual bool 	  SetProperty( int32_t lFlags,
                               uint32_t dwPropertyID,
                               void* pValue );
        virtual bool    SetObserver( IProtocolObserver * lpObserver );

        void _Read();

    protected:
        bool OpenLogFile( int32_t dwPort , char * pDevPath);
        void CloseLogFile();
        bool LoadConfig();
        bool SetTTYAtt(int fd, uint32_t baud);
        bool SetTTYBaudrate(uint32_t baud);

    public:
        CTTYComm * m_pNext;
        int         m_fdTTY;                   /* tty file descriptor */
        uint32_t   m_dwPort;
        tcflag_t    m_baudOld;
    private:
        CMemoryMgr          m_MemMgr;
        CSpLog              m_log;
        IProtocolObserver * m_pObserver;

        uint32_t m_dwErrorCode;

        struct termios m_tio;       /* termios structure for the port */
        struct termios m_tioOld;    /* old termios structure */

        uint32_t m_uiLogLevel;
        bool     m_bConnected;
        bool     m_bUseMempool;
        char     m_szLogName[_MAX_PATH];
};

#endif // TTYCOMM_H
