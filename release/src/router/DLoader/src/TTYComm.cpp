#include "TTYComm.h"

#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <string>

#include <assert.h>
#include "ExePathHelper.h"
extern "C"
{
#include "confile.h"
}


/* signal number for serial i/o read */
static int  g_sigRead=0;
static bool g_bSigInit=false;
/* sigactions */
static struct sigaction g_sa;
static struct sigaction g_saOld;

static CTTYComm* g_head = NULL;

/* prototype of signal handler */
static void SignalHandler(int signo, siginfo_t *info, void *ignored);

ICommChannel::~ICommChannel()
{

}

CTTYComm::CTTYComm()
{
    m_pObserver = NULL;
    m_fdTTY = -1;
    m_bConnected = false;
    m_bUseMempool = true;
    m_baudOld = B115200;
    m_uiLogLevel = INVALID_VALUE;
}

CTTYComm::~CTTYComm()
{
    Close();
}
bool CTTYComm::InitLog( char * pszLogName,
                 uint32_t uiLogLevel)
{
    if(m_bConnected)
	{
		return false;
	}

	if(pszLogName != NULL && strlen(pszLogName)>= _MAX_PATH)
	{
		m_dwErrorCode = CH_E_INVALIDARG;
		return false;
	}

	if(pszLogName != NULL && strlen(pszLogName) != 0)
	{
		strcpy(m_szLogName, pszLogName);
	}

	m_uiLogLevel = uiLogLevel;

	m_dwErrorCode = CH_S_OK;

	return true;
}

bool CTTYComm::Open( PCCHANNEL_ATTRIBUTE pOpenArgument )
{
    if(NULL == pOpenArgument|| CHANNEL_TYPE_TTY != pOpenArgument->ChannelType  )
	{
		m_dwErrorCode = CH_E_INVALIDARG;
		return false;
	}

	m_dwErrorCode = CH_S_OK;

    uint32_t dwPort =  pOpenArgument->tty.dwPortNum;
    uint32_t dwBaud =	pOpenArgument->tty.dwBaudRate;
    char *pDevPath  =  pOpenArgument->tty.pDevPath;

    assert( dwPort > 0 );
    assert( dwBaud > 0 );

	if(dwPort == 0 || dwBaud==0 || pDevPath == NULL) //lint !e774
	{
		m_dwErrorCode = CH_E_INVALIDARG;
		return false;
	}

	// first load configure
	// mainly for user can set not to create log folder and files.
	if(!LoadConfig())
	{
		m_dwErrorCode = CH_E_LOAD_CONFIG_FAILED;
		return false;
	}

	// second open log
    if(!OpenLogFile( dwPort, pDevPath ))
	{
		m_dwErrorCode = CH_E_OPEN_LOG_FAILED;
        return false;
	}


	/* Init memory pool */
	m_MemMgr.Init(m_bUseMempool);


    int fd = -1;
    /* opening the file */
    if(m_pObserver)
    {
        /* user wants event driven reading */
        fd =open (pDevPath,O_RDWR|O_NOCTTY|O_NONBLOCK,0666);
        if(fd != -1)
        {
            fcntl(fd,F_SETSIG,g_sigRead);
            fcntl(fd,F_SETOWN,getpid());
            fcntl(fd,F_SETFL,O_ASYNC|O_NONBLOCK);
        }

    }
    else
    {
        /* the read/write operations will be bloking */
        fd = open(pDevPath,O_RDWR|O_NOCTTY);
    }

    /* oops, cannot open */
    if (fd == -1) {
        m_log.LogFmtStr(SPLOGLV_ERROR,"Open: can not open device, error code: %d,\"%s\"",errno,strerror(errno));
        CloseLogFile();
        return false;
    }

    m_log.LogFmtStr(SPLOGLV_INFO,"Open: open channel \"%s\" success.",pDevPath);

    if( ioctl(fd,TIOCEXCL) == -1)
    {
        m_log.LogFmtStr(SPLOGLV_ERROR,"Open: set TIOCEXCL failed.",errno,strerror(errno));
        CloseLogFile();
        close(fd);
        return false;
    }

    /* we remember old termios */
    if(tcgetattr(fd,&(m_tioOld)) == -1)
    {
        m_log.LogFmtStr(SPLOGLV_ERROR,"Open: tcgetattr failed.",errno,strerror(errno));
        CloseLogFile();
        close(fd);
        return false;
    }

    /* now we set new values */
    if(!SetTTYAtt(fd,dwBaud))
    {
        CloseLogFile();
        close(fd);
        return false;
    }

    m_fdTTY = fd;

    /* we add the serial to our list */
    m_pNext = g_head;
    g_head  = this;

    m_bConnected = true;

    return TRUE;
}

void CTTYComm::Close()
{
    /* first we flush the port */
    Clear();

    m_bConnected = false;

    /* then we restore old settings */
    tcsetattr(m_fdTTY,TCSANOW,&(m_tioOld));

    /* and close the file */
    close(m_fdTTY);

    m_fdTTY = -1;

    m_log.LogRawStr(SPLOGLV_INFO,"Close tty channel.");
    CloseLogFile();

    /* now we can remove the serial from the list */
    if (g_head==this) {
        g_head=this->m_pNext;
        return;
    }

    CTTYComm *cur = NULL;
    for(cur=g_head;cur;cur=cur->m_pNext)
    {
        if (cur->m_pNext==this)
        {
            cur->m_pNext=this->m_pNext;
            return;
        }
    }
}

bool CTTYComm::Clear()
{
    if(m_fdTTY != -1)
    {
        tcflush(m_fdTTY,TCOFLUSH);
        tcflush(m_fdTTY,TCIFLUSH);
    }

    return true;
}

bool CTTYComm::Drain()
{
    if(m_fdTTY != -1)
    {
        tcdrain(m_fdTTY);
    }
    return true;
}

uint32_t CTTYComm::Read( uint8_t* lpData,
                uint32_t ulDataSize,
                uint32_t dwTimeOut,
                uint32_t dwReserved /*= 0*/ )
{
    if (m_fdTTY == -1) {
        m_log.LogRawStr(SPLOGLV_WARN,"Read: m_hTTY is invalid.");
        return 0;
    }

    if(lpData == NULL || ulDataSize == 0)
	{
		m_log.LogRawStr(SPLOGLV_WARN,"Write: parameters are invalid.");
		return 0;
	}

    uint32_t uRead =  read(m_fdTTY,lpData,ulDataSize);
    if(uRead == (uint32_t)(-1))
    {
        m_log.LogFmtStr(SPLOGLV_ERROR,"Read failed, error code: %d,\"%s\"",errno,strerror(errno));
        uRead = 0;
    }

    m_log.LogBufData(SPLOGLV_DATA,lpData,uRead,LOG_READ,&ulDataSize);

    return uRead;
}

uint32_t CTTYComm::Write(uint8_t* lpData,
                uint32_t ulDataSize,
                uint32_t dwReserved /*= 0 */ )
{
    if (m_fdTTY == -1) {
        m_log.LogRawStr(SPLOGLV_WARN,"Write: m_fdTTY is invalid.");
        return 0;
    }

    if(lpData == NULL || ulDataSize == 0)
	{
		m_log.LogRawStr(SPLOGLV_WARN,"Write: parameters are invalid.");
		return 0;
	}

	uint32_t dwMaxLength = ulDataSize;
	uint32_t dwLeft = ulDataSize;
	uint32_t dwRealWritten = 0;
	int32_t dwSize = 0;

	while(dwLeft)
	{
	    if(dwLeft > dwMaxLength)
	    {
	        dwSize = dwMaxLength;
	    }
	    else
	    {
	        dwSize = dwLeft;
	    }
        dwSize = write(m_fdTTY,lpData+dwRealWritten,dwSize);
        if(dwSize <= 0)
        {
            if(errno==EINTR) /* 中断错误 我们继续写*/
            {
                m_log.LogFmtStr(SPLOGLV_ERROR,"Write failed, errno=EINTR continue.");
                continue;
            }
            else if(errno==EAGAIN) /* EAGAIN : Resource temporarily unavailable*/
            {
                m_log.LogFmtStr(SPLOGLV_ERROR,"Write failed, errno=EAGAIN continue.");
                _sleep(100);//等待100ms，希望发送缓冲区能得到释放
                continue;
            }
            else /* 其他错误 没有办法,只好退了*/
            {
               m_log.LogFmtStr(SPLOGLV_ERROR,"Write failed, error code: %d,\"%s\".",errno,strerror(errno));
               break;
            }

        }
        dwRealWritten += dwSize;
        dwLeft -= dwSize;
        //tcdrain(m_fdTTY);
	}

/*
    uint32_t dwRealWritten = write(m_fdTTY,lpData,ulDataSize);
    if(dwRealWritten == (uint32_t)(-1))
    {
        m_log.LogFmtStr(SPLOGLV_ERROR,"Write failed, error code: %d,\"%s\".",errno,strerror(errno));
        dwRealWritten = 0;
    }
    else
    {
        while(dwRealWritten < ulDataSize)
        {
            m_log.LogFmtStr(SPLOGLV_INFO,"%d/%d",dwRealWritten,ulDataSize);
            uint32_t dwRealWritten2 = write(m_fdTTY,lpData+dwRealWritten,ulDataSize-dwRealWritten2);
            if(dwRealWritten2 == (uint32_t)(-1))
            {
                m_log.LogFmtStr(SPLOGLV_ERROR,"Write failed, error code: %d,\"%s\".",errno,strerror(errno));
                break;
            }
            dwRealWritten += dwRealWritten2;
        }
    }
*/
    m_log.LogBufData(SPLOGLV_DATA,lpData,dwRealWritten,LOG_WRITE,&ulDataSize);

    return dwRealWritten;
}

void CTTYComm::FreeMem( void* pMemBlock )
{
    m_MemMgr.FreeMemory(pMemBlock);
}

bool CTTYComm::GetProperty( int32_t lFlags,
                       uint32_t dwPropertyID,
                       void* pValue )
{

    return true;
}

bool CTTYComm::SetProperty( int32_t lFlags,
                       uint32_t dwPropertyID,
                       void* pValue )
{
    if( CH_PROP_BAUD == dwPropertyID )
    {
		DWORD dwBaudRate = *((uint32_t *)pValue);


        if( dwBaudRate != m_baudOld )
        {

            if( !SetTTYAtt(m_fdTTY,dwBaudRate))
            {
                m_log.LogFmtStr( SPLOGLV_ERROR,_T("Call SetProperty( Baudrate: %d ) fail."), dwBaudRate );
                return FALSE;
            }
            m_baudOld = dwBaudRate;
        }

		m_log.LogFmtStr( SPLOGLV_INFO,_T("Call SetProperty( Baudrate: %d ) success."), dwBaudRate);
		return true;
    }

    return false;
}

bool CTTYComm::SetObserver( IProtocolObserver * lpObserver )
{
    m_pObserver = lpObserver;
}

bool CTTYComm::OpenLogFile( int32_t dwPort , char * pDevPath)
{
    CloseLogFile();

    char szLogFileName[ _MAX_PATH ] = {0};
	if(strlen(m_szLogName)==0 ) // not initialized, so set default value
	{
		sprintf( szLogFileName, "TTYComm_%s_ID%d", PathFindFileName(pDevPath), dwPort);
		strcpy(m_szLogName, szLogFileName);
	}

    if( m_log.Open(m_szLogName,m_uiLogLevel))
    {
        //GetModuleFileName( NULL,szLogFileName, MAX_PATH );
        GetExePath helper;
        std::string strDir = helper.getExeDir();
        std::string strName = helper.getExeName();

        m_log.LogFmtStr(SPLOGLV_ERROR,"===%s%s", strDir.c_str(), strName.c_str() );
        return true;
    }
    return false;
}

void CTTYComm::CloseLogFile()
{
    m_log.Close();
}

bool CTTYComm::LoadConfig()
{
    INI_CONFIG *config = NULL;

    GetExePath helper;
    std::string strIniPath = helper.getExeDir();
    strIniPath.insert(0,"/");
    strIniPath += "Channel.ini";

    config = ini_config_create_from_file(strIniPath.c_str(),0);
    if(m_uiLogLevel == INVALID_VALUE)
    {
        m_uiLogLevel = 0;
        if(config)
        {
            m_uiLogLevel = ini_config_get_int(config,"Log","Level",0);
        }
    }

    ini_config_destroy(config);

    return true;
}
// sets up the port parameters
bool CTTYComm::SetTTYAtt(int fd, uint32_t baud)
{
    tcflag_t baudrate;
    tcflag_t databits;
    tcflag_t stopbits;
    tcflag_t checkparity;
    int timeout = 0;
    int bits = 8;
    int parity = 0;
    int stop = 0;
    int rtscts= 0;
    int xonxoff = 0;

    // get the propr baudrate
    switch (baud)
    {
    case 115200:
        baudrate=B115200;
        break;
    case 460800:
        baudrate=B460800;
        break;
    case 921600:
        baudrate=B921600;
        break;
    default:
        baudrate=B115200;
    }

    m_baudOld = baudrate;

    // databits
    switch (bits)
    {
    case 7:
        databits=CS7;
        break;
    case 8:
        databits=CS8;
        break;
    default:
        databits=CS8;
    }

    // parity
    switch (parity) {
    case 0:
        checkparity=0;
        break;
    case 1:   //odd
        checkparity=PARENB|PARODD;
        break;
    case 2:
        checkparity=PARENB;
        break;
    default:
        checkparity=0;
    }

    // and stop bits
    switch (stop) {
    case 1:
        stopbits=0;
        break;
    case 2:
        stopbits=CSTOPB;
        break;
    default:
        stopbits=0;
    }

    // now we setup the values in port's termios
    m_tio.c_cflag=baudrate|databits|checkparity|stopbits|CLOCAL|CREAD;
    m_tio.c_iflag=IGNPAR;
    m_tio.c_oflag=0;
    m_tio.c_lflag=0;
    m_tio.c_cc[VMIN]=1;
    // Blocking mode: sets the timeout in
    // hundreds of miliseconds
    m_tio.c_cc[VTIME]=10;

    // We setup rts/cts (hardware) flow control
    //if (rtscts) {
    //    m_tio.c_cflag |= CRTSCTS;
    //} else {
    //    m_tio.c_cflag &= ~CRTSCTS;
    //}

    /* We setup xon/xoff (soft) flow control */
    //if (xonxoff) {
    //    m_tio.c_iflag |= (IXON|IXOFF);
    //} else {
    //    m_tio.c_iflag &= ~(IXON|IXOFF);
    //}

    cfsetispeed(&m_tio,baudrate);
    cfsetospeed(&m_tio,baudrate);

    /* we flush the port */
    tcflush(fd,TCOFLUSH);
    tcflush(fd,TCIFLUSH);

    /* we send new config to the port */
    if(tcsetattr(fd,TCSANOW,&(m_tio)) == -1)
    {
        m_log.LogFmtStr(SPLOGLV_ERROR,"tcsetattr failed, error code: %d,\"%s\"",errno,strerror(errno));
        return false;
    }

    m_dwErrorCode =CH_S_OK;

    return true;
}


bool CTTYComm::SetTTYBaudrate(uint32_t baud)
{
    tcflag_t baudrate;

    // get the propr baudrate
    switch (baud)
    {
    case 115200:
        baudrate=B115200;
        break;
    case 460800:
        baudrate=B460800;
        break;
    case 921600:
        baudrate=B921600;
        break;
    default:
        baudrate=B115200;
    }

    m_baudOld = baudrate;

    cfsetispeed(&m_tio,baudrate);
    cfsetospeed(&m_tio,baudrate);

    if(tcsetattr(m_fdTTY,TCSANOW,&(m_tio)) == -1)
    {
        m_log.LogFmtStr(SPLOGLV_ERROR,"tcsetattr failed, error code: %d,\"%s\"",errno,strerror(errno));
        return false;
    }

    m_dwErrorCode=CH_S_OK;

    return true;
}

void CTTYComm::_Read()
{
    uint32_t nRealSize = 0;
    uint8_t *pBuf = (uint8_t *)m_MemMgr.GetMemory(1024,&nRealSize);

    if(nRealSize == 0 || pBuf == NULL)
    {
        return;
    }

    uint32_t uRead =  read(m_fdTTY,pBuf,nRealSize);
    if(uRead == (uint32_t)(-1))
    {
        m_log.LogFmtStr(SPLOGLV_ERROR,"Read failed, error code: %d,\"%s\"",errno,strerror(errno));
        uRead = 0;
    }

    m_log.LogBufData(SPLOGLV_DATA,pBuf,uRead,LOG_ASYNC_READ,NULL);

    /* Execute callback */
    if ((uRead>0)&&(m_pObserver))
    {
        m_pObserver->OnChannelData(pBuf,uRead,m_dwPort);
    }

    return;
}

bool InitTTYSignal()
{
    int sig;

    if (g_bSigInit) {
        //m_log.LogRawStr(SPLOGLV_INFO,"InitTTYSignal: already init.");
        return true;
    }

    /* Here we scan for unused real time signal */
    sig=SIGRTMIN;

    do {
        /* get old sigaction */
        sigaction(sig,0,&g_saOld);

        /* if signal's handler is empty */
        if (g_saOld.sa_handler == 0)
        {
            /* set the signal handler, and others */
            g_sigRead=sig;
            g_sa.sa_sigaction = SignalHandler;
            g_sa.sa_flags = SA_SIGINFO;
            g_sa.sa_restorer = NULL;
            sigemptyset(&g_sa.sa_mask);
            sigaction(g_sigRead,&g_sa,0);

            /* OK, the cssl is started */
            g_bSigInit=true;
            //m_log.LogRawStr(SPLOGLV_INFO,"InitTTYSignal: success.");
            return true;
        }
        else
        {
            /* signal handler was not empty,
               restore original */
            sigaction(g_sigRead,&g_saOld,0);
        }
        sig++;
    } while(sig<=SIGRTMAX);

    //m_log.LogRawStr(SPLOGLV_ERROR,"InitTTYSignal: failed.");

    return false;
}

void UninitTTYSignal()
{
    /* if not started we do nothing */
    if (!g_bSigInit)
        return;

    /* we close all ports, and free the list */
    while (g_head)
    {
        CTTYComm * pCur = g_head;
        pCur->Close();
    }
    /* then we remove the signal handler */
    sigaction(g_sigRead,&g_saOld,NULL);

    /* And at least : */
    g_bSigInit=false;
}

void SignalHandler(int signo, siginfo_t *info, void *ignored)
{
    CTTYComm *cur;

    /* is this signal which says about
       incoming of the data? */
    if (info->si_code==POLL_IN)
    {
        /* Yes, we got some data */
        for(cur=g_head;cur;cur=cur->m_pNext)
        {
            /* Let's find proper cssl_t */
            if (cur->m_fdTTY==info->si_fd)
            {
                /* Got it */
                cur->_Read();
                return;
            }
        }
    }
}


