#include "TTYComm2.h"

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
#include <sys/file.h>

#include <pthread.h>

#include <assert.h>
#include "ExePathHelper.h"
extern "C"
{
#include "confile.h"
}

typedef void *(*PTHREAD_START_ROUTINE) (void *);

//ICommChannel::~ICommChannel()
//{
//}

CTTYComm2::CTTYComm2()
{
    m_pObserver = NULL;
    m_fdTTY = -1;
    m_bConnected = false;
    m_bUseMempool = true;
    m_baudOld = B115200;
    m_nBandRate = 115200;
    m_uiLogLevel = INVALID_VALUE;
    m_hRecvThread = NULL;
    m_bExitThread = FALSE;
    memset(m_szLogName,0,sizeof(m_szLogName));
}

CTTYComm2::~CTTYComm2()
{
    Close();
}
bool CTTYComm2::InitLog( char * pszLogName,
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

bool CTTYComm2::Open( PCCHANNEL_ATTRIBUTE pOpenArgument )
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
#if 0
	    /*here to wait a moment for really dev checking starting*/
	    printf("Please Press the power key and volume down key to start downloading.");
	    printf("Please input S to notice the programme that you are ready.");
	    char c =' ';
	    do{
	    c = getchar();
	    }while(c != 's' );
#endif
	    fd =open (pDevPath,O_RDWR|O_NOCTTY,0666);
	}
	else
	{
	    /* the read/write operations will be bloking */
	    fd = open(pDevPath,O_RDWR|O_NOCTTY);
	}

	/* oops, cannot open */
	if (fd == -1) {
		printf("\n[Error]: can not open device \"%s\", error code: 0x%x,\"%s\"\n",pDevPath,errno,strerror(errno) );
		m_log.LogFmtStr(SPLOGLV_ERROR,"Open: can not open device \"%s\", error code: %d,\"%s\"",pDevPath,errno,strerror(errno));
		CloseLogFile();
		return false;
	}
	if(-1 == flock(fd, LOCK_EX|LOCK_NB))
	{
		m_log.LogFmtStr(SPLOGLV_ERROR,"device \"%s\" has been opened by other process,error code: %d,\"%s\".",pDevPath,errno,strerror(errno));
		CloseLogFile();
		close(fd);
		return false;
		
	}

	m_log.LogFmtStr(SPLOGLV_INFO,"Open: open channel \"%s\" success.",pDevPath);

	if( ioctl(fd,TIOCEXCL) == -1)
	{
		m_log.LogFmtStr(SPLOGLV_ERROR,"Open: set TIOCEXCL failed,error code: %d,\"%s\".",errno,strerror(errno));
		CloseLogFile();
		flock(fd, LOCK_UN);
		close(fd);
		return false;
	}

	/* we remember old termios */
	if(tcgetattr(fd,&(m_tioOld)) == -1)
	{
		m_log.LogFmtStr(SPLOGLV_ERROR,"Open: tcgetattr failed,error code: %d,\"%s\".",errno,strerror(errno));
		CloseLogFile();
		flock(fd, LOCK_UN);
		close(fd);
		return false;
	}

	memcpy(&m_tio,&m_tioOld,sizeof(m_tio));

	/* now we set new values */
	if(!SetTTYAtt(fd,dwBaud))
	{
		CloseLogFile();
		close(fd);
		return false;
	}

	m_fdTTY = fd;
	m_bConnected = true;
	if(m_pObserver)
	{
		if( !CreateRecvThread())
		{
		    m_log.LogRawStr(SPLOGLV_ERROR,"Open: CreateRecvThread failed.");
		    Close();
		    return false;
		}
	}

	return TRUE;
}

void CTTYComm2::Close()
{
	/* first we flush the port */
	Clear();

	DestroyRecvThread();

	m_bConnected = false;

	/* then we restore old settings */
	tcsetattr(m_fdTTY,TCSANOW,&(m_tioOld));

	/* and close the file */
	flock(m_fdTTY, LOCK_UN);
	close(m_fdTTY);

	m_fdTTY = -1;

	m_log.LogRawStr(SPLOGLV_INFO,"Close tty channel.");
	CloseLogFile();

}

bool CTTYComm2::Clear()
{
    tcflush(m_fdTTY,TCOFLUSH);
    //tcflush(m_fdTTY,TCIFLUSH);
    return true;
}

bool CTTYComm2::Drain()
{
    if(m_fdTTY != -1)
    {
        tcdrain(m_fdTTY);
    }
    return true;
}

uint32_t CTTYComm2::Read( uint8_t* lpData,
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

uint32_t CTTYComm2::Write(uint8_t* lpData,
                uint32_t ulDataSize,
                uint32_t dwReserved /*= 0 */ )
{
    m_log.LogRawStr(SPLOGLV_INFO,"Write: +++");

    if (m_fdTTY == -1) {
        m_log.LogRawStr(SPLOGLV_WARN,"Write: m_fdTTY is invalid.");
        m_log.LogRawStr(SPLOGLV_INFO,"Write: ---");
        return 0;
    }

    if(lpData == NULL || ulDataSize == 0)
	{
		m_log.LogRawStr(SPLOGLV_WARN,"Write: parameters are invalid.");
		m_log.LogRawStr(SPLOGLV_INFO,"Write: ---");
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

    m_log.LogBufData(SPLOGLV_DATA,lpData,dwRealWritten,LOG_WRITE,&ulDataSize);
    m_log.LogRawStr(SPLOGLV_INFO,"Write: ---");
    return dwRealWritten;
}

void CTTYComm2::FreeMem( void* pMemBlock )
{
    m_MemMgr.FreeMemory(pMemBlock);
}

bool CTTYComm2::GetProperty( int32_t lFlags,
                       uint32_t dwPropertyID,
                       void* pValue )
{
    return true;
}

bool CTTYComm2::SetProperty( int32_t lFlags,
                       uint32_t dwPropertyID,
                       void* pValue )
{
    if( CH_PROP_BAUD == dwPropertyID )
    {
		DWORD dwBaudRate = *((uint32_t *)pValue);


        if( dwBaudRate != m_nBandRate )
        {

            if( !SetTTYAtt(m_fdTTY,dwBaudRate))
            {
                m_log.LogFmtStr( SPLOGLV_ERROR,_T("Call SetProperty( Baudrate: %d ) fail."), dwBaudRate );
                return FALSE;
            }
        }

		m_log.LogFmtStr( SPLOGLV_INFO,_T("Call SetProperty( Baudrate: %d ) success."), dwBaudRate);
		return true;
    }

    return false;
}

bool CTTYComm2::SetObserver( IProtocolObserver * lpObserver )
{
    m_pObserver = lpObserver;
}

bool CTTYComm2::OpenLogFile( int32_t dwPort , char * pDevPath)
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

void CTTYComm2::CloseLogFile()
{
    m_log.Close();
}

bool CTTYComm2::LoadConfig()
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
bool CTTYComm2::SetTTYAtt(int fd, uint32_t baud)
{
    tcflag_t baudrate;
	m_log.LogFmtStr(SPLOGLV_INFO,"SetTTYAtt baud= %d",baud);
    // get the propr baudrate
    switch (baud)
    {
    case 115200:
        baudrate=B115200;
	 m_nBandRate = 115200;
        break;
		
 case 230400:
        baudrate=B230400;
	 m_nBandRate = 230400;
        break;
		
    case 460800:
        baudrate=B460800;
	  m_nBandRate = 460800;
        break;
		
    case 921600:
        baudrate=B921600;
	 m_nBandRate = 921600;
        break;
    default:
	 m_nBandRate = 115200;
        baudrate=B115200;
    }

    m_baudOld = baudrate;

    /*
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
    if (rtscts) {
        m_tio.c_cflag |= CRTSCTS;
    } else {
        m_tio.c_cflag &= ~CRTSCTS;
    }

    // We setup xon/xoff (soft) flow control
    if (xonxoff) {
        m_tio.c_iflag |= (IXON|IXOFF);
    } else {
        m_tio.c_iflag &= ~(IXON|IXOFF);
    }

    m_tio.c_cflag &= ~CSIZE;
    m_tio.c_cflag |= CS8;
    m_tio.c_cflag &= ~CSTOPB;
    m_tio.c_cflag &= ~PARENB;
    m_tio.c_cflag &= ~INPCK;
    m_tio.c_cflag |= (CLOCAL | CREAD);

    m_tio.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);

    m_tio.c_oflag &= ~OPOST;
    m_tio.c_oflag &= ~(ONLCR | OCRNL);

    m_tio.c_iflag &= ~(ICRNL | INLCR);
    m_tio.c_iflag &= ~(IXON | IXOFF | IXANY);
    m_tio.c_iflag |= IGNPAR;
    */


    cfmakeraw(&m_tio);

    m_tio.c_cflag |= CS8;
    m_tio.c_cflag &= ~CSTOPB;
    m_tio.c_cflag &= ~PARENB;
    m_tio.c_cflag |= (CLOCAL | CREAD);

    m_tio.c_cc[VMIN]=1;
    m_tio.c_cc[VTIME]=0;

    cfsetispeed(&m_tio,baudrate);
    cfsetospeed(&m_tio,baudrate);

    // we flush the port
    tcflush(fd,TCOFLUSH);
    tcflush(fd,TCIFLUSH);

    // we send new config to the port
    if(tcsetattr(fd,TCSANOW,&(m_tio)) == -1)
    {
        m_log.LogFmtStr(SPLOGLV_ERROR,"tcsetattr failed, error code: %d,\"%s\"",errno,strerror(errno));
        return false;
    }

    m_dwErrorCode =CH_S_OK;

    return true;
}




bool CTTYComm2::SetTTYBaudrate(uint32_t baud)
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

    //m_tio.c_cflag &= ~m_baudOld;
    //m_tio.c_cflag |= baudrate;

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

void CTTYComm2::_Read()
{
	uint32_t nRealSize = 0;
	uint8_t *pBuf = (uint8_t *)m_MemMgr.GetMemory(1024,&nRealSize);

	if(nRealSize == 0 || pBuf == NULL)
	{
	    m_log.LogFmtStr(SPLOGLV_ERROR,"CTTYComm2::_Read GetMemory fail.");
	    return;
	}
	bool bContinue = false;
	uint32_t uRead =  0;
	
	do
	{
		uRead =  read(m_fdTTY,pBuf,nRealSize);
		bContinue = false;
		m_log.LogFmtStr(SPLOGLV_INFO,"Read= %d,Readed= %d",nRealSize,uRead);
		if(uRead == (uint32_t)(-1))
		{
		     if(errno==EINTR) 
	            {
	                m_log.LogFmtStr(SPLOGLV_ERROR,"Read failed, errno=EINTR continue.");
	                bContinue = true;
	            }
	            else if(errno==EAGAIN) /* EAGAIN : Resource temporarily unavailable*/
	            {
	                m_log.LogFmtStr(SPLOGLV_ERROR,"Read failed, errno=EAGAIN continue.");
	                _sleep(100);
	                bContinue = true;
	            }
		     else
		     {
		        m_log.LogFmtStr(SPLOGLV_ERROR,"Read failed, error code: %d,\"%s\"",errno,strerror(errno));
		     	 uRead = 0;
		     }

		}
		
	}while(bContinue);

	/*uint32_t uRead =  read(m_fdTTY,pBuf,nRealSize);
	m_log.LogFmtStr(SPLOGLV_INFO,"Read= %d,Readed= %d",nRealSize,uRead);
	if(uRead == (uint32_t)(-1))
	{
		m_log.LogFmtStr(SPLOGLV_ERROR,"Read failed, error code: %d,\"%s\"",errno,strerror(errno));
		uRead = 0;
	}
*/
	m_log.LogBufData(SPLOGLV_DATA,pBuf,uRead,LOG_ASYNC_READ,NULL);

	/* Execute callback */
	if ((uRead>0)&&(m_pObserver))
	{
		m_pObserver->OnChannelData(pBuf,uRead,m_dwPort);
	}
	else
	{
		m_MemMgr.FreeMemory(pBuf);
	}

	return;
}


void* CTTYComm2::GetRecvFunc(void* lpParam)
{
	CTTYComm2 * p = (CTTYComm2 *)lpParam;
	return p->RecvFunc();
}

void* CTTYComm2::RecvFunc()
{
    int fs_sel=0;
    fd_set fs_read;
    struct timeval tv_timeout;
    tv_timeout.tv_sec = 0; //time out : unit sec
    tv_timeout.tv_usec = 0;

    while( !m_bExitThread && m_fdTTY != -1)
    {
        FD_ZERO(&fs_read);
        FD_SET(m_fdTTY, &fs_read);
        fs_sel = select( m_fdTTY+1, &fs_read, NULL, NULL, &tv_timeout);

        if(fs_sel>=0 &&  FD_ISSET(m_fdTTY, &fs_read))
        {
            _Read();
        }
        usleep(1);
    }
}

bool CTTYComm2::CreateRecvThread()
{
    m_bExitThread = FALSE;
    int nRet = pthread_create(&m_hRecvThread,
                              NULL,
                              (PTHREAD_START_ROUTINE)GetRecvFunc,
                              this);

    if(nRet==-1)
    {
        m_log.LogRawStr(SPLOGLV_ERROR, _T("Create boot mode thread failed."));
        m_bExitThread = TRUE;
        return FALSE;
    }

    return TRUE;
}
void CTTYComm2::DestroyRecvThread()
{
    if(m_hRecvThread != NULL )
    {
        m_bExitThread = TRUE;

        pthread_join(m_hRecvThread,NULL);

        m_hRecvThread = NULL;
    }
}



