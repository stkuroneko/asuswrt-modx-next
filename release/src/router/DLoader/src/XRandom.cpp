#include "XRandom.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/time.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>


CXRandom::CXRandom(BOOL bRandom/* = TRUE*/)
{
	m_nFd = -1;
	m_nFd = open_random_fd(bRandom);
}

CXRandom::~CXRandom()
{
	close_random_fd();
}

int CXRandom::open_random_fd (BOOL bRandom/* = TRUE*/)
{
	if (-1 == m_nFd)
	{
		if(bRandom)
		{
			m_nFd = open ("/dev/random", O_RDONLY | O_NONBLOCK);
		}
		else
		{
			m_nFd = open ("/dev/urandom", O_RDONLY | O_NONBLOCK);
		}
	}

	return m_nFd;
}

void CXRandom::close_random_fd()
{
	if (-1 != m_nFd)
	{
		close(m_nFd);
		m_nFd = -1;
	}
}

int  CXRandom::GetRandomNumber(void)
{
	BYTE byteBuf = 0; 
    	GetRandomBytes((LPBYTE)&byteBuf,1);
   	return byteBuf%10;
}

void CXRandom::GetRandomNumbers(LPBYTE pBuf, DWORD dwSize)
{
	if(pBuf == NULL)
		return;

	for(int i= 0; i< dwSize; i++)
	{
		pBuf[i] = (BYTE)GetRandomNumber();
	}
}
string CXRandom::GetRandomNumbers( DWORD dwSize)
{
	string strRandom;
	char szTemp[10] ={0};
	for(int i= 0; i< dwSize; i++)
	{
		sprintf(szTemp,_T("%d"),GetRandomNumber());
		strRandom +=szTemp;
	}
	return strRandom;
}
/*

 * Generate a series of random bytes. Use /dev/random if possible,

 * and if not, use /dev/urandom.

 */
void CXRandom::GetRandomBytes(LPBYTE pBuf, DWORD dwSize)
{

	struct timeval tv;
	static unsigned seed = 0;	
 	int i 			= 0 ;
	BYTE* lpCp 		= (BYTE*)pBuf;	
	int nReads		= dwSize;
	int nReaded	= 0;
	int nLoseCount = 0;

	m_nFd = open_random_fd();
	if (m_nFd  !=  -1)
	{
		while (nReads  > 0)
		{
			nReaded = read (m_nFd, lpCp, nReads);
			if ((nReaded <= 0) && ((errno == EINTR) || (errno == EAGAIN)))
			{
				if ( ++nLoseCount == 10 )
				{
					break;
				}
				continue;
			}
			nReads 	-= nReaded;
			lpCp 		+= nReaded;
			nLoseCount = 0;
		}
	}
	
	for (i = 0; i < nReads; i++)
	{
		if (seed == 0)

		{
			gettimeofday(&tv, 0);
			seed = (getpid() << 16) ^ getuid() ^ tv.tv_sec ^ tv.tv_usec;
		}
		*lpCp++ = rand_r(&seed) & 0xFF;
	}

}


