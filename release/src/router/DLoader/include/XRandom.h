
#ifndef _XRANDOM_H
#define _XRANDOM_H
#include "typedef.h"
#include <string.h>
using namespace std;

class CXRandom  
{
public:
	CXRandom(BOOL bRandom = TRUE);
	virtual ~CXRandom();
	//BYTE GetRandomByte(void);
	int  GetRandomNumber(void);

	void GetRandomBytes(LPBYTE pBuf, DWORD dwSize);
	void GetRandomNumbers(LPBYTE pBuf, DWORD dwSize);
	string GetRandomNumbers( DWORD dwSize);

private:
    int m_nFd;
private:
	int 	open_random_fd (BOOL bRandom = TRUE);
	void 	close_random_fd();
};

#endif
