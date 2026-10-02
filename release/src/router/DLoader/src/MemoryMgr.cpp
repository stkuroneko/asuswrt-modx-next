// MemoryMgr.cpp: implementation of the CMemoryMgr class.
//
//////////////////////////////////////////////////////////////////////

//#include "stdafx.h"
#include "MemoryMgr.h"
#ifdef _WIN32
#include ".\Mempool\dlmalloc.h"
#else
#include "../Mempool/dlmalloc.h"
#endif

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CMemoryMgr::CMemoryMgr()
{
	m_ulBlockSize = 1000;
	m_ulBlockCount = 0;

	m_bUseMempool = true;

}

CMemoryMgr::~CMemoryMgr()
{
	m_ulBlockSize = 0;
	m_ulBlockCount = 0;
}

bool CMemoryMgr::Init( bool bUseMempool, uint32_t ulSize,uint32_t ulCount)
{
	m_ulBlockSize = ulSize;
	m_ulBlockCount = ulCount;
	m_bUseMempool = bUseMempool;
	return true;
}
void*	CMemoryMgr::GetMemory( uint32_t ulSize, uint32_t *pRealSize)
{
	if( ulSize == 0)
	{
		return NULL;
	}
	if(pRealSize != NULL)
	{
		*pRealSize = ulSize;
	}
	if(m_bUseMempool)
	{
		return dlmalloc((size_t)ulSize);
	}
	else
	{
		return (void *)new uint8_t[ulSize];
	}

}

void 	CMemoryMgr::FreeMemory( void* lpMemBlock )
{
	if(lpMemBlock != NULL)
	{
		if(m_bUseMempool)
		{
			dlfree(lpMemBlock);
		}
		else
		{
			delete [] lpMemBlock;
		}
	}
}
void	CMemoryMgr::Reset()
{
	return;
}
