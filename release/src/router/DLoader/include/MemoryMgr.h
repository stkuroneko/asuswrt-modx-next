// MemoryMgr.h: interface for the CMemoryMgr class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_MEMORYMGR_H__5906FA6F_2A7A_46A7_9F58_9D045DABB64E__INCLUDED_)
#define AFX_MEMORYMGR_H__5906FA6F_2A7A_46A7_9F58_9D045DABB64E__INCLUDED_


#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include <stdint.h>
#include <stddef.h>

class CMemoryMgr
{
public:
	CMemoryMgr();
	virtual ~CMemoryMgr();
public:
	/*Init unused now*/
	bool 	Init( bool bUseMempool = true, uint32_t ulSize = 0, uint32_t ulCount = 0 );
	void*	GetMemory( uint32_t ulSize, uint32_t *pRealSize = NULL);
	void 	FreeMemory( void* lpMemBlock );
	void	Reset(); // reserved
private:
	uint32_t m_ulBlockSize;  //unused now
	uint32_t m_ulBlockCount; //unused now
	bool      m_bUseMempool;
};

#endif // !defined(AFX_MEMORYMGR_H__5906FA6F_2A7A_46A7_9F58_9D045DABB64E__INCLUDED_)
