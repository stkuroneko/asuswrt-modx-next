// PhaseCheckBuild.h: interface for the CPhaseCheckBuild class.
//
//////////////////////////////////////////////////////////////////////

#ifndef PHASECHECKBUILD_H
#define PHASECHECKBUILD_H

//////////////////////////////////////////////////////////////////////////
// Include files
#include "phdef.h"
#define MAX_PRODUCTIONINFO_SIZE         ( 0x2000 )

//////////////////////////////////////////////////////////////////////////
//
class CPhaseCheckBuild  
{
public:
	CPhaseCheckBuild();
	virtual 	~CPhaseCheckBuild();

	BOOL        	CnstPhaseInfo(const char *sn, LPBYTE lpData, int nDataLen, int *pnRetLen);
	BOOL        	CnstPhaseInfo(const char *sn1, const char *sn2, LPBYTE lpData, int nDataLen, int *pnRetLen);
	SPPH_MAGIC  GetMagic(void) {  return m_eMagic; };
    
    /* Below interface ONLY for Download...  [[[ */
    /*
        Input : --> sn 
        Output: <-- lpData (8192Byts buffer)
    
        sn:         pointer to the buffer containing sn, max. length is 24 bytes.
        lpData:     pointer to the buffer that receives the phasecheck datas, the buffer must be larger than 8192 bytes
        nDataLen:   number of bytes of lpData buffer.
    */
    BOOL        Cnst8KBuffer(const char *sn/*IN*/, LPBYTE lpData/*OUT*/, int nDataLen,const char *sn2  =NULL);
    /*
        Input : --> lpData
        Output: <-- sn

        lpData:     pointer to the buffer containing phasecheck datas.
        nDataLen:   number of bytes of lpData buffer.
        sn:         pointer to the buffer that receives the sn.  
        nSnLen:     number of bytes of sn buffer.
            
    */
    BOOL        FindSnFrom8K(const BYTE *lpData/*IN*/, int nDataLen, BYTE *sn/*OUT*/, int nSnLen);
    //  ]]]

private:
    BOOL        LoadConfigFile(void);

private:
    SP05_PHASE_CHECK_T  m_phaseBuf05;    
    SP09_PHASE_CHECK_T  m_phaseBuf09; 
    SP15_PHASE_CHECK_T  m_phaseBuf15;  // Bug: 449541
    SPPH_MAGIC          m_eMagic;

};

#endif
