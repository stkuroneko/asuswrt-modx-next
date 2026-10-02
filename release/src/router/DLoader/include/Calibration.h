#ifndef _CALIBRATION_H
#define	_CALIBRATION_H

#include "typedef.h"
#include <string>
#include <vector>
//#define AGC_SIZE     2 * 142 * 2
//#define APC_SIZE     90 * 2
extern int g_nGSMCaliVaPolicy;

#define NV_MULTI_LANG_ID   (405)
#define GSM_CALI_ITEM_ID   (0x2)
#define GSM_IMEI_ITEM_ID   (0x5)
#define XTD_CALI_ITEM_ID   (0x516)
#define LTE_CALI_ITEM_ID   (0x9C4)
#define BT_ITEM_ID         (0x191)

#define BT_ADDR_LEN  6
typedef struct BT_CONFIG_T
{
	BYTE  bt_addr[BT_ADDR_LEN];
	WORD  xtal_dac;
}BT_CONFIG;

std::string GetErrorDesc( UINT dwID );

///////////////////////////////////////////////////////////////////////
BOOL  XFindNVOffset(WORD wId,LPBYTE lpCode,DWORD dwCodeSize,
                     DWORD& dwOffset,DWORD& dwLength,BOOL bBigEndian = TRUE);

BOOL  XFindNVOffsetEx(WORD wId,LPBYTE lpCode,DWORD dwCodeSize,
                      DWORD& dwOffset,DWORD& dwLength,BOOL &bBigEndian, BOOL bModule);

DWORD GSMCaliPreserve( WORD wID,LPBYTE lpCode, DWORD dwCodeSize, 
                       LPBYTE lpReadBuffer, DWORD dwReadSize,
                       BOOL bOldReplaceNew , BOOL bContinue );

DWORD XTDCaliPreserve(  WORD wID,LPBYTE lpCode, DWORD dwCodeSize, 
                        LPBYTE lpReadBuffer, DWORD dwReadSize,
                        BOOL bOldReplaceNew , BOOL bContinue );

DWORD XPreserveNVItem( WORD wID, LPBYTE lpCode, DWORD dwCodeSize,
					   LPBYTE lpReadBuffer, DWORD dwReadSize,
					   BOOL bOldReplaceNew=FALSE, BOOL bContinue=FALSE);

BOOL  XCheckGSMCali(WORD wId,LPBYTE lpPhoBuf,DWORD dwPhoSize,std::string &strErr,BOOL bModule);

BOOL  XCheckNVStructEx(LPBYTE lpPhoBuf, DWORD dwPhoSize,BOOL &bBigEndian,BOOL bModule);

//BOOL  XSetRandomBT( WORD wId, LPBYTE lpCode, DWORD dwCodeSize, const BT_CONFIG &bt);

DWORD  XPreserveIMEIs( std::vector<UINT> &agIMEIID,LPBYTE lpCode, DWORD dwCodeSize,
					  LPBYTE lpReadBuffer, DWORD dwReadSize, int &nFailedIMEIIndex,
					  BOOL bOldReplaceNew=FALSE, BOOL bContinue=FALSE);

DWORD  LTECaliPreserve(  LPBYTE lpCode, DWORD dwCodeSize,
					  LPBYTE lpReadBuffer, DWORD dwReadSize,
                        BOOL bOldReplaceNew , BOOL bContinue );

//////////////////////////////////////////////////////////////////////////

#endif // _CALIBRATION_H
