/**********************************************************************************
 * 
 * Copyright (c) 2011-2013 ENE Technology, Inc.
 * All rights reserved.
 * 
 * ENE Technology <www.ene.com.tw>
 *		
 * EnE reserves the right to amend this code without notice at any time.  
 * EnE assumes no responsibility for any errors appeared in the code,	  
 * and EnE disclaims any express or implied warranty, relating to sale	  
 * and/or use of this code including liability or warranties relating	  
 * to fitness for a particular purpose, or infringement of any patent,	  
 *	copyright or other intellectual property right.			   
 *
 *********************************************************************************/

#ifndef _SB_FLASH_UPDATE_H_
#define _SB_FLASH_UPDATE_H_
#include <iboxcom.h>
#include <stdbool.h>
#define BOOL	bool

enum { FLASH_READ_PROTECT = 1, FLASH_WRITE_PROTECT = 2 }; // read-protect and write-protect flags.
enum { CHKSUM_DISABLE = 0xAA, CHKSUM_PARTIAL = 0x55, CHKSUM_FULL = 0 };

typedef struct CheckSum
{
	DWORD len;
	BYTE xoR;
	WORD sum;
} CHECKSUM;

#pragma pack(1)
typedef struct
{
	WORD len; // current chips with maskROM support flash size <= 64KB.
	BYTE rev0;
	BYTE rev1;
	BYTE sum;
	BYTE xoR;
	BYTE mode;	  // CHKSUM_MODE_XXX.
	BYTE partSum; // partial mode check sum.
	BYTE partXor; // partial mode check xor.
	BYTE rp : 1;
	BYTE wp : 1;
	BYTE rev2 : 6;
	WORD wordsum;
	BYTE rev3[4];
} CHKDATA;
#pragma pack()

CHKDATA    _chkdata;

//--------------------------------------------------------------------
//Function Prototype
//--------------------------------------------------------------------
INT GetFreeRam(BOOL *bBothFree);

BOOL WaitRamReady(INT iRam);

//BOOL WaitBothRamReady(void) { return WaitRamReady(0) && WaitRamReady(1); }
BOOL ReadRamBuffer(INT iRam, BYTE *buf, DWORD len);

BOOL ReadFlashRam(DWORD addr, BYTE *buf, DWORD len);

BOOL WriteFlashRam(DWORD addr, BYTE *buf, DWORD len);

char *ErrString(INT err);

BOOL WriteChkData(void);

BOOL ReadChkData(void);

BOOL SbEnterCodeInRom(void);

BOOL SbExitCodeInRom(void);

BOOL SbFlashChipErase(void);

BOOL SbFlashWrite(DWORD addr, BYTE *buf, DWORD buflen);

BOOL SbFlashRead(DWORD addr, BYTE *buf, DWORD buflen);

BOOL SbFWUpdate(BYTE *buf, DWORD buflen);

#endif // _SB_FLASH_UPDATE_H_
