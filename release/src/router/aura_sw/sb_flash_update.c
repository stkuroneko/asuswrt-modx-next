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

#if defined(WIN32)
#include "MyTypeDefs.h"
#include "MaskRom.h"
#endif
#include "sb_flash_update.h"
#include <sys/ioctl.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <shutils.h>
#include <bcmnvram.h>
#include <stdlib.h>
#include <shared.h>
//--------------------------------------------------------------------
//Variables
//--------------------------------------------------------------------

#if defined(WIN32)
extern MaskRom s_mask; // at most one of this working structure allowed.
#endif

#define I2CAddr 0x4e
#define FW_SIZE 8176

//--------------------------------------------------------------------
//Structure, ENUM define
//--------------------------------------------------------------------
enum
{
#if defined(WIN32)
	REG_E51CFG			= 0xF010, // E51 config
	REG_F011			= 0xF011, // E51_efen, real h/w reg
	REG_F012			= 0xF012, // E51_status, real h/w reg
	REG_F100			= 0xF100, // WDT reg, real h/w reg
	REG_BUF0			= 0x8000, // SRAM
	REG_BUF0_PARAMS			= 0x80F0,
	REG_BUF0STS			= 0x80F6,
	REG_BUF1			= 0x8100, // SRAM
	REG_BUF1_PARAMS			= 0x81F0,
	REG_BUF1STS			= 0x81F6,
#else
	REG_E51CFG			= 0x10F0, // E51 config
	REG_F011			= 0x11F0, // E51_efen, real h/w reg
	REG_F012			= 0x12F0, // E51_status, real h/w reg
	REG_CHKSUM			= 0x1FF0, // flash check sum
	REG_F100			= 0x00F1, // WDT reg, real h/w reg
	REG_BUF0			= 0x0080, // SRAM
	REG_BUF0_PARAMS			= 0xF080,
	REG_BUF0STS			= 0xF680,
	REG_BUF1			= 0x0081, // SRAM
	REG_BUF1_PARAMS			= 0xF081,
	REG_BUF1STS			= 0xF681,
#endif
};

enum
{
	BIT_BUFRDY			= 0x02,
	BIT_UPDATE_REQ			= 0x01,
	BIT_CODE_IN_FLH_REQ		= 0x01,
	BIT_ROM_OWNERSHIP		= 0x02,
};

enum
{
	//EBD_FLH_SIZE		  = 0x3FF0, // replaced by dwFlashSize
	//EBD_FLH_PAGE_SIZE   = 512,	//			   dwPageSize
	//RAM_SIZE			= 128,
	/*	I2C_SMBUS_BLOCK_MAX 32	*/
	RAM_SIZE			= 32,
	CMD_CHIP_ERASE			= 0x10,
	CMD_PAGE_ERASE			= 0x11,
	CMD_PROGRAM			= 0x20,
	CMD_FLH_READ			= 0x30,
	CMD_FLH_FINISH			= 0x80,
};

typedef struct
{
	BYTE parsing : 1; // f/w is parsing/processing the command.
	BYTE ready : 1;   // the buffer is ready for use.
	BYTE rev : 2;
	BYTE err : 4;	  // ERR_XXX below
} BufSts;

enum {
	ERR_OK			= 0, 
	ERR_INV_ADR		= 1,
	ERR_INV_SIZ		= 2,
	ERR_INV_ADR_SIZ		= 3,
	ERR_WP			= 4,
	ERR_RP			= 5,
	ERR_CODE_SIZE		= 6,
	ERR_CHK_SUM		= 7,	  
	ERR_INV_CMD		= 0x0F
};

#pragma pack(1)
typedef struct
{
	BYTE A2;
	BYTE A1;
	BYTE A0;
	BYTE len2;
	BYTE len1;
	BYTE len0;
	BYTE zeros; // it is in fact buffer status; must zero it when sending cmd/params.
	BYTE cmd;
} CmdParams;
#pragma pack()

//--------------------------------------------------------------------
//macro define
//--------------------------------------------------------------------

#ifndef SLEEP_MS
	#if defined(WIN32)
		#define SLEEP_MS(ms)	   Sleep(ms);
	#else
		#define SLEEP_MS(ms)	   usleep(ms);
	#endif
#endif

#ifndef MAX
	#define MAX(a,b)		(((a) > (b)) ? (a) : (b))
#endif

#ifndef MIN
	#define MIN(a,b)		(((a) < (b)) ? (a) : (b))
#endif

#define _DEBUG_			"/tmp/as_debug"
#if !defined(RTCONFIG_RALINK) && !defined(HND_ROUTER)
#define DBG_MSG(fmt, args...) \
	if(f_exists(_DEBUG_)) { \
		_dprintf(fmt, ## args); \
	}
#else
#define DBG_MSG(fmt, args...) \
	if(f_exists(_DEBUG_)) { \
		printf(fmt, ## args); \
	}
#endif

#define _DEBUG_MORE_		"/tmp/as_debug_more"
#if !defined(RTCONFIG_RALINK) && !defined(HND_ROUTER)
#define DBG_MSG_MORE(fmt, args...) \
	if(f_exists(_DEBUG_MORE_)) { \
		_dprintf(fmt, ## args); \
	}
#else
#define DBG_MSG_MORE(fmt, args...) \
	if(f_exists(_DEBUG_MORE_)) { \
		printf(fmt, ## args); \
	}
#endif

#define MCU_FW_PATH	"/usr/aura_sw/LED.bin"

//--------------------------------------------------------------------
//Static functions
//--------------------------------------------------------------------
static BOOL ReadRegs(WORD wReg, BYTE *pBytes, INT nBytes) 
{
#if defined(WIN32)
	return (&s_mask)->conn->ReadRegs((&s_mask)->conn, wReg, pBytes, nBytes);
#else
	char *buffer;
	char *tmp, *p;
	char tValue;
	int writeBytes = 0;
	char i2c_cmd[255] = {0};

	if(nBytes <= 0 || nBytes > 32)
	{
		DBG_MSG("I2C ReadRegs fail!\n");
		return FALSE;
	}
	
	BYTE readBlock = 0x80;
	readBlock += nBytes;

	if(nBytes > 1)
	{
		snprintf(i2c_cmd, sizeof(i2c_cmd), "i2cset -y 0 0x%02x 0 0x%04x w", I2CAddr, wReg);
		system(i2c_cmd);
		snprintf(i2c_cmd, sizeof(i2c_cmd), "i2cget -y 0 0x%02x 0x%02x i %d > /tmp/i2coutput.txt", I2CAddr, readBlock, nBytes);
		system(i2c_cmd);
		DBG_MSG_MORE("i2cset -y 0 0x%02x 0 0x%04x w\n", I2CAddr, wReg);
		DBG_MSG_MORE("i2cget -y 0 0x%02x 0x%02x i %d > /tmp/i2coutput.txt\n", I2CAddr, readBlock, nBytes);
		buffer = read_whole_file("/tmp/i2coutput.txt");
		if(buffer)
		{
			tmp = p = buffer;
			int i;
			for(i = 0; i < nBytes - 1; i++)
			{
				if((tmp = strchr(tmp, ' ')))
				{
					tValue = atoi(p);
					pBytes[i] = tValue;
					tmp++;
					p = tmp;
					writeBytes++;
				}
			}
			free(buffer);
		}
		unlink("/tmp/i2coutput.txt");

		if(writeBytes != (nBytes - 1))
		{
			DBG_MSG("I2C ReadRegs fail!\n");
			return FALSE;
		}

		//fill in last byte data
		wReg += ((nBytes - 1) << 8);
	}

	//handle single byte case or block data last byte
	snprintf(i2c_cmd, sizeof(i2c_cmd), "i2cset -y 0 0x%02x 0 0x%04x w", I2CAddr, wReg);
	system(i2c_cmd);
	snprintf(i2c_cmd, sizeof(i2c_cmd), "i2cget -y 0 0x%02x 0x81 i 1 > /tmp/i2coutput.txt", I2CAddr);
	system(i2c_cmd);
	DBG_MSG_MORE("i2cset -y 0 0x%02x 0 0x%04x w\n", I2CAddr, wReg);
	DBG_MSG_MORE("i2cget -y 0 0x%02x 0x81 i 1 > /tmp/i2coutput.txt\n", I2CAddr);

	buffer = read_whole_file("/tmp/i2coutput.txt");
	if(buffer)
	{
		tmp = p = buffer;
		if((tmp = strchr(tmp, ' ')))
		{
			tValue = atoi(p);
			pBytes[nBytes - 1] = tValue;
		}
		free(buffer);
	}
	unlink("/tmp/i2coutput.txt");
	
	return TRUE;
#endif	  
}

static BOOL WriteRegs(WORD wReg, BYTE *pBytes, INT nBytes)
{
#if defined(WIN32)
	return (&s_mask)->conn->WriteRegs((&s_mask)->conn, wReg, pBytes, nBytes);
#else
	//for i2c write block data
	char writeBlock[256] = {0};
	char hex[10];
	int singleByte = 0, i;
	char i2c_cmd[255] = {0};
	int maxRegProtect = 0;

#if defined(_DEBUG_MORE_)
	DBG_MSG_MORE("WriteRegs %d \n", nBytes);
	for(i = 0; i < nBytes; i++)
	{
		DBG_MSG_MORE("0x%02x ", pBytes[i]);
	}

	DBG_MSG_MORE("\n", nBytes);
#endif
	if(nBytes > 1)
	{
		if(nBytes == 32)
			maxRegProtect = nBytes - 2;
		else
			maxRegProtect = nBytes;
		for(i = 0; i < maxRegProtect; i++)
		{
			sprintf(hex, "0x%02x ", pBytes[i]);
			strcat(writeBlock, hex);
		}
		if(i != maxRegProtect)
		{
			DBG_MSG("I2C WriteRegs fail!\n");
			return FALSE;
		}
		snprintf(i2c_cmd, sizeof(i2c_cmd), "i2cset -y 0 0x%02x 0 0x%04x w", I2CAddr, wReg);
		system(i2c_cmd);	
		snprintf(i2c_cmd, sizeof(i2c_cmd), "i2cset -y 0 0x%02x 0x03 0x%02x %s i", I2CAddr, maxRegProtect, writeBlock);
		system(i2c_cmd);
		DBG_MSG_MORE("i2cset -y 0 0x%02x 0 0x%04x w\n", I2CAddr, wReg);	
		DBG_MSG_MORE("i2cset -y 0 0x%02x 0x03 0x%02x %s i\n", I2CAddr, maxRegProtect, writeBlock);

		//fill in last byte data
		wReg += (maxRegProtect << 8);
		singleByte = maxRegProtect;
	}

	if(nBytes == 1)	//handle single byte case

	{
		snprintf(i2c_cmd, sizeof(i2c_cmd), "i2cset -y 0 0x%02x 0 0x%04x w", I2CAddr, wReg);
		system(i2c_cmd);
		snprintf(i2c_cmd, sizeof(i2c_cmd), "i2cset -y 0 0x%02x 0x03 0x01 0x%02x i", I2CAddr, pBytes[singleByte]);
		system(i2c_cmd);
		DBG_MSG_MORE("i2cset -y 0 0x%02x 0 0x%04x w\n", I2CAddr, wReg);
		DBG_MSG_MORE("i2cset -y 0 0x%02x 0x03 0x01 0x%02x i\n", I2CAddr, pBytes[singleByte]);
	}
	else if(nBytes == 32) //handle block data last bytes

	{
		snprintf(i2c_cmd, sizeof(i2c_cmd), "i2cset -y 0 0x%02x 0 0x%04x w", I2CAddr, wReg);
		system(i2c_cmd);
		snprintf(i2c_cmd, sizeof(i2c_cmd), "i2cset -y 0 0x%02x 0x03 0x02 0x%02x 0x%02x i", I2CAddr, pBytes[singleByte], pBytes[singleByte + 1]);
		system(i2c_cmd);
		DBG_MSG_MORE("i2cset -y 0 0x%02x 0 0x%04x w\n", I2CAddr, wReg);
		DBG_MSG_MORE("i2cset -y 0 0x%02x 0x03 0x02 0x%02x 0x%02x i", I2CAddr, pBytes[singleByte], pBytes[singleByte + 1]);
	}

	return TRUE;
#endif	  
}


char *ErrString(INT err)
{
	switch(err)
	{
	case ERR_OK:
		return "No error";
	case ERR_INV_ADR:
		return "Invalid address";
	case ERR_INV_SIZ:
		return "Invalid size";
	case ERR_INV_ADR_SIZ:
		return "Invalid address size";
	case ERR_WP:
		return "Write protected";
	case ERR_RP:
		return "Read protected";
	case ERR_CODE_SIZE:
		return "Code size";
	case ERR_CHK_SUM:
		return "Check sum";		   
	case ERR_INV_CMD:
		return "Invalid command";
	default:
		return "Unknown error";
	};
}

//
// PURPOSE: return the free (ready) ram buffer (0 or 1)
//			return -1 if no free ram buffer
INT GetFreeRam(BOOL *pBothFree)
{
	BYTE flg12;
	BufSts sts0, sts1;
	INT ram = -1;
	BOOL bBothFree = FALSE;
#ifdef WIN32
	DWORD t0 = GetTickCount(), dt = 0;
#else
	DWORD dt = 0;
#endif

	if(!ReadRegs(REG_F012, &flg12, 1))
	{
		DBG_MSG("GetFreeRam() failed: ReadRegs(REG_F012) fail.\n");
		return -1;
	}

	if(!(flg12 & BIT_ROM_OWNERSHIP))
	{
		DBG_MSG("GetFreeRam() failed: No BIT_ROM_OWNERSHIP.\n");
		return -1;
	}

	while(dt < 2000) // retry 2 sec.
	{
		if (!ReadRegs(REG_BUF0STS, (BYTE *) &sts0, 1) ||
			!ReadRegs(REG_BUF1STS, (BYTE *) &sts1, 1))
		{
			DBG_MSG("GetFreeRam() failed: ReadRegs(REG_BUF0/1STS) fail.\n");
			return -1;
		}

		if(sts0.ready)
		{
			bBothFree = sts1.ready;
			ram = 0;
			break;
		}
		else if(sts1.ready)
		{
			ram = 1;
			break;
		}
		// else, both not ready, wait.

#ifdef WIN32
		dt = GetTickCount() - t0; // wrapping doesn't matter.
#else
		SLEEP_MS(10);
		dt += 10;
#endif
	}

	if(pBothFree)
		*pBothFree = bBothFree;


#if defined(WIN32) && defined(_DEBUG )
	if(ram == -1)
		DBG_MSG("GetFreeRam() timed out: flg12 = 0x%X, buf0sts = 0x%X, buf1sts = 0x%X\n",
				flg12, *(BYTE *) &sts0, *(BYTE *) &sts1);
#endif

	return ram;
}

BOOL WaitRamReady(INT iRam)
{
	WORD regBufSts = (iRam == 0) ? REG_BUF0STS : REG_BUF1STS;
	BufSts sts;
#ifdef WIN32
	DWORD t0 = GetTickCount(), dt = 0;
#else
	DWORD dt = 0;
#endif

	while(dt < 2000) // retry 2 sec.
	{
		if(!ReadRegs(regBufSts, (BYTE *) &sts, 1))
			return FALSE;
		
		if(sts.ready)
		{
			if(sts.err == 0)
				return TRUE;
			else
			{
				DBG_MSG("WaitRamReady() RAM%d ERR: %s\n", iRam, ErrString(sts.err));
				return FALSE;
			}
		}
#ifdef WIN32
		dt = GetTickCount() - t0; // wrapping doesn't matter.
#else
		SLEEP_MS(10);
		dt += 10;
#endif
	}

	DBG_MSG("WaitRamReady() timeout.\n");

	return FALSE;
}

void ChkSumCalc(DWORD flashAdr, BYTE *buf, DWORD len, BOOL bPartialMode)
{
	DWORD i;

	if(flashAdr == 0) // reset checksum
	{
		_chkdata.len = 0;
		_chkdata.wordsum= 0;
		_chkdata.xoR = 0;
	}

	if(bPartialMode) // Only offset 7F, FF, ...XX7F,XXFF are checksum-ed. (7F+n*80).
	{
		// If adr is between XX00~XX7F==>offset=XX7F; If adr is between XX80~XXFF==>offset=XXFF.
		DWORD offset = ((flashAdr & 0xFF) <= 0x7F) ? ((flashAdr & 0xFFFFFF00) + 0x7F) : ((flashAdr & 0xFFFFFF00) + 0xFF);
		while(offset < flashAdr + len)
		{
			_chkdata.wordsum += buf[offset - flashAdr];
			_chkdata.xoR ^= buf[offset - flashAdr];
			offset += 0x80;
		}
	}
	else // mode full.
	{
		for(i = 0; i < len; i++)
		{
			_chkdata.wordsum += buf[i];
			_chkdata.xoR ^= buf[i];
		}
	}

	_chkdata.sum = (BYTE)_chkdata.wordsum;
	_chkdata.len += (WORD)len; // accumulate len written to flash.
}

BOOL ReadRamBuffer(INT iRam, BYTE *buf, DWORD len)
{
	WORD regBuf = (iRam == 0) ? REG_BUF0 : REG_BUF1;
	return ReadRegs(regBuf, buf, len);
}

//
// PURPOSE: Read RAM_SIZE bytes (or less) from embedded flash.
// REQUIRE: Already entered code-in-rom.
BOOL ReadFlashRam(DWORD adr, BYTE *buf, DWORD len)
{
	INT ram;
	WORD regParams;
	CmdParams params = {0};

#ifdef WIN32
	ASSERT(len <= RAM_SIZE);
#endif

	ram = GetFreeRam(NULL);
	if(ram == -1)
		return FALSE;

	regParams = (ram == 0) ? REG_BUF0_PARAMS : REG_BUF1_PARAMS;

	params.A0 = (BYTE) adr;
	params.A1 = (BYTE) (adr >> 8);
	params.A2 = (BYTE) (adr >> 16);
	params.len0 = (BYTE) len;
	params.len1 = (BYTE) (len >> 8);
	params.len2 = (BYTE) (len >> 16);
	params.cmd = CMD_FLH_READ;

	if(!WriteRegs(regParams, (BYTE *) &params, sizeof(params)))
		return FALSE;

	if(!WaitRamReady(ram))
		return FALSE;

	if(!ReadRamBuffer(ram, buf, len))
		return FALSE;

	return TRUE;
}

//
// PURPOSE: Write RAM_SIZE bytes (or less) to one of the RAMs,
//			and make rom-code begin moving data to flash.
// REQUIRE: Already entered code-in-rom.
BOOL WriteFlashRam(DWORD adr, BYTE *buf, DWORD len)
{
	INT ram;
	WORD regBuf;
	WORD regParams;

#ifdef WIN32
	ASSERT(len <= RAM_SIZE);
#endif

	ram = GetFreeRam(NULL);
	if(ram == -1)
		return FALSE;

	regBuf = (ram == 0) ? REG_BUF0 : REG_BUF1;


	if (!WriteRegs(regBuf, buf, len))
		return FALSE;


	CmdParams params = {0};
	regParams = (ram == 0) ? REG_BUF0_PARAMS : REG_BUF1_PARAMS;

	params.A0 = (BYTE) adr;
	params.A1 = (BYTE) (adr >> 8);
	params.A2 = (BYTE) (adr >> 16);
	params.len0 = (BYTE) len;
	params.len1 = (BYTE) (len >> 8);
	params.len2 = (BYTE) (len >> 16);
	params.cmd = CMD_PROGRAM;

	if (!WriteRegs(regParams, (BYTE *) &params, sizeof(params)))
		return FALSE;

	return	TRUE;
}

BOOL WriteChkData(void)
{
	CHKDATA sChkData = {0};

	// Convert to f/w defined checksum format.
	sChkData.len = _chkdata.len;
	_chkdata.rp = sChkData.rp = 0; //FLASH_READ_PROTECT
	_chkdata.wp = sChkData.wp = 0; //FLASH_WRITE_PROTECT

	//only do full checksum
	sChkData.sum = (BYTE)_chkdata.wordsum;
	sChkData.wordsum = _chkdata.wordsum;	
	sChkData.xoR = _chkdata.xoR;
	sChkData.mode = CHKSUM_FULL;

	// Write check data to flash.
	if(!WriteFlashRam(REG_CHKSUM, (BYTE *)&sChkData, sizeof(CHKDATA)))
		return FALSE;

	//Wait for the write above to complete
	SLEEP_MS(10);

	return TRUE;
}

BOOL ReadChkData(void)
{
	CHKDATA sChkData = {0};

	if(!ReadFlashRam(REG_CHKSUM, (BYTE *)&sChkData, sizeof(CHKDATA)))
		return FALSE;
	
	//only check full check sum data
	if (sChkData.mode == CHKSUM_FULL)
	{
		if (_chkdata.len == sChkData.len &&
			_chkdata.rp == sChkData.rp &&
			_chkdata.wp == sChkData.wp &&
			_chkdata.sum == sChkData.sum &&
			_chkdata.wordsum == sChkData.wordsum &&
			_chkdata.xoR == sChkData.xoR)
			return TRUE;
	}

	return FALSE;	 
}

BOOL SbEnterCodeInRom(void)
{
	INT i;
	BYTE flg12 = 0, flg11 = 0, flg_10 = 0, flg_f100 = 0, flg_0x04 = 1;

	//no need?
	//WriteRegs(0x04, &flg_0x04, 1);		//switch to SMBUS mode

	if (!ReadRegs(REG_F012, &flg12, 1) || !ReadRegs(REG_F011, &flg11, 1)|| !ReadRegs(REG_E51CFG, &flg_10, 1))
		return FALSE;

	flg_10 |= 0x01;				// stop and reset 8051
	flg12 |= BIT_UPDATE_REQ;		// update request
	flg11 &= ~BIT_CODE_IN_FLH_REQ;		// code-in-rom request


	if (!WriteRegs(REG_E51CFG, &flg_10, 1)) //stop 8051
		return FALSE;

	if (!WriteRegs(REG_F100, &flg_f100, 1)) // stop WDT
		return FALSE;

	// set the requests.
	if (!WriteRegs(REG_F012, &flg12, 1) || !WriteRegs(REG_F011, &flg11, 1)) 
		return FALSE;
	
	flg_10 &= ~0x01;			// start 8051
	if (!WriteRegs(REG_E51CFG, &flg_10, 1))
		return FALSE;
	for(i = 0; i < 200; i++)		// retry 2 sec
	{
		if (!ReadRegs(REG_F012, &flg12, 1) || !ReadRegs(REG_F011, &flg11, 1))
			return FALSE;

		if ((flg12 & BIT_ROM_OWNERSHIP)    &&
			(flg12 & BIT_UPDATE_REQ)	   &&
			!(flg11 & BIT_CODE_IN_FLH_REQ))
			return TRUE;

		SLEEP_MS(10);
	}

	DBG_MSG("SbEnterCodeInRom() failed\n");
	return FALSE;
}

BOOL SbExitCodeInRom(void)
{
	WORD regParams;
	CmdParams params = {0};
	INT i, ram;

	ram = GetFreeRam(NULL);
	if(ram == -1)
		return FALSE;

	regParams = (ram == 0) ? REG_BUF0_PARAMS : REG_BUF1_PARAMS;
	params.cmd = CMD_FLH_FINISH; // tell rom to end parsing cmds.

	if(!WriteRegs(regParams, (BYTE *) &params, sizeof(params)))
		return FALSE;
	for(i = 0; i < 200; i++) // retry 2 sec
	{
		BYTE flg12 = 0;
		
		if(!ReadRegs(REG_F012, &flg12, 1))
			return FALSE;
		
		if (!(flg12 & BIT_UPDATE_REQ)) // &&
			//!(flg12 & BIT_ROM_OWNERSHIP) == 0)  This stands only if flash code is checksum good.
		{
			// Seems required. The ROM checks checksum by reading flash, if good, gives ownership to flash code...
			// This delay especially required when there is checksum-good f/w in flash.
			// If no delay, the next loop of enter-code-in-rom->erase->program, is easy to fail.
			SLEEP_MS(200);

			return TRUE;
		}

		SLEEP_MS(10);
	}

	return FALSE;
}

BOOL SbFlashChipErase(void)
{
	DWORD len;
	WORD regParams;
	CmdParams params = {0};
	INT ram;

	ram = GetFreeRam(NULL);
	if(ram == -1)
		return FALSE;

	len = 0x2000; // erase whole flash size.
	regParams = (ram == 0) ? REG_BUF0_PARAMS : REG_BUF1_PARAMS;

	params.len0 = (BYTE) (len);
	params.len1 = (BYTE) (len >> 8);
	params.len2 = (BYTE) (len >> 16);
	params.cmd = CMD_CHIP_ERASE;

	if(!WriteRegs(regParams, (BYTE *) &params, sizeof(params)))
		return FALSE;

	//spec says it is needed.
	if(!WaitRamReady(ram))
		return FALSE;
	
	/* seems required for waiting erase done, otherwise subsequent flash-write
		causes compare error. (any better way like status checking ?) */
	SLEEP_MS(50);  
	
	return TRUE;
}

BOOL SbFlashWrite(DWORD adr, BYTE *buf, DWORD len)
{
	DWORD dwBytesLeft = len;

	//loop to write data into flash
	while(dwBytesLeft)
	{
		DWORD dwBytesThisWrite = MIN(dwBytesLeft, (DWORD) RAM_SIZE);

		// compute and accumulate checksum of this INPUT buffer.
		ChkSumCalc(adr, buf, dwBytesThisWrite, false);
	
		if(WriteFlashRam(adr, buf, dwBytesThisWrite))
		{
			// No need to wait ram-buffer ready, since we're going to write next page using another free ram-buffer.
			// It is possible both ram-buffers are busy, then GetFreeRam() called by WriteFlashRam() will wait.
			dwBytesLeft -= dwBytesThisWrite;
			adr += dwBytesThisWrite;
			buf += dwBytesThisWrite;
		}
		else
			break;
	}

	if (dwBytesLeft) // not all done.
		return FALSE;

	// spec. says this is needed.
	//if(!WaitBothRamReady()) 
	if (!(WaitRamReady(0) && WaitRamReady(1)))
		return FALSE;

	return TRUE;
}

BOOL SbFlashRead(DWORD adr, BYTE *buf, DWORD len)
{
	DWORD dwBytesLeft = len;

	//loop to read data from flash
	while(dwBytesLeft)
	{
		DWORD dwBytesThisRead = MIN(dwBytesLeft, (DWORD) RAM_SIZE);

		if(ReadFlashRam(adr, buf, dwBytesThisRead))
		{
			// Compute and accumulate checksum of this OUTPUT flash data. For the "Update" case where some sectors(pages)
			//	 are protected; The AP will write non-protected pages and read protected pages so that we can have chance
			//	 to accumulate checksum for ALL pages involved.
			ChkSumCalc(adr, buf, dwBytesThisRead, false);

			adr += dwBytesThisRead;
			buf += dwBytesThisRead;
			dwBytesLeft -= dwBytesThisRead;
		}
		else
			break;
	}

	if (dwBytesLeft) // not all done.
		return FALSE;

	return TRUE;
}

BOOL SbFWUpdate(BYTE *buf, DWORD buflen)
{
	BYTE r_data[0x1FF0];   
	BYTE flg11 = 0;
	WORD i;
	BYTE backup_i2cAdr;
	BYTE adrs[] = {0x9C, 0x9E, 0xCC, 0xCE};
	BYTE flg12;
	
	/* customer code
		buf = fw code data
		buflen = fw code length in byte unit
	*/
		
	//a. Enter code-in-rom before we can talk to mask ROM.
	//back up I2C address
	//backup_i2cAdr = GetI2cAdr();
	//check i2c device exist?
	char *detect;
	system("i2cdetect -y -r 0 > /tmp/i2coutput.txt");
	detect = read_whole_file("/tmp/i2coutput.txt");
	if(detect)
	{
		if(!strstr(detect, "4e"))
		{
			DBG_MSG("i2c device detect error!\n");
			unlink("/tmp/i2coutput.txt");
			goto err_update;
		}
		free(detect);
	}
	else
	{
		DBG_MSG("i2c device detect error!\n");
		unlink("/tmp/i2coutput.txt");
		goto err_update;
	}
	unlink("/tmp/i2coutput.txt");

	DBG_MSG("### start SbEnterCodeInRom!\n");
	if (!SbEnterCodeInRom())
	{
#if 0
		// Switch to ROM code or Stop 8051 Fail
		// Retry SB357x B0 4 address because B0 ROMcode will change I2C address here
		for(i = 0; i < sizeof(adrs) / sizeof(adrs[0]); i++)
		{
			SetI2cAdr(adrs[i]);
			flg12 = flg11 = 0;
			
			if (!ReadRegs(REG_F012, &flg12, 1) || !ReadRegs(REG_F011, &flg11, 1))
				continue;

			if ((flg12 & BIT_ROM_OWNERSHIP)    &&
				(flg12 & BIT_UPDATE_REQ)	   &&
				!(flg11 & BIT_CODE_IN_FLH_REQ))
				break;
		}
		if (i == sizeof(adrs))
#endif
			DBG_MSG("SbEnterCodeInRom error!\n");
			goto err_update;		
	}

	DBG_MSG("### end SbEnterCodeInRom!\n");

	DBG_MSG("### start SbFlashChipErase!\n");
	//b. Erase content before writing
	if (!SbFlashChipErase())
		goto err_update;
	DBG_MSG("### end SbFlashChipErase!\n");

	DBG_MSG("### start SbFlashWrite!\n");
	//c. to write FW code into flash 
	if (!SbFlashWrite(0x00, buf, buflen))
		goto err_update;	  
	DBG_MSG("### end SbFlashWrite!\n");

	DBG_MSG("### start WriteChkData!\n");
	//d. write checksum data
	if (!WriteChkData())
		return FALSE;
	DBG_MSG("### end WriteChkData!\n");

	DBG_MSG("### start SbFlashRead!\n");
	//e. to read FW code from flash and verify the r_data with write data
	if (!SbFlashRead(0x00, r_data, buflen))
		goto err_update;
	DBG_MSG("### end SbFlashRead!\n");

	for (i=0; i<buflen; i++)
	{
		if (buf[i] != r_data[i])
		{
			//verify failed
			DBG_MSG("%d byte verify failed! 0x%02x:0x%02x\n", i, buf[i], r_data[i]);
			goto err_update;
		}
	}

	DBG_MSG("### start ReadChkData!\n");
	//f. to compare check data from 0x1FF0~0x1FFF
	if (!ReadChkData())
		return FALSE;
	DBG_MSG("### end ReadChkData!\n");

	DBG_MSG("### start SbExitCodeInRom!\n");
	//g. exit code-in-rom
	if (!SbExitCodeInRom())
	{
#if 0
		//restore I2C address if B0 chip
		SetI2cAdr(backup_i2cAdr);
		if(!ReadRegs(REG_F012, &flg12, 1))
			return FALSE;
		
		if ((flg12 & BIT_UPDATE_REQ))
#endif
		DBG_MSG("SbExitCodeInRom error!\n");
			goto err_update;
	}
	DBG_MSG("### end SbExitCodeInRom!\n");

	//h. reset mcu
	flg11 = 1;
	WriteRegs(REG_F011, &flg11, 1);
	flg11 = 0;
	WriteRegs(REG_F011, &flg11, 1);
	return TRUE;

err_update:
	return FALSE;
}

int main()
{
	FILE *fp=NULL;
	BYTE buf[FW_SIZE];
	INT file_length=0;

	fp = fopen(MCU_FW_PATH, "rb");
	if(!fp)
	{
		DBG_MSG("fw bin file open fail!\n");
		return FALSE;
	}

	if(fseek(fp, 0, SEEK_END))
	{
		DBG_MSG("fw bin file read length fail!\n");
		fclose(fp);
		return FALSE;
	}
	
	file_length = ftell(fp);
	rewind(fp);
	//don't read check sum data
	file_length -= 0x10;
	
	if(fread(buf, sizeof(BYTE), file_length, fp) != file_length)
	{
		DBG_MSG("fw bin file read fail!\n");
		fclose(fp);
		return FALSE;
	}

	DBG_MSG("fw bin file open success!\n");
	if(!SbFWUpdate(buf, file_length))
	{
		DBG_MSG("fw update fail!\n");
		fclose(fp);
		return FALSE;
	}
	
	DBG_MSG("fw update success!\n");
	_dprintf("sb flash update success\n");
	fclose(fp);
	return TRUE;
}
