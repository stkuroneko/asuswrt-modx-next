#include "MasterImgGen.h"
#include "BootParamDef.h"
#include <stdio.h>
#include <string.h>

#define SECTOR_SIZE			512
static const unsigned char MAGIC[] = { 'S', 'T', 'B', 'P' };

#define NEW_ARRAY( p, type, size ) \
{                                  \
	(p) = new type [ size ];       \
	if ( NULL == (p) )             \
		__leave;                   \
}

#define DELETE_ARRAY( p ) \
	if ( NULL != (p) ) {  \
		delete[] (p);     \
		(p) = NULL;       \
	}

#define CLOSE_FILE( f )  \
	if ( NULL != (f) ) { \
		::fclose( f );   \
		(f) = NULL;      \
	}



LPBYTE CMasterImgGen::MakeMasterImageHeader(DWORD dwPSSize,DWORD *pdwHdrSize, int page_type )
{

	DWORD		dwSectsPerBlock = 0;
	DWORD		dwHeadSize = 0;
	DWORD		dwBootSize= 0;
	BOOT_PARAM * pBoot = NULL;
	OS_INFO    * pOS= NULL;

	BOOT_PARAM * pBootBak= NULL;
	OS_INFO    * pOSBak= NULL;


	LPBYTE pHeadBuf = NULL;

	dwSectsPerBlock = (SMALL_PAGE == page_type) ? 32 : 256;
	dwBootSize = sizeof(BOOT_PARAM) + sizeof( OS_INFO );

	dwHeadSize = dwSectsPerBlock * SECTOR_SIZE;

	pHeadBuf = new BYTE[dwHeadSize];
	memset(pHeadBuf,0xFF,dwHeadSize);

	//init boot param
	pBoot = (BOOT_PARAM *)pHeadBuf;
	memset(pBoot,0,sizeof(BOOT_PARAM));
	memcpy( pBoot->Magic, MAGIC, sizeof(pBoot->Magic) );
	pBoot->Size = SwapWord((WORD)sizeof( BOOT_PARAM ));
	pBoot->TotalSize = SwapWord((WORD)dwBootSize);
	time(&pBoot->TimeStamp);
	pBoot->TimeStamp = SwapDword( pBoot->TimeStamp );
	pBoot->TraceOn   = ( BYTE )1;
	pBoot->Reserved  = ( BYTE )0;
	pBoot->CurrentOS = ( BYTE )0;
	pBoot->NumOfOS   = ( BYTE )1;
	pBoot->SizeOfOSInfo =  SwapWord((WORD)sizeof( OS_INFO ));
	pBoot->OSOffset  = SwapWord((WORD)sizeof( BOOT_PARAM ));

	//init OS info
	pOS = (OS_INFO*)(((BYTE *)pHeadBuf) + sizeof(BOOT_PARAM));
	memset(pOS,0,sizeof(OS_INFO));
	pOS->Offset =  SwapWord((WORD)dwSectsPerBlock);
	pOS->Size =  SwapWord((WORD)(( dwPSSize + SECTOR_SIZE - 1 ) / SECTOR_SIZE ));

	pBootBak = (BOOT_PARAM*)(pHeadBuf + dwHeadSize/2);
	pOSBak = (OS_INFO*)( ((BYTE*)(pBootBak)) + sizeof(BOOT_PARAM));
	memcpy(pBootBak,pBoot,sizeof(BOOT_PARAM));
	memcpy(pOSBak,pOS,sizeof(OS_INFO));

	*pdwHdrSize = dwHeadSize;

	return pHeadBuf;

}

void * CMasterImgGen::MakeMasterImageSingle(DWORD *pImageSize,
		                  int NumOfImages,
						  IMAGE_PARAM * lpImageParam,
						  int PageType )
{
	if(pImageSize == NULL || NumOfImages != 1 || lpImageParam == NULL)
	{
		return NULL;
	}

	FILE *pFile = NULL;
	pFile = fopen(lpImageParam->szPath,"rb");

	if(NULL == pFile)
	{
		return NULL;
	}

    	fseek(pFile,0,SEEK_END);

	DWORD dwSize = ftell(pFile);

	fseek(pFile,0,SEEK_SET);

	DWORD dwHeadSize = 0;

	LPBYTE pHead = MakeMasterImageHeader(dwSize,&dwHeadSize,PageType);
	if(pHead == NULL || dwHeadSize==0)
	{
		fclose(pFile);
		return NULL;
	}

	DWORD dwImgSize= dwHeadSize + (((dwSize + SECTOR_SIZE - 1 ) / SECTOR_SIZE) * SECTOR_SIZE);

	LPBYTE pImg = new BYTE[dwImgSize];
	if(pImg == NULL)
	{
		delete [] pHead;
		fclose(pFile);
		return NULL;

	}

	memset(pImg,0xFF,dwImgSize);

	memcpy(pImg,pHead,dwHeadSize);
	delete [] pHead;
	pHead = NULL;

	DWORD dwRead = fread(pImg+dwHeadSize,1, dwSize,pFile);
	if(dwRead != dwSize)
	{
		delete [] pImg;
		fclose(pFile);
		return NULL;
	}

	*pImageSize = dwImgSize;

	fclose(pFile);

	return pImg;
}
