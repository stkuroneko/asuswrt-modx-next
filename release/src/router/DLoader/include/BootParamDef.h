#ifndef BOOTPARAMDEF_H
#define BOOTPARAMDEF_H

/*lint -save -e756*/
typedef struct _OS_INFO {
	char    Name[24];
	char    Description[48];
	char	Version[24];
	unsigned short	Offset;  // in sectors
	unsigned short	Size;    // in sectors
} OS_INFO/*, * POS_INFO*/;

typedef struct _BOOT_PARAM {
	unsigned char	Magic[4];
	unsigned short  Size;
	unsigned short  TotalSize;
	long	        TimeStamp;
	unsigned char	TraceOn;
	unsigned char	Reserved;
	unsigned char	CurrentOS;
	unsigned char	NumOfOS;
	unsigned short  SizeOfOSInfo;
	unsigned short  OSOffset;
} BOOT_PARAM/*, * PBOOT_PARAM*/;
/*lint -restore */

inline unsigned short SwapWord( unsigned short src )
{
	return MAKEWORD( HIBYTE(src), LOBYTE(src) );
}

inline unsigned long SwapDword( unsigned long src )
{
	return MAKELONG( SwapWord( HIWORD(src) ),
		             SwapWord( LOWORD(src) ) );
}


#endif // BOOTPARAMDEF_H