#ifndef _PRECOMP_H
#define _PRECOMP_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <time.h>
#include   <fcntl.h>   //   optional
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/io.h>
#include "typedef.h"
#include "lib/pci.h"
#include "pci.h"
#include "interctl.h"
#include "asm114.h"
#include "xhci.h"

#define DEBUG  0

//#ifdef DEBUG
//#define func_enter() 	printf("\n\nEnter :    %s(%d)-%s\n",__FILE__,__LINE__,__FUNCTION__);
//#define func_exit()		printf("\n\nExit :    %s(%d)-%s\n",__FILE__,__LINE__,__FUNCTION__);
//#else
#define func_enter()
#define func_exit()
//#endif

#define MAX_DEVICE_CNT 16

//gloable var
extern int verblevel;


//pci.c
int asm_pci_init( void );
void asm_pci_exit( void );
int do_detect_device( int *devices_cnt, int display );



//interctl.c

int interctl_write_command( BYTE cmd, BYTE mem_type, WORD size, DWORD addr, DWORD sec_low, DWORD sec_high );
int interctl_read_memory( BYTE mem_type, WORD size, DWORD addr, DWORD sec_low, DWORD sec_high, BYTE *pbuffer );
int interctl_usb_test_mode(int port, int mode);
int interctl_read_8051_memory( BYTE mem_type, DWORD addr, DWORD size, BYTE *pbuffer );
WORD interctl_get_DeviceID(void);

//xhci.c
int xhci_start_usb_line_test(int port, int mode);
void xhci_stop_usb_line_test(int port);


#endif

