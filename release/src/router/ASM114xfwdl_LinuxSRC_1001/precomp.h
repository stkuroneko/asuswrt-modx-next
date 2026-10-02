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
#include "xhci.h"
#include "pci.h"
#include "interctl.h"
#include "config.h"
#include "asm2114.h"

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

/**
 * A structure representing firmware information.
 */
struct firmware_info
{
    /** Firmware version  */
    BYTE version[6];
};
//pci.c
int asm_pci_init( void );
void asm_pci_exit( void );
int do_detect_device( int *devices_cnt, int display );

//xhci.c
int xhci_config( void );
int xhci_enter_test_mode (int port, int mode);

//interctl.c
char *interctl_strerror( int errnum );
struct spi_rom_model *interctl_init_spirom( void );
int interctl_update_firmware( struct spi_rom_model *rom, BYTE *pbuffer, DWORD size );
int interctl_verify_firmware( struct spi_rom_model *rom, BYTE *pbuffer );
int interctl_get_version_from_file( BYTE *pbuffer, struct firmware_info *info );
int interctl_read_8051_memory( BYTE mem_type, DWORD addr, DWORD size, BYTE *pbuffer );
int interctl_get_version_from_code( struct firmware_info *info );
int interctl_Get_firmware(struct spi_rom_model *rom, DWORD offset, BYTE *pbuffer, DWORD dwSize);
int interctl_update_customer_info(struct spi_rom_model *rom, BYTE *pbuffer, DWORD size);

//config.c
void crc32_init( void );
DWORD get_crc32( BYTE *buffer, DWORD size );
BOOL cfgctl_read_config_file( void );
BYTE *cfgctl_update_config_table( const BYTE *inbuf );
WORD cfgctl_get_svid( void );
WORD cfgctl_get_ssid( void );
void cfgctl_get_fwversion( void *info );

#endif

