/*
 * PCI relative functions
 *
 * Copyright (C) 2010-2016 ASMedia Technology
 */

/**
 * \defgroup pci PCI configuration space access API
 * This page documents 104's API for PCI device I/O.
 */

#include "precomp.h"

extern struct pci_dev *cur_dev;
extern struct pci_dev *Selected_pci[MAX_DEVICE_CNT];


static struct pci_access *pacc;
static struct asm_pci_id asm114_id_list[]=
{
    {ASM2114_VENDOR_ID, ASM2114_DEVICE_ID},
    {ASM2114_VENDOR_ID, ASM21141_DEVICE_ID},
    {ASM2114_VENDOR_ID, ASM21142_DEVICE_ID},
    {0,0}
};



int asm_pci_init( void )
{

    struct pci_dev *dev;


#if 0
    /* Check IO permissions to be able to open /dev/mem
     */
    if ( iopl( 3 ) )
    {
        printf( "Cannot get I/O permissions (being root helps)\n" );
        return -1;
    }
#endif


    /* Scan the PCI bus, and find the device we want
     */
    pacc = pci_alloc(); /* Allocate memory for all_devices */
    pci_init( pacc );   /* Initialisation of all_devices   */
    pci_scan_bus( pacc ); /* Scan the PCI bus(es)         */


    for ( dev = pacc->devices; dev; dev = dev->next )
    {
        pci_fill_info( dev, PCI_FILL_IDENT | PCI_FILL_BASES | PCI_FILL_CLASS );	/* Fill in header info we need */
    }


    return 0;
}

void asm_pci_exit( void )
{

    pci_cleanup( pacc );		 /* Close everything */
}



/*
*bug cnt gt MAX_DEVICE_CNT
*
*/



static int asm_select_devices( void )
{
    struct pci_dev *dev;

    int cnt = 0,i;

    for ( i=0;; i++ )
    {
        if ( asm114_id_list[i].vid==0 )
            { break; }

        for ( dev=pacc->devices; dev; dev=dev->next )
            if ( ( asm114_id_list[i].pid== dev->device_id ) &&
                    ( asm114_id_list[i].vid== dev->vendor_id ) )
            {
                Selected_pci[cnt]=dev;
                cnt++;
            }
    }

    if ( cnt==0 )
    {
        printf( "Cannot found device\n" );
    }

    return cnt;
}

/**
 * \mainpage ASM104x firmware download tool
 * \section intro Introdution
 * 104xfwdl is a tool that allow you to download firmware to
 * ASM104x's external SPI ROM.
 */

/*
 *
 */
int do_detect_device( int *devices_cnt, int display )
{
    int i,  index, ret;

    index = ASMT_DEVICE_NOT_FOUND;

    *devices_cnt= asm_select_devices( );
    if ( *devices_cnt==0 )
    {
        printf( "cannot found the device" );
        return -1;
    }  // not found any asm114
    if ( display )
        { printf( "Detect ASM114x\n" ); }
    for ( i = 0; i < *devices_cnt; i++ )
    {

        cur_dev=Selected_pci[i];
        if ( DEBUG&&cur_dev )
            printf( "\n%d >  ASM114 Bus:0x%02X Device:0x%02X Function:0x%02X\n",
                    i+1, cur_dev->bus,cur_dev->dev,cur_dev->func );
        if ( display )
            printf( "%d >  ASM114 Bus:0x%02X Device:0x%02X Function:0x%02X\n",
                    i+1, cur_dev->bus,cur_dev->dev,cur_dev->func );

    }
    return 0;
}


