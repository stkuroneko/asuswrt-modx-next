/*
 * Asmedia ASM2114 XHCI Access Functions
 *
 * Copyright (C) 2015-2018 ASMedia Technology
 */

#include "precomp.h"

#define PCI_MEM_LEN (1<<12) /* This must be <= than the actual amount of PCI memory */

extern struct pci_dev *cur_dev;

static  u32 xhci_readl( const struct xhci_hcd *xhci, u32 *regs )
{
    func_enter();
    return *regs;
}

static  void xhci_writel( struct xhci_hcd *xhci, const u32 val, u32 *regs )
{
    func_enter();
    *regs = val;
}

static  int handshake( struct xhci_hcd *xhci, void *ptr, u32 mask, u32 done, int msec )
{
    u32	result;
    func_enter();

    do
    {
        result = xhci_readl( xhci, ptr );
        if ( result == ~( u32 )0 )
            { return -1; }
        result &= mask;
        if ( result == done )
            { return 0; }
        usleep( 1*1000 );
        msec--;
    }
    while ( msec > 0 );
    return -1;
}

static int xhci_init( struct xhci_hcd *xhci )
{
    u32 pci_mem_addr;
    char *base;

    func_enter();
    if ( verblevel )
        { printf( "xHC init\n" ); }

    if ( cur_dev==NULL )
        { return ASMT_DEVICE_NOT_FOUND ; }

    memset( xhci, 0, sizeof( struct xhci_hcd ) );

    /* Here we assume that BAR0 (offset 0x10) is of memory type...
     */
    pci_mem_addr = pci_read_long( cur_dev, 0x10 ) & PCI_BASE_ADDRESS_MEM_MASK;

    if ( verblevel )
        { printf( "BAR0 0x%08x\n", pci_mem_addr ); }

    /* We now open the memory...
     */
    xhci->fd = open ( "/dev/mem", O_RDWR );



    /* ...and map the PCI memory area (man 2 mmap for more info)
     */
    base = ( char * ) mmap( NULL, PCI_MEM_LEN, PROT_READ|PROT_WRITE, MAP_SHARED, xhci->fd , ( off_t )pci_mem_addr );
   if ( verblevel )
        { printf( "base address  0x%08x\n", base ); }


    xhci->cap_regs = ( struct xhci_cap_regs * )base;
    xhci->op_regs = ( struct xhci_op_regs * )( base + HC_LENGTH( xhci_readl( xhci, &xhci->cap_regs->hc_capbase ) ) );
    xhci->hcs_params1 = xhci_readl( xhci, &xhci->cap_regs->hcs_params1 );
    return ASMT_SUCCESS;
}
/*
Set Number of Device Slots (MaxSlots)
Get max slots form config register and set value to hcs_parrams1
*/
static void xhci_set_configreg( struct xhci_hcd *xhci )
{
    u32 temp, *addr;

    func_enter();
    if ( verblevel )
        { printf( "Set configure register\n" ); }

    addr = &xhci->op_regs->config_reg;
    xhci_writel( xhci, xhci->hcs_params1 & 0x0ff, addr );
    temp = xhci_readl( xhci, addr );
    if ( verblevel )
        { printf( "CONGIF 0x%08x\n", temp ); }
}

static int xhci_reset( struct xhci_hcd *xhci )
{
    int ret;
    u32 temp;

    func_enter();
    if ( verblevel )
        { printf( "xHC reset\n" ); }

    temp = xhci_readl( xhci, &xhci->op_regs->status );
    if ( verblevel )
        { printf( "USBSTS 0x%08x\n", temp ); }
// Host Controller Reset (HCRST)
    temp = xhci_readl( xhci, &xhci->op_regs->command );
    temp |= 0x02;
    xhci_writel( xhci, temp, &xhci->op_regs->command );
    if ( verblevel )
        { printf( "USBCMD 0x%08x\n", temp ); }
//Host Controller Reset (HCRST) bit is cleared to '0' by the Host Controller when the reset process is complete
    ret = handshake( xhci, &xhci->op_regs->command, 0x02, 0, 250 );
    if ( ret < 0 )
        { return ASMT_IO_ERROR; }
//Controller Not Ready (CNR) ¡V RO. Default ='1' .'0'  = Ready and '1' = Not Ready
    ret = handshake( xhci, &xhci->op_regs->status, ( 1<<11 ), 0, 250 );
    if ( ret < 0 )
        { return ASMT_IO_ERROR; }
    else
        { usleep( 250*1000 ); }

    return ASMT_SUCCESS;
}

static int xhci_halt( struct xhci_hcd *xhci )
{
    int ret = ASMT_SUCCESS;
    u32 temp;

    func_enter();
    if ( verblevel )
        { printf( "xHC halt\n" ); }

    temp = xhci_readl( xhci, &xhci->op_regs->status );
    if ( verblevel )
        { printf( "USBSTS 0x%08x\n", temp ); }
// Run/Stop (R/S) - RW: Default = '0'. '1' = Run.'0'= Stop
    if ( ( temp & 0x01 ) == 0 )
    {
        temp = xhci_readl( xhci, &xhci->op_regs->command );
        if ( verblevel )
            { printf( "USBCMD 0x%08x\n", temp ); }

        temp &= ( u32 )~0x01;
        xhci_writel( xhci, temp, &xhci->op_regs->command );
        if ( verblevel )
            { printf( "USBCMD 0x%08x\n", temp ); }

        ret = handshake( xhci, &xhci->op_regs->status, 0x01, 0x01, 2 );
    }

    return ( ret < 0 ) ? ASMT_IO_ERROR : ASMT_SUCCESS;
}

static void xhci_exit( struct xhci_hcd *xhci )
{
    munmap( xhci->cap_regs, PCI_MEM_LEN );
    close( xhci->fd );
}

int xhci_config( void )
{
    int ret;
    func_enter();
    struct xhci_hcd xhci;
    ret=xhci_init( &xhci );
    ret=xhci_reset( &xhci );
    xhci_set_configreg( &xhci );
    ret=xhci_halt( &xhci );
    xhci_exit( &xhci );
    return ret;
}


/*
The encoding of the Test Mode bits for a USB2 protocol port are:
Value Test Mode[31:28]
0 Test mode not enabled
1 Test J_STATE
2 Test K_STATE
3 Test SE0_NAK
4 Test Packet
5 Test FORCE_ENABLE */
int xhci_enter_test_mode (int port, int mode)
{
    u32 temp, *addr=0;
    int ret;
    int i;


    func_enter();
    struct xhci_hcd xhci;
    ret=xhci_init( &xhci );
    ret=xhci_reset( &xhci );
    xhci_set_configreg( &xhci );
    ret=xhci_halt( &xhci );


	// step 1: set pp[9]=0;
    addr = &xhci.op_regs->port_status_base + (4 * (port + 1));// baseaddr + 404h+(10h*(n-1))
    temp = xhci_readl( &xhci, addr );

    temp = temp &0xfffffdff;
    xhci_writel(&xhci, temp, addr);
    if (verblevel)
        printf("port_status_base=%x, read Port status pp[9]=%x, \n", (int)&xhci.op_regs->port_status_base, temp);

    if (verblevel)
        printf("usb2 xhci_enter_test_mode test, &xhci=%x, port_power_base=%x\n", &xhci, (int)&xhci.op_regs->port_power_base);


    addr = &xhci.op_regs->port_power_base + (4 * (port + 1));// baseaddr + 404h+(10h*(n-1))
    temp = xhci_readl( &xhci, addr );

    if (verblevel)
                printf("PORTMSC%d addr[0x%08x], temp[0x%08x]\n", port, (int)addr, (int)temp);



	temp = temp | (mode<<28);

    xhci_writel(&xhci, temp, addr);

    for (i=0;i<250;i++);
    temp = xhci_readl(&xhci, addr);
    if (verblevel)
                printf("PORTMSC%d addr[0x%08x], temp[0x%08x]\n", port, (int)addr, (int)temp);



    return ASMT_SUCCESS ;
}

