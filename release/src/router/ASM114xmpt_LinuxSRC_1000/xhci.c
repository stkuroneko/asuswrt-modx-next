/*
 * Asmedia ASM2104 XHCI Access Functions
 *
 * Copyright (C) 2010-2012 ASMedia Technology
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
        {
            return ASMT_IO_ERROR;
        }
        result &= mask;
        if ( result == done )
        {
            return ASMT_SUCCESS;
        }
        usleep( 1*1000 );
        msec--;
    }
    while ( msec > 0 );
    return ASMT_IO_ERROR;
}

static int xhci_init( struct xhci_hcd *xhci )
{
    u32 pci_mem_addr;
    char *base;

    func_enter();
    if ( verblevel )
    {
        printf( "xHC init\n" );
    }

    if ( cur_dev==NULL )
    {
        return ASMT_IO_ERROR;
    }

    memset( xhci, 0, sizeof( struct xhci_hcd ) );

    /* Here we assume that BAR0 (offset 0x10) is of memory type...
     */
    pci_mem_addr = pci_read_long( cur_dev, 0x10 ) & PCI_BASE_ADDRESS_MEM_MASK;

    if ( verblevel )
    {
        printf( "BAR0 0x%08x\n", pci_mem_addr );
    }

    /* We now open the memory...
     */
    xhci->fd = open ( "/dev/mem", O_RDWR );



    /* ...and map the PCI memory area (man 2 mmap for more info)
     */
    base = ( char * ) mmap( NULL, PCI_MEM_LEN, PROT_READ|PROT_WRITE, MAP_SHARED, xhci->fd , ( off_t )pci_mem_addr );
    if ( verblevel )
    {
        printf( "base address  0x%08x\n", base );
    }


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
    {
        printf( "Set configure register\n" );
    }

    addr = &xhci->op_regs->config_reg;
    xhci_writel( xhci, xhci->hcs_params1 & 0x0ff, addr );
    temp = xhci_readl( xhci, addr );
    if ( verblevel )
    {
        printf( "CONGIF 0x%08x\n", temp );
    }
}

static int xhci_reset( struct xhci_hcd *xhci )
{
    int ret;
    u32 temp;

    func_enter();
    if ( verblevel )
    {
        printf( "xHC reset\n" );
    }

    temp = xhci_readl( xhci, &xhci->op_regs->status );
    if ( verblevel )
    {
        printf( "USBSTS 0x%08x\n", temp );
    }

// Host Controller Reset (HCRST)
    temp = xhci_readl( xhci, &xhci->op_regs->command );
    temp |= 0x02;
    xhci_writel( xhci, temp, &xhci->op_regs->command );

    if ( verblevel )
    {
        printf( "USBCMD 0x%08x\n", temp );
    }

//Host Controller Reset (HCRST) bit is cleared to '0' by the Host Controller when the reset process is complete
    ret = handshake( xhci, &xhci->op_regs->command, 0x02, 0, 250 );
    if ( ret < 0 )
    {
        return ASMT_IO_ERROR;
    }
//Controller Not Ready (CNR) ¡V RO. Default ='1' .'0'  = Ready and '1' = Not Ready
    ret = handshake( xhci, &xhci->op_regs->status, ( 1<<11 ), 0, 250 );
    if ( ret < 0 )
    {
       return ASMT_IO_ERROR;
    }else{
        usleep( 250*1000 );
    }

    return ASMT_SUCCESS;
}

static int xhci_halt( struct xhci_hcd *xhci )
{
    int ret = ASMT_SUCCESS;
    u32 temp;

    func_enter();
    if ( verblevel )
    {
        printf( "xHC halt\n" );
    }

    temp = xhci_readl( xhci, &xhci->op_regs->status );
    if ( verblevel )
    {
        printf( "USBSTS 0x%08x\n", temp );
    }

// Run/Stop (R/S) - RW: Default = '0'. '1' = Run.'0'= Stop
    if ( ( temp & 0x01 ) == 0 )
    {
        temp = xhci_readl( xhci, &xhci->op_regs->command );
        if ( verblevel )
       {
                printf( "USBCMD 0x%08x\n", temp );
        }

        temp &= ( u32 )~0x01;
        xhci_writel( xhci, temp, &xhci->op_regs->command );
        if ( verblevel )
        {
            printf( "USBCMD 0x%08x\n", temp );
        }

        ret = handshake( xhci, &xhci->op_regs->status, 0x01, 0x01, 2 );
    }

    return ret ;
}

static void xhci_exit( struct xhci_hcd *xhci )
{
    munmap( xhci->cap_regs, PCI_MEM_LEN );
    close( xhci->fd );
}
/*
When this bit is cleared to ¡¥0¡¦, the xHC completes the current and any actively pipelined
transactions on the USB and then halts. The xHC shall halt within 16 microframes after
software clears the Run/Stop bit. The HCHalted (HCH) bit in the USBSTS register indicates
when the xHC has finished its pending pipelined transactions and has entered the stopped
state. Software shall not write a ¡¥1¡¦ to this flag unless the xHC is in the Halted state
*/

void xhci_run(struct xhci_hcd *xhci)
{
    u32 temp;

    if (verblevel)
        printf("xHC run\n");

    temp = xhci_readl(xhci, &xhci->op_regs->command);
    if (verblevel)
        printf("USBCMD 0x%08x\n", temp);

    temp |= 0x01;
    xhci_writel(xhci, temp, &xhci->op_regs->command);
    handshake(xhci, &xhci->op_regs->status, 0x01, 0x00, 250);
    temp = xhci_readl(xhci, &xhci->op_regs->status);

    if (verblevel)
        printf("USBSTS 0x%08x\n", temp);
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
int xhci_start_usb_line_test (int port, int mode)
{
    u32 temp, *addr=0;
    int ret;
    int i;


    func_enter();
    struct xhci_hcd xhci;
    ret=xhci_init( &xhci );

     if (verblevel)
        printf("Line test start\n");

    ret=xhci_reset( &xhci );

    /* All ports shall be in the Disabled state (PP = '0') */
    for (i = 2; i < 4; i++) {
        addr = &xhci.op_regs->port_status_base + NUM_PORT_REGS * i;
        temp = xhci_readl(&xhci, addr);
        if (verblevel)
            printf("PORTSC%d 0x%08x\n", i, temp);

        temp &= ~(u32)0x200;
        xhci_writel(&xhci, temp, addr);
        temp = xhci_readl(&xhci, addr);
        if (verblevel)
            printf("PORTSC%d 0x%08x\n", i, temp);
    }

    ret = xhci_halt(&xhci);
    if (ret < 0)
        goto err_exit;

    /* Set the Port Test Control field in the port under
     * test PORTPMSC register.
     */
    addr = &xhci.op_regs->port_power_base + NUM_PORT_REGS * (port - 1);
    temp = xhci_readl(&xhci, addr);
    if (verblevel)
        printf("PORTSPMSC%d 0x%08x\n", port, temp);

    temp &= 0x0fffffff;
    temp |= (u32)mode << 28;
    xhci_writel(&xhci, temp, addr);
    temp = xhci_readl(&xhci, addr);
    if (verblevel)
        printf("PORTSPMSC%d 0x%08x\n", port, temp);

    if (mode == 3) {
        ret = interctl_usb_test_mode(port, mode);
        if (ret < 0)
            goto err_exit;

        sleep(10);
    } else if (mode == 5) {
        xhci_run(&xhci);
    }

    addr = &xhci.op_regs->port_status_base + NUM_PORT_REGS * (port - 1);
    temp = xhci_readl(&xhci, addr);
    if (verblevel)
        printf("PORTSC%d 0x%08x\n", port, temp);

    ret = ASMT_SUCCESS;

err_exit:
    return ret;
}

void xhci_stop_usb_line_test(int port)
{
    u32 temp, *addr;
    int ret;
 	func_enter();
    struct xhci_hcd xhci;
    ret=xhci_init( &xhci );
    if (verblevel)
        printf("Line test stop\n");

    addr = &xhci.op_regs->port_power_base + NUM_PORT_REGS * (port - 1);
    temp = xhci_readl(&xhci, addr);
    if (verblevel)
        printf("PORTSPMSC%d 0x%08x\n", port, temp);

    temp &= 0x0fffffff;
    xhci_writel(&xhci, temp, addr);
    temp = xhci_readl(&xhci, addr);
    if (verblevel)
        printf("PORTSPMSC%d 0x%08x\n", port, temp);

    xhci_halt(&xhci);
    xhci_reset(&xhci);
}


