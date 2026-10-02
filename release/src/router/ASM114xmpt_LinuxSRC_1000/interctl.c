/*
 * Asmedia ASM2104 Firmware Interface Access Functions
 *
 * Copyright (C) 2010-2012 ASMedia Technology
 */

/**
 * \defgroup interctl Firmware Interface access API
 * This page documents 104xust's API for firmware interface
 * access functions.
 */

#include "precomp.h"

struct pci_dev *cur_dev = NULL;


/*
 * Wait write ready.
 *
 * \return ASMT_SUCCESS on success
 * \return ASMT_TIMEOUT if write timeout
 */
static int wait_write_ready( void )
{
    int ret;
    BYTE value;
    clock_t start_time, end_time;
    unsigned long pass_time;
    BYTE retry = 0;


    if ( cur_dev == NULL )
    {
        ret = ASMT_PARAMETER_INVALID;
        goto err_exit;
    }

    start_time = clock();

    /*
     * Wait to xHCI receive data.
     * If xHCI is ready, CONTROL_WRITE_BIT will be clear(0).
     */
    while ( 1 )
    {
        value = pci_read_byte( cur_dev, CONTROL_REG );
        if ( value == 0xff )
        {
            ret = ASMT_IO_ERROR;
            printf( "wait_write_ready!!, ret = ASMT_IO_ERROR, value[%x]\n",value );
	    if (retry > 3)
            break;
        }
        else if ( ( value & CONTROL_WRITE_BIT ) == 0 )
        {
            ret = ASMT_SUCCESS;
            break;
        }

        end_time = clock();
        pass_time = ( end_time - start_time ) / CLOCKS_PER_SEC ;
        if ( pass_time > 2 )    /* If 2 seconds exceeded, return fail */
        {
            ret = ASMT_TIMEOUT;
            printf( "wait_write_ready!!, ret = ASMT_TIMEOUT, value[%x]\n",value );
            break;
        }
	retry++;
    }

err_exit:
    return ret;
}

/*
 * Wait read ready.
 *
 * \return ASMT_SUCCESS on success
 * \return ASMT_TIMEOUT if read timeout
 */
static int wait_read_ready( void )
{
    int ret;
    BYTE value;
    clock_t start_time, end_time;
    unsigned long pass_time;

    if ( cur_dev == NULL )
    {
        ret = ASMT_PARAMETER_INVALID;
        goto err_exit;
    }

    start_time = clock();

    /* Wait for data ready */
    while ( 1 )
    {
        value = pci_read_byte( cur_dev, CONTROL_REG );
        if ( value == 0xff )
        {
            ret = ASMT_IO_ERROR;
            break;
        }
        else if ( ( value & CONTROL_READ_BIT ) == CONTROL_READ_BIT )
        {
            ret = ASMT_SUCCESS;
            break;
        }

        end_time = clock();
        pass_time = ( end_time - start_time ) / CLOCKS_PER_SEC;
        if ( pass_time > 2 )    /* If 2 seconds exceeded, return fail */
        {
            ret = ASMT_TIMEOUT;
            break;
        }
    }

err_exit:
    return ret;
}
int interctl_write_command( BYTE cmd, BYTE mem_type, WORD size,
                                   DWORD addr, DWORD sec_low, DWORD sec_high )
{
    int ret;
    DWORD value_low, value_high;

    if ( cur_dev == NULL )
    {
        ret = ASMT_PARAMETER_INVALID;
        goto err_exit;
    }

    /* Send Read command to xHC */
    ret = wait_write_ready();
    if ( ret < 0 )
        {
		printf("(write before)wait_write_ready failed\n");
		goto err_exit;
	 }

    /* Send first 8 bytes */
    value_low = cmd | ( ( DWORD )mem_type << 8 ) | ( ( DWORD )size << 16 );
    value_high = addr;
    pci_write_long( cur_dev, DATA_WRITE0_REG, value_low );
    pci_write_long( cur_dev, DATA_WRITE1_REG, value_high );

    /* Write 1 to CONTROL_WRITE_BIT, inform xHCI to get data */
    pci_write_byte( cur_dev, CONTROL_REG, CONTROL_WRITE_BIT );

    ret = wait_write_ready();
    if ( ret < 0 )
        {
		printf("wait_write_ready(first 8 bytes) failed\n");
		goto err_exit;
	 }

    /* Send second 8 bytes */
    pci_write_long( cur_dev, DATA_WRITE0_REG, sec_low );
    pci_write_long( cur_dev, DATA_WRITE1_REG, sec_high );

    /* Write 1 to CONTROL_WRITE_BIT, inform xHCI to get data */
    pci_write_byte( cur_dev, CONTROL_REG, CONTROL_WRITE_BIT );
    ret = ASMT_SUCCESS;

err_exit:
    return ret;
}

/*

 * \param pbuffer buffer to store read data
 * \return ASMT_SUCCESS on transfer OK
 * \return negative if transfer fail
 */
int interctl_read_memory( BYTE mem_type, WORD size, DWORD addr,
                                 DWORD sec_low, DWORD sec_high, BYTE *pbuffer )
{
    int ret;
    BYTE temp[8];
    WORD i;

    if ( cur_dev == NULL )
    {
        ret = ASMT_PARAMETER_INVALID;
        goto err_exit;
    }

    if ( size > 8 )
    {
        ret = ASMT_PARAMETER_INVALID;
        goto err_exit;
    }

    ret = interctl_write_command( CMD_READ_MEM, mem_type, size, addr, sec_low, sec_high );
    if ( ret < 0 )
        { goto err_exit; }

    /* Read data from xHC */
    ret = wait_read_ready();
    if ( ret < 0 )
        { goto err_exit; }

    /* Read first 8 bytes (dummy) */
    *( ( DWORD * )temp ) = pci_read_long( cur_dev, DATA_READ0_REG );
    *( ( DWORD * )( temp + 4 ) ) = pci_read_long( cur_dev, DATA_READ1_REG );
    /* Clear ready bit (RW1C) */
    pci_write_byte( cur_dev, CONTROL_REG, CONTROL_READ_BIT );

    ret = wait_read_ready();
    if ( ret < 0 )
        { goto err_exit; }

    /* Read second 8 bytes (real) */
    if ( size == 8 )
    {
        *( ( DWORD * )pbuffer ) = pci_read_long( cur_dev, DATA_READ0_REG );
        *( ( DWORD * )( pbuffer + 4 ) ) = pci_read_long( cur_dev, DATA_READ1_REG );
    }
    else
    {
        for ( i = 0; i < size; i++ )
            { pbuffer[i] = pci_read_byte( cur_dev, DATA_READ0_REG + i ); }
    }
    /* Clear ready bit (RW1C) */
    pci_write_byte( cur_dev, CONTROL_REG, CONTROL_READ_BIT );
    ret = ASMT_SUCCESS;

err_exit:
    return ret;
}


/**
 *
 */
int interctl_usb_test_mode(int port, int mode)
{
    int ret;
    DWORD sec_low;

    sec_low = ((DWORD)mode << 8) | port;
    ret = interctl_write_command(CMD_TEST_USBEYE, TYPE_XDATA, 2, 0, sec_low, 0);
    if (ret < 0)
        goto err_exit;

    ret = ASMT_SUCCESS;

err_exit:
    return ret;
}
/**
 * \ingroup interctl
 * Inform ASM2114 starting to read 8051 memory.
 *
 * \param mem_type memory type
 * \param addr offset of read address
 * \param size buffer size
 * \param pbuffer data buffer
 * \return ASMT_SUCCESS on success
 * \return negative if transfer fail
 */
int interctl_read_8051_memory( BYTE mem_type, DWORD addr, DWORD size, BYTE *pbuffer )
{
    int ret = ASMT_PARAMETER_INVALID;
    WORD read_size;
    DWORD done_size;
    func_enter();

    if ( mem_type != TYPE_DATA &&
            mem_type != TYPE_IDATA &&
            mem_type != TYPE_XDATA &&
            mem_type != TYPE_RAM_CODE )
        { goto err_exit; }

    done_size = 0;
    read_size = ( size < 8 ) ? size : 8;
    while ( done_size < size )
    {
        ret = interctl_read_memory( mem_type, read_size, done_size + addr, 0, 0, pbuffer );
        if ( ret < 0 )
            { goto err_exit; }

        done_size += read_size;
        pbuffer += read_size;
        if ( ( size - done_size ) < 8 )
            { read_size = size - done_size; }
    }

    ret = ASMT_SUCCESS;

err_exit:
    return ret;
}

/**
 *
 */
WORD interctl_get_DeviceID(void)
{
    return   pci_read_word( cur_dev, 0x02 );
}


