/*
 * Asmedia ASM114x Firmware Update Tool
 *
 * Copyright (C) 2015-2018 ASMedia Technology
 */

#include "precomp.h"


#define VERSION "V1.0.0.1"

extern struct pci_dev *cur_dev;

struct pci_dev *Selected_pci[MAX_DEVICE_CNT]= {};

int verblevel = 0;

static int do_show_version_all( void )
{
    int ret;
    struct firmware_info current;
    int devices_cnt;
    int index;
    func_enter();

    ret=do_detect_device( &devices_cnt, 0 );
    if ( ret<0 )
    {
        printf( "do_detect_device error \n" );
        ret= ASMT_DEVICE_NOT_FOUND ;
        goto err_aborted;
    }

    for ( index = 0; index < devices_cnt; index++ )
    {
        if ( DEBUG )
            { printf( "\nI'm here\n" ); }

        cur_dev=Selected_pci[index];

        printf( "%d > Bus:0x%02X Device:0x%02X Function:0x%02X\n", index + 1, cur_dev->bus, cur_dev->dev, cur_dev->func );
        printf( "Version :" );
        ret = interctl_get_version_from_code( &current );
        if ( !ret )
        {
            printf( " %02x%02x%02x_%02x_%02x_%02x\n",
                    current.version[0], current.version[1], current.version[2],
                    current.version[3], current.version[4], current.version[5] );
        }
        else
            { printf( " unknown\n" ); }

        printf( "\n" );
    }

    ret = ASMT_SUCCESS;

err_aborted:
    if ( ret )
        { printf( "\n update failed, %s (%d)\n", interctl_strerror( ret ), ret ); }
    return ret;
}

static int do_update_firmware_all( char *filename )
{
    int ret, error = 0;
    struct spi_rom_model *rom;
    struct firmware_info current, update;
    FILE *file;
    BYTE *pbuffer = NULL, *outbuf = NULL;
    DWORD file_size;
    int index;
    BOOL bOpenCFG;
    int devices_cnt;

    func_enter();

     ret=do_detect_device( &devices_cnt, 0 );
    if ( ret<0 )
    {
        ret= ASMT_DEVICE_NOT_FOUND ;
        goto err_aborted;
    }

   /* Open firmware file */
    file = fopen( filename, "rb" );
    if ( file )
    {
        /* Get file size */
        fseek( file, 0L, SEEK_END );
        file_size = ftell( file );
        fseek( file, 0L, SEEK_SET );
        /* Allocate memory to store file context */
        pbuffer = ( BYTE * )malloc( file_size + 8 );
        if ( pbuffer == NULL )
        {
            fclose( file );
            ret = ASMT_MEMORY_ALLOCATE_ERROR;
            goto err_aborted;
        }

        /* Read file content into fbuffer array */
        fread( pbuffer, 1, file_size, file );
        fclose( file );
        ret = interctl_get_version_from_file( pbuffer, &update );
        if ( ret < 0 )
        {
            goto err_aborted;
        }

        bOpenCFG =cfgctl_read_config_file();

        if (bOpenCFG==TRUE)
        {
                 if (verblevel)
                    printf("update config table\n");

                outbuf = cfgctl_update_config_table( pbuffer );
                if ( outbuf )
                {
                    free( pbuffer );
                    pbuffer = outbuf;
                }

        }
    }
    else
    {
        ret = ASMT_FILE_NOT_FOUND;
        goto err_aborted;
    }

    ret=do_detect_device( &devices_cnt, 0 );
    if ( ret<0 )
    {
        ret= ASMT_DEVICE_NOT_FOUND ;
        goto err_aborted;
    }


    for ( index = 0; index < devices_cnt; index++ )
    {
        cur_dev=Selected_pci[index];
        printf( "%d > Bus:0x%02X Device:0x%02X Function:0x%02X\n", index + 1, cur_dev->bus, cur_dev->dev, cur_dev->func );


// halt xhci...
        xhci_config();

        rom = interctl_init_spirom();
        if ( rom )
        {
            printf( "%-9s :", "Current" );
            ret = interctl_get_version_from_code( &current );
            if ( !ret )
            {
                printf( " %02x%02x%02x_%02x_%02x_%02x\n",
                        current.version[0], current.version[1], current.version[2],
                        current.version[3], current.version[4], current.version[5] );
            }
            else
                { printf( " unknown\n" ); }
        }
        else
        {
            error++;
            printf( "\n update failed, %s (%d)\n\n", interctl_strerror( ASMT_UNMATCH ), ASMT_UNMATCH );
            continue;
        }

        printf( "%-9s :", "Update to" );
        printf( " %02x%02x%02x_%02x_%02x_%02x",
                update.version[0], update.version[1], update.version[2],
                update.version[3], update.version[4], update.version[5] );
        printf( " (SVID:SSID = 0x%04x:0x%04x)\n",
                cfgctl_get_svid(), cfgctl_get_ssid() );
        printf( "Start to update firmware...\n" );


        ret = interctl_update_firmware( rom, pbuffer, file_size );
        if ( ret < 0 )
        {
            error++;
            // printf("\n update failed, %s (%d)\n", interctl_strerror(ret), ret);
            goto err_aborted;
        }

        printf( "\n" );
    }

    free( pbuffer );
    printf( "update successfully completed !!!\n" );
    ret = ( error ) ? ASMT_IO_ERROR : ASMT_SUCCESS;

    goto exit;

err_aborted:
    if ( ret < 0 )
        { printf( "\n update failed, %s (%d)\n", interctl_strerror( ret ), ret ); }

    if ( pbuffer )
        { free( pbuffer ); }

exit:

    return ret;
}

static int do_verify_firmware_all( void )
{
    int ret, error = 0;
    struct spi_rom_model *rom;
    BYTE *pbuffer = NULL;
    int index;
    int devices_cnt;
    func_enter();

    ret=do_detect_device( &devices_cnt, 0 );
    if ( ret<0 )
    {
        ret= ASMT_DEVICE_NOT_FOUND ;
        goto err_aborted;
    }

    pbuffer = ( BYTE * )malloc( 64 * 1024 );
    if ( NULL == pbuffer )
    {
        if ( verblevel )
            { printf( "Fail to alloc memory\n" ); }

        ret = ASMT_MEMORY_ALLOCATE_ERROR;
        goto err_aborted;
    }

    for ( index = 0; index < devices_cnt; index++ )
    {
        cur_dev=Selected_pci[index];
        printf( "%d > Bus:0x%02X Device:0x%02X Function:0x%02X\n", index + 1, cur_dev->bus, cur_dev->dev, cur_dev->func );

        rom = interctl_init_spirom();
        if ( NULL == rom )
        {
            error++;
            printf( "\n update failed, %s (%d)\n\n", interctl_strerror( ASMT_UNMATCH ), ASMT_UNMATCH );
            continue;
        }

        printf( "Start to verify firmware...\n" );
        ret = interctl_verify_firmware( rom, pbuffer );
        if ( ret < 0 )
        {
            error++;
            printf( "\n update failed, %s (%d)\n", interctl_strerror( ret ), ret );
        }

        printf( "\n" );
    }

    free( pbuffer );
    printf( "Verify Finished!!!\n" );
    ret = ( error ) ? ASMT_IO_ERROR : ASMT_SUCCESS;


    goto exit;

err_aborted:
    if ( ret < 0 )
        { printf( "\n update failed, %s (%d)\n", interctl_strerror( ret ), ret ); }

    if ( pbuffer )
        { free( pbuffer ); }
exit:

    return ret;
}

static int do_check_firmware_all( void )
{
    int ret, i, error = 0;
    struct firmware_info current, target;
    int index;
    int devices_cnt;
    func_enter();

    ret=do_detect_device( &devices_cnt, 0 );
    if ( ret<0 )
    {
        ret= ASMT_DEVICE_NOT_FOUND ;
        goto err_aborted;
    }

    ret = cfgctl_read_config_file();
    if ( FALSE == ret )
    {
        ret = ASMT_UNMATCH;
        goto err_aborted;
    }

    cfgctl_get_fwversion( &target );
    for ( i = 0; i < 6; i++ )
    {
        if ( target.version[i] )
            { break; }
    }

    if ( i >= 6 )
    {
        ret = ASMT_PARAMETER_INVALID;
        goto err_aborted;
    }

    for ( index = 0; index < devices_cnt; index++ )
    {
        cur_dev=Selected_pci[index];
        printf( "%d > Bus:0x%02X Device:0x%02X Function:0x%02X\n", index + 1, cur_dev->bus, cur_dev->dev, cur_dev->func );
        printf( "Start to check firmware version...\n" );
        ret = interctl_get_version_from_code( &current );
        if ( !ret )
        {
            for ( i = 0; i < 6; i++ )
            {
                if ( current.version[i] != target.version[i] )
                    { break; }
            }

            if ( i < 6 )
            {
                if ( verblevel )

                {
                    printf( "%-9s :", "Current" );
                    printf( " %02x%02x%02x_%02x_%02x_%02x\n",
                            current.version[0], current.version[1], current.version[2],
                            current.version[3], current.version[4], current.version[5] );
                    printf( "%-9s :", "Target" );
                    printf( " %02x%02x%02x_%02x_%02x_%02x\n",
                            target.version[0], target.version[1], target.version[2],
                            target.version[3], target.version[4], target.version[5] );
                }

                error++;
                printf( "FAIL!\n" );
            }
            else
            {
                printf( "PASS!\n" );
            }
        }
        else
        {
            if ( verblevel )
            {
                printf( "%-9s : unknown\n", "Current" );
                printf( "%-9s :", "Target" );
                printf( " %02x%02x%02x_%02x_%02x_%02x\n",
                        target.version[0], target.version[1], target.version[2],
                        target.version[3], target.version[4], target.version[5] );
            }

            error++;
            printf( "FAIL!\n" );
        }

        printf( "\n" );
    }

    printf( "Check Finished!!!\n" );
    ret = ( error ) ? ASMT_IO_ERROR : ASMT_SUCCESS;
    goto exit;

err_aborted:
    if ( ret < 0 )
        { printf( "\n update failed, %s (%d)\n", interctl_strerror( ret ), ret ); }
exit:
    return ret;
}

static int do_enter_test_mode( int port, int mode )
{
    int ret, error = 0;
    int index;
    int devices_cnt;
    func_enter();

    ret=do_detect_device( &devices_cnt, 0 );
    if ( ret<0 )
    {
        ret= ASMT_DEVICE_NOT_FOUND ;
        goto err_aborted;
    }

    for ( index = 0; index < devices_cnt; index++ )
    {
        cur_dev=Selected_pci[index];
        printf( "%d > Bus:0x%02X Device:0x%02X Function:0x%02X\n", index + 1, cur_dev->bus, cur_dev->dev, cur_dev->func );
        printf( "Set Enter Test Mode\n" );
// halt xhci...
        ret = xhci_enter_test_mode(port , mode);
        if ( ret<0 )
       {
           ret= ASMT_IO_ERROR;
           printf( "xhci_config failed\n" );
           goto err_aborted;
       }


        printf( "\n" );
    }

    printf( "Set Finished!!!\n" );
    ret = ( error ) ? ASMT_IO_ERROR : ASMT_SUCCESS;
    goto exit;

err_aborted:
    if ( ret < 0 )
        { printf( "\n update failed, %s (%d)\n", interctl_strerror( ret ), ret ); }
exit:
    return ret;
}

int do_update_Customer_info(char *filename)
{
    int ret=ASMT_SUCCESS, error = 0;
    struct spi_rom_model *rom;
    FILE *file;
    BYTE *pbuffer = NULL;
    DWORD file_size;
    int bus = -1, device = -1, function = -1;
    int index, devices;
    int devices_cnt;
    struct xhci_hcd xhci;
                if (verblevel)
                    printf("do_update_WD_info , %s\n", filename);


    /* Open firmware file */
    file = fopen(filename, "rb");
        if (file)
        {
                /* Get file size */
                fseek(file, 0L, SEEK_END);

                file_size = ftell(file);
                if ( file_size>256)
                {
                        fclose(file);
                        printf("Input file size too big\n");
                        ret = ASMT_PARAMETER_INVALID;
                        goto err_aborted;
                }

                fseek(file, 0L, SEEK_SET);
                /* Allocate memory to store file context */
                pbuffer = (BYTE *)malloc(file_size );
                if (pbuffer == NULL)
                {
                        fclose(file);
                        printf("Fail to alloc memory\n");
                        ret = ASMT_MEMORY_ALLOCATE_ERROR;
                        goto err_aborted;
                }

                /* Read file content into fbuffer array */
                fread(pbuffer, 1, file_size, file);
                fclose(file);

                ret=do_detect_device( &devices_cnt, 0 );
                if (ret<0 )
                {
                        ret = ASMT_DEVICE_NOT_FOUND ;
                        printf("Can not find ASMT Hosts\n");
                        goto err_aborted;
                }
        }
        else
        {
                ret = ASMT_FILE_NOT_FOUND;
                printf("Can not find firmware file:%s \n", filename);
                goto err_aborted;
        }


        for (index = 0; index < devices_cnt; index++)
        {
         cur_dev=Selected_pci[index];


        // halt xhci...

   /* ret= xhci_config();
        if ( ret<0 )
       {
           ret= ASMT_IO_ERROR;
           printf( "xhci_config failed\n" );
           goto err_aborted;
       }
*/

                rom = interctl_init_spirom();
                if (rom)
                {
                        printf("SPI ROM,  Device[%s]\n", rom->device);
                }
                else
                {
                    error++;
                    printf("\n update failed, %s (%d)\n\n", interctl_strerror(ASMT_UNMATCH), ASMT_UNMATCH);
                    continue;
                }

                printf("update host[%d] Info.....", index+1);

                ret = interctl_update_customer_info(rom, pbuffer, file_size);
                if (ret < 0)
                    {
                    error++;
                   // printf("\n update failed, %s (%d)\n", interctl_strerror(ret), ret);
                        goto err_aborted;
                }

                printf("PASS!!\n\n");
    }

err_aborted:

    if (pbuffer)
        free(pbuffer);

    return ret;
}

int do_create_fw_text_all(char *filename, DWORD dwoffset, DWORD dwSize)
{
        int ret,  error = 0;
        struct spi_rom_model *rom;
        BYTE *pbuffer = NULL;
        int bus = -1, device = -1, function = -1;
        int index, devices;
        DWORD rom_size;
        int sections;
        struct firmware_info current;
        FILE *pFile ;
        char szVersion[128];
        DWORD read_size=0;
        DWORD read_offset=0;
        int i,j;
    int devices_cnt;
    func_enter();

    ret=do_detect_device( &devices_cnt, 0 );
    if ( ret<0 )
    {
        ret= ASMT_DEVICE_NOT_FOUND ;
        goto err_aborted;
    }


    for (index = 0; index < devices_cnt; index++) {

        rom = interctl_init_spirom();
        if (NULL == rom) {
            error++;
            printf("\n update failed, %s (%d)\n\n", interctl_strerror(ASMT_UNMATCH), ASMT_UNMATCH);
            continue;
        }
            rom_size = rom->rom_size *rom->sector_size * 0x1000;
            sections = 1;
            if (rom_size >= 0x20000 && dwoffset==0)
                sections++;

                if (dwoffset==0)
                {
                        read_size = rom_size;// all rom size
                        read_offset = dwoffset;// all rom size
                }
                else
                {
                        read_size = dwSize;     // read specific size
                        read_offset =  (rom->rom_size) *rom->sector_size * 0x1000-256;  // read WD Info address
                }
                if (verblevel)
                    printf("allocate memory , read_size=%d, read_offset=%x, rom->cmd.rom_size=%x, rom size=%d\n",read_size, read_offset, rom->rom_size, rom_size);

            pbuffer = (BYTE *)malloc(read_size);
            if (NULL == pbuffer) {
                if (verblevel)
                    printf("Fail to alloc memory,read_size=%d\n",read_size);

                ret = ASMT_MEMORY_ALLOCATE_ERROR;
                goto err_aborted;
            }


        memset(pbuffer, 0, read_size);
        ret = interctl_Get_firmware(rom, read_offset, pbuffer, read_size);
        if (ret!=ASMT_SUCCESS)
        {
                printf("interctl_Get_firmware Failed\n");
                goto err_aborted;
        }

       if (verblevel)
        {
                for ( i = 0; i<16;i++)
                {
                        for ( j=0;j<17;j++)
                        {
                                printf ("%02x ", pbuffer[(i*16+j)]);
                        }
                        printf("\n");;
                }
        }
        if (dwoffset ==0)
        {
                ret = interctl_get_version_from_code(&current);
                if (ret==0) {
                    printf(" Current version is :%02x%02x%02x_%02x_%02x_%02x\n",
                           current.version[0], current.version[1], current.version[2],
                           current.version[3], current.version[4], current.version[5]);
                        sprintf(&szVersion,  " De%d_%02x%02x.bin",
                           index, current.version[4], current.version[5]);

                } else
                    printf(" unknown\n");

        }
        else
        {
                if (devices==1)
                        sprintf(&szVersion,  "%s", filename );
                else
                        sprintf(&szVersion,  "D%d_%s",index, filename );
        }

        // enable write protect
        ret = interctl_spirom_writeprotect_enable(TRUE);
        if (ret!=ASMT_SUCCESS)
        {
                printf("cinterctl_spirom_writeprotect_enable Failed\n");
                goto err_aborted;
        }
                //write buffer to file

       if (verblevel)
            printf("create file[%s], buffer sections=%d, size=%d\n", szVersion, sections, read_size);

        pFile = fopen(szVersion, "wb");
        if (pFile)
        {
                ret = fwrite((BYTE *)pbuffer,sizeof(BYTE), read_size ,pFile ) ;
                //printf("Create Finished!!!\n");
        }
        else
                 printf(" create file failed %s!!\n", szVersion);

        fclose( pFile ) ;

         free(pbuffer);
         pbuffer = NULL;
    }

        printf(" create file %s success!!\n", szVersion);



    ret = (error) ? ASMT_IO_ERROR : ASMT_SUCCESS;
    return ret;

err_aborted:
    if (ret < 0)
        printf("\n update failed, %s (%d)\n", interctl_strerror(ret), ret);

    if (pbuffer)
        free(pbuffer);

    return ret;
}
/*
 * Main function of ASM114x USB 3.0 Host Controller firmware
 * download tool.
 *
 * \param argc argument count
 * \param argv command-line arguments
 */
int main( int argc, char **argv )
{
    int c, ret=0;
    int do_update = 0, do_show = 0, do_verify = 0, do_test = 0, do_entertestmode=0, do_import=0, do_export=0;
    char *file=NULL, *w_file = NULL;
        int port=-1, all_port=0;
        int testmode=0;

    printf( "ASM114x Firmware Update Tool " VERSION "\n" );

    asm_pci_init(  );

    while ( ( c = getopt( argc, argv, ":u:U:dDvVcCtTs:S:p:P:r:R:w:W:" ) ) != -1 )
    {

       // printf( "input command is %c \r\n",c );
        switch ( c )
        {
        case 'v':
        case 'V':
            verblevel++;
            break;
                case 'r':
        case 'R':
            if (do_show || do_verify || do_test  || do_import || do_update|| do_entertestmode) {
                ret = 1;
                printf("Invalid parameter (/%c)\n", c);
                goto prog_done;
            }
                printf( "input command is %c, w_file is %s \r\n",c ,optarg);
            w_file = optarg;
            do_export = 1;
            break;
        case 'w':
        case 'W':
            if (do_show || do_verify || do_test  || do_export|| do_entertestmode) {
                ret = 1;
                printf("Invalid parameter (/%c)\n", c);
                goto prog_done;
            }

            w_file = optarg;
            do_import = 1;
            break;
        case 'u':
        case 'U':
            if ( do_show || do_verify || do_test  || do_entertestmode|| do_import|| do_export)
            {
                ret = 1;
                printf( "Invalid parameter (/%c)\n", c );
                goto prog_done;
            }

            file = optarg;
            do_update = 1;
            break;
        case 'd':
        case 'D':
            if ( do_update || do_verify || do_test  || do_entertestmode|| do_import|| do_export)
            {
                ret = 1;
                printf( "Invalid parameter (/%c)\n", c );
                goto prog_done;
            }

            do_show = 1;
            break;
        case 'c':
        case 'C':
            if ( do_update || do_show || do_test  || do_entertestmode|| do_import|| do_export)
            {
                ret = 1;
                printf( "Invalid parameter (/%c)\n", c );
                goto prog_done;
            }

            do_verify = 1;
            break;
        case 't':
        case 'T':
            if ( do_update || do_show || do_verify || do_entertestmode|| do_import|| do_export)
            {
                ret = 1;
                printf( "Invalid parameter (/%c)\n", c );
                goto prog_done;
            }

            do_test = 1;
            break;
        case 'p':
        case 'P':

            port = strtol(optarg, NULL, 10);
            if (port <= 0 || port > 3) {
                ret = 1;
                printf("Invalid parameter (%s)\n", optarg);
                goto prog_done;
            }
            else if ( port == 3)
                        all_port = 1;
            if ( verblevel )
            {
                printf( "Port number is assigned port=%d\n", port );
            }

            break;

        case 's':
        case 'S':

            if ( do_update || do_show || do_verify || do_test|| do_import|| do_export)
            {
                ret = 1;
                printf( "Invalid parameter (/%c)\n", c );
                goto prog_done;
            }
           if ( verblevel )
            {
                printf( "Test Mode !!! port=%d, optarg=%s\n", port, optarg );
            }

            do_entertestmode = 1;
           testmode = strtol(optarg, NULL, 10);
            if (testmode <= 0 || testmode > 14) {
                ret = 1;
                printf("Invalid parameter (%s)\n", optarg);
                goto prog_done;
            }

            break;
        case '?':
        default:
            goto show_usage;
        }

    }

    if ( argc == 1 )
    {
show_usage:
        ret = 0;
        printf(
                "Usage: 114XFWDL [option]...\n"
                "  -U filename\tUpdate firmware.\n"
                "  -C\t\tVerify firmware.\n"
                "  -D\t\tDisplay running firmware version.\n"
                "  -T\t\tCheck running firmware version.\n"
                "  -P\t\tSpecify port number., 3 -->port 1 & port 2\n"
                "  -S\t\tForce Enter Test Mode.\n"
                                "  -W\t\tfilename \timport Customer information in SPI-ROM \n"
                                "  -R\t\tfilename \texport Customer information in file \n");
    }
    else
    {
        if ( do_update )
        {
            ret = do_update_firmware_all( file );
            ret = ( ret < 0 ) ? 1 : 0;
        }
                else if (do_export) {
           // ret = do_create_fw_text_all(w_file, 64*1024-256, 256);
            ret = do_create_fw_text_all(w_file, 64*1024-256, 256);
            ret = (ret < 0) ? 1 : 0;
        }
                else if (do_import) {

                ret = do_update_Customer_info(w_file);
                if (ret==0)
                        printf("%-25s%s\n", "Update private data.....","PASS!!");
                else
                        printf("%-25s%s\n", "Update private data.....","FAIL!!");
                ret = (ret < 0) ? 1 : 0;



        }
        else if ( do_show )
        {
            ret = do_show_version_all();
            ret = ( ret < 0 ) ? 1 : 0;
        }
        else if ( do_verify )
        {
            ret = do_verify_firmware_all();
            ret = ( ret < 0 ) ? 1 : 0;
        }
        else if ( do_test )
        {
            ret = do_check_firmware_all();
            ret = ( ret < 0 ) ? 1 : 0;
        }
        else if ( do_entertestmode )
        {
                if (port<0 || port > 3)
                {

                        printf(" port setting  is Invalided[%d] \n", port);
                        return ASMT_PARAMETER_INVALID;
                }
            if (testmode ==0)
                {

                        printf("port[%d], Test mode is Invalided \n", testmode);
                        return ASMT_PARAMETER_INVALID;
                }

                if (all_port)
                {
                        // USB 2.0 Port 1
                    ret = do_enter_test_mode(1,testmode);
                    if (ret!=0)
                        {
                                 ret = ( ret < 0 ) ? 1 : 0;
                                printf("USB 2.0 Port 1 set test mode failed!!\n");
                                goto prog_done;
                        }

                        // USB 2.0 Port 2
                    ret = do_enter_test_mode(2,testmode);
                    if (ret!=0)
                        {
                                 ret = ( ret < 0 ) ? 1 : 0;
                                printf("USB 2.0 Port 2 set test mode failed!!\n");
                                goto prog_done;
                        }
                }
                else
                {
                    ret = do_enter_test_mode(port,testmode);
                    if (ret!=0)
                        {
                                 ret = ( ret < 0 ) ? 1 : 0;
                                printf("USB 2.0 Port [%d] set test mode failed!!\n",port );
                                goto prog_done;
                        }

                }
                ret = ( ret < 0 ) ? 1 : 0;
        }
    }

prog_done:
    asm_pci_exit();
    return ret;
}

