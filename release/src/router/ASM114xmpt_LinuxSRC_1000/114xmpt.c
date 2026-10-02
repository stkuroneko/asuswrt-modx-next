/*
 * ASMedia ASM114x USB Signal Check Tool
 *
 * Copyright (C) 2014-2016 ASMedia Technology
 */

#include "precomp.h"

#define VERSION "V1.0.0.0"

extern struct pci_dev *cur_dev;

struct pci_dev *Selected_pci[MAX_DEVICE_CNT]= {};

int verblevel = 0;

#define CHIPTYPE_ADDR           0xF38C
#define CHIPTYPE214_ADDR        0x1508C

#define Port1_CMPLTST           0xF201
#define Port2_CMPLTST           0xF281
#define ADDR_IRINTE             0xF030

#define LOOPBACK_SET_EQ_LOOP 	9U
#define LOOPBACK_RETRY          10U
#define LOOPBACK31_CHECK        500U


#define Port1_214CMPLTST           0x19201
#define Port2_214CMPLTST           0x1A201
//==========================================================================
//  Local App           :  get_chip_Type_xmpt
//  Des                 :
//  Input               :
//  Do                  :
//  Return              :
//==========================================================================
int get_chip_Type_xmpt( BYTE* ChipType)
{
    BYTE reg;
    WORD DeviceID;
    int ret = ASMT_SUCCESS;
    DeviceID = interctl_get_DeviceID();
        if((DeviceID ==ASM2114_DEVICE_ID)||(DeviceID ==ASM21141_DEVICE_ID)||(DeviceID ==ASM21142_DEVICE_ID))
        {
            *ChipType = Device_114;

            if (verblevel)
                printf("chip 114[%X]\n",DeviceID);

            ret = interctl_read_8051_memory(TYPE_XDATA, CHIPTYPE_ADDR, 1, &reg);

            if (verblevel)
                printf("CHIPTYPE_ADDR=%x\n", reg);

        }else if((DeviceID ==ASM2142_DEVICE_ID)||(DeviceID ==ASM2142CM_DEVICE_ID))
        {
            *ChipType = Device_214;

            if (verblevel)
                printf("chip 214[%X]\n",DeviceID);
            ret = interctl_read_8051_memory(TYPE_XDATA, CHIPTYPE214_ADDR, 1, &reg);

            if (verblevel)
                printf("CHIPTYPE_ADDR=%x\n", reg);
        }
        #ifdef ASM1142WITH1143
        else if((DeviceID ==AMD3102_DEVICE_ID)||(DeviceID ==AMD1343_DEVICE_ID))
        {
            *ChipType = Device_114;

            if (verblevel)
                printf("chip 114[%X]\n",DeviceID);

            ret = interctl_read_8051_memory(TYPE_XDATA, CHIPTYPE_ADDR, 1, &reg);

            if (verblevel)
                printf("CHIPTYPE_ADDR=%x\n", reg);

        }
        #endif
        else
        {
            *ChipType = 0xFF;

            if (verblevel)
                printf("unsupport DeviceID [%X]\n",DeviceID);
        }



       return ret;
}
/*
 *
 */
static int do_compliance(int port)
{
    int ret = ASMT_SUCCESS;
    int index;
     unsigned char OrginalValue,tmp,allport,IRINTEValue;
    DWORD addr;
    BYTE ChipType;
    int devices_cnt;
   /* if (port < 0 ) {
        ret = ASMT_PARAMETER_INVALID;
        printf("Please specify (/P) option.\n");
        goto err_exit;
    }*/
    allport = 0;
    ret=do_detect_device( &devices_cnt, 0 );
    if ( ret<0 )
    {
        ret= ASMT_DEVICE_NOT_FOUND ;
        goto err_exit;
    }

      for (index = 0; index < devices_cnt; index++) {
    cur_dev=Selected_pci[index];
        printf( "%d > Bus:0x%02X Device:0x%02X Function:0x%02X\n", index + 1, cur_dev->bus, cur_dev->dev, cur_dev->func );
    ChipType = Device_114;
    #ifndef AMD_TOOL_1143
    ret = get_chip_Type_xmpt(&ChipType);
    #endif
    switch(port)
    {
        case 1:
            if(ChipType == Device_114)
            {
            addr = Port1_CMPLTST;
            }else if(ChipType == Device_214)
            {
                addr = Port1_214CMPLTST;
            }
              if (verblevel)
                printf("PORT 1 selected");
            break;
        case 2:
            if(ChipType == Device_114)
            {
                addr = Port2_CMPLTST;
            }else if(ChipType == Device_214)
            {
                addr = Port2_214CMPLTST;
            }

             if (verblevel)
                printf("PORT 2 selected");
            break;
         default:
            allport = 1;
            if(ChipType == Device_114)
            {
            addr = Port1_CMPLTST;
            }else if(ChipType == Device_214)
            {
                addr = Port1_214CMPLTST;
            }
            break;

    }
lb_do_again:

     ret =interctl_read_memory(TYPE_XDATA, 1,addr, 0, 0,&OrginalValue );

     if (verblevel)
         printf("Readaddr[0x%X][0x%X]\n",addr,OrginalValue);

    if(ret <0)
      goto err_exit;

    tmp = OrginalValue|0x20;
         ret = interctl_write_command(CMD_WRITE_MEM, TYPE_XDATA, 1,addr  , tmp,0 );

     if (verblevel)
         printf("Write addr[0x%X][0x%X]\n",addr,tmp);

     if(ret <0)
      goto err_exit;
   /* printf("\n\n\n==============Enable USB3.1 Compliance Test Mode==============\n\n");
     printf("Press Any Key to finish Compliance Test ");
     if(addr == Port1_CMPLTST){
      printf("Port 1==>");
     }else
     {
        printf("Port 2==>");
     }
     getche();
    tmp = OrginalValue;
         ret = interctl_write_command(CMD_WRITE_MEM, TYPE_XDATA, 1,addr  , tmp,0 );
     if (verblevel)
         printf("Write addr[0x%X][0x%X]\n",addr,tmp);
    printf("\n======================= Finshed =======================\n");
*/

  if(allport ){
    allport = 0;
    if(ChipType == Device_114)
    {
        addr = Port2_CMPLTST;
    }else if(ChipType == Device_214)
    {
        addr = Port2_214CMPLTST;
    }
    goto lb_do_again;
  }
    ret =interctl_read_memory(TYPE_XDATA, 1,ADDR_IRINTE, 0, 0,&IRINTEValue );

    if (verblevel)
         printf("Readaddr[0x%X][0x%X]\n",ADDR_IRINTE,IRINTEValue);

    if(ret <0)
      goto err_exit;

    tmp = IRINTEValue|0x04;
    ret = interctl_write_command(CMD_WRITE_MEM, TYPE_XDATA, 1,ADDR_IRINTE, tmp,0 );

     if (verblevel)
         printf("Write addr[0x%X][0x%X]\n",ADDR_IRINTE,tmp);

    printf("\n\nEnable USB3.1 Compliance Test Mode\n\n\n");
      }
err_exit:
    return ret;
}
/*
 *
 */
static int do_enter_test_mode(int mode ,int port  )
{
    int ret = ASMT_SUCCESS, error = 0;
    int index , real_port , c;
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
        printf( "Set Enter Test Mode,port[%x],mode[%X]\n",port,mode );
        real_port = port + 2;
// halt xhci...
        ret = xhci_start_usb_line_test(real_port, mode);
        if (ret < 0)
            goto err_aborted;

        printf("Press ENTER key to stop ...");

        do {
            c = getchar();
        } while (c != '\n');

        xhci_stop_usb_line_test(real_port);
        printf("Test Mode stopped.\n");

        printf( "\n" );
    }


    ret = ( error ) ? ASMT_IO_ERROR : ASMT_SUCCESS;
    goto exit;

err_aborted:
    if ( ret < 0 )
    {
        printf( "\n update failed,  (%d)\n",  ret );
    }
exit:
    return ret;
}

/*
 * Main function of ASM104x USB 3.0 Host Controller firmware
 * download tool.
 *
 * \param argc argument count
 * \param argv command-line arguments
 */
int main( int argc, char **argv )
{
    int c, ret=0;
    int port = -1, testmode = -1,  all_port=0;

    int  do_testmode = 0, do_complianceTest;


    printf( "ASM114x Setting Tool " VERSION "\n" );

    asm_pci_init(  );

    while ( ( c = getopt( argc, argv, "vVm:M:p:P:iI" ) ) != -1 )
    {

       // printf( "input command is %c \r\n",c );
        switch ( c )
        {
        case 'v':
        case 'V':
            verblevel++;
            break;
        case 'i':
        case 'I':
            if ( do_testmode ) {
                ret = 1;
                printf("Invalid parameter (/%c)\n", c);
                goto prog_done;
            }

            do_complianceTest= 1;
            break;
        case 'm':
        case 'M':

            testmode = strtol(optarg, NULL, 10);
            if (testmode <= 0 || testmode > 5) {
                ret = 1;
                printf("Invalid parameter (%s)\n", optarg);
                goto prog_done;
            }

            do_testmode = 1;
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

            break;
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
        printf("ASM114x USB Signal Check Tool " VERSION "\n"
                "Usage: 114xmpt [option]...\n"
				"  -M [Mode]\t\t\t\t \n"
				"  -I \t\t\t\t\t Enter Compliance Test Mode\n"
				"  -P [Port]\t\t\t\t Specify target USB port. (valid value is 1 or 3)\n"
		 		);
    }
    else
    {
        if (do_testmode)
        {
            if (all_port==1)
            {
                    ret =  do_enter_test_mode(testmode, 1);
                    if (ret<0)
                    {
                             return ret;
                    }
                    printf("\n");

                    sleep(100);
                    ret =  do_enter_test_mode(testmode, 2);
                    if (ret<0)
                    {
                             return ret;
                    }
            }
            else
                ret = do_enter_test_mode(testmode, port);
       // ret = (ret < 0) ? 1 : 0;
        }else if (do_complianceTest) {
            ret = do_compliance(port);
          //  ret = (ret < 0) ? 1 : 0;
        }
    }

prog_done:
    asm_pci_exit();
    return ret;
}

