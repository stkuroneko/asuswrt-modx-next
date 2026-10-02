//------------------------------------------------------------------------------
// Copyright (c) 2009-2010 Atheros Corporation.  All rights reserved.
// $ATH_LICENSE_HOSTSDK0_C$
//------------------------------------------------------------------------------
//==============================================================================
// common header file for HIF modules designed for SDIO
//
// Author(s): ="Atheros"
//==============================================================================
/*
 *  Copyright (c) 2014 Qualcomm Atheros, Inc.  All rights reserved. 
 *
 *  Qualcomm is a trademark of Qualcomm Technologies Incorporated, registered in the United
 *  States and other countries.  All Qualcomm Technologies Incorporated trademarks are used with
 *  permission.  Atheros is a trademark of Qualcomm Atheros, Inc., registered in
 *  the United States and other countries.  Other products and brand names may be
 *  trademarks or registered trademarks of their respective owners. 
 */

#ifdef WIN_MOBILE7
#include <ntddk.h>
#endif

#ifndef HIF_SDIO_COMMON_H_
#define HIF_SDIO_COMMON_H_

#ifndef INLINE
#ifdef __GNUC__
#define INLINE __inline__
#else
#define INLINE __inline
#endif
#endif
    /* SDIO manufacturer ID and Codes */
#define MANUFACTURER_ID_AR6002_BASE        0x200
#define MANUFACTURER_ID_AR6003_BASE        0x300
#define MANUFACTURER_ID_AR6004_BASE        0x400
#define MANUFACTURER_ID_AR6320_BASE        0x500    /* AR6320_TBDXXX */
#define MANUFACTURER_ID_AR6K_BASE_MASK     0xFF00
#define FUNCTION_CLASS                     0x0
#define MANUFACTURER_CODE                  0x271    /* Atheros */

    /* Mailbox address in SDIO address space */
#if defined(SDIO_3_0)
#define HIF_MBOX_BASE_ADDR                 0x1000
#define HIF_DUMMY_MBOX_WIDTH               0x1000
#else
#define HIF_MBOX_BASE_ADDR                 0x800
#endif
#define HIF_MBOX_WIDTH                     0x800
#if defined(SDIO_3_0)
#define HIF_MBOX_START_ADDR(mbox)               \
   ( HIF_MBOX_BASE_ADDR + mbox * HIF_DUMMY_MBOX_WIDTH)
#else
#define HIF_MBOX_START_ADDR(mbox)               \
   ( HIF_MBOX_BASE_ADDR + mbox * HIF_MBOX_WIDTH)
#endif

#define HIF_MBOX_END_ADDR(mbox)                 \
    (HIF_MBOX_START_ADDR(mbox) + HIF_MBOX_WIDTH - 1)

    /* extended MBOX address for larger MBOX writes to MBOX 0*/
#if defined(SDIO_3_0)
#define HIF_MBOX0_EXTENDED_BASE_ADDR       0x5000
#else
#define HIF_MBOX0_EXTENDED_BASE_ADDR       0x2800
#endif
#define HIF_MBOX0_EXTENDED_WIDTH_AR6002    (6*1024)
#define HIF_MBOX0_EXTENDED_WIDTH_AR6003    (18*1024)

    /* version 1 of the chip has only a 12K extended mbox range */
#define HIF_MBOX0_EXTENDED_BASE_ADDR_AR6003_V1  0x4000
#define HIF_MBOX0_EXTENDED_WIDTH_AR6003_V1      (12*1024)

#define HIF_MBOX0_EXTENDED_BASE_ADDR_AR6004     0x2800
#define HIF_MBOX0_EXTENDED_WIDTH_AR6004         (18*1024)

#if defined(SDIO_3_0)
#define HIF_MBOX0_EXTENDED_BASE_ADDR_AR6320     0x5000
#else
#define HIF_MBOX0_EXTENDED_BASE_ADDR_AR6320     0x2800
#endif
#define HIF_MBOX0_EXTENDED_WIDTH_AR6320         (24*1024)

    /* GMBOX addresses */
#define HIF_GMBOX_BASE_ADDR                0x7000
#define HIF_GMBOX_WIDTH                    0x4000

    /* for SDIO we recommend a 128-byte block size */
#define HIF_DEFAULT_IO_BLOCK_SIZE          128

    /* set extended MBOX window information for SDIO interconnects */
static INLINE void SetExtendedMboxWindowInfo(A_UINT16 Manfid, HIF_DEVICE_MBOX_INFO *pInfo)
{
    switch (Manfid & MANUFACTURER_ID_AR6K_BASE_MASK) {
        case MANUFACTURER_ID_AR6002_BASE :
                /* MBOX 0 has an extended range */
            
            /**** FIXME .. AR6004 currently masquerades as an AR6002 device 
             * and thus it's actual extended window size will be incorrectly
             * set.  Temporarily force the location and size to match AR6004 ****/
            //pInfo->MboxProp[0].ExtendedAddress = HIF_MBOX0_EXTENDED_BASE_ADDR;
            //pInfo->MboxProp[0].ExtendedSize = HIF_MBOX0_EXTENDED_WIDTH_AR6002;
            
            pInfo->MboxProp[0].ExtendedAddress = HIF_MBOX0_EXTENDED_BASE_ADDR_AR6003_V1;             
            pInfo->MboxProp[0].ExtendedSize = HIF_MBOX0_EXTENDED_WIDTH_AR6003_V1;

            pInfo->MboxProp[0].ExtendedAddress = HIF_MBOX0_EXTENDED_BASE_ADDR_AR6003_V1;
            pInfo->MboxProp[0].ExtendedSize = HIF_MBOX0_EXTENDED_WIDTH_AR6003_V1;
            
            pInfo->MboxProp[0].ExtendedAddress = HIF_MBOX0_EXTENDED_BASE_ADDR_AR6004;             
            pInfo->MboxProp[0].ExtendedSize = HIF_MBOX0_EXTENDED_WIDTH_AR6004;

            break;
        case MANUFACTURER_ID_AR6003_BASE :
                /* MBOX 0 has an extended range */
            pInfo->MboxProp[0].ExtendedAddress = HIF_MBOX0_EXTENDED_BASE_ADDR_AR6003_V1;
            pInfo->MboxProp[0].ExtendedSize = HIF_MBOX0_EXTENDED_WIDTH_AR6003_V1;
            pInfo->GMboxAddress = HIF_GMBOX_BASE_ADDR;
            pInfo->GMboxSize = HIF_GMBOX_WIDTH;
            break;
        case MANUFACTURER_ID_AR6004_BASE :
            pInfo->MboxProp[0].ExtendedAddress = HIF_MBOX0_EXTENDED_BASE_ADDR_AR6004;
            pInfo->MboxProp[0].ExtendedSize = HIF_MBOX0_EXTENDED_WIDTH_AR6004;
            pInfo->GMboxAddress = HIF_GMBOX_BASE_ADDR;
            pInfo->GMboxSize = HIF_GMBOX_WIDTH;
            break;
        case MANUFACTURER_ID_AR6320_BASE :
                /* AR6320_TBDXXX */
            pInfo->MboxProp[0].ExtendedAddress = HIF_MBOX0_EXTENDED_BASE_ADDR_AR6320;
            pInfo->MboxProp[0].ExtendedSize = HIF_MBOX0_EXTENDED_WIDTH_AR6320;
            pInfo->GMboxAddress = HIF_GMBOX_BASE_ADDR;
            pInfo->GMboxSize = HIF_GMBOX_WIDTH;
            break;            
        default:
            A_ASSERT(FALSE);
            break;
    }
}

/*
  In SDIO 2.0, asynchronous interrupt is not in SPEC requirement, but AR6003 support it, so the register
  is placed in vendor specific field 0xF0(bit0)
  In SDIO 3.0, the register is defined in SPEC, and its address is 0x16(bit1)
*/

#define CCCR_SDIO_IRQ_MODE_REG_AR6003         0xF0        /* interrupt mode register of AR6003*/
#define SDIO_IRQ_MODE_ASYNC_4BIT_IRQ_AR6003   (1 << 0)    /* mode to enable special 4-bit interrupt assertion without clock*/

#define CCCR_SDIO_IRQ_MODE_REG_AR6320           0x16        /* interrupt mode register of AR6320*/
#define SDIO_IRQ_MODE_ASYNC_4BIT_IRQ_AR6320     (1 << 1)    /* mode to enable special 4-bit interrupt assertion without clock*/

#endif /*HIF_SDIO_COMMON_H_*/
