/*
 * Definitions of Asmedia ASM104 Firmware Interface Access Functions
 *
 * Copyright (C) 2010-2016 ASMedia Technology
 */

#ifndef _INTERCTL_H_
#define _INTERCTL_H_

#include "typedef.h"



/**
 * \def CMD_WRITE_MEM
 * Protocol command for writing data to particular memory.
 */
#define CMD_WRITE_MEM           0x23


/**
 * \def CMD_READ_MEM
 * Protocol command for reading data from particular memory.
 */
#define CMD_READ_MEM            0x40


/**
 * \def TYPE_DATA
 * Protocol type for 8051 data memory.
 */
#define TYPE_DATA       0x01

/**
 * \def TYPE_IDATA
 * Protocol type for 8051 idata memory.
 */
#define TYPE_IDATA      0x02

/**
 * \def TYPE_XDATA
 * Protocol type for 8051 xdata memory.
 */
#define TYPE_XDATA      0x04

/**
 * \def TYPE_RAM_CODE
 * Protocol type for 8051 code memory.
 */
#define TYPE_RAM_CODE   0x08
/**
 *
 */
#define CMD_TEST_USBEYE         0x90



enum interctl_error {
 ASMT_SUCCESS                           = 0,
 ASMT_IO_ERROR                          =-1,            //Control I/O Fail
 ASMT_FWVERSION_UNMATCH                 =-2,            // FW bin is older than curr, no need to upgrade
 ASMT_UNMATCH                           =-3,            // parameter comparsion result is ummatch
 ASMT_DEVICE_NOT_FOUND                  =-4,            // Target Deives can not find
 ASMT_FILE_NOT_FOUND                    =-5,            //Target File can not find
 ASMT_SPI_VERIFY_ERROR                  =-6,            //Error when verify SPI after update config or firmware
 ASMT_RESET_FAIL                        =-7,            //Re-link Failed
 ASMT_MEMORY_ALLOCATE_ERROR             =-8,            //Error when allocate memory
 ASMT_TIMEOUT                           =-9,            //Program Time out
 ASMT_PARAMETER_INVALID                 =-10,           //Parameter Invalid
};
#endif  /* _INTERCTL_H_ */

