/*
 * Definitions of Asmedia ASM2114 Firmware Interface Access Functions
 *
 * Copyright (C) 2015-2018 ASMedia Technology
 */

#ifndef _INTERCTL_H_
#define _INTERCTL_H_

#include "typedef.h"

/** \addtogroup interctl */
/*@{*/
/**
 * \def CMD_ERASE_SPI
 * Protocol command for sending SPI ROM erase command.
 */
#define CMD_ERASE_SPI           0x10

/**
 * \def CMD_WRITE_SPI_START
 * Protocol command for starting to write data to SPI ROM.
 */
#define CMD_WRITE_SPI_START     0x11

/**
 * \def DEF_PCIE_CMD_WRITE_CMD
 * For write single byte command , WREN
 */
#define DEF_PCIE_CMD_WRITE_CMD  0x19

/**
 * \def DEF_PCIE_CMD_SET_SPI_CLOCK
 * set SPI clock
 */
#define DEF_PCIE_CMD_SET_SPI_CLOCK  0x1A

/**
 * \def DEF_PCIE_CMD_SET_SPI_PAGESIZE
 * set page write buffer length
 */
#define DEF_PCIE_CMD_SET_SPI_PAGESIZE   0x1B

/**
 * \def DEF_PCIE_CMD_WRITE_ROM_STATUS
 * 2 byte command for write staus
 */
#define DEF_PCIE_CMD_WRITE_ROM_STATUS   0x1C

/**
 * \def CMD_WRITE_SST_SPI_START
 * Protocol command for starting to write data to SST SPI ROM.
 */
#define CMD_WRITE_SST_SPI_START     0x1D

/**
 * \def CMD_LOOP
 * Protocol command for continuing to write data to SPI ROM.
 */
#define CMD_LOOP                0x1E

/**
 * \def CMD_END
 * Protocol command for ending to write data to SPI ROM.
 */
#define CMD_END                 0x1F

/**
 * \def CMD_JUMP_FIXED_CODE
 * Protocol command for jumping to fixed code.
 */
#define CMD_JUMP_FIXED_CODE     0x21

/**
 * \def CMD_WRITE_MEM
 * Protocol command for writing data to particular memory.
 */
#define CMD_WRITE_MEM           0x23

/**
 * \def CMD_WRITE_CODE
 * Protocol command for writing data to program memory.
 */
#define CMD_WRITE_CODE          0x25

/**
 * \def CMD_ERASE_SPI_SECTOR
 * Protocol command for sending SPI ROM sector erase command.
 */
#define CMD_ERASE_SPI_SECTOR    0x30

/**
 * \def CMD_READ_MEM
 * Protocol command for reading data from particular memory.
 */
#define CMD_READ_MEM            0x40

/**
 *
 */
#define CMD_TEST_USBLINE        0x80

/**
 *
 */
#define CMD_TEST_USBEYE         0x90

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
 * \def TYPE_SPI
 * Protocol type for SPI ROM.
 */
#define TYPE_SPI        0x10

/**
 * \def TYPE_SPIID
 * Protocol type for SPI ROM ID.
 */
#define TYPE_SPIID      0x20

/**
 * \def TYPE_SPI_OFFSET
 * Protocol type for SPI ROM offset.
 */
#define TYPE_SPI_OFFSET 0x30

/**
 *
 */
#define TYPE_READ_USBTEST_RTN   0x81

/**
 * \def SPI_CLOCK_1MHz
 * SPI clock is 1Mhz when crystal clock = xxMhz
 */
#define SPI_CLOCK_1MHz   0x38

/**
 * \def SPI_CLOCK_2MHz
 * SPI clock is 2Mhz when crystal clock = xxMhz
 */
#define SPI_CLOCK_2MHz  0x1C

/**
 * \def SPI_CLOCK_10MHz
 * SPI clock is 10Mhz when crystal clock = xxMhz
 */
#define SPI_CLOCK_10MHz 0x06

/**
 * \def SPI_CLOCK_20MHz
 * SPI clock is 20Mhz when crystal clock = xxMhz
 */
#define SPI_CLOCK_20MHz 0x03

/**
 * \def SPI_Instruction_WREN
 * Write Enable Command
 */
#define SPI_Instruction_WREN    0x06

/**
 * \def SPI_Instruction_WRDI)
 * Write Disable Command
 */
#define SPI_Instruction_WRDI    0x04
/**
 * \def SPI_Instruction_WRSR
 * Write Status Register Command
 */
#define SPI_Instruction_WRSR    0x01

#define MAX_PCI_DEVICES 10




/**
 * A structure representing SPI ROM special different command.
 */
struct spi_rom_command
{
    /** Read ID command */
    BYTE cmd_read_id;
    /** Address length */
    BYTE addr_len;
    /** Erase SPI ROM command */
    BYTE cmd_chip_erase;
    /** SPI ROM sector size, the unit is 4KB. */
    BYTE sector_size;
    /** SPI ROM total size, the unit is 4KB. */
    BYTE rom_size;
    /** SPI ROM sector erase command */
    BYTE cmd_sector_erase;
    /** command polling time */
    BYTE polling_time;
};

/**
 * A structure representing SPI ROM different vendor.
 */
struct spi_rom_model
{
    /** SPI ROM command descriptor */
    //  struct spi_rom_command cmd;

    /** Read ID command */
    BYTE cmd_read_id;
    /** Address length */
    BYTE addr_len;
    /** Erase SPI ROM command */
    BYTE cmd_chip_erase;
    /** SPI ROM sector size, the unit is 4KB. */
    BYTE sector_size;
    /** SPI ROM total size, the unit is 4KB. */
    BYTE rom_size;
    /** SPI ROM sector erase command */
    BYTE cmd_sector_erase;
    /** command polling time */
    BYTE polling_time;

    /** Manufacturer ID */
    BYTE mid;
    /** Device ID (1st byte) */
    BYTE fid;
    /** Device ID (2nd byte) */
    BYTE sid;
    /** Vendor string */
    char *vendor;
    /** Device string */
    char *device;
};



/**
 * Error codes. Most functions return 0 on success or one of
 * these codes on failure.
 */
 #if 0
enum interctl_error
{
    /** Success (no error) */
    INTERCTL_SUCCESS = 0,
    /** Operation timed out */
    INTERCTL_ERROR_TIMEOUT = -1,
    /** Input/output error */
    INTERCTL_ERROR_IO = -2,
    /** Data miss match */
    INTERCTL_ERROR_NOT_MATCH = -3,
    /** Invalid parameter */
    INTERCTL_ERROR_INVALID_PARAM = -4,
    /** Insufficient memory */
    INTERCTL_ERROR_NO_MEM = -5,
    /** Entity not found */
    INTERCTL_ERROR_NOT_FOUND = -6,
    /** File not found */
    INTERCTL_ERROR_FILE_NOT_FOUND = -7,
    /** SPIROM not found */
    INTERCTL_ERROR_SPIROM_NOT_FOUND = -8,
    /** CFG file not found */
    INTERCTL_ERROR_CFGFILE_NOT_FOUND = -9,
};
/*@}*/
#endif
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

