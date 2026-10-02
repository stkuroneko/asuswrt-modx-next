/*
 * Definitions of Asmedia ASM2114 PCIE Registers
 *
 * Copyright (C) 2015-2018 ASMedia Technology
 */

#ifndef _ASM2114_H_
#define _ASM2114_H_

#define SVID_ADDR	                    0xE260
#define SSID_ADDR	                    0xE262

#define RESET_RAM_ADDR                  0xF340        // reset ram code
#define RESET_CPU_ADDR                  0xF342        // reset CPU


enum DEVICE_IC{
    ASM114_DEVICE  = 0,
    AMD1143_DEVICE = 1,

};

enum ChipDevice_Type
{
    Device_114 = 0,
    Device_214 ,

};


#define ASM2114_VENDOR_ID       0x1b21	/* Asmedia 2114 vendor ID */
#define ASM2114_DEVICE_ID       0x1240		/* Asmedia 2114 device ID */

#define ASM21141_DEVICE_ID      0x1241
#define ASM21142_DEVICE_ID      0x1242

#define ASM2142_DEVICE_ID       0x2142    /* Asmedia 2142  device ID*/
#define ASM2142CM_DEVICE_ID     0x214C

#define AMD3102_VENDOR_ID       0x1022
#define AMD3102_DEVICE_ID       0x3102
#define AMD1343_DEVICE_ID       0x1343




#define VID_REG                     0x00    /* offset 0x00-02: Vendor ID */
#define DID_REG                     0x02    /* offset 0x02-04: Device ID */
#define PCI_COMMAND_REG             0x04    /* offset 0x04: Command register */
#define PCI_IO_SPACE_ENABLED        0x01    /* bit 0: IO space enable */
#define PCI_MEMORY_SPACE_ENABLED    0x02    /* bit 1: Memory space enable */
#define PCI_BUS_MASTER_ENABLED      0x04    /* bit 2: Bus master enable */
#define REVISION_REG                0x08    /* offset 0x08: Revision ID register */
#define PROGRAMMING_INTERFACE_REG   0x09    /* offset 0x09: Programming interface */
#define SUB_CLASS_REG               0x0A    /* offset 0x0A: Sub class code */
#define BASE_CLASS_REG              0x0B    /* offset 0x0B: Base class code */
#define BAR0_REG                    0x10    /* offset 0x10-13: Base Address 0 */
#define IDE_PRI_COMMAND_BASE_REG    BAR0_REG
#define BAR1_REG                    0x14    /* offset 0x14-17: Base Address 1 */
#define IDE_PRI_CONTROL_BASE_REG    BAR1_REG
#define BAR2_REG                    0x18    /* offset 0x18-1B: Base Address 2 */
#define IDE_SEC_COMMAND_BASE_REG    BAR2_REG
#define BAR3_REG                    0x1C    /* offset 0x1C-1F: Base Address 3 */
#define IDE_SEC_CONTROL_BASE_REG    BAR3_REG
#define BAR4_REG                    0x20    /* offset 0x20-23: Base Address 4 */
#define IDE_BM_BASE_REG             BAR4_REG
#define BAR5_REG                    0x24    /* offset 0x24-27: Base Address 5 */
#define SATA_AHCI_BASE_REG          BAR5_REG
#define SVID_REG                    0x2C    /* offset 0x2C-2D: Subsystem Vendor ID */
#define SDID_REG                    0x2E    /* offset 0x2E-2F: Subsystem Device ID */
#define EXPANSION_ROM_BASE_REG      0x30    /* offset 0x30-33: Expansion ROM Base Address */
#define INTERRUPT_LINE_REG          0x3C    /* offset 0x3C: Interrupt line (IRQ) */
#define INTERRUPT_PIN_REG           0x3D    /* offset 0x3D: Interrupt Pin (INTA,B,C,D) */

/*
 * PCI-E and Firmware Communcation Interface
 * 1. Control Register      (4-Bytes)
 * 2. Write Data Register   (8-Bytes)
 * 3. Read Dara Register    (8-Bytes)
 */
#define INTERFACE_BASE_REG  0xF0    /* PCI Config offset */
#define DATA_READ0_REG      INTERFACE_BASE_REG
#define DATA_READ1_REG      (INTERFACE_BASE_REG + 0x04)
#define DATA_WRITE0_REG     (INTERFACE_BASE_REG + 0x08)
#define DATA_WRITE1_REG     (INTERFACE_BASE_REG + 0x0C)
#define CONTROL_REG         0xE0
#define CONTROL_READ_BIT    0x01
#define CONTROL_WRITE_BIT   0x02

/*
 * Input Firmware Format
 */
#define CFG_SIGNATURE           "2114A_RCFG"
#define CFG_SIGNATURE_SIZE      10
#define FW_SIGNATURE_0          0x34313132  /* "4112" */
#define FW_SIGNATURE_1          0x57465F41  /* "WF_A" */
#define FW_SIGNATURE_SIZE       8

#define CFG_LENGTH_OFFSET       4
#define CFG_SIGNATURE_OFFSET    (CFG_LENGTH_OFFSET + 2)
#endif  /* _ASM2114_H_ */

