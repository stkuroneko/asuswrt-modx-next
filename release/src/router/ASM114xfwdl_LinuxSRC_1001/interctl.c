/*
 * Asmedia ASM2114 Firmware Interface Access Functions
 *
 * Copyright (C) 2015-2018 ASMedia Technology
 */

/**
 * \defgroup interctl Firmware Interface access API
 * This page documents 2114fwdl's API for firmware interface
 * access functions.
 */

#include "precomp.h"

struct pci_dev *cur_dev = NULL;

#define RetryTime 5

static DWORD g_dwInc = 0;
struct spi_rom_model spi_rom_table[] = {
    {
        /*
         * MXIC
         * MX25L512, MX25L512C, MX25V512C,
         */
        0x9F, 0,        /* Read Manufacturer and Device ID */
        0x60, 1, 16,    /* Chip Erase CMD, sector size 4K, ROM Size 64K (16X4K) */
        0x20,           /* Sector Erase CMD */
        22,             /* 60_ms x 16_Sectors = 960_ms */
        0xC2,           /* Manufacturer ID */
        0x20,           /* First Device ID */
        0x10,           /* Second Device ID */
        "MXIC",
        "MX25L(V)512(C)",
    },
    {
        /*
         * MXIC
         * MX25L1005C, MX25L1025C,MX25L1006E
         */
        0x9F, 0,        /* Read Manufacturer and Device ID */
        0x60, 1, 32,    /* Chip Erase CMD, sector size 4K, ROM Size 128K (32X4K) */
        0x20,           /* Sector Erase CMD */
        22,             /* 60_ms x 16_Sectors = 960_ms */
        0xC2,           /* Manufacturer ID */
        0x20,           /* First Device ID */
        0x11,           /* Second Device ID */
        "MXIC",
        "MX25L100(2)5C/1006E",
    },
    {
        /*
         * MXIC
         * MX25L5121E,
         */
        0x9F, 0,        /* Read Manufacturer and Device ID */
        0x60, 1, 16,    /* Chip Erase CMD, sector size 4K, ROM Size 64K (16X4K) */
        0x20,           /* Sector Erase CMD */
        22,             /* 60_ms x 16_Sectors = 960_ms */
        0xC2,           /* Manufacturer ID */
        0x22,           /* First Device ID */
        0x10,           /* Second Device ID */
        "MXIC",
        "MX25L5121E",
    },
    {
        /*
         * MXIC
         * MX25L1021E,
         */
        0x9F, 0,        /* Read Manufacturer and Device ID */
        0x60, 1, 32,    /* Chip Erase CMD, sector size 4K, ROM Size 128K (32X4K) */
        0x20,           /* Sector Erase CMD */
        22,             /* 60_ms x 16_Sectors = 960_ms */
        0xC2,           /* Manufacturer ID */
        0x22,           /* First Device ID */
        0x11,           /* Second Device ID */
        "MXIC",
        "MX25L1021E",
    },
    {
        /*
         * MXIC
         * MX25L2006E,MX25L2026E
         */
        0x9F, 0,        /* Read Manufacturer and Device ID */
        0x60, 1, 64,    /* Chip Erase CMD, sector size 4K, ROM Size 256K (64X4K) */
        0x20,           /* Sector Erase CMD */
        22,             /* 60_ms x 16_Sectors = 960_ms */
        0xC2,           /* Manufacturer ID */
        0x20,           /* First Device ID */
        0x12,           /* Second Device ID */
        "MXIC",
        "MX25L2006E",
    },
    {
        /*
         * MXIC
         * MX25L4006E, MX25V4006E,MX25L4026E
         */
        0x9F, 0,        /* Read Manufacturer and Device ID */
        0x60, 1, 128,    /* Chip Erase CMD, sector size 4K, ROM Size 512K (128X4K) */
        0x20,           /* Sector Erase CMD */
        22,             /* 60_ms x 16_Sectors = 960_ms */
        0xC2,           /* Manufacturer ID */
        0x20,           /* First Device ID */
        0x13,           /* Second Device ID */
        "MXIC",
        "MX25x4006E",
    },
    {
        /*
         * MXIC
         * MX25V512F
         */
        0x9F, 0,        /* Read Manufacturer and Device ID */
        0x60, 1, 16,    /* Chip Erase CMD, sector size 4K, ROM Size 64K (16X4K) */
        0x20,           /* Sector Erase CMD */
        22,             /* 60_ms x 16_Sectors = 960_ms */
        0xC2,           /* Manufacturer ID */
        0x22,           /* First Device ID */
        0x10,           /* Second Device ID */
        "MXIC",
        "MX25V512F",
    },
    {
        /*
         * MXIC
         * MX25V1035F,
         */
        0x9F, 0,        /* Read Manufacturer and Device ID */
        0x60, 1, 32,    /* Chip Erase CMD, sector size 4K, ROM Size 128K (32X4K) */
        0x20,           /* Sector Erase CMD */
        22,             /* 60_ms x 16_Sectors = 960_ms */
        0xC2,           /* Manufacturer ID */
        0x22,           /* First Device ID */
        0x11,           /* Second Device ID */
        "MXIC",
        "MX25V1035F",
    },
    {
        /*
         * MXIC
         * MX25V2035F
         */
        0x9F, 0,        /* Read Manufacturer and Device ID */
        0x60, 1, 64,    /* Chip Erase CMD, sector size 4K, ROM Size 256K (64X4K) */
        0x20,           /* Sector Erase CMD */
        22,             /* 60_ms x 16_Sectors = 960_ms */
        0xC2,           /* Manufacturer ID */
        0x23,           /* First Device ID */
        0x12,           /* Second Device ID */
        "MXIC",
        "MX25V2035F",
    },
    {
        /*
         * MXIC
         * MX25V4035F
         */
        0x9F, 0,        /* Read Manufacturer and Device ID */
        0x60, 1, 128,    /* Chip Erase CMD, sector size 4K, ROM Size 512K (128X4K) */
        0x20,           /* Sector Erase CMD */
        22,             /* 60_ms x 16_Sectors = 960_ms */
        0xC2,           /* Manufacturer ID */
        0x23,           /* First Device ID */
        0x13,           /* Second Device ID */
        "MXIC",
        "MMX25V4035F",
    },
    {
        /*
         * MXIC
         * MX25U4035,
         */
        0x9F, 0,        /* Read Manufacturer and Device ID */
        0x60, 1, 128,    /* Chip Erase CMD, sector size 4K, ROM Size 512K (128X4K) */
        0x20,           /* Sector Erase CMD */
        22,             /* 60_ms x 16_Sectors = 960_ms */
        0xC2,           /* Manufacturer ID */
        0x25,           /* First Device ID */
        0x33,           /* Second Device ID */
        "MXIC",
        "MX25U4035",
    },
    {
        /*
         * MXIC
         * MX25U8035,
         */
        0x9F, 0,        /* Read Manufacturer and Device ID */
        0x60, 1, 255,    /* Chip Erase CMD, sector size 4K, ROM Size 1024K (256X4K) */
        0x20,           /* Sector Erase CMD */
        22,             /* 60_ms x 16_Sectors = 960_ms */
        0xC2,           /* Manufacturer ID */
        0x25,           /* First Device ID */
        0x34,           /* Second Device ID */
        "MXIC",
        "MX25U8035",
    },
    {
        /*
         * WinBond
         * W25Q20BW,
         */
        0x9F, 0,        /* Read Manufacturer and Device ID */
        0x60, 1, 64,    /* Chip Erase CMD, sector size 4K, ROM Size 256K (64X4K) */
        0x20,           /* Sector Erase CMD */
        22,             /* 60_ms x 16_Sectors = 960_ms */
        0xEF,           /* Manufacturer ID */
        0x50,           /* First Device ID */
        0x12,           /* Second Device ID */
        "WinBond",
        "W25Q20BW",
    },
    {
        /*
         * WinBond
         * W25Q40BW,
         */
        0x9F, 0,        /* Read Manufacturer and Device ID */
        0x60, 1, 128,    /* Chip Erase CMD, sector size 4K, ROM Size 512K (128X4K) */
        0x20,           /* Sector Erase CMD */
        22,             /* 60_ms x 16_Sectors = 960_ms */
        0xEF,           /* Manufacturer ID */
        0x50,           /* First Device ID */
        0x13,           /* Second Device ID */
        "WinBond",
        "W25Q40BW",
    },
    {
        /*
         * WinBond
         * W25X05CL
         */
        0x9F, 0,        /* Read Manufacturer and Device ID */
        0x60, 1, 16,    /* Chip Erase CMD, sector size 4K, ROM Size 64K (32X4K) */
        0x20,           /* Sector Erase CMD */
        22,             /* 60_ms x 16_Sectors = 960_ms */
        0xEF,           /* Manufacturer ID */
        0x30,           /* First Device ID */
        0x10,           /* Second Device ID */
        "WinBond",
        "W25X05CL",
    },
    {
        /*
         * WinBond
         * W25X10BL,W25X10BV, W25X10CL
         */
        0x9F, 0,        /* Read Manufacturer and Device ID */
        0x60, 1, 32,    /* Chip Erase CMD, sector size 4K, ROM Size 128K (32X4K) */
        0x20,           /* Sector Erase CMD */
        22,             /* 60_ms x 16_Sectors = 960_ms */
        0xEF,           /* Manufacturer ID */
        0x30,           /* First Device ID */
        0x11,           /* Second Device ID */
        "WinBond",
        "W25X10B(C)L(V)",
    },
    {
        /*
         * WinBond
         * W25X20BL,W25X20BV, W25X20CL
         */
        0x9F, 0,        /* Read Manufacturer and Device ID */
        0x60, 1, 64,    /* Chip Erase CMD, sector size 4K, ROM Size 256K (64X4K) */
        0x20,           /* Sector Erase CMD */
        22,             /* 60_ms x 16_Sectors = 960_ms */
        0xEF,           /* Manufacturer ID */
        0x30,           /* First Device ID */
        0x12,           /* Second Device ID */
        "WinBond",
        "W25X20B(C)L(V)",
    },
    {
        /*
         * WinBond
         * W25X40BL,W25X40BV
         */
        0x9F, 0,        /* Read Manufacturer and Device ID */
        0x60, 1, 128,    /* Chip Erase CMD, sector size 4K, ROM Size 512K (128X4K) */
        0x20,           /* Sector Erase CMD */
        22,             /* 60_ms x 16_Sectors = 960_ms */
        0xEF,           /* Manufacturer ID */
        0x30,           /* First Device ID */
        0x13,           /* Second Device ID */
        "WinBond",
        "W25X40BL(V)",
    },
    {
        /*
         * WinBond
         * W25Q40BL, W25Q40BV
         */
        0x9F, 0,        /* Read Manufacturer and Device ID */
        0x60, 1, 128,    /* Chip Erase CMD, sector size 4K, ROM Size 512K (128X4K) */
        0x20,           /* Sector Erase CMD */
        22,             /* 60_ms x 16_Sectors = 960_ms */
        0xEF,           /* Manufacturer ID */
        0x40,           /* First Device ID */
        0x13,           /* Second Device ID */
        "WinBond",
        "W25Q40BL(V)",
    },
    {
        /*
         * WinBond
         * W25Q80DV
         */
        0x9F, 0,        /* Read Manufacturer and Device ID */
        0x60, 1, 255,    /* Chip Erase CMD, sector size 4K, ROM Size 1024K (256X4K) 256 is too big*/
        0x20,           /* Sector Erase CMD */
        22,             /* 60_ms x 16_Sectors = 960_ms */
        0xEF,           /* Manufacturer ID */
        0x40,           /* First Device ID */
        0x14,           /* Second Device ID */
        "WinBond",
        "W25Q80DV",
    },
    {
        /*
         * Sanyo
         * LE25FU206A
         */
        0x9F, 0,        /* Read Manufacturer and Device ID */
        0xC7, 1, 64,    /* Chip Erase CMD, sector size 4K, ROM Size 256K (64X4K) */
        0xd8,           /* Sector Erase CMD */
        22,             /* 60_ms x 16_Sectors = 960_ms */
        0x62,           /* Manufacturer ID */
        0x06,           /* First Device ID */
        0x12,           /* Second Device ID */
        "Sanyo",
        "LE25FU206A",
    },
    {
        /*
         * Sanyo
         * LE25FU406B
         */
        0x9F, 0,        /* Read Manufacturer and Device ID */
        0xC7, 1, 128,    /* Chip Erase CMD, sector size 4K, ROM Size 512K (128X4K) */
        0xd8,           /* Sector Erase CMD */
        22,             /* 60_ms x 16_Sectors = 960_ms */
        0x62,           /* Manufacturer ID */
        0x1E,           /* First Device ID */
        0x62,           /* Second Device ID */
        "Sanyo",
        "LE25FU406B",
    },
    {
        /*
         * ESMT
         * F25L05PA
         */
        0x9F, 0,        /* Read Manufacturer and Device ID */
        0x60, 1, 128,    /* Chip Erase CMD, sector size 4K, ROM Size 512K (128X4K) */
        0x20,           /* Sector Erase CMD */
        22,             /* 60_ms x 16_Sectors = 960_ms */
        0x8C,           /* Manufacturer ID */
        0x30,           /* First Device ID */
        0x10,           /* Second Device ID */
        "ESMT",
        "F25L05PA",
    },
    {
        /*
         * ESMT
         * F25L01PA
         */
        0x9F, 0,        /* Read Manufacturer and Device ID */
        0x60, 1, 16,    /* Chip Erase CMD, sector size 4K, ROM Size 64K (16X4K) */
        0x20,           /* Sector Erase CMD */
        22,             /* 60_ms x 16_Sectors = 960_ms */
        0x8C,           /* Manufacturer ID */
        0x30,           /* First Device ID */
        0x11,           /* Second Device ID */
        "ESMT",
        "F25L01PA",
    },
#if 0
    {
        /*
         * ESMT
         * F25L02PA
         */
        0x9F, 0,        /* Read Manufacturer and Device ID */
        0x60, 1, 32,    /* Chip Erase CMD, sector size 4K, ROM Size128K (32X4K) */
        0x20,           /* Sector Erase CMD */
        22,             /* 60_ms x 16_Sectors = 960_ms */
        0x8C,           /* Manufacturer ID */
        0x30,           /* First Device ID */
        0x12,           /* Second Device ID */
        "ESMT",
        "F25L02PA",
    },
    {
        /*
         * ESMT
         * F25L04PA
         */
        0x9F, 0,        /* Read Manufacturer and Device ID */
        0x60, 1, 64,    /* Chip Erase CMD, sector size 4K, ROM Size 256K (64X4K) */
        0x20,           /* Sector Erase CMD */
        22,             /* 60_ms x 16_Sectors = 960_ms */
        0x8C,           /* Manufacturer ID */
        0x30,           /* First Device ID */
        0x13,           /* Second Device ID */
        "ESMT",
        "F25L04PA",
    },
#endif
    {
        /*
         * Giga Device
         * GD25Q40, GD25Q40BT, GD25Q41B
         */
        0x9F, 0,        /* Read Manufacturer and Device ID */
        0x60, 1, 128,    /* Chip Erase CMD, sector size 4K, ROM Size 512K (128X4K) */
        0x20,           /* Sector Erase CMD */
        150,             /* 60_ms x 16_Sectors = 960_ms */
        0xC8,           /* Manufacturer ID */
        0x40,           /* First Device ID */
        0x13,           /* Second Device ID */
        "Giga Device",
        "GD25Q40/1BT",
    },
    {
        /*
         * Giga Device
         * GD25Q20, GD25Q20BT,GD25Q21B
         */
        0x9F, 0,        /* Read Manufacturer and Device ID */
        0x60, 1, 64,    /* Chip Erase CMD, sector size 4K, ROM Size 256K (64X4K) */
        0x20,           /* Sector Erase CMD */
        150,             /* 60_ms x 16_Sectors = 960_ms */
        0xC8,           /* Manufacturer ID */
        0x40,           /* First Device ID */
        0x12,           /* Second Device ID */
        "Giga Device",
        "GD25Q20/1",
    },
    {
        /*
         * Giga Device
         * GD25Q10
         */
        0x9F, 0,        /* Read Manufacturer and Device ID */
        0x60, 1, 32,    /* Chip Erase CMD, sector size 4K, ROM Size 128K (32X4K) */
        0x20,           /* Sector Erase CMD */
        150,             /* 60_ms x 16_Sectors = 960_ms */
        0xC8,           /* Manufacturer ID */
        0x40,           /* First Device ID */
        0x11,           /* Second Device ID */
        "Giga Device",
        "GD25Q10/D10B",
    },
    {
        /*
         * Giga Device
         * GD25Q512
         */
        0x9F, 0,        /* Read Manufacturer and Device ID */
        0x60, 1, 16,    /* Chip Erase CMD, sector size 4K, ROM Size 64K (16X4K) */
        0x20,           /* Sector Erase CMD */
        150,             /* 60_ms x 16_Sectors = 960_ms */
        0xC8,           /* Manufacturer ID */
        0x40,           /* First Device ID */
        0x10,           /* Second Device ID */
        "Giga Device",
        "GD25Q512/D05B",
    },
    {
        /*
         * Giga Device
         * GD25VQ21B
         */
        0x9F, 0,        /* Read Manufacturer and Device ID */
        0x60, 1, 64,    /* Chip Erase CMD, sector size 4K, ROM Size 256K (64X4K) */
        0x20,           /* Sector Erase CMD */
        150,             /* 60_ms x 16_Sectors = 960_ms */
        0xC8,           /* Manufacturer ID */
        0x42,           /* First Device ID */
        0x12,           /* Second Device ID */
        "Giga Device",
        "GD25VQ21B",
    },
    {
        /*
         * NUMONYX
         * M25P05A,
         */
        0x9F, 0,        /* Read Manufacturer and Device ID */
        0xC7, 8, 16,    /* Chip Erase CMD, sector size 32K byte (8X4K), ROM Size 64K byte(16X4K) */
        0xD8,           /* Sector Erase CMD */
        22,             /* 650_ms x 2_Sectors = 1300_ms */
        0x20,           /* Manufacturer ID */
        0x20,           /* First Device ID */
        0x10,           /* Second Device ID */
        "NUMONYX",
        "M25P05A",
    },
    {
        /*
         * NUMONYX
         * M25P10A,
         */
        0x9F, 0,        /* Read Manufacturer and Device ID */
        0xC7, 8, 32,    /* Chip Erase CMD, sector size 32K byte (8X4K), ROM Size 128K byte (32X4K) */
        0xD8,           /* Sector Erase CMD */
        22,             /* 650_ms x 2_Sectors = 1300_ms */
        0x20,           /* Manufacturer ID */
        0x20,           /* First Device ID */
        0x11,           /* Second Device ID */
        "NUMONYX",
        "M25P10A",
    },
    {
        /*
         * NUMONYX
         * M25PE10,
         */
        0x9F, 0,        /* Read Manufacturer and Device ID */
        0xC7, 16, 32,   /* Chip Erase CMD, sector size 64K byte (16X4K), ROM Size 128K byte (32X4K) */
        0xD8,           /* Sector Erase CMD */
        22,             /* 650_ms x 2_Sectors = 1300_ms */
        0x20,           /* Manufacturer ID */
        0x80,           /* First Device ID */
        0x11,           /* Second Device ID */
        "NUMONYX",
        "M25PE10",
    },
    {
        /*
         * NUMONYX
         * M25PE20,
         */
        0x9F, 0,        /* Read Manufacturer and Device ID */
        0xC7, 16, 64,   /* Chip Erase CMD, sector size 64K byte, ROM Size 256K byte (64X4K) */
        0xD8,           /* Sector Erase CMD */
        22,             /* 650_ms x 2_Sectors = 1300_ms */
        0x20,           /* Manufacturer ID */
        0x80,           /* First Device ID */
        0x12,           /* Second Device ID */
        "NUMONYX",
        "M25PE20",
    },
    {
        /*
         * NUMONYX
         * M45PE10,
         */
        0x9F, 0,        /* Read Manufacturer and Device ID */
        0xD8, 16, 32,   /* Sectors Erase CMD, 64K BYTES per Sector (16X4K), ROM Size 128K byte (32X4K) */
        0xD8,           /* Sector Erase CMD */
        22,             /* 2200ms */
        0x20,           /* Manufacturer ID */
        0x40,           /* First Device ID */
        0x11,           /* Second Device ID */
        "NUMONYX",
        "M45PE10",
    },
    {
        /*
         * EON
         * EN25F05, EN25LF05,
         */
        0x9F, 0,        /* Read Manufacturer and Device ID */
        0xC7, 1, 16,    /* Chip Erase CMD, sector size 4K byte, ROM Size 64K byte(16X4K) */
        0x20,           /* Sector Erase CMD */
        22,             /* 2200ms */
        0x1C,           /* Manufacturer ID */
        0x31,           /* First Device ID */
        0x10,           /* Second Device ID */
        "EON",
        "EN25xF05",
    },
    {
        /*
         * EON
         * EN25F10, EN25LF10,
         */
        0x9F, 0,        /* Read Manufacturer and Device ID */
        0xC7, 1, 32,    /* Chip Erase CMD, sector size 4K byte, ROM Size 128K byte(32X4K) */
        0x20,           /* Sector Erase CMD */
        22,             /* 2200ms */
        0x1C,           /* Manufacturer ID */
        0x31,           /* First Device ID */
        0x11,           /* Second Device ID */
        "EON",
        "EN25(L)F10",
    },
    {
        /*
         * EON
         * EN25S10
         */
        0x9F, 0,        /* Read Manufacturer and Device ID */
        0xC7, 1, 32,    /* Chip Erase CMD, sector size 4K byte, ROM Size 128K byte(32X4K) */
        0x20,           /* Sector Erase CMD */
        22,             /* 2200ms */
        0x1C,           /* Manufacturer ID */
        0x38,           /* First Device ID */
        0x11,           /* Second Device ID */
        "EON",
        "EN25S10",
    },
    {
        /*
         * EON
         * EN25F20
         */
        0x9F, 0,        /* Read Manufacturer and Device ID */
        0xC7, 1, 64,    /* Chip Erase CMD, sector size 4K byte, ROM Size 256K byte(64X4K) */
        0x20,           /* Sector Erase CMD */
        22,             /* 2200ms */
        0x1C,           /* Manufacturer ID */
        0x31,           /* First Device ID */
        0x12,           /* Second Device ID */
        "EON",
        "EN25F20",
    },
    {
        /*
         * EON
         * EN25F40
         */
        0x9F, 0,        /* Read Manufacturer and Device ID */
        0xC7, 1, 128,    /* Chip Erase CMD, sector size 4K byte, ROM Size 512K byte(128X4K) */
        0x20,           /* Sector Erase CMD */
        22,             /* 2200ms */
        0x1C,           /* Manufacturer ID */
        0x31,           /* First Device ID */
        0x13,           /* Second Device ID */
        "EON",
        "EN25F40",
    },
    {
        /*
         * ATMEL
         * AT25F512B, AT25F512A,
         */
        0x15, 0,        /* Read Manufacturer and Device ID */
        0x62, 8, 16,    /* Chip Erase CMD, sector size 32K byte (8X4K), ROM Size 64K byte(16X4K) */
        0x52,           /* Sector Erase CMD */
        22,             /* 2200ms */
        0x1F,           /* Manufacturer ID */
        0x65,           /* First Device ID */
        0xFF,           /* Second Device ID */
        "ATMEL",
        "AT25F512A(B)",
    },
    {
        /*
         * ATMEL
         * AT25FS010,
         */
        0x15, 0,        /* Read Manufacturer and Device ID */
        0x60, 1, 32,    /* Chip Erase CMD, sector size 4K byte, ROM Size 128K byte(32X4K) */
        0x20,           /* Sector Erase CMD */
        22,             /* 2200ms */
        0x1F,           /* Manufacturer ID */
        0x66,           /* First Device ID */
        0xFF,           /* Second Device ID */
        "ATMEL",
        "AT25FS010",
    },
    {
        /*
         * PFLASH
         * PM25LV512A,
         */
        0xAB, 3,        /* Read Manufacturer and Device ID */
        0xC7, 1, 16,    /* Chip Erase CMD, sector size 4K byte, ROM Size 64K byte(16X4K) */
        0xD7,           /* Sector Erase CMD */
        22,             /* 2200ms */
        0x9D,           /* Manufacturer ID */
        0x7B,           /* First Device ID */
        0x7F,           /* Second Device ID */
        "PFLASH",
        "PM25LV512A",
    },
    {
        /*
         * PFLASH
         * PM25LV010A,
         */
        0xAB, 3,        /* Read Manufacturer and Device ID */
        0xC7, 1, 32,    /* Chip Erase CMD, sector size 4K byte, ROM Size 128K byte(16X4K) */
        0xD7,           /* Sector Erase CMD */
        22,             /* 2200ms */
        0x9D,           /* Manufacturer ID */
        0x7C,           /* First Device ID */
        0x7F,           /* Second Device ID */
        "PFLASH",
        "PM25LV010A",
    },
    {
        /*
         * PFLASH
         * PM25LD512C,
         */
        0x90, 3,        /* Read Manufacturer and Device ID */
        0x60, 1, 16,    /* Chip Erase CMD,  sector size 4K byte, ROM Size 64K byte(16X4K) */
        0xD7,           /* Sector Erase CMD */
        22,             /* 2200ms */
        0x9D,           /* Manufacturer ID */
        0x05,           /* First Device ID */
        0x7F,           /* Second Device ID */
        "PFLASH",
        "PM25LD512C",
    },
    {
        /*
         * PFLASH
         * PM25LD010, PM25LD010C,
         */
        0x90, 3,        /* Read Manufacturer and Device ID */
        0x60, 1, 32,    /* Chip Erase CMD, sector size 4K byte, ROM Size 128K byte(32X4K) */
        0xD7,           /* Sector Erase CMD */
        22,             /* 2200ms */
        0x9D,           /* Manufacturer ID */
        0x10,           /* First Device ID */
        0x7F,           /* Second Device ID */
        "PFLASH",
        "PM25LD010x",
    },
    {
        /*
         * PFLASH
         * PM25LD020C,Pm25WD020
         */
        0x90, 3,        /* Read Manufacturer and Device ID */
        0x60, 1, 64,    /* Chip Erase CMD, sector size 4K byte, ROM Size 256K byte(64X4K) */
        0xD7,           /* Sector Erase CMD */
        22,             /* 2200ms */
        0x9D,           /* Manufacturer ID */
        0x11,           /* First Device ID */
        0x7F,           /* Second Device ID */
        "PFLASH",
        "PM25L(W)D020C",
    },
    {
        /*
         * PFLASH
         * Pm25WD040
         */
        0x90, 3,        /* Read Manufacturer and Device ID */
        0x60, 1, 128,    /* Chip Erase CMD, sector size 4K byte, ROM Size 512K byte(128X4K) */
        0xD7,           /* Sector Erase CMD */
        22,             /* 2200ms */
        0x9D,           /* Manufacturer ID */
        0x12,           /* First Device ID */
        0x7F,           /* Second Device ID */
        "PFLASH",
        "Pm25WD040",
    },
    {
        /*
         * PFLASH
         * Pm25LD040
         */
        0x90, 3,        /* Read Manufacturer and Device ID */
        0x60, 1, 128,    /* Chip Erase CMD, sector size 4K byte, ROM Size 512K byte(128X4K) */
        0xD7,           /* Sector Erase CMD */
        22,             /* 2200ms */
        0x9D,           /* Manufacturer ID */
        0x7e,           /* First Device ID */
        0x7F,           /* Second Device ID */
        "PFLASH",
        "Pm25LD040",
    },

    {
        /*
         * PFLASH
         * Pm25LQ010A
         */
        0x9F, 3,        /* Read Manufacturer and Device ID */
        0x60, 1, 32,    /* Chip Erase CMD, sector size 4K byte, ROM Size 128K byte(32X4K) */
        0xD7,           /* Sector Erase CMD */
        22,             /* 2200ms */
        0x9D,           /* Manufacturer ID */
        0x40,           /* First Device ID */
        0x11,           /* Second Device ID */
        "PFLASH",
        "Pm25LQ010A",
    },
    {
        /*
         * AMIC
         * A25L512,
         */
        0x9F, 0,        /* Read Manufacturer and Device ID */
        0xC7, 1, 16,    /* Chip Erase CMD, sector size 4K byte, ROM Size 64K byte(16X4K) */
        0x20,           /* Sector Erase CMD */
        22,             /* 2200ms */
        0x37,           /* Manufacturer ID */
        0x30,           /* First Device ID */
        0x10,           /* Second Device ID */
        "AMIC",
        "A25L512",
    },
    {
        /*
         * AMIC
         * A25L010,
         */
        0x9F, 0,        /* Read Manufacturer and Device ID */
        0xC7, 1, 32,    /* Chip Erase CMD, sector size 4K byte, ROM Size 128K byte(32X4K) */
        0x20,           /* Sector Erase CMD */
        22,             /* 2200ms */
        0x37,           /* Manufacturer ID */
        0x30,           /* First Device ID */
        0x11,           /* Second Device ID */
        "AMIC",
        "A25L010",
    },
    {
        /*
         * AMIC
         * A25L020,
         */
        0x9F, 0,        /* Read Manufacturer and Device ID */
        0xC7, 1, 64,    /* Chip Erase CMD, sector size 4K byte, ROM Size 128K byte(32X4K) */
        0x20,           /* Sector Erase CMD */
        22,             /* 2200ms */
        0x37,           /* Manufacturer ID */
        0x30,           /* First Device ID */
        0x12,           /* Second Device ID */
        "AMIC",
        "A25L020",
    },
    {
        /*
         * AMIC
         * A25L040,
         */
        0x9F, 0,        /* Read Manufacturer and Device ID */
        0xC7, 1, 128,    /* Chip Erase CMD, sector size 4K byte, ROM Size 128K byte(32X4K) */
        0x20,           /* Sector Erase CMD */
        22,             /* 2200ms */
        0x37,           /* Manufacturer ID */
        0x30,           /* First Device ID */
        0x13,           /* Second Device ID */
        "AMIC",
        "A25L040",
    },
    {
        /*
         * SST
         * SST25VF512, SST25VF512A,
         */
        0x90, 3,        /* Read Manufacturer and Device ID */
        0x60, 1, 16,    /* Chip Erase CMD, sector size 4K byte, ROM Size 64K byte(16X4K) */
        0x20,           /* Sector Erase CMD */
        22,             /* 2200ms */
        0xBF,           /* Manufacturer ID */
        0x48,           /* First Device ID */
        0xBF,           /* Second Device ID */
        "SST",
        "SST25VF512X",
    },
    {
        /*
         * SST
         * SST25VF010A,
         */
        0x90, 3,        /* Read Manufacturer and Device ID */
        0x60, 1, 32,    /* Chip Erase CMD, sector size 4K byte, ROM Size 128K byte(32X4K) */
        0x20,           /* Sector Erase CMD */
        22,             /* 2200ms */
        0xBF,           /* Manufacturer ID */
        0x49,           /* First Device ID */
        0xBF,           /* Second Device ID */
        "SST",
        "SST25VF010A",
    },
    {
        /*
         * Micron
         * M25P80,
         */
        0x9F, 0,        /* Read Manufacturer and Device ID */
        0xC7, 4, 16,    /* Chip Erase CMD, sector size 16K byte, ROM Size 1M byte(16X16K) */
        0xD8,           /* Sector Erase CMD */
        100,             /* 600ms (max 255)*/
        0x20,           /* Manufacturer ID */
        0x20,           /* First Device ID */
        0x14,           /* Second Device ID */
        "Micron",
        "M25P80",
    },
    {
        /*
         * Boya
         * BY25Q20A
         */
        0x9F, 0,        /* Read Manufacturer and Device ID */
        0x60, 1, 64,    /* Chip Erase CMD, sector size 4K, ROM Size 256K (64X4K) */
        0x20,           /* Sector Erase CMD */
        250,             /* 60_ms x 16_Sectors = 960_ms */
        0xE0,           /* Manufacturer ID */
        0x40,           /* First Device ID */
        0x12,           /* Second Device ID */
        "Boya",
        "BY25Q20A",
    },
    {
        /*
         * Boya
         * BY25Q10A
         */
        0x9F, 0,        /* Read Manufacturer and Device ID */
        0x60, 1, 32,    /* Chip Erase CMD, sector size 4K, ROM Size 128K (32X4K) */
        0x20,           /* Sector Erase CMD */
        150,             /* 60_ms x 16_Sectors = 960_ms */
        0xE0,           /* Manufacturer ID */
        0x40,           /* First Device ID */
        0x11,           /* Second Device ID */
        "Boya",
        "BY25Q10A",
    },
    {
        /*
         * Boya
         * BY25Q512A
         */
        0x9F, 0,        /* Read Manufacturer and Device ID */
        0x60, 1, 16,    /* Chip Erase CMD, sector size 4K, ROM Size 64K (16X4K) */
        0x20,           /* Sector Erase CMD */
        150,             /* 60_ms x 16_Sectors = 960_ms */
        0xE0,           /* Manufacturer ID */
        0x40,           /* First Device ID */
        0x10,           /* Second Device ID */
        "Boya",
        "BY25Q512A",
    },
};
#define SPI_MODEL_ITEMS (sizeof(spi_rom_table) / sizeof(spi_rom_table[0]))

static int interctl_write_8051_memory( BYTE mem_type, DWORD addr, DWORD size, BYTE *pbuffer );

/* Force ASM2114 jump to ROM code */
static int interctl_ResetDev( void )
{
    BYTE data;
    int ret;
    if ( verblevel )
        { printf( "interctl_ResetDev!!\n " ); }

    /* Force ASM2114 jump to ROM code */
    data = 0x02;
    ret = interctl_write_8051_memory( TYPE_XDATA, RESET_RAM_ADDR, 1, &data );
    if ( ret < 0 )
        { goto err_exit; }

    usleep( 10*1000 );
    data = 0x01;
    ret = interctl_write_8051_memory( TYPE_XDATA, RESET_CPU_ADDR, 1, &data );
    if ( ret < 0 )
        { goto err_exit; }


err_exit:
    return ASMT_RESET_FAIL;
}


/*
 * Compares the first length bytes of the block of memory
 * pointed by src to memory pointed by dst.
 *
 * \param src pointer to block of memory
 * \param dst pointer to block of memory
 * \param length number of bytes to compare
 * \return ASMT_SUCCESS on data match
 * \return ASMT_SPI_VERIFY_ERROR if data not match
 */
static int data_compare(BYTE *src, BYTE *dst, DWORD length)
{
    DWORD i;

    for (i = 0; i < length; i++) {
        if (src[i] != dst[i])
            return ASMT_SPI_VERIFY_ERROR;
    }

    return ASMT_SUCCESS;
}

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
    func_enter();

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
    func_enter();

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

/*
 * Write command to xHC.
 *
 * \param cmd protocol command defined in interctl.h
 * \param mem_type protocol type defined in interctl.h
 * \param size length of buffer
 * \param addr offset of read address, or SPI ROM address length
 * \param sec_low inupt value for the sencond 8 bytes
 * \param sec_high inupt value for the sencond 8 bytes
 * \return ASMT_SUCCESS on transfer OK
 * \return negative if transfer fail
 */
static int interctl_write_command( BYTE cmd, BYTE mem_type, WORD size,
                                   DWORD addr, DWORD sec_low, DWORD sec_high )
{
    int ret;
    DWORD value_low, value_high;
    func_enter();

    if ( cur_dev == NULL )
    {
        ret = ASMT_PARAMETER_INVALID;
        goto err_exit;
    }

    /* Send Read command to xHC */
    ret = wait_write_ready();
    if ( ret < 0 )
        { goto err_exit; }

    /* Send first 8 bytes */
    value_low = cmd | ( ( DWORD )mem_type << 8 ) | ( ( DWORD )size << 16 );
    value_high = addr;
    pci_write_long( cur_dev, DATA_WRITE0_REG, value_low );
    pci_write_long( cur_dev, DATA_WRITE1_REG, value_high );

    /* Write 1 to CONTROL_WRITE_BIT, inform xHCI to get data */
    pci_write_byte( cur_dev, CONTROL_REG, CONTROL_WRITE_BIT );

    ret = wait_write_ready();
    if ( ret < 0 )
        { goto err_exit; }

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
 * Read data from xHC.
 *
 * \param mem_type protocol type defined in interctl.h
 * \param size length of buffer
 * \param addr offset of read address, or SPI ROM address length
 * \param sec_low inupt value for the sencond 8 bytes
 * \param sec_high inupt value for the sencond 8 bytes
 * \param pbuffer buffer to store read data
 * \return ASMT_SUCCESS on transfer OK
 * \return negative if transfer fail
 */
static int interctl_read_memory( BYTE mem_type, WORD size, DWORD addr,
                                 DWORD sec_low, DWORD sec_high, BYTE *pbuffer )
{
    int ret;
    BYTE temp[8];
    WORD i;
    func_enter();

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

/*
 * Write data to xHC.
 *
 * \param mem_type protocol type defined in interctl.h
 * \param size length of buffer
 * \param addr offset of write address
 * \param pbuffer data buffer
 * \return ASMT_SUCCESS on transfer OK
 * \return negative if transfer fail
 */
static int interctl_write_memory( BYTE mem_type, WORD size, DWORD addr, BYTE *pbuffer )
{
    int ret;
    DWORD sec_low, sec_high;
    func_enter();

    if ( size > 8 )
    {
        ret = ASMT_PARAMETER_INVALID;
        goto err_exit;
    }

    sec_low = 0;
    if ( size > 0 )
        { sec_low |= pbuffer[0]; }
    if ( size > 1 )
        { sec_low |= ( DWORD )pbuffer[1] << 8; }
    if ( size > 2 )
        { sec_low |= ( DWORD )pbuffer[2] << 16; }
    if ( size > 3 )
        { sec_low |= ( DWORD )pbuffer[3] << 24; }

    sec_high = 0;
    if ( size > 4 )
        { sec_high |= pbuffer[4]; }
    if ( size > 5 )
        { sec_high |= ( DWORD )pbuffer[5] << 8; }
    if ( size > 6 )
        { sec_high |= ( DWORD )pbuffer[6] << 16; }
    if ( size > 7 )
        { sec_high |= ( DWORD )pbuffer[7] << 24; }

    ret = interctl_write_command( CMD_WRITE_MEM, mem_type, size, addr, sec_low, sec_high );
    if ( ret < 0 )
        { goto err_exit; }

    ret = ASMT_SUCCESS;

err_exit:
    return ret;
}

/*
 * Read data from SPI ROM.
 *
 * \param offset offset of write address
 * \param size length of buffer
 * \param pbuffer data buffer
 * \return ASMT_SUCCESS on transfer OK
 * \return negative if transfer fail
 */
static int interctl_read_spirom( DWORD offset, DWORD size, BYTE *pbuffer )
{
    int ret;
    WORD read_size;
    DWORD done_size;
    func_enter();

    done_size = 0;
    read_size = ( size < 8 ) ? size : 8;
    while ( done_size < size )
    {
        ret = interctl_read_memory( TYPE_SPI, read_size, done_size + offset, 0, 0, pbuffer );
        if ( ret < 0 )
            { goto err_exit; }

        pbuffer += read_size;
        done_size += read_size;
        if ( ( size - done_size ) < 8 )
            { read_size = size - done_size; }
    }

    ret = ASMT_SUCCESS;

err_exit:
    return ret;
}

/*
 * Write data to SPI ROM section.
 *
 * \param rom the SPI ROM model to operate on
 * \param pbuffer data buffer
 * \param offset offset of write address
 * \param size length of buffer
 * \return ASMT_SUCCESS on transfer OK
 * \return negative if transfer fail
 */
int interctl_erase_spirom(struct spi_rom_model *rom)
{
    int ret;
    func_enter();

    ret = interctl_write_command(CMD_ERASE_SPI_SECTOR, TYPE_SPI, rom->rom_size,
                                 0, *((DWORD *)rom), *((DWORD *)rom + 1));
    return ret;
}

static int interctl_write_section( struct spi_rom_model *rom, BYTE *pbuffer, DWORD offset, DWORD size, BYTE iRetry )
{
    int ret;
    DWORD sector_size, sector_count;
    DWORD i, remain_size;
    BYTE temp[8];
    BYTE half_speed_enable = 0;
    DWORD dwDelayCnt_LSB = 0;
    DWORD dwDelayCnt_MSB = 0;
    func_enter();


    sector_size = rom->sector_size * 0x1000;
    sector_count = ( size + sector_size - 1 ) / sector_size;
    ret = interctl_write_command( CMD_ERASE_SPI_SECTOR, TYPE_SPI, sector_count,
                                  offset, *( ( DWORD * )rom ), *( ( DWORD * )rom + 1 ) );
    if ( ret < 0 )
    {
        if ( verblevel )
            { printf( "CMD_ERASE_SPI_SECTOR Failed,sector_size=%lx, sector_count=%lx\n", sector_size, sector_count ); }

        goto err_exit;
    }
// delay for erase spi sectors
    for ( i=0; i<200000; i++ );

    if ( rom->mid == 0xbf )
    {
        // read cpu clock
        ret = interctl_read_8051_memory( TYPE_XDATA, 0XF341  , 1,( BYTE * )&temp[0] );
        if ( ret < 0 )
        {
            goto err_exit;
        }
        half_speed_enable = ( temp[0]&0x02 )>>1;
        dwDelayCnt_LSB  = ( half_speed_enable ? 0x80 : 0xF0 ) + g_dwInc;

        if ( verblevel )
            { printf( "half_speed_enable = %x, dwDelayCnt_LSB=%lu\n", half_speed_enable, dwDelayCnt_LSB ); }

        ret = interctl_write_command( CMD_WRITE_SST_SPI_START, TYPE_SPI, 0, offset, dwDelayCnt_LSB, dwDelayCnt_MSB );
    }
    else
        { ret = interctl_write_command( CMD_WRITE_SPI_START, TYPE_SPI, 0, offset, 0, 0 ); }
    if ( ret < 0 )
        { goto err_exit; }

    remain_size = size;
    while ( remain_size > 8 )
    {
        ret = interctl_write_command( CMD_LOOP, TYPE_SPI, 8, offset,
                                      *( ( DWORD * )pbuffer ), *( ( DWORD * )( pbuffer + 4 ) ) );
        if ( ret < 0 )
        {
            if ( ( iRetry+1==RetryTime ) || ( verblevel ) )
                { printf( "CMD_LOOP fail!! offset[%lx], retry[%d]\n ", offset, iRetry ); }
            goto err_exit;
        }


        pbuffer += 8;
        offset += 8;
        remain_size -= 8;
    }

    for ( i = 0; i < 8; i++ )
        { temp[i] = ( i < remain_size ) ? pbuffer[i] : 0; }

    ret = interctl_write_command( CMD_END, TYPE_SPI, remain_size,
                                  offset, *( ( DWORD * )temp ), *( ( DWORD * )( temp + 4 ) ) );
    if ( ret < 0 )
    {
        if ( verblevel )
            { printf( "CMD_END fail!! offset[%lx], retry[%d]\n ", offset, iRetry ); }
        goto err_exit;
    }

    ret = ASMT_SUCCESS;

err_exit:

    return ret;
}

/*
 * Compare the section data of SPI ROM with data buffer.
 *
 * \param pbuffer data buffer
 * \param offset offset of read address
 * \param size length of buffer
 * \return ASMT_SUCCESS on success
 * \return negative if miss compare
 */
static int interctl_compare_section( BYTE *pbuffer, DWORD offset, DWORD size, BYTE iRetry )
{
    int i, ret;
    BYTE temp[10];
    WORD compare_size;
    DWORD done_size;
    func_enter();

    done_size = 0;
    compare_size = ( size < 8 ) ? size : 8;
    while ( done_size < size )
    {
        ret = interctl_read_memory( TYPE_SPI, compare_size, done_size + offset, 0, 0, temp );
        if ( ret < 0 )
        {
            if ( ( iRetry+1==RetryTime ) || ( verblevel ) )
                { printf( "interctl_read_memory Fail\n" ); }
            goto err_exit;
        }

        ret= memcmp( pbuffer + done_size, temp, compare_size );
        if ( ret != 0 )
        {
            if ( ( iRetry+1==RetryTime ) || ( verblevel ) )
            {
                printf( "Miss Compare\n"  "SRC %08lX  ",   done_size );
                for ( i = 0; i < compare_size; i++ )
                    { printf( "%02X ", pbuffer[done_size+i] ); }
                printf( "\nDST %08lX  ",	done_size + offset );

                for ( i = 0; i < compare_size; i++ )
                    { printf( "%02X ", temp[i] ); }

                printf( "\n" );
                goto err_exit;
            }
            if ( verblevel )
                { printf( "Retry[%d]\n",iRetry ); }

            goto err_exit;
        }

        done_size += compare_size;
        if ( ( size - done_size ) < 8 )
            { compare_size = size - done_size; }
    }

    ret = ASMT_SUCCESS;

err_exit:
    return ret;
}

/**
 * \ingroup interctl
 * Exchange error code to string.
 *
 * \param errnum error code
 * \return string pointer
 */
char *interctl_strerror( int errnum )
{
    char *str;

    switch ( errnum )
    {
    case ASMT_TIMEOUT:
        str = "Operation timed out";
        break;
    case ASMT_IO_ERROR:
        str = "Transfer error";
        break;
    case ASMT_SPI_VERIFY_ERROR:
        str = "Data not match";
        break;
    case ASMT_PARAMETER_INVALID:
        str = "Invalid parameter";
        break;
    case ASMT_MEMORY_ALLOCATE_ERROR:
        str = "Insufficient memory";
        break;
    case ASMT_DEVICE_NOT_FOUND :
        str = "Entity not found";
        break;
    case ASMT_FILE_NOT_FOUND:
        str = "File not found";
        break;
    case ASMT_UNMATCH:
        str = "UNMATCH";
        break;
		case ASMT_RESET_FAIL:
        str = "RESET fail";
        break;

    default:
        str = "Unknown error";
        break;
    }

    return str;
}

/**
 * \ingroup interctl
 * Read External SPI ROM ID (3 bytes).
 *
 * \return SPI ROM model
 */
static struct spi_rom_model *interctl_read_romid( void )
{
    unsigned int i;
    int ret = 0;
    struct spi_rom_model *rom;
    BYTE romid[3];  /* romid[0]:MID, romid[1]:FID, romid[2]:SID */
    func_enter();

    for ( i = 0; i < SPI_MODEL_ITEMS; i++ )
    {
        rom = &spi_rom_table[i];
        /* Issue command to get ROM ID */
        ret = interctl_read_memory( TYPE_SPIID, 3, rom->addr_len,
                                    rom->cmd_read_id, 0, romid );
        if ( ret<0 )
        {
            rom = NULL;
            break;
        }


        /* Manufacturer and Device ID are matched */
        /*Bob 20110317 fix sid*/
        if ( rom->mid == romid[0] &&
                rom->fid == romid[1] &&
                ( ( rom->sid == 0xFF )||( rom->sid == romid[2] ) ) )
        {
            // if (verblevel)
            printf( "\nSPI ROM, vendor[%s], device id[%s]\n",  rom->vendor, rom->device );
            break;
        }
    }

    if ( verblevel )
        { printf( "\n" ); }

    if ( i == SPI_MODEL_ITEMS )
        { rom = NULL; }

    return rom;
}

/**
 * \ingroup interctl
 *  SPIROM Write protect Enable/disable.
 *
 * \return ASMT_SUCCESS on success
 */
 int interctl_spirom_writeprotect_enable(int  nEnable)
{
    int ret;

	BYTE nEnableBYte = 0x1c;// BP2[4]=1,BP1[3]=1,BP0[2]=1
	BYTE nDisableBYte = 0;


    func_enter();


	BYTE nCtrlByte;
	nCtrlByte = nEnable ? nEnableBYte :  nDisableBYte;

    if (verblevel)
                {printf("\ninterctl_spirom_writeprotect_enable nEnable=[%d], nCtrlByte=[%x]\n", nEnable, nCtrlByte);}

		//Write Enable
		ret = interctl_write_command(DEF_PCIE_CMD_WRITE_CMD, TYPE_SPI, 1, 0, SPI_Instruction_WREN, 0);
		if (ret < 0){
			 printf("\nSPI_Instruction_WREN failed\n" );
			    {goto err_exit;}
		}
		// wait disable write protection register active
    usleep( 200*1000 );



	// Write Status Register
        ret = interctl_write_command(DEF_PCIE_CMD_WRITE_ROM_STATUS, TYPE_SPI, 2, 0, ((0x03 | nCtrlByte) << 8) | SPI_Instruction_WRSR, 0);
        if (ret < 0){
		printf("SPI_Instruction_WRSR failed, status=%x \n",(0x03 << 8) | SPI_Instruction_WRSR  );
            goto err_exit;
        }
        // wait disable write protection register active
    usleep( 200*1000 );


	if (nEnable)
	{
		//Write Disable
	    if (verblevel)
  		printf("Write Disable, SPI_Instruction_WRDI \n");
	        ret = interctl_write_command(DEF_PCIE_CMD_WRITE_CMD, TYPE_SPI, 1, 0, SPI_Instruction_WRDI, 0);
	        if (ret < 0){
		     printf("SPI_Instruction_WRDI failed\n" );
	            goto err_exit;
	    	}
	        // wait disable write protection register active
    usleep( 200*1000 );
	}

err_exit:
    return ret;
}

/**
 * \ingroup interctl
 * Initial External SPIROM.
 *
 * \return SPI ROM model
 */
struct spi_rom_model *interctl_init_spirom( void )
{
    int ret;
    struct spi_rom_model *rom;
    func_enter();

    //ret = interctl_write_command(DEF_PCIE_CMD_SET_SPI_CLOCK, TYPE_SPI, 1, 0, SPI_CLOCK_10MHz, 0);
    ret = interctl_write_command( DEF_PCIE_CMD_SET_SPI_PAGESIZE, TYPE_SPI, 1, 0, 128, 0 );
    rom = interctl_read_romid();
    if ( !rom )
        { goto err_exit; }

    /* MXIC MX25L5121E */
    if ( rom->mid == 0xc2 && rom->fid == 0x22 && ( ( rom->sid == 0x10 ) || ( rom->sid == 0x11 ) ) )
    {
        ret = interctl_write_command( DEF_PCIE_CMD_SET_SPI_PAGESIZE, TYPE_SPI, 1, 0, 32, 0 );
        if ( ret < 0 )
            { goto err_exit; }

    }

	//write protect disable
	ret =interctl_spirom_writeprotect_enable(FALSE);
        if (ret < 0)
            goto err_exit;


err_exit:
    return rom;
}


/**
 * \ingroup interctl
 * Inform ASM2114 starting to write 8051 memory.
 *
 * \param mem_type memory type
 * \param addr offset of write address
 * \param size buffer size
 * \param pbuffer data buffer
 * \return ASMT_SUCCESS on success
 * \return negative if transfer fail
 */
static int interctl_write_8051_memory( BYTE mem_type, DWORD addr, DWORD size, BYTE *pbuffer )
{
    int ret = ASMT_PARAMETER_INVALID;
    DWORD remain_size;
    func_enter();

    if ( mem_type != TYPE_DATA &&
            mem_type != TYPE_IDATA &&
            mem_type != TYPE_XDATA )
        { goto err_exit; }

    remain_size = size;
    while ( remain_size > 8 )
    {
        ret = interctl_write_memory( mem_type, 8, addr, pbuffer );
        if ( ret < 0 )
            { goto err_exit; }

        remain_size -= 8;
        addr += 8;
        pbuffer += 8;
    }

    if ( remain_size > 0 )
    {
        ret = interctl_write_memory( TYPE_XDATA, remain_size, addr, pbuffer );
        if ( ret < 0 )
            {goto err_exit;}
    }

    ret = ASMT_SUCCESS;

err_exit:
    return ret;
}

/**
 * \ingroup interctl
 * Inform ASM2114 starting to download firmware.
 *
 * \param rom the particular SPI ROM model
 * \param pbuffer data buffer
 * \param size buffer size
 * \return ASMT_SUCCESS on success
 * \return negative if transfer fail
 */

int interctl_update_firmware( struct spi_rom_model *rom, BYTE *pbuffer, DWORD size )
{
    int ret, sections;
    DWORD rom_size;
    int iRetry = 0;
    func_enter();

    rom_size = rom->rom_size * 0x1000;
    sections = 1;
    if ( rom_size >= 0x20000 && size <= 0x10000 )
        { sections++; }

//	retry mechanism by kung

    for ( iRetry = 0; iRetry<RetryTime; iRetry++ )
    {
        g_dwInc = iRetry * 0x20;
        ret = interctl_write_section( rom, pbuffer, 0, size, iRetry );
        if ( ret < 0 )
            { continue; }

        ret = interctl_compare_section( pbuffer, 0, size, iRetry );
        if ( ret==ASMT_SUCCESS )
        {
            if ( ret >=0 )
            {
                printf( "Update Section %d  Done\n", sections );
                printf( "Verify Section %d OK\n ", sections );

            }
            else
            {
                if ( iRetry+1==RetryTime )
                {
                    printf( "Update Section %d Fail\n ", sections );
                    printf( "Verify Section %d Fail\n ", sections );

                }

            }

            break;
        }
        else
        {
            if ( verblevel )
                { printf( "\n Retry[%d]\n", iRetry ); }

            continue;
        }
    }
    if ( ret!=ASMT_SUCCESS )
        { goto err_exit; }

// write section 2
    if ( sections > 1 )
    {

        for ( iRetry = 0; iRetry<RetryTime; iRetry++ )
        {
            g_dwInc = iRetry * 0x20;


            ret = interctl_write_section( rom, pbuffer, 0x10000, size, iRetry );
            if ( ret < 0 )
                { continue; }

            ret = interctl_compare_section( pbuffer, 0x10000, size, iRetry );
            if ( ret==ASMT_SUCCESS )
            {
                if ( ret >=0 )
                {
                    printf( "Update Section %d  Done\n", sections );
                    printf( "Verify Section %d OK ", sections );

                }
                else
                {
                    if ( iRetry+1==RetryTime )
                    {
                        printf( "Update Section %d Fail\n ", sections );
                        printf( "Verify Section %d Fail ", sections );

                    }

                }

                break;
            }
            else
            {
                if ( verblevel )
                    { printf( "\\n Retry[%d]\n", iRetry ); }

                continue;
            }
        }
    }


		ret = interctl_spirom_writeprotect_enable(TRUE);
		if (ret!=ASMT_SUCCESS)
			{goto err_exit;}

    /* Force ASM2114 jump to ROM code */
    ret = interctl_ResetDev();

    ret = ASMT_SUCCESS;

err_exit:
    return ret;
}

/**
 * \ingroup interctl
 * Check firmware file whether is valid or not.
 *
 * \param pbuffer data buffer
 * \return ASMT_SUCCESS on success
 * \return ASMT_PARAMETER_INVALID if it is a invalid
 *         firmware file
 */
static int interctl_check_firmware( BYTE *pbuffer )
{
    int ret = ASMT_PARAMETER_INVALID;
    DWORD i, table_size, code_size, crc_value1, crc_value2;
    BYTE checksum, *temp;
    func_enter();

    /* Check configure table signature */
    if (strncmp((char *)&pbuffer[CFG_SIGNATURE_OFFSET], CFG_SIGNATURE, CFG_SIGNATURE_SIZE))
     {
    	 printf("\n config signature [%c%c%c%c%c%c] invalid, CFG_SIGNATURE_OFFSET=%d \n",
		 	pbuffer[CFG_SIGNATURE_OFFSET],
		 	pbuffer[CFG_SIGNATURE_OFFSET+1],
		 	pbuffer[CFG_SIGNATURE_OFFSET+2],
		 	pbuffer[CFG_SIGNATURE_OFFSET+3],
		 	pbuffer[CFG_SIGNATURE_OFFSET+4],
		 	pbuffer[CFG_SIGNATURE_OFFSET+5],

		 						CFG_SIGNATURE_OFFSET);

        goto err_exit;
    }

    /* Check configure table checksum & CRC32 */
    table_size = ( ( WORD )pbuffer[CFG_LENGTH_OFFSET + 1] << 8 ) | pbuffer[CFG_LENGTH_OFFSET];
    checksum = 0;
    for ( i = 0; i < table_size; i++ )
        { checksum += pbuffer[i]; }

    if ( verblevel )
        {printf( "\ntcs %x %x\n", checksum, pbuffer[table_size] ); }

    if ( checksum != pbuffer[table_size] )
    {
    	printf("\n checksum failed %x %x\n", checksum, pbuffer[table_size]);
        goto err_exit;
    }

    crc32_init();
    crc_value1 = get_crc32( pbuffer, table_size );
    crc_value2 = pbuffer[table_size + 4];
    crc_value2 = ( crc_value2 << 8 ) | pbuffer[table_size + 3];
    crc_value2 = ( crc_value2 << 8 ) | pbuffer[table_size + 2];
    crc_value2 = ( crc_value2 << 8 ) | pbuffer[table_size + 1];


    if ( crc_value2 != crc_value1 )
        {
        printf( "check crc %08lx %08lx\n", crc_value1, crc_value2 );
        	goto err_exit;
    	}

    /* Check firmware signature */
    code_size = ( ( WORD )pbuffer[table_size + 5 + 1] << 8 ) | pbuffer[table_size + 5];
	if ((*((DWORD *)(pbuffer + table_size + 7 + code_size)) != FW_SIGNATURE_0 ||
            *( ( DWORD * )( pbuffer + table_size + 7 + code_size + 4 ) ) != FW_SIGNATURE_1 ))
	{
		printf("\n  firmware signature [%s] invalid \n", pbuffer + table_size + 7 + code_size);
		goto err_exit;
	}
    if (verblevel)
       {printf("\n  firmware signature [%s] , length = %d \n", pbuffer + table_size + 7 + code_size,table_size + 7 + code_size );}

    /* Check firmware checksum & CRC32 */
    checksum = 0;
    temp = pbuffer + table_size + 7;
    for ( i = 0; i < code_size; i++ )
        { checksum += temp[i]; }

    if ( verblevel )
        { printf( "ccs %x %x\n", checksum, temp[code_size + FW_SIGNATURE_SIZE] ); }

    if ( checksum != temp[code_size + FW_SIGNATURE_SIZE] )
        { goto err_exit; }

    crc32_init();
    crc_value1 = get_crc32( temp, code_size );
    crc_value2 = temp[code_size + FW_SIGNATURE_SIZE + 4];
    crc_value2 = ( crc_value2 << 8 ) | temp[code_size + FW_SIGNATURE_SIZE + 3];
    crc_value2 = ( crc_value2 << 8 ) | temp[code_size + FW_SIGNATURE_SIZE + 2];
    crc_value2 = ( crc_value2 << 8 ) | temp[code_size + FW_SIGNATURE_SIZE + 1];

    if ( verblevel )
        { printf( "ccrc %lu %lu\n", crc_value1, crc_value2 ); }

    if ( crc_value2 != crc_value1 )
        { goto err_exit; }

    ret = ASMT_SUCCESS;

err_exit:
    return ret;
}

int interctl_verify_firmware(struct spi_rom_model *rom, BYTE *pbuffer)
{
    int ret, sections, result = ASMT_SUCCESS;
    DWORD rom_size;
    func_enter();

    rom_size = rom->rom_size * 0x1000;
    sections = 1;
    if (rom_size >= 0x20000)
        { sections++; }

    printf("Section %d  ", 1);
    ret = interctl_read_spirom(0, 64 * 1024, pbuffer);
    if ( ret < 0 )
    {
        result = ASMT_IO_ERROR;
        printf("Fail\n");
    }
    else
    {
        ret = interctl_check_firmware(pbuffer);
        if (ret < 0)
            { result = ASMT_IO_ERROR; }
        printf("%s\n", (ret) ? "Fail" : "Pass");
    }

    if ( sections > 1 )
    {
        printf("Section %d  ", 2);
        ret = interctl_read_spirom(64 * 1024, 64 * 1024, pbuffer);
        if ( ret < 0 )
        {
            result = ASMT_IO_ERROR;
            printf("Fail\n");
        }
        else
        {
            ret = interctl_check_firmware(pbuffer);
            if (ret < 0)
                { result = ASMT_IO_ERROR; }
            printf("%s\n", (ret) ? "Fail" : "Pass");
        }
    }

    return result;
}

/**
 * \ingroup interctl
 * Get the firmware version from the firmware file.
 *
 * \param pbuffer data buffer
 * \param info firmware information return to
 * \return ASMT_SUCCESS on success
 * \return negative if fail to get the firmware version
 */
int interctl_get_version_from_file( BYTE *pbuffer, struct firmware_info *info )
{
    int i, ret, offset;
    func_enter();

    ret = interctl_check_firmware( pbuffer );
    if ( ret < 0 )
        { goto err_exit; }

    offset = ( ( WORD )pbuffer[CFG_LENGTH_OFFSET + 1] << 8 ) | pbuffer[CFG_LENGTH_OFFSET];
    offset += 0x87;
    for ( i = 0; i < 6; i++ )
        { info->version[i] = pbuffer[offset++]; }

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
 * \ingroup interctl
 * Get the firmware version from the 8051 code memory.
 *
 * \param info firmware information return to
 * \return ASMT_SUCCESS on success
 * \return negative if fail to get the firmware version
 */
int interctl_get_version_from_code( struct firmware_info *info )
{
    int i, ret;
    BYTE temp[6];
    func_enter();

    ret = interctl_read_8051_memory( TYPE_RAM_CODE, 0x80, 6, &temp[0] );
    if ( ret < 0 )
        { goto err_exit; }

    for ( i = 0; i < 6; i++ )
        { info->version[i] = temp[i]; }

    ret = ASMT_SUCCESS;

err_exit:
    return ret;
}


int interctl_Get_firmware(struct spi_rom_model *rom, DWORD offset, BYTE *pbuffer, DWORD dwSize)
{
    return interctl_read_spirom(offset, dwSize, pbuffer);;
}

/**
 * \ingroup interctl
 * Inform update wd info to Last 256 of last sector.
 *
 * \param rom the particular SPI ROM model
 * \param pbuffer data buffer
 * \param size buffer size
 * \return ASMT_SUCCESS on success
 * \return negative if transfer fail
 */
int interctl_update_customer_info(struct spi_rom_model *rom, BYTE *pbuffer, DWORD size)
{
    int ret;
    DWORD rom_size, sector_size;
    DWORD lastsector_offset = 0;;
    int iRetry = 0;
BYTE *pSectorBuffer=NULL;
int i,j;


	sector_size =  rom->sector_size* 0x1000;
	rom_size = rom->rom_size *sector_size;
	pSectorBuffer = (BYTE *)malloc(sector_size );
	if (pSectorBuffer == NULL)
	{
		printf("Fail to alloc memory\n");
			return ASMT_MEMORY_ALLOCATE_ERROR;
	}
	memset (pSectorBuffer, 0,sector_size);
	// write wd info to last 256 bytes of last sector
	memcpy(pSectorBuffer+(sector_size-256), pbuffer, 256);
	if (verblevel)
	{
		for ( i = 0; i<16;i++)
		{
			for ( j=0;j<17;j++)
			{
				printf ("%02x ", pSectorBuffer[(i*16+j)+(sector_size-256)]);
			}
			printf("\n");;
		}
	}

	for (iRetry = 0;iRetry<RetryTime;iRetry++)
	{
		g_dwInc = iRetry * 0x20;
		lastsector_offset =  (rom->rom_size-1) * sector_size;

	        if (verblevel)
	            printf("interctl_update_customer_info, lastsector_offset=0x%x, , rom->cmd.rom_size=0x%x, rom->cmd.sector_size=0x%x\n",lastsector_offset,  rom->rom_size, rom->sector_size);
			// erase last sector
		    ret = interctl_write_command(CMD_ERASE_SPI_SECTOR, TYPE_SPI, 1,  lastsector_offset, *((DWORD *)rom), *((DWORD *)rom + 1));
		    if (ret < 0)
		    {
		        if (verblevel)
		            printf("CMD_ERASE_SPI_SECTOR Failed,offset =%x\n", (rom->rom_size-1) * sector_size);

			continue;
		    }

		// write section 1
		ret = interctl_write_section(rom, pSectorBuffer,lastsector_offset, sector_size, iRetry);// put SPI-ROM at Last 256 Bytes of last sector
		if (ret < 0)
		{
			if (verblevel)
				printf("\n interctl_write_section failed, Retry[%d]\n", iRetry);
			continue;
		}



		ret = interctl_compare_section(pSectorBuffer, lastsector_offset, sector_size, iRetry);
		if (ret < 0)
		{
			if (verblevel)
				printf("\n interctl_compare_section failed, Retry[%d]\n", iRetry);
			continue;
		}

		break;

	}


		ret = interctl_spirom_writeprotect_enable(TRUE);
		if (ret!=ASMT_SUCCESS)
			goto err_exit;


    ret = ASMT_SUCCESS;

err_exit:
	free (pSectorBuffer);
    return ret;
}



