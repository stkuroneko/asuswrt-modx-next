#ifndef CSR_TEST_H
#define CSR_TEST_H

#define CHIPNAME0_3     0xa0300000
#define CHIPNAME4_7     0xa0300004
#define CHIPID          0xa030000c
#define CPUCFG          0xa0300010
#define ICACHE_HIT	0xa0300080
#define ICACHE_MISS	0xa0300084
#define DCACHE_HIT	0xa0300088
#define DCACHE_MISS	0xa030008c

#define CSRTEST_VERSION	"0.3"
#define CMD_ERROR	-1
#define CMD_HELP	0

typedef struct _cpu_cfg_reg
{
#if BIG_ENDIAN 
  unsigned long reserved0		: 3;
  unsigned long inic_ee_sdram		: 1;
  unsigned long inic_8mb_sdram		: 1;
  unsigned long gp1_rxclk_dir_out	: 1;
  unsigned long pci_host_mode		: 1;
  unsigned long byepass_pll		: 1;
  unsigned long gg1_txclk_dir_out	: 1;
  unsigned long gp1_rgmii_mode		: 1;
  unsigned long cpu_clk_sel		: 2;
  unsigned long pci_66_en		: 1;
  unsigned long byte_order		: 1;	/* 1: Big Endian, 0: Little Endian */
  unsigned long boot_from_rom		: 1;
  unsigned long flash_width		: 1;
  unsigned long test_code		: 8;
  unsigned long sel_pci_host_mode	: 1;
  unsigned long uartf_pcm_mdoe		: 1;
  unsigned long pf_en			: 1;
  unsigned long reserved		: 1;
  unsigned long sdramapb		: 1;
  unsigned long sdramap0		: 1;
  unsigned long reserved1		: 1;
  unsigned long rommapb			: 1;
#else
  unsigned long rommapb			: 1;
  unsigned long reserved1		: 1;
  unsigned long sdramap0		: 1;
  unsigned long sdramapb		: 1;
  unsigned long reserved		: 1;
  unsigned long pf_en			: 1;
  unsigned long uartf_pcm_mode		: 1;
  unsigned long sel_pci_host_mode	: 1;
  unsigned long test_code		: 8;
  unsigned long flash_width		: 1;
  unsigned long boot_from_rom		: 1;
  unsigned long byte_order		: 1;	/* 1: Big Endian, 0: Little Endian */
  unsigned long pci_66_en		: 1;
  unsigned long cpu_clk_sel		: 2;
  unsigned long gp1_rgmii_mode		: 1;
  unsigned long gp1_txclk_dir_out	: 1;
  unsigned long byepass_pll		: 1;
  unsigned long pci_host_mode		: 1;
  unsigned long gp1_rxclk_dir_out	: 1;
  unsigned long inic_8mb_sdram		: 1;
  unsigned long inic_ee_sdram		: 1;
  unsigned long reserved0		: 3;
#endif
} CPU_CFG_REG __attribute__((packed));

typedef struct chipid_reg {
#ifdef BIG_ENDIAN
  unsigned long reserved		: 16;
  unsigned long chipnum			:  8;
  unsigned long chiprev			:  8;
#else
  unsigned long chiprev			:  8;
  unsigned long chipnum			:  8;
  unsigned long reserved		: 16;
#endif
} CHIPID_REG __attribute__((packed));

#endif
