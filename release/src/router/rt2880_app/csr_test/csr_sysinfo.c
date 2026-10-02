#include "csr_test.h"
#include "csr_netlink.h"
#include "csr_sysinfo.h"
#include <stdio.h>

char* cpu_clock_rate(unsigned int option)
{
	switch(option) {
		case CLK_250MHZ:
			return "250Mhz";
		case CLK_266MHZ:
			return "266Mhz";
		case CLK_280MHZ:
			return "280Mhz";
		case CLK_300MHZ:
			return "300Mhz";
	}
}

void show_sysinfo()
{
	int i;
	unsigned char *chipname0, *chipname1;
	unsigned long reg32, chipname_reg0, chipname_reg1, id_reg, icache_hit, icache_miss;
	unsigned long dcache_hit, dcache_miss;
	RT2880_CSR_MSG read_csrmsg;
	CPU_CFG_REG *cpu_reg_map;
	CHIPID_REG  *chip_id;

	read_csrmsg.enable  = CSR_READ;
	read_csrmsg.address = DCACHE_HIT;
	dcache_hit = reg_rw_test(&read_csrmsg);

	if ( dcache_hit == 0)
		icache_hit = reg_rw_test(&read_csrmsg);

	for ( reg32 = 0; reg32 < 10000; reg32++)
		;

	read_csrmsg.enable  = CSR_READ;
	read_csrmsg.address = DCACHE_MISS;
	dcache_miss = reg_rw_test(&read_csrmsg);
	if ( dcache_miss == 0)
		dcache_miss = reg_rw_test(&read_csrmsg);

	for ( reg32 = 0; reg32 < 10000; reg32++)
		;

	read_csrmsg.enable  = CSR_READ;
	read_csrmsg.address = ICACHE_HIT;
	icache_hit = reg_rw_test(&read_csrmsg);

	if ( icache_hit == 0)
		icache_hit = reg_rw_test(&read_csrmsg);

	for ( reg32 = 0; reg32 < 10000; reg32++)
		;

	read_csrmsg.enable  = CSR_READ;
	read_csrmsg.address = ICACHE_MISS;
	icache_miss = reg_rw_test(&read_csrmsg);
	if ( icache_miss == 0)
		icache_miss = reg_rw_test(&read_csrmsg);

	/* delay for branch when calling netlink from user side to kernel */
	for ( reg32 = 0; reg32 < 10000; reg32++)
		;

	read_csrmsg.enable  = CSR_READ;
	read_csrmsg.address = CPUCFG;
	reg32 = reg_rw_test(&read_csrmsg);

	if (reg32 == 0)
  		reg32 = reg_rw_test(&read_csrmsg);

	if (reg32 == 0xffffffff)
  		reg32 = reg_rw_test(&read_csrmsg);

	// printf("debug - 0x%08x\n", reg32);
	cpu_reg_map = (CPU_CFG_REG*)&reg32;

	for ( i = 0; i < 100000; i++)
		;

	read_csrmsg.enable  = CSR_READ;
 	read_csrmsg.address = CHIPNAME0_3;
	chipname0 = (unsigned char*)&chipname_reg0;
	chipname_reg0 = reg_rw_test(&read_csrmsg);
	chipname_reg0 = reg_rw_test(&read_csrmsg);

	if (chipname_reg0 == 0)
  		chipname_reg0 = reg_rw_test(&read_csrmsg);

	/* delay for branch when calling netlink from user side to kernel */
	for ( i = 0; i < 100000; i++)
		;

	read_csrmsg.enable  = CSR_READ;
 	read_csrmsg.address = CHIPNAME4_7;
	chipname1 = (unsigned char*)&chipname_reg1;
	chipname_reg1 = reg_rw_test(&read_csrmsg);
	chipname_reg1 = reg_rw_test(&read_csrmsg);
	chipname_reg1 = reg_rw_test(&read_csrmsg);

	if (chipname_reg1 == 0)
  		chipname_reg1 = reg_rw_test(&read_csrmsg);

	printf("  Chip name : %c%c%c%c%c%c\n", chipname0[0], chipname0[1], chipname0[2], chipname0[3],\
		 chipname1[0], chipname1[1]);

	for ( i = 0; i < 100000; i++)
		;
	read_csrmsg.enable  = CSR_READ;
 	read_csrmsg.address = CHIPID;
	chip_id = (CHIPID_REG*)&id_reg;
	id_reg = reg_rw_test(&read_csrmsg);
	id_reg = reg_rw_test(&read_csrmsg);
	id_reg = reg_rw_test(&read_csrmsg);

	if ( id_reg == 0)
		id_reg = reg_rw_test(&read_csrmsg);

	printf("  Chip ID : %d.%d\n", chip_id->chipnum, chip_id->chiprev);
	printf("  Clock Rate : %s\n", cpu_clock_rate(cpu_reg_map->cpu_clk_sel));
	printf("  byte order : %s\n",  cpu_reg_map->byte_order ? "Big Endian":"Little Endian");
	printf("  Use PCI Bridge as %s\n", cpu_reg_map->pci_host_mode ? "Host Mode":"Device Mode");
	printf("  PCI Clock : %s\n", cpu_reg_map->pci_66_en ? "66Mhz":"33Mhz");

	printf("  GMAC RX Clock Direction : %s\n", cpu_reg_map->gp1_rxclk_dir_out ? "Output":"Input");
	printf("  GMAC TX Clock Direction : %s\n", cpu_reg_map->gp1_txclk_dir_out ? "Output":"Input");
	printf("  GE RGMII Voltage : %s\n", cpu_reg_map->gp1_rgmii_mode ? "2.5V":"3.3V");
	printf("  Bypass PLL : %s\n", cpu_reg_map->byepass_pll ? "Yes":"No");
	printf("  Flash Width : %d-bit\n", cpu_reg_map->flash_width ? 16:8);
	printf("  UART FULL PIN : %s\n", cpu_reg_map->uartf_pcm_mode ? "PCM Mode":"UART Mode");
	printf("  CPU Port SDRAM Prefetch : %s\n", cpu_reg_map->pf_en ? "Enable":"Disable");
	printf("  Remap 2MB of SDRAM Bank0 to 0x1fc0-0000 : %s\n", cpu_reg_map->sdramapb ? "Remap":"Normal");
	printf("  Remap SDRAM of Address 0x0000-00000 to 0x001f:ffff : %s\n", cpu_reg_map->sdramap0 ? "Remap":"Normal");
	printf("  Remap 16k Boot Rom to 0x01fc-3ffff : %s\n", cpu_reg_map->rommapb ? "Normal": "Remap to boot address");
//	printf("  I-Cache Hit/Miss : %d / %d\n", icache_hit, icache_miss);
//	printf("  D-Cache Hit/Miss : %d / %d\n", dcache_hit, dcache_miss);
}
