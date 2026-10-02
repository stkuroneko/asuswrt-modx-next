#ifndef _COMMAND_H_
#define _COMMAND_H_

#include "uboot_cfg.h"
#ifdef CONFIG_UBOOT_CONFIG_OVERLAY
  #ifdef CONFIG_UBOOT_CONFIG_FIRMWARE_IN_ROOTFS
    #ifdef CONFIG_BOOT_FROM_NAND
      #define MTD_CONFIG_DEV_NAME  "/dev/mtd5"
    #else
      #define MTD_CONFIG_DEV_NAME  "/dev/mtd/5"
    #endif
  #else
    #ifdef CONFIG_BOOT_FROM_NAND
      #define MTD_CONFIG_DEV_NAME  "/dev/mtd6"
    #else
      #define MTD_CONFIG_DEV_NAME  "/dev/mtd/6"
    #endif
  #endif
#else
  #ifdef CONFIG_UBOOT_CONFIG_FIRMWARE_IN_ROOTFS
    #ifdef CONFIG_BOOT_FROM_NAND
      #define MTD_CONFIG_DEV_NAME  "/dev/mtd4"
    #else
      #define MTD_CONFIG_DEV_NAME  "/dev/mtd/4"
    #endif
  #else
    #ifdef CONFIG_BOOT_FROM_NAND
      #define MTD_CONFIG_DEV_NAME  "/dev/mtd5"
    #else
      #define MTD_CONFIG_DEV_NAME  "/dev/mtd/5"
    #endif
  #endif
#endif

#ifdef CONFIG_TARGET_UBI_MTD_SUPPORT
  #undef MTD_CONFIG_DEV_NAME
  #define MTD_CONFIG_DEV_NAME "/dev/mtd1"

  #undef IFX_CFG_FLASH_UBOOT_CFG_SIZE 
  #define IFX_CFG_FLASH_UBOOT_CFG_SIZE CONFIG_UBOOT_CONFIG_ENV_SIZE

#endif

#define MTD_DEV_START_ADD 	IFX_CFG_FLASH_ROOTFS_IMAGE_START_ADDR
#define CFG_ENV_ADDR    IFX_CFG_FLASH_UBOOT_CFG_START_ADDR
#define CFG_ENV_SIZE    IFX_CFG_FLASH_UBOOT_CFG_SIZE
#ifdef CONFIG_UBOOT_CONFIG_ENV_REDUND
  #define ENV_HEADER_SIZE (sizeof(unsigned long) + sizeof(char))
#else
  #define ENV_HEADER_SIZE	(sizeof(unsigned long))
#endif
#define ENV_SIZE (CFG_ENV_SIZE - ENV_HEADER_SIZE)

typedef struct environment_s {
	unsigned long crc;	/* CRC32 over data bytes        */
#ifdef CONFIG_UBOOT_CONFIG_ENV_REDUND
	unsigned char flags;      /* active/obsolete flags    */
#endif
	unsigned char data[ENV_SIZE];	/* Environment data             */
} env_t;

int read_env(void);
int envmatch(char *s1, int i2);
char *get_env(char *name);
int set_env(char *name, char *val);
int saveenv(void);
unsigned long find_mtd(unsigned long addr_first, char *mtd_dev);

#endif				/* _COMMAND_H_ */
