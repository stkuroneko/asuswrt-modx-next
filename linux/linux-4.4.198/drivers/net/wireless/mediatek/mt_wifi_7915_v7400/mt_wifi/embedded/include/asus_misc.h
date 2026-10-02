#ifndef	__ASUS_MISC_H__
#define	__ASUS_MISC_H__

#if defined(CONFIG_MODEL_RTAC85U)|| defined(CONFIG_MODEL_RTAC85P) || defined(CONFIG_MODEL_RPAC87) || defined(CONFIG_MODEL_RTAC65U) || defined(CONFIG_MODEL_RTN800HP) || defined(CONFIG_MODEL_RT4GAX56)
#define REG2G_EEPROM_ADDR	0xff40 //10 bytes
#define REG5G_EEPROM_ADDR	0xff4a //10 bytes
#define REGSPEC_ADDR		0xff54 // 4 bytes
#elif defined(CONFIG_MODEL_RTAX53U) || defined(CONFIG_MODEL_RTAX54) || defined(CONFIG_MODEL_XD4S)
#define REG2G_EEPROM_ADDR	0x2ff40 //10 bytes
#define REG5G_EEPROM_ADDR	0x2ff4a //10 bytes
#define REGSPEC_ADDR		0x2ff54 // 4 bytes
#else
#define REG2G_EEPROM_ADDR	0x234 //10 bytes
#define REG5G_EEPROM_ADDR	0x23E //10 bytes
#define REGSPEC_ADDR		0x248 // 4 bytes
#endif
#define MAX_REGDOMAIN_LEN		10
#define	MAX_REGSPEC_LEN		4
extern u_char reg_spec_2g[MAX_REGDOMAIN_LEN + 1];
extern u_char reg_spec_5g[MAX_REGDOMAIN_LEN + 2];
extern u_char reg_spec[MAX_REGSPEC_LEN + 1];

#define WL_REG_2G		"wl_reg_2g"
#define WL_REG_5G		"wl_reg_5g"

void check_runtime_para(char *regspec, char *regspec_2g, char *regspec_5g);
void change_config_para(char *buf);
int check_config_change(void);

#if defined(SINGLE_SKU_IN_DRIVER)
void dump_wifi_sku(RTMP_STRING *buf);
void dump_wifi_sku_bf(RTMP_STRING *buf);
#endif
#if defined(ASUS_VSIE)
extern UCHAR IEOUI_2G[4];
extern UCHAR IEOUI_5G[4];
extern UCHAR IEDATA_2G[255];
extern UCHAR IEDATA_5G[255];
extern INT len_2G;
extern INT len_5G;
#endif

#if defined(ASUS_RVSIE)
#define MAX_IE_SIZE 255
extern INT len_IE;
#endif


/* product id */
#if defined(CONFIG_MODEL_RTAC85U) || defined(CONFIG_MODEL_RTAC65U)
#define PRODUCT_ID	"RT-AC85U"
#elif defined(CONFIG_MODEL_RTAC85P)
#define PRODUCT_ID	"RT-AC85P"
#else
#define PRODUCT_ID	"Unknown"
#endif


extern UINT wifi_hwnat_enable;

#endif /* __ASUS_MISC_H__ */

