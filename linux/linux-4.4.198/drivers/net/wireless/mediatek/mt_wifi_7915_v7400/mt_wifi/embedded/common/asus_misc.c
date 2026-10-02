#ifdef ASUS_EXT
#include "rt_config.h"
#include <linux/mtd/mtd.h>
/* ASUS EXT */
#define ASUS_NVRAM             /* ASUS EXT */
#include <nvram/bcmnvram.h>    /* ASUS EXT */
/* ASUS EXT */
#include <linux/version.h>

u_char reg_spec[MAX_REGSPEC_LEN + 1];
#if defined(MT7628) || defined(MT7603)
u_char reg_spec_2g[MAX_REGDOMAIN_LEN + 1];
#elif defined(MT7612)
u_char reg_spec_5g[MAX_REGDOMAIN_LEN + 2];
#elif defined(MT7615) || defined(MT7626) || defined(MT7915)
u_char reg_spec_2g[MAX_REGDOMAIN_LEN + 1];
u_char reg_spec_5g[MAX_REGDOMAIN_LEN + 2];
#elif defined(MT7663)
u_char reg_spec_5g[MAX_REGDOMAIN_LEN + 2];
#else
#error invalid product!!
#endif

static int need_to_change = 0;

#if 0
int mtd_local_read(u_char *cal_part,loff_t from, size_t len,
		size_t *retlen, u_char *buf)
{
	int r;
	struct mtd_info *mtd;

	if (!cal_part || *cal_part == '\0' || !buf)
		return -EINVAL;

	//printk("%s: cal_part [%s] from %llx len %x\n", __func__, cal_part, from, len);
	mtd = get_mtd_device_nm(cal_part);

	if (IS_ERR(mtd)) {
		printk("Get %s MTD partition fail! (error %ld)\n", mtd->name, PTR_ERR(mtd));
		return -EPERM;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,14)
	r = mtd->_read(mtd, from, len, retlen, buf);
#else
	r = mtd->read(mtd, from, len, retlen, buf);
#endif
	put_mtd_device(mtd);

	printk("%s: cal_part [%s] from %llx lend %x retlen %x\n", __func__, cal_part, from, len, *retlen);
	
	return r;
}

int get_eeprom_para(loff_t from, size_t len, u_char *buf)
{
	u_char *ptr = NULL;
	int ret_val = 0, ret_len;

	ptr = vmalloc(len);
	if (ptr == NULL) {

		MTWF_LOG(DBG_CAT_ALL, DBG_SUBCAT_ALL, DBG_LVL_OFF,("%s %d: flash cal data allocation failed\n",__func__, __LINE__));
		return 1;
	}
	else 
	{
		ret_val = mtd_local_read("Factory", from, len, &ret_len, ptr);
		if (ret_val){

			MTWF_LOG(DBG_CAT_ALL, DBG_SUBCAT_ALL, DBG_LVL_OFF, ("%s %d: flash cal data read failed\n",__func__, __LINE__));
			if (ptr) vfree(ptr);
			return 1;
		}
		else
		{
			//snprintf(buf, len, "%s", ptr);
			memcpy(buf, ptr, len);			
/*#if defined(MT7628)
			MTWF_LOG(DBG_CAT_ALL, DBG_SUBCAT_ALL, DBG_LVL_OFF,
#else
			DBGPRINT(RT_DEBUG_ERROR,
#endif
									 ("%s %d: len %x ret_len %x %s\n", __func__, __LINE__, len, ret_len, buf));
*/
		}
	}
        
	if (ptr) vfree(ptr);

	return 0;
}
#endif
#if defined(CONFIG_MODEL_RTAC1200) || defined(CONFIG_MODEL_RTN11PB1)
#if defined(MT7628)
void convertCountryCode2G(unsigned char *dst)
{
	int i = 0;

	for(i = 0; i < MAX_REGDOMAIN_LEN; i++)
		if(dst[i] == 0xff || dst[i] == 0)
			break;
	dst[i] = 0;

	nvram_set(WL_REG_5G, dst);
	if      (strcmp(dst, "2G_CH11") == 0)
		nvram_set("wl0_country_code", "US");
	else if (strcmp(dst, "2G_CH13") == 0)
		nvram_set("wl0_country_code", "GB");
	else if (strcmp(dst, "2G_CH14") == 0)
		nvram_set("wl0_country_code", "DB");
	else
		nvram_set("wl0_country_code", "DB");
}

int getCountryRegion2G(const char *countryCode)
{
	if (countryCode == NULL)
	{
		return 5;	// 1-14
	}
	else if((strcasecmp(countryCode, "CA") == 0) || (strcasecmp(countryCode, "CO") == 0) ||
		(strcasecmp(countryCode, "DO") == 0) || (strcasecmp(countryCode, "GT") == 0) ||
		(strcasecmp(countryCode, "MX") == 0) || (strcasecmp(countryCode, "NO") == 0) ||
		(strcasecmp(countryCode, "PA") == 0) || (strcasecmp(countryCode, "PR") == 0) ||
		(strcasecmp(countryCode, "TW") == 0) || (strcasecmp(countryCode, "US") == 0) ||
		(strcasecmp(countryCode, "UZ") == 0) || 
		(strcasecmp(countryCode, "Z1") == 0) || (strcasecmp(countryCode, "Z3") == 0)  
		)
	{
		return 0;	// 1-11
	}
	else if (strcasecmp(countryCode, "DB") == 0  || strcasecmp(countryCode, "") == 0)
	{
		return 5;	// 1-14
	}

	return 1;	// 1-13
}
#endif	/* defined(MT7628) || defined(MT7603) */

#if defined(MT7612)
void convertCountryCode5G(unsigned char *dst)
{
	int i = 0;

	for(i = 0; i < MAX_REGDOMAIN_LEN; i++)
		if(dst[i] == 0xff || dst[i] == 0)
			break;

	dst[i] = 0;
	nvram_set(WL_REG_5G, dst);
	if      (strcmp(dst, "5G_BAND1") == 0)
		nvram_set("wl1_country_code", "GB");
	else if (strcmp(dst, "5G_BAND123") == 0)
		nvram_set("wl1_country_code", "GB");
	else if (strcmp(dst, "5G_BAND14") == 0)
		nvram_set("wl1_country_code", "US");
	else if (strcmp(dst, "5G_BAND24") == 0)
		nvram_set("wl1_country_code", "TW");
	else if (strcmp(dst, "5G_BAND4") == 0)
		nvram_set("wl1_country_code", "CN");
	else if (strcmp(dst, "5G_BAND124") == 0)
		nvram_set("wl1_country_code", "IN");
	else
		nvram_set("wl1_country_code", "DB");
}

int getCountryRegion5G(const char *countryCode)
{
	if (		(!strcasecmp(countryCode, "AE")) ||
			(!strcasecmp(countryCode, "AL")) ||
#ifdef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "AR")) ||
#endif
			(!strcasecmp(countryCode, "AU")) ||
			(!strcasecmp(countryCode, "BH")) ||
			(!strcasecmp(countryCode, "BY")) ||
			(!strcasecmp(countryCode, "CA")) ||
			(!strcasecmp(countryCode, "CL")) ||
			(!strcasecmp(countryCode, "CO")) ||
			(!strcasecmp(countryCode, "CR")) ||
			(!strcasecmp(countryCode, "DO")) ||
			(!strcasecmp(countryCode, "DZ")) ||
			(!strcasecmp(countryCode, "EC")) ||
			(!strcasecmp(countryCode, "GT")) ||
			(!strcasecmp(countryCode, "HK")) ||
			(!strcasecmp(countryCode, "HN")) ||
			(!strcasecmp(countryCode, "IL")) ||
#ifndef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "IN")) ||
#endif
			(!strcasecmp(countryCode, "JO")) ||
			(!strcasecmp(countryCode, "KW")) ||
			(!strcasecmp(countryCode, "KZ")) ||
			(!strcasecmp(countryCode, "LB")) ||
			(!strcasecmp(countryCode, "MA")) ||
			(!strcasecmp(countryCode, "MK")) ||
#ifndef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "MO")) ||
			(!strcasecmp(countryCode, "MX")) ||
#endif
			(!strcasecmp(countryCode, "MY")) ||
#ifndef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "NO")) ||
#endif
			(!strcasecmp(countryCode, "NZ")) ||
			(!strcasecmp(countryCode, "OM")) ||
			(!strcasecmp(countryCode, "PA")) ||
			(!strcasecmp(countryCode, "PK")) ||
			(!strcasecmp(countryCode, "PR")) ||
			(!strcasecmp(countryCode, "QA")) ||
#ifndef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "RO")) ||
			(!strcasecmp(countryCode, "RU")) ||
#endif
			(!strcasecmp(countryCode, "SA")) ||
			(!strcasecmp(countryCode, "SG")) ||
			(!strcasecmp(countryCode, "SV")) ||
			(!strcasecmp(countryCode, "SY")) ||
			(!strcasecmp(countryCode, "TH")) ||
#ifndef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "UA")) ||
#endif
			(!strcasecmp(countryCode, "US")) ||
#ifdef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "UY")) ||
#endif
			(!strcasecmp(countryCode, "VN")) ||
			(!strcasecmp(countryCode, "YE")) ||
			(!strcasecmp(countryCode, "ZW")) ||
#if defined(RTN65U)
			//for specific power
			(!strcasecmp(countryCode, "Z1")) 
#else
			0
#endif
	)
	{
		return 0;
	}
	else if (
#ifdef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "AM")) ||
#endif
			(!strcasecmp(countryCode, "AT")) ||
#ifdef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "AZ")) ||
#endif
			(!strcasecmp(countryCode, "BE")) ||
			(!strcasecmp(countryCode, "BG")) ||
#ifndef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "BR")) ||
#endif
			(!strcasecmp(countryCode, "CH")) ||
			(!strcasecmp(countryCode, "CY")) ||
#ifdef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "CZ")) ||wl0_country_code=US
#endif
			(!strcasecmp(countryCode, "DE")) ||
			(!strcasecmp(countryCode, "DK")) ||
			(!strcasecmp(countryCode, "EE")) ||
#ifdef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "EG")) ||
#endif
			(!strcasecmp(countryCode, "ES")) ||
			(!strcasecmp(countryCode, "FI")) ||
#ifdef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "FR")) ||
#endif
			(!strcasecmp(countryCode, "GB")) ||
#ifdef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "GE")) ||
#endif
			(!strcasecmp(countryCode, "GR")) ||
#ifdef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "HR")) ||
#endif
			(!strcasecmp(countryCode, "HU")) ||
			(!strcasecmp(countryCode, "IE")) ||
			(!strcasecmp(countryCode, "IS")) ||
			(!strcasecmp(countryCode, "IT")) ||
#ifdef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "JP")) ||
			(!strcasecmp(countryCode, "KP")) ||
			(!strcasecmp(countryCode, "KR")) ||
#endif
			(!strcasecmp(countryCode, "LI")) ||
			(!strcasecmp(countryCode, "LT")) ||
			(!strcasecmp(countryCode, "LU")) ||
			(!strcasecmp(countryCode, "LV")) ||
#ifdef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "MC")) ||
#endif
			(!strcasecmp(countryCode, "NL")) ||
#ifdef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "NO")) ||
#endif
			(!strcasecmp(countryCode, "PL")) ||
			(!strcasecmp(countryCode, "PT")) ||
#ifdef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "RO")) ||
#endif
			(!strcasecmp(countryCode, "SE")) ||
			(!strcasecmp(countryCode, "SI")) ||
			(!strcasecmp(countryCode, "SK")) ||
#ifdef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "TN")) ||
			(!strcasecmp(countryCode, "TR")) ||
			(!strcasecmp(countryCode, "TT")) ||
#endif
			(!strcasecmp(countryCode, "UZ")) ||
			(!strcasecmp(countryCode, "ZA")) ||
#if defined(RTN65U)
			//for specific power
			(!strcasecmp(countryCode, "Z2"))
#else
			0
#endif
	)
	{
		return 1;
	}
	else if (
#ifndef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "AM")) ||
			(!strcasecmp(countryCode, "AZ")) ||
			(!strcasecmp(countryCode, "CZ")) ||
			(!strcasecmp(countryCode, "EG")) ||
			(!strcasecmp(countryCode, "FR")) ||
			(!strcasecmp(countryCode, "GE")) ||
			(!strcasecmp(countryCode, "HR")) ||
			(!strcasecmp(countryCode, "MC")) ||
			(!strcasecmp(countryCode, "TN")) ||
			(!strcasecmp(countryCode, "TR")) ||
			(!strcasecmp(countryCode, "TT"))
#else
			(!strcasecmp(countryCode, "IN")) ||
			(!strcasecmp(countryCode, "MX"))
#endif
	)
	{
		return 2;
	}
	else if (
#ifndef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "AR")) ||
#endif
			(!strcasecmp(countryCode, "TW")) ||
#if defined(RTN65U)
			//for specific power
			(!strcasecmp(countryCode, "Z3")) 
#else
			0
#endif
	)
	{
		return 3;
	}
	else if (
#ifdef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "BR")) ||
#endif
			(!strcasecmp(countryCode, "BZ")) ||
			(!strcasecmp(countryCode, "BO")) ||
			(!strcasecmp(countryCode, "BN")) ||
			(!strcasecmp(countryCode, "CN")) ||
			(!strcasecmp(countryCode, "ID")) ||
			(!strcasecmp(countryCode, "IR")) ||
#ifdef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "MO")) ||
#endif
			(!strcasecmp(countryCode, "PE")) ||
			(!strcasecmp(countryCode, "PH"))
#ifdef RTCONFIG_LOCALE2012
						 ||
			(!strcasecmp(countryCode, "VE"))
#endif
						 ||
#if defined(RTN65U)
			//for specific power
			(!strcasecmp(countryCode, "Z4")) 
#else
			0
#endif
	)
	{
		return 4;
	}
#ifndef RTCONFIG_LOCALE2012
	else if (	(!strcasecmp(countryCode, "KP")) ||
			(!strcasecmp(countryCode, "KR")) ||
			(!strcasecmp(countryCode, "UY")) ||
			(!strcasecmp(countryCode, "VE"))
	)
	{
		return 5;
	}
#else
	else if (!strcasecmp(countryCode, "RU"))
	{
		return 6;
	}
#endif
	else if (!strcasecmp(countryCode, "DB"))
	{
		return 7;
	}
	else if (
#ifndef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "JP"))
#else
			(!strcasecmp(countryCode, "UA"))
#endif
	)
	{
		return 9;
	}
	else
	{
		return 7;
	}
}
#endif	/* defined(MT7612) */

#elif defined(CONFIG_MODEL_RPAC56)  || defined(CONFIG_MODEL_RTAC1200GA1) || defined(CONFIG_MODEL_RTAC1200GU)
#if defined(MT7603)
void convertReg2G(unsigned char *str)
{
	int i = 0;

	for(i = 0; i < MAX_REGDOMAIN_LEN; i++)
		if(str[i] == 0xff || str[i] == 0)
			break;
	str[i] = 0;

	nvram_set(WL_REG_2G, str);
}

int getCountryRegion2G(char *str)
{
	if (strcmp(str,"2G_CH11")==0)
		return 0;
	else if (strcmp(str,"2G_CH14")==0)
		return 5;
	else
		return 1;
}

#elif defined(MT7612)
void convertReg5G(unsigned char *str)
{
	int i = 0;

	for(i = 0; i < MAX_REGDOMAIN_LEN; i++)
		if(str[i] == 0xff || str[i] == 0)
			break;

	str[i] = 0;
	nvram_set(WL_REG_5G, str);
}

int getCountryRegion5G(char *str)
{
	// reference MTK driver include/rtmp_def.h, REGION_0_A_BAND - REGION_16_A_BAND
	if (strcmp(str,"5G_BAND14")==0)
		return 10;
	else if (strcmp(str,"5G_BAND24")==0)
		return 16;
	else if (strcmp(str,"5G_BAND1")==0)
		return 6;
	else if (strcmp(str,"5G_BAND4")==0)
		return 4;
	else if (strcmp(str,"5G_BAND123")==0)
#ifdef DFS_SUPPORT
		return 1;
#else
		return 6;
#endif
#if 0
#ifdef EEPROM_BACKWARD_COMPATIBILITY
	else if (strcmp(str,"5G_BAND124")==0)
		return 0;
	else if (strcmp(str,"5G_BAND12")==0)
		return 2;
	else if (strcmp(str,"5G_BAND24_")==0)
		return 3;
	else if (strcmp(str,"5G_BAND4_")==0)
		return 5;
	else if (strcmp(str,"5G_ALL_")==0)
		return 9;
#endif
#endif
	else if (strcmp(str,"5G_ALL")==0)
		return 7;
	else
		return 7;
}
#endif
#endif	/* CONFIG_MODEL_RTAC1200 */

#if defined(MT7615) || defined(MT7626) || defined(MT7915)
void convertCountryCode2G(unsigned char *dst)
{
	int i = 0;

	for(i = 0; i < MAX_REGDOMAIN_LEN; i++)
		if(dst[i] == 0xff || dst[i] == 0)
			break;
	dst[i] = 0;

	nvram_set(WL_REG_5G, dst);
	if      (strcmp(dst, "2G_CH11") == 0)
		nvram_set("wl0_country_code", "US");
	else if (strcmp(dst, "2G_CH13") == 0)
		nvram_set("wl0_country_code", "GB");
	else if (strcmp(dst, "2G_CH14") == 0)
		nvram_set("wl0_country_code", "DB");
	else
		nvram_set("wl0_country_code", "DB");
}

int getCountryRegion2G(const char *countryCode)
{
	if (countryCode == NULL)
	{
		return 5;	// 1-14
	}
	else if((strcasecmp(countryCode, "CA") == 0) || (strcasecmp(countryCode, "CO") == 0) ||
		(strcasecmp(countryCode, "DO") == 0) || (strcasecmp(countryCode, "GT") == 0) ||
		(strcasecmp(countryCode, "MX") == 0) || (strcasecmp(countryCode, "NO") == 0) ||
		(strcasecmp(countryCode, "PA") == 0) || (strcasecmp(countryCode, "PR") == 0) ||
		(strcasecmp(countryCode, "TW") == 0) || (strcasecmp(countryCode, "US") == 0) ||
		(strcasecmp(countryCode, "UZ") == 0) || 
		(strcasecmp(countryCode, "Z1") == 0) || (strcasecmp(countryCode, "Z3") == 0)  
		)
	{
		return 0;	// 1-11
	}
	else if (strcasecmp(countryCode, "DB") == 0  || strcasecmp(countryCode, "") == 0)
	{
		return 5;	// 1-14
	}

	return 1;	// 1-13
}

void convertCountryCode5G(unsigned char *dst)
{
	int i = 0;

	for(i = 0; i < MAX_REGDOMAIN_LEN; i++)
		if(dst[i] == 0xff || dst[i] == 0)
			break;

	dst[i] = 0;
	nvram_set(WL_REG_5G, dst);
	if      (strcmp(dst, "5G_BAND1") == 0)
		nvram_set("wl1_country_code", "GB");
	else if (strcmp(dst, "5G_BAND123") == 0)
		nvram_set("wl1_country_code", "GB");
	else if (strcmp(dst, "5G_BAND14") == 0)
		nvram_set("wl1_country_code", "US");
	else if (strcmp(dst, "5G_BAND24") == 0)
		nvram_set("wl1_country_code", "TW");
	else if (strcmp(dst, "5G_BAND4") == 0)
		nvram_set("wl1_country_code", "CN");
	else if (strcmp(dst, "5G_BAND124") == 0)
		nvram_set("wl1_country_code", "IN");
	else
		nvram_set("wl1_country_code", "DB");
}

int getCountryRegion5G(const char *countryCode)
{
	if (		(!strcasecmp(countryCode, "AE")) ||
			(!strcasecmp(countryCode, "AL")) ||
#ifdef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "AR")) ||
#endif
			(!strcasecmp(countryCode, "AU")) ||
			(!strcasecmp(countryCode, "BH")) ||
			(!strcasecmp(countryCode, "BY")) ||
			(!strcasecmp(countryCode, "CA")) ||
			(!strcasecmp(countryCode, "CL")) ||
			(!strcasecmp(countryCode, "CO")) ||
			(!strcasecmp(countryCode, "CR")) ||
			(!strcasecmp(countryCode, "DO")) ||
			(!strcasecmp(countryCode, "DZ")) ||
			(!strcasecmp(countryCode, "EC")) ||
			(!strcasecmp(countryCode, "GT")) ||
			(!strcasecmp(countryCode, "HK")) ||
			(!strcasecmp(countryCode, "HN")) ||
			(!strcasecmp(countryCode, "IL")) ||
#ifndef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "IN")) ||
#endif
			(!strcasecmp(countryCode, "JO")) ||
			(!strcasecmp(countryCode, "KW")) ||
			(!strcasecmp(countryCode, "KZ")) ||
			(!strcasecmp(countryCode, "LB")) ||
			(!strcasecmp(countryCode, "MA")) ||
			(!strcasecmp(countryCode, "MK")) ||
#ifndef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "MO")) ||
			(!strcasecmp(countryCode, "MX")) ||
#endif
			(!strcasecmp(countryCode, "MY")) ||
#ifndef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "NO")) ||
#endif
			(!strcasecmp(countryCode, "NZ")) ||
			(!strcasecmp(countryCode, "OM")) ||
			(!strcasecmp(countryCode, "PA")) ||
			(!strcasecmp(countryCode, "PK")) ||
			(!strcasecmp(countryCode, "PR")) ||
			(!strcasecmp(countryCode, "QA")) ||
#ifndef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "RO")) ||
			(!strcasecmp(countryCode, "RU")) ||
#endif
			(!strcasecmp(countryCode, "SA")) ||
			(!strcasecmp(countryCode, "SG")) ||
			(!strcasecmp(countryCode, "SV")) ||
			(!strcasecmp(countryCode, "SY")) ||
			(!strcasecmp(countryCode, "TH")) ||
#ifndef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "UA")) ||
#endif
			(!strcasecmp(countryCode, "US")) ||
#ifdef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "UY")) ||
#endif
			(!strcasecmp(countryCode, "VN")) ||
			(!strcasecmp(countryCode, "YE")) ||
			(!strcasecmp(countryCode, "ZW")) ||
#if defined(RTN65U)
			//for specific power
			(!strcasecmp(countryCode, "Z1")) 
#else
			0
#endif
	)
	{
		return 0;
	}
	else if (
#ifdef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "AM")) ||
#endif
			(!strcasecmp(countryCode, "AT")) ||
#ifdef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "AZ")) ||
#endif
			(!strcasecmp(countryCode, "BE")) ||
			(!strcasecmp(countryCode, "BG")) ||
#ifndef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "BR")) ||
#endif
			(!strcasecmp(countryCode, "CH")) ||
			(!strcasecmp(countryCode, "CY")) ||
#ifdef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "CZ")) ||
#endif
			(!strcasecmp(countryCode, "DE")) ||
			(!strcasecmp(countryCode, "DK")) ||
			(!strcasecmp(countryCode, "EE")) ||
#ifdef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "EG")) ||
#endif
			(!strcasecmp(countryCode, "ES")) ||
			(!strcasecmp(countryCode, "FI")) ||
#ifdef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "FR")) ||
#endif
			(!strcasecmp(countryCode, "GB")) ||
#ifdef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "GE")) ||
#endif
			(!strcasecmp(countryCode, "GR")) ||
#ifdef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "HR")) ||
#endif
			(!strcasecmp(countryCode, "HU")) ||
			(!strcasecmp(countryCode, "IE")) ||
			(!strcasecmp(countryCode, "IS")) ||
			(!strcasecmp(countryCode, "IT")) ||
#ifdef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "JP")) ||
			(!strcasecmp(countryCode, "KP")) ||
			(!strcasecmp(countryCode, "KR")) ||
#endif
			(!strcasecmp(countryCode, "LI")) ||
			(!strcasecmp(countryCode, "LT")) ||
			(!strcasecmp(countryCode, "LU")) ||
			(!strcasecmp(countryCode, "LV")) ||
#ifdef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "MC")) ||
#endif
			(!strcasecmp(countryCode, "NL")) ||
#ifdef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "NO")) ||
#endif
			(!strcasecmp(countryCode, "PL")) ||
			(!strcasecmp(countryCode, "PT")) ||
#ifdef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "RO")) ||
#endif
			(!strcasecmp(countryCode, "SE")) ||
			(!strcasecmp(countryCode, "SI")) ||
			(!strcasecmp(countryCode, "SK")) ||
#ifdef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "TN")) ||
			(!strcasecmp(countryCode, "TR")) ||
			(!strcasecmp(countryCode, "TT")) ||
#endif
			(!strcasecmp(countryCode, "UZ")) ||
			(!strcasecmp(countryCode, "ZA")) ||
#if defined(RTN65U)
			//for specific power
			(!strcasecmp(countryCode, "Z2"))
#else
			0
#endif
	)
	{
		return 1;
	}
	else if (
#ifndef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "AM")) ||
			(!strcasecmp(countryCode, "AZ")) ||
			(!strcasecmp(countryCode, "CZ")) ||
			(!strcasecmp(countryCode, "EG")) ||
			(!strcasecmp(countryCode, "FR")) ||
			(!strcasecmp(countryCode, "GE")) ||
			(!strcasecmp(countryCode, "HR")) ||
			(!strcasecmp(countryCode, "MC")) ||
			(!strcasecmp(countryCode, "TN")) ||
			(!strcasecmp(countryCode, "TR")) ||
			(!strcasecmp(countryCode, "TT"))
#else
			(!strcasecmp(countryCode, "IN")) ||
			(!strcasecmp(countryCode, "MX"))
#endif
	)
	{
		return 2;
	}
	else if (
#ifndef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "AR")) ||
#endif
			(!strcasecmp(countryCode, "TW")) ||
#if defined(RTN65U)
			//for specific power
			(!strcasecmp(countryCode, "Z3")) 
#else
			0
#endif
	)
	{
		return 3;
	}
	else if (
#ifdef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "BR")) ||
#endif
			(!strcasecmp(countryCode, "BZ")) ||
			(!strcasecmp(countryCode, "BO")) ||
			(!strcasecmp(countryCode, "BN")) ||
			(!strcasecmp(countryCode, "CN")) ||
			(!strcasecmp(countryCode, "ID")) ||
			(!strcasecmp(countryCode, "IR")) ||
#ifdef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "MO")) ||
#endif
			(!strcasecmp(countryCode, "PE")) ||
			(!strcasecmp(countryCode, "PH"))
#ifdef RTCONFIG_LOCALE2012
						 ||
			(!strcasecmp(countryCode, "VE"))
#endif
						 ||
#if defined(RTN65U)
			//for specific power
			(!strcasecmp(countryCode, "Z4")) 
#else
			0
#endif
	)
	{
		return 4;
	}
#ifndef RTCONFIG_LOCALE2012
	else if (	(!strcasecmp(countryCode, "KP")) ||
			(!strcasecmp(countryCode, "KR")) ||
			(!strcasecmp(countryCode, "UY")) ||
			(!strcasecmp(countryCode, "VE"))
	)
	{
		return 5;
	}
#else
	else if (!strcasecmp(countryCode, "RU"))
	{
		return 6;
	}
#endif
	else if (!strcasecmp(countryCode, "DB"))
	{
		return 7;
	}
	else if (
#ifndef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "JP"))
#else
			(!strcasecmp(countryCode, "UA"))
#endif
	)
	{
		return 9;
	}
	else
	{
		return 7;
	}
}
#endif

#if defined(MT7663)
void convertCountryCode2G(unsigned char *dst)
{
	int i = 0;

	for(i = 0; i < MAX_REGDOMAIN_LEN; i++)
		if(dst[i] == 0xff || dst[i] == 0)
			break;
	dst[i] = 0;

	nvram_set(WL_REG_5G, dst);
	if      (strcmp(dst, "2G_CH11") == 0)
		nvram_set("wl0_country_code", "US");
	else if (strcmp(dst, "2G_CH13") == 0)
		nvram_set("wl0_country_code", "GB");
	else if (strcmp(dst, "2G_CH14") == 0)
		nvram_set("wl0_country_code", "DB");
	else
		nvram_set("wl0_country_code", "DB");
}

int getCountryRegion2G(const char *countryCode)
{
	if (countryCode == NULL)
	{
		return 5;	// 1-14
	}
	else if((strcasecmp(countryCode, "CA") == 0) || (strcasecmp(countryCode, "CO") == 0) ||
		(strcasecmp(countryCode, "DO") == 0) || (strcasecmp(countryCode, "GT") == 0) ||
		(strcasecmp(countryCode, "MX") == 0) || (strcasecmp(countryCode, "NO") == 0) ||
		(strcasecmp(countryCode, "PA") == 0) || (strcasecmp(countryCode, "PR") == 0) ||
		(strcasecmp(countryCode, "TW") == 0) || (strcasecmp(countryCode, "US") == 0) ||
		(strcasecmp(countryCode, "UZ") == 0) || 
		(strcasecmp(countryCode, "Z1") == 0) || (strcasecmp(countryCode, "Z3") == 0)  
		)
	{
		return 0;	// 1-11
	}
	else if (strcasecmp(countryCode, "DB") == 0  || strcasecmp(countryCode, "") == 0)
	{
		return 5;	// 1-14
	}

	return 1;	// 1-13
}

void convertCountryCode5G(unsigned char *dst)
{
	int i = 0;

	for(i = 0; i < MAX_REGDOMAIN_LEN; i++)
		if(dst[i] == 0xff || dst[i] == 0)
			break;

	dst[i] = 0;
	nvram_set(WL_REG_5G, dst);
	if      (strcmp(dst, "5G_BAND1") == 0)
		nvram_set("wl1_country_code", "GB");
	else if (strcmp(dst, "5G_BAND123") == 0)
		nvram_set("wl1_country_code", "GB");
	else if (strcmp(dst, "5G_BAND14") == 0)
		nvram_set("wl1_country_code", "US");
	else if (strcmp(dst, "5G_BAND24") == 0)
		nvram_set("wl1_country_code", "TW");
	else if (strcmp(dst, "5G_BAND4") == 0)
		nvram_set("wl1_country_code", "CN");
	else if (strcmp(dst, "5G_BAND124") == 0)
		nvram_set("wl1_country_code", "IN");
	else if (strcmp(dst, "5G_BAND12") == 0)
		nvram_set("wl1_country_code", "IL");
	else
		nvram_set("wl1_country_code", "DB");
}

int getCountryRegion5G(const char *countryCode)
{
	if (		(!strcasecmp(countryCode, "AE")) ||
			(!strcasecmp(countryCode, "AL")) ||
#ifdef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "AR")) ||
#endif
			(!strcasecmp(countryCode, "AU")) ||
			(!strcasecmp(countryCode, "BH")) ||
			(!strcasecmp(countryCode, "BY")) ||
			(!strcasecmp(countryCode, "CA")) ||
			(!strcasecmp(countryCode, "CL")) ||
			(!strcasecmp(countryCode, "CO")) ||
			(!strcasecmp(countryCode, "CR")) ||
			(!strcasecmp(countryCode, "DO")) ||
			(!strcasecmp(countryCode, "DZ")) ||
			(!strcasecmp(countryCode, "EC")) ||
			(!strcasecmp(countryCode, "GT")) ||
			(!strcasecmp(countryCode, "HK")) ||
			(!strcasecmp(countryCode, "HN")) ||
//			(!strcasecmp(countryCode, "IL")) ||
#ifndef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "IN")) ||
#endif
			(!strcasecmp(countryCode, "JO")) ||
			(!strcasecmp(countryCode, "KW")) ||
			(!strcasecmp(countryCode, "KZ")) ||
			(!strcasecmp(countryCode, "LB")) ||
			(!strcasecmp(countryCode, "MA")) ||
			(!strcasecmp(countryCode, "MK")) ||
#ifndef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "MO")) ||
			(!strcasecmp(countryCode, "MX")) ||
#endif
			(!strcasecmp(countryCode, "MY")) ||
#ifndef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "NO")) ||
#endif
			(!strcasecmp(countryCode, "NZ")) ||
			(!strcasecmp(countryCode, "OM")) ||
			(!strcasecmp(countryCode, "PA")) ||
			(!strcasecmp(countryCode, "PK")) ||
			(!strcasecmp(countryCode, "PR")) ||
			(!strcasecmp(countryCode, "QA")) ||
#ifndef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "RO")) ||
			(!strcasecmp(countryCode, "RU")) ||
#endif
			(!strcasecmp(countryCode, "SA")) ||
			(!strcasecmp(countryCode, "SG")) ||
			(!strcasecmp(countryCode, "SV")) ||
			(!strcasecmp(countryCode, "SY")) ||
			(!strcasecmp(countryCode, "TH")) ||
#ifndef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "UA")) ||
#endif
			(!strcasecmp(countryCode, "US")) ||
#ifdef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "UY")) ||
#endif
			(!strcasecmp(countryCode, "VN")) ||
			(!strcasecmp(countryCode, "YE")) ||
			(!strcasecmp(countryCode, "ZW")) ||
#if defined(RTN65U)
			//for specific power
			(!strcasecmp(countryCode, "Z1")) 
#else
			0
#endif
	)
	{
		return 0;
	}
	else if (
#ifdef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "AM")) ||
#endif
			(!strcasecmp(countryCode, "AT")) ||
#ifdef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "AZ")) ||
#endif
			(!strcasecmp(countryCode, "BE")) ||
			(!strcasecmp(countryCode, "BG")) ||
#ifndef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "BR")) ||
#endif
			(!strcasecmp(countryCode, "CH")) ||
			(!strcasecmp(countryCode, "CY")) ||
#ifdef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "CZ")) ||
#endif
			(!strcasecmp(countryCode, "DE")) ||
			(!strcasecmp(countryCode, "DK")) ||
			(!strcasecmp(countryCode, "EE")) ||
#ifdef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "EG")) ||
#endif
			(!strcasecmp(countryCode, "ES")) ||
			(!strcasecmp(countryCode, "FI")) ||
#ifdef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "FR")) ||
#endif
			(!strcasecmp(countryCode, "GB")) ||
#ifdef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "GE")) ||
#endif
			(!strcasecmp(countryCode, "GR")) ||
#ifdef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "HR")) ||
#endif
			(!strcasecmp(countryCode, "HU")) ||
			(!strcasecmp(countryCode, "IE")) ||
			(!strcasecmp(countryCode, "IS")) ||
			(!strcasecmp(countryCode, "IT")) ||
#ifdef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "JP")) ||
			(!strcasecmp(countryCode, "KP")) ||
			(!strcasecmp(countryCode, "KR")) ||
#endif
			(!strcasecmp(countryCode, "LI")) ||
			(!strcasecmp(countryCode, "LT")) ||
			(!strcasecmp(countryCode, "LU")) ||
			(!strcasecmp(countryCode, "LV")) ||
#ifdef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "MC")) ||
#endif
			(!strcasecmp(countryCode, "NL")) ||
#ifdef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "NO")) ||
#endif
			(!strcasecmp(countryCode, "PL")) ||
			(!strcasecmp(countryCode, "PT")) ||
#ifdef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "RO")) ||
#endif
			(!strcasecmp(countryCode, "SE")) ||
			(!strcasecmp(countryCode, "SI")) ||
			(!strcasecmp(countryCode, "SK")) ||
#ifdef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "TN")) ||
			(!strcasecmp(countryCode, "TR")) ||
			(!strcasecmp(countryCode, "TT")) ||
#endif
			(!strcasecmp(countryCode, "UZ")) ||
			(!strcasecmp(countryCode, "ZA")) ||
#if defined(RTN65U)
			//for specific power
			(!strcasecmp(countryCode, "Z2"))
#else
			0
#endif
	)
	{
		return 1;
	}
	else if (
#ifndef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "AM")) ||
			(!strcasecmp(countryCode, "AZ")) ||
			(!strcasecmp(countryCode, "CZ")) ||
			(!strcasecmp(countryCode, "EG")) ||
			(!strcasecmp(countryCode, "FR")) ||
			(!strcasecmp(countryCode, "GE")) ||
			(!strcasecmp(countryCode, "HR")) ||
			(!strcasecmp(countryCode, "MC")) ||
			(!strcasecmp(countryCode, "TN")) ||
			(!strcasecmp(countryCode, "TR")) ||
			(!strcasecmp(countryCode, "TT"))
#else
			(!strcasecmp(countryCode, "IN")) ||
			(!strcasecmp(countryCode, "IL")) ||
			(!strcasecmp(countryCode, "MX"))
#endif
	)
	{
		return 2;
	}
	else if (
#ifndef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "AR")) ||
#endif
			(!strcasecmp(countryCode, "TW")) ||
#if defined(RTN65U)
			//for specific power
			(!strcasecmp(countryCode, "Z3")) 
#else
			0
#endif
	)
	{
		return 3;
	}
	else if (
#ifdef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "BR")) ||
#endif
			(!strcasecmp(countryCode, "BZ")) ||
			(!strcasecmp(countryCode, "BO")) ||
			(!strcasecmp(countryCode, "BN")) ||
			(!strcasecmp(countryCode, "CN")) ||
			(!strcasecmp(countryCode, "ID")) ||
			(!strcasecmp(countryCode, "IR")) ||
#ifdef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "MO")) ||
#endif
			(!strcasecmp(countryCode, "PE")) ||
			(!strcasecmp(countryCode, "PH"))
#ifdef RTCONFIG_LOCALE2012
						 ||
			(!strcasecmp(countryCode, "VE"))
#endif
						 ||
#if defined(RTN65U)
			//for specific power
			(!strcasecmp(countryCode, "Z4")) 
#else
			0
#endif
	)
	{
		return 4;
	}
#ifndef RTCONFIG_LOCALE2012
	else if (	(!strcasecmp(countryCode, "KP")) ||
			(!strcasecmp(countryCode, "KR")) ||
			(!strcasecmp(countryCode, "UY")) ||
			(!strcasecmp(countryCode, "VE"))
	)
	{
		return 5;
	}
#else
	else if (!strcasecmp(countryCode, "RU"))
	{
		return 6;
	}
#endif
	else if (!strcasecmp(countryCode, "DB"))
	{
		return 7;
	}
	else if (
#ifndef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "JP"))
#else
			(!strcasecmp(countryCode, "UA"))
#endif
	)
	{
		return 9;
	}
	else
	{
		return 7;
	}
}
#endif /* MT7663 */

void check_runtime_para(char *regspec, char *regspec_2g, char *regspec_5g)
{
	//int ret_val = 1;
	//int i = 0;

	/* init para */
	need_to_change = 0;

#ifdef MODULE
	memset(reg_spec, 0, MAX_REGSPEC_LEN + 1);
#if defined(MT7628) || defined(MT7603)
	memset(reg_spec_2g, 0, MAX_REGDOMAIN_LEN + 1);
#elif defined(MT7612)
	memset(reg_spec_5g, 0, MAX_REGDOMAIN_LEN + 2);
#elif defined(MT7615) || defined(MT7626) || defined(MT7915)
	memset(reg_spec_2g, 0, MAX_REGDOMAIN_LEN + 1);
	memset(reg_spec_5g, 0, MAX_REGDOMAIN_LEN + 2);
#elif defined(MT7663)
	memset(reg_spec_5g, 0, MAX_REGDOMAIN_LEN + 2);
#endif
#if 0
	ret_val = get_eeprom_para(REGSPEC_ADDR, MAX_REGSPEC_LEN, reg_spec);
	if (!ret_val) {
		if(reg_spec[0] == 0xff || reg_spec[0] == 0x0) {

			MTWF_LOG(DBG_CAT_ALL, DBG_SUBCAT_ALL, DBG_LVL_OFF,("%s %d: invalid value for reg_spec\n", __func__, __LINE__));
			return;
		}

		for (i=(MAX_REGSPEC_LEN-1) ; i>=0 ; i--) {
			if ((reg_spec[i] == 0xff) || (reg_spec[i] == '\0'))
				reg_spec[i] = '\0';
		}


		//MTWF_LOG(DBG_CAT_ALL, DBG_SUBCAT_ALL, DBG_LVL_OFF,("%s %d: reg_spec - %s\n", __func__, __LINE__, reg_spec));

		if (strcmp(reg_spec, "FCC")) {
			MTWF_LOG(DBG_CAT_ALL, DBG_SUBCAT_ALL, DBG_LVL_OFF,("%s %d: don't need to check runtime para\n", __func__, __LINE__));
			return;
		}
	}
	else
		return;

#if defined(MT7628) || defined(MT7603)
	ret_val = get_eeprom_para(REG2G_EEPROM_ADDR, MAX_REGDOMAIN_LEN, reg_spec_2g);
	if (!ret_val) {
		if(reg_spec_2g[0] == 0xff || reg_spec_2g[0] == 0x0) {

		MTWF_LOG(DBG_CAT_ALL, DBG_SUBCAT_ALL, DBG_LVL_OFF,("%s %d: invalid value for reg_spec_2g\n", __func__, __LINE__));
			return;
		}

		for (i=(MAX_REGDOMAIN_LEN-1) ; i>=0 ; i--) {
			if ((reg_spec_2g[i] == 0xff) || (reg_spec_2g[i] == '\0'))
				reg_spec_2g[i] = '\0';
		}

		MTWF_LOG(DBG_CAT_ALL, DBG_SUBCAT_ALL, DBG_LVL_OFF,("%s %d: reg_spec_2g - %s\n", __func__, __LINE__, reg_spec_2g));
	}
	else
		return;
#elif defined(MT7612)
	ret_val = get_eeprom_para(REG5G_EEPROM_ADDR, MAX_REGDOMAIN_LEN, reg_spec_5g);
	if (!ret_val) {
		if(reg_spec_5g[0] == 0xff || reg_spec_5g[0] == 0x0) {

		MTWF_LOG(DBG_CAT_ALL, DBG_SUBCAT_ALL, DBG_LVL_OFF,("%s %d: invalid value for reg_spec_5g\n", __func__, __LINE__));
			return;
		}

		for (i=(MAX_REGDOMAIN_LEN-1) ; i>=0 ; i--) {
			if ((reg_spec_5g[i] == 0xff) || (reg_spec_5g[i] == '\0'))
				reg_spec_5g[i] = '\0';
		}

		MTWF_LOG(DBG_CAT_ALL, DBG_SUBCAT_ALL, DBG_LVL_OFF,("%s %d: reg_spec_5g - %s\n", __func__, __LINE__, reg_spec_5g));
	}
	else
		return;
#elif defined(MT7615)
	ret_val = get_eeprom_para(REG2G_EEPROM_ADDR, MAX_REGDOMAIN_LEN, reg_spec_2g);
	if (!ret_val) {
		if(reg_spec_2g[0] == 0xff || reg_spec_2g[0] == 0x0) {

		MTWF_LOG(DBG_CAT_ALL, DBG_SUBCAT_ALL, DBG_LVL_OFF,("%s %d: invalid value for reg_spec_2g\n", __func__, __LINE__));
			return;
		}

		for (i=(MAX_REGDOMAIN_LEN-1) ; i>=0 ; i--) {
			if ((reg_spec_2g[i] == 0xff) || (reg_spec_2g[i] == '\0'))
				reg_spec_2g[i] = '\0';
		}

		MTWF_LOG(DBG_CAT_ALL, DBG_SUBCAT_ALL, DBG_LVL_OFF,("%s %d: reg_spec_2g - %s\n", __func__, __LINE__, reg_spec_2g));
	}
	else
		return;

	ret_val = get_eeprom_para(REG5G_EEPROM_ADDR, MAX_REGDOMAIN_LEN, reg_spec_5g);
	if (!ret_val) {
		if(reg_spec_5g[0] == 0xff || reg_spec_5g[0] == 0x0) {

		MTWF_LOG(DBG_CAT_ALL, DBG_SUBCAT_ALL, DBG_LVL_OFF,("%s %d: invalid value for reg_spec_5g\n", __func__, __LINE__));
			return;
		}

		for (i=(MAX_REGDOMAIN_LEN-1) ; i>=0 ; i--) {
			if ((reg_spec_5g[i] == 0xff) || (reg_spec_5g[i] == '\0'))
				reg_spec_5g[i] = '\0';
		}

		MTWF_LOG(DBG_CAT_ALL, DBG_SUBCAT_ALL, DBG_LVL_OFF,("%s %d: reg_spec_5g - %s\n", __func__, __LINE__, reg_spec_5g));
	}
	else
		return;			
#elif defined(MT7663)
	ret_val = get_eeprom_para(REG5G_EEPROM_ADDR, MAX_REGDOMAIN_LEN, reg_spec_5g);
	if (!ret_val) {
		if(reg_spec_5g[0] == 0xff || reg_spec_5g[0] == 0x0) {

		MTWF_LOG(DBG_CAT_ALL, DBG_SUBCAT_ALL, DBG_LVL_OFF,("%s %d: invalid value for reg_spec_5g\n", __func__, __LINE__));
			return;
		}

		for (i=(MAX_REGDOMAIN_LEN-1) ; i>=0 ; i--) {
			if ((reg_spec_5g[i] == 0xff) || (reg_spec_5g[i] == '\0'))
				reg_spec_5g[i] = '\0';
		}

		MTWF_LOG(DBG_CAT_ALL, DBG_SUBCAT_ALL, DBG_LVL_OFF,("%s %d: reg_spec_5g - %s\n", __func__, __LINE__, reg_spec_5g));
	}
	else
		return;				
#endif
#endif
	strcpy(reg_spec, regspec);
#if defined(MT7628) || defined(MT7603) || defined(MT7626) || defined(MT7915)
	strcpy(reg_spec_2g, regspec_2g);
#elif defined(MT7612) || defined(MT7663) || defined(MT7626) || defined(MT7915)
	strcpy(reg_spec_5g, regspec_5g);
#endif
#endif
	if (nvram_match("reg_spec", reg_spec) 
#if defined(MT7628) || defined(MT7603) || defined(MT7626) || defined(MT7915)
		&& nvram_match(WL_REG_2G, reg_spec_2g)
#elif defined(MT7612) || defined(MT7663) || defined(MT7626) || defined(MT7915)
		&& nvram_match(WL_REG_5G, reg_spec_5g)
#endif 
	)
	{

		MTWF_LOG(DBG_CAT_ALL, DBG_SUBCAT_ALL, DBG_LVL_OFF,("%s %d: match\n", __func__, __LINE__));
		//return 0;
	}
	else
	{
		MTWF_LOG(DBG_CAT_ALL, DBG_SUBCAT_ALL, DBG_LVL_OFF, ("%s %d: dismatch\n", __func__, __LINE__));
		need_to_change = 1;
		//return 1;
	}

}

int check_config_change(void)
{
	return need_to_change;
}

void change_config_para(char *buf)
{
	char cr_str[32], cc_str[32];
#if defined(CONFIG_MODEL_RPAC56)  || defined(CONFIG_MODEL_RTAC1200GA1) || defined(CONFIG_MODEL_RTAC1200GU)
	char cd_str[32];
#ifdef DFS_SUPPORT
	int flag_80211h = 0;
	char rr_str[32], dfs_str[32];
#endif
#endif
	char *str = NULL;

#if defined(CONFIG_MODEL_RTAC1200)  || defined(CONFIG_MODEL_RTN11PB1)
	if (nvram_invmatch("reg_spec", reg_spec)) {
		MTWF_LOG(DBG_CAT_ALL, DBG_SUBCAT_ALL, DBG_LVL_OFF,("%s %d: reg_spec dismatch\n", __func__, __LINE__));
		strcat(buf, "RDRegion=\n");
	}

#if defined(MT7628)
	if (nvram_invmatch(WL_REG_2G, reg_spec_2g)) {
		MTWF_LOG(DBG_CAT_ALL, DBG_SUBCAT_ALL, DBG_LVL_OFF, ("%s %d: reg_spec_2g dismatch\n", __func__, __LINE__));
		convertCountryCode2G(reg_spec_2g);
		str = nvram_safe_get("wl0_country_code");
		/* for CountryRegion */
		memset(cr_str, 0, sizeof(cr_str));
		if (str && strlen(str))
			sprintf(cr_str, "CountryRegion=%d\n", getCountryRegion2G(str));
		else
			sprintf(cr_str, "CountryRegion=5\n");
		strcat(buf, cr_str);

		/* for CountryCode */
		memset(cc_str, 0, sizeof(cc_str));
		if (str && strlen(str))
			sprintf(cc_str, "CountryCode=%s\n", str);
		else
			sprintf(cc_str, "CountryCode=DB\n");
		strcat(buf, cc_str);
	}
#elif defined(MT7612)
	if (nvram_invmatch(WL_REG_5G, reg_spec_5g)) {
		MTWF_LOG(DBG_CAT_ALL, DBG_SUBCAT_ALL, DBG_LVL_OFF, ("%s %d: reg_spec_5g dismatch\n", __func__, __LINE__));
		convertCountryCode5G(reg_spec_5g);
		str = nvram_safe_get("wl1_country_code");
		/* for CountryRegionABand */
		memset(cr_str, 0, sizeof(cr_str));
		if (str && strlen(str))
			sprintf(cr_str, "CountryRegionABand=%d\n", getCountryRegion5G(str));
		else
			sprintf(cr_str, "CountryRegionABand=7\n");
		strcat(buf, cr_str);

		/* for CountryCode */
		memset(cc_str, 0, sizeof(cc_str));
		if (str && strlen(str))
			sprintf(cc_str, "CountryCode=%s\n", str);
		else
			sprintf(cc_str, "CountryCode=DB\n");
		strcat(buf, cc_str);
	}
#endif 

#elif defined(CONFIG_MODEL_RPAC56)  || defined(CONFIG_MODEL_RTAC1200GA1) || defined(CONFIG_MODEL_RTAC1200GU)
	if (nvram_invmatch("reg_spec", reg_spec)) {
		MTWF_LOG(DBG_CAT_ALL, DBG_SUBCAT_ALL, DBG_LVL_OFF, ("%s %d: reg_spec dismatch\n", __func__, __LINE__));
		/* for CountryCode */
		memset(cr_str, 0, sizeof(cr_str));
		if (!strcmp(reg_spec, "CE"))
			sprintf(cc_str, "CountryCode=FR\n");
		else
			sprintf(cc_str, "CountryCode=\n");
		strcat(buf, cc_str);


		/* for CarrierDetect */
		memset(cd_str, 0, sizeof(cd_str));	
		if (!strcmp(reg_spec, "JP"))
			sprintf(cd_str, "CarrierDetect=1\n");
		else
			sprintf(cd_str, "CarrierDetect=0\n");
		strcat(buf, cd_str);
	}

#if defined(MT7603)
	if (nvram_invmatch(WL_REG_2G, reg_spec_2g)) {
		MTWF_LOG(DBG_CAT_ALL, DBG_SUBCAT_ALL, DBG_LVL_OFF, ("%s %d: reg_spec_2g dismatch\n", __func__, __LINE__));
		convertReg2G(reg_spec_2g);
		str = nvram_safe_get(WL_REG_2G);
		/* for CountryRegion */
		memset(cr_str, 0, sizeof(cr_str));
		if (str && strlen(str))
			sprintf(cr_str, "CountryRegion=%d\n", getCountryRegion2G(str));
		else
			sprintf(cr_str, "CountryRegion=5\n");
		strcat(buf, cr_str);
	}
#elif defined(MT7612)
	if (nvram_invmatch(WL_REG_5G, reg_spec_5g)) {
		MTWF_LOG(DBG_CAT_ALL, DBG_SUBCAT_ALL, DBG_LVL_OFF, ("%s %d: reg_spec_5g dismatch\n", __func__, __LINE__));
		convertReg5G(reg_spec_5g);
		str = nvram_safe_get(WL_REG_5G); 
		/* for CountryRegionABand */
		memset(cr_str, 0, sizeof(cr_str));
		if (str && strlen(str))
			sprintf(cr_str, "CountryRegionABand=%d\n", getCountryRegion5G(str));
		else
			sprintf(cr_str, "CountryRegionABand=7\n");
		strcat(buf, cr_str);

#ifdef DFS_SUPPORT
		/* for IEEE80211H */
		memset(dfs_str, 0, sizeof(dfs_str));
		if (nvram_match(WL_REG_5G, "5G_BAND123") && (!strcmp(reg_spec, "CE") || !strcmp(reg_spec, "JP"))) {
			sprintf(dfs_str, "IEEE80211H=1\n");
			flag_80211h = 1;
		}
		else
			sprintf(dfs_str, "IEEE80211H=0\n");
		strcat(buf, dfs_str);

		/* for RDRegion */
		memset(rr_str, 0, sizeof(rr_str));
		if (flag_80211h) {
			if (!strcmp(reg_spec, "CE"))
				sprintf(rr_str, "RDRegion=CE\n");
			else if (!strcmp(reg_spec, "JP"))
				sprintf(rr_str, "RDRegion=JAP\n");
			else
				sprintf(rr_str, "RDRegion=\n");
		}
		else
			sprintf(rr_str, "RDRegion=\n");
		strcat(buf, rr_str);
#endif /*DFS_SUPPORT*/
	}
#endif 
#endif	/* defined(CONFIG_MODEL_RTAC1200) */
#if defined(MT7615) || defined(MT7626) || defined(MT7915)
if (nvram_invmatch(WL_REG_2G, reg_spec_2g)) {
		MTWF_LOG(DBG_CAT_ALL, DBG_SUBCAT_ALL, DBG_LVL_OFF, ("%s %d: reg_spec_2g dismatch\n", __func__, __LINE__));
		convertCountryCode2G(reg_spec_2g);
		str = nvram_safe_get("wl0_country_code");
		/* for CountryRegion */
		memset(cr_str, 0, sizeof(cr_str));
		if (str && strlen(str))
			sprintf(cr_str, "CountryRegion=%d\n", getCountryRegion2G(str));
		else
			sprintf(cr_str, "CountryRegion=5\n");
		strcat(buf, cr_str);

		/* for CountryCode */
		memset(cc_str, 0, sizeof(cc_str));
		if (str && strlen(str))
			sprintf(cc_str, "CountryCode=%s\n", str);
		else
			sprintf(cc_str, "CountryCode=DB\n");
		strcat(buf, cc_str);
	}

	if (nvram_invmatch(WL_REG_5G, reg_spec_5g)) {
		MTWF_LOG(DBG_CAT_ALL, DBG_SUBCAT_ALL, DBG_LVL_OFF, ("%s %d: reg_spec_5g dismatch\n", __func__, __LINE__));
		convertCountryCode5G(reg_spec_5g);
		str = nvram_safe_get("wl1_country_code");
		/* for CountryRegionABand */
		memset(cr_str, 0, sizeof(cr_str));
		if (str && strlen(str))
			sprintf(cr_str, "CountryRegionABand=%d\n", getCountryRegion5G(str));
		else
			sprintf(cr_str, "CountryRegionABand=7\n");
		strcat(buf, cr_str);

		/* for CountryCode */
		memset(cc_str, 0, sizeof(cc_str));
		if (str && strlen(str))
			sprintf(cc_str, "CountryCode=%s\n", str);
		else
			sprintf(cc_str, "CountryCode=DB\n");
		strcat(buf, cc_str);
	}
#endif	
#if defined(MT7663)


	if (nvram_invmatch(WL_REG_5G, reg_spec_5g)) {
		MTWF_LOG(DBG_CAT_ALL, DBG_SUBCAT_ALL, DBG_LVL_OFF, ("%s %d: reg_spec_5g dismatch\n", __func__, __LINE__));
		convertCountryCode5G(reg_spec_5g);
		str = nvram_safe_get("wl1_country_code");
		/* for CountryRegionABand */
		memset(cr_str, 0, sizeof(cr_str));
		if (str && strlen(str))
			sprintf(cr_str, "CountryRegionABand=%d\n", getCountryRegion5G(str));
		else
			sprintf(cr_str, "CountryRegionABand=7\n");
		strcat(buf, cr_str);

		/* for CountryCode */
		memset(cc_str, 0, sizeof(cc_str));
		if (str && strlen(str))
			sprintf(cc_str, "CountryCode=%s\n", str);
		else
			sprintf(cc_str, "CountryCode=DB\n");
		strcat(buf, cc_str);
	}
#endif	

}

#if defined(SINGLE_SKU_IN_DRIVER)
void dump_wifi_sku(RTMP_STRING *buf)
{
	extern RTMP_STRING CurSKU[MAX_INI_BUFFER_SIZE];
	memcpy(buf, CurSKU, strlen(CurSKU)+1);
}

void dump_wifi_sku_bf(RTMP_STRING *buf)
{
	extern RTMP_STRING CurSKU_BF[MAX_POWER_LIMIT_BUFFER_SIZE];
	memcpy(buf, CurSKU_BF, strlen(CurSKU_BF)+1);
}
#endif

#endif	/* ASUS_EXT */

