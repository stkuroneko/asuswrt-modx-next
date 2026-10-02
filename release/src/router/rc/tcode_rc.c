#include "rc.h"
#include "tcode.h"
#if defined(RTCONFIG_SOC_IPQ8074)
#include <qca.h>
#endif

#ifdef RTCONFIG_TCODE
#define RC_SUPPORT_ADD	1
#define RC_SUPPORT_DEL	2
extern struct tcode_nvram_s tcode_nvram_list[];
extern struct tcode_rc_support_s tcode_rc_support_list[];
extern struct tcode_rc_support_by_odmpid_s tcode_del_rc_support_list_by_odmpid[];
extern struct tcode_rc_support_s tcode_del_rc_support_list[];

void config_nvram_val(int model, char *tcode, char *odmpid, const struct tcode_nvram_s *p_nvram)
{
#ifdef RTAC68U
	unsigned int flag = hardware_flag();
#endif
#if 1	/* TODO: define RTCONFIG_XXX for this */
	int skiplan = nvram_match("ci", "1");
#endif

	if (!odmpid)
		odmpid = "";
	for (; p_nvram->model != 0; p_nvram++) {
#if 1	/* TODO: define RTCONFIG_XXX for this */
		/* Skip change setting when run auto test */
		if (skiplan) {
			if (strcmp(p_nvram->name, "lan_ipaddr") == 0 ||
					strcmp(p_nvram->name, "lan_ipaddr_rt") == 0 ||
					strcmp(p_nvram->name, "dhcp_start") == 0 ||
					strcmp(p_nvram->name, "dhcp_end") == 0)
				continue;
		}
#endif
		/* specific model are per odmpid & full tcode */
		if (p_nvram->model == model &&
#ifdef RTAC68U
				(flag & p_nvram->flag) != 0 &&
#endif
				(!p_nvram->odmpid || strcmp(p_nvram->odmpid, odmpid) == 0) &&
				(!strlen(p_nvram->tcode) || strcmp(p_nvram->tcode, tcode) == 0))
			nvram_set(p_nvram->name, p_nvram->value);
		else
		/* generic models are per country only */
		if (p_nvram->model == MODEL_GENERIC &&
#ifdef RTAC68U
				(!p_nvram->flag || (flag & p_nvram->flag) != 0) &&
				(strcmp(p_nvram->odmpid, "") == 0 || strcmp(p_nvram->odmpid, odmpid) == 0) &&
#endif
				(!strlen(p_nvram->tcode) || strncmp(p_nvram->tcode, tcode, 2) == 0))
			nvram_set(p_nvram->name, p_nvram->value);
	}
}

void config_rc_support(int model, char *tcode, char *odmpid, const struct tcode_rc_support_s *p_rc_support, int action)
{
#ifdef RTAC68U
	unsigned int flag = hardware_flag();
#endif
	for (; p_rc_support->model != 0; p_rc_support++) {
		if (p_rc_support->model == model &&
#ifdef RTAC68U
		    (flag & p_rc_support->flag) != 0 &&
#endif
		    strcmp(p_rc_support->tcode, tcode) == 0) {
			if (action == RC_SUPPORT_ADD)
				add_rc_support(p_rc_support->features);
			else if (action == RC_SUPPORT_DEL)
				del_rc_support(p_rc_support->features);
		} else
		/* generic models are per country only */
		if (p_rc_support->model == MODEL_GENERIC &&
#ifdef RTAC68U
		    (!p_rc_support->flag || (flag & p_rc_support->flag) != 0) &&
#endif
		    strncmp(p_rc_support->tcode, tcode, 2) == 0) {
			if (action == RC_SUPPORT_ADD)
				add_rc_support(p_rc_support->features);
			else if (action == RC_SUPPORT_DEL)
				del_rc_support(p_rc_support->features);
		}
	}
}
void config_rc_support_by_odmpid(int model, char *tcode, char *odmpid, const struct tcode_rc_support_by_odmpid_s *p_rc_support, int action)
{

	for (; p_rc_support->model != 0; p_rc_support++) {
		if (p_rc_support->model == model &&
			strcmp(p_rc_support->odmpid, odmpid) == 0 &&
		    strcmp(p_rc_support->tcode, tcode) == 0)
		{
			if (action == RC_SUPPORT_ADD)
				add_rc_support(p_rc_support->features);
			else if (action == RC_SUPPORT_DEL)
				del_rc_support(p_rc_support->features);
		} else
		/* generic models are per country only */
		if (p_rc_support->model == MODEL_GENERIC &&
		    strncmp(p_rc_support->tcode, tcode, 2) == 0) {
			if (action == RC_SUPPORT_ADD)
				add_rc_support(p_rc_support->features);
			else if (action == RC_SUPPORT_DEL)
				del_rc_support(p_rc_support->features);
		}
	}
}

void config_rc_support_location(int model, char *lcode, char *odmpid, const struct location_nvram_s *p_locnvram, int action)
{
	for (; p_locnvram->model != 0; p_locnvram++) {
		if ((p_locnvram->model == model || p_locnvram->model == MODEL_GENERIC) &&
		    strcmp(p_locnvram->location_code, lcode) == 0 &&
		    strcmp(p_locnvram->name, "rc_support") == 0) {
			/* TODO: support del? *//*
			if (p_locnvram->value[0] == '-') {
				if (action == RC_SUPPORT_DEL)
					del_rc_support(p_locnvram->value + 1);
			} else
			*/
			if (action == RC_SUPPORT_ADD)
				add_rc_support(p_locnvram->value);
		}
	}
}

int config_tcode(int type)
{
	char tcode[7], lcode[7], *odmpid;
	int model;

#if defined(RTN14U) // OLD non-tcode model workaround, make LAN50=y & ATCOVER=y option work
	if ( type != 1 || snprintf(tcode, sizeof(tcode), "%s", nvram_safe_get("wl_country_code")) <= 0 )
		return 0;
#else
	if (snprintf(tcode, sizeof(tcode), "%s", nvram_safe_get("territory_code")) <= 0)
		return 0;
	strlcpy(lcode, nvram_safe_get("location_code"), sizeof(lcode));
#endif

	model = get_model();
	odmpid = nvram_safe_get("odmpid");

	switch (type) {
	case 0:
		config_nvram_val(model, tcode, odmpid, tcode_nvram_list);
		config_rc_support(model, tcode, odmpid, tcode_rc_support_list, RC_SUPPORT_ADD);
		config_rc_support_location(model, lcode, odmpid, location_init_nvram_list, RC_SUPPORT_ADD);
		break;
	case 1:
		config_nvram_val(model, tcode, odmpid, tcode_init_nvram_list);
#if defined(RPAX56) || defined(RPAX58)
		if (ATE_BRCM_FACTORY_MODE())
			config_nvram_val(model, tcode, odmpid, ate_nvram_list);
#endif
		break;
	case 2:
		config_rc_support(model, tcode, odmpid, tcode_del_rc_support_list, RC_SUPPORT_DEL);
		config_rc_support_location(model, lcode, odmpid, location_init_nvram_list, RC_SUPPORT_DEL);
		break;
	case 3:
		config_rc_support_by_odmpid(model, tcode, odmpid, tcode_del_rc_support_list_by_odmpid, RC_SUPPORT_DEL);
		break;
	}

	return 1;
}

#if !defined(CONFIG_BCMWL5)	//Broadcom set this in check_wl_territory_code()
void handle_location_code_for_wl(void)
{
#if defined(RTCONFIG_SOC_IPQ8074)
	const int soc_version_major __attribute__((unused)) = get_soc_version_major();
#endif
	char *TC = nvram_get("territory_code");
	char *LC = nvram_safe_get("location_code");
	char location[7];
	int unit = 0;
	char word[256], *next;
	int model = get_model();
	const struct tcode_location_s *p_location;
	const struct tcode_langcode_s *p_langcode;

	if (TC == NULL || strlen(TC) != 5) {
	error:
#if defined(RTCONFIG_QCA)
		nvram_unset("curr_CTL");
		verify_ctl_table();
#endif	/* RTCONFIG_QCA */
		return;
	}

	if (!nvram_contains_word("rc_support", "loclist")) {
		for (p_langcode = tcode_langcode_list; p_langcode->model; p_langcode++) {
			if (p_langcode->model == model &&
			    strncmp(p_langcode->tcode, TC, 2) == 0 &&
			    strcmp(p_langcode->location, LC) == 0)
				break;
		}
		if (p_langcode->model == 0)
			goto error;
	}

	if (*LC == '\0') {
		//set default location_code
		strncpy(location, TC, 2);
		location[2] = '\0';
		nvram_set("location_code", location);
	} else
		strlcpy(location, LC, sizeof(location));

#if defined(TUFAX6000)
	//cprintf("### not set location(%s) to country_code ###\n", location);
#else
	foreach (word, nvram_safe_get("wl_ifnames"), next) {
		char tmp[32];

		SKIP_ABSENT_BAND_AND_INC_UNIT(unit);
		snprintf(tmp, sizeof(tmp), "wl%d_country_code", unit);
		nvram_set(tmp, location);
		unit++;
	}
#endif

	p_location = &tcode_location_list[0];
#if 0
	if (nvram_match("HwId", "A")) // overwrite
		p_location = &tcode_location_list_HwIdA[0];
#endif
#if defined(TUFAX4200)
	if (nvram_match("HwId", "B")) // overwrite
		p_location = &tcode_location_list_HwIdB[0];
#endif
	for (; p_location->model != 0; p_location++) {
#if defined(RTCONFIG_SOC_IPQ8074)
		if (soc_version_major != 2
		 && (!strncmp(p_location->location, "EU", 2)
		  || !strncmp(p_location->location, "JP", 2)))
			continue;
#endif
		if(p_location->model == model && strcmp(p_location->location, location) == 0)
		{
			char tmp[128], *p = tmp;
			const char *name;

			p += sprintf(p, "tcode: location(%s) model(%d):", location, p_location->model);
			if(p_location->ccode_2g)
			{
				name = "wl0_country_code";
				nvram_set(name, p_location->ccode_2g);
				p += sprintf(p, " %s(%s)", name, p_location->ccode_2g);
			}

			if(p_location->regrev_2g)
			{
#if defined(RTCONFIG_QCA)
				char *curr_CTL;
				name = "curr_CTL";
				curr_CTL = nvram_get(name);
				if(curr_CTL == NULL || strcmp(curr_CTL, p_location->regrev_2g) != 0)
				{
					p += sprintf(p, " %s(%s --> %s)", name, curr_CTL, p_location->regrev_2g);
					//setCTL(p_location->regrev_2g);		//modify the wifi power
					nvram_set(name, p_location->regrev_2g);
				}
				else
				{
					p += sprintf(p, " %s(%s)", name, curr_CTL);
				}
#elif defined(RTCONFIG_NEW_REGULATION_DOMAIN)
				name = "reg_spec";
				nvram_set(name, p_location->regrev_2g);
				p += sprintf(p, " %s(%s)", name, p_location->regrev_2g);
#endif	/* RTCONFIG_NEW_REGULATION_DOMAIN */
			}

#if defined(RTCONFIG_HAS_5G)
			if(p_location->ccode_5g)
			{
				name = "wl1_country_code";
				nvram_set(name, p_location->ccode_5g);
				p += sprintf(p, " %s(%s)", name, p_location->ccode_5g);
#if defined(RTCONFIG_HAS_5G_2)
				name = "wl2_country_code";
				nvram_set(name, p_location->ccode_5g);
				p += sprintf(p, " %s(%s)", name, p_location->ccode_5g);
#endif
			}
#endif
			cprintf("%s\n", tmp);

#ifdef RA_SINGLE_SKU
			void reset_ra_sku(const char *location, const char *country, const char *reg_spec);
			reset_ra_sku(location, p_location->ccode_2g, p_location->regrev_2g);
#endif	/* RA_SINGLE_SKU */
			break;
		}
	}
#if defined(RTCONFIG_QCA)
	verify_ctl_table();
#endif
}
#endif	/* ! CONFIG_BCMWL5 */
#endif	/* RTCONFIG_TCODE */
