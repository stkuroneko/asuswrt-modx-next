#include <string.h>
#include "sysdeps.h"
#include <conn_diag.h>

int get_hw_acceleration(char *output, int size)
{
	snprintf(output, size, "%s", nvram_safe_get("qca_sfe"));

	return 0;
}

int get_sys_clk(char *output, int size)
{
#if defined(RTCONFIG_QCA953X)
	snprintf(output, size, "650");
#elif defined(RTCONFIG_SOC_QCA9557)
	snprintf(output, size, "700");
#elif defined(RTCONFIG_QCA956X)
	snprintf(output, size, "775");
#elif defined(RTCONFIG_SOC_IPQ40XX)
	snprintf(output, size, "710");
#else
	snprintf(output, size, "-1");
#endif

	return 0;
}

int get_sys_temp(unsigned int *temp)
{
#warning FIXME
	*temp = -1;

	return -1;
}

int get_wifi_chip(char *ifname, char *output, int size)
{
#if defined(RTCONFIG_MT798X)
	if (!strcmp(ifname, "ra0") || !strcmp(ifname, "rax0"))
		snprintf(output, size, "MT7976iD,-1,-1");
#else
	snprintf(output, size, "-1,-1,-1");
#endif

	return 0;
}

int get_wifi_temp(char *ifname, unsigned int *temp)
{
#warning FIXME
	*temp = -1;
	return 0;
}

int get_wifi_country(char *ifname, char *output, int len)
{
	snprintf(output, len, nvram_safe_get("wl0_country_code"));
	return 0;
}

int get_wifi_noise(char *ifname, char *output, int len)
{
	snprintf(output, len, "-1");
	return -1;
}

int get_wifi_mcs(char *ifname, char *output, int len)
{
	snprintf(output, len, "-1");
	return -1;
}

char *diag_get_wifi_fh_ifnames(int wifi_unit, char *buffer, size_t buffer_size)
{
	return NULL;
}

char *diag_get_eth_bh_ifnames(char *buffer, size_t buffer_size)
{
	char eth_ifnames[64];
	char amas_ifname[64];
	char *ptr;
	char *end;
	char word[64], *next;
	int len;

	if (!buffer || buffer_size <= 0)
		return NULL;

	memset(buffer, 0, buffer_size);
	ptr = &buffer[0];
	end = ptr + buffer_size;

	snprintf(eth_ifnames, sizeof(eth_ifnames), "%s", nvram_safe_get("eth_ifnames"));
	snprintf(amas_ifname, sizeof(amas_ifname), "%s", nvram_safe_get("amas_ifname"));

	foreach(word, eth_ifnames, next) {
		if (!find_word(amas_ifname, word))
			continue;

		len = strlen(word);
		if (ptr + len + 1 >= end)
			break;

		ptr += snprintf(ptr, end-ptr, "%s ", word);
	}

	if (ptr <= buffer)
		return NULL;

	*(ptr-1) = '\0';	// remove ' ' at the end

	return buffer;
}

char *diag_get_eth_fh_ifnames(char *buffer, size_t buffer_size)
{
	char *ptr;
	char *end;
	char lan_ifnames[64];
	char eth_bh_ifnames[64];

	char word[64], *next;
	size_t len;

	if (!buffer || buffer_size <= 0)
		return NULL;

	memset(buffer, 0, buffer_size);
	snprintf(lan_ifnames, sizeof(lan_ifnames), nvram_safe_get("lan_ifnames"));

	// Get backhaul interface
	diag_get_eth_bh_ifnames(eth_bh_ifnames, sizeof(eth_bh_ifnames));

	ptr = &buffer[0];
	end = ptr + buffer_size;

	foreach(word, lan_ifnames, next)
	{
		if (is_wlif(word) || guest_wlif(word) || find_word(eth_bh_ifnames, word))  // bypass wifi/guest/backhaul interfaces
			continue;

		len = strlen(word);
		if (ptr + len + 1 >= end)
			break;

		ptr += snprintf(ptr, end-ptr, "%s ", word);
	}

	if (strlen(buffer) > 0)
		buffer[strlen(buffer)-1] = '\0';

	return (strlen(buffer) > 0) ? buffer : NULL;
	if (ptr <= buffer)
		return NULL;

	*(ptr-1) = '\0';	// remove ' ' at the end

	return buffer;
}
