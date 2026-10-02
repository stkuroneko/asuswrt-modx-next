#include <stdio.h>
#include <string.h>
#include <shared.h>
#include <bcmnvram.h>
#include "tcode.h"

#ifdef RTCONFIG_TCODE
struct tcode_nvram_s tcode_init_nvram_list[] = {
#if (defined(RTAC95U) || defined(RTAX95Q) || defined(XT8PRO) || defined(XT8_V2) || defined(RTAXE95Q) || defined(ET8PRO) || defined(RTAX56_XD4) || defined(XD4PRO) || defined(CTAX56_XD4)) && defined(RTCONFIG_PRELINK)
	{ MODEL_GENERIC, "", "US/01", "prelink_ui_flag", "1" },
	{ MODEL_GENERIC, "", "U2/01", "prelink_ui_flag", "1" },
	{ MODEL_GENERIC, "", "CA/01", "prelink_ui_flag", "1" },
#endif
#ifdef RTCONFIG_QCA
#if defined(RTAC59U)
	{ MODEL_RTAC59U, NULL, "CX/02", "ipv6_service", "dhcp6" },
	{ MODEL_RTAC59U, NULL, "CX/05", "wan_ifnames", "vlan10" },
	{ MODEL_RTAC59U, NULL, "CX/05", "wan0_ifname", "vlan10" },
	{ MODEL_RTAC59U, NULL, "CX/05", "switch_wantag", "stuff_fibre" },
	{ MODEL_RTAC59U, NULL, "CX/05", "switch_wan0tagid", "10" },
	{ MODEL_RTAC59U, NULL, "CX/05", "dr_enable_x", "3" },
	{ MODEL_RTAC59U, NULL, "CX/05", "ipv6_service", "dhcp6" },
	{ MODEL_RTAC59U, NULL, "CX/05", "lan_ipaddr", "192.168.1.1" },
	{ MODEL_RTAC59U, NULL, "CX/05", "lan_ipaddr_rt", "192.168.1.1" },
	{ MODEL_RTAC59U, NULL, "CX/05", "dhcp_start", "192.168.1.2" },
	{ MODEL_RTAC59U, NULL, "CX/05", "dhcp_end", "192.168.1.254" },
#elif defined(RTAC59_CD6N)
	{ MODEL_RTAC59CD6N, NULL, "", "wl1_channel", "36" },
#elif defined(PLAC66U)
	{ MODEL_PLAC66U, "", "US/01", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_PLAC66U, "", "US/01", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_PLAC66U, "", "US/01", "dhcp_start", "192.168.50.2" },
	{ MODEL_PLAC66U, "", "US/01", "dhcp_end", "192.168.50.254" },
	{ MODEL_PLAC66U, "", "CA/01", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_PLAC66U, "", "CA/01", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_PLAC66U, "", "CA/01", "dhcp_start", "192.168.50.2" },
	{ MODEL_PLAC66U, "", "CA/01", "dhcp_end", "192.168.50.254" },
#elif defined(RTAC95U)
#if defined(RTCONFIG_PRELINK)
	{ MODEL_GENERIC, "", "US/01", "prelink_ui_flag", "1" },
	{ MODEL_GENERIC, "", "U2/01", "prelink_ui_flag", "1" },
	{ MODEL_GENERIC, "", "CA/01", "prelink_ui_flag", "1" },
#endif
#if defined(RTCONFIG_MUMIMO_2G)
	{ MODEL_GENERIC, "", "", "wl0_mumimo", "1" },
#endif
#if defined(RTCONFIG_MUMIMO_5G)
	{ MODEL_GENERIC, "", "", "wl1_mumimo", "1" },
#endif
#endif
#elif defined(RTCONFIG_RALINK)
#ifdef RTAC1200
	{ MODEL_RTAC1200, NULL, "US/01", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_RTAC1200, NULL, "US/01", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_RTAC1200, NULL, "US/01", "dhcp_start", "192.168.50.2" },
	{ MODEL_RTAC1200, NULL, "US/01", "dhcp_end", "192.168.50.254" },
	{ MODEL_RTAC1200, NULL, "CA/01", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_RTAC1200, NULL, "CA/01", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_RTAC1200, NULL, "CA/01", "dhcp_start", "192.168.50.2" },
	{ MODEL_RTAC1200, NULL, "CA/01", "dhcp_end", "192.168.50.254" },
#endif	/* RTAC1200 */
#ifdef RTAC1200V2
	{ MODEL_RTAC1200V2, NULL, "EU/01", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_RTAC1200V2, NULL, "EU/01", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_RTAC1200V2, NULL, "EU/01", "dhcp_start", "192.168.50.2" },
	{ MODEL_RTAC1200V2, NULL, "EU/01", "dhcp_end", "192.168.50.254" },
	{ MODEL_RTAC1200V2, NULL, "US/01", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_RTAC1200V2, NULL, "US/01", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_RTAC1200V2, NULL, "US/01", "dhcp_start", "192.168.50.2" },
	{ MODEL_RTAC1200V2, NULL, "US/01", "dhcp_end", "192.168.50.254" },
	{ MODEL_RTAC1200V2, NULL, "CN/01", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_RTAC1200V2, NULL, "CN/01", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_RTAC1200V2, NULL, "CN/01", "dhcp_start", "192.168.50.2" },
	{ MODEL_RTAC1200V2, NULL, "CN/01", "dhcp_end", "192.168.50.254" },
	{ MODEL_RTAC1200V2, NULL, "TW/01", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_RTAC1200V2, NULL, "TW/01", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_RTAC1200V2, NULL, "TW/01", "dhcp_start", "192.168.50.2" },
	{ MODEL_RTAC1200V2, NULL, "TW/01", "dhcp_end", "192.168.50.254" },
	{ MODEL_RTAC1200V2, NULL, "RU/01", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_RTAC1200V2, NULL, "RU/01", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_RTAC1200V2, NULL, "RU/01", "dhcp_start", "192.168.50.2" },
	{ MODEL_RTAC1200V2, NULL, "RU/01", "dhcp_end", "192.168.50.254" },
	{ MODEL_RTAC1200V2, NULL, "IL/01", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_RTAC1200V2, NULL, "IL/01", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_RTAC1200V2, NULL, "IL/01", "dhcp_start", "192.168.50.2" },
	{ MODEL_RTAC1200V2, NULL, "IL/01", "dhcp_end", "192.168.50.254" },
	{ MODEL_RTAC1200V2, NULL, "AA/01", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_RTAC1200V2, NULL, "AA/01", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_RTAC1200V2, NULL, "AA/01", "dhcp_start", "192.168.50.2" },
	{ MODEL_RTAC1200V2, NULL, "AA/01", "dhcp_end", "192.168.50.254" },
	{ MODEL_RTAC1200V2, NULL, "IN/01", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_RTAC1200V2, NULL, "IN/01", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_RTAC1200V2, NULL, "IN/01", "dhcp_start", "192.168.50.2" },
	{ MODEL_RTAC1200V2, NULL, "IN/01", "dhcp_end", "192.168.50.254" },
	{ MODEL_RTAC1200V2, NULL, "CA/01", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_RTAC1200V2, NULL, "CA/01", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_RTAC1200V2, NULL, "CA/01", "dhcp_start", "192.168.50.2" },
	{ MODEL_RTAC1200V2, NULL, "CA/01", "dhcp_end", "192.168.50.254" },
	{ MODEL_RTAC1200V2, NULL, "BZ/01", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_RTAC1200V2, NULL, "BZ/01", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_RTAC1200V2, NULL, "BZ/01", "dhcp_start", "192.168.50.2" },
	{ MODEL_RTAC1200V2, NULL, "BZ/01", "dhcp_end", "192.168.50.254" },
	{ MODEL_RTAC1200V2, NULL, "AR/01", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_RTAC1200V2, NULL, "AR/01", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_RTAC1200V2, NULL, "AR/01", "dhcp_start", "192.168.50.2" },
	{ MODEL_RTAC1200V2, NULL, "AR/01", "dhcp_end", "192.168.50.254" },
	{ MODEL_RTAC1200V2, NULL, "KR/01", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_RTAC1200V2, NULL, "KR/01", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_RTAC1200V2, NULL, "KR/01", "dhcp_start", "192.168.50.2" },
	{ MODEL_RTAC1200V2, NULL, "KR/01", "dhcp_end", "192.168.50.254" },
#endif  /* RTAC1200V2 */
#ifdef RTACRH18
	{ MODEL_RTACRH18, NULL, "BZ/01", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_RTACRH18, NULL, "BZ/01", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_RTACRH18, NULL, "BZ/01", "dhcp_start", "192.168.50.2" },
	{ MODEL_RTACRH18, NULL, "BZ/01", "dhcp_end", "192.168.50.254" },
	{ MODEL_RTACRH18, NULL, "CA/01", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_RTACRH18, NULL, "CA/01", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_RTACRH18, NULL, "CA/01", "dhcp_start", "192.168.50.2" },
	{ MODEL_RTACRH18, NULL, "CA/01", "dhcp_end", "192.168.50.254" },
	{ MODEL_RTACRH18, NULL, "EU/01", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_RTACRH18, NULL, "EU/01", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_RTACRH18, NULL, "EU/01", "dhcp_start", "192.168.50.2" },
	{ MODEL_RTACRH18, NULL, "EU/01", "dhcp_end", "192.168.50.254" },
	{ MODEL_RTACRH18, NULL, "UK/01", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_RTACRH18, NULL, "UK/01", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_RTACRH18, NULL, "UK/01", "dhcp_start", "192.168.50.2" },
	{ MODEL_RTACRH18, NULL, "UK/01", "dhcp_end", "192.168.50.254" },
	{ MODEL_RTACRH18, NULL, "US/01", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_RTACRH18, NULL, "US/01", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_RTACRH18, NULL, "US/01", "dhcp_start", "192.168.50.2" },
	{ MODEL_RTACRH18, NULL, "US/01", "dhcp_end", "192.168.50.254" },
#endif	/* RTACRH18 */

#ifdef RTAX53U
	{ MODEL_RTAX53U, NULL, "AA/01", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_RTAX53U, NULL, "AA/01", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_RTAX53U, NULL, "AA/01", "dhcp_start", "192.168.50.2" },
	{ MODEL_RTAX53U, NULL, "AA/01", "dhcp_end", "192.168.50.254" },
	{ MODEL_RTAX53U, NULL, "EU/01", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_RTAX53U, NULL, "EU/01", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_RTAX53U, NULL, "EU/01", "dhcp_start", "192.168.50.2" },
	{ MODEL_RTAX53U, NULL, "EU/01", "dhcp_end", "192.168.50.254" },
	{ MODEL_RTAX53U, NULL, "JP/01", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_RTAX53U, NULL, "JP/01", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_RTAX53U, NULL, "JP/01", "dhcp_start", "192.168.50.2" },
	{ MODEL_RTAX53U, NULL, "JP/01", "dhcp_end", "192.168.50.254" },
	{ MODEL_RTAX53U, NULL, "KR/01", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_RTAX53U, NULL, "KR/01", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_RTAX53U, NULL, "KR/01", "dhcp_start", "192.168.50.2" },
	{ MODEL_RTAX53U, NULL, "KR/01", "dhcp_end", "192.168.50.254" },
	{ MODEL_RTAX53U, NULL, "UK/01", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_RTAX53U, NULL, "UK/01", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_RTAX53U, NULL, "UK/01", "dhcp_start", "192.168.50.2" },
	{ MODEL_RTAX53U, NULL, "UK/01", "dhcp_end", "192.168.50.254" },
	{ MODEL_RTAX53U, NULL, "US/01", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_RTAX53U, NULL, "US/01", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_RTAX53U, NULL, "US/01", "dhcp_start", "192.168.50.2" },
	{ MODEL_RTAX53U, NULL, "US/01", "dhcp_end", "192.168.50.254" },
#endif	/* RTAX53U */

#ifdef RTAX54
	{ MODEL_RTAX54, NULL, "AA/01", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_RTAX54, NULL, "AA/01", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_RTAX54, NULL, "AA/01", "dhcp_start", "192.168.50.2" },
	{ MODEL_RTAX54, NULL, "AA/01", "dhcp_end", "192.168.50.254" },
	{ MODEL_RTAX54, NULL, "AU/01", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_RTAX54, NULL, "AU/01", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_RTAX54, NULL, "AU/01", "dhcp_start", "192.168.50.2" },
	{ MODEL_RTAX54, NULL, "AU/01", "dhcp_end", "192.168.50.254" },
	{ MODEL_RTAX54, NULL, "CA/01", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_RTAX54, NULL, "CA/01", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_RTAX54, NULL, "CA/01", "dhcp_start", "192.168.50.2" },
	{ MODEL_RTAX54, NULL, "CA/01", "dhcp_end", "192.168.50.254" },
	{ MODEL_RTAX54, NULL, "US/01", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_RTAX54, NULL, "US/01", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_RTAX54, NULL, "US/01", "dhcp_start", "192.168.50.2" },
	{ MODEL_RTAX54, NULL, "US/01", "dhcp_end", "192.168.50.254" },
	{ MODEL_RTAX54, NULL, "TW/01", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_RTAX54, NULL, "TW/01", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_RTAX54, NULL, "TW/01", "dhcp_start", "192.168.50.2" },
	{ MODEL_RTAX54, NULL, "TW/01", "dhcp_end", "192.168.50.254" },
	{ MODEL_RTAX54, NULL, "TW/02", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_RTAX54, NULL, "TW/02", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_RTAX54, NULL, "TW/02", "dhcp_start", "192.168.50.2" },
	{ MODEL_RTAX54, NULL, "TW/02", "dhcp_end", "192.168.50.254" },
#endif  /* RTAX54 */

#ifdef XD4S
	{ MODEL_XD4S, NULL, "AA/01", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_XD4S, NULL, "AA/01", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_XD4S, NULL, "AA/01", "dhcp_start", "192.168.50.2" },
	{ MODEL_XD4S, NULL, "AA/01", "dhcp_end", "192.168.50.254" },
	{ MODEL_XD4S, NULL, "EU/01", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_XD4S, NULL, "EU/01", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_XD4S, NULL, "EU/01", "dhcp_start", "192.168.50.2" },
	{ MODEL_XD4S, NULL, "EU/01", "dhcp_end", "192.168.50.254" },
	{ MODEL_XD4S, NULL, "UK/01", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_XD4S, NULL, "UK/01", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_XD4S, NULL, "UK/01", "dhcp_start", "192.168.50.2" },
	{ MODEL_XD4S, NULL, "UK/01", "dhcp_end", "192.168.50.254" },
	{ MODEL_XD4S, NULL, "US/01", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_XD4S, NULL, "US/01", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_XD4S, NULL, "US/01", "dhcp_start", "192.168.50.2" },
	{ MODEL_XD4S, NULL, "US/01", "dhcp_end", "192.168.50.254" },
#endif	/* XD4S */

#ifdef RT4GAC86U
	{ MODEL_RT4GAC86U, NULL, "EU/01", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_RT4GAC86U, NULL, "EU/01", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_RT4GAC86U, NULL, "EU/01", "dhcp_start", "192.168.50.2" },
	{ MODEL_RT4GAC86U, NULL, "EU/01", "dhcp_end", "192.168.50.254" },
	{ MODEL_GENERIC, "", "EU", "wl1_frameburst", "off" },
#endif	/* RT4GAC86U */

#ifdef RT4GAX56
	{ MODEL_RT4GAX56, NULL, "EU/01", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_RT4GAX56, NULL, "EU/01", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_RT4GAX56, NULL, "EU/01", "dhcp_start", "192.168.50.2" },
	{ MODEL_RT4GAX56, NULL, "EU/01", "dhcp_end", "192.168.50.254" },
	{ MODEL_RT4GAX56, NULL, "AA/01", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_RT4GAX56, NULL, "AA/01", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_RT4GAX56, NULL, "AA/01", "dhcp_start", "192.168.50.2" },
	{ MODEL_RT4GAX56, NULL, "AA/01", "dhcp_end", "192.168.50.254" },
    { MODEL_RT4GAX56, NULL, "TW/01", "lan_ipaddr", "192.168.50.1" },
    { MODEL_RT4GAX56, NULL, "TW/01", "lan_ipaddr_rt", "192.168.50.1" },
    { MODEL_RT4GAX56, NULL, "TW/01", "dhcp_start", "192.168.50.2" },
    { MODEL_RT4GAX56, NULL, "TW/01", "dhcp_end", "192.168.50.254" },	
#endif	/* RT4GAX56 */

#ifdef RTN11P_B1
	{ MODEL_RTN11P_B1, NULL, "US/01", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_RTN11P_B1, NULL, "US/01", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_RTN11P_B1, NULL, "US/01", "dhcp_start", "192.168.50.2" },
	{ MODEL_RTN11P_B1, NULL, "US/01", "dhcp_end", "192.168.50.254" },
	{ MODEL_RTN11P_B1, NULL, "CA/01", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_RTN11P_B1, NULL, "CA/01", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_RTN11P_B1, NULL, "CA/01", "dhcp_start", "192.168.50.2" },
	{ MODEL_RTN11P_B1, NULL, "CA/01", "dhcp_end", "192.168.50.254" },
	{ MODEL_RTN11P_B1, NULL, "BZ/01", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_RTN11P_B1, NULL, "BZ/01", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_RTN11P_B1, NULL, "BZ/01", "dhcp_start", "192.168.50.2" },
	{ MODEL_RTN11P_B1, NULL, "BZ/01", "dhcp_end", "192.168.50.254" },
#endif	/* RTN11P_B1 */
#ifdef RTN800HP
	{ MODEL_RTN800HP, NULL, "TW/01", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_RTN800HP, NULL, "TW/01", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_RTN800HP, NULL, "TW/01", "dhcp_start", "192.168.50.2" },
	{ MODEL_RTN800HP, NULL, "TW/01", "dhcp_end", "192.168.50.254" },
#endif	/* RTN800HP */

#ifdef TUFAX4200
	{ MODEL_TUFAX4200, NULL, "EU/01", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_TUFAX4200, NULL, "EU/01", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_TUFAX4200, NULL, "EU/01", "dhcp_start", "192.168.50.2" },
	{ MODEL_TUFAX4200, NULL, "EU/01", "dhcp_end", "192.168.50.254" },
	{ MODEL_TUFAX4200, NULL, "UK/01", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_TUFAX4200, NULL, "UK/01", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_TUFAX4200, NULL, "UK/01", "dhcp_start", "192.168.50.2" },
	{ MODEL_TUFAX4200, NULL, "UK/01", "dhcp_end", "192.168.50.254" },
	{ MODEL_TUFAX4200, NULL, "AA/01", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_TUFAX4200, NULL, "AA/01", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_TUFAX4200, NULL, "AA/01", "dhcp_start", "192.168.50.2" },
	{ MODEL_TUFAX4200, NULL, "AA/01", "dhcp_end", "192.168.50.254" },
	{ MODEL_TUFAX4200, NULL, "JP/01", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_TUFAX4200, NULL, "JP/01", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_TUFAX4200, NULL, "JP/01", "dhcp_start", "192.168.50.2" },
	{ MODEL_TUFAX4200, NULL, "JP/01", "dhcp_end", "192.168.50.254" },
	{ MODEL_TUFAX4200, NULL, "TW/01", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_TUFAX4200, NULL, "TW/01", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_TUFAX4200, NULL, "TW/01", "dhcp_start", "192.168.50.2" },
	{ MODEL_TUFAX4200, NULL, "TW/01", "dhcp_end", "192.168.50.254" },
	{ MODEL_TUFAX4200, NULL, "CN/01", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_TUFAX4200, NULL, "CN/01", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_TUFAX4200, NULL, "CN/01", "dhcp_start", "192.168.50.2" },
	{ MODEL_TUFAX4200, NULL, "CN/01", "dhcp_end", "192.168.50.254" },

	/* Enable 160MHz by default on all sku, except EU sku. */
	{ MODEL_TUFAX4200, NULL, "AA/01", "wl1_bw_160", "1" },
	{ MODEL_TUFAX4200, NULL, "JP/01", "wl1_bw_160", "1" },
	{ MODEL_TUFAX4200, NULL, "TW/01", "wl1_bw_160", "1" },
	{ MODEL_TUFAX4200, NULL, "CN/01", "wl1_bw_160", "1" },
	{ MODEL_TUFAX4200, NULL, "US/01", "wl1_bw_160", "1" },
#endif	/* TUFAX4200 */
#ifdef TUFAX6000
	/* Enable 160MHz by default on all sku, except EU sku. */
	{ MODEL_TUFAX6000, NULL, "AA/01", "wl1_bw_160", "1" },
	{ MODEL_TUFAX6000, NULL, "JP/01", "wl1_bw_160", "1" },
	{ MODEL_TUFAX6000, NULL, "TW/01", "wl1_bw_160", "1" },
	{ MODEL_TUFAX6000, NULL, "CN/01", "wl1_bw_160", "1" },
	{ MODEL_TUFAX6000, NULL, "US/01", "wl1_bw_160", "1" },
#endif	/* TUFAX6000 */
#endif // end of RTCONFIG_RALINK

#if defined(RTCONFIG_BCMARM) || defined(RTCONFIG_QCA)
#if defined(RTAX56_XD4) || defined(XD4PRO) || defined(CTAX56_XD4) || defined(RTAX56U) || defined(RTAX95Q) || defined(XT8PRO) || defined(XT8_V2) || defined(RTAXE95Q) || defined(ET8PRO) || defined(RPAX56) || defined(RPAX58)
	{ MODEL_GENERIC, "", "EU", "wl0_frameburst", "off" },
#endif
	{ MODEL_GENERIC, "", "EE", "wl1_frameburst", "off" },
	{ MODEL_GENERIC, "", "EU", "wl1_frameburst", "off" },
	{ MODEL_GENERIC, "", "IL", "wl1_frameburst", "off" },
	{ MODEL_GENERIC, "", "RU", "wl1_frameburst", "off" },
	{ MODEL_GENERIC, "", "UA", "wl1_frameburst", "off" },
	{ MODEL_GENERIC, "", "UK", "wl1_frameburst", "off" },
	{ MODEL_GENERIC, "", "WE", "wl1_frameburst", "off" },
#ifdef RTCONFIG_HAS_5G_2
	{ MODEL_GENERIC, "", "EE", "wl2_frameburst", "off" },
	{ MODEL_GENERIC, "", "EU", "wl2_frameburst", "off" },
	{ MODEL_GENERIC, "", "IL", "wl2_frameburst", "off" },
	{ MODEL_GENERIC, "", "RU", "wl2_frameburst", "off" },
	{ MODEL_GENERIC, "", "UA", "wl2_frameburst", "off" },
	{ MODEL_GENERIC, "", "UK", "wl2_frameburst", "off" },
	{ MODEL_GENERIC, "", "WE", "wl2_frameburst", "off" },
#endif

#if defined(RTAX89U)
	/* Enable 160MHz by default on all sku, except EU sku. */
	{ MODEL_GENERIC, NULL, "AA", "wl1_bw_160", "1" },
	{ MODEL_GENERIC, NULL, "JP", "wl1_bw_160", "1" },
	{ MODEL_GENERIC, NULL, "TW", "wl1_bw_160", "1" },
	{ MODEL_GENERIC, NULL, "CN", "wl1_bw_160", "1" },
	{ MODEL_GENERIC, NULL, "US", "wl1_bw_160", "1" },
#endif
#endif

#if defined(RTAC68U)
	{ MODEL_GENERIC, "RP-AC1900", "", "lan_ipaddr", "192.168.50.1", RTAC66U_V2 },
	{ MODEL_GENERIC, "RP-AC1900", "", "lan_ipaddr_rt", "192.168.50.1", RTAC66U_V2 },
	{ MODEL_GENERIC, "RP-AC1900", "", "dhcp_start", "192.168.50.2", RTAC66U_V2 },
	{ MODEL_GENERIC, "RP-AC1900", "", "dhcp_end", "192.168.50.254", RTAC66U_V2 },
	{ MODEL_GENERIC, "RP-AC1900", "", "sw_mode", "3", RTAC66U_V2 },
	{ MODEL_GENERIC, "RP-AC1900", "", "wlc_psta", "2", RTAC66U_V2 },
	{ MODEL_GENERIC, "RP-AC1900", "", "wlc_dpsta", "1", RTAC66U_V2 },
	{ MODEL_GENERIC, "RP-AC1900", "", "lan_proto", "dhcp", RTAC66U_V2 },
	{ MODEL_GENERIC, "RP-AC1900", "", "lan_dnsenable_x", "1", RTAC66U_V2 },
	{ MODEL_GENERIC, "RT-AC66U_B1", "US", "lan_ipaddr", "192.168.50.1", RTAC66U_V2 },
	{ MODEL_GENERIC, "RT-AC66U_B1", "US", "lan_ipaddr_rt", "192.168.50.1", RTAC66U_V2 },
	{ MODEL_GENERIC, "RT-AC66U_B1", "US", "dhcp_start", "192.168.50.2", RTAC66U_V2 },
	{ MODEL_GENERIC, "RT-AC66U_B1", "US", "dhcp_end", "192.168.50.254", RTAC66U_V2 },
	{ MODEL_GENERIC, "RT-AC66U_B1", "CA", "lan_ipaddr", "192.168.50.1", RTAC66U_V2 },
	{ MODEL_GENERIC, "RT-AC66U_B1", "CA", "lan_ipaddr_rt", "192.168.50.1", RTAC66U_V2 },
	{ MODEL_GENERIC, "RT-AC66U_B1", "CA", "dhcp_start", "192.168.50.2", RTAC66U_V2 },
	{ MODEL_GENERIC, "RT-AC66U_B1", "CA", "dhcp_end", "192.168.50.254", RTAC66U_V2 },
	{ MODEL_GENERIC, "RT-AC66U_B1", "TW", "wl0_turbo_qam", "0", RTAC66U_V2 },
	{ MODEL_GENERIC, "RT-AC1750_B1", "US", "lan_ipaddr", "192.168.50.1", RTAC66U_V2 },
	{ MODEL_GENERIC, "RT-AC1750_B1", "US", "lan_ipaddr_rt", "192.168.50.1", RTAC66U_V2 },
	{ MODEL_GENERIC, "RT-AC1750_B1", "US", "dhcp_start", "192.168.50.2", RTAC66U_V2 },
	{ MODEL_GENERIC, "RT-AC1750_B1", "US", "dhcp_end", "192.168.50.254", RTAC66U_V2 },
	{ MODEL_GENERIC, "RT-AC1750_B1", "CA", "lan_ipaddr", "192.168.50.1", RTAC66U_V2 },
	{ MODEL_GENERIC, "RT-AC1750_B1", "CA", "lan_ipaddr_rt", "192.168.50.1", RTAC66U_V2 },
	{ MODEL_GENERIC, "RT-AC1750_B1", "CA", "dhcp_start", "192.168.50.2", RTAC66U_V2 },
	{ MODEL_GENERIC, "RT-AC1750_B1", "CA", "dhcp_end", "192.168.50.254", RTAC66U_V2 },
	{ MODEL_GENERIC, "RT-N66U_C1", "US", "lan_ipaddr", "192.168.50.1", RTAC66U_V2 },
	{ MODEL_GENERIC, "RT-N66U_C1", "US", "lan_ipaddr_rt", "192.168.50.1", RTAC66U_V2 },
	{ MODEL_GENERIC, "RT-N66U_C1", "US", "dhcp_start", "192.168.50.2", RTAC66U_V2 },
	{ MODEL_GENERIC, "RT-N66U_C1", "US", "dhcp_end", "192.168.50.254", RTAC66U_V2 },
	{ MODEL_GENERIC, "RT-N66U_C1", "CA", "lan_ipaddr", "192.168.50.1", RTAC66U_V2 },
	{ MODEL_GENERIC, "RT-N66U_C1", "CA", "lan_ipaddr_rt", "192.168.50.1", RTAC66U_V2 },
	{ MODEL_GENERIC, "RT-N66U_C1", "CA", "dhcp_start", "192.168.50.2", RTAC66U_V2 },
	{ MODEL_GENERIC, "RT-N66U_C1", "CA", "dhcp_end", "192.168.50.254", RTAC66U_V2 },
#endif
#ifdef RTAC86U
	{ MODEL_GENERIC, "", "CX", "wan_ifnames", "vlan10" },
	{ MODEL_GENERIC, "", "CX", "wan0_ifname", "vlan10" },
	{ MODEL_GENERIC, "", "CX", "switch_wantag", "stuff_fibre" },
	{ MODEL_GENERIC, "", "CX", "switch_wan0tagid", "10" },
	{ MODEL_GENERIC, "", "CX", "dr_enable_x", "3" },
	{ MODEL_GENERIC, "", "CX", "ipv6_service", "dhcp6" },
	{ MODEL_GENERIC, "", "CX", "x_Setting", "1" },
	{ MODEL_GENERIC, "", "CX", "dns_probe_timeout", "8" },
	{ MODEL_GENERIC, "", "A2", "acs_dfs", "0" },
#ifdef RTCONFIG_DFS_US
	{ MODEL_GENERIC, "", "U2", "acs_dfs", "0" },
#endif
	{ MODEL_GENERIC, "", "U2", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_GENERIC, "", "U2", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_GENERIC, "", "U2", "dhcp_start", "192.168.50.2" },
	{ MODEL_GENERIC, "", "U2", "dhcp_end", "192.168.50.254" },
	{ MODEL_GENERIC, "", "US", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_GENERIC, "", "US", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_GENERIC, "", "US", "dhcp_start", "192.168.50.2" },
	{ MODEL_GENERIC, "", "US", "dhcp_end", "192.168.50.254" },
	{ MODEL_GENERIC, "", "CA", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_GENERIC, "", "CA", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_GENERIC, "", "CA", "dhcp_start", "192.168.50.2" },
	{ MODEL_GENERIC, "", "CA", "dhcp_end", "192.168.50.254" },
#endif
#ifdef GTAC2900
	{ MODEL_GENERIC, "", "US", "acs_dfs", "0" },
#endif

#if defined(RTAC87U)
	{ MODEL_GENERIC, "", "TW", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_GENERIC, "", "TW", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_GENERIC, "", "TW", "dhcp_start", "192.168.50.2" },
	{ MODEL_GENERIC, "", "TW", "dhcp_end", "192.168.50.254" },
	{ MODEL_GENERIC, "", "CN", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_GENERIC, "", "CN", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_GENERIC, "", "CN", "dhcp_start", "192.168.50.2" },
	{ MODEL_GENERIC, "", "CN", "dhcp_end", "192.168.50.254" },
	{ MODEL_RTAC87U, "", "HK/01", "ipv6_service", "dhcp6" },
#endif
#ifdef RTAC1200G
	{ MODEL_RTAC1200G, "", "US/01", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_RTAC1200G, "", "US/01", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_RTAC1200G, "", "US/01", "dhcp_start", "192.168.50.2" },
	{ MODEL_RTAC1200G, "", "US/01", "dhcp_end", "192.168.50.254" },
	{ MODEL_RTAC1200G, "", "CA/01", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_RTAC1200G, "", "CA/01", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_RTAC1200G, "", "CA/01", "dhcp_start", "192.168.50.2" },
	{ MODEL_RTAC1200G, "", "CA/01", "dhcp_end", "192.168.50.254" },
#endif
#ifdef RTAC1200GP
	{ MODEL_RTAC1200GP, "", "HK/01", "ipv6_service", "dhcp6" },
#endif
#ifdef RTAC88U
	{ MODEL_RTAC88U, "", "AU/05", "wan_ifnames", "vlan10" },
	{ MODEL_RTAC88U, "", "AU/05", "wan0_ifname", "vlan10" },
	{ MODEL_RTAC88U, "", "AU/05", "switch_wantag", "stuff_fibre" },
	{ MODEL_RTAC88U, "", "AU/05", "switch_wan0tagid", "10" },
	{ MODEL_RTAC88U, "", "AU/05", "dr_enable_x", "3" },
	{ MODEL_RTAC88U, "", "AU/05", "ipv6_service", "dhcp6" },
	{ MODEL_RTAC88U, "", "AU/05", "x_Setting", "1" },
	{ MODEL_RTAC88U, "", "AU/08", "wan_ifnames", "vlan10" },
	{ MODEL_RTAC88U, "", "AU/08", "wan0_ifname", "vlan10" },
	{ MODEL_RTAC88U, "", "AU/08", "switch_wantag", "stuff_fibre" },
	{ MODEL_RTAC88U, "", "AU/08", "switch_wan0tagid", "10" },
	{ MODEL_RTAC88U, "", "AU/08", "dr_enable_x", "3" },
	{ MODEL_RTAC88U, "", "AU/08", "ipv6_service", "dhcp6" },
	{ MODEL_RTAC88U, "", "AU/08", "x_Setting", "1" },
	{ MODEL_RTAC88U, "", "CX/02", "ipv6_service", "dhcp6" },
	{ MODEL_RTAC88U, "", "CX/08", "ipv6_service", "dhcp6" },
#endif
#ifdef GTAC5300
	{ MODEL_GENERIC, "", "CA", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_GENERIC, "", "CA", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_GENERIC, "", "CA", "dhcp_start", "192.168.50.2" },
	{ MODEL_GENERIC, "", "CA", "dhcp_end", "192.168.50.254" },
	{ MODEL_GENERIC, "", "CN", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_GENERIC, "", "CN", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_GENERIC, "", "CN", "dhcp_start", "192.168.50.2" },
	{ MODEL_GENERIC, "", "CN", "dhcp_end", "192.168.50.254" },
	{ MODEL_GENERIC, "", "TW", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_GENERIC, "", "TW", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_GENERIC, "", "TW", "dhcp_start", "192.168.50.2" },
	{ MODEL_GENERIC, "", "TW", "dhcp_end", "192.168.50.254" },
	{ MODEL_GENERIC, "", "US", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_GENERIC, "", "US", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_GENERIC, "", "US", "dhcp_start", "192.168.50.2" },
	{ MODEL_GENERIC, "", "US", "dhcp_end", "192.168.50.254" },
#endif
#if defined(RTCONFIG_HND_ROUTER_AX) && !defined(RTAC68U_V4)
#if defined(BCM6750) || defined(RTAX58U_V2) || defined(TUFAX3000_V2)
	{ MODEL_GENERIC, "", "AA", "wl1_bw_160", "1" },
	{ MODEL_GENERIC, "", "AU", "wl1_bw_160", "1" },
	{ MODEL_GENERIC, "", "CA", "wl1_bw_160", "1" },
	{ MODEL_GENERIC, "", "CN", "wl1_bw_160", "1" },
#ifdef RTAX82U
	{ MODEL_GENERIC, "", "GD", "wl1_bw_160", "1" },
	{ MODEL_GENERIC, "", "TC", "wl1_bw_160", "1" },
#endif
	{ MODEL_GENERIC, "", "JP", "wl1_bw_160", "1" },
	{ MODEL_GENERIC, "", "KR", "wl1_bw_160", "1" },
	{ MODEL_GENERIC, "", "S2", "wl1_bw_160", "1" },
	{ MODEL_GENERIC, "", "SG", "wl1_bw_160", "1" },
	{ MODEL_GENERIC, "", "US", "wl1_bw_160", "1" },
#ifdef RTAX58U
	{ MODEL_GENERIC, "", "CX", "wl1_bw_160", "1" },
#endif
#endif
#if defined(RTAX58U) || defined(RTAX56U)
	{ MODEL_GENERIC, "", "CX", "wan_ifnames", "vlan10" },
	{ MODEL_GENERIC, "", "CX", "wan0_ifname", "vlan10" },
	{ MODEL_GENERIC, "", "CX", "switch_wantag", "stuff_fibre" },
	{ MODEL_GENERIC, "", "CX", "switch_wan0tagid", "10" },
	{ MODEL_GENERIC, "", "CX", "dr_enable_x", "3" },
	{ MODEL_GENERIC, "", "CX", "ipv6_service", "dhcp6" },
	{ MODEL_GENERIC, "", "CX", "lan_ipaddr", "192.168.1.1" },
	{ MODEL_GENERIC, "", "CX", "lan_ipaddr_rt", "192.168.1.1" },
	{ MODEL_GENERIC, "", "CX", "dhcp_start", "192.168.1.2" },
	{ MODEL_GENERIC, "", "CX", "dhcp_end", "192.168.1.254" },
	{ MODEL_GENERIC, "", "CX", "wandog_interval", "10" },
	{ MODEL_GENERIC, "", "CX", "dns_probe_content", "*" },
	{ MODEL_GENERIC, "", "CX", "x_Setting", "1" },
#endif
#if defined(RTAX88U) || defined(GTAX11000) || defined(RTAX86U) || defined(RTAX5700) || defined(GTAXE11000) || defined(GTAX11000_PRO) || defined(ET12) || defined(XT12) || defined(GTAXE16000) || defined(GTAX6000) || defined(RTAXE7800)
	{ MODEL_GENERIC, "", "AA", "wl1_bw_160", "1" },
	{ MODEL_GENERIC, "", "CA", "wl1_bw_160", "1" },
	{ MODEL_GENERIC, "", "CN", "wl1_bw_160", "1" },
#ifdef RTAX86U
	{ MODEL_GENERIC, "", "GD", "wl1_bw_160", "1" },
#endif
	{ MODEL_GENERIC, "", "JP", "wl1_bw_160", "1" },
	{ MODEL_GENERIC, "", "KR", "wl1_bw_160", "1" },
	{ MODEL_GENERIC, "", "S2", "wl1_bw_160", "1" },
	{ MODEL_GENERIC, "", "SG", "wl1_bw_160", "1" },
	{ MODEL_GENERIC, "", "TW", "wl1_bw_160", "1" },
	{ MODEL_GENERIC, "", "US", "wl1_bw_160", "1" },
#endif
#if defined(GTAX11000) || defined(GTAX11000_PRO) || defined(XT12)
	{ MODEL_GENERIC, "", "JP", "wl2_bw_160", "1" },
	{ MODEL_GENERIC, "", "KR", "wl2_bw_160", "1" },
	{ MODEL_GENERIC, "", "TW", "wl2_bw_160", "1" },
	{ MODEL_GENERIC, "", "US", "wl2_bw_160", "1" },
#endif
#if defined(GTAXE11000) || defined(ET12)
	{ MODEL_GENERIC, "", "US", "wl2_bw_160", "1" },
	{ MODEL_GENERIC, "", "KR", "wl2_bw_160", "1" },
	{ MODEL_GENERIC, "", "EU", "wl2_bw_160", "1" },
#endif
#if defined(RPAX56) || defined(RPAX58)
	{ MODEL_GENERIC, "", "", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_GENERIC, "", "", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_GENERIC, "", "", "dhcp_start", "192.168.50.2" },
	{ MODEL_GENERIC, "", "", "dhcp_end", "192.168.50.254" },
	{ MODEL_GENERIC, "", "", "lan_proto", "dhcp" },
	{ MODEL_GENERIC, "", "", "lan_dnsenable_x", "1"},
	{ MODEL_GENERIC, "", "", "sw_mode", "3" },
#ifdef RTCONFIG_BCM_MFG
	{ MODEL_GENERIC, "", "", "telnetd_enable", "1"},
	{ MODEL_GENERIC, "", "", "wl0_bw", "2" },
	{ MODEL_GENERIC, "", "", "wlc_psta", "0" },
	{ MODEL_GENERIC, "", "", "wlc_dpsta", "0" },
#else
	{ MODEL_GENERIC, "", "", "wlc_psta", "2" },
#ifdef RPAX58
	{ MODEL_GENERIC, "", "", "wlc_dpsta", "2" },
#else
	{ MODEL_GENERIC, "", "", "wlc_dpsta", "1" },
#endif
#endif
#endif
	{ MODEL_GENERIC, "", "AA", "acs_dfs", "0" },
	{ MODEL_GENERIC, "", "CA", "acs_dfs", "0" },
#if defined(RTAX82_XD6) || defined(RTAX82_XD6S)
	{ MODEL_GENERIC, "", "CH", "acs_dfs", "0" },
	{ MODEL_GENERIC, "", "CH", "wl_wpa_gtk_rekey", "0" },
	{ MODEL_GENERIC, "", "CH", "wl0_wpa_gtk_rekey", "3600" },
	{ MODEL_GENERIC, "", "CH", "wl1_wpa_gtk_rekey", "3600" },
#endif
	{ MODEL_GENERIC, "", "CN", "acs_dfs", "0" },
	{ MODEL_GENERIC, "", "SG", "acs_dfs", "0" },
	{ MODEL_GENERIC, "", "TW", "acs_dfs", "0" },
	{ MODEL_GENERIC, "", "US", "acs_dfs", "0" },
#if defined(RTAX55) || defined(RTAX1800) || defined(RTAX86U)
	{ MODEL_GENERIC, "", "JP", "acs_dfs_144", "0" },
#endif
#ifdef RTAX55
	{ MODEL_GENERIC, "", "SG", "ipv6_service", "dhcp6" },
#endif
#endif

#ifdef BLUECAVE
	{ MODEL_GENERIC, "", "CA", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_GENERIC, "", "CA", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_GENERIC, "", "CA", "dhcp_start", "192.168.50.2" },
	{ MODEL_GENERIC, "", "CA", "dhcp_end", "192.168.50.254" },
	{ MODEL_GENERIC, "", "CN", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_GENERIC, "", "CN", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_GENERIC, "", "CN", "dhcp_start", "192.168.50.2" },
	{ MODEL_GENERIC, "", "CN", "dhcp_end", "192.168.50.254" },
	{ MODEL_GENERIC, "", "TW", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_GENERIC, "", "TW", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_GENERIC, "", "TW", "dhcp_start", "192.168.50.2" },
	{ MODEL_GENERIC, "", "TW", "dhcp_end", "192.168.50.254" },
	{ MODEL_GENERIC, "", "US", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_GENERIC, "", "US", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_GENERIC, "", "US", "dhcp_start", "192.168.50.2" },
	{ MODEL_GENERIC, "", "US", "dhcp_end", "192.168.50.254" },
#endif

#if defined(BRTAC828) || defined(RTAD7200)
	{ MODEL_GENERIC, "", "US", "lan_ipaddr", "192.168.50.1"},
	{ MODEL_GENERIC, "", "US", "lan_ipaddr_rt", "192.168.50.1"},
	{ MODEL_GENERIC, "", "US", "dhcp_start", "192.168.50.2"},
	{ MODEL_GENERIC, "", "US", "dhcp_end", "192.168.50.254"},
	{ MODEL_GENERIC, "", "CA", "lan_ipaddr", "192.168.50.1"},
	{ MODEL_GENERIC, "", "CA", "lan_ipaddr_rt", "192.168.50.1"},
	{ MODEL_GENERIC, "", "CA", "dhcp_start", "192.168.50.2"},
	{ MODEL_GENERIC, "", "CA", "dhcp_end", "192.168.50.254"},
#endif
#if defined(RTCONFIG_WIFI_QCN5024_QCN5054) && !defined(RTCONFIG_SOC_IPQ60XX)
	{ MODEL_GENERIC, "", "US", "acs_dfs", "0" },
	{ MODEL_GENERIC, "", "CN", "acs_dfs", "0" },
#endif

#ifdef RTCONFIG_DEFLAN50
#ifdef RTCONFIG_QCA
#if defined(RTAC58U) || defined(RTAC82U)
	{ MODEL_GENERIC, "", "US", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_GENERIC, "", "US", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_GENERIC, "", "US", "dhcp_start", "192.168.50.2" },
	{ MODEL_GENERIC, "", "US", "dhcp_end", "192.168.50.254" },
	{ MODEL_GENERIC, "", "CA", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_GENERIC, "", "CA", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_GENERIC, "", "CA", "dhcp_start", "192.168.50.2" },
	{ MODEL_GENERIC, "", "CA", "dhcp_end", "192.168.50.254" },
#if defined(RTAC58U)
	{ MODEL_GENERIC, "", "SP", "http_username", "Spirit" },
	{ MODEL_GENERIC, "", "SP", "http_passwd", "Spirit" },
	{ MODEL_GENERIC, "", "SP", "acc_list", "Spirit/Spirit" },
	{ MODEL_RTAC58U, NULL, "CX/01", "wan_ifnames", "vlan10" },
	{ MODEL_RTAC58U, NULL, "CX/01", "wan0_ifname", "vlan10" },
	{ MODEL_RTAC58U, NULL, "CX/01", "switch_wantag", "stuff_fibre" },
	{ MODEL_RTAC58U, NULL, "CX/01", "switch_wan0tagid", "10" },
	{ MODEL_RTAC58U, NULL, "CX/01", "dr_enable_x", "3" },
	{ MODEL_RTAC58U, NULL, "CX/01", "ipv6_service", "dhcp6" },
	{ MODEL_RTAC58U, NULL, "CX/05", "wan_ifnames", "vlan10" },
	{ MODEL_RTAC58U, NULL, "CX/05", "wan0_ifname", "vlan10" },
	{ MODEL_RTAC58U, NULL, "CX/05", "switch_wantag", "stuff_fibre" },
	{ MODEL_RTAC58U, NULL, "CX/05", "switch_wan0tagid", "10" },
	{ MODEL_RTAC58U, NULL, "CX/05", "dr_enable_x", "3" },
	{ MODEL_RTAC58U, NULL, "CX/05", "ipv6_service", "dhcp6" },

#endif
#endif
#endif
#ifdef RTAC51U
	{ MODEL_GENERIC, "", "US", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_GENERIC, "", "US", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_GENERIC, "", "US", "dhcp_start", "192.168.50.2" },
	{ MODEL_GENERIC, "", "US", "dhcp_end", "192.168.50.254" },
	{ MODEL_GENERIC, "", "CA", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_GENERIC, "", "CA", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_GENERIC, "", "CA", "dhcp_start", "192.168.50.2" },
	{ MODEL_GENERIC, "", "CA", "dhcp_end", "192.168.50.254" },
	{ MODEL_GENERIC, "", "BZ", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_GENERIC, "", "BZ", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_GENERIC, "", "BZ", "dhcp_start", "192.168.50.2" },
	{ MODEL_GENERIC, "", "BZ", "dhcp_end", "192.168.50.254" },
#endif	/* RTAC51U */
	{ MODEL_GENERIC, "", "TW", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_GENERIC, "", "TW", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_GENERIC, "", "TW", "dhcp_start", "192.168.50.2" },
	{ MODEL_GENERIC, "", "TW", "dhcp_end", "192.168.50.254" },
	{ MODEL_GENERIC, "", "CN", "lan_ipaddr", "192.168.50.1" },
	{ MODEL_GENERIC, "", "CN", "lan_ipaddr_rt", "192.168.50.1" },
	{ MODEL_GENERIC, "", "CN", "dhcp_start", "192.168.50.2" },
	{ MODEL_GENERIC, "", "CN", "dhcp_end", "192.168.50.254" },
#endif
	{ MODEL_GENERIC, "", "CN", "wan_ppp_echo", "0" },
	{ MODEL_GENERIC, "", "CN", "wan0_ppp_echo", "0" },
	{ MODEL_GENERIC, "", "CN", "wan1_ppp_echo", "0" },
	{ MODEL_GENERIC, "", "CN", "preferred_lang", "CN" },
	{ MODEL_GENERIC, "", "CN", "ping_target", "www.baidu.com" },
	{ MODEL_GENERIC, "", "CN", "dns_probe_host", "www.baidu.com" },
	{ MODEL_GENERIC, "", "CN", "dns_probe_content", "*" },
	{ MODEL_GENERIC, "", "AA", "dns_probe_content", "*" },
	{ MODEL_GENERIC, "", "AA", "wandog_interval", "10" },
	{ MODEL_GENERIC, "", "AA", "wandog_maxfail", "6" },
	{ MODEL_GENERIC, "", "AA", "dns_probe_timeout", "8" },
	{ MODEL_GENERIC, "", "AA", "http_enable", "2" },
	{ MODEL_GENERIC, "", "JP", "preferred_lang", "JP" },
	{ MODEL_GENERIC, "", "SG", "http_enable", "2" },
#if defined(RTAX82U) || defined(RTAX86U)
	{ MODEL_GENERIC, "", "GD", "wan_ppp_echo", "0" },
	{ MODEL_GENERIC, "", "GD", "wan0_ppp_echo", "0" },
	{ MODEL_GENERIC, "", "GD", "wan1_ppp_echo", "0" },
	{ MODEL_GENERIC, "", "GD", "preferred_lang", "CN" },
	{ MODEL_GENERIC, "", "GD", "ping_target", "www.baidu.com" },
	{ MODEL_GENERIC, "", "GD", "dns_probe_host", "www.baidu.com" },
	{ MODEL_GENERIC, "", "GD", "dns_probe_content", "*" },
#endif
#if defined(DSL_AX82U)
	{ MODEL_GENERIC, "", "OP", "dsl8_enable", "1" },
	{ MODEL_GENERIC, "", "OP", "dsl8_proto", "dhcp" },
	{ MODEL_GENERIC, "", "OP", "dsl8_nat", "1" },
	{ MODEL_GENERIC, "", "OP", "dsl8_upnp_enable", "1" },
	{ MODEL_GENERIC, "", "OP", "dsl8_DHCPClient", "1" },
	{ MODEL_GENERIC, "", "OP", "dsl8_dnsenable", "1" },
	{ MODEL_GENERIC, "", "OP", "dsl8_dhcp_qry", "2" },
	{ MODEL_GENERIC, "", "OP", "wan0_dhcp_qry", "2" },
	{ MODEL_GENERIC, "", "OP", "wan1_dhcp_qry", "2" },
	{ MODEL_GENERIC, "", "OP", "wan0_dscp", "0" },
	{ MODEL_GENERIC, "", "OP", "wan1_dscp", "0" },
	{ MODEL_GENERIC, "", "OP", "wl0_11ax", "0" },
	{ MODEL_GENERIC, "", "OP", "wl0_twt", "0" },
	{ MODEL_GENERIC, "", "OP", "wl0_txbf", "0" },
	{ MODEL_GENERIC, "", "OP", "wl0_itxbf", "0" },
	{ MODEL_GENERIC, "", "OP", "wl0_user_rssi", "0" },
	{ MODEL_GENERIC, "", "OP", "wl0_auth_mode_x", "psk2" },
	{ MODEL_GENERIC, "", "OP", "wl1_itxbf", "0" },
	{ MODEL_GENERIC, "", "OP", "wl1_ofdma", "3" },
	{ MODEL_GENERIC, "", "OP", "wl1_user_rssi", "0" },
	{ MODEL_GENERIC, "", "OP", "wl1_auth_mode_x", "psk2sae" },
	{ MODEL_GENERIC, "", "OP", "wl1_mfp", "1" },
	{ MODEL_GENERIC, "", "OP", "wl1_nmode_x", "8" },
	{ MODEL_GENERIC, "", "OP", "wl1_mbo_enable", "1" },
	{ MODEL_GENERIC, "", "OP", "fw_dos_x", "1" },
	{ MODEL_GENERIC, "", "OP", "usb_usb3", "0" },
	{ MODEL_GENERIC, "", "OP", "lan_ipaddr", "192.168.0.1" },
	{ MODEL_GENERIC, "", "OP", "lan_ipaddr_rt", "192.168.0.1" },
	{ MODEL_GENERIC, "", "OP", "dhcp_start", "192.168.0.2" },
	{ MODEL_GENERIC, "", "OP", "dhcp_end", "192.168.0.254" },
	{ MODEL_GENERIC, "", "OP", "tr_enable", "1" },
	{ MODEL_GENERIC, "", "OP", "tr_discovery", "0" },
	{ MODEL_GENERIC, "", "OP", "tr_enable", "1" },
	{ MODEL_GENERIC, "", "OP", "tr_acs_url", "https://acs.optusnet.com.au/" },
	{ MODEL_GENERIC, "", "OP", "tr_username", "optus" },
	{ MODEL_GENERIC, "", "OP", "tr_passwd", "optus" },
	{ MODEL_GENERIC, "", "OP", "tr_conn_username", "optus" },
	{ MODEL_GENERIC, "", "OP", "tr_conn_passwd", "optus" },
	{ MODEL_GENERIC, "", "OP", "wans_mode", "fo" },
	{ MODEL_GENERIC, "", "OP", "qos_type", "0" },
	{ MODEL_GENERIC, "", "OP", "time_zone", "UTC-10DST_1" },
	{ MODEL_GENERIC, "", "OP", "time_zone_dst", "1" },
	{ MODEL_GENERIC, "", "OP", "time_zone_dstoff", "M10.1.0/2,M4.1.0/3" },
	{ MODEL_GENERIC, "", "OP", "ntp_server0", "time01.syd.optusnet.com.au" },
	{ MODEL_GENERIC, "", "OP", "wandog_interval", "10" },
	{ MODEL_GENERIC, "", "OP", "wandog_maxfail", "6" },
	{ MODEL_GENERIC, "", "OP", "dns_probe_timeout", "8" },
	{ MODEL_GENERIC, "", "OP", "btn_ez_mode", "0" },
	{ MODEL_GENERIC, "", "OP", "http_enable", "2" },
#endif
#ifdef RTAX82U
	{ MODEL_GENERIC, "", "GD", "ledg_scheme", "3", 2 },
	{ MODEL_GENERIC, "", "GD", "ledg_rgb2", "128,40,25,128,40,25,128,40,25,128,40,25", 2 },
	{ MODEL_GENERIC, "", "GD", "ledg_rgb3", "128,50,35,128,50,35,128,50,35,128,50,35", 2 },
	{ MODEL_GENERIC, "", "GD", "ledg_rgb6", "128,50,35,128,50,35,128,50,35,128,50,35", 2 },
	{ MODEL_GENERIC, "", "GD", "ledg_rgb7", "128,50,35,128,50,35,128,50,35,128,50,35", 2 },
	{ MODEL_GENERIC, "", "TC", "ledg_scheme", "2" },
	{ MODEL_GENERIC, "", "TC", "ledg_rgb2", "128,90,0,128,90,0,128,90,0,128,90,0" },
	{ MODEL_GENERIC, "", "TC", "preferred_lang", "CN" },
#endif
#ifdef RTCONFIG_HND_ROUTER_AX
	{ MODEL_GENERIC, "", "AA", "bcm_snooping", "0" },
	{ MODEL_GENERIC, "", "SG", "bcm_snooping", "0" },
#endif
	{ 0, NULL, NULL, NULL }
};

struct tcode_nvram_s tcode_nvram_list[] = {
#ifdef CONFIG_BCMWL5
#ifdef RTAC87U
	{ MODEL_RTAC87U, "RT-AC87R", "US/02", "color", "B" },
	{ MODEL_RTAC87U, "RT-AC87R", "CA/02", "color", "B" },
	{ MODEL_RTAC87U, "", "UK/02", "color", "W" },
	{ MODEL_RTAC87U, "", "EU/01", "color", "R" },
	{ MODEL_RTAC87U, "", "AA/02", "color", "R" },
	{ MODEL_RTAC87U, "", "AA/03", "color", "W" },
	{ MODEL_RTAC87U, "", "JP/02", "color", "R" },
	{ MODEL_RTAC87U, "", "SG/02", "color", "R" },
	{ MODEL_RTAC87U, "", "SG/03", "color", "W" },
#endif
#endif
	{ 0, NULL, NULL, NULL }
};

struct tcode_nvram_s ate_nvram_list[] = {
#if defined(RPAX56) || defined(RPAX58)
	{ MODEL_GENERIC, "", "", "sw_mode", "3" },
	{ MODEL_GENERIC, "", "", "wlc_psta", "0" },
	{ MODEL_GENERIC, "", "", "wlc_dpsta", "0" },
	{ MODEL_GENERIC, "", "", "wl0_bw", "2" },
	//{ MODEL_GENERIC, "", "", "force_dhcp_enable", "1"},
#endif
	{ 0, NULL, NULL, NULL }
};

/* Yandex.DNS strings */
#ifdef RTCONFIG_YANDEXDNS
#define _yadns " yadns"
#define _yadns_hideqis " yadns_hideqis"
#define yadns_ "yadns "
#define yadns_hideqis_ "yadns_hideqis "
#else
#define _yadns ""
#define _yadns_hideqis ""
#define yadns_ ""
#define yadns_hideqis_ ""
#endif

struct tcode_rc_support_s tcode_rc_support_list[] = {
	/* loclist: display country_code_list */
	/* defpsk: disable security open_none */
	/* dfs: DFS / Carrier Sense support */
	/* yadns: enable Yandex.DNS */

#ifndef RTCONFIG_WIFI_SON /* Lyra not support loclist */
#if defined(CONFIG_BCMWL5) || defined(RTCONFIG_RALINK) || defined(RTCONFIG_QCA) || defined(RTCONFIG_REALTEK)
#if !defined(RPAX58) && !defined(RPAX56)
	{ MODEL_GENERIC, "AA", "loclist" },
	{ MODEL_GENERIC, "AP", "loclist" },
	{ MODEL_GENERIC, "AQ", "loclist" },
	{ MODEL_GENERIC, "AU", "loclist" },
	{ MODEL_GENERIC, "CN", "loclist" },
	{ MODEL_GENERIC, "HK", "loclist" },
	{ MODEL_GENERIC, "ID", "loclist" },
	{ MODEL_GENERIC, "IN", "loclist" },
#ifdef CONFIG_BCMWL5
	{ MODEL_GENERIC, "KR", "defpsk loclist" },
#else
	{ MODEL_GENERIC, "KR", "loclist" },
#endif
	{ MODEL_GENERIC, "MY", "loclist" },
	{ MODEL_GENERIC, "S2", "loclist" },
	{ MODEL_GENERIC, "SG", "loclist" },
#endif
#endif
	{ MODEL_GENERIC, "RU", _yadns },
	{ MODEL_GENERIC, "UA", _yadns },
	{ MODEL_GENERIC, "EU", _yadns },
#if defined(RTAX89U) || defined(GTAX11000) || defined(GTAX11000_PRO) || defined(XT12)
	{ MODEL_GENERIC, "IL", _yadns },
#endif
#endif	/* !RTCONFIG_WIFI_SON */

#ifdef CONFIG_BCMWL5
#ifdef RTAC66U
#endif
#ifdef RTAC68U
	{ MODEL_GENERIC, "CA", "defpsk", RTAC66U_V2 },
	{ MODEL_GENERIC, "JP", "dfs", RTAC68U_ALL },
	{ MODEL_GENERIC, "US", "defpsk", RTAC66U_V2 },
#endif
#ifdef RTAC87U
#endif
#ifdef RTN12D1
#endif
#ifdef RTN12HP_B1
#endif
#ifdef RTN18U
#endif
#ifdef RTAC1200G
	{ MODEL_RTAC1200G, "US/01", "defpsk" },
	{ MODEL_RTAC1200G, "CA/01", "defpsk" },
#endif
#ifdef RTAC1200GP
	{ MODEL_RTAC1200GP, "EU/01", _yadns },
#endif
#ifdef RTAC88U
	{ MODEL_RTAC88U, "AU/05", "loclist defpsk noupdate" },
	{ MODEL_RTAC88U, "AU/08", "loclist defpsk noupdate" },
	{ MODEL_RTAC88U, "KR/08", "loclist defpsk" },
#endif
#ifdef RTAC3100
#endif
#ifdef RTAC5300
#endif
#ifdef GTAC5300
#endif
#ifdef RTAC86U
	{ MODEL_GENERIC, "A2", "loclist" },
#endif
#if defined(RTAC86U) || defined(RTAX58U) || defined(RTAX56U)
	{ MODEL_GENERIC, "CX", "loclist defpsk noupdate" },
#endif
#if defined(RTAX82U) || defined(RTAX86U)
	{ MODEL_GENERIC, "GD", "loclist" },
#endif
#ifdef RTAX82U
	{ MODEL_GENERIC, "TC", "loclist" },
#endif
#if defined(RTAX82_XD6) || defined(RTAX82_XD6S)
	{ MODEL_GENERIC, "CH", "noFwManual" },
#endif
#ifdef RTAX55
	{ MODEL_GENERIC, "JP", "defpsk" },
#endif
#elif	defined(RTCONFIG_RALINK)
#ifdef RTN11P
#endif	/* RTN11P */
#ifdef RTAC51U
#endif	/* RTAC51U */
#ifdef RTN56UB1
	{ MODEL_RTN56UB1, "EU/01", "" },
	{ MODEL_RTN56UB1, "UK/01", "" },
	{ MODEL_RTN56UB1, "US/01", "" },
#endif	/* RTN56UB1 */
#ifdef RTAC51UP
#endif  /* RTAC51UP */
#ifdef RTAC53
#endif /* RTAC53 */
#ifdef RTAC1200
	{ MODEL_RTAC1200, "US/01", "defpsk" },
	{ MODEL_RTAC1200, "CA/01", "defpsk" },
#endif /* RTAC1200 */
#ifdef RTAC1200V2
	{ MODEL_RTAC1200V2, "AA/01", "loclist" },
	{ MODEL_RTAC1200V2, "AR/01", "" },
	{ MODEL_RTAC1200V2, "CA/01", "" },	
	{ MODEL_RTAC1200V2, "CN/01", "loclist" },
	{ MODEL_RTAC1200V2, "EU/01", "non_frameburst"_yadns },
	{ MODEL_RTAC1200V2, "IL/01", "non_frameburst"_yadns },
	{ MODEL_RTAC1200V2, "IN/01", "loclist" },
	{ MODEL_RTAC1200V2, "KR/01", "loclist" },
	{ MODEL_RTAC1200V2, "RU/01", "non_frameburst"_yadns },
	{ MODEL_RTAC1200V2, "TW/01", "" },
	{ MODEL_RTAC1200V2, "US/01", "" },
	{ MODEL_RTAC1200V2, "BZ/01", "" },
#endif /* RTAC1200V2 */
#ifdef RTACRH18
	{ MODEL_RTACRH18, "CA/01", "" },
	{ MODEL_RTACRH18, "EU/01", _yadns },
	{ MODEL_RTACRH18, "UK/01", _yadns },
	{ MODEL_RTACRH18, "US/01", "" },
#endif /* RTACRH18 */
#ifdef RT4GAC86U
	{ MODEL_RT4GAC86U, "EU/01", _yadns },
#endif /* RT4GAC86U */
#ifdef RT4GAX56
	{ MODEL_RT4GAX56, "EU/01", _yadns },
	{ MODEL_RT4GAX56, "AA/01", "loclist" },
	{ MODEL_RT4GAX56, "TW/01", "" },
#endif /* RT4GAX56 */
#ifdef RTAX53U
	{ MODEL_RTAX53U, "AA/01", "loclist" },
#endif /* RTAX53U */
#ifdef RTAX54
	{ MODEL_RTAX54, "AA/01", "loclist" },
	{ MODEL_RTAX54, "AU/01", "loclist" },
#endif /* RTAX54 */
#ifdef XD4S
	{ MODEL_XD4S, "AA/01", "loclist" },
#endif /* XD4S */
#ifdef RTN11P_B1
	{ MODEL_RTN11P_B1 , "EU/01", _yadns },
	{ MODEL_RTN11P_B1 , "UK/01", _yadns },
	{ MODEL_RTN11P_B1 , "CA/01", "noiptv" },
	{ MODEL_RTN11P_B1 , "US/01", "noiptv" },
	{ MODEL_RTN11P_B1 , "BZ/01", "noiptv" },
#endif /* RTN11P_B1 */
#ifdef RTAC1200GU
#endif /* RTAC1200GU */
#ifdef RTAC85U
	{ MODEL_RTAC85U, "AA/01", "nodm" },
#endif /* RTAC85U */
#ifdef RTAC85P
	{ MODEL_RTAC85P, "CN/01", "loclist" },
	{ MODEL_RTAC85P, "AA/01", "nodm loclist" },
	{ MODEL_RTAC85P, "SG/01", "loclist" },
#endif /* RTAC85P */
#ifdef RTACRH26
	{ MODEL_RTACRH26, "CN/01", "loclist" },
	{ MODEL_RTACRH26, "AA/01", "nodm loclist" },
	{ MODEL_RTACRH26, "SG/01", "loclist" },
#endif /* RTACRH26 */
#ifdef TUFAX4200
	{ MODEL_TUFAX4200, "CN/01", "loclist" },
	{ MODEL_TUFAX4200, "AA/01", "loclist" },
#endif	/* TUFAX4200 */
#elif	defined(RTCONFIG_QCA)
#ifdef RTAC55U
#endif	/* RTAC55U */
#if defined(BRTAC828)
	{ MODEL_BRTAC828, "SG/01", "loclist"},
	{ MODEL_BRTAC828, "AA/01", "loclist"},
	{ MODEL_BRTAC828, "US/01", "defpsk"},
	{ MODEL_BRTAC828, "CA/01", "defpsk"},
#elif defined(RTAD7200)
	{ MODEL_RTAD7200, "SG/01", "loclist"},
	{ MODEL_RTAD7200, "AA/01", "loclist"},
	{ MODEL_RTAD7200, "US/01", "defpsk"},
	{ MODEL_RTAD7200, "CA/01", "defpsk"},
#elif defined(GTAXY16000)
	{ MODEL_GTAXY16000, "SG/01", "loclist"},
	{ MODEL_GTAXY16000, "AA/01", "loclist"},
#elif defined(RTAX89U)
	{ MODEL_RTAX89U, "SG/01", "loclist"},
	{ MODEL_RTAX89U, "S2/01", "loclist"},
	{ MODEL_RTAX89U, "AA/01", "loclist"},
	{ MODEL_RTAX89U, "KR/01", "defpsk loclist" },
#endif
#ifdef RTAC58U
	{ MODEL_GENERIC, "US", "noprinter nocloudsync nomodem" },
	{ MODEL_GENERIC, "CA", "noprinter nocloudsync nomodem" },
	{ MODEL_GENERIC, "SP", "loclist" },
	{ MODEL_RTAC58U, "CX/01", "loclist noupdate" },
	{ MODEL_RTAC58U, "CX/05", "loclist noupdate" },
#endif	/* RTAC58U */
#if defined(RTAC59U)
	{ MODEL_RTAC59U, "CX/05", "loclist noupdate" },
#endif	/* RTAC59U */
#ifdef RTAC82U
#endif	/* RTAC82U */
#ifdef RPAC51
#endif	/* RPAC51 */
#if defined(PLAX56_XP4)
	{ MODEL_PLAX56XP4, "EU/01", "non_frameburst" },
#endif
#elif defined(RTCONFIG_REALTEK)
#ifdef RPAC55
	{ MODEL_RPAC55, "AU/01", "dfs" },
	{ MODEL_RPAC55, "IL/01", "dfs" },
#endif
#elif defined(BLUECAVE)
	{ MODEL_BLUECAVE, "AA/01", "loclist" },
	{ MODEL_BLUECAVE, "CN/01", "loclist" },
	{ MODEL_BLUECAVE, "AU/01", "loclist" },
	{ MODEL_BLUECAVE, "KR/01", "defpsk loclist" },
#endif	/* CONFIG_BCMWL5 */

	{ 0, NULL, NULL }
};

struct tcode_rc_support_s tcode_del_rc_support_list[] = {
	/* remove feature */
#if defined(CONFIG_BCMWL5) || defined(RTCONFIG_RALINK) || defined(RTCONFIG_QCA) || defined(RTCONFIG_REALTEK)
	{ MODEL_GENERIC, "BZ", "loclist" },
	{ MODEL_GENERIC, "CA", "loclist" },
#if defined(RTAX82_XD6) || defined(RTAX82_XD6S)
	{ MODEL_GENERIC, "CH", "loclist" },
#endif
	{ MODEL_GENERIC, "CZ", "loclist" },
	{ MODEL_GENERIC, "DE", "loclist" },
	{ MODEL_GENERIC, "EE", "loclist" },
	{ MODEL_GENERIC, "EU", "loclist" },
	{ MODEL_GENERIC, "JP", "loclist" },
	{ MODEL_GENERIC, "ME", "loclist" },
	{ MODEL_GENERIC, "NE", "loclist" },
	{ MODEL_GENERIC, "RU", "loclist" },
	{ MODEL_GENERIC, "SA", "loclist" },
	{ MODEL_GENERIC, "SE", "loclist" },
	{ MODEL_GENERIC, "TR", "loclist" },
	{ MODEL_GENERIC, "TW", "loclist" },
	{ MODEL_GENERIC, "UA", "loclist" },
	{ MODEL_GENERIC, "UK", "loclist" },
	{ MODEL_GENERIC, "US", "loclist" },
	{ MODEL_GENERIC, "WE", "loclist" },
#endif

#ifdef CONFIG_BCMWL5
#ifdef DSL_AC68U
	{ MODEL_DSLAC68U, "AA/02", "loclist" },
	{ MODEL_DSLAC68U, "AU/02", "loclist" },
	{ MODEL_DSLAC68U, "IN/02", "loclist" },
#endif
#elif defined(RTCONFIG_RALINK)
#ifdef RTN11P_B1
	{ MODEL_RTN11P_B1, "CA/01", "vpnc pptpd" },
	{ MODEL_RTN11P_B1, "US/01", "vpnc pptpd" },
	{ MODEL_RTN11P_B1, "BZ/01", "vpnc pptpd" },
#ifdef RTN10P_V3
	{ MODEL_RTN11P_B1, "RU/01", "vpnc pptpd" },
#endif
#endif /* RTN11P_B1 */
#ifdef RTN800HP
	{ MODEL_GENERIC, "AP", "loclist" },
	{ MODEL_GENERIC, "AQ", "loclist" },
	{ MODEL_GENERIC, "AA", "loclist" },
#endif
#if defined(RTAC1200V2)
	{ MODEL_RTAC1200V2, "AA/01", "repeater" },
	{ MODEL_RTAC1200V2, "AR/01", "repeater" },
	{ MODEL_RTAC1200V2, "CA/01", "repeater" },
	{ MODEL_RTAC1200V2, "CN/01", "repeater" },
	{ MODEL_RTAC1200V2, "EU/01", "repeater" },
	{ MODEL_RTAC1200V2, "IL/01", "repeater" },
	{ MODEL_RTAC1200V2, "IN/01", "repeater" },
	{ MODEL_RTAC1200V2, "KR/01", "repeater" },
//	{ MODEL_RTAC1200V2, "RU/01", "repeater" },	/* only RU/01 support repeater mode */
	{ MODEL_RTAC1200V2, "TW/01", "repeater" },
	{ MODEL_RTAC1200V2, "US/01", "repeater" },
	{ MODEL_RTAC1200V2, "BZ/01", "repeater" },
#endif
#elif	defined(RTCONFIG_QCA)
#if defined(PLAC56)
	{ MODEL_GENERIC, "AU", "loclist" },
#endif
#ifdef RPAC51
	{ MODEL_GENERIC, "CN", "loclist" },
#endif
#elif defined(RTCONFIG_REALTEK)
#ifdef RPAC68U
	{ MODEL_RPAC68U, "AA/01", "loclist"},
	{ MODEL_RPAC68U, "AU/01", "loclist"},
#endif
#ifdef RPAC55
	{ MODEL_RPAC55, "AA/01", "loclist"},
	{ MODEL_RPAC55, "AU/01", "loclist"},
#endif
#endif	/* CONFIG_BCMWL5 */
	{ 0, NULL, NULL }
};

struct tcode_rc_support_by_odmpid_s tcode_del_rc_support_list_by_odmpid[] = {
#ifdef RTAC1200V2
	{ MODEL_RTAC1200V2, "RT-AC51", "EU/01", "dualwan" },
	{ MODEL_RTAC1200V2, "RT-AC51", "RU/01", "dualwan" },
	{ MODEL_RTAC1200V2, "RT-AC52", "TW/01", "dualwan" },
	{ MODEL_RTAC1200V2, "RT-AC750L", "AA/01", "dualwan" },
	{ MODEL_RTAC1200V2, "RT-AC750L", "IN/01", "dualwan" },
	{ MODEL_RTAC1200V2, "RT-AC750L", "EU/01", "dualwan" },
	{ MODEL_RTAC1200V2, "RT-AC750L", "RU/01", "dualwan" },
	{ MODEL_RTAC1200V2, "RT-AC750L", "KR/01", "dualwan" },
#endif
#ifdef RTACRH18
#endif	
	{ 0, NULL, NULL }
};

struct tcode_location_s tcode_location_list[] = {
	/* changing location */
#ifdef CONFIG_BCMWL5
#ifdef RTAC3200
	{ MODEL_RTAC3200, "AA", "%d:%s", 1, "AU", "999","AU", "999","AU", "999" },
	{ MODEL_RTAC3200, "CA", "%d:%s", 1, "CA", "70",	"CA", "70", "CA", "70" },
	{ MODEL_RTAC3200, "EE", "%d:%s", 1, "E0", "989","E0", "989","E0", "989" },
	{ MODEL_RTAC3200, "RU", "%d:%s", 1, "E0", "989","E0", "989","E0", "989" },
	{ MODEL_RTAC3200, "IN", "%d:%s", 1, "AU", "999","AU", "999","AU", "999" },
	{ MODEL_RTAC3200, "JP", "%d:%s", 1, "JP", "999","JP", "999","JP", "999" },
	{ MODEL_RTAC3200, "SG", "%d:%s", 1, "SG", "999","SQ", "999","SG", "999" },
	{ MODEL_RTAC3200, "TW", "%d:%s", 1, "TW", "64",	"TW", "64", "TW", "64" },
	{ MODEL_RTAC3200, "UK", "%d:%s", 1, "E0", "989","E0", "989","E0", "989" },
	{ MODEL_RTAC3200, "US", "%d:%s", 1, "Q2", "96",	"Q2", "96", "Q2", "96" },
	{ MODEL_RTAC3200, "WE", "%d:%s", 1, "E0", "989","E0", "989","E0", "989" },
#endif
#ifdef RTAC66U
	{ MODEL_RTAC66U, "AA", "pci/%d/1/%s", 1, "US", "0", "US", "0", NULL, NULL },
	{ MODEL_RTAC66U, "AP", "pci/%d/1/%s", 1, "US", "0", "Q2", "33", NULL, NULL },
	{ MODEL_RTAC66U, "AU", "pci/%d/1/%s", 1, "US", "0", "Q2", "33", NULL, NULL },
	{ MODEL_RTAC66U, "BZ", "pci/%d/1/%s", 1, "US", "0", "Q2", "33", NULL, NULL },
	{ MODEL_RTAC66U, "CA", "pci/%d/1/%s", 1, "US", "0", "US", "0", NULL, NULL },
	{ MODEL_RTAC66U, "CN", "pci/%d/1/%s", 1, "CN", "1", "CN", "1", NULL, NULL },
	{ MODEL_RTAC66U, "EE", "pci/%d/1/%s", 1, "EU", "13","EU", "31", NULL, NULL },
	{ MODEL_RTAC66U, "EU", "pci/%d/1/%s", 1, "EU", "13","EU", "31", NULL, NULL },
	{ MODEL_RTAC66U, "KR", "pci/%d/1/%s", 1, "KR", "44","KR", "44", NULL, NULL },
	{ MODEL_RTAC66U, "ME", "pci/%d/1/%s", 1, "EU", "13","EU", "31", NULL, NULL },
	{ MODEL_RTAC66U, "MY", "pci/%d/1/%s", 1, "US", "0", "Q2", "33", NULL, NULL },
	{ MODEL_RTAC66U, "RU", "pci/%d/1/%s", 1, "EU", "13","EU", "31", NULL, NULL },
	{ MODEL_RTAC66U, "SG", "pci/%d/1/%s", 1, "US", "0", "US", "0", NULL, NULL },
	{ MODEL_RTAC66U, "TR", "pci/%d/1/%s", 1, "EU", "13","EU", "31", NULL, NULL },
	{ MODEL_RTAC66U, "TW", "pci/%d/1/%s", 1, "TW", "0", "TW", "0", NULL, NULL },
	{ MODEL_RTAC66U, "UA", "pci/%d/1/%s", 1, "EU", "13","EU", "31", NULL, NULL },
	{ MODEL_RTAC66U, "UK", "pci/%d/1/%s", 1, "EU", "13","EU", "31", NULL, NULL },
	{ MODEL_RTAC66U, "US", "pci/%d/1/%s", 1, "US", "0", "Q2", "33", NULL, NULL },
	{ MODEL_RTAC66U, "WE", "pci/%d/1/%s", 1, "EU", "13","EU", "31", NULL, NULL },
	{ MODEL_RTAC66U, "XX", "pci/%d/1/%s", 1, "Q2", "12","Q2", "12", NULL, NULL },
#endif
#ifdef RTAC68U
	{ MODEL_RTAC68U, "AA", "%d:%s", 0, "GB","995", "GB","995", NULL, NULL, RT4GAC68U_V1_C0 },
	{ MODEL_RTAC68U, "AA", "%d:%s", 0, "US",  "0", "US",  "0", NULL, NULL, RTAC68U_V1_ALL },
	{ MODEL_RTAC68U, "AA", "%d:%s", 0, "Q2", "61", "Q2", "61", NULL, NULL, RTAC66U_V2 },
	{ MODEL_RTAC68U, "AP", "%d:%s", 0, "US",  "0", "US",  "0", NULL, NULL, RTAC68U_V1_ALL },
	{ MODEL_RTAC68U, "AU", "%d:%s", 0, "AU","927", "AU","927", NULL, NULL, RT4GAC68U_V1_C0 },
	{ MODEL_RTAC68U, "AU", "%d:%s", 0, "AU", "36", "AU", "36", NULL, NULL, RTAC66U_V2 },
	{ MODEL_RTAC68U, "BZ", "%d:%s", 0, "US",  "0", "US",  "0", NULL, NULL, RTAC68U_V1_ALL },
	{ MODEL_RTAC68U, "CA", "%d:%s", 0, "US",  "0", "US",  "0", NULL, NULL, RTAC68U_V1_ALL },
	{ MODEL_RTAC68U, "CA", "%d:%s", 0, "CA", "60", "CA", "60", NULL, NULL, RTAC66U_V2 },
	{ MODEL_RTAC68U, "CN", "%d:%s", 0, "CN",  "1", "CN",  "1", NULL, NULL, RTAC68U_V1_ALL | RTAC68U_V2_C0 },
	{ MODEL_RTAC68U, "CN", "%d:%s", 0, "CN", "56", "CN", "56", NULL, NULL, RTAC66U_V2 },
	{ MODEL_RTAC68U, "EE", "%d:%s", 0, "EU", "33", "EU", "33", NULL, NULL, RTAC66U_V2 },
	{ MODEL_RTAC68U, "EU", "%d:%s", 0, "GB","995", "GB","995", NULL, NULL, RT4GAC68U_V1_C0 },
	{ MODEL_RTAC68U, "EU", "%d:%s", 0, "EU", "13", "EU", "13", NULL, NULL, RTAC68U_V1_ALL },
	{ MODEL_RTAC68U, "EU", "%d:%s", 0, "EU", "33", "EU", "33", NULL, NULL, RTAC66U_V2 },
	{ MODEL_RTAC68U, "IL", "%d:%s", 0, "IL", "11", "IL", "11", NULL, NULL, RTAC66U_V2 },
	{ MODEL_RTAC68U, "IN", "%d:%s", 0, "Q2", "61", "Q2", "61", NULL, NULL, RTAC66U_V2 },
	{ MODEL_RTAC68U, "JP", "%d:%s", 0, "JP", "45", "JP", "45", NULL, NULL, RTAC68U_V1_ALL },
	{ MODEL_RTAC68U, "JP", "%d:%s", 0, "JP", "39", "JP", "39", NULL, NULL, RTAC66U_V2 },
	{ MODEL_RTAC68U, "KR", "%d:%s", 0, "KR", "41", "KR", "41", NULL, NULL, RTAC68U_V1_ALL },
	{ MODEL_RTAC68U, "ME", "%d:%s", 0, "EU", "13", "EU", "13", NULL, NULL, RTAC68U_V1_ALL },
	{ MODEL_RTAC68U, "MY", "%d:%s", 0, "US",  "0", "US",  "0", NULL, NULL, RTAC68U_V1_ALL },
	{ MODEL_RTAC68U, "RU", "%d:%s", 0, "EU", "33", "EU", "33", NULL, NULL, RTAC66U_V2 },
	{ MODEL_RTAC68U, "RU", "%d:%s", 0, "GB","995", "GB","995", NULL, NULL, RT4GAC68U_V1_C0 },
	{ MODEL_RTAC68U, "RU", "%d:%s", 0, "EU", "13", "EU", "13", NULL, NULL, RTAC68U_V1_ALL },
	{ MODEL_RTAC68U, "SG", "%d:%s", 0, "SG",  "0", "SG",  "0", NULL, NULL, RTAC68U_V1_ALL },
	{ MODEL_RTAC68U, "SG", "%d:%s", 0, "SG", "22", "SG", "22", NULL, NULL, RTAC66U_V2 },
	{ MODEL_RTAC68U, "TR", "%d:%s", 0, "EU", "13", "EU", "13", NULL, NULL, RTAC68U_V1_ALL },
	{ MODEL_RTAC68U, "TW", "%d:%s", 0, "TW",  "0", "TW",  "0", NULL, NULL, RTAC68U_V1 | RTAC68U_V1_C0 },
	{ MODEL_RTAC68U, "TW", "%d:%s", 0, "TW", "50", "TW", "50", NULL, NULL, RTAC66U_V2 },
	{ MODEL_RTAC68U, "TW", "%d:%s", 0, "Q2", "33", "Q2", "33", NULL, NULL, RTAC68U_V3_C0 },
	{ MODEL_RTAC68U, "UA", "%d:%s", 0, "EU", "13", "EU", "13", NULL, NULL, RTAC68U_V1_ALL },
	{ MODEL_RTAC68U, "UK", "%d:%s", 0, "GB","995", "GB","995", NULL, NULL, RT4GAC68U_V1_C0 },
	{ MODEL_RTAC68U, "UK", "%d:%s", 0, "EU", "13", "EU", "13", NULL, NULL, RTAC68U_V1_ALL },
	{ MODEL_RTAC68U, "UK", "%d:%s", 0, "EU", "33", "EU", "33", NULL, NULL, RTAC66U_V2 },
	{ MODEL_RTAC68U, "US", "%d:%s", 0, "US",  "0", "US",  "0", NULL, NULL, RTAC68U_V1 },
	{ MODEL_RTAC68U, "US", "%d:%s", 0, "Q2", "33", "Q2", "33", NULL, NULL, RTAC68U_V1_C0 | RTAC68U_V3_C0 },
	{ MODEL_RTAC68U, "US", "%d:%s", 0, "Q2", "40", "Q2", "40", NULL, NULL, RTAC68U_V2_ALL },
	{ MODEL_RTAC68U, "US", "%d:%s", 0, "Q2", "61", "Q2", "61", NULL, NULL, RTAC66U_V2 },
	{ MODEL_RTAC68U, "U2", "%d:%s", 0, "Q2", "40", "Q2", "40", NULL, NULL, RTAC68U_V2 },
	{ MODEL_RTAC68U, "WE", "%d:%s", 0, "EU", "33", "EU", "33", NULL, NULL, RTAC66U_V2 },
	{ MODEL_RTAC68U, "XX", "%d:%s", 0, "CN",  "5", "CN",  "5", NULL, NULL, RTAC68U_ALL },
	{ MODEL_RTAC68U, "XY", "%d:%s", 0, "EU", "15", "EU", "15", NULL, NULL, RTAC68U_ALL },
#endif
#ifdef RTAC87U
	{ MODEL_RTAC87U, "AA", "%d:%s", 0, "US", "0", "US", "0", NULL, NULL },
	{ MODEL_RTAC87U, "AP", "%d:%s", 0, "US", "0", "US", "0", NULL, NULL },
	{ MODEL_RTAC87U, "HK", "%d:%s", 0, "US", "0", "US", "0", NULL, NULL },
	{ MODEL_RTAC87U, "AU", "%d:%s", 0, "US", "0", "US", "0", NULL, NULL },
	{ MODEL_RTAC87U, "BZ", "%d:%s", 0, "US", "0", "US", "0", NULL, NULL },
	{ MODEL_RTAC87U, "CA", "%d:%s", 0, "US", "0", "CA", "0", NULL, NULL },
	{ MODEL_RTAC87U, "CN", "%d:%s", 0, "CN", "1", "CN", "0", NULL, NULL },
	{ MODEL_RTAC87U, "EE", "%d:%s", 0, "EU", "13","EU", "0", NULL, NULL },
	{ MODEL_RTAC87U, "EU", "%d:%s", 0, "EU", "13","EU", "0", NULL, NULL },
	{ MODEL_RTAC87U, "JP", "%d:%s", 0, "JP", "45","JP", "0", NULL, NULL },
	{ MODEL_RTAC87U, "KR", "%d:%s", 0, "KR", "45","KR", "0", NULL, NULL },
	{ MODEL_RTAC87U, "ME", "%d:%s", 0, "EU", "13","EU", "0", NULL, NULL },
	{ MODEL_RTAC87U, "MY", "%d:%s", 0, "US", "0", "US", "0", NULL, NULL },
	{ MODEL_RTAC87U, "RU", "%d:%s", 0, "EU", "13","EU", "0", NULL, NULL },
	{ MODEL_RTAC87U, "SG", "%d:%s", 0, "SG", "0", "SG", "0", NULL, NULL },
	{ MODEL_RTAC87U, "TR", "%d:%s", 0, "EU", "13","EU", "0", NULL, NULL },
	{ MODEL_RTAC87U, "TW", "%d:%s", 0, "US", "0", "TW", "0", NULL, NULL },
	{ MODEL_RTAC87U, "UA", "%d:%s", 0, "EU", "13","EU", "0", NULL, NULL },
	{ MODEL_RTAC87U, "UK", "%d:%s", 0, "EU", "13","EU", "0", NULL, NULL },
	{ MODEL_RTAC87U, "US", "%d:%s", 0, "US", "0", "US", "0", NULL, NULL },
	{ MODEL_RTAC87U, "WE", "%d:%s", 0, "EU", "13","EU", "0", NULL, NULL },
	{ MODEL_RTAC87U, "XX", "%d:%s", 0, "AU", "0", "AU", "0", NULL, NULL },
#endif
#ifdef RTAC88U
	{ MODEL_RTAC88U, "U2", "%d:%s", 0, "US", "793", "US", "793", NULL, NULL },
	{ MODEL_RTAC88U, "US", "%d:%s", 0, "Q2", "992", "Q2", "992", NULL, NULL },
	{ MODEL_RTAC88U, "AA", "%d:%s", 0, "US", "758", "US", "758", NULL, NULL },
	{ MODEL_RTAC88U, "AP", "%d:%s", 0, "Q2", "992", "Q2", "992", NULL, NULL },
	{ MODEL_RTAC88U, "CA", "%d:%s", 0, "CA", "878", "CA", "878", NULL, NULL },
	{ MODEL_RTAC88U, "SG", "%d:%s", 0, "SG", "978", "SG", "978", NULL, NULL },
	{ MODEL_RTAC88U, "JP", "%d:%s", 0, "JP", "94","JP", "94", NULL, NULL },
	{ MODEL_RTAC88U, "KR", "%d:%s", 0, "KR", "932","KR", "932", NULL, NULL },
	{ MODEL_RTAC88U, "WE", "%d:%s", 0, "E0", "745","E0", "745", NULL, NULL },
	{ MODEL_RTAC88U, "EE", "%d:%s", 0, "E0", "745","E0", "745", NULL, NULL },
	{ MODEL_RTAC88U, "EU", "%d:%s", 0, "E0", "745","E0", "745", NULL, NULL },
	{ MODEL_RTAC88U, "UK", "%d:%s", 0, "E0", "745","E0", "745", NULL, NULL },
	{ MODEL_RTAC88U, "CN", "%d:%s", 0, "CN", "63", "CN", "63", NULL, NULL },
	{ MODEL_RTAC88U, "TW", "%d:%s", 0, "TW", "969", "TW", "969", NULL, NULL },
	{ MODEL_RTAC88U, "RU", "%d:%s", 0, "E0", "745","E0", "745", NULL, NULL },
	{ MODEL_RTAC88U, "AU", "%d:%s", 0, "AU", "903", "AU", "903", NULL, NULL },
	{ MODEL_RTAC88U, "XX", "%d:%s", 0, "Q1", "947", "Q1", "947", NULL, NULL },
	{ MODEL_RTAC88U, "CX", "%d:%s", 0, "US", "758", "US", "758", NULL, NULL },
	{ MODEL_RTAC88U, "IL", "%d:%s", 0, "E0", "745","E0", "745", NULL, NULL },
#endif
#ifdef RTAC3100
	{ MODEL_RTAC3100, "U2", "%d:%s", 0, "US", "793", "US", "793", NULL, NULL },
	{ MODEL_RTAC3100, "US", "%d:%s", 0, "Q2", "992", "Q2", "992", NULL, NULL },
	{ MODEL_RTAC3100, "AA", "%d:%s", 0, "US", "758", "US", "758", NULL, NULL },
	{ MODEL_RTAC3100, "CA", "%d:%s", 0, "CA", "878", "CA", "878", NULL, NULL },
	{ MODEL_RTAC3100, "EU", "%d:%s", 0, "E0", "745", "E0", "745", NULL, NULL },
#endif
#ifdef RTAC86U
	{ MODEL_RTAC86U, "AA", "%d:%s", 0, "Q2", "992", "Q2", "992", NULL, NULL },
	{ MODEL_RTAC86U, "A2", "%d:%s", 0, "US", "0",   "US", "0",   NULL, NULL },
	{ MODEL_RTAC86U, "AU", "%d:%s", 0, "AU", "984", "AU", "984", NULL, NULL },
	{ MODEL_RTAC86U, "BZ", "%d:%s", 0, "Q2", "992", "Q2", "992", NULL, NULL },
	{ MODEL_RTAC86U, "CA", "%d:%s", 0, "CA", "987", "CA", "987", NULL, NULL },
	{ MODEL_RTAC86U, "CN", "%d:%s", 0, "CN", "63",  "CN", "63",  NULL, NULL },
	{ MODEL_RTAC86U, "CT", "%d:%s", 0, "CN", "0",   "CN", "0",   NULL, NULL },
	{ MODEL_RTAC86U, "CX", "%d:%s", 0, "Q2", "992", "Q2", "992", NULL, NULL },
	{ MODEL_RTAC86U, "EE", "%d:%s", 0, "E0", "962", "E0", "962", NULL, NULL },
	{ MODEL_RTAC86U, "EU", "%d:%s", 0, "E0", "962", "E0", "962", NULL, NULL },
	{ MODEL_RTAC86U, "RU", "%d:%s", 0, "E0", "962", "E0", "962", NULL, NULL },
	{ MODEL_RTAC86U, "IL", "%d:%s", 0, "IL", "0",   "IL", "0",   NULL, NULL },
	{ MODEL_RTAC86U, "IN", "%d:%s", 0, "Q2", "992", "Q2", "992", NULL, NULL },
	{ MODEL_RTAC86U, "JP", "%d:%s", 0, "JP", "94",  "JP", "94",  NULL, NULL },
	{ MODEL_RTAC86U, "KR", "%d:%s", 0, "KR", "975", "KR", "975", NULL, NULL },
	{ MODEL_RTAC86U, "SG", "%d:%s", 0, "Q2", "992", "Q2", "992", NULL, NULL },
	{ MODEL_RTAC86U, "TW", "%d:%s", 0, "TW", "994", "TW", "994", NULL, NULL },
	{ MODEL_RTAC86U, "UK", "%d:%s", 0, "E0", "962", "E0", "962", NULL, NULL },
#ifdef RTCONFIG_DFS_US
	{ MODEL_RTAC86U, "U2", "%d:%s", 0, "US", "0",   "US", "0",   NULL, NULL },
#endif
	{ MODEL_RTAC86U, "US", "%d:%s", 0, "Q2", "992", "Q2", "992", NULL, NULL },
	{ MODEL_RTAC86U, "WE", "%d:%s", 0, "E0", "962", "E0", "962", NULL, NULL },
	{ MODEL_RTAC86U, "XX", "%d:%s", 0, "CN", "998", "CN", "998", NULL, NULL },
#endif
#ifdef GTAC2900
	{ MODEL_RTAC86U, "AA", "%d:%s", 0, "US", "1",   "US", "1",   NULL, NULL },
	{ MODEL_RTAC86U, "CA", "%d:%s", 0, "CA", "987", "CA", "987", NULL, NULL },
	{ MODEL_RTAC86U, "CN", "%d:%s", 0, "CN", "63",  "CN", "63",  NULL, NULL },
	{ MODEL_RTAC86U, "CX", "%d:%s", 0, "US", "1",   "US", "1",   NULL, NULL },
	{ MODEL_RTAC86U, "EE", "%d:%s", 0, "E0", "946", "E0", "946", NULL, NULL },
	{ MODEL_RTAC86U, "EU", "%d:%s", 0, "E0", "946", "E0", "946", NULL, NULL },
	{ MODEL_RTAC86U, "UK", "%d:%s", 0, "E0", "946", "E0", "946", NULL, NULL },
	{ MODEL_RTAC86U, "WE", "%d:%s", 0, "E0", "946", "E0", "946", NULL, NULL },
	{ MODEL_RTAC86U, "IL", "%d:%s", 0, "IL", "0",   "IL", "0",   NULL, NULL },
	{ MODEL_RTAC86U, "JP", "%d:%s", 0, "JP", "94",  "JP", "94",  NULL, NULL },
	{ MODEL_RTAC86U, "KR", "%d:%s", 0, "KR", "975", "KR", "975", NULL, NULL },
	{ MODEL_RTAC86U, "TW", "%d:%s", 0, "US", "0",   "US", "0",   NULL, NULL },
	{ MODEL_RTAC86U, "US", "%d:%s", 0, "US", "0",   "US", "0",   NULL, NULL },
	{ MODEL_RTAC86U, "XX", "%d:%s", 0, "CN", "998", "CN", "998", NULL, NULL },
#endif
#ifdef RTAC5300
	{ MODEL_RTAC5300, "US", "%d:%s", 0, "Q1", "984", "Q1", "984", "Q1", "984" },
	{ MODEL_RTAC5300, "CA", "%d:%s", 0, "CA", "986", "CA", "986", "CA", "986" },
	{ MODEL_RTAC5300, "AA", "%d:%s", 0, "Q1", "984", "Q1", "984", "Q1", "984" },
	{ MODEL_RTAC5300, "AP", "%d:%s", 0, "Q1", "984", "Q1", "984", "Q1", "984" },
	{ MODEL_RTAC5300, "SG", "%d:%s", 0, "SG", "991", "SG", "991", "SG", "991" },
	{ MODEL_RTAC5300, "WE", "%d:%s", 0, "E0", "946", "E0", "946", "E0", "946" },
	{ MODEL_RTAC5300, "EE", "%d:%s", 0, "E0", "946", "E0", "946", "E0", "946" },
	{ MODEL_RTAC5300, "EU", "%d:%s", 0, "E0", "946", "E0", "946", "E0", "946" },
	{ MODEL_RTAC5300, "UK", "%d:%s", 0, "E0", "946", "E0", "946", "E0", "946" },
	{ MODEL_RTAC5300, "TW", "%d:%s", 0, "TW", "993", "TW", "993", "TW", "993" },
	{ MODEL_RTAC5300, "CN", "%d:%s", 0, "CN", "998", "CN", "998", "CN", "998" },
	{ MODEL_RTAC5300, "AU", "%d:%s", 0, "AU", "986", "AU", "986", "AU", "986" },
	{ MODEL_RTAC5300, "RU", "%d:%s", 0, "E0", "946", "E0", "946", "E0", "946" },
	{ MODEL_RTAC5300, "IN", "%d:%s", 0, "Q1", "984", "Q1", "984", "Q1", "984" },
	{ MODEL_RTAC5300, "XX", "%d:%s", 0, "Q1", "947", "Q1", "947", "Q1", "947" },
#endif
#ifdef GTAC5300
	{ MODEL_GTAC5300, "US", "%d:%s", 1, "Q1", "984", "Q1", "984", "Q1", "984" },
	{ MODEL_GTAC5300, "CA", "%d:%s", 1, "CA", "986", "CA", "986", "CA", "986" },
	{ MODEL_GTAC5300, "AA", "%d:%s", 1, "Q1", "984", "Q1", "984", "Q1", "984" },
	{ MODEL_GTAC5300, "AP", "%d:%s", 1, "Q1", "984", "Q1", "984", "Q1", "984" },
	{ MODEL_GTAC5300, "SG", "%d:%s", 1, "SG", "991", "SG", "991", "SG", "991" },
	{ MODEL_GTAC5300, "WE", "%d:%s", 1, "E0", "946", "E0", "946", "E0", "946" },
	{ MODEL_GTAC5300, "EE", "%d:%s", 1, "E0", "946", "E0", "946", "E0", "946" },
	{ MODEL_GTAC5300, "EU", "%d:%s", 1, "E0", "946", "E0", "946", "E0", "946" },
	{ MODEL_GTAC5300, "RU", "%d:%s", 1, "E0", "946", "E0", "946", "E0", "946" },
	{ MODEL_GTAC5300, "UK", "%d:%s", 1, "E0", "946", "E0", "946", "E0", "946" },
	{ MODEL_GTAC5300, "TW", "%d:%s", 1, "TW", "993", "TW", "993", "TW", "993" },
	{ MODEL_GTAC5300, "CN", "%d:%s", 1, "CN", "963", "CN", "963", "CN", "963" },
	{ MODEL_GTAC5300, "JP", "%d:%s", 1, "JP", "103", "JP", "103", "JP", "103" },
	{ MODEL_GTAC5300, "KR", "%d:%s", 1, "KR", "954", "KR", "954", "KR", "954" },
	{ MODEL_GTAC5300, "XX", "%d:%s", 1, "Q1", "947", "Q1", "947", "Q1", "947" },
#endif
#ifdef RTAX88U
	{ MODEL_RTAX88U, "US", "%d:%s", 1, "US", "823", "US", "823", NULL, NULL },
	{ MODEL_RTAX88U, "CA", "%d:%s", 1, "CA", "887", "CA", "887", NULL, NULL },
	{ MODEL_RTAX88U, "AA", "%d:%s", 1, "US", "817", "US", "817", NULL, NULL },
	{ MODEL_RTAX88U, "EU", "%d:%s", 1, "DE", "963", "DE", "963", NULL, NULL },
	{ MODEL_RTAX88U, "UK", "%d:%s", 1, "DE", "963", "DE", "963", NULL, NULL },
	{ MODEL_RTAX88U, "JP", "%d:%s", 1, "JP", "914", "JP", "914", NULL, NULL },
	{ MODEL_RTAX88U, "KR", "%d:%s", 1, "KR", "937", "KR", "937", NULL, NULL },
	{ MODEL_RTAX88U, "RU", "%d:%s", 1, "DE", "963", "DE", "963", NULL, NULL },
	{ MODEL_RTAX88U, "S2", "%d:%s", 1, "US", "817", "US", "817", NULL, NULL },
	{ MODEL_RTAX88U, "SG", "%d:%s", 1, "US", "817", "US", "817", NULL, NULL },
	{ MODEL_RTAX88U, "TW", "%d:%s", 1, "US", "823", "US", "823", NULL, NULL },
	{ MODEL_RTAX88U, "CN", "%d:%s", 1, "CN", "950", "CN", "950", NULL, NULL },
	{ MODEL_RTAX88U, "IL", "%d:%s", 1, "DE", "963", "DE", "963", NULL, NULL },
	{ MODEL_RTAX88U, "XX", "%d:%s", 1, "CN", "947", "CN", "947", NULL, NULL },
	{ MODEL_RTAX88U, "BZ", "%d:%s", 1, "US", "823", "US", "823", NULL, NULL },
#endif

#ifdef GTAX11000
	{ MODEL_GTAX11000, "AA", "%d:%s", 1, "US", "816", "US", "816", "US", "816" },
	{ MODEL_GTAX11000, "CA", "%d:%s", 1, "CA", "886", "CA", "886", "CA", "886" },
	{ MODEL_GTAX11000, "CN", "%d:%s", 1, "CN", "948", "CN", "948", "CN", "948" },
	{ MODEL_GTAX11000, "EU", "%d:%s", 1, "E0", "770", "E0", "770", "E0", "770" },
	{ MODEL_GTAX11000, "IL", "%d:%s", 1, "E0", "770", "E0", "770", "E0", "770" },
	{ MODEL_GTAX11000, "JP", "%d:%s", 1, "JP", "908", "JP", "908", "JP", "908" },
	{ MODEL_GTAX11000, "KR", "%d:%s", 1, "KR", "936", "KR", "936", "KR", "936" },
	{ MODEL_GTAX11000, "RU", "%d:%s", 1, "E0", "770", "E0", "770", "E0", "770" },
	{ MODEL_GTAX11000, "S2", "%d:%s", 1, "US", "816", "US", "816", "US", "816" },
	{ MODEL_GTAX11000, "SG", "%d:%s", 1, "US", "816", "US", "816", "US", "816" },
	{ MODEL_GTAX11000, "TW", "%d:%s", 1, "TW", "973", "TW", "973", "TW", "973" },
	{ MODEL_GTAX11000, "US", "%d:%s", 1, "US", "821", "US", "821", "US", "821" },
	{ MODEL_GTAX11000, "XX", "%d:%s", 1, "CN", "947", "CN", "947", "CN", "947" },
#endif

#ifdef RTAX92U
	{ MODEL_RTAX92U, "US", "%d:%s", 1, "US", "815", "US", "815", "US", "814" },
	{ MODEL_RTAX92U, "EU", "%d:%s", 1, "DE", "959", "DE", "959", "DE", "958" },
	{ MODEL_RTAX92U, "UK", "%d:%s", 1, "DE", "959", "DE", "959", "DE", "958" },
	{ MODEL_RTAX92U, "AU", "%d:%s", 1, "AU", "914", "AU", "914", "AU", "913" },
	{ MODEL_RTAX92U, "CA", "%d:%s", 1, "CA", "883", "CA", "883", "CA", "882" },
	{ MODEL_RTAX92U, "AA", "%d:%s", 1, "US", "815", "US", "815", "CA", "882" },
	{ MODEL_RTAX92U, "S2", "%d:%s", 1, "US", "815", "US", "815", "CA", "882" },
	{ MODEL_RTAX92U, "TW", "%d:%s", 1, "US", "815", "US", "815", "US", "814" },
	{ MODEL_RTAX92U, "CN", "%d:%s", 1, "CN", "945", "CN", "945", "CN", "944" },
	{ MODEL_RTAX92U, "RU", "%d:%s", 1, "DE", "959", "DE", "959", "DE", "958" },
	{ MODEL_RTAX92U, "XX", "%d:%s", 1, "CN", "943", "CN", "943", "CN", "942" },
	{ MODEL_RTAX92U, "JP", "%d:%s", 1, "JP", "905", "JP", "905", "JP", "904" },
#endif

#ifdef GTAXE11000
	{ MODEL_GTAXE11000, "EU", "%d:%s", 1, "E0", "652", "E0", "652", "E0", "652" },
	{ MODEL_GTAXE11000, "KR", "%d:%s", 1, "KR", "913", "KR", "913", "KR", "913" },
	{ MODEL_GTAXE11000, "US", "%d:%s", 1, "US", "699", "US", "699", "US", "699" },
#endif

#ifdef GTAX6000
	{ MODEL_GTAX6000, "EU", "%d:%s", 1, "E0", "650", "E0", "650", NULL, NULL },
	{ MODEL_GTAX6000, "IL", "%d:%s", 1, "E0", "650", "E0", "650", NULL, NULL },
	{ MODEL_GTAX6000, "JP", "%d:%s", 1, "JP", "858", "JP", "858", NULL, NULL },
	{ MODEL_GTAX6000, "KR", "%d:%s", 1, "KR", "910", "KR", "910", NULL, NULL },
	{ MODEL_GTAX6000, "UK", "%d:%s", 1, "E0", "650", "E0", "650", NULL, NULL },
	{ MODEL_GTAX6000, "US", "%d:%s", 1, "US", "650", "US", "650", NULL, NULL },
	{ MODEL_GTAX6000, "CN", "%d:%s", 1, "CN", "908", "CN", "908", NULL, NULL },
	{ MODEL_GTAX6000, "XX", "%d:%s", 1, "CN", "907", "CN", "907", NULL, NULL },
#endif

#ifdef GTAX11000_PRO
	{ MODEL_GTAX11000_PRO, "US", "%d:%s", 1, "Q1", "159", "Q1", "159", "Q1", "159" },
#endif

#ifdef GTAXE16000
	{ MODEL_GTAXE16000, "US", "%d:%s", 1, "Q1", "159", "Q1", "159", "Q1", "159" },
#endif

#ifdef ET12
	{ MODEL_ET12, "EU", "%d:%s", 1, "E0", "648", "E0", "648", "E0", "648" },
	{ MODEL_ET12, "US", "%d:%s", 1, "US", "654", "US", "654", "US", "654" },
#endif

#ifdef XT12
	{ MODEL_XT12, "AU", "%d:%s", 1, "AU", "865", "AU", "865", "AU", "865" },
	{ MODEL_XT12, "CN", "%d:%s", 1, "CN", "910", "CN", "910", "CN", "910" },
	{ MODEL_XT12, "EU", "%d:%s", 1, "E0", "666", "E0", "666", "E0", "666" },
	{ MODEL_XT12, "TW", "%d:%s", 1, "TW", "966", "TW", "966", "TW", "966" },
	{ MODEL_XT12, "US", "%d:%s", 1, "US", "653", "US", "653", "US", "653" },
	{ MODEL_XT12, "XX", "%d:%s", 1, "CN", "909", "CN", "909", "CN", "909" },
#endif

#ifdef RTAX95Q
	{ MODEL_RTAX95Q, "US", "%d:%s", 0, "US", "767", "US", "767", "US", "767" },
	{ MODEL_RTAX95Q, "CA", "%d:%s", 0, "CA", "864", "CA", "864", "CA", "864" },
	{ MODEL_RTAX95Q, "AA", "%d:%s", 0, "US", "767", "US", "767", "US", "767" },
	{ MODEL_RTAX95Q, "AU", "%d:%s", 0, "US", "755", "US", "755", "US", "755" },
	{ MODEL_RTAX95Q, "EU", "%d:%s", 0, "E0", "740", "E0", "740", "E0", "740" },
	{ MODEL_RTAX95Q, "UK", "%d:%s", 0, "E0", "740", "E0", "740", "E0", "740" },
	{ MODEL_RTAX95Q, "JP", "%d:%s", 0, "JP", "888", "JP", "888", "JP", "888" },
	{ MODEL_RTAX95Q, "KR", "%d:%s", 0, "KR", "924", "KR", "924", "KR", "923" },
	{ MODEL_RTAX95Q, "TW", "%d:%s", 0, "US", "767", "US", "767", "US", "767" },
	{ MODEL_RTAX95Q, "CN", "%d:%s", 0, "CN", "933", "CN", "933", "CN", "933" },
	{ MODEL_RTAX95Q, "XX", "%d:%s", 0, "CN", "925", "CN", "925", "CN", "925" },
#endif

#ifdef XT8PRO
	{ MODEL_XT8PRO, "US", "%d:%s", 0, "US", "636", "US", "636", "US", "636" },
	{ MODEL_XT8PRO, "CA", "%d:%s", 0, "CA", "810", "CA", "810", "CA", "810" },
	{ MODEL_XT8PRO, "AA", "%d:%s", 0, "US", "632", "US", "632", "US", "632" },
	{ MODEL_XT8PRO, "AU", "%d:%s", 0, "AU", "863", "AU", "863", "AU", "863" },
	{ MODEL_XT8PRO, "EU", "%d:%s", 0, "E0", "645", "E0", "645", "E0", "645" },
	{ MODEL_XT8PRO, "UK", "%d:%s", 0, "E0", "740", "E0", "740", "E0", "740" },
	{ MODEL_XT8PRO, "JP", "%d:%s", 0, "JP", "894", "JP", "894", "JP", "894" },
	{ MODEL_XT8PRO, "KR", "%d:%s", 0, "KR", "937", "KR", "937", "Q1", "151" },
	{ MODEL_XT8PRO, "TW", "%d:%s", 0, "US", "632", "US", "632", "US", "632" },
	{ MODEL_XT8PRO, "CN", "%d:%s", 0, "CN", "903", "CN", "903", "CN", "903" },
	{ MODEL_XT8PRO, "XX", "%d:%s", 0, "CN", "902", "CN", "902", "CN", "902" },
#endif

#ifdef XT8_V2
	{ MODEL_XT8_V2, "US", "%d:%s", 0, "US", "635", "US", "635", "US", "635" },
	{ MODEL_XT8_V2, "CA", "%d:%s", 0, "CA", "811", "CA", "811", "CA", "811" },
	{ MODEL_XT8_V2, "AA", "%d:%s", 0, "US", "633", "US", "633", "US", "633" },
	{ MODEL_XT8_V2, "AU", "%d:%s", 0, "AU", "862", "AU", "862", "AU", "862" },
	{ MODEL_XT8_V2, "EU", "%d:%s", 0, "E0", "641", "E0", "641", "E0", "643" },
	{ MODEL_XT8_V2, "UK", "%d:%s", 0, "E0", "740", "E0", "740", "E0", "740" },
	{ MODEL_XT8_V2, "JP", "%d:%s", 0, "JP", "894", "JP", "894", "JP", "894" },
	{ MODEL_XT8_V2, "KR", "%d:%s", 0, "KR", "937", "KR", "937", "Q1", "151" },
	{ MODEL_XT8_V2, "TW", "%d:%s", 0, "US", "633", "US", "633", "US", "633" },
	{ MODEL_XT8_V2, "CN", "%d:%s", 0, "CN", "900", "CN", "900", "CN", "900" },
	{ MODEL_XT8_V2, "XX", "%d:%s", 0, "CN", "901", "CN", "901", "CN", "901" },
#endif

#ifdef RTAXE95Q
	{ MODEL_RTAXE95Q, "US", "%d:%s", 0, "US", "767", "US", "767", "US", "767" },
	{ MODEL_RTAXE95Q, "CA", "%d:%s", 0, "CA", "864", "CA", "864", "CA", "864" },
	{ MODEL_RTAXE95Q, "AA", "%d:%s", 0, "US", "767", "US", "767", "US", "767" },
	{ MODEL_RTAXE95Q, "AU", "%d:%s", 0, "US", "755", "US", "755", "US", "755" },
	{ MODEL_RTAXE95Q, "EU", "%d:%s", 0, "E0", "740", "E0", "740", "E0", "740" },
	{ MODEL_RTAXE95Q, "UK", "%d:%s", 0, "E0", "740", "E0", "740", "E0", "740" },
	{ MODEL_RTAXE95Q, "JP", "%d:%s", 0, "JP", "888", "JP", "888", "JP", "888" },
	{ MODEL_RTAXE95Q, "KR", "%d:%s", 0, "KR", "924", "KR", "924", "KR", "923" },
	{ MODEL_RTAXE95Q, "TW", "%d:%s", 0, "US", "767", "US", "767", "US", "767" },
	{ MODEL_RTAXE95Q, "CN", "%d:%s", 0, "CN", "933", "CN", "933", "CN", "933" },
	{ MODEL_RTAXE95Q, "XX", "%d:%s", 0, "CN", "925", "CN", "925", "CN", "925" },
#endif

#ifdef ET8PRO
	{ MODEL_ET8PRO, "US", "%d:%s", 0, "US", "823", "US", "823", "Q1", "149" },
	{ MODEL_ET8PRO, "CA", "%d:%s", 0, "CA", "887", "CA", "887", "CA", "886" },
	{ MODEL_ET8PRO, "AA", "%d:%s", 0, "US", "823", "US", "823", "Q1", "151" },
	{ MODEL_ET8PRO, "AU", "%d:%s", 0, "US", "817", "US", "817", "CA", "886" },
	{ MODEL_ET8PRO, "EU", "%d:%s", 0, "DE", "963", "DE", "963", "E0", "666" },
	{ MODEL_ET8PRO, "UK", "%d:%s", 0, "E0", "740", "E0", "740", "E0", "740" },
	{ MODEL_ET8PRO, "JP", "%d:%s", 0, "JP", "894", "JP", "894", "JP", "894" },
	{ MODEL_ET8PRO, "KR", "%d:%s", 0, "KR", "937", "KR", "937", "Q1", "151" },
	{ MODEL_ET8PRO, "TW", "%d:%s", 0, "US", "767", "US", "767", "US", "767" },
	{ MODEL_ET8PRO, "CN", "%d:%s", 0, "CN", "950", "CN", "950", "CN", "910" },
	{ MODEL_ET8PRO, "XX", "%d:%s", 0, "CN", "947", "CN", "947", "CN", "909" },
#endif

#ifdef RTAX56_XD4
	{ MODEL_RTAX56_XD4, "AA", "%d:%s", 0, "US", "737", "US", "737", NULL, NULL },
	{ MODEL_RTAX56_XD4, "AU", "%d:%s", 0, "AU", "917", "AU", "917", NULL, NULL },
	{ MODEL_RTAX56_XD4, "CA", "%d:%s", 0, "CA", "857", "CA", "857", NULL, NULL },
	{ MODEL_RTAX56_XD4, "CN", "%d:%s", 0, "CN", "927", "CN", "927", NULL, NULL },
	{ MODEL_RTAX56_XD4, "EU", "%d:%s", 0, "E0", "720", "E0", "720", NULL, NULL },
	{ MODEL_RTAX56_XD4, "IL", "%d:%s", 0, "E0", "720", "E0", "720", NULL, NULL },
	{ MODEL_RTAX56_XD4, "JP", "%d:%s", 0, "JP", "878", "JP", "878", NULL, NULL },
	{ MODEL_RTAX56_XD4, "KR", "%d:%s", 0, "KR", "914", "KR", "914", NULL, NULL },
	{ MODEL_RTAX56_XD4, "US", "%d:%s", 0, "US", "737", "US", "737", NULL, NULL },
	{ MODEL_RTAX56_XD4, "UK", "%d:%s", 0, "E0", "720", "E0", "720", NULL, NULL },
	{ MODEL_RTAX56_XD4, "TW", "%d:%s", 0, "US", "737", "US", "737", NULL, NULL },
	{ MODEL_RTAX56_XD4, "XX", "%d:%s", 0, "CN", "924", "CN", "924", NULL, NULL },
#endif
#ifdef XD4PRO
	{ MODEL_XD4PRO, "AA", "%d:%s", 0, "US", "640", "US", "640", NULL, NULL },
	{ MODEL_XD4PRO, "AU", "%d:%s", 0, "US", "640", "US", "640", NULL, NULL },
	{ MODEL_XD4PRO, "CA", "%d:%s", 0, "CA", "819", "CA", "819", NULL, NULL },
	{ MODEL_XD4PRO, "CN", "%d:%s", 0, "CN", "906", "CN", "906", NULL, NULL },
	{ MODEL_XD4PRO, "EU", "%d:%s", 0, "E0", "647", "E0", "647", NULL, NULL },
	{ MODEL_XD4PRO, "IL", "%d:%s", 0, "E0", "720", "E0", "720", NULL, NULL },
	{ MODEL_XD4PRO, "JP", "%d:%s", 0, "JP", "894", "JP", "894", NULL, NULL },
	{ MODEL_XD4PRO, "KR", "%d:%s", 0, "KR", "937", "KR", "937", NULL, NULL },
	{ MODEL_XD4PRO, "US", "%d:%s", 0, "US", "651", "US", "651", NULL, NULL },
	{ MODEL_XD4PRO, "UK", "%d:%s", 0, "E0", "720", "E0", "720", NULL, NULL },
	{ MODEL_XD4PRO, "TW", "%d:%s", 0, "US", "651", "US", "651", NULL, NULL },
	{ MODEL_XD4PRO, "XX", "%d:%s", 0, "CN", "905", "CN", "905", NULL, NULL },
#endif
#ifdef CTAX56_XD4
	{ MODEL_CTAX56_XD4, "AA", "%d:%s", 0, "US", "737", "US", "737", NULL, NULL },
	{ MODEL_CTAX56_XD4, "AU", "%d:%s", 0, "AU", "917", "AU", "917", NULL, NULL },
	{ MODEL_CTAX56_XD4, "CA", "%d:%s", 0, "CA", "857", "CA", "857", NULL, NULL },
	{ MODEL_CTAX56_XD4, "CN", "%d:%s", 0, "CN", "927", "CN", "927", NULL, NULL },
	{ MODEL_CTAX56_XD4, "CT", "%d:%s", 0, "CN", "927", "CN", "927", NULL, NULL },
	{ MODEL_CTAX56_XD4, "EU", "%d:%s", 0, "E0", "720", "E0", "720", NULL, NULL },
	{ MODEL_CTAX56_XD4, "IL", "%d:%s", 0, "E0", "720", "E0", "720", NULL, NULL },
	{ MODEL_CTAX56_XD4, "JP", "%d:%s", 0, "JP", "878", "JP", "878", NULL, NULL },
	{ MODEL_CTAX56_XD4, "KR", "%d:%s", 0, "KR", "937", "KR", "937", NULL, NULL },
	{ MODEL_CTAX56_XD4, "US", "%d:%s", 0, "US", "737", "US", "737", NULL, NULL },
	{ MODEL_CTAX56_XD4, "UK", "%d:%s", 0, "E0", "720", "E0", "720", NULL, NULL },
	{ MODEL_CTAX56_XD4, "TW", "%d:%s", 0, "US", "737", "US", "737", NULL, NULL },
	{ MODEL_CTAX56_XD4, "XX", "%d:%s", 0, "CN", "924", "CN", "924", NULL, NULL },
#endif
#if defined(BCM6750) && !defined(RTAX82_XD6S)
#ifdef RTAX82_XD6
	{ MODEL_RTAX58U, "AA", "%d:%s", 0, "US", "668", "US", "668", NULL, NULL },
#else
	{ MODEL_RTAX58U, "AA", "%d:%s", 0, "US", "756", "US", "756", NULL, NULL },
#endif
	{ MODEL_RTAX58U, "AU", "%d:%s", 0, "AU", "917", "AU", "917", NULL, NULL },
#ifdef RTAX82_XD6
	{ MODEL_RTAX58U, "CA", "%d:%s", 0, "CA", "829", "CA", "829", NULL, NULL },
#else
	{ MODEL_RTAX58U, "CA", "%d:%s", 0, "CA", "869", "CA", "869", NULL, NULL },
#endif
#ifdef RTAX82_XD6
	{ MODEL_RTAX58U, "CH", "%d:%s", 0, "US", "669", "US", "669", NULL, NULL },
	{ MODEL_RTAX58U, "CN", "%d:%s", 0, "CN", "911", "CN", "911", NULL, NULL },
#else
	{ MODEL_RTAX58U, "CN", "%d:%s", 0, "CN", "935", "CN", "935", NULL, NULL },
#endif
#ifdef RTAX58U
	{ MODEL_RTAX58U, "CX", "%d:%s", 0, "US", "669", "US", "669", NULL, NULL },
#endif
#ifdef RTAX82_XD6
	{ MODEL_RTAX58U, "BZ", "%d:%s", 0, "US", "669", "US", "669", NULL, NULL },
#else
	{ MODEL_RTAX58U, "BZ", "%d:%s", 0, "US", "768", "US", "768", NULL, NULL },
#endif
#ifdef RTAX82U
	{ MODEL_RTAX58U, "GD", "%d:%s", 0, "CN", "935", "CN", "935", NULL, NULL },
	{ MODEL_RTAX58U, "TC", "%d:%s", 0, "CN", "935", "CN", "935", NULL, NULL },
#endif
#ifdef RTAX82_XD6
	{ MODEL_RTAX58U, "EU", "%d:%s", 0, "E0", "676", "E0", "676", NULL, NULL },
#else
	{ MODEL_RTAX58U, "EU", "%d:%s", 0, "E0", "742", "E0", "742", NULL, NULL },
#endif
#ifdef RTAX82_XD6
	{ MODEL_RTAX58U, "IL", "%d:%s", 0, "E0", "676", "E0", "676", NULL, NULL },
#else
	{ MODEL_RTAX58U, "IL", "%d:%s", 0, "E0", "742", "E0", "742", NULL, NULL },
#endif
#ifdef RTAX82_XD6
	{ MODEL_RTAX58U, "JP", "%d:%s", 0, "JP", "861", "JP", "861", NULL, NULL },
#else
	{ MODEL_RTAX58U, "JP", "%d:%s", 0, "JP", "889", "JP", "889", NULL, NULL },
#endif
	{ MODEL_RTAX58U, "KR", "%d:%s", 0, "KR", "923", "KR", "923", NULL, NULL },
#ifdef RTAX82_XD6
	{ MODEL_RTAX58U, "S2", "%d:%s", 0, "US", "668", "US", "668", NULL, NULL },
	{ MODEL_RTAX58U, "SG", "%d:%s", 0, "US", "668", "US", "668", NULL, NULL },
#else
	{ MODEL_RTAX58U, "S2", "%d:%s", 0, "US", "756", "US", "756", NULL, NULL },
	{ MODEL_RTAX58U, "SG", "%d:%s", 0, "US", "756", "US", "756", NULL, NULL },
#endif
#ifdef RTAX82_XD6
	{ MODEL_RTAX58U, "TW", "%d:%s", 0, "US", "669", "US", "669", NULL, NULL },
#else
	{ MODEL_RTAX58U, "TW", "%d:%s", 0, "US", "768", "US", "768", NULL, NULL },
#endif
#ifdef RTAX82_XD6
	{ MODEL_RTAX58U, "UK", "%d:%s", 0, "E0", "676", "E0", "676", NULL, NULL },
#else
	{ MODEL_RTAX58U, "UK", "%d:%s", 0, "E0", "742", "E0", "742", NULL, NULL },
#endif
#ifdef RTAX82_XD6
	{ MODEL_RTAX58U, "US", "%d:%s", 0, "US", "669", "US", "669", NULL, NULL },
#else
	{ MODEL_RTAX58U, "US", "%d:%s", 0, "US", "768", "US", "768", NULL, NULL },
#endif
	{ MODEL_RTAX58U, "XX", "%d:%s", 0, "CN", "926", "CN", "926", NULL, NULL },
#endif

#ifdef RTAX82_XD6S
	{ MODEL_RTAX82_XD6S, "AA", "%d:%s", 0, "US", "668", "US", "668", NULL, NULL },
	{ MODEL_RTAX82_XD6S, "AU", "%d:%s", 0, "AU", "917", "AU", "917", NULL, NULL },
	{ MODEL_RTAX82_XD6S, "CA", "%d:%s", 0, "CA", "829", "CA", "829", NULL, NULL },
	{ MODEL_RTAX82_XD6S, "CH", "%d:%s", 0, "US", "669", "US", "669", NULL, NULL },
	{ MODEL_RTAX82_XD6S, "CN", "%d:%s", 0, "CN", "911", "CN", "911", NULL, NULL },
	{ MODEL_RTAX82_XD6S, "BZ", "%d:%s", 0, "US", "669", "US", "669", NULL, NULL },
	{ MODEL_RTAX82_XD6S, "EU", "%d:%s", 0, "E0", "676", "E0", "676", NULL, NULL },
	{ MODEL_RTAX82_XD6S, "IL", "%d:%s", 0, "E0", "676", "E0", "676", NULL, NULL },
	{ MODEL_RTAX82_XD6S, "JP", "%d:%s", 0, "JP", "861", "JP", "861", NULL, NULL },
	{ MODEL_RTAX82_XD6S, "KR", "%d:%s", 0, "KR", "923", "KR", "923", NULL, NULL },
	{ MODEL_RTAX82_XD6S, "S2", "%d:%s", 0, "US", "668", "US", "668", NULL, NULL },
	{ MODEL_RTAX82_XD6S, "SG", "%d:%s", 0, "US", "668", "US", "668", NULL, NULL },
	{ MODEL_RTAX82_XD6S, "TW", "%d:%s", 0, "US", "669", "US", "669", NULL, NULL },
	{ MODEL_RTAX82_XD6S, "UK", "%d:%s", 0, "E0", "676", "E0", "676", NULL, NULL },
	{ MODEL_RTAX82_XD6S, "US", "%d:%s", 0, "US", "669", "US", "669", NULL, NULL },
	{ MODEL_RTAX82_XD6S, "XX", "%d:%s", 0, "CN", "926", "CN", "926", NULL, NULL },
#endif

#ifdef RTAX58U_V2
	{ MODEL_RTAX58U_V2, "AA", "%d:%s", 0, "US", "756", "US", "756", NULL, NULL },
	{ MODEL_RTAX58U_V2, "AU", "%d:%s", 0, "AU", "917", "AU", "917", NULL, NULL },
	{ MODEL_RTAX58U_V2, "CA", "%d:%s", 0, "CA", "869", "CA", "869", NULL, NULL },
	{ MODEL_RTAX58U_V2, "CN", "%d:%s", 0, "CN", "905", "CN", "905", NULL, NULL },
	{ MODEL_RTAX58U_V2, "CX", "%d:%s", 0, "US", "669", "US", "669", NULL, NULL },
	{ MODEL_RTAX58U_V2, "BZ", "%d:%s", 0, "US", "768", "US", "768", NULL, NULL },
	{ MODEL_RTAX58U_V2, "EU", "%d:%s", 0, "E0", "653", "E0", "653", NULL, NULL },
	{ MODEL_RTAX58U_V2, "IL", "%d:%s", 0, "E0", "653", "E0", "653", NULL, NULL },
	{ MODEL_RTAX58U_V2, "JP", "%d:%s", 0, "JP", "859", "JP", "859", NULL, NULL },
	{ MODEL_RTAX58U_V2, "KR", "%d:%s", 0, "KR", "923", "KR", "923", NULL, NULL },
	{ MODEL_RTAX58U_V2, "S2", "%d:%s", 0, "US", "756", "US", "756", NULL, NULL },
	{ MODEL_RTAX58U_V2, "SG", "%d:%s", 0, "US", "756", "US", "756", NULL, NULL },
	{ MODEL_RTAX58U_V2, "TW", "%d:%s", 0, "US", "768", "US", "768", NULL, NULL },
	{ MODEL_RTAX58U_V2, "UK", "%d:%s", 0, "E0", "653", "E0", "653", NULL, NULL },
	{ MODEL_RTAX58U_V2, "US", "%d:%s", 0, "US", "768", "US", "768", NULL, NULL },
	{ MODEL_RTAX58U_V2, "XX", "%d:%s", 0, "CN", "906", "CN", "906", NULL, NULL },
#endif

#ifdef TUFAX3000_V2
	{ MODEL_TUFAX3000_V2, "US", "%d:%s", 0, "US", "768", "US", "768", NULL, NULL },
#endif

#ifdef RTAXE7800
	{ MODEL_RTAXE7800, "US", "%d:%s", 0, "US", "768", "US", "768", NULL, NULL },
#endif

#if defined(DSL_AX82U)
	{ MODEL_DSLAX82U, "EU", "sb/%d/%s", 0, "E0", "683", "E0", "683", NULL, NULL },
	{ MODEL_DSLAX82U, "UK", "sb/%d/%s", 0, "E0", "683", "E0", "683", NULL, NULL },
	{ MODEL_DSLAX82U, "IL", "sb/%d/%s", 0, "E0", "683", "E0", "683", NULL, NULL },
	{ MODEL_DSLAX82U, "AA", "sb/%d/%s", 0, "E0", "683", "AU", "882", NULL, NULL },
	{ MODEL_DSLAX82U, "AU", "sb/%d/%s", 0, "AU", "882", "AU", "882", NULL, NULL },
	{ MODEL_DSLAX82U, "OP", "sb/%d/%s", 0, "AU", "882", "AU", "882", NULL, NULL },
#endif

#if defined(RTAX86U) || defined(RTAX5700)
	{ MODEL_RTAX86U, "AA", "%d:%s", 0, "US", "733", "US", "733", NULL, NULL },
	{ MODEL_RTAX86U, "CA", "%d:%s", 0, "CA", "859", "CA", "859", NULL, NULL },
	{ MODEL_RTAX86U, "CN", "%d:%s", 0, "CN", "929", "CN", "929", NULL, NULL },
	{ MODEL_RTAX86U, "EU", "%d:%s", 0, "E0", "717", "E0", "717", NULL, NULL },
	{ MODEL_RTAX86U, "GD", "%d:%s", 0, "CN", "929", "CN", "929", NULL, NULL },
	{ MODEL_RTAX86U, "IL", "%d:%s", 0, "E0", "717", "E0", "717", NULL, NULL },
	{ MODEL_RTAX86U, "JP", "%d:%s", 0, "JP", "872", "JP", "872", NULL, NULL },
	{ MODEL_RTAX86U, "KR", "%d:%s", 0, "KR", "936", "KR", "936", NULL, NULL },
	{ MODEL_RTAX86U, "S2", "%d:%s", 0, "US", "733", "US", "733", NULL, NULL },
	{ MODEL_RTAX86U, "TW", "%d:%s", 0, "US", "741", "US", "741", NULL, NULL },
	{ MODEL_RTAX86U, "UK", "%d:%s", 0, "E0", "717", "E0", "717", NULL, NULL },
	{ MODEL_RTAX86U, "US", "%d:%s", 0, "US", "741", "US", "741", NULL, NULL },
	{ MODEL_RTAX86U, "XX", "%d:%s", 0, "CN", "947", "CN", "947", NULL, NULL },
#endif
#if defined(RTAX68U)
	{ MODEL_RTAX68U, "CA", "%d:%s", 0, "CA", "850", "CA", "850", NULL, NULL },
	{ MODEL_RTAX68U, "CN", "%d:%s", 0, "CN", "917", "CN", "917", NULL, NULL },
	{ MODEL_RTAX68U, "EU", "%d:%s", 0, "E0", "704", "E0", "704", NULL, NULL },
	{ MODEL_RTAX68U, "TW", "%d:%s", 0, "TW", "967", "TW", "967", NULL, NULL },
	{ MODEL_RTAX68U, "UK", "%d:%s", 0, "E0", "704", "E0", "704", NULL, NULL },
	{ MODEL_RTAX68U, "US", "%d:%s", 0, "US", "726", "US", "726", NULL, NULL },
	{ MODEL_RTAX68U, "XX", "%d:%s", 0, "CN", "918", "CN", "918", NULL, NULL },
#endif
#if defined(RTAC68U_V4)
	{ MODEL_RTAC68U_V4, "CA", "%d:%s", 0, "CA", "850", "CA", "850", NULL, NULL },
	{ MODEL_RTAC68U_V4, "CN", "%d:%s", 0, "CN", "917", "CN", "917", NULL, NULL },
	{ MODEL_RTAC68U_V4, "EU", "%d:%s", 0, "E0", "704", "E0", "704", NULL, NULL },
	{ MODEL_RTAC68U_V4, "TW", "%d:%s", 0, "TW", "967", "TW", "967", NULL, NULL },
	{ MODEL_RTAC68U_V4, "UK", "%d:%s", 0, "E0", "704", "E0", "704", NULL, NULL },
	{ MODEL_RTAC68U_V4, "US", "%d:%s", 0, "US", "726", "US", "726", NULL, NULL },
	{ MODEL_RTAC68U_V4, "XX", "%d:%s", 0, "CN", "918", "CN", "918", NULL, NULL },
#endif

#if defined(RTAX55) || defined(RTAX1800)
	{ MODEL_RTAX55, "AA", "sb/%d/%s", 0, "US", "719", "US", "719", NULL, NULL },
	{ MODEL_RTAX55, "CA", "sb/%d/%s", 0, "CA", "849", "CA", "849", NULL, NULL },
	{ MODEL_RTAX55, "CN", "sb/%d/%s", 0, "CN", "916", "CN", "916", NULL, NULL },
	{ MODEL_RTAX55, "EU", "sb/%d/%s", 0, "E0", "711", "E0", "711", NULL, NULL },
	{ MODEL_RTAX55, "IL", "sb/%d/%s", 0, "E0", "711", "E0", "711", NULL, NULL },
	{ MODEL_RTAX55, "JP", "sb/%d/%s", 0, "JP", "871", "JP", "871", NULL, NULL },
	{ MODEL_RTAX55, "KR", "sb/%d/%s", 0, "KR", "915", "KR", "915", NULL, NULL },
	{ MODEL_RTAX55, "S2", "sb/%d/%s", 0, "US", "719", "US", "719", NULL, NULL },
	{ MODEL_RTAX55, "SG", "sb/%d/%s", 0, "US", "719", "US", "719", NULL, NULL },
	{ MODEL_RTAX55, "TW", "sb/%d/%s", 0, "US", "719", "US", "719", NULL, NULL },
	{ MODEL_RTAX55, "UK", "sb/%d/%s", 0, "E0", "711", "E0", "711", NULL, NULL },
	{ MODEL_RTAX55, "US", "sb/%d/%s", 0, "US", "719", "US", "719", NULL, NULL },
	{ MODEL_RTAX55, "XX", "sb/%d/%s", 0, "CN", "915", "CN", "915", NULL, NULL },
#endif

#ifdef RTAX56U
        { MODEL_RTAX56U, "AA", "sb/%d/%s", 0, "US", "770", "US", "770", NULL, NULL },
        { MODEL_RTAX56U, "AU", "sb/%d/%s", 0, "AU", "917", "AU", "917", NULL, NULL },
        { MODEL_RTAX56U, "CA", "sb/%d/%s", 0, "CA", "867", "CA", "867", NULL, NULL },
        { MODEL_RTAX56U, "CN", "sb/%d/%s", 0, "CN", "934", "CN", "934", NULL, NULL },
        { MODEL_RTAX56U, "CX", "sb/%d/%s", 0, "US", "770", "US", "770", NULL, NULL },
        { MODEL_RTAX56U, "EU", "sb/%d/%s", 0, "E0", "741", "E0", "741", NULL, NULL },
        { MODEL_RTAX56U, "IL", "sb/%d/%s", 0, "E0", "741", "E0", "741", NULL, NULL },
        { MODEL_RTAX56U, "JP", "sb/%d/%s", 0, "JP", "886", "JP", "886", NULL, NULL },
        { MODEL_RTAX56U, "KR", "sb/%d/%s", 0, "KR", "924", "KR", "924", NULL, NULL },
        { MODEL_RTAX56U, "US", "sb/%d/%s", 0, "US", "770", "US", "770", NULL, NULL },
        { MODEL_RTAX56U, "UK", "sb/%d/%s", 0, "E0", "741", "E0", "741", NULL, NULL },
        { MODEL_RTAX56U, "TW", "sb/%d/%s", 0, "TW", "968", "TW", "968", NULL, NULL },
        { MODEL_RTAX56U, "XX", "sb/%d/%s", 0, "CN", "931", "CN", "931", NULL, NULL },
#endif

#if defined(RPAX56)
	{ MODEL_RPAX56, "CA", "sb/%d/%s", 0, "CA", "842", "CA", "842", NULL, NULL },
	{ MODEL_RPAX56, "CN", "sb/%d/%s", 0, "CN", "920", "CN", "920", NULL, NULL },
	{ MODEL_RPAX56, "EU", "sb/%d/%s", 0, "E0", "712", "E0", "712", NULL, NULL },
	{ MODEL_RPAX56, "UK", "sb/%d/%s", 0, "E0", "712", "E0", "712", NULL, NULL },
	{ MODEL_RPAX56, "US", "sb/%d/%s", 0, "US", "722", "US", "722", NULL, NULL },
	{ MODEL_RPAX56, "AU", "sb/%d/%s", 0, "AU", "867", "AU", "867", NULL, NULL },
	{ MODEL_RPAX56, "XX", "sb/%d/%s", 0, "CN", "921", "CN", "921", NULL, NULL },
#endif

#if defined(RPAX58)
        { MODEL_RPAX58, "CA", "sb/%d/%s", 0, "CA", "869", "CA", "869", NULL, NULL },
        { MODEL_RPAX58, "CN", "sb/%d/%s", 0, "CN", "935", "CN", "935", NULL, NULL },
        { MODEL_RPAX58, "EU", "sb/%d/%s", 0, "E0", "742", "E0", "742", NULL, NULL },
        { MODEL_RPAX58, "UK", "sb/%d/%s", 0, "E0", "742", "E0", "742", NULL, NULL },
        { MODEL_RPAX58, "US", "sb/%d/%s", 0, "US", "768", "US", "768", NULL, NULL },
        { MODEL_RPAX58, "XX", "sb/%d/%s", 0, "CN", "926", "CN", "926", NULL, NULL },
#endif

#ifdef RTN12D1
	{ MODEL_RTN12D1, "AP", "sb/%d/%s", 1, "US", "10", NULL, NULL, NULL, NULL },
	{ MODEL_RTN12D1, "AQ", "sb/%d/%s", 1, "US", "10", NULL, NULL, NULL, NULL },
	{ MODEL_RTN12D1, "AU", "sb/%d/%s", 1, "US", "10", NULL, NULL, NULL, NULL },
	{ MODEL_RTN12D1, "BZ", "sb/%d/%s", 1, "XU", "0", NULL, NULL, NULL, NULL },
	{ MODEL_RTN12D1, "CA", "sb/%d/%s", 1, "US", "10", NULL, NULL, NULL, NULL },
	{ MODEL_RTN12D1, "CN", "sb/%d/%s", 1, "XU", "0", NULL, NULL, NULL, NULL },
	{ MODEL_RTN12D1, "EU", "sb/%d/%s", 1, "XU", "0", NULL, NULL, NULL, NULL },
	{ MODEL_RTN12D1, "JP", "sb/%d/%s", 1, "XU", "0", NULL, NULL, NULL, NULL },
	{ MODEL_RTN12D1, "KR", "sb/%d/%s", 1, "XU", "0", NULL, NULL, NULL, NULL },
	{ MODEL_RTN12D1, "ME", "sb/%d/%s", 1, "XU", "0", NULL, NULL, NULL, NULL },
	{ MODEL_RTN12D1, "MY", "sb/%d/%s", 1, "US", "10", NULL, NULL, NULL, NULL },
	{ MODEL_RTN12D1, "RU", "sb/%d/%s", 1, "XU", "0", NULL, NULL, NULL, NULL },
	{ MODEL_RTN12D1, "SG", "sb/%d/%s", 1, "US", "10", NULL, NULL, NULL, NULL },
	{ MODEL_RTN12D1, "TR", "sb/%d/%s", 1, "XU", "0", NULL, NULL, NULL, NULL },
	{ MODEL_RTN12D1, "TW", "sb/%d/%s", 1, "US", "10", NULL, NULL, NULL, NULL },
	{ MODEL_RTN12D1, "UA", "sb/%d/%s", 1, "XU", "0", NULL, NULL, NULL, NULL },
	{ MODEL_RTN12D1, "UK", "sb/%d/%s", 1, "XU", "0", NULL, NULL, NULL, NULL },
	{ MODEL_RTN12D1, "US", "sb/%d/%s", 1, "US", "10", NULL, NULL, NULL, NULL },
	{ MODEL_RTN12D1, "XX", "sb/%d/%s", 1, "AU", "2", NULL, NULL, NULL, NULL },
#endif
#ifdef RTN12HP_B1
	{ MODEL_RTN12HP_B1, "AP", "sb/%d/%s", 1, "US", "16", NULL, NULL, NULL, NULL },
	{ MODEL_RTN12HP_B1, "AQ", "sb/%d/%s", 1, "US", "16", NULL, NULL, NULL, NULL },
	{ MODEL_RTN12HP_B1, "AU", "sb/%d/%s", 1, "US", "16", NULL, NULL, NULL, NULL },
	{ MODEL_RTN12HP_B1, "BZ", "sb/%d/%s", 1, "US", "16", NULL, NULL, NULL, NULL },
	{ MODEL_RTN12HP_B1, "CA", "sb/%d/%s", 1, "US", "16", NULL, NULL, NULL, NULL },
	{ MODEL_RTN12HP_B1, "CN", "sb/%d/%s", 1, "EU", "5", NULL, NULL, NULL, NULL },
	{ MODEL_RTN12HP_B1, "EU", "sb/%d/%s", 1, "EU", "5", NULL, NULL, NULL, NULL },
	{ MODEL_RTN12HP_B1, "JP", "sb/%d/%s", 1, "EU", "5", NULL, NULL, NULL, NULL },
	{ MODEL_RTN12HP_B1, "KR", "sb/%d/%s", 1, "EU", "5", NULL, NULL, NULL, NULL },
	{ MODEL_RTN12HP_B1, "ME", "sb/%d/%s", 1, "EU", "5", NULL, NULL, NULL, NULL },
	{ MODEL_RTN12HP_B1, "MY", "sb/%d/%s", 1, "US", "16", NULL, NULL, NULL, NULL },
	{ MODEL_RTN12HP_B1, "RU", "sb/%d/%s", 1, "RU", "4", NULL, NULL, NULL, NULL },
	{ MODEL_RTN12HP_B1, "SG", "sb/%d/%s", 1, "SG", "7", NULL, NULL, NULL, NULL },
	{ MODEL_RTN12HP_B1, "TR", "sb/%d/%s", 1, "EU", "5", NULL, NULL, NULL, NULL },
	{ MODEL_RTN12HP_B1, "TW", "sb/%d/%s", 1, "US", "16", NULL, NULL, NULL, NULL },
	{ MODEL_RTN12HP_B1, "UA", "sb/%d/%s", 1, "EU", "5", NULL, NULL, NULL, NULL },
	{ MODEL_RTN12HP_B1, "US", "sb/%d/%s", 1, "US", "16", NULL, NULL, NULL, NULL },
	{ MODEL_RTN12HP_B1, "XX", "sb/%d/%s", 1, "AU", "2", NULL, NULL, NULL, NULL },
#endif
#ifdef RTN18U
	{ MODEL_RTN18U, "AA", "%d:%s", 0, "US", "0", NULL, NULL, NULL, NULL },
	{ MODEL_RTN18U, "AP", "%d:%s", 0, "US", "0", NULL, NULL, NULL, NULL },
	{ MODEL_RTN18U, "CN", "%d:%s", 0, "CN", "1", NULL, NULL, NULL, NULL },
	{ MODEL_RTN18U, "EU", "%d:%s", 0, "EU", "13", NULL, NULL, NULL, NULL },
	{ MODEL_RTN18U, "KR", "%d:%s", 0, "EU", "13", NULL, NULL, NULL, NULL },
	{ MODEL_RTN18U, "RU", "%d:%s", 0, "EU", "13", NULL, NULL, NULL, NULL },
	{ MODEL_RTN18U, "SG", "%d:%s", 0, "EU", "13", NULL, NULL, NULL, NULL },
	{ MODEL_RTN18U, "TW", "%d:%s", 0, "US", "0", NULL, NULL, NULL, NULL },
	{ MODEL_RTN18U, "XX", "%d:%s", 0, "Q2", "12", NULL, NULL, NULL, NULL },
#endif
#ifdef RTN66U
	{ MODEL_RTN66U, "AA", "pci/%d/1/%s", 1, "Q2", "32","Q2", "32", NULL, NULL },
	{ MODEL_RTN66U, "CA", "pci/%d/1/%s", 1, "US", "39","Q2", "2", NULL, NULL },
	{ MODEL_RTN66U, "CN", "pci/%d/1/%s", 1, "EU", "3", "CN", "0", NULL, NULL },
	{ MODEL_RTN66U, "EE", "pci/%d/1/%s", 1, "EU", "3", "EU", "0", NULL, NULL },
	{ MODEL_RTN66U, "EU", "pci/%d/1/%s", 1, "EU", "3", "EU", "0", NULL, NULL },
	{ MODEL_RTN66U, "RU", "pci/%d/1/%s", 1, "EU", "3", "EU", "0", NULL, NULL },
	{ MODEL_RTN66U, "JP", "pci/%d/1/%s", 1, "JP", "42","JP", "42", NULL, NULL },
	{ MODEL_RTN66U, "SG", "pci/%d/1/%s", 1, "US", "39","Q2", "2", NULL, NULL },
	{ MODEL_RTN66U, "TW", "pci/%d/1/%s", 1, "US", "39","TW", "0", NULL, NULL },
	{ MODEL_RTN66U, "UK", "pci/%d/1/%s", 1, "EU", "3", "EU", "0", NULL, NULL },
	{ MODEL_RTN66U, "US", "pci/%d/1/%s", 1, "Q2", "32","Q2", "32", NULL, NULL },
	{ MODEL_RTN66U, "WE", "pci/%d/1/%s", 1, "EU", "3", "EU", "0", NULL, NULL },
	{ MODEL_RTN66U, "XX", "pci/%d/1/%s", 1, "US", "2", "Q2", "0", NULL, NULL },
#endif
#ifdef RTAC1200G
	{ MODEL_RTAC1200G, "CA", "%d:%s", 0, "CA", "973", "CA", "973", NULL, NULL },
	{ MODEL_RTAC1200G, "US", "%d:%s", 0, "US", "807", "US", "807", NULL, NULL },
#endif
#ifdef RTAC1200GP
	{ MODEL_RTAC1200GP, "AA", "%d:%s", 0, "US", "807", "US", "807", NULL, NULL },
	{ MODEL_RTAC1200GP, "AP", "%d:%s", 0, "US", "807", "US", "807", NULL, NULL },
	{ MODEL_RTAC1200GP, "AU", "%d:%s", 0, "AU", "979", "AU", "979", NULL, NULL },
	{ MODEL_RTAC1200GP, "CN", "%d:%s", 0, "US", "807", "US", "807", NULL, NULL },
	{ MODEL_RTAC1200GP, "EU", "%d:%s", 0, "E0", "943", "E0", "943", NULL, NULL },
	{ MODEL_RTAC1200GP, "HK", "%d:%s", 0, "US", "807", "US", "807", NULL, NULL },
	{ MODEL_RTAC1200GP, "KR", "%d:%s", 0, "E0", "943", "E0", "943", NULL, NULL },
	{ MODEL_RTAC1200GP, "RU", "%d:%s", 0, "E0", "943", "E0", "943", NULL, NULL },
	{ MODEL_RTAC1200GP, "SG", "%d:%s", 0, "US", "807", "US", "807", NULL, NULL },
	{ MODEL_RTAC1200GP, "TW", "%d:%s", 0, "TW", "987", "TW", "987", NULL, NULL },
	{ MODEL_RTAC1200GP, "UK", "%d:%s", 0, "E0", "943", "E0", "943", NULL, NULL },
	{ MODEL_RTAC1200GP, "US", "%d:%s", 0, "US", "807", "US", "807", NULL, NULL },
#endif
#elif	defined(RTCONFIG_RALINK)
#ifdef RTN11P
	{ MODEL_RTN11P, "AP", NULL, 0, "US", "NCC", "US", NULL, NULL, NULL },
	{ MODEL_RTN11P, "AU", NULL, 0, "US", "FCC" , "US", NULL, NULL, NULL },
	{ MODEL_RTN11P, "BZ", NULL, 0, "US", "FCC" , "US", NULL, NULL, NULL },
	{ MODEL_RTN11P, "CA", NULL, 0, "US", "FCC" , "CA", NULL, NULL, NULL },
	{ MODEL_RTN11P, "CN", NULL, 0, "CN", "CN" , "CN", NULL, NULL, NULL },
	{ MODEL_RTN11P, "EU", NULL, 0, "GB", "CE" , "GB", NULL, NULL, NULL },
	{ MODEL_RTN11P, "JP", NULL, 0, "JP", "CE" , "JP", NULL, NULL, NULL },
	{ MODEL_RTN11P, "KR", NULL, 0, "KR", "CE" , "KR", NULL, NULL, NULL },
	{ MODEL_RTN11P, "ME", NULL, 0, "GB", "CE" , "GB", NULL, NULL, NULL },
	{ MODEL_RTN11P, "MY", NULL, 0, "US", "FCC" , "US", NULL, NULL, NULL },
	{ MODEL_RTN11P, "RU", NULL, 0, "GB", "CE" , "GB", NULL, NULL, NULL },
	{ MODEL_RTN11P, "SG", NULL, 0, "SG", "CE" , "SG", NULL, NULL, NULL },
	{ MODEL_RTN11P, "TR", NULL, 0, "GB", "CE" , "GB", NULL, NULL, NULL },
	{ MODEL_RTN11P, "TW", NULL, 0, "TW", "NCC", "TW", NULL, NULL, NULL },
	{ MODEL_RTN11P, "UA", NULL, 0, "GB", "CE" , "GB", NULL, NULL, NULL },
	{ MODEL_RTN11P, "US", NULL, 0, "US", "FCC", "US", NULL, NULL, NULL },
	{ MODEL_RTN11P, "IN", NULL, 0, "US", "NCC" , "US", NULL, NULL, NULL },
	{ MODEL_RTN11P, "XX", NULL, 0, "AU", "AU" , "AU", NULL, NULL, NULL },
#endif	/* RTN11P */
#ifdef RTN11P_B1
	{ MODEL_RTN11P_B1, "AP", NULL, 0, "US", "FCC", "US", NULL, NULL, NULL },
	{ MODEL_RTN11P_B1, "AQ", NULL, 0, "US", "FCC", "US", NULL, NULL, NULL },
	{ MODEL_RTN11P_B1, "AU", NULL, 0, "US", "FCC" , "US", NULL, NULL, NULL },
	{ MODEL_RTN11P_B1, "BZ", NULL, 0, "US", "FCC" , "US", NULL, NULL, NULL },
	{ MODEL_RTN11P_B1, "CA", NULL, 0, "US", "FCC" , "CA", NULL, NULL, NULL },
	{ MODEL_RTN11P_B1, "CN", NULL, 0, "CN", "CN" , "CN", NULL, NULL, NULL },
	{ MODEL_RTN11P_B1, "EU", NULL, 0, "GB", "CE" , "GB", NULL, NULL, NULL },
	{ MODEL_RTN11P_B1, "JP", NULL, 0, "JP", "CE" , "JP", NULL, NULL, NULL },
	{ MODEL_RTN11P_B1, "KR", NULL, 0, "US", "FCC" , "US", NULL, NULL, NULL },
	{ MODEL_RTN11P_B1, "ME", NULL, 0, "GB", "CE" , "GB", NULL, NULL, NULL },
	{ MODEL_RTN11P_B1, "MY", NULL, 0, "US", "FCC" , "US", NULL, NULL, NULL },
	{ MODEL_RTN11P_B1, "RU", NULL, 0, "GB", "CE" , "GB", NULL, NULL, NULL },
	{ MODEL_RTN11P_B1, "SG", NULL, 0, "US", "FCC" , "US", NULL, NULL, NULL },
	{ MODEL_RTN11P_B1, "TR", NULL, 0, "GB", "CE" , "GB", NULL, NULL, NULL },
	{ MODEL_RTN11P_B1, "TW", NULL, 0, "TW", "NCC", "TW", NULL, NULL, NULL },
	{ MODEL_RTN11P_B1, "UA", NULL, 0, "GB", "CE" , "GB", NULL, NULL, NULL },
	{ MODEL_RTN11P_B1, "US", NULL, 0, "US", "FCC", "US", NULL, NULL, NULL },
	{ MODEL_RTN11P_B1, "IN", NULL, 0, "US", "FCC" , "US", NULL, NULL, NULL },
	{ MODEL_RTN11P_B1, "XX", NULL, 0, "AU", "AU" , "AU", NULL, NULL, NULL },
#endif	/* RTN11PB1 */
#ifdef RTAC51U
	{ MODEL_RTAC51U, "AP", NULL, 0, "US", "CE" , "US", NULL, NULL, NULL },
	{ MODEL_RTAC51U, "CN", NULL, 0, "CN", "CN" , "CN", NULL, NULL, NULL },
	{ MODEL_RTAC51U, "EU", NULL, 0, "GB", "CE" , "GB", NULL, NULL, NULL },
	{ MODEL_RTAC51U, "KR", NULL, 0, "KR", "CE" , "KR", NULL, NULL, NULL },
	{ MODEL_RTAC51U, "RU", NULL, 0, "GB", "CE" , "GB", NULL, NULL, NULL },
	{ MODEL_RTAC51U, "SG", NULL, 0, "SG", "CE" , "SG", NULL, NULL, NULL },
	{ MODEL_RTAC51U, "US", NULL, 0, "US", "NCC", "US", NULL, NULL, NULL },
	{ MODEL_RTAC51U, "XX", NULL, 0, "AU", "AU" , "AU", NULL, NULL, NULL },
#endif	/* RTAC51U */
#ifdef RTAC51UP
	{ MODEL_RTAC51UP, "AP", NULL, 0, "US", "CE" , "US", NULL, NULL, NULL },
	{ MODEL_RTAC51UP, "CN", NULL, 0, "CN", "CN" , "CN", NULL, NULL, NULL },
	{ MODEL_RTAC51UP, "EU", NULL, 0, "GB", "CE" , "GB", NULL, NULL, NULL },
	{ MODEL_RTAC51UP, "KR", NULL, 0, "KR", "CE" , "KR", NULL, NULL, NULL },
	{ MODEL_RTAC51UP, "RU", NULL, 0, "GB", "CE" , "GB", NULL, NULL, NULL },
	{ MODEL_RTAC51UP, "SG", NULL, 0, "SG", "CE" , "SG", NULL, NULL, NULL },
	{ MODEL_RTAC51UP, "US", NULL, 0, "US", "NCC", "US", NULL, NULL, NULL },
	{ MODEL_RTAC51UP, "XX", NULL, 0, "AU", "AU" , "AU", NULL, NULL, NULL },
#endif	/* RTAC51UP */
#ifdef RTAC53
	{ MODEL_RTAC53, "AP", NULL, 0, "US", "CE" , "US", NULL, NULL, NULL },
	{ MODEL_RTAC53, "CN", NULL, 0, "CN", "CN" , "CN", NULL, NULL, NULL },
	{ MODEL_RTAC53, "EU", NULL, 0, "GB", "CE" , "GB", NULL, NULL, NULL },
	{ MODEL_RTAC53, "KR", NULL, 0, "KR", "CE" , "KR", NULL, NULL, NULL },
	{ MODEL_RTAC53, "RU", NULL, 0, "GB", "CE" , "GB", NULL, NULL, NULL },
	{ MODEL_RTAC53, "SG", NULL, 0, "SG", "CE" , "SG", NULL, NULL, NULL },
	{ MODEL_RTAC53, "US", NULL, 0, "US", "NCC", "US", NULL, NULL, NULL },
	{ MODEL_RTAC53, "XX", NULL, 0, "AU", "AU" , "AU", NULL, NULL, NULL },
#endif
#ifdef RTAC1200GU
	{ MODEL_RTAC1200GU, "AP", NULL, 0, "US", "CE" , "US", NULL, NULL, NULL },
	{ MODEL_RTAC1200GU, "CN", NULL, 0, "CN", "CN" , "CN", NULL, NULL, NULL },
	{ MODEL_RTAC1200GU, "EU", NULL, 0, "GB", "CE" , "GB", NULL, NULL, NULL },
	{ MODEL_RTAC1200GU, "KR", NULL, 0, "KR", "CE" , "KR", NULL, NULL, NULL },
	{ MODEL_RTAC1200GU, "RU", NULL, 0, "GB", "CE" , "GB", NULL, NULL, NULL },
	{ MODEL_RTAC1200GU, "SG", NULL, 0, "SG", "CE" , "SG", NULL, NULL, NULL },
	{ MODEL_RTAC1200GU, "US", NULL, 0, "US", "FCC", "US", NULL, NULL, NULL },
	{ MODEL_RTAC1200GU, "XX", NULL, 0, "AU", "AU", "AU", NULL, NULL, NULL },
#endif
#ifdef RTN800HP
	{ MODEL_RTN800HP, "AA", NULL, 0, "US", "FCC" , "US", NULL, NULL, NULL },
	{ MODEL_RTN800HP, "AP", NULL, 0, "US", "FCC" , "US", NULL, NULL, NULL },
	{ MODEL_RTN800HP, "AQ", NULL, 0, "US", "FCC" , "US", NULL, NULL, NULL },
	{ MODEL_RTN800HP, "IN", NULL, 0, "US", "FCC" , "US", NULL, NULL, NULL },
	{ MODEL_RTN800HP, "HK", NULL, 0, "US", "FCC" , "US", NULL, NULL, NULL },
	{ MODEL_RTN800HP, "SG", NULL, 0, "US", "FCC" , "US", NULL, NULL, NULL },
	{ MODEL_RTN800HP, "AU", NULL, 0, "AU", "AU", "AU", NULL, NULL, NULL },
	{ MODEL_RTN800HP, "XX", NULL, 0, "AU", "AU", "AU", NULL, NULL, NULL },
#endif
#ifdef RTAC85U
	{ MODEL_RTAC85U, "JP", NULL, 0, "JP", "CE" , "JP", NULL, NULL, NULL },
	{ MODEL_RTAC85U, "AA", NULL, 0, "AA", "FCC" , "AA", NULL, NULL, NULL },
	{ MODEL_RTAC85U, "SG", NULL, 0, "SG", "FCC" , "SG", NULL, NULL, NULL },
#endif
#ifdef RTAC85P
	{ MODEL_RTAC85P, "CN", NULL, 0, "CN", "CN" , "CN", NULL, NULL, NULL },
	{ MODEL_RTAC85P, "AA", NULL, 0, "AA", "FCC" , "AA", NULL, NULL, NULL },
	{ MODEL_RTAC85P, "SG", NULL, 0, "SG", "FCC" , "SG", NULL, NULL, NULL },
	{ MODEL_RTAC85P, "XX", NULL, 0, "CN", "AU", "CN", NULL, NULL, NULL },
#endif
#ifdef RTACRH26
	{ MODEL_RTACRH26, "CN", NULL, 0, "CN", "CN" , "CN", NULL, NULL, NULL },
	{ MODEL_RTACRH26, "AA", NULL, 0, "AA", "FCC" , "AA", NULL, NULL, NULL },
	{ MODEL_RTACRH26, "SG", NULL, 0, "SG", "FCC" , "SG", NULL, NULL, NULL },
	{ MODEL_RTACRH26, "XX", NULL, 0, "AU", "AU", "AU", NULL, NULL, NULL },
#endif
#ifdef RTAC1200V2
	{ MODEL_RTAC1200V2, "AA", NULL, 0, "AA", "FCC", "AA", NULL, NULL, NULL },
	{ MODEL_RTAC1200V2, "CN", NULL, 0, "CN", "CN" , "CN", NULL, NULL, NULL },
	{ MODEL_RTAC1200V2, "IN", NULL, 0, "IN", "FCC", "IN", NULL, NULL, NULL },
	{ MODEL_RTAC1200V2, "KR", NULL, 0, "KR", "KCC", "KR", NULL, NULL, NULL},
	{ MODEL_RTAC1200V2, "XX", NULL, 0, "CN", "AU" , "CN", NULL, NULL, NULL },
#endif /* RTAC1200V2 */
#ifdef RTACRH18
	{ MODEL_RTACRH18, "CA", NULL, 0, "CA", "IC", "CA", NULL, NULL, NULL },
	{ MODEL_RTACRH18, "EU", NULL, 0, "GB", "CE" , "GB", NULL, NULL, NULL },
	{ MODEL_RTACRH18, "UK", NULL, 0, "GB", "CE" , "GB", NULL, NULL, NULL },
	{ MODEL_RTACRH18, "US", NULL, 0, "US", "FCC", "US", NULL, NULL, NULL },
	{ MODEL_RTACRH18, "XX", NULL, 0, "AU", "AU" , "AU", NULL, NULL, NULL },
#endif /* RTACRH18 */
#ifdef RT4GAX56
	{ MODEL_RT4GAX56, "EU", NULL, 0, "GB", "CE" , "GB", NULL, NULL, NULL },
	{ MODEL_RT4GAX56, "AA", NULL, 0, "AA", "CE" , "AA", NULL, NULL, NULL },
	{ MODEL_RT4GAX56, "TW", NULL, 0, "TW", "NCC", "TW", NULL, NULL, NULL },
#endif /* RT4GAX56 */
#ifdef RTAX53U
	{ MODEL_RTAX53U, "AA", NULL, 0, "AA", "FCC" , "AA", NULL, NULL, NULL },
	{ MODEL_RTAX53U, "KR", NULL, 0, "KR", "KCC" , "KR", NULL, NULL, NULL },
#endif /* RTAX53U */
#ifdef RTAX54
	{ MODEL_RTAX54, "AA", NULL, 0, "AA", "FCC" , "AA", NULL, NULL, NULL },
	{ MODEL_RTAX54, "AU", NULL, 0, "AU", "AU" , "AU", NULL, NULL, NULL },
	{ MODEL_RTAX54, "XX", NULL, 0, "AA", "CN" , "AA", NULL, NULL, NULL },
#endif /* RTAX54 */
#ifdef XD4S
	{ MODEL_XD4S, "AA", NULL, 0, "AA", "FCC" , "AA", NULL, NULL, NULL },
	{ MODEL_XD4S, "XX", NULL, 0, "AA", "AU" , "AA", NULL, NULL, NULL },
#endif /* XD4S */
#ifdef TUFAX4200
	{ MODEL_TUFAX4200, "AA", NULL, 0, "AA", "FCC" , "AA", NULL, NULL, NULL },
	{ MODEL_TUFAX4200, "XX", NULL, 0, "AA", "AU" , "AA", NULL, NULL, NULL },
#endif /* TUFAX4200 */
#ifdef TUFAX6000
	{ MODEL_TUFAX6000, "AA", NULL, 0, NULL, "FCC", NULL, NULL, NULL, NULL },
	{ MODEL_TUFAX6000, "CN", NULL, 0, NULL, "CN" , NULL, NULL, NULL, NULL },
	{ MODEL_TUFAX6000, "XX", NULL, 0, NULL, "AU" , NULL, NULL, NULL, NULL },
#endif /* TUFAX6000 */
#elif	defined(RTCONFIG_QCA)
#ifdef BRTAC828
	{ MODEL_BRTAC828, "AA", NULL, 0, "US", "US" , "US", NULL, NULL, NULL},
	{ MODEL_BRTAC828, "AP", NULL, 0, "US", "US" , "US", NULL, NULL, NULL},
	{ MODEL_BRTAC828, "EU", NULL, 0, "GB", "GB" , "GB", NULL, NULL, NULL},
	{ MODEL_BRTAC828, "RU", NULL, 0, "GB", "GB" , "GB", NULL, NULL, NULL},
	{ MODEL_BRTAC828, "KR", NULL, 0, "KR", "KR" , "KR", NULL, NULL, NULL},
	{ MODEL_BRTAC828, "SG", NULL, 0, "US", "US" , "US", NULL, NULL, NULL},	/* FCC cert. not IMDA cert. ch12-13 can't be enabled. */
#endif
#ifdef RTAD7200
	{ MODEL_RTAD7200, "AA", NULL, 0, "US", "US" , "US", NULL, NULL, NULL},
	{ MODEL_RTAD7200, "AP", NULL, 0, "US", "US" , "US", NULL, NULL, NULL},
	{ MODEL_RTAD7200, "EU", NULL, 0, "GB", "GB" , "GB", NULL, NULL, NULL},
	{ MODEL_RTAD7200, "RU", NULL, 0, "GB", "GB" , "GB", NULL, NULL, NULL},
	{ MODEL_RTAD7200, "KR", NULL, 0, "KR", "KR" , "KR", NULL, NULL, NULL},
#endif
#ifdef GTAXY16000
	{ MODEL_GTAXY16000, "AA", NULL, 0, "US", "US" , "US", NULL, NULL, NULL},
	{ MODEL_GTAXY16000, "AP", NULL, 0, "US", "US" , "US", NULL, NULL, NULL},
	{ MODEL_GTAXY16000, "EU", NULL, 0, "GB", "GB" , "GB", NULL, NULL, NULL},
	{ MODEL_GTAXY16000, "RU", NULL, 0, "GB", "GB" , "GB", NULL, NULL, NULL},
	{ MODEL_GTAXY16000, "KR", NULL, 0, "KR", "KR" , "KR", NULL, NULL, NULL},
#endif
#ifdef RTAX89U
	{ MODEL_RTAX89U, "AA", NULL, 0, "US", "US" , "US", NULL, NULL, NULL },
	{ MODEL_RTAX89U, "S2", NULL, 0, "US", "US" , "US", NULL, NULL, NULL },
	{ MODEL_RTAX89U, "SG", NULL, 0, "US", "US" , "US", NULL, NULL, NULL },
	{ MODEL_RTAX89U, "XX", NULL, 0, "AU", "AU" , "AU", NULL, NULL, NULL },
	{ MODEL_RTAX89U, "US", NULL, 0, "US", "US" , "US", NULL, NULL, NULL },
	{ MODEL_RTAX89U, "EU", NULL, 0, "GB", "GB" , "GB", NULL, NULL, NULL },
	{ MODEL_RTAX89U, "CN", NULL, 0, "CN", "CN" , "CN", NULL, NULL, NULL },
//	{ MODEL_RTAX89U, "JP", NULL, 0, "JP", "JP" , "JP", NULL, NULL, NULL },
#endif
#ifdef RTAC55U
	{ MODEL_RTAC55U, "AP", NULL, 0, "US", "US" , "US", NULL, NULL, NULL },
	{ MODEL_RTAC55U, "CN", NULL, 0, "CN", "CN" , "CN", NULL, NULL, NULL },
	{ MODEL_RTAC55U, "EU", NULL, 0, "HU", "HU" , "HU", NULL, NULL, NULL },
	{ MODEL_RTAC55U, "KR", NULL, 0, "HU", "HU" , "HU", NULL, NULL, NULL },
	{ MODEL_RTAC55U, "RU", NULL, 0, "HU", "HU" , "HU", NULL, NULL, NULL },
	{ MODEL_RTAC55U, "SG", NULL, 0, "SG", "HU" , "SG", NULL, NULL, NULL },
	{ MODEL_RTAC55U, "US", NULL, 0, "US", "US" , "US", NULL, NULL, NULL },
	{ MODEL_RTAC55U, "XX", NULL, 0, "AU", "AU" , "AU", NULL, NULL, NULL },
#endif	/* RTAC55U */
#ifdef RTAC55UHP
	{ MODEL_RTAC55UHP, "AA", NULL, 0, "US", "US" , "US", NULL, NULL, NULL},
	{ MODEL_RTAC55UHP, "IN", NULL, 0, "US", "US" , "US", NULL, NULL, NULL},
#endif	/* RTAC55UHP */
#if defined(RTAC59U)
	{ MODEL_RTAC59U, "AA", NULL, 0, "US", "US" , "US", NULL, NULL, NULL },
	{ MODEL_RTAC59U, "KR", NULL, 0, "KR", "KR" , "KR", NULL, NULL, NULL },
	{ MODEL_RTAC59U, "CN", NULL, 0, "CN", "CN" , "CN", NULL, NULL, NULL },
	{ MODEL_RTAC59U, "CX", NULL, 0, "AU", "AU" , "AU", NULL, NULL, NULL },
#endif
#if defined(RTAC95U)
	{ MODEL_RTAC95U, "AA", NULL, 0, "US", "US" , "US", NULL, NULL, NULL },
	{ MODEL_RTAC95U, "XX", NULL, 0, "AU", "AU" , "AU", NULL, NULL, NULL },
	{ MODEL_RTAC95U, "SG", NULL, 0, "US", "US" , "US", NULL, NULL, NULL },
#endif
#ifdef RTAC58U
	{ MODEL_RTAC58U, "AA", NULL, 0, "US", "US" , "US", NULL, NULL, NULL },
	{ MODEL_RTAC58U, "EU", NULL, 0, "GB", "GB" , "GB", NULL, NULL, NULL },
	{ MODEL_RTAC58U, "KR", NULL, 0, "KR", "KR" , "KR", NULL, NULL, NULL },
	{ MODEL_RTAC58U, "SG", NULL, 0, "US", "US" , "US", NULL, NULL, NULL },
	{ MODEL_RTAC58U, "US", NULL, 0, "US", "US" , "US", NULL, NULL, NULL },
	{ MODEL_RTAC58U, "CX", NULL, 0, "AU", "AU" , "AU", NULL, NULL, NULL },
	{ MODEL_RTAC58U, "SP", NULL, 0, "AU", "AU" , "AU", NULL, NULL, NULL },
	{ MODEL_RTAC58U, "HK", NULL, 0, "US", "US" , "US", NULL, NULL, NULL },
#endif	/* RTAC58U */
#ifdef RT4GAC53U
	{ MODEL_RT4GAC53U, "AA", NULL, 0, "GB", "GB" , "GB", NULL, NULL, NULL },
	{ MODEL_RT4GAC53U, "SG", NULL, 0, "GB", "GB" , "GB", NULL, NULL, NULL },
	{ MODEL_RT4GAC53U, "EU", NULL, 0, "GB", "GB" , "GB", NULL, NULL, NULL },
	{ MODEL_RT4GAC53U, "AU", NULL, 0, "AU", "AU" , "AU", NULL, NULL, NULL },
#endif	/* RT4GAC53U */
#ifdef RTAC82U
	{ MODEL_RTAC82U, "CN", NULL, 0, "CN", "CN" , "CN", NULL, NULL, NULL },
	{ MODEL_RTAC82U, "US", NULL, 0, "US", "US" , "US", NULL, NULL, NULL },
	{ MODEL_RTAC82U, "XX", NULL, 0, "AU", "AU" , "AU", NULL, NULL, NULL },
#endif	/* RTAC82U */
#ifdef RPAC51
	{ MODEL_RPAC51, "CN", NULL, 0, "CN", "CN" , "CN", NULL, NULL, NULL },
	{ MODEL_RPAC51, "EU", NULL, 0, "GB", "GB" , "GB", NULL, NULL, NULL },
	{ MODEL_RPAC51, "XX", NULL, 0, "CN", "AU" , "CN", NULL, NULL, NULL },
#endif	/* RPAC51 */
#ifdef PLAX56_XP4
	{ MODEL_PLAX56XP4, "AA", NULL, 0, "AA", "AA" , "AA", NULL, NULL, NULL },
	{ MODEL_PLAX56XP4, "EU", NULL, 0, "GB", "GB" , "GB", NULL, NULL, NULL },
	{ MODEL_PLAX56XP4, "US", NULL, 0, "US", "US" , "US", NULL, NULL, NULL },
#endif	/* PLAX56_XP4 */
#elif defined(RTCONFIG_REALTEK)
#elif defined(BLUECAVE)
	{ MODEL_BLUECAVE, "AA", NULL, 0, "US", "0" , "US", "0", NULL, NULL },
	{ MODEL_BLUECAVE, "AU", NULL, 0, "AU", "0" , "AU", "0", NULL, NULL },
	{ MODEL_BLUECAVE, "CA", NULL, 0, "CA", "0" , "CA", "0", NULL, NULL },
	{ MODEL_BLUECAVE, "CN", NULL, 0, "CN", "0" , "CN", "0", NULL, NULL },
	{ MODEL_BLUECAVE, "GB", NULL, 0, "GB", "0" , "GB", "0", NULL, NULL },
	{ MODEL_BLUECAVE, "KR", NULL, 0, "KR", "0" , "KR", "0", NULL, NULL },
	{ MODEL_BLUECAVE, "US", NULL, 0, "US", "0" , "US", "0", NULL, NULL },
	{ MODEL_BLUECAVE, "XX", NULL, 0, "US", "0" , "US", "0", NULL, NULL },
#endif	/* ! CONFIG_BCMWL5 */

	/* END */
	{ 0, NULL, NULL, -1, NULL, NULL, NULL, NULL, NULL, NULL }
};

struct tcode_location_s tcode_location_list_HwIdA[] = {

	/* END */
	{ 0, NULL, NULL, -1, NULL, NULL, NULL, NULL, NULL, NULL }
};

struct tcode_location_s tcode_location_list_HwIdB[] = {
	/* changing location for HwIdB*/
#if	defined(RTCONFIG_RALINK)
#ifdef TUFAX4200
	{ MODEL_TUFAX4200, "CN", NULL, 0, "CN", "CN" , "CN", NULL, NULL, NULL },
	{ MODEL_TUFAX4200, "XX", NULL, 0, "CN", "AU" , "CN", NULL, NULL, NULL },
#endif /* TUFAX4200 */
#endif // end of RTCONFIG_RALINK

	/* END */
	{ 0, NULL, NULL, -1, NULL, NULL, NULL, NULL, NULL, NULL }
};

#ifdef RTCONFIG_ASUSCTRL
struct tcode_location_s asusctrl_tcode_location_list[] = {
#if defined(RTAC88U)
	{ MODEL_RTAC88U, "U2", "%d:%s", 0, "US", "793", "US", "793", NULL, NULL },
	{ MODEL_RTAC88U, "US", "%d:%s", 0, "US", "793", "US", "793", NULL, NULL },
	{ MODEL_RTAC88U, "AA", "%d:%s", 0, "US", "758", "US", "758", NULL, NULL },
	{ MODEL_RTAC88U, "AP", "%d:%s", 0, "Q2", "992", "Q2", "992", NULL, NULL },
	{ MODEL_RTAC88U, "CA", "%d:%s", 0, "CA", "878", "CA", "878", NULL, NULL },
	{ MODEL_RTAC88U, "SG", "%d:%s", 0, "SG", "978", "SG", "978", NULL, NULL },
	{ MODEL_RTAC88U, "JP", "%d:%s", 0, "JP", "94","JP", "94", NULL, NULL },
	{ MODEL_RTAC88U, "KR", "%d:%s", 0, "KR", "932","KR", "932", NULL, NULL },
	{ MODEL_RTAC88U, "WE", "%d:%s", 0, "E0", "745","E0", "745", NULL, NULL },
	{ MODEL_RTAC88U, "EE", "%d:%s", 0, "E0", "745","E0", "745", NULL, NULL },
	{ MODEL_RTAC88U, "EU", "%d:%s", 0, "E0", "745","E0", "745", NULL, NULL },
	{ MODEL_RTAC88U, "UK", "%d:%s", 0, "E0", "745","E0", "745", NULL, NULL },
	{ MODEL_RTAC88U, "CN", "%d:%s", 0, "CN", "63", "CN", "63", NULL, NULL },
	{ MODEL_RTAC88U, "TW", "%d:%s", 0, "TW", "969", "TW", "969", NULL, NULL },
	{ MODEL_RTAC88U, "RU", "%d:%s", 0, "E0", "745","E0", "745", NULL, NULL },
	{ MODEL_RTAC88U, "AU", "%d:%s", 0, "AU", "903", "AU", "903", NULL, NULL },
	{ MODEL_RTAC88U, "XX", "%d:%s", 0, "Q1", "947", "Q1", "947", NULL, NULL },
	{ MODEL_RTAC88U, "CX", "%d:%s", 0, "US", "758", "US", "758", NULL, NULL },
	{ MODEL_RTAC88U, "IL", "%d:%s", 0, "E0", "745","E0", "745", NULL, NULL },
#endif
#if defined(RTAC3100)
	{ MODEL_RTAC3100, "U2", "%d:%s", 0, "US", "793", "US", "793", NULL, NULL },
	{ MODEL_RTAC3100, "US", "%d:%s", 0, "US", "793", "US", "793", NULL, NULL },
	{ MODEL_RTAC3100, "AA", "%d:%s", 0, "US", "758", "US", "758", NULL, NULL },
	{ MODEL_RTAC3100, "CA", "%d:%s", 0, "CA", "878", "CA", "878", NULL, NULL },
	{ MODEL_RTAC3100, "EU", "%d:%s", 0, "E0", "745", "E0", "745", NULL, NULL },
#endif
	/* END */
	{ 0, NULL, NULL, -1, NULL, NULL, NULL, NULL, NULL, NULL }
};
#endif

#if defined(RTAC88U) || defined(RTAC3100)
struct tcode_location_s legacy_tcode_location_list[] = {
#if defined(RTAC88U)
	{ MODEL_RTAC88U, "US", "%d:%s", 0, "Q2", "992", "Q2", "992", NULL, NULL },
	{ MODEL_RTAC88U, "AA", "%d:%s", 0, "Q2", "992", "Q2", "992", NULL, NULL },
	{ MODEL_RTAC88U, "AP", "%d:%s", 0, "Q2", "992", "Q2", "992", NULL, NULL },
	{ MODEL_RTAC88U, "CA", "%d:%s", 0, "CA", "987", "CA", "987", NULL, NULL },
	{ MODEL_RTAC88U, "SG", "%d:%s", 0, "SG", "997", "SG", "997", NULL, NULL },
	{ MODEL_RTAC88U, "JP", "%d:%s", 0, "JP", "94","JP", "94", NULL, NULL },
	{ MODEL_RTAC88U, "KR", "%d:%s", 0, "KR", "975","KR", "975", NULL, NULL },
	{ MODEL_RTAC88U, "WE", "%d:%s", 0, "E0", "962","E0", "962", NULL, NULL },
	{ MODEL_RTAC88U, "EE", "%d:%s", 0, "E0", "962","E0", "962", NULL, NULL },
	{ MODEL_RTAC88U, "EU", "%d:%s", 0, "E0", "962","E0", "962", NULL, NULL },
	{ MODEL_RTAC88U, "UK", "%d:%s", 0, "E0", "962","E0", "962", NULL, NULL },
	{ MODEL_RTAC88U, "CN", "%d:%s", 0, "CN", "63", "CN", "63", NULL, NULL },
	{ MODEL_RTAC88U, "TW", "%d:%s", 0, "TW", "994", "TW", "994", NULL, NULL },
	{ MODEL_RTAC88U, "RU", "%d:%s", 0, "E0", "962","E0", "962", NULL, NULL },
	{ MODEL_RTAC88U, "AU", "%d:%s", 0, "AU", "984", "AU", "984", NULL, NULL },
	{ MODEL_RTAC88U, "XX", "%d:%s", 0, "Q1", "947", "Q1", "947", NULL, NULL },
	{ MODEL_RTAC88U, "CX", "%d:%s", 0, "Q2", "992", "Q2", "992", NULL, NULL },
	{ MODEL_RTAC88U, "IL", "%d:%s", 0, "E0", "962","E0", "962", NULL, NULL },
#endif
#if defined(RTAC3100)
	{ MODEL_RTAC3100, "US", "%d:%s", 0, "Q2", "992", "Q2", "992", NULL, NULL },
	{ MODEL_RTAC3100, "AA", "%d:%s", 0, "Q2", "992", "Q2", "992", NULL, NULL },
	{ MODEL_RTAC3100, "CA", "%d:%s", 0, "CA", "987", "CA", "987", NULL, NULL },
	{ MODEL_RTAC3100, "EU", "%d:%s", 0, "E0", "962", "E0", "962", NULL, NULL },
#endif
	/* END */
	{ 0, NULL, NULL, -1, NULL, NULL, NULL, NULL, NULL, NULL }
};
#endif

struct tcode_lang_s tcode_lang_list[] = {
	/* { model, odmpid, tcode, support_lang_list, auto_change } */
	{ MODEL_GENERIC, NULL, "CN", "CN EN", 0 },
	{ MODEL_GENERIC, NULL, "JP", "JP EN", 0 },
#ifdef RTAX82U
	{ MODEL_GENERIC, NULL, "TC", "CN EN", 0 },
#endif
	{ MODEL_GENERIC, NULL, "GLOBAL", ALL_LANGS, 1 },
	{ 0, NULL, NULL, NULL, 0 }
};

struct tcode_langcode_s tcode_langcode_list[] = {
	/* { model, tcode, lang_list, location } */
#ifdef CONFIG_BCMWL5
#ifdef RTAC66U
	{ MODEL_RTAC66U, "EE", "RU", "RU" },
	{ MODEL_RTAC66U, "EU", "RU", "RU" },
#endif
#ifdef RTN66U
	{ MODEL_RTN66U, "EE", "RU", "RU" },
	{ MODEL_RTN66U, "EU", "RU", "RU" },
#endif
#ifdef RTCONFIG_BCMARM
	{ MODEL_GENERIC, "EE", "RU", "RU" },
	{ MODEL_GENERIC, "EU", "RU", "RU" },
#endif
#elif defined(RTCONFIG_RALINK)
/* TODO */
#elif defined(RTCONFIG_QCA)
/* TODO */
#elif defined(RTCONFIG_REALTEK)
/* TODO */
#elif defined(BLUECAVE)
/* TODO */
#endif
	{ 0, NULL, NULL, NULL }
};

struct location_nvram_s location_init_nvram_list[] = {
#ifdef RTCONFIG_HAS_5G_2
	/* Tri-band are not handled */
#else
	{ MODEL_GENERIC, "", "RU", "acs_band3", "0" },
#endif
#ifdef RTCONFIG_YANDEXDNS
	{ MODEL_GENERIC, "", "RU", "rc_support", "yadns" },
#endif
	{ 0, NULL, NULL, NULL, NULL }
};

char *tcode_default_get(const char *name)
{
	struct tcode_nvram_s *p_nvram = tcode_init_nvram_list;
	char tcode[7], *odmpid;
	int model;
#ifdef RTAC68U
	unsigned int flag = hardware_flag();
#endif

	if (snprintf(tcode, sizeof(tcode), "%s", nvram_safe_get("territory_code")) <= 0)
		return NULL;

	model = get_model();
	odmpid = nvram_safe_get("odmpid");

	for (; p_nvram->model != 0; p_nvram++) {
		/* specific model are per odmpid & full tcode */
		if (p_nvram->model == model &&
#ifdef RTAC68U
			((flag & p_nvram->flag) != 0) &&
#endif
#ifdef RTAX82U
			(!p_nvram->cobrand || (nvram_get_int("CoBrand") && (p_nvram->cobrand == nvram_get_int("CoBrand")))) &&
#endif
			(!p_nvram->odmpid || strcmp(p_nvram->odmpid, odmpid) == 0) &&
			strcmp(p_nvram->tcode, tcode) == 0 &&
			strcmp(p_nvram->name, name) == 0)
			return p_nvram->value;
		else
		/* generic models are per country only */
		if (p_nvram->model == MODEL_GENERIC &&
#ifdef RTAC68U
			(!p_nvram->flag || (flag & p_nvram->flag) != 0) &&
			(strcmp(p_nvram->odmpid, "") == 0 || strcmp(p_nvram->odmpid, odmpid) == 0) &&
#endif
#ifdef RTAX82U
			(!p_nvram->cobrand || (nvram_get_int("CoBrand") && (p_nvram->cobrand == nvram_get_int("CoBrand")))) &&
#endif
			(!strlen(p_nvram->tcode) || strncmp(p_nvram->tcode, tcode, 2) == 0) &&
			strcmp(p_nvram->name, name) == 0)
			return p_nvram->value;
	}

	return NULL;
}

#ifdef RTCONFIG_ASUSCTRL
int asus_ctrl_en(int cid) {

	int ctrlf = nvram_get_hex("asusctrl_flags");

	if(ctrlf & 1<<cid)
		return 1;
	else 
		return 0;
}

int asus_ctrl_ignore() {
    if(*nvram_safe_get("asusctrl_flags"))
	return 0;
    else
	return 1;
}

/* close wps in first time start_wireless */
int setting_SG_mode_wps(){

	int ctrlf = 0;
	char *asusctrl = nvram_safe_get("asusctrl_flags");
	ctrlf = strtol(asusctrl, NULL, 16);

	if((ctrlf & 1<<ASUSCTRL_SG_MODE) && nvram_get_int("SG_mode") == 0 && nvram_get_int("w_Setting") == 1){
		nvram_set_int("SG_mode", 1);
		nvram_set_int("wps_enable", 0);
		nvram_set_int("wps_enable_x", 0);
		nvram_commit();
		return 1;
	}
	return 0;
}

int asus_ctrl_nv(char *asusctrl){

	int ctrlf = 0, nvram_modify = 0;
#if defined(RTCONFIG_QCA) || defined(RTCONFIG_RALINK)
	char wif[8], *next;
	unsigned int ch, need_restart = 0;
#endif

	ctrlf = strtol(asusctrl, NULL, 16);

#if defined(RTCONFIG_QCA) || defined(RTAX55) || defined(DSL_AX82U)
	if(nvram_get_int("EG_mode") == 0 && (ctrlf & 1<<ASUSCTRL_EG_MODE)){
		nvram_set_int("EG_mode", 1);
		nvram_modify = 1;
	}
#endif

	if(nvram_get_int("SG_mode") == 0 && (ctrlf & 1<<ASUSCTRL_SG_MODE)){
		//nvram_set_int("http_enable", 2);
		nvram_set_int("wan_upnp_enable", 0);
		nvram_set_int("wan0_upnp_enable", 0);
		nvram_set_int("wan1_upnp_enable", 0);
#ifdef RTCONFIG_DSL
		nvram_set_int("dsl_upnp_enable", 0);
		nvram_set_int("dsl0_upnp_enable", 0);
#ifdef RTCONFIG_VDSL
		nvram_set_int("dsl8_upnp_enable", 0);
#endif
#endif
		nvram_set_int("webs_update_enable", 1);
		nvram_set("webs_update_time", "03:00");
		if(asus_ctrl_en(ASUSCTRL_SG_MODE) == 0){
			nvram_set("webs_SG_mode", "1");
			notify_rc("stop_upnp");
		}
		nvram_modify = 1;
	}

	if(nvram_get_int("ID_mode") == 0 && (ctrlf & 1<<ASUSCTRL_ID_MODE)){
		nvram_set_int("ID_mode", 1);
		nvram_modify = 1;
	}

	if(nvram_modify == 1)
		nvram_commit();

#if defined(RTCONFIG_QCA) || defined(RTCONFIG_RALINK)
	foreach (wif, nvram_safe_get("wl_ifnames"), next) {
		if (!nvram_get_int("wlready"))
			continue;

		ch = get_channel(wif);
		if (((ctrlf & 1<<ASUSCTRL_ACS_IGNORE_BAND2) && (ch >= 52) && (ch <= 64))
		 || ((ctrlf & 1<<ASUSCTRL_ACS_IGNORE_BAND3) && (ch >= 100) && (ch <= 144))
		 || ((ctrlf & 1<<ASUSCTRL_ACS_IGNORE_BAND1) && (ch >= 36) && (ch <= 48))
		 || ((ctrlf & 1<<ASUSCTRL_ACS_IGNORE_BAND4) && (ch >= 149) && (ch <= 165)))
			need_restart++;

		if (nvram_get_int("x_Setting") && need_restart)
			notify_rc("restart_wireless");
	}
#endif

	return 0;
}

int asus_ctrl_nv_restore(){

	char *asusctrl = nvram_safe_get("asusctrl_flags");
	asus_ctrl_nv(asusctrl);
	return 0;
}

#endif

int is_CN_sku(void) {
	char tcode[16];
	snprintf(tcode, sizeof(tcode), "%s", nvram_safe_get("territory_code"));
	if (!strncmp(tcode, "CN", 2)
	    || !strncmp(tcode, "CT", 2)
#if defined(RTAX82U) || defined(RTAX86U)
	    || !strncmp(tcode, "GD", 2)
#endif
#ifdef RTAX82U
	    || !strncmp(tcode, "TC", 2)
#endif
	)
		return 1;
	else
		return 0;
}

int is_CN_location(void) {
	char location[16];
	snprintf(location, sizeof(location), "%s", nvram_safe_get("location_code"));
	if (!strncmp(location, "CN", 2)
	    || !strncmp(location, "CT", 2)
#if defined(RTAX82U) || defined(RTAX86U)
	    || !strncmp(location, "GD", 2)
#endif
#ifdef RTAX82U
	    || !strncmp(location, "TC", 2)
#endif
	)
		return 1;
	else
		return 0;
}

#endif	/* RTCONFIG_TCODE */
