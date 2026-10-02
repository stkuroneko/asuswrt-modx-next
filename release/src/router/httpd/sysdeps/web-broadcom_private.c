/*
 * Broadcom Home Gateway Reference Design
 * Web Page Configuration Support Routines
 *
 * Copyright 2004, Broadcom Corporation
 * All Rights Reserved.
 *
 * THIS SOFTWARE IS OFFERED "AS IS", AND BROADCOM GRANTS NO WARRANTIES OF ANY
 * KIND, EXPRESS OR IMPLIED, BY STATUTE, COMMUNICATION OR OTHERWISE. BROADCOM
 * SPECIFICALLY DISCLAIMS ANY IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A SPECIFIC PURPOSE OR NONINFRINGEMENT CONCERNING THIS SOFTWARE.
 * $Id: broadcom.c,v 1.1.1.1 2010/10/15 02:24:15 shinjung Exp $
 */

#ifdef WEBS
#include <webs.h>
#include <uemf.h>
#include <ej.h>
#else /* !WEBS */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <limits.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <httpd.h>
#endif /* WEBS */

#include <shared.h>

#if defined(RTCONFIG_HND_ROUTER_AX_675X) || defined(RTCONFIG_HND_ROUTER_AX_6756) || defined(RTCONFIG_HND_ROUTER_AX_6710) || defined(RTCONFIG_BCM_502L07P2)
#include "ethctl.h"
#include "bcmnet.h"

static int et_cable_diag(int skfd, struct ifreq *ifr, webs_t wp)
{
    int err, i;
    struct ethctl_data *ethctl = ifr->ifr_data;
    static char *color[] ={"Brown", "Blue", "Green", "Orange"};
    static char *result[] = {"Invalid", "Good", "Open", "Intra Pair Short", "Inter Pair Short"};
    int retval = 0;

    ethctl->op = ETHCDRUN;

    strlcpy(ethctl->ifname, ifr->ifr_name, sizeof(ethctl->ifname));

    err = ioctl(skfd, SIOCETHCTLOPS, ifr);

    if (err) {
        dbg("command return error!\n");
        return retval;
    }

    retval += websWrite(wp, "Interface %s: PHY address %d. ", ethctl->ifname, ethctl->phy_addr);

    switch (ethctl->ret_val) {
        case CD_INVALID:
            dbg("CD return invalid.\n");
            goto error;
        case CD_ALL_PAIR_OK:
            retval += websWrite(wp, "Connected Cable length: %d.%d meter.", ethctl->pair_len[0]/100, ethctl->pair_len[0]%100);
            break;
        case CD_ALL_PAIR_OPEN:
            if((ethctl->pair_len[0] + ethctl->pair_len[1] +
                ethctl->pair_len[2] + ethctl->pair_len[3]) == 0) {
                retval += websWrite(wp, "No cable connected to the port.");
            }
            else if (ethctl->pair_len[0] == ethctl->pair_len[1] &&
                    ethctl->pair_len[0] == ethctl->pair_len[2] &&
                    ethctl->pair_len[0] == ethctl->pair_len[3]) {
                retval += websWrite(wp, "Open Cable length: %d.%d meter.", ethctl->pair_len[0]/100, ethctl->pair_len[0]%100);
            }
            else {
                retval += websWrite(wp, "Cable Open at Pair Br:%d.%d Bl:%d.%d Gr:%d.%d Or%d.%d meters.",
                        ethctl->pair_len[0]/100, ethctl->pair_len[0]%100, 
                        ethctl->pair_len[1]/100, ethctl->pair_len[1]%100, 
                        ethctl->pair_len[2]/100, ethctl->pair_len[2]%100, 
                        ethctl->pair_len[3]/100, ethctl->pair_len[3]%100);
            }
            break;
            /* Fall through here for Open cable case */
        case CD_NOT_SUPPORTED:
            retval += websWrite(wp, "Cable Diagnosis Not Supported.");
            break;
        default:
            if(ethctl->flags & CD_LINK_UP) {
                retval += websWrite(wp, "Connected Cable length: %d.%d meter.", ethctl->pair_len[0]/100, ethctl->pair_len[0]%100);
                for(i=0; i<4; i++)
                    if (CD_CODE_PAIR_GET(ethctl->ret_val, i) != CD_OK) {
                        retval += websWrite(wp, " Pair %s: %s;", color[i], result[CD_CODE_PAIR_GET(ethctl->ret_val, i)]);
                    }
            } else {
                for(i=0; i<4; i++)
                {
                    if (CD_CODE_PAIR_GET(ethctl->ret_val, i)==CD_INVALID)
                    {
                        retval += websWrite(wp, " Pair %s: Cable Diagnosis Failed - Skipped.", color[i]);
                        continue;
                    }

                    retval += websWrite(wp, " Pair %s is %s %s %d.%d meters.", color[i], 
                            result[CD_CODE_PAIR_GET(ethctl->ret_val, i)],
                            CD_CODE_PAIR_GET(ethctl->ret_val, i)==CD_OK? "with": "at",
                            ethctl->pair_len[i]/100, ethctl->pair_len[i]%100);
                }
            }
            break;
    }

error:
    return retval;
}

int ej_cable_diag(int eid, webs_t wp, int argc, char_t **argv)
{
	int lan = 0;
	int port;
	char word[16] = { 0 };
	char *next = NULL;
	int i;
#if 0
	char cmd[64], buf[1024];
	FILE *pfp = NULL;
#else
	char ifname[16];
	static struct ethctl_data ethctl;
	struct ifreq ifr;
	int skfd;
#endif
	int retval = 0;

	if ((argc != 1) || (strlen(argv[0]) != 2))
		return retval;

	if (!strncmp(argv[0], "L", 1))
		lan = 1;

	port = atoi(argv[0]+1);
	if (lan)
		port--;

	i = 0;
	foreach(word, ((lan == 1) ? nvram_safe_get("lanports") : nvram_safe_get("wanports")), next) {
		if (i == port) break;
		i++;
	}
#if 0
	snprintf(cmd, sizeof(cmd), "ethctl eth%s cable-diag run", word);
	pfp = popen(cmd, "r");
	if (pfp != NULL) {
		while (fgets(buf, sizeof(buf), pfp) != NULL) {
			replace_char(buf, '\n', '');
			retval += websWrite(wp, "%s", buf);
		}

		pclose(pfp);
	}
#else
	snprintf(ifname, sizeof(ifname), "eth%s", word);
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		dbg("socket open error\n");
		return retval;
	}

	if (ioctl(skfd, SIOCGIFINDEX, &ifr) < 0 ) {
		dbg("ioctl failed. check if %s exists\n", ifr.ifr_name);
		close(skfd);
		return -1;
	}

	memset(&ethctl, 0, sizeof(ethctl));
	ifr.ifr_data = &ethctl;
	retval += et_cable_diag(skfd, &ifr, wp);
	close(skfd);
#endif
	return retval;
}

#ifdef RTCONFIG_BCMBSD_V2
extern void gen_bcmbsd_def_policy(int sel);

int ej_bcmbsd_def_policy(int eid, webs_t wp, int argc, char_t **argv)
{
	int selif_val = nvram_get_int("smart_connect_selif");

	gen_bcmbsd_def_policy(selif_val);

	return 0;
}
#endif

#endif
