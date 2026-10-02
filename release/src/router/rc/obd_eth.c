/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 USA
 *
 * Copyright 2012, ASUSTeK Inc.
 * All Rights Reserved.
 *
 * THIS SOFTWARE IS OFFERED "AS IS", AND ASUS GRANTS NO WARRANTIES OF ANY
 * KIND, EXPRESS OR IMPLIED, BY STATUTE, COMMUNICATION OR OTHERWISE. BROADCOM
 * SPECIFICALLY DISCLAIMS ANY IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A SPECIFIC PURPOSE OR NONINFRINGEMENT CONCERNING THIS SOFTWARE.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>
#include <time.h>
#include <bcmnvram.h>
#include <bcmutils.h>
#include <wlutils.h>
#include <shutils.h>
#include <shared.h>
#include <wlioctl.h>
#include <rc.h>


#ifdef RTCONFIG_SW_HW_AUTH
#include <auth_common.h>
#define APP_ID  "33716237"
#define APP_KEY "g2hkhuig238789ajkhc"
#endif

#include <wlscan.h>
#include <bcmendian.h>
#if defined(RTCONFIG_BCM7) || defined(RTCONFIG_BCM_7114) || defined(HND_ROUTER)
#include <bcmutils.h>
#include <security_ipc.h>
#endif

#include <sys/reboot.h>

#include <amas-utils.h>
#include <amas_path.h>
#include <amas_ob.h>

#ifdef __MBEDTLS__
#include <mbedtls/rsa.h>
#include <mbedtls/error.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>
#include <mbedtls/aes.h>
#include <mbedtls/version.h>
#include <mbedtls/sha256.h>
#else   /* __MBEDTLS__ */
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#endif  /* __MBEDTLS__ */

#ifdef RTCONFIG_QCA_PLC2
#include <plc_utils.h>
#endif

#include <pthread.h>

int dbglevel = 0;

#define OBD_DBG(fmt, arg...) \
        do {    \
               if(dbglevel) \
                dbG("obd_eth %lu: "fmt, uptime(), ##arg); \
        } while (0)

#define OBD_EX_PERIOD               1       /* second */
#define NORMAL_PERIOD               1       /* second */
#define RUSHURGENT_PERIOD           50 * 1000   /* microsecond */
#define CLEAR_PERIOD                30
#define NVRAM_BUFSIZE               100

#define RETRY_TIMES                 30
#define NUMCHANS                    64
#define MAX_SSID_LEN                32

#define OBD_TIMEOUT                 300

static time_t time_ref;
static int status_g = 0;
int obdmsg_timer = 30;
int keystat = SS_OFF;

pthread_attr_t attr;
pthread_attr_t *attrptr = NULL;
#ifndef RTCONFIG_NO_PTHREAD_TIMEDWAIT
pthread_mutex_t obdeth_mutex;
pthread_cond_t obdeth_cond;
#endif
unsigned char newea[ETHER_ADDR_LEN] = {0};
unsigned char peermac[7]={0};
unsigned char newre_lastkey[64]={0};
unsigned char oldnode[ETHER_ADDR_LEN] ={0};

int retry_count = 0;

static void obd_eth_exit(int sig);
int reset_obd_status();

static int
ethernet_scan()
{
    //ob_status *P_obstatus = NULL;
    id_info *P_idinfo = NULL;
    unsigned char macaddr[7]={0};
    unsigned char groupid[256] = {0};
    int res = 0;
    int len = 0;
    int k = 0, q = 0;
    int ob_locked = 0;
    int count_available = 0;
    int match_4 = 0;

#ifdef RTCONFIG_PRELINK
    bundle_key *P_bundlekey = NULL;
    int bundlekeylen = 0;

    // Check Prelink first.
    if (amas_get_bundle_key(&P_bundlekey, &bundlekeylen) == AMAS_RESULT_SUCCESS &&
        P_bundlekey &&
        bundlekeylen) {
        int verified = 0;
        int lock = -1;
        OBD_DBG("%s:%d  bundle key len =%d\n", __FUNCTION__,__LINE__, bundlekeylen);
        OBD_DBG("%s:%d  bundle key =\n", __FUNCTION__,__LINE__);
        if (status_g == 0 &&
            amas_verify_hash_bundle_key(P_bundlekey->bundlekey, &verified) == AMAS_RESULT_SUCCESS &&
            verified == 1 &&
            (lock = prelink_lock_acquire(dbglevel)) >= 0) {
            OBD_DBG("Prelink detected.\n");
            nvram_set("prelink", "1");
            nvram_set("obdeth_Setting", "1");
#ifdef RTCONFIG_MSSID_PRELINK
            restore_mssid_prelink_config();
#endif
            nvram_set("sw_mode", "3");
            nvram_set("wlc_psta", "2");
#if defined(RTCONFIG_WIFI6E) || defined(RTCONFIG_HND_ROUTER_AX_6756) || !defined(RTCONFIG_DPSTA)
	    nvram_set("wlc_dpsta", "2");    // dpsr
#else
	    nvram_set("wlc_dpsta", "1");    // dpsta
#endif
            nvram_set("lan_proto", "dhcp");
            nvram_set("lan_dnsenable_x", "1");
#ifdef RTCONFIG_DHCP_OVERRIDE
            nvram_set("dnsqmode", "1");
#endif
            nvram_set("x_Setting", "1");
            nvram_set("w_Setting", "1");
            nvram_set("re_mode", "1");
            nvram_set("amas_ethernet", "2");
            nvram_unset("cfg_group");
            nvram_commit();
            if(P_bundlekey != NULL)
                free(P_bundlekey);
            OBD_DBG("Exit due to ethernet prelink successfully\n\n");
            prelink_unlock(lock);
            obd_switch_re(0);
            obd_eth_exit(SIGTERM);
            return 0;
        }

        if(P_bundlekey != NULL)
            free(P_bundlekey);
    }
#endif

    // Check original onboarding.
#if defined(RTCONFIG_AMAS_UNIQUE_MAC)
    ether_atoe(get_label_mac(), newea);
#else
    ether_atoe(get_lan_hwaddr(), newea);
#endif
    res = amas_get_obdinfo(&P_idinfo, &len);
    if (res != AMAS_RESULT_SUCCESS) {
        OBD_DBG("Can't get onborading information\n");
        if(keystat != SS_OFF)
            retry_count++;
    }
    else
    {
        if (len > 0)
        {

            for (k = 0; k < len; k ++)
            {
                OBD_DBG("%s:%d  Entry[%d] neighbors MAC = %02X:%02X:%02X:%02X:%02X:%02X\n",__FUNCTION__,__LINE__, k, P_idinfo[k].neighmac[0], P_idinfo[k].neighmac[1], P_idinfo[k].neighmac[2], P_idinfo[k].neighmac[3], P_idinfo[k].neighmac[4], P_idinfo[k].neighmac[5]);
                OBD_DBG("%s:%d  Entry[%d] id len =%d\n", __FUNCTION__,__LINE__,  k, P_idinfo[k].idlen);
                OBD_DBG("%s:%d  Entry[%d] id =", __FUNCTION__,__LINE__, k);
                for(q = 0; q <  P_idinfo[k].idlen; q++)
                    OBD_DBG("%02X ", P_idinfo[k].id[q]);
                OBD_DBG("\n");
                OBD_DBG("%s:%d  Entry[%d] newremac = %02X:%02X:%02X:%02X:%02X:%02X\n", __FUNCTION__,__LINE__,  k, P_idinfo[k].newremac[0], P_idinfo[k].newremac[1], P_idinfo[k].newremac[2], P_idinfo[k].newremac[3], P_idinfo[k].newremac[4], P_idinfo[k].newremac[5]);
                OBD_DBG("%s:%d  Entry[%d] ob status = %d\n", __FUNCTION__, __LINE__,k, P_idinfo[k].obstatus);
                OBD_DBG("%s:%d  Entry[%d] ob status Timestamp = %X\n", __FUNCTION__, __LINE__,k, P_idinfo[k].timestamp);
                OBD_DBG("%s:%d  Entry[%d] ob status Model Name = %s\n", __FUNCTION__, __LINE__,k, P_idinfo[k].modelname);
                OBD_DBG("%s:%d  Entry[%d] ob status Tcode = %s\n", __FUNCTION__, __LINE__,k, P_idinfo[k].tcode);
                OBD_DBG("%s:%d  Entry[%d] bundle key len =%d\n", __FUNCTION__,__LINE__,  k, P_idinfo[k].bundlekeylen);
                OBD_DBG("%s:%d  Entry[%d] bundle key =", __FUNCTION__,__LINE__, k);
                for(q = 0; q <  P_idinfo[k].bundlekeylen; q++)
                    OBD_DBG("%02X ", P_idinfo[k].bundlekey[q]);
                OBD_DBG("\n");
                OBD_DBG("%s:%d  ======================================\n", __FUNCTION__, __LINE__);

                if(!isNull(P_idinfo[k].newremac, sizeof(P_idinfo[k].newremac)))
                    memcpy(macaddr, P_idinfo[k].newremac, sizeof(macaddr));

                if(P_idinfo[k].obstatus == OB_LOCKED && !isNull(P_idinfo[k].newremac, sizeof(P_idinfo[k].newremac)))
                {
                    if (!memcmp(newea, P_idinfo[k].newremac, ETHER_ADDR_LEN))
                    {
                        if (isNull(peermac, sizeof(peermac)))
                        {
                            memset(peermac, 0x00, sizeof(peermac));
                            memcpy(peermac, P_idinfo[k].neighmac, sizeof(peermac));
                            memcpy(groupid, P_idinfo[k].id, P_idinfo[k].idlen);

                        }
                        else if (memcmp(peermac, P_idinfo[k].neighmac, sizeof(peermac)))
                        {
                            OBD_DBG("%s:%d  neighbors MAC = %02X:%02X:%02X:%02X:%02X:%02X\n",__FUNCTION__,__LINE__, P_idinfo[k].neighmac[0], P_idinfo[k].neighmac[1], P_idinfo[k].neighmac[2], P_idinfo[k].neighmac[3], P_idinfo[k].neighmac[4], P_idinfo[k].neighmac[5]);
                            if(memcmp(groupid, P_idinfo[k].id, P_idinfo[k].idlen)) {
                                keystat = SS_SECURITYFAIL; // overlapping, OBD failed.
                                OBD_DBG("===================Overlapping=====================\n");
                                break;
                            }
                        }
                    }
                }
            }

            if (keystat != SS_SECURITYFAIL)
            {
               for (k = 0; k<len; k++)
                {
                    OBD_DBG("Local MAC Address(%02X:%02X:%02X:%02X:%02X:%02X)\n", newea[0], newea[1], newea[2], newea[3], newea[4], newea[5]);
                    OBD_DBG("New RE's MAC Address(%02X:%02X:%02X:%02X:%02X:%02X)\n", macaddr[0], macaddr[1], macaddr[2], macaddr[3], macaddr[4], macaddr[5]);
                    if (!isNull(macaddr, sizeof(macaddr)) && !memcmp(newea, macaddr, ETHER_ADDR_LEN))
                        match_4 = 1;
                    else
                        match_4 = -1;

                    if (status_g == 0 && P_idinfo[k].obstatus == OB_AVALIABLE)
                    {
                            count_available++;
                        if (count_available == 1)
                            nvram_set_int("amesh_found_cap", 1);
                    }
                    else if (status_g == 1) {
                        if (P_idinfo[k].obstatus == OB_AVALIABLE) {
                            count_available++;

                            if (match_4 == 1) {
                                OBD_DBG("Start to blink WPS LED\n");
                                if (nvram_get_int("amesh_led") == 0) {
                                    nvram_set_int("amesh_led", 1);
                                    obd_led_blink();
                                }
                            } else if (match_4 == -1) {
                                OBD_DBG("Stop WPS LED blinking for BSSID \n");
                                if (nvram_get_int("amesh_led") == 1) {
                                    nvram_set_int("amesh_led", 0);
                                    obd_led_off();
                                }
                            }
                        } else if (P_idinfo[k].obstatus == OB_LOCKED) {
                            if (match_4 == -1) {
                                OBD_DBG("Reset due to mismatch of RE MAC address\n\n");
                                status_g = 0;
                                time_ref = uptime();
                                nvram_set_int("amesh_found_cap", 0);

                                if(P_idinfo != NULL)
                                    free(P_idinfo);
                                return 0;

                            } else if (match_4 == 1) {
                                OBD_DBG("OB Lock for %02X:%02X:%02X:%02X:%02X:%02X\n\n", macaddr[0], macaddr[1], macaddr[2], macaddr[3], macaddr[4], macaddr[5]);
                                ob_locked = 1;
                                nvram_set_int("amesh_found_cap", 0);
                                goto ACTION;
                            }
                        }
                    }
                }
            }
        }
    }

ACTION:
    if (retry_count >= RETRY_TIMES) {
        OBD_DBG("Reset due to retry_count over %d\n\n", RETRY_TIMES);
        keystat = SS_TIMEOUT;
    }
    else if ((uptime() - time_ref) > OBD_TIMEOUT) {
        OBD_DBG("Reset due to timeout\n\n");
        status_g = 0;
        time_ref = uptime();
        nvram_set_int("amesh_found_cap", 0);
        reset_obd_status();

    } else if (ob_locked && status_g == 1) {
        OBD_DBG("===========Start Change information============\n");
        if (nvram_get_int("amesh_led") == 1) {
            nvram_set_int("amesh_led", 0);
            obd_led_off();
        }
        keystat = SS_KEY;
        retry_count = 0;
        status_g = 2;
    } else if (count_available && (status_g == 0 || status_g == 1)) {

        res = amas_set_obstatus(OB_REQ);
        if (res == AMAS_RESULT_SUCCESS) {
            OBD_DBG("Set OB request finished\n");
        }
        else{
            OBD_DBG("Set OB request failed\n");
        }

        OBD_DBG("Send OB Request\n\n");


        if (!status_g) {
            status_g = 1;
        }
    }

    if (P_idinfo != NULL)
        free(P_idinfo);
    return 0;
}

static struct itimerval itv;
static void
alarmtimer(unsigned long sec, unsigned long usec)
{
    itv.it_value.tv_sec = sec;
    itv.it_value.tv_usec = usec;
    itv.it_interval = itv.it_value;
    setitimer(ITIMER_REAL, &itv, NULL);
}

static void
obd_eth(int sig)
{
    if (sig == SIGALRM)
    {
        if (status_g == 0 || status_g == 1) {
            ethernet_scan();

            alarm(NORMAL_PERIOD);

        } else if (status_g == 2) { // OBD exchange
            ethernet_scan();

            if(keystat == SS_OBD_FIN) { //OBD Finished
                status_g = 3;
            }
            alarm(NORMAL_PERIOD);

        } else if (status_g == 3) { // OBD success
            if (nvram_get_int("obdeth_Setting") == 1) {
#ifdef RTCONFIG_QCA_PLC2
		char nmk[64];	/* more than 48 */
		if(nvram_get_int("autodet_plc_state") > 0 && current_nmk(nmk) == 0) {
			nvram_set("plc_nmk", nmk);
		}
#endif	/* RTCONFIG_QCA_PLC2 */
#ifdef RTCONFIG_MSSID_PRELINK
                restore_mssid_prelink_config();
#endif
                nvram_set("sw_mode", "3");
                nvram_set("wlc_psta", "2");
#if defined(RTCONFIG_WIFI6E) || defined(RTCONFIG_HND_ROUTER_AX_6756) || !defined(RTCONFIG_DPSTA)
		nvram_set("wlc_dpsta", "2");    // dpsr
#else
		nvram_set("wlc_dpsta", "1");    // dpsta
#endif
                nvram_set("lan_proto", "dhcp");
                nvram_set("lan_dnsenable_x", "1");
#ifdef RTCONFIG_DHCP_OVERRIDE
				nvram_set("dnsqmode", "1");
#endif
                nvram_set("x_Setting", "1");
                nvram_set("w_Setting", "1");
                nvram_set("re_mode", "1");
                nvram_set("amas_ethernet", "2");
                nvram_unset("cfg_group");
                nvram_commit();
                OBD_DBG("Exit due to ethernet onboarding successfully\n\n");
                kill(1, SIGTERM);
                obd_eth_exit(SIGTERM);
            } else {
                alarm(NORMAL_PERIOD);
            }
        } else if (status_g == 4) { // OBD failure
            OBD_DBG("Exit due to ethernet onboarding failure\n\n");
            status_g = 0;
            time_ref = uptime();
            nvram_set_int("amesh_found_cap", 0);
            sleep(CLEAR_PERIOD);
            reset_obd_status();
            ethernet_scan();

            alarm(NORMAL_PERIOD);
        }
    }
}

int reset_obd_status() {

    int res = 0;
    unsigned char value[8]={0};

    if(keystat == SS_OFF)
        return 0;

    retry_count = 0;
    keystat = SS_OFF;

    memset(newea, 0x00, sizeof(newea));
    memset(peermac, 0x00, sizeof(peermac));
    memset(newre_lastkey, 0x00, sizeof(newre_lastkey));
    memset(oldnode, 0x00, sizeof(oldnode));

    nvram_set_int("amesh_found_cap", 0);
    nvram_set("obdeth_Setting", "0");

    res = amas_set_obstatus(0);
    if (res == AMAS_RESULT_SUCCESS)
        OBD_DBG("Clear ob status\n");

    res = amas_set_secstatus(0);
    if (res == AMAS_RESULT_SUCCESS)
        OBD_DBG("Clear security key status\n");

    strlcpy(value, "NONE", sizeof(value));
    res = amas_set_sessionkey(value);
    if (res == AMAS_RESULT_SUCCESS)
        OBD_DBG("Clear session key status\n");

    res = amas_set_peermac(value);
    if (res == AMAS_RESULT_SUCCESS)
        OBD_DBG("Clear new RE's information.\n");

    res = amas_set_group(value);
    if (res == AMAS_RESULT_SUCCESS)
        OBD_DBG("Clear group information.\n");

    return 0;
}

static void
obd_eth_exit(int sig)
{
    if (sig == SIGTERM)
    {
        alarmtimer(0, 0);

        reset_obd_status();


        remove("/var/run/obd_eth.pid");
        exit(0);
    }
}

#ifdef RTCONFIG_BHCOST_OPT
static void set_eth_ob_ifname(char *ob_ifname)
{
    char ifname[16] = {0}, eth_ifnames[32] = {0}, *next = NULL;
    int found = 0;

    if (!ob_ifname) {
        OBD_DBG("ob_ifname is null\n");
        return;
    }

    if (*ob_ifname == '\0') {
        OBD_DBG("ob_ifname is empty\n");
        return;
    }

    if (nvram_get("eth_ifnames")) {
        snprintf(eth_ifnames, sizeof(eth_ifnames), "%s", nvram_safe_get("eth_ifnames"));
        OBD_DBG("eth_ifnames is %s", eth_ifnames);

        foreach(ifname, eth_ifnames, next) {
            if (strcmp(ifname, ob_ifname) == 0) {
                found = 1;
                break;
            }
        }

        if (found) {
            OBD_DBG("eth ob ifname is %s", ob_ifname);
            nvram_set("cfg_obifname", ob_ifname);
        }
        else
            OBD_DBG("don't need set eth ob ifname\n");

    }
    else
    {
        OBD_DBG("eth ob ifname is %s", ob_ifname);
        nvram_set("cfg_obifname", ob_ifname);
    }
}
#endif

void *obd_msg_exchange()
{
    pthread_detach(pthread_self());

    struct timeval now;
    struct timespec outtime;
    AMAS_RESULT res = AMAS_RESULT_FAILED;
    AMAS_RESULT res2 = AMAS_RESULT_FAILED;
    int len = 0, i =0, k=0;
    size_t sha256KeyLen = 0;
    size_t decodeMsgLen = 0;
    char sha256KeyStr[128]={0};
    char oldnode_str[20]={0};
    char outId[128] = {0};
    unsigned char temp_key[17]={0};
    unsigned char *sha256Key = NULL;
    unsigned char *decodeMsg = NULL;

    sec_status *P_secstatus = NULL;


    while (1)
    {
#ifndef RTCONFIG_NO_PTHREAD_TIMEDWAIT
        pthread_mutex_lock(&obdeth_mutex);
        obdmsg_timer = nvram_get_int("obdmsg_timer") ? : OBD_EX_PERIOD;
        gettimeofday(&now, NULL);
        outtime.tv_sec = now.tv_sec + obdmsg_timer;
        outtime.tv_nsec = 0;
        pthread_cond_timedwait(&obdeth_cond, &obdeth_mutex, &outtime);
#else
		obdmsg_timer = nvram_get_int("obdmsg_timer") ? : OBD_EX_PERIOD;
		sleep(obdmsg_timer);
#endif

        if(keystat == SS_KEY)
        {
            memset(newre_lastkey, 0x00, sizeof(newre_lastkey));

            if(!isNull(newea, sizeof(newea)) && !isNull(peermac, sizeof(peermac)))
            {
                for(i = 0; i<ETHER_ADDR_LEN; i++) {
                    temp_key[i] = peermac[i];
                    temp_key[i+6] = newea[i];
                    oldnode[i] = peermac[i];  //record RE's MAC address for onboarding.
                }

                sha256Key = gen_sha256_key(temp_key, sizeof(temp_key) - 1, &sha256KeyLen);

                if (sha256Key == NULL || sha256KeyLen <= 0)
                {
                    OBD_DBG("gen_sha256_key() failed ...");
                    retry_count++;
                    continue;
                }


                memcpy(newre_lastkey, sha256Key, HASH_LEN);
                hex2str_x(sha256Key, sha256KeyStr, sha256KeyLen);
                free(sha256Key);
                sha256KeyStr[64] = '\0';
                memset(outId, 0, sizeof(outId));
                snprintf(outId, sizeof(outId), "%s",sha256KeyStr);
                OBD_DBG("outId (%s)\n", outId);
                OBD_DBG("Generate Session Key finished. (%s)\n", outId);
                keystat = SS_KEYACK;
                retry_count = 0;
#if 0
                if(!memcmp(newre_lastkey, P_exchange[k].data, HASH_LEN)) {
                    OBD_DBG("%s:%d Check session Key successfully.\n", __FUNCTION__, __LINE__);
                    keystat = SS_KEYACK;
                    /* set SS_KEYACK*/
                    res2 = amas_set_secstatus(SS_KEYACK);
                    if (res2 == AMAS_RESULT_SUCCESS){
                        OBD_DBG("Set security status to %d\n", SS_KEYACK);
                    }
                }
                else {
                    OBD_DBG("%s:%d Check session Key failed.\n", __FUNCTION__, __LINE__);
                }
#endif
            }
            else {
                OBD_DBG("RE MAC or NEW RE MAC IS NULL.\n");
                retry_count++;
            }
        }

        if(keystat == SS_KEYACK) {
            data_exchange *P_exchange = NULL;

            res = amas_get_sessionkey(&P_exchange, &len);
            if (res == AMAS_RESULT_SUCCESS)
            {
                if(len > 0) {
                    for (k = 0; k < len; k ++)
                    {
    #if 0
                        printf("%s:%d  Entry[%d] neighbors MAC = %02X:%02X:%02X:%02X:%02X:%02X\n",__FUNCTION__,__LINE__, k, P_exchange[k].neighmac[0], P_exchange[k].neighmac[1], P_exchange[k].neighmac[2], P_exchange[k].neighmac[3], P_exchange[k].neighmac[4], P_exchange[k].neighmac[5]);
                        printf("%s:%d  Entry[%d] peer's MAC = %02X:%02X:%02X:%02X:%02X:%02X\n",__FUNCTION__,__LINE__, k, P_exchange[k].peermac[0], P_exchange[k].peermac[1], P_exchange[k].peermac[2], P_exchange[k].peermac[3], P_exchange[k].peermac[4], P_exchange[k].peermac[5]);
                        printf("%s:%d  Len = %d Entry[%d] tempKey =", __FUNCTION__,__LINE__, P_exchange[k].datalen, k);
                        for(i = 0; i < P_exchange[k].datalen; i++)
                            printf("%02X ", P_exchange[k].data[i]);
                        printf("===================================\n\n");

                        printf("newre_lastkey :");
                        for(i = 0; i < strlen((char*)newre_lastkey); i++) {
                            printf("%02X ", newre_lastkey[i]);
                        }
                        printf("===================================\n\n");
    #endif

                        if(!memcmp(newea, P_exchange[k].peermac, ETHER_ADDR_LEN) && !memcmp(oldnode, P_exchange[k].neighmac, ETHER_ADDR_LEN))
                        {

                            decodeMsg = data_aes_decrypt(newre_lastkey, &P_exchange[k].data[0], P_exchange[k].datalen, &decodeMsgLen);
                            if (decodeMsg == NULL) {
                                OBD_DBG("Failed to aes_decrypt() !!!");
                                retry_count++;
                            }
                            else {
                                retry_count = 0;
                                OBD_DBG("decodeMsg:%s\n", decodeMsg);
                                OBD_DBG("interface:%s\n", &P_exchange[k].ifname[0]);
                                OBD_DBG("===================================\n\n");


                                nvram_set("cfg_obkey", (char *)decodeMsg);
#ifdef RTCONFIG_BHCOST_OPT
                                set_eth_ob_ifname(&P_exchange[k].ifname[0]);
#endif
                                nvram_set("obdeth_Setting", "1");

                                ether_etoa((const unsigned char *)&oldnode, oldnode_str);
                                res2 = amas_set_peermac((unsigned char *)oldnode_str);
                                if (res2 == AMAS_RESULT_SUCCESS){
                                    OBD_DBG("Set peer's MAC to (%s)\n", oldnode_str);
                                }
                                res2 = amas_set_secstatus(SS_SUCCESS);
                                if (res2 == AMAS_RESULT_SUCCESS){
                                    OBD_DBG("Set security status to SS_SUCCESS(%d)\n", SS_SUCCESS);
                                }
                                 keystat = SS_SUCCESS;
                            }
                        }
                        else {
                            retry_count++;
                            OBD_DBG("Can't find node for onboarding.\n");
                        }
                    }
                }
                else {
                    retry_count++;
                    OBD_DBG("Can't get key for onboarding.\n");
                }

                if(P_exchange != NULL)
                    free(P_exchange);
            }
            else {
                retry_count++;
                OBD_DBG("Can't get key for onboarding.\n");
            }
        }

        if(keystat == SS_SUCCESS) {

            res = amas_get_secstatus(&P_secstatus, &len);

            if (res != AMAS_RESULT_SUCCESS) {
                OBD_DBG("Get security status failed.\n");
                if(P_secstatus != NULL)
                    free(P_secstatus);
                retry_count++;
                continue;
            }
            else {
                if (len > 0) {
                    for (k = 0; k < len; k ++)
                    {
                        OBD_DBG("%s:%d  Entry[%d] neighbors MAC = %02X:%02X:%02X:%02X:%02X:%02X\n",__FUNCTION__,__LINE__, k, P_secstatus[k].neighmac[0], P_secstatus[k].neighmac[1], P_secstatus[k].neighmac[2], P_secstatus[k].neighmac[3], P_secstatus[k].neighmac[4], P_secstatus[k].neighmac[5]);
                        OBD_DBG("%s:%d  Entry[%d] peer MAC = %02X:%02X:%02X:%02X:%02X:%02X\n",__FUNCTION__,__LINE__, k, P_secstatus[k].peermac[0], P_secstatus[k].peermac[1], P_secstatus[k].peermac[2], P_secstatus[k].peermac[3], P_secstatus[k].peermac[4], P_secstatus[k].peermac[5]);
                        OBD_DBG("%s:%d  Entry[%d] sec status = %d\n", __FUNCTION__, __LINE__, k, P_secstatus[k].secstatus);
                        OBD_DBG("=============================================================\n");

                        if (!memcmp(newea, P_secstatus[k].peermac, ETHER_ADDR_LEN) && !memcmp(oldnode, P_secstatus[k].neighmac, ETHER_ADDR_LEN)) {
                            if(P_secstatus[k].secstatus == SS_OBD_FIN)
                                keystat = SS_OBD_FIN;
                        }
                    }
                }
                else {
                    OBD_DBG("Can't get SS_OBD_FIN status.\n");
                    retry_count++;
                }
            }
            if(P_secstatus != NULL)
                free(P_secstatus);
        }

        if(keystat == SS_SECURITYFAIL || keystat == SS_TIMEOUT) {
            OBD_DBG("=============== overlapping or timeout=====================\n");
            ether_etoa((const unsigned char *)&oldnode, oldnode_str);
            res2 = amas_set_peermac((unsigned char *)oldnode_str);
            if (res2 == AMAS_RESULT_SUCCESS){
                OBD_DBG("Set peer's MAC to (%s)\n", oldnode_str);
            }
            res = amas_set_secstatus(SS_SECURITYFAIL);
            if (res == AMAS_RESULT_SUCCESS){
                OBD_DBG("Set security status to SS_SECURITYFAIL(%d)\n", SS_SECURITYFAIL);
            }
            status_g = 4;
        }

#ifndef RTCONFIG_NO_PTHREAD_TIMEDWAIT
        pthread_mutex_unlock(&obdeth_mutex);
#endif
    }
    pthread_exit(NULL);

}


int
obdeth_main(int argc, char *argv[])
{
    FILE *fp;
    sigset_t sigs_to_catch;
    char *val;

    int res = 0;
    pthread_t obdeth_thread;
    struct time_mapping_s time_mapping;

    if (no_need_obdeth() == -1) {
        return 0;
    }

#ifdef RTCONFIG_SW_HW_AUTH
    time_t timestamp = time(NULL);
    char in_buf[48];
    char out_buf[65];
    char hw_out_buf[65];
    char *hw_auth_code = NULL;

    // initial
    memset(in_buf, 0, sizeof(in_buf));
    memset(out_buf, 0, sizeof(out_buf));
    memset(hw_out_buf, 0, sizeof(hw_out_buf));

    // use timestamp + APP_KEY to get auth_code
    snprintf(in_buf, sizeof(in_buf)-1, "%ld|%s", timestamp, APP_KEY);

    hw_auth_code = hw_auth_check(APP_ID, get_auth_code(in_buf, out_buf, sizeof(out_buf)), timestamp, hw_out_buf, sizeof(hw_out_buf));

    // use timestamp + APP_KEY + APP_ID to get auth_code
    snprintf(in_buf, sizeof(in_buf)-1, "%ld|%s|%s", timestamp, APP_KEY, APP_ID);

    // if check fail, return
    if (strcmp(hw_auth_code, get_auth_code(in_buf, out_buf, sizeof(out_buf))))
        return 0;
#else
    dbG("auth check is disabled\n");
    return 0;
#endif

    /* write pid */
    if ((fp = fopen("/var/run/obd_eth.pid", "w")) != NULL)
    {
        fprintf(fp, "%d", getpid());
        fclose(fp);
    }

    time_ref = uptime();

    nvram_set_int("amesh_found_cap", 0);
    nvram_set_int("amesh_led", 0);

    reset_obd_status();
    keystat = SS_OFF;
    /* set the signal handler */
    sigemptyset(&sigs_to_catch);
    sigaddset(&sigs_to_catch, SIGALRM);
    sigaddset(&sigs_to_catch, SIGTERM);
    sigprocmask(SIG_UNBLOCK, &sigs_to_catch, NULL);

    signal(SIGALRM, obd_eth);
    signal(SIGTERM, obd_eth_exit);

    alarm(NORMAL_PERIOD);

    /* Prepare timeout value */
    time_mapping_get(get_productid(), &time_mapping);
    amas_set_timeout(time_mapping.reboot_time, time_mapping.connection_timeout, time_mapping.traffic_timeout);
    dbG("model=%s, reboot_time=%d, connection_timeout=%d, traffic_timeout=%d\n",
        get_productid(), time_mapping.reboot_time, time_mapping.connection_timeout, time_mapping.traffic_timeout);

    attrptr = &attr;
    /* change the default stack size of pthread */
    pthread_attr_init(&attr);
#ifdef PTHREAD_STACK_SIZE
    pthread_attr_setstacksize(&attr, PTHREAD_STACK_SIZE);
#endif

#ifndef RTCONFIG_NO_PTHREAD_TIMEDWAIT
    res = pthread_mutex_init(&obdeth_mutex, NULL);
    if (res != 0) {
        dbG("[obd_msg_exchange] semaphore initialization failed\n");
        return 0;
    }

    res = pthread_cond_init(&obdeth_cond, NULL);
    if (res != 0) {
        dbG("[obd_msg_exchange] detectcap_cond initialization failed\n");
        return 0;
    }
#endif
    res = pthread_create (&obdeth_thread, attrptr, obd_msg_exchange, NULL);
    if (res != 0) {
        dbG("[obd_msg_exchange] thread creation failed");
        return 0;
    }

    /* Most of time it goes to sleep */
    while (1)
    {
        val = nvram_safe_get("obdeth_msglevel");
        if (strcmp(val, ""))
            dbglevel = strtoul(val, NULL, 0);

        if (nvram_get_int("x_Setting") == 1)
            obd_eth_exit(SIGTERM);

        pause();
    }

    if (attrptr != NULL) pthread_attr_destroy(attrptr);
    return 0;
}
