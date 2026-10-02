/*
* Copyright (c) 2016 Qualcomm Atheros, Inc.
* All Rights Reserved.
* Qualcomm Atheros Confidential and Proprietary.
*/

/*
 * QCA specific tool to trigger channel swicth and scan.
 */
#include <sys/types.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>

#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <err.h>

#include "if_athioctl.h"
#include <ext_ioctl_drv_if.h>

#ifndef _LITTLE_ENDIAN
#define _LITTLE_ENDIAN 1234  /* LSB first: i386, vax */
#endif
#ifndef _BIG_ENDIAN
#define _BIG_ENDIAN 4321/* MSB first: 68000, ibm, net */
#endif
#if defined(__LITTLE_ENDIAN)
#define _BYTE_ORDER _LITTLE_ENDIAN
#elif defined(__BIG_ENDIAN)
#define _BYTE_ORDER _BIG_ENDIAN
#else
#error "Please fix asm/byteorder.h"
#endif

#define FALSE   0
#define TRUE    1
#define MAX_INTERFACE_NAME_LEN    20
#define BASE10  10
#define INVALID_ARG  (-1)
/**
* @brief    Prints usage message.
*/
static void print_usage() {
    /* print usage message */
    fprintf(stdout, "Usage: exttool --chanswitch"
            " --interface wifiX"
            " --chan <dest primary channel>"
            " --chwidth <channelwidth>"
            " --numcsa <channel switch announcement count>"
            " --secoffset <1: PLUS, 3: MINUS> "
            " --cfreq2 <secondary 80 centre channel freq,"
            " applicable only for 80+80 MHz>\n");

     fprintf(stdout, "Usage: exttool --scan"
            " --interface wifiX"
            " --mindwell <min dwell time> allowed range [50ms to less than <max dwell>]"
            " --maxdwell <max dwell time> allowed range [greater than min dwell to 10000ms]"
            " --resttime <rest time > allowed ranged [greater than 0]"
            " --scanmode <1: ACTIVE, 2: PASSIVE> "
            " --chcount < Channel count and chan number > [ chancount <1 to 32>]\n");
}


#define MIN_DWELL_TIME        200  /* DEFAULT MIN DWELL Time for scanning 20ms */
#define MAX_DWELL_TIME        300  /* default MAX_DWELL time for scanning 300 ms */
#define CHAN_MIN                1  /* Lowest number channel */
#define CHAN_MAX              165  /* highest number channel */

int validate_scan_param( wifi_scan_custom_request_cmd_t *scan_req)
{
    if ((scan_req->min_dwell_time <= 0)) {
        fprintf(stdout, "Invalid min dwell time \n");
        return INVALID_ARG;
    }

    if ((scan_req->max_dwell_time <= 0)) {
        fprintf(stdout, "Invalid max dwell time \n");
        return INVALID_ARG;
    }

    if (scan_req->rest_time <= 0) {
        fprintf(stdout, "Invalid rest time \n");
        return INVALID_ARG;
    }
    if ((scan_req->chanlist.n_chan <= 0) ||
        (scan_req->chanlist.n_chan > 32)) {
        fprintf(stdout, "Invalid number of channels requested to scan \n");
        return INVALID_ARG;
    }
    return 0;
}

int
main(int argc, char *argv[])
{

    wifi_channel_switch_request_t channel_switch_req;
    wifi_scan_custom_request_cmd_t channel_scan_req;
    struct extended_ioctl_wrapper extended_cmd;
    char ifname[MAX_INTERFACE_NAME_LEN] = {'\0', };
    struct ifreq ifr;
    unsigned int subioctl_cmd = EXTENDED_SUBIOCTL_INVALID;
    int s = -1;
    int option = -1;
    int index = -1;
    int count = 0;
    char *cmd = NULL;

    static struct option exttool_long_options[] = {
        /* List of options supported by this tool */
        {"help",          no_argument,       NULL, 'h'},
        {"interface",     required_argument, NULL, 'i'},
        {"chanswitch",    no_argument,       NULL, 'c'},
        {"scan",          no_argument,       NULL, 's'},
        {"chan",          required_argument, NULL, 'a'},
        {"chwidth",       required_argument, NULL, 'w'},
        {"numcsa",        required_argument, NULL, 'n'},
        {"secoffset",     required_argument, NULL, 'o'},
        {"cfreq2",        required_argument, NULL, 'f'},
        {"mindwell",      required_argument, NULL, 'd'},
        {"maxdwell",      required_argument, NULL, 'x'},
        {"resttime",      required_argument, NULL, 'r'},
        {"scanmode",      required_argument, NULL, 'm'},
        {"chcount",       required_argument, NULL, 'e'},
        {0,               0,                 0,     0},
    };

    if (argc < 6) {
        print_usage();
        return -1;
    }

    memset(&channel_switch_req, 0, sizeof(channel_switch_req));
    memset(&channel_scan_req, 0, sizeof(wifi_scan_custom_request_cmd_t));

    while (TRUE)
    {
        option = getopt_long (argc, argv, "hi:csa:w:n:o:f:d:x:r:m:e",
                exttool_long_options, &index);

        if (option == -1) {
            break;
        }

        switch (option) {
            case 'h': /* Help */
                print_usage();
                break;
            case 'i': /* Interface name */
                strncpy(ifname, optarg, MAX_INTERFACE_NAME_LEN);
                if (strncmp(ifname, "wifi", 4) != 0) {
                    fprintf(stdout, "Invalid interface name %s \n", ifname);
                    print_usage();
                    return -1;
                }
                break;
            case 'c': /* Channel switch request */
                subioctl_cmd = EXTENDED_SUBIOCTL_CHANNEL_SWITCH;
                break;
            case 's': /* Channel scan request */
                subioctl_cmd = EXTENDED_SUBIOCTL_CHANNEL_SCAN;
                break;
            case 'w': /* New channel width */
                channel_switch_req.target_chanwidth = atoi(optarg);
                break;
            case 'a': /* New primary 20 centre channel number */
                channel_switch_req.target_pchannel = atoi(optarg);
                break;
            case 'f': /* New secondary 80 MHz channel centre frequency for 80+80 */
                channel_switch_req.target_cfreq2 = atoi(optarg);
                break;
            case 'o': /* Secondary 20 is above or below primary 20 channel */
                channel_switch_req.sec_chan_offset = atoi(optarg);
                break;
            case 'n': /* Number of channel switch announcement frames */
                channel_switch_req.num_csa = atoi(optarg);
                break;
            case 'd': /* min dwell time  */
                channel_scan_req.min_dwell_time = atoi(optarg);
                break;
            case 'x': /* max dwell time  */
                channel_scan_req.max_dwell_time = atoi(optarg);
                break;
            case 'r': /* rest time  */
                channel_scan_req.rest_time = atoi(optarg);
                break;
            case 'm': /* scan active mode  */
                channel_scan_req.scan_mode = atoi(optarg);
                break;
            case 'e': /* channel to scan  */
                channel_scan_req.chanlist.n_chan = atoi(optarg);
                while (count < channel_scan_req.chanlist.n_chan) {
                    channel_scan_req.chanlist.chan[count++] = atoi(argv[++index]);
                }

                break;
            default:
                print_usage();
                break;
        }
    }

    if (subioctl_cmd == EXTENDED_SUBIOCTL_INVALID) {
        print_usage();
        return -1;
    }

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        err(1, "socket");
    }
    strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
    ifr.ifr_name[sizeof(ifr.ifr_name) - 1] = '\0';

    extended_cmd.cmd = subioctl_cmd;

    if (subioctl_cmd == EXTENDED_SUBIOCTL_CHANNEL_SWITCH) {
        extended_cmd.data = (caddr_t)&channel_switch_req;
        extended_cmd.data_len = sizeof(channel_switch_req);
    } else if (subioctl_cmd == EXTENDED_SUBIOCTL_CHANNEL_SCAN) {
        if (validate_scan_param(&channel_scan_req)) {
            return -1;
        }
        extended_cmd.data = (caddr_t)&channel_scan_req;
        extended_cmd.data_len = sizeof(channel_scan_req);
    }

    ifr.ifr_data = (caddr_t) &extended_cmd;
    if (ioctl(s, SIOCGATHEXTENDED, &ifr) < 0) {
        err(1, "%s", ifr.ifr_name);
        return -1;
    }

    return 0;
}
