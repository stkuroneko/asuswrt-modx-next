/*
**
**  amas-utils-cli.c
**
**
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <shared.h>
#include "amas-utils.h"

unsigned char s2x(unsigned char *c)
{
    unsigned char val = 0;

    switch(c[0]) {
    case '0'...'9':
        val = (unsigned char)atoi(c);
        break;
    case 'a'...'f':
        val = 0xa + (c[0]-'a');
        break;
    case 'A'...'F':
        val = 0xa + (c[0]-'A');
        break;
    default:
        return 0;
    }
    return val;
}


#define STR2HEX2(hex, str, len)  \
    do { \
        int i = 0;\
        char temp1[2]={0};\
        char temp2[2]={0};\
        for(i = 0; i < len; i++) {\
            temp1[0]=str[i*2];\
            temp1[1]='\0';\
            temp2[0]=str[i*2 + 1];\
            temp2[1]='\0';\
            hex[i] = (s2x(temp1) << 4) + s2x(temp2);\
        }\
    } while(0)

typedef int (*execute) (int argc, char *argv[]);
typedef struct command_t {
    char *name;
    struct command_t *next;
    execute exec;
    char *desc;
} command;

int cmd_ver(int argc, char *argv[]);
int cmd_get_cost(int argc, char *argv[]);
int cmd_set_cost(int argc, char *argv[]);
int cmd_get_obstatus(int argc, char *argv[]);
int cmd_set_obstatus(int argc, char *argv[]);
int cmd_get_peermac(int argc, char *argv[]);
int cmd_set_peermac(int argc, char *argv[]);
int cmd_get_secstatus(int argc, char *argv[]);
int cmd_set_secstatus(int argc, char *argv[]);
int cmd_get_sessionkey(int argc, char *argv[]);
int cmd_set_sessionkey(int argc,char *argv[]);
int cmd_get_wifisec(int argc, char *argv[]);
int cmd_set_wifisec(int argc, char *argv[]);
int cmd_get_obdinfo(int argc, char *argv[]);
int cmd_get_group(int argc, char *argv[]);
int cmd_set_group(int argc, char *argv[]);
int cmd_get_rssi_score(int argc, char *argv[]);
int cmd_set_rssi_score(int argc, char *argv[]);
int cmd_get_wifi_lastbyte(int argc, char *argv[]);
int cmd_set_wifi_lastbyte(int argc, char *argv[]);
int cmd_get_dest_ethRole(int argc, char *argv[]);
int cmd_set_ethRole(int argc, char *argv[]);
#if defined(RTCONFIG_PRELINK)
int cmd_get_bundle_key(int argc, char *argv[]);
#endif /* RTCONFIG_PRELINK */
int cmd_set_misc_info(int argc, char *argv[]);
int cmd_get_misc_info(int argc, char *argv[]);

struct command_t cmds_set[] =
{
    {   "cost\0",       0,      cmd_set_cost,       "Set cost configure.\0"             },
    {   "obstatus\0",   0,      cmd_set_obstatus,   "Set ob status configure.\0"        },
    {   "peermac\0",   0,       cmd_set_peermac,   "Set new RE's MAC.\0"               },
    {   "secstatus\0",  0,      cmd_set_secstatus,  "Set security status.\0"            },
    {   "sessionkey\0", 0,      cmd_set_sessionkey, "Set session key.\0"                },
    {   "wifisec\0",    0,      cmd_set_wifisec,    "Set wireless security.\0"          },
    {   "group\0",   0,      cmd_set_group,   "Set group mac.\0"                  },
    {   "rssi_score\0",   0,      cmd_set_rssi_score,   "Set rssi_score.\0"             },
    {   "wifi_lastbyte\0",   0,   cmd_set_wifi_lastbyte,   "Set wifi_lastbyte.\0"          },
    {   "ethRole",        0, cmd_set_ethRole, "Set ethernet port role.\0"},
    {   "misc_info",        0, cmd_set_misc_info, "Set miscellaneous infomation.\0"},

    {   0,              0,      0,                   0                                  },
};

struct command_t cmds_get[] =
{
    {   "cost\0",           0,      cmd_get_cost,           "Get cost configure.\0"       },
    {   "obstatus\0",       0,      cmd_get_obstatus,       "Get ob status configure.\0"  },
    {   "peermac\0",        0,      cmd_get_peermac,       "Get new RE's MAC.\0"         },
    {   "secstatus\0",      0,      cmd_get_secstatus,      "Get security status.\0"      },
    {   "sessionkey\0",     0,      cmd_get_sessionkey,     "Get session key.\0"          },
    {   "wifisec\0",        0,      cmd_get_wifisec,        "Get wireless security.\0"    },
    {   "obdinfo\0",        0,      cmd_get_obdinfo,        "Get ID.\0"                   },
    {   "group\0",       0,      cmd_get_group,       "Get group mac.\0"            },
    {   "rssi_score\0",       0,      cmd_get_rssi_score,       "Get rssi score.\0"       },
    {   "wifi_lastbyte\0",    0,      cmd_get_wifi_lastbyte,    "Get wifi lastbyte.\0"    },
#if defined(RTCONFIG_PRELINK)
    {   "bundlekey\0",        0,      cmd_get_bundle_key,        "Get hash bundle key.\0"                   },
#endif /* RTCONFIG_PRELINK */
    {   "dest_ethRole",        0, cmd_get_dest_ethRole, "Get destination ethernet port role.\0"},
    {   "misc_info",        0,      cmd_get_misc_info,        "Get miscellaneous infomation.\0"                   },
    {   0,                  0,      0,                       0                            },
};

struct command_t cmds_root[] =
{
    {   "ver\0",        0,          cmd_ver,        "amas-utils library version.\0"     },
    {   "get\0",        cmds_get,   0,              "Get amas configure.\0"             },
    {   "set\0",        cmds_set,   0,              "Set amas configure.\0"             },
    {   0,              0,          0,              0                                   },
};

#define END_OF_CMDS_FIELD(__cmds__) ((__cmds__->name == NULL || strlen(__cmds__->name) <= 0))

#define CMDS_SHOW(__cmds__) do {\
    struct command_t* __P__ = (struct command_t *)&__cmds__[0];\
    printf("available commands : \n");\
    if (__cmds__ != NULL)\
    {\
        while (!END_OF_CMDS_FIELD(__P__))\
        {\
            printf("%10s - %s\n", __P__->name, __P__->desc);\
            __P__++;\
        }\
    }\
}while(0)

#define USAGE_SHOW(__message__) do {\
    if (__message__ != NULL && strlen(__message__) > 0)\
    {\
        printf("%10s\n", __message__);\
    }\
}while(0)
//---------------------------------------------------------------------------
command* cmds_find_next(
    command *cmds,
    char *name)
{
    struct command_t *P = cmds, *PP = NULL;

    if (P != NULL && name != NULL && strlen(name) > 0)
    {
        while (!END_OF_CMDS_FIELD(P))
        {
            if (strncmp(name, P->name, strlen(name)) == 0)
            {
                PP = P;
                break;
            }
            P++;
        }
    }

    return PP;
}
//---------------------------------------------------------------------------
int cmd_ver(
    int argc,
    char *argv[])
{
    printf("%s\n", amas_utils_version_text());
    return 1;
}
//---------------------------------------------------------------------------
int cmd_get_cost(
    int argc,
    char *argv[])
{
#if defined(USE_GET_TLV_SUPPORT_MAC)
const char get_cost_usage[] =
{
    "usage : -v -b -c [-d]\n"\
    "\t-v : interface name\n"\
    "\t-b : wireless band mode (0:2.4GHz, 1:5GHz, 2:5GHz-1)\n"\
    "\t-c : wireless 5G capability (2:dual band, 3:tri band)\n"\
    "\t-m : interface mac address (ex.00:12:3e:ff:ff:01)\n"\
    "\t-d : show debug message\n"\
};
#else   // USE_GET_TLV_SUPPORT_MAC
    const char get_cost_usage[] =
    {
        "usage : -v -b -c [-d]\n"\
        "\t-v : interface name\n"\
        "\t-b : wireless band mode (0:2.4GHz, 1:5GHz, 2:5GHz-1)\n"\
        "\t-c : wireless 5G capability (2:dual band, 3:tri band)\n"\
        "\t-d : show debug message\n"\
    };
#endif  // USE_GET_TLV_SUPPORT_MAC

    int i, bandidx = 0, cost = 0, capability5g = 0;
    char *s = NULL;
    AMAS_RESULT res = AMAS_RESULT_FAILED;

#if defined(USE_GET_TLV_SUPPORT_MAC)
    char *m = NULL;
#endif  // USE_GET_TLV_SUPPORT_MAC

    if (argc <= 1)
    {
        printf("%s", get_cost_usage);
        return 0;
    }

    for (i=1; i<argc; i++)
    {
        if (argv[i][0] != '-')
        {
            printf("%s", get_cost_usage);
            return 0;
        }

        switch (argv[i][1])
        {
            case 'v':
                i++;
                s = argv[i];
                break;
            case 'b':
                i++;
                bandidx = atoi(argv[i]);
                break;
            case 'c':
                i++;
                capability5g = atoi(argv[i]);
                break;
#if defined(USE_GET_TLV_SUPPORT_MAC)
            case 'm':
                i++;
                m = argv[i];
                break;
#endif  // USE_GET_TLV_SUPPORT_MAC
            case 'd':
                i++;
                amas_utils_set_debug(1);
                break;
        }
    }

#if defined(USE_GET_TLV_SUPPORT_MAC)
    res = amas_get_cost(s, bandidx, capability5g, m, &cost);
#else   // USE_GET_TLV_SUPPORT_MAC
    res = amas_get_cost(s, bandidx, capability5g, &cost);
#endif  // USE_GET_TLV_SUPPORT_MAC
    printf("cost : %d\n", cost);
    printf("amas-result : %s\n", amas_utils_str_error(res));
    return 1;
}
//---------------------------------------------------------------------------
int cmd_set_cost(
    int argc,
    char *argv[])
{
    const char set_cost_usage[] =
    {
        "usage : -v [-d]\n"\
        "\t-v : cost\n"\
        "\t-d : show debug message\n"\
    };

    int i, cost = 0;
    AMAS_RESULT res = AMAS_RESULT_FAILED;

    if (argc <= 1)
    {
        printf("%s", set_cost_usage);
        return 0;
    }

    for (i=1; i<argc; i++)
    {
        if (argv[i][0] != '-')
        {
            printf("%s", set_cost_usage);
            return 0;
        }

        switch (argv[i][1])
        {
            case 'v':
                i++;
                cost = atoi(argv[i]);
                printf("set cost : %d\n", cost);
                break;
            case 'd':
                i++;
                amas_utils_set_debug(1);
                break;
        }
    }

    res = amas_set_cost(cost);
    printf("amas-result : %s\n", amas_utils_str_error(res));
    return 1;
}
//---------------------------------------------------------------------------

int cmd_get_obstatus(
    int argc,
    char *argv[])
{

const char get_obstatus_usage[] =
{
    "usage : [-h] [-d]\n"\
    "\t-h : show help.\n"\
    "\t-d : show debug message\n"\
};

    int i = 0, k = 0, len = 0;
    char *s = NULL;

    ob_status *P_obstatus = NULL;
    AMAS_RESULT res = AMAS_RESULT_FAILED;

    for (i=1; i<argc; i++)
    {
        if (argv[i][0] != '-')
        {
            printf("%s", get_obstatus_usage);
            return 0;
        }

        switch (argv[i][1])
        {
            case 'h':
                printf("%s", get_obstatus_usage);
                return 0;
            case 'd':
                amas_utils_set_debug(1);
                break;
        }
    }

    res = amas_get_obstatus(&P_obstatus, &len);
    if (len > 0) {
        printf("%s:%d len = %d\n", __FUNCTION__, __LINE__, len);
        for (k = 0; k < len; k ++) {
            printf("%s:%d  Entry[%d] neighbors MAC = %02X:%02X:%02X:%02X:%02X:%02X\n",__FUNCTION__,__LINE__, k, P_obstatus[k].neighmac[0], P_obstatus[k].neighmac[1], P_obstatus[k].neighmac[2], P_obstatus[k].neighmac[3], P_obstatus[k].neighmac[4], P_obstatus[k].neighmac[5]);
            printf("%s:%d  Entry[%d] ob status = %d\n", __FUNCTION__, __LINE__, k, P_obstatus[k].obstatus);
            printf("%s:%d  Entry[%d] ob status Timestamp = %X\n", __FUNCTION__, __LINE__, k, P_obstatus[k].timestamp);
            printf("%s:%d  Entry[%d] ob status Model Name = %s\n", __FUNCTION__, __LINE__, k, P_obstatus[k].modelname);
            printf("%s:%d  Entry[%d] ob status Tcode = %s\n", __FUNCTION__, __LINE__, k, P_obstatus[k].tcode);
            printf("=============================================================\n");
        }
    }
    else {
        printf("Can't get any ob status\n");
    }

    printf("amas-result : %s\n", amas_utils_str_error(res));

    if (P_obstatus != NULL)
        free(P_obstatus);
    return 1;
}
//---------------------------------------------------------------------------
int cmd_set_obstatus(
    int argc,
    char *argv[])
{
    const char set_obstatus_usage[] =
    {
        "usage : -v [-d]\n"\
        "\t-v : ob status [1 (OB_OFF),  2 (OB_Available), 3 (OB_REQ), 4 (OB_LOCKED), 5 (OB_SUCCESS)]\n"\
        "\t-d : show debug message\n"\
    };

    int i, status = 0;
    AMAS_RESULT res = AMAS_RESULT_FAILED;

    if (argc <= 1)
    {
        printf("%s", set_obstatus_usage);
        return 0;
    }

    for (i=1; i<argc; i++)
    {
        if (argv[i][0] != '-')
        {
            printf("%s", set_obstatus_usage);
            return 0;
        }

        switch (argv[i][1])
        {
            case 'v':
                i++;
                status = atoi(argv[i]);
                break;
            case 'd':
                i++;
                amas_utils_set_debug(1);
                break;
        }
    }

    res = amas_set_obstatus(status);

    if(status == 0)
            printf("clear ob status, amas-result : %s\n", amas_utils_str_error(res));
    else
            printf("amas-result : %s\n", amas_utils_str_error(res));
    return 1;
}
//---------------------------------------------------------------------------
int cmd_get_peermac(
    int argc,
    char *argv[])
{

const char get_peermac_usage[] =
{
    "usage : [-h] [-d]\n"\
    "\t-h : show help.\n"\
    "\t-d : show debug message\n"\
};

    int i = 0, k = 0, len = 0;
    char *s = NULL;

    unsigned char newmac[7]={0};
    AMAS_RESULT res = AMAS_RESULT_FAILED;

    for (i=1; i<argc; i++)
    {
        if (argv[i][0] != '-')
        {
            printf("%s", get_peermac_usage);
            return 0;
        }

        switch (argv[i][1])
        {
            case 'h':
                printf("%s", get_peermac_usage);
                return 0;
            case 'd':
                amas_utils_set_debug(1);
                break;
        }
    }

    res = amas_get_peermac(newmac);

    printf("New RE's MAC is %02X:%02X:%02X:%02X:%02X:%02X\n", newmac[0], newmac[1],newmac[2],newmac[3],newmac[4],newmac[5]);

    printf("amas-result : %s\n", amas_utils_str_error(res));

    return 1;
}
//---------------------------------------------------------------------------
int cmd_set_peermac(
    int argc,
    char *argv[])
{
    const char set_peermac_usage[] =
    {
        "usage : -v [-d]\n"\
        "\t-v : mac address\n"\
        "\t-d : show debug message\n"\
    };

    int i;
    unsigned char mac[20]={0};
    AMAS_RESULT res = AMAS_RESULT_FAILED;

    if (argc <= 1)
    {
        printf("%s", set_peermac_usage);
        return 0;
    }

    for (i=1; i<argc; i++)
    {
        if (argv[i][0] != '-')
        {
            printf("%s", set_peermac_usage);
            return 0;
        }

        switch (argv[i][1])
        {
            case 'v':
                i++;
                memcpy(mac, argv[i], sizeof(mac));
                printf("Input MAC = %s\n", mac);
                break;
            case 'd':
                i++;
                amas_utils_set_debug(1);
                break;
        }
    }

    res = amas_set_peermac(mac);

    if(!memcmp(mac, "none", 4) || !memcmp(mac, "NONE", 4))
            printf("clear new RE's mac address, amas-result : %s\n", amas_utils_str_error(res));

    printf("amas-result : %s\n", amas_utils_str_error(res));
    return 1;
}
//---------------------------------------------------------------------------
int cmd_get_secstatus(
    int argc,
    char *argv[])
{

const char get_sectatus_usage[] =
{
    "usage : [-h] [-d]\n"\
    "\t-h : show help.\n"\
    "\t-d : show debug message\n"\
};

    int i = 0, k = 0, len = 0;
    char *s = NULL;

    sec_status *P_secstatus = NULL;
    AMAS_RESULT res = AMAS_RESULT_FAILED;

    for (i=1; i<argc; i++)
    {
        if (argv[i][0] != '-')
        {
            printf("%s", get_sectatus_usage);
            return 0;
        }

        switch (argv[i][1])
        {
            case 'h':
                printf("%s", get_sectatus_usage);
                return 0;
            case 'd':
                amas_utils_set_debug(1);
                break;
        }
    }

    res = amas_get_secstatus(&P_secstatus, &len);
    if (len > 0) {
        printf("%s:%d len = %d\n", __FUNCTION__, __LINE__, len);
        for (k = 0; k < len; k ++) {
            printf("%s:%d  Entry[%d] neighbors MAC = %02X:%02X:%02X:%02X:%02X:%02X\n",__FUNCTION__,__LINE__, k, P_secstatus[k].neighmac[0], P_secstatus[k].neighmac[1], P_secstatus[k].neighmac[2], P_secstatus[k].neighmac[3], P_secstatus[k].neighmac[4], P_secstatus[k].neighmac[5]);
            printf("%s:%d  Entry[%d] peer's MAC = %02X:%02X:%02X:%02X:%02X:%02X\n",__FUNCTION__,__LINE__, k, P_secstatus[k].peermac[0], P_secstatus[k].peermac[1], P_secstatus[k].peermac[2], P_secstatus[k].peermac[3], P_secstatus[k].peermac[4], P_secstatus[k].peermac[5]);
            printf("%s:%d  Entry[%d] sec status = %d\n", __FUNCTION__, __LINE__, k, P_secstatus[k].secstatus);
            printf("=============================================================\n");
        }
    }
    else {
        printf("Can't get any status for security key.\n");
    }

    printf("amas-result : %s\n", amas_utils_str_error(res));

    if (P_secstatus != NULL)
        free(P_secstatus);
    return 1;
}
//---------------------------------------------------------------------------
int cmd_set_secstatus(
    int argc,
    char *argv[])
{
    const char set_secstatus_usage[] =
    {
        "usage : -v [-d]\n"\
        "\t-v : ob status [1 (SS_KEY),  2 (SS_KEYACK), 3 (SS_SECURITY), 4 (SS_SUCCESS)]\n"\
        "\t-d : show debug message\n"\
    };

    int i, status = 0;
    AMAS_RESULT res = AMAS_RESULT_FAILED;

    if (argc <= 1)
    {
        printf("%s", set_secstatus_usage);
        return 0;
    }

    for (i=1; i<argc; i++)
    {
        if (argv[i][0] != '-')
        {
            printf("%s", set_secstatus_usage);
            return 0;
        }

        switch (argv[i][1])
        {
            case 'v':
                i++;
                status = atoi(argv[i]);
                break;
            case 'd':
                i++;
                amas_utils_set_debug(1);
                break;
        }
    }

    res = amas_set_secstatus(status);

    if(status == 0)
            printf("clear security status, amas-result : %s\n", amas_utils_str_error(res));
    else
            printf("amas-result : %s\n", amas_utils_str_error(res));
    return 1;
}
//---------------------------------------------------------------------------
int cmd_get_sessionkey(
    int argc,
    char *argv[])
{

const char get_sessionkey_usage[] =
{
    "usage : [-h] [-d]\n"\
    "\t-h : show help.\n"\
    "\t-d : show debug message\n"\
};

    int i = 0, k = 0, q=0, len = 0;
    char *s = NULL;
    data_exchange *P_keyexchange = NULL;
    AMAS_RESULT res = AMAS_RESULT_FAILED;

    //unsigned char sessionkey[SESSION_KEY_LENGTH+1]={0};

    for (i=1; i<argc; i++)
    {
        if (argv[i][0] != '-')
        {
            printf("%s", get_sessionkey_usage);
            return 0;
        }

        switch (argv[i][1])
        {
            case 'h':
                printf("%s", get_sessionkey_usage);
                return 0;
            case 'd':
                amas_utils_set_debug(1);
                break;
        }
    }

    //res = amas_get_sessionkey(sessionkey, &len);
    res = amas_get_sessionkey(&P_keyexchange, &len);

    for (k = 0; k < len; k ++) {
        printf("%s:%d  Entry[%d] neighbors MAC = %02X:%02X:%02X:%02X:%02X:%02X\n",__FUNCTION__,__LINE__, k, P_keyexchange[k].neighmac[0], P_keyexchange[k].neighmac[1], P_keyexchange[k].neighmac[2], P_keyexchange[k].neighmac[3], P_keyexchange[k].neighmac[4], P_keyexchange[k].neighmac[5]);
        printf("%s:%d  Entry[%d] peer's MAC = %02X:%02X:%02X:%02X:%02X:%02X\n",__FUNCTION__,__LINE__, k, P_keyexchange[k].peermac[0], P_keyexchange[k].peermac[1], P_keyexchange[k].peermac[2], P_keyexchange[k].peermac[3], P_keyexchange[k].peermac[4], P_keyexchange[k].peermac[5]);
        printf("%s:%d  Entry[%d] SessionKey =", __FUNCTION__,__LINE__, k);
        for(q = 0; q <  P_keyexchange[k].datalen ; q++)
            printf("%02X ", P_keyexchange[k].data[q]);
        printf("\n");
        printf("%s:%d  Entry[%d] interface =%s\n", __FUNCTION__,__LINE__, k, P_keyexchange[k].ifname);
        printf("%s:%d  Entry[%d] key len =%d", __FUNCTION__,__LINE__,  k, P_keyexchange[k].datalen);
    }


    printf("amas-result : %s\n", amas_utils_str_error(res));

    if(P_keyexchange != NULL)
        free(P_keyexchange);

    return 1;
}
//---------------------------------------------------------------------------
int cmd_set_sessionkey(
    int argc,
    char *argv[])
{
    const char set_sessionkey_usage[] =
    {
        "usage : -v [-d]\n"\
        "\t-v : session key\n"\
        "\t-d : show debug message\n"\
    };

    int i;
    unsigned char sessionkey[MAX_VERSION_TEXT_LENGTH*2 + 1]={0};
    AMAS_RESULT res = AMAS_RESULT_FAILED;

    if (argc <= 1)
    {
        printf("%s", set_sessionkey_usage);
        return 0;
    }

    for (i=1; i<argc; i++)
    {
        if (argv[i][0] != '-')
        {
            printf("%s", set_sessionkey_usage);
            return 0;
        }

        switch (argv[i][1])
        {
            case 'v':
                i++;
                if(strlen(argv[i]) < (MAX_VERSION_TEXT_LENGTH * 2)) {
                    memcpy(sessionkey, argv[i], strlen(argv[i]));
                    printf("Input session key = %s\n", sessionkey);
                }
                break;
            case 'd':
                i++;
                amas_utils_set_debug(1);
                break;
        }
    }

    res = amas_set_sessionkey(sessionkey);

    if(!memcmp(sessionkey, "none", 4) || !memcmp(sessionkey, "NONE", 4))
            printf("clear session key, amas-result : %s\n", amas_utils_str_error(res));
    else
            printf("amas-result : %s\n", amas_utils_str_error(res));
    return 1;
}
//---------------------------------------------------------------------------
int cmd_get_wifisec(
    int argc,
    char *argv[])
{

const char get_wifisec_usage[] =
{
    "usage : [-h] [-d]\n"\
    "\t-t : type (ssid, auth, crypto, key)\n"
    "\t-h : show help.\n"\
    "\t-d : show debug message\n"\
};

    int i = 0, k = 0, len = 0;
    char *s = NULL;
    char type[8] = {0};

    unsigned char value[MAX_VERSION_TEXT_LENGTH]={0};
    AMAS_RESULT res = AMAS_RESULT_FAILED;

    for (i=1; i<argc; i++)
    {
        if (argv[i][0] != '-')
        {
            printf("%s", get_wifisec_usage);
            return 0;
        }

        switch (argv[i][1])
        {
            case 't':
                i++;
                memcpy(type,  argv[i], sizeof(type) - 1);
                break;
            case 'h':
                printf("%s", get_wifisec_usage);
                return 0;
            case 'd':
                amas_utils_set_debug(1);
                break;
        }
    }

    res = amas_get_wifisec(type, value, &len);

    printf("type(%s) value =", type);
    for (i = 0; i < len; i ++) {
        printf("%02X ", value[i]);
    }
    printf("\n");

    printf("amas-result : %s\n", amas_utils_str_error(res));

    return 1;
}
//---------------------------------------------------------------------------
int cmd_set_wifisec(
    int argc,
    char *argv[])
{
    const char set_wifisec_usage[] =
    {
        "usage : -v [-d]\n"\
        "\t-t : type (ssid, auth, crypto, key)\n"
        "\t-v : hash value\n"\
        "\t-d : show debug message\n"\
    };

    int i = 0;
    char type[8]={0};
    unsigned char value[MAX_VERSION_TEXT_LENGTH*2 + 1]={0};
    AMAS_RESULT res = AMAS_RESULT_FAILED;

    if (argc <= 1)
    {
        printf("%s", set_wifisec_usage);
        return 0;
    }

    for (i=1; i<argc; i++)
    {
        if (argv[i][0] != '-')
        {
            printf("%s", set_wifisec_usage);
            return 0;
        }

        switch (argv[i][1])
        {
            case 't':
                i++;
                memcpy(type,  argv[i], sizeof(type) - 1);
                break;
            case 'v':
                i++;
                if(strlen(argv[i]) < (MAX_VERSION_TEXT_LENGTH * 2)) {
                    memcpy(value, argv[i], strlen(argv[i]));
                    printf("Input value = %s\n", value);
                }
                else{
                    printf("Input value is invalid.");
                    return 0;
                }
                break;
            case 'd':
                i++;
                amas_utils_set_debug(1);
                break;
        }
    }

    res = amas_set_wifisec(type, value);

    if(!memcmp(value, "none", 4) || !memcmp(value, "NONE", 4))
            printf("clear %s, amas-result : %s\n", type, amas_utils_str_error(res));
    else
            printf("amas-result : %s\n", amas_utils_str_error(res));
    return 1;
}
//---------------------------------------------------------------------------
int cmd_get_obdinfo(
    int argc,
    char *argv[])
{

const char get_id_usage[] =
{
    "usage : [-h] [-d]\n"\
    "\t-h : show help.\n"\
    "\t-d : show debug message\n"\
};

    int i = 0, k = 0, q=0, len = 0;
    char *s = NULL;
    id_info *P_idinfo = NULL;
    AMAS_RESULT res = AMAS_RESULT_FAILED;


    for (i=1; i<argc; i++)
    {
        if (argv[i][0] != '-')
        {
            printf("%s", get_id_usage);
            return 0;
        }

        switch (argv[i][1])
        {
            case 'h':
                printf("%s", get_id_usage);
                return 0;
            case 'd':
                amas_utils_set_debug(1);
                break;
        }
    }

    res = amas_get_obdinfo(&P_idinfo, &len);

    for (k = 0; k < len; k ++) {
        printf("%s:%d  Entry[%d] neighbors MAC = %02X:%02X:%02X:%02X:%02X:%02X\n",__FUNCTION__,__LINE__, k, P_idinfo[k].neighmac[0], P_idinfo[k].neighmac[1], P_idinfo[k].neighmac[2], P_idinfo[k].neighmac[3], P_idinfo[k].neighmac[4], P_idinfo[k].neighmac[5]);
        printf("%s:%d  Entry[%d] id len =%d\n", __FUNCTION__,__LINE__,  P_idinfo[k].idlen);
        printf("%s:%d  Entry[%d] id =", __FUNCTION__,__LINE__, k);
        for(q = 0; q <  P_idinfo[k].idlen; q++)
            printf("%02X ", P_idinfo[k].id[q]);
        printf("\n");
        printf("%s:%d  Entry[%d] peermac = %02X:%02X:%02X:%02X:%02X:%02X\n", __FUNCTION__,__LINE__,  k, P_idinfo[k].newremac[0], P_idinfo[k].newremac[1], P_idinfo[k].newremac[2], P_idinfo[k].newremac[3], P_idinfo[k].newremac[4], P_idinfo[k].newremac[5]);
        printf("%s:%d  Entry[%d] ob status = %d\n", __FUNCTION__, __LINE__,k, P_idinfo[k].obstatus);
        printf("%s:%d  Entry[%d] ob status Timestamp = %X\n", __FUNCTION__, __LINE__,k, P_idinfo[k].timestamp);
        printf("%s:%d  Entry[%d] ob status Model Name = %s\n", __FUNCTION__, __LINE__,k, P_idinfo[k].modelname);
        printf("%s:%d  Entry[%d] ob status Tcode = %s\n", __FUNCTION__, __LINE__,k, P_idinfo[k].tcode);
        printf("\n");
    }


    printf("amas-result : %s\n", amas_utils_str_error(res));

    if(P_idinfo != NULL)
        free(P_idinfo);

    return 1;
}

//---------------------------------------------------------------------------
int cmd_get_group(
    int argc,
    char *argv[])
{

const char get_group_usage[] =
{
    "usage : [-h] [-d]\n"\
    "\t-h : show help.\n"\
    "\t-d : show debug message\n"\
};

    int i = 0, k = 0, len = 0;
    char *s = NULL;

    unsigned char group[MAX_VERSION_TEXT_LENGTH*2 + 1]={0};
    AMAS_RESULT res = AMAS_RESULT_FAILED;

    for (i=1; i<argc; i++)
    {
        if (argv[i][0] != '-')
        {
            printf("%s", get_group_usage);
            return 0;
        }

        switch (argv[i][1])
        {
            case 'h':
                printf("%s", get_group_usage);
                return 0;
            case 'd':
                amas_utils_set_debug(1);
                break;
        }
    }

    res = amas_get_group(group, &len);

    printf("Group is ");
    for (i = 0; i< len; i++)
        printf("%02X ", group[i]);
    printf("\n");
    printf("amas-result : %s\n", amas_utils_str_error(res));

    return 1;
}
//---------------------------------------------------------------------------
int cmd_set_group(
    int argc,
    char *argv[])
{
  const char set_group_usage[] =
    {
        "usage : -v [-d]\n"\
        "\t-v : group key\n"\
        "\t-d : show debug message\n"\
    };

    int i;
    unsigned char group[MAX_VERSION_TEXT_LENGTH*2 + 1]={0};
    AMAS_RESULT res = AMAS_RESULT_FAILED;

    if (argc <= 1)
    {
        printf("%s", set_group_usage);
        return 0;
    }

    for (i=1; i<argc; i++)
    {
        if (argv[i][0] != '-')
        {
            printf("%s", set_group_usage);
            return 0;
        }

        switch (argv[i][1])
        {
            case 'v':
                i++;
                if(strlen(argv[i]) < (MAX_VERSION_TEXT_LENGTH * 2)) {
                    memcpy(group, argv[i], strlen(argv[i]));
                    printf("Input group = %s\n", group);
                }
                break;
            case 'd':
                i++;
                amas_utils_set_debug(1);
                break;
        }
    }

    res = amas_set_group(group);

    if(!memcmp(group, "none", 4) || !memcmp(group, "NONE", 4))
            printf("clear group value, amas-result : %s\n", amas_utils_str_error(res));
    else
            printf("amas-result : %s\n", amas_utils_str_error(res));
    return 1;
}

/**
 * @brief Set ethernet port role.
 *
 * @param argc
 * @param argv
 * @return int processing result.
 */
int cmd_set_ethRole(
    int argc,
    char *argv[])
{
const char set_ethRole[] =
{
    "usage : [-i] [-d]\n"\
    "\t-s : Ethernet port role. (eth0:1>eth1:2)\n"\
    "\t-d : show debug message\n"\
};

    int i;
    char buf[64] = {};
    AMAS_RESULT res = AMAS_RESULT_FAILED;

    if (argc <= 1)
    {
        printf("%s", set_ethRole);
        return 0;
    }

    for (i=1; i<argc; i++)
    {
        if (argv[i][0] != '-')
        {
            printf("%s", set_ethRole);
            return 0;
        }

        switch (argv[i][1])
        {
            case 's':
                i++;
                strcpy(buf, argv[i]);
                break;
            case 'd':
                i++;
                amas_utils_set_debug(1);
                break;
        }
    }

    res = amas_set_eth_role(buf);

    printf("amas-result : %s\n", amas_utils_str_error(res));
    return 1;
}

/**
 * @brief Get destination ethernet port role.
 *
 * @param argc
 * @param argv
 * @return int processing result.
 */
int cmd_get_dest_ethRole(
    int argc,
    char *argv[])
{

const char get_dest_ethRole[] =
{
    "usage : [-i] [-d]\n"\
    "\t-i : interface name.\n"\
    "\t-d : show debug message\n"\
};

    int i;
    char ifname[32] = {};
    AMAS_RESULT res = AMAS_RESULT_FAILED;
    int ethRole = 0;

    if (argc <= 1)
    {
        printf("%s", get_dest_ethRole);
        return 0;
    }

    for (i=1; i<argc; i++)
    {
        if (argv[i][0] != '-')
        {
            printf("%s", get_dest_ethRole);
            return 0;
        }

        switch (argv[i][1])
        {
            case 'i':
                i++;
                strcpy(ifname, argv[i]);
                printf("ifname: %s\n", ifname);
                break;
            case 'd':
                i++;
                amas_utils_set_debug(1);
                break;
        }
    }

    res = amas_get_dest_eth_role(ifname, &ethRole);

    printf("Ifname: %s, ethRole: %d\n", ifname, ethRole);
    printf("amas-result : %s\n", amas_utils_str_error(res));
    return 1;
}

#if defined(RTCONFIG_PRELINK)
//---------------------------------------------------------------------------
int cmd_get_bundle_key(
    int argc,
    char *argv[])
{

const char get_bundle_key_usage[] =
{
    "usage : [-h] [-d]\n"\
    "\t-h : show help.\n"\
    "\t-d : show debug message\n"\
};

    int i = 0, k = 0, q=0, len = 0;
    char *s = NULL;
    bundle_key *P_bundlekey = NULL;
    AMAS_RESULT res = AMAS_RESULT_FAILED;


    for (i=1; i<argc; i++)
    {
        if (argv[i][0] != '-')
        {
            printf("%s", get_bundle_key_usage);
            return 0;
        }

        switch (argv[i][1])
        {
            case 'h':
                printf("%s", get_bundle_key_usage);
                return 0;
            case 'd':
                amas_utils_set_debug(1);
                break;
        }
    }

    res = amas_get_bundle_key(&P_bundlekey, &len);

    for (k = 0; k < len; k ++) {
        printf("%s:%d  Entry[%d] bundle key len =%d\n", __FUNCTION__,__LINE__,k, P_bundlekey[k].bundlekeylen);
        printf("%s:%d  Entry[%d] bundle key =", __FUNCTION__,__LINE__, k);
        for(q = 0; q <  P_bundlekey[k].bundlekeylen; q++)
            printf("%02X ", P_bundlekey[k].bundlekey[q]);
        printf("\n");
    }

    printf("amas-result : %s\n", amas_utils_str_error(res));

    if(P_bundlekey != NULL)
        free(P_bundlekey);

    return 1;
}
#endif /* RTCONFIG_PRELINK */
//---------------------------------------------------------------------------
int cmd_get_rssi_score(
    int argc,
    char *argv[])
{
const char get_rssi_score_usage[] =
{
    "usage : -v -b -c [-d]\n"\
    "\t-v : interface name\n"\
    "\t-b : wireless band mode (0:2.4GHz, 1:5GHz, 2:5GHz-1)\n"\
    "\t-c : wireless 5G capability (2:dual band, 3:tri band)\n"\
    "\t-m : interface mac address (ex.00:12:3e:ff:ff:01)\n"\
    "\t-d : show debug message\n"\
};

    int i, bandidx = 0, rssi_score = 0, capability5g = 0;
    char *s = NULL;
    AMAS_RESULT res = AMAS_RESULT_FAILED;
    char *m = NULL;

    if (argc <= 1)
    {
        printf("%s", get_rssi_score_usage);
        return 0;
    }

    for (i=1; i<argc; i++)
    {
        if (argv[i][0] != '-')
        {
            printf("%s", get_rssi_score_usage);
            return 0;
        }

        switch (argv[i][1])
        {
            case 'v':
                i++;
                s = argv[i];
                break;
            case 'b':
                i++;
                bandidx = atoi(argv[i]);
                break;
            case 'c':
                i++;
                capability5g = atoi(argv[i]);
                break;
            case 'm':
                i++;
                m = argv[i];
                break;
            case 'd':
                i++;
                amas_utils_set_debug(1);
                break;
        }
    }

    res = amas_get_rssi_score(s, bandidx, capability5g, m, &rssi_score);

    printf("rssi score : %d\n", rssi_score);
    printf("amas-result : %s\n", amas_utils_str_error(res));
    return 1;
}
//---------------------------------------------------------------------------
int cmd_set_rssi_score(
    int argc,
    char *argv[])
{
    const char set_rssi_score_usage[] =
    {
        "usage : -v [-d]\n"\
        "\t-v : rssi score\n"\
        "\t-d : show debug message\n"\
    };

    int i, rssi_score = 0;
    AMAS_RESULT res = AMAS_RESULT_FAILED;

    if (argc <= 1)
    {
        printf("%s", set_rssi_score_usage);
        return 0;
    }

    for (i=1; i<argc; i++)
    {
        if (argv[i][0] != '-')
        {
            printf("%s", set_rssi_score_usage);
            return 0;
        }

        switch (argv[i][1])
        {
            case 'v':
                i++;
                rssi_score = atoi(argv[i]);
                printf("set rssi score : %d\n", rssi_score);
                break;
            case 'd':
                i++;
                amas_utils_set_debug(1);
                break;
        }
    }

    res = amas_set_rssi_score(rssi_score);
    printf("amas-result : %s\n", amas_utils_str_error(res));
    return 1;
}

int cmd_set_wifi_lastbyte(
    int argc,
    char *argv[])
{
    const char set_wifi_lastbyte_usage[] =
    {
        "usage : -v [-d]\n"\
        "\t-v : wifi lastbyte\n"\
        "\t-d : show debug message\n"\
    };

    int i;
    AMAS_RESULT res = AMAS_RESULT_FAILED;
    unsigned char input_wifi_lastbyte[18] = {0};

    if (argc <= 1)
    {
        printf("%s", set_wifi_lastbyte_usage);
        return 0;
    }

    for (i=1; i<argc; i++)
    {
        if (argv[i][0] != '-')
        {
            printf("%s", set_wifi_lastbyte_usage);
            return 0;
        }

        switch (argv[i][1])
        {
            case 'v':
                i++;
                memcpy(input_wifi_lastbyte, argv[i], sizeof(input_wifi_lastbyte));
                printf("Input wifi lastbyte = %s\n", input_wifi_lastbyte);
                break;
            case 'd':
                i++;
                amas_utils_set_debug(1);
                break;
        }
    }

    res = amas_set_wifi_lastbyte(input_wifi_lastbyte);
    printf("amas-result : %s\n", amas_utils_str_error(res));
    return 1;
}


int cmd_get_wifi_lastbyte(
    int argc,
    char *argv[])
{
const char get_wifi_lastbyte_usage[] =
{
    "usage : -v -b -c [-d]\n"\
    "\t-v : interface name\n"\
    "\t-b : wireless band mode (0:2.4GHz, 1:5GHz, 2:5GHz-1)\n"\
    "\t-c : wireless 5G capability (2:dual band, 3:tri band)\n"\
    "\t-m : interface mac address (ex.00:12:3e:ff:ff:01)\n"\
    "\t-d : show debug message\n"\
};

    int i, bandidx = 0, capability5g = 0;
    char *s = NULL;
    AMAS_RESULT res = AMAS_RESULT_FAILED;
    char *m = NULL;
    int lastbyte = 0;
    unsigned char wifi_lastbyte_str[17]={0};
    unsigned char wifi_lastbyte_result[17]={0};

    if (argc <= 1)
    {
        printf("%s", get_wifi_lastbyte_usage);
        return 0;
    }

    for (i=1; i<argc; i++)
    {
        if (argv[i][0] != '-')
        {
            printf("%s", get_wifi_lastbyte_usage);
            return 0;
        }

        switch (argv[i][1])
        {
            case 'v':
                i++;
                s = argv[i];
                break;
            case 'b':
                i++;
                bandidx = atoi(argv[i]);
                break;
            case 'c':
                i++;
                capability5g = atoi(argv[i]);
                break;
            case 'm':
                i++;
                m = argv[i];
                break;
            case 'd':
                i++;
                amas_utils_set_debug(1);
                break;
        }
    }

    res = amas_get_wifi_lastbyte(s, bandidx, capability5g, m, wifi_lastbyte_str, sizeof(wifi_lastbyte_str));

    for (i = 0; i < strlen(wifi_lastbyte_str);i++) {
          printf("wifi_lastbyte_str[%d] = %02X\n", i, wifi_lastbyte_str[i]);
    }

    printf("wifi_lastbyte_str = %s\n", wifi_lastbyte_str);


    STR2HEX2(wifi_lastbyte_result, wifi_lastbyte_str, strlen(wifi_lastbyte_str));

    for (i = 0; i < strlen((char*)wifi_lastbyte_str);i++) {
          printf("wifi_lastbyte_result[%d] = %02X\n", i, wifi_lastbyte_result[i]);
    }

    printf("amas-result : %s\n", amas_utils_str_error(res));
    return 1;
}

//---------------------------------------------------------------------------
int cmd_set_misc_info(
    int argc,
    char *argv[])
{
    const char set_misc_info_usage[] =
    {
        "usage : -v [-d]\n"\
        "\t-i : index\n"\
        "\t-v : value"\
        "\t-d : show debug message\n"\
    };

    int i, index = 0;
    char *value;
    AMAS_RESULT res = AMAS_RESULT_FAILED;

    if (argc <= 1)
    {
        printf("%s", set_misc_info_usage);
        return 0;
    }

    for (i=1; i<argc; i++)
    {
        if (argv[i][0] != '-')
        {
            printf("%s", set_misc_info_usage);
            return 0;
        }

        switch (argv[i][1])
        {
            case 'i':
                i++;
                index = atoi(argv[i]);
                break;
            case 'v':
                i++;
                value = argv[i];
                break;
            case 'd':
                i++;
                amas_utils_set_debug(1);
                break;
        }
    }

    res = amas_set_misc_info(index, value);

    printf("amas-result : %s\n", amas_utils_str_error(res));
    return 1;
}
//---------------------------------------------------------------------------
int cmd_get_misc_info(
    int argc,
    char *argv[])
{

const char get_misc_info_usage[] =
{
    "usage : [-h] [-d]\n"\
    "\t-h : show help.\n"\
    "\t-d : show debug message\n"\
};

    int i = 0, len = 0;
    unsigned char misc_info[128];
    AMAS_RESULT res = AMAS_RESULT_FAILED;

    for (i=1; i<argc; i++)
    {
        if (argv[i][0] != '-')
        {
            printf("%s", get_misc_info_usage);
            return 0;
        }

        switch (argv[i][1])
        {
            case 'h':
                printf("%s", get_misc_info_usage);
                return 0;
            case 'd':
                amas_utils_set_debug(1);
                break;
        }
    }

    res = amas_get_misc_info((unsigned char *)&misc_info, &len);

    printf("misc info len = %d\n", len);
    if (len > 0) {
        for (i = 0; i < len; i++)
            printf("%02X ", misc_info[i]);
        printf("\n");
    }

    printf("amas-result : %s\n", amas_utils_str_error(res));

    return 1;
}

int
main(int argc, char *argv[])
{
    int i;
    struct command_t *P = (struct command_t *)&cmds_root[0], *next = NULL;
    char *s = NULL, flag = 0;

    if(nvram_get_int("amascli_dbg") == 0) {
        printf("amas-utils-cli: command not found\n");
        return 0;
    }


    if (argc <= 1)
    {
        CMDS_SHOW(P);
        return 0;
    }

    for (i=1; i<argc; i++)
    {
        next = cmds_find_next(P, argv[i]);
        if (next == NULL)
        {
            break;
        }

        if (next->next != NULL)
        {
            P = next->next;
            continue;
        }
        else if (next->exec != NULL)
        {
            next->exec(argc-i, &argv[i]);
            flag = 1;
            break;
        }
        else
        {
            break;
        }
    }

    if (flag == 0)
    {
        CMDS_SHOW(P);
    }
    return 0;
}
