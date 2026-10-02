/*****************************************************************************

  Copyright (c) 2015
  Lantiq Beteiligungs-GmbH & Co. KG
  Lilienthalstrasse 15, 85579 Neubiberg, Germany 

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

 ******************************************************************************/

/***************************************************************************** *
 *     File Name  : scapi_ifconfig_stats.c                                     *
 *     Project    : UGW                                                        *
 *     Description: APIs for stats of an interface                             *
 *                                                                             *
 ******************************************************************************/


#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <ltq_api_include.h>


#define PATH_PROCNET_DEV               "/proc/net/dev"

static char* skip_whitespace(char *str)
{
    while (*str == ' ' || (unsigned char)(*str - 9) <= (13 - 9))
        str++;

    return (char *) str;
} 

/* 
** =============================================================================
**   Function Name    :get_name
**
**   Description      :
**
**   Parameters       :name(IN) p(OUT)
**
**   Return Value     :Success -> returns the pointer of interface name
**                      Failure -> returns blank
** 
**   Notes            :
**
** ============================================================================
*/

static char* get_name(char *name, char *p)
{
    /* Extract <name> from nul-terminated p where p matches
     * <name>: after leading whitespace.
     * If match is not made, set name empty and return unchanged p
     */
    char *nameend;
    char *namestart = skip_whitespace(p);

    nameend = namestart;
    while (*nameend && *nameend != ':' && !isspace(*nameend))
        nameend++;
    if (*nameend == ':') {
        if ((nameend - namestart) < IFNAMSIZ) {
            memcpy(name, namestart, nameend - namestart);
            name[nameend - namestart] = '\0';
            p = nameend;
        } else {
            /* interface name too large */
            name[0] = '\0';
        }
    } else {
        /* trailing ':' not found - return empty */
        name[0] = '\0';
    }
    return p + 1;
}


#if INT_MAX == LONG_MAX
static const char *const ss_fmt[] = {
    "%n%llu%u%u%u%u%n%n%n%llu%u%u%u%u%u",
    "%llu%llu%u%u%u%u%n%n%llu%llu%u%u%u%u%u",
    "%llu%llu%u%u%u%u%u%u%llu%llu%u%u%u%u%u%u"
};
#else
static const char *const ss_fmt[] = {
    "%n%llu%lu%lu%lu%lu%n%n%n%llu%lu%lu%lu%lu%lu",
    "%llu%llu%lu%lu%lu%lu%n%n%llu%llu%lu%lu%lu%lu%lu",
    "%llu%llu%lu%lu%lu%lu%lu%lu%llu%llu%lu%lu%lu%lu%lu%lu"
};

#endif


/* 
** =============================================================================
**   Function Name    :get_dev_fields
**
**   Description      :
**
**   Parameters       :bp(IN), ife(OUT), procnetdev_vsn(IN)
**
**   Return Value     :returns filled structure with counter value
**                      
** 
**   Notes            :
**
** ============================================================================
*/

static void get_dev_fields(char *bp, INTERFACE *ife, int procnetdev_vsn)
{

    sscanf(bp, ss_fmt[procnetdev_vsn],
           &ife->rx_bytes_counter,
           &ife->rx_pkt_counter,
           &ife->rx_errors_counter,
           &ife->rx_dropped_counter,
           &ife->rx_fifo_errors_counter,
           &ife->rx_frame_errors_counter,
           &ife->rx_compressed_counter,
           &ife->rx_multicast_counter,
           &ife->tx_bytes_counter,
           &ife->tx_pkt_counter,
           &ife->tx_errors_counter,
           &ife->tx_dropped_counter,
           &ife->tx_fifo_errors_counter,
           &ife->collisions_counter,
           &ife->tx_carrier_errors_counter,
           &ife->tx_compressed_counter);
}

/* 
** =============================================================================
**   Function Name    :if_readlist_proc
**
**   Description      :This function is used to read /proc/net/dev entries
		       and to fetech given interface counter values
**
**   Parameters       :target(IN) ife(OUT)
**
**   Return Value     :Success -> returns structure with counter values
**                     Failure -> errno value
** 
**   Notes            :
**
** ============================================================================
*/

static int if_readlist_proc(char *target, INTERFACE *ife)
{
    FILE *fh;
    char buf[1024] = { 0 };
    int err = 0;

    fh = fopen(PATH_PROCNET_DEV, "r");
    if (!fh) {
	err = -1;
        goto error;
    }
    /* */
    fgets(buf, sizeof(buf) - 1, fh); /* To escape 1st two lines of /proc/net/dev entries*/
    fgets(buf, sizeof(buf) - 1, fh);

    while (fgets(buf, sizeof(buf) - 1, fh)) 
    {
    	char *s = NULL, name[128] = { 0 };
        
	s = get_name(name, buf);
        if (target && !strcmp(target, name)) 
	{
        	get_dev_fields(s, ife, 2);
		break;
	}

	memset(buf, 0x0, sizeof(buf));
    }
    if(fh)
	fclose(fh);

error:
    return err;
}

/* 
** =============================================================================
**   Function Name    :scapi_ifconfig_stats
**
**   Description      :
                       
**
**   Parameters       :name(IN) if_list(OUT)
**
**   Return Value     :Success -> returns structure with counter values
**                     Failure -> Different -ve values
** 
**   Notes            :
**
** ============================================================================
*/

int scapi_ifconfigStats(char *name, INTERFACE *if_list)
{
    int iRet = 0;

    iRet = if_readlist_proc(name, if_list);
    return iRet;
}

