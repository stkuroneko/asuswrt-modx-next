 /*
 * Copyright 2017, ASUSTeK Inc.
 * All Rights Reserved.
 * 
 * THIS SOFTWARE IS OFFERED "AS IS", AND ASUS GRANTS NO WARRANTIES OF ANY
 * KIND, EXPRESS OR IMPLIED, BY STATUTE, COMMUNICATION OR OTHERWISE. BROADCOM
 * SPECIFICALLY DISCLAIMS ANY IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A SPECIFIC PURPOSE OR NONINFRINGEMENT CONCERNING THIS SOFTWARE.
 *
 */

/*
	wlc_nt is the filter between "eventd from driver" and "nt_center", it decides to send which event or not to send event to nt_center.
	wireless driver <---udp socket (or ioctl)---> eventd from driver <---unix socket---> wlc_nt <---unix socket---> nt_center

	eventd from driver in different platform
	BRCM : wlceventd
	MTK  : iwevent
	QCA  : qca-wifi-assoc-eventd
*/

#include "wlc_nt.h"

#ifdef RTCONFIG_SW_HW_AUTH
#include <auth_common.h>
#define APP_ID    "25124577"
#define APP_KEY   "afa125g46h4yefse03t"
#endif

#define MAX_SPAM_LIST 256

/* global variables */
struct list *wlc_tstamp_list = NULL;
unsigned int list_count = 0;

static void handlesignal(int sig)
{
	if (sig == SIGTERM) {
		MyDBG("receive SIGTERM\n");
		remove(WLCNT_PID_PATH);

		/* free whole record when wlc_nt terminates */
		if (wlc_tstamp_list)
			list_delete(wlc_tstamp_list);

		exit(0);
	}
	else {
		MyDBG("Unknown SIGNAL or No defined\n");
	}
}

static void signal_register(void)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = &handlesignal;
	//sigaction(SIGUSR1, &sa, NULL);
	//sigaction(SIGUSR2, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);    
}

char ipaddr_g[32];
char *arp_ipaddr(char *ea)
{
	char buf[256], ipaddr[16], hwaddr[18], mask[32], device[16];
	unsigned hwtype, flags;
	int ret;
	char *p = NULL;

	FILE *fp = fopen("/proc/net/arp", "r");
	if (!fp) {
		perror("no proc fs mounted!\n");
		return NULL;
	}

	while (fgets(buf, 256, fp)) {
		ret = sscanf(buf, "%15s %x %x %s %31s %15s", ipaddr, &hwtype, &flags, hwaddr, mask, device);
		if (ret == 6) {
			if (!strcasecmp(ea, hwaddr)) {
				strncpy(ipaddr_g, ipaddr, sizeof(ipaddr_g) - 1);
				p = ipaddr_g;
				break;
			}
		}
	}

	fclose(fp);

	return p;
}

static int wlcnt_filter_roaming(char *mac)
{
	// roaming filter (roaming file)
	json_object *root = NULL;
	json_object *staObj = NULL;

	if (f_exists("/tmp/sta_roaming.json") == 0) return 0;

	if ((root = json_object_from_file("/tmp/sta_roaming.json")) == NULL) {
		perror("fail to open /tmp/sta_roaming.json!\n");
		return 0;
	}

	json_object_object_get_ex(root, mac, &staObj);
	if (staObj == NULL)
		return 0;
	else
		return 1;
}

static int wlcnt_filter_spam(time_t tstamp, char *mac, int online)
{
	// spam filter (online timestamp)
	int ret = 0;
	int is_found = 0;
	struct listnode *ln = NULL;
	WLC_SPAM_T *mylist = NULL;
	WLC_SPAM_T *spam_t = NULL;

	/* traversing the linklist */
	LIST_LOOP(wlc_tstamp_list, mylist, ln)
	{
		if (strcmp(mylist->mac, mac)) continue;
		MyDBG("found : %ld/%s\n", mylist->tstamp, mylist->mac);
		if (online == 0 && ((tstamp - mylist->tstamp) < WLCNT_SPAM_OFFLINE)) ret = 1;
		if (online == 1 && ((tstamp - mylist->tstamp) < WLCNT_SPAM_ONLINE))  ret = 1;
		if (online == 1) mylist->tstamp = tstamp; // update timestamp when device connected
		is_found = 1;
		break;
	}

	/* add listnode */
	if (is_found == 0) {
		spam_t = (WLC_SPAM_T *)malloc(sizeof(WLC_SPAM_T));
		spam_t->tstamp = tstamp;
		memcpy(spam_t->mac, mac, sizeof(spam_t->mac));
		listnode_add(wlc_tstamp_list, (void*)spam_t);
		list_count++;
	}

	// debug to show whole listnode
	mylist = NULL;
	ln = NULL;
	LIST_LOOP(wlc_tstamp_list, mylist, ln)
	{
		MyDBG("display : %ld/%s\n", mylist->tstamp, mylist->mac);
	}

	MyDBG("count = %u\n", list_count);
	/* check the length of linked list */
	if (list_count > MAX_SPAM_LIST) {
		if (wlc_tstamp_list) {
			list_delete_all_node(wlc_tstamp_list);
			list_count = 0;
		}
		MyDBG("The linked list is over 256 entries, free wlc_tstamp_list!\n");
	}

	return ret;
}

static int wlcnt_filter_age(char *mac)
{
	// age filter (custom_clientlist)
	char *p = NULL;
	char *g = NULL;
	char *buf = NULL;
	char *a = NULL, *macaddr = NULL, *c = NULL, *d = NULL, *e = NULL, *f = NULL;
	char *group = NULL, *age = NULL;

	g = buf = strdup(nvram_safe_get("custom_clientlist"));
	while (g) {
		if ((p = strsep(&g, "<")) == NULL) break;
		if ((vstrsep(p, ">", &a, &macaddr, &c, &d, &e, &f, &group, &age)) != 8) continue;
		if (!strcmp(macaddr, mac)) break;
	}
	if (buf) free(buf);

	MyDBG("macaddr=%s, group=%s, age=%s\n", macaddr, group, age);

	/*
		age = ""   // default
		age = 0    // unknown
		age = 1    // adult
		age = 2    // child
		age = NULL // can't get such flag 

		return value:
		0 : this device is over 18 years old
		1 : this device is under 18 years old
	*/

	if (age == NULL) return 0;

	if (!strcmp(age, "2"))
		return 1;
	else
		return 0; 
}

static void filter_wlcnt_rule(WLCNT_EVENT_T event_t)
{
	json_object *root = NULL;
	char *p1 = NULL;
	char *p2 = NULL;
	char eaddr[18];
	int is_exist = 0;   // exists before
	int is_online = 0;  // online or offline status
	int is_roaming = 0; // roaming status
	int is_spam = 0;    // spam status
	int is_age = 0;     // age is under 18 years old

	strlcpy(eaddr, event_t.addr, sizeof(eaddr));
	erase_symbol(eaddr, ":");

	p1 = search_mnt(eaddr);
	p2 = arp_ipaddr(event_t.addr);

	MyDBG("tstamp=%ld, macaddr=%s, ifname=%s, online=%d\n", event_t.tstamp, event_t.addr, event_t.ifname, event_t.online);
#if defined(RTCONFIG_NOTIFICATION_CENTER) && (defined(RTCONFIG_IFTTT) || defined(RTCONFIG_ALEXA))
	IFTTT_DEBUG("tstamp=%ld, macaddr=%s, ifname=%s, online=%d\n", event_t.tstamp, event_t.addr, event_t.ifname, event_t.online);
#endif

	/* update status of the device */
	if (p1 && p2) is_exist = 1;
	if (event_t.online == 1) is_online = 1;

	/* update roaming status from json table */
	is_roaming = wlcnt_filter_roaming(event_t.addr);

	/* filter spam online / offline rule */
	is_spam = wlcnt_filter_spam(event_t.tstamp, event_t.addr, event_t.online);

	/* filter age rule (under 18) */
	is_age = wlcnt_filter_age(event_t.addr);

	/* debug message */
	MyDBG("is_exist=%d, is_online=%d, is_roaming=%d, is_spam=%d, is_age=%d\n", is_exist, is_online, is_roaming, is_spam, is_age);
#if defined(RTCONFIG_NOTIFICATION_CENTER) && (defined(RTCONFIG_IFTTT) || defined(RTCONFIG_ALEXA))
	IFTTT_DEBUG("is_exist=%d, is_online=%d, is_roaming=%d, is_spam=%d, is_age=%d\n", is_exist, is_online, is_roaming, is_spam, is_age);
#endif

	/* filtering case : not to send event to nt_center */
	if (is_roaming || is_spam) return;

	/* send event to nt_center */
	root = json_object_new_object();
	if (root == NULL) {
		/* can't create json object */
		perror("ERROR create json object.\n");

		if (is_online == 0) {
			SEND_NT_EVENT(SYS_WIFI_DEVICE_DISCONNECTED_EVENT, "");
		}
		else if (is_online == 1 && is_exist == 0) {
			SEND_NT_EVENT(SYS_NEW_DEVICE_WIFI_CONNECTED_EVENT, "");
		}
		else if (is_online == 1 && is_exist == 1) {
			SEND_NT_EVENT(SYS_EXISTED_DEVICE_WIFI_CONNECTED_EVENT, "");
		}
	}
	else {
		MyDBG("cname=%s, macaddr=%s, ip=%s, ifanme=%s\n", p1, event_t.addr, p2, event_t.ifname);
		/* add json object : json_object_new_string can't be NULL */
		if(p1 == NULL) p1 = "";
		if(p2 == NULL) p2 = "";
		json_object_object_add(root, "cname", json_object_new_string(p1));
		json_object_object_add(root, "macaddr", json_object_new_string(event_t.addr));
		json_object_object_add(root, "ip", json_object_new_string(p2));
		json_object_object_add(root, "ifname", json_object_new_string(event_t.ifname));
		json_object_object_add(root, "RMacAddr", json_object_new_string(nvram_safe_get("lan_hwaddr")));

		if (is_online == 0) {
			SEND_NT_EVENT(SYS_WIFI_DEVICE_DISCONNECTED_EVENT, json_object_to_json_string(root));
#if defined(RTCONFIG_NOTIFICATION_CENTER) && (defined(RTCONFIG_IFTTT) || defined(RTCONFIG_ALEXA))
			IFTTT_DEBUG("Trigger OFFLINE event\n");
#endif
		}
		else if (is_online == 1 && is_exist == 0) {
			SEND_NT_EVENT(SYS_NEW_DEVICE_WIFI_CONNECTED_EVENT, json_object_to_json_string(root));
#if defined(RTCONFIG_NOTIFICATION_CENTER) && (defined(RTCONFIG_IFTTT) || defined(RTCONFIG_ALEXA))
			IFTTT_DEBUG("Trigger NEW DEVICE ONLINE event\n");
#endif
		}
		else if (is_online == 1 && is_exist == 1) {
			SEND_NT_EVENT(SYS_EXISTED_DEVICE_WIFI_CONNECTED_EVENT, json_object_to_json_string(root));
#if defined(RTCONFIG_NOTIFICATION_CENTER) && (defined(RTCONFIG_IFTTT) || defined(RTCONFIG_ALEXA))
			IFTTT_DEBUG("Trigger EXISTED DEVICE ONLINE event\n");
#endif
		}
	}
	json_object_put(root);
	MyDBG("SEND EVENT DONE!\n"); // VANIC
}

void receive_s(int newsockfd)
{
	int    n;
	char   date[30];
	WLCNT_EVENT_T event_t;

	memset(&event_t, 0, sizeof(WLCNT_EVENT_T));

	n = read(newsockfd, &event_t, sizeof(WLCNT_EVENT_T));
	if (n < 0)
	{
		perror("ERROR reading from socket.\n");
		return;
	}

	StampToDate(event_t.tstamp, date);
	MyDBG("tstamp=%ld(%s), macaddr=%s, ifname=%s, online=%d\n", event_t.tstamp, date, event_t.addr, event_t.ifname, event_t.online);

	filter_wlcnt_rule(event_t);
}

int main(void)
{
	char cmd[40];
	int pid;
	struct sockaddr_un addr;
	int sockfd, newsockfd;

	MyDBG("wlc_nt starting ...\n");

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
	if (strcmp(hw_auth_code, get_auth_code(in_buf, out_buf, sizeof(out_buf))) == 0) {
		MyDBG("This is ASUS router\n");
	}
	else {
		MyDBG("This is not ASUS router\n");
		return 0;
	}
#endif

	pid = getpid();
	snprintf(cmd, sizeof(cmd), "echo %d > %s", pid, WLCNT_PID_PATH);
	system(cmd);

	/* Signal */
	signal_register();

	/* create linked list for spam mechanism */
	wlc_tstamp_list = list_new();

	/* start unix socket */
	if ((sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		perror("socket error");
		exit(-1);
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strlcpy(addr.sun_path, WLCNT_SOCKET_PATH, sizeof(addr.sun_path));
	
	unlink(WLCNT_SOCKET_PATH);

	if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
		perror("socket bind error");
		exit(-1);
	}
	
	if (listen(sockfd, MAX_WLCNT_SOCKET_CLIENT) == -1) {
		perror("listen error");
		exit(-1);
	}

	while (1)
	{
		if ((newsockfd = accept(sockfd, NULL, NULL)) == -1) {
			perror("accept error");
			continue;
		}

		/* receive socket information */
		receive_s(newsockfd);
		close(newsockfd);
		MyDBG("close sockfd ...\n");
	}

	return 0;
}
