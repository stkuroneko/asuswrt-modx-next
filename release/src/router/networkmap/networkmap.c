#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <netinet/in.h>
#if !(defined(__GLIBC__) || defined(__UCLIBC__))
#include <netinet/if_ether.h>
#endif
#include <linux/if_ether.h>
#include <net/if.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <ctype.h>	//toupper()
#include <sys/time.h>
#include <shutils.h> //for eval()
#include <rtstate.h>
#include <bcmnvram.h>
#include <stdlib.h>
#include <asm/byteorder.h>
#include <networkmap.h>
//2011.02 Yau add shard memory
#include <sys/ipc.h>
#include <sys/shm.h>
#include <rtconfig.h>
#if (defined(RTCONFIG_BWDPI) || defined(RTCONFIG_BWDPI_DEP))
#include <bwdpi.h>
#endif
#ifdef RTCONFIG_NOTIFICATION_CENTER
#include <libnt.h>
int TRIGGER_FLAG;
#endif

#if defined(RTCONFIG_CONNDIAG)
#include <linux/limits.h>
#include "conn_diag-sql.h"
#endif

#include "protect_name.h"
#include "download.h"
#include "shared_func.h"

#include <json.h>

#ifdef RTCONFIG_CFGSYNC
#include <cfg_param.h>
#include <cfg_slavelist.h>
#include <cfg_wevent.h>
#include <cfg_event.h>
#include <cfg_lib.h>
#include <cfg_clientlist.h>
#include <cfg_onboarding.h>
#endif

#ifdef RTCONFIG_AMAS
static int is_re_node(char *client_mac, int check_path);
#endif

#define vstrsep(buf, sep, args...) _vstrsep(buf, sep, args, NULL)
#define swapx(a, b) { (a^=b), (b^=a), (a^=b); }

static int arp_skt = 0;
unsigned char my_hwaddr[6];
// LAN gateway
struct in_addr my_ipaddr_he; //router_addr_ne in host endian
uint32_t my_ipaddr_ne;

CLIENT_DETAIL_INFO_TABLE *p_client_detail_info_tab;
int arp_sockfd;

#ifdef RTCONFIG_TAGGED_BASED_VLAN
//VLAN gateway
unsigned char vlan_ipaddr[8][4];
CLIENT_DETAIL_INFO_TABLE *vlan_client_detail_info_tab[8];
int vlan_arp_sockfd[8];
int vlan_flag = 0; //record valid vlan subnet
#endif

#ifdef RTCONFIG_CAPTIVE_PORTAL
unsigned char fw_ipaddr[4], cp_ipaddr[4];
CLIENT_DETAIL_INFO_TABLE *fw_client_detail_info_tab, *cp_client_detail_info_tab;
int fw_arp_sockfd, cp_arp_sockfd;
int fw_flag = 0, cp_flag = 0;
#endif

#ifdef RTCONFIG_AMAS_WGN
//wgn VLAN gateway
unsigned char wgn_vlan_ipaddr[4][4];
int wgn_vlan_arp_sockfd[4];
int wgn_vlan_flag = 0; //record valid wgn vlan subnet
#endif

enum {
	SCAN_INIT=0,
	SCAN_PROC,
	SCAN_DONE,
	SCAN_CLEAN,
	SCAN_MAX
};
char *fullscan_state[SCAN_MAX] = {"0", "1", "2", "3"};
static int clean_shm = 0; //clean shm client list when wl setting changed first time

unsigned char broadcast_hwaddr[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
int networkmap_fullscan, lock, mdns_lock, nvram_lock;
int scan_count=0;
static int terminated = 1;

#ifdef NMP_DB
struct json_object *nmp_cl_json;
#endif
int delete_sig;

#define DEL_SHM_INTERVAL		300

//set default check device number waiting interval to 300s
int check_clients_interval = 300;
int clients_start_ts;
int check_all_device = 0;

/* add vendor attribute */
//oui json DB
struct json_object *oui_obj;
static int oui_enable = 0;

//signature
extern convType convTypes[];
extern convType bwdpiTypes[];
extern convType vendorTypes[];
//state machine for define device type
ac_state *acType, *dpiType, *vendorType;

#ifdef RTCONFIG_BONJOUR
typedef struct mDNSClientList_struct mDNSClientList;
struct mDNSClientList_struct
{
	unsigned char IPaddr[255][4];
	char Name[255][32];
	char Model[255][16];
};
mDNSClientList *shmClientList;

struct apple_model_handler {
	char *phototype;
	char *model;
	char *type;
};

struct apple_name_handler {
	char *name;
	char *type;
};

struct upnp_type_handler {
	char *server;
	char *type;
};

struct apple_model_handler apple_model_handlers[] = {
	{ "k68ap",	"iPhone",	"10" },
	{ "n82ap",	"iPhone 3G",	"10" },
	{ "n88ap",	"iPhone 3GS",	"10" },
	{ "n90ap",	"iPhone 4",	"10" },
	{ "n90bap",	"iPhone 4",	"10" },
	{ "n92ap",	"iPhone 4",	"10" },
	{ "n41ap",	"iPhone 5",	"10" },
	{ "n42ap",	"iPhone 5",	"10" },
	{ "n48ap",	"iPhone 5c",	"10" },
	{ "n49ap",	"iPhone 5c",	"10" },
	{ "n51ap",	"iPhone 5s",	"10" },
	{ "n53ap",	"iPhone 5s",	"10" },
	{ "n61ap",	"iPhone 6",	"10" },
	{ "n56ap",	"iPhone 6 Plus","10" },
	{ "n71ap",	"iPhone 6s",	"10" },
	{ "n71map",	"iPhone 6s",	"10" },
	{ "n66ap",	"iPhone 6s Plus","10" },
	{ "n66map",	"iPhone 6s Plus","10" },
	{ "n69ap",	"iPhone SE",	"10" },
	{ "d10ap",	"iPhone 7",	"10"},
	{ "d101ap",	"iPhone 7",	"10"},
	{ "d11ap",	"iPhone 7 Plus","10"},
	{ "d111ap",	"iPhone 7 Plus","10"},
	{ "d20ap",	"iPhone 8"	,"10"},
	{ "d201ap",	"iPhone 8"	,"10"},
	{ "d21ap",	"iPhone 8 Plus","10"},
	{ "d211ap",	"iPhone 8 Plus","10"},
	{ "d22ap",	"iPhone X",	"10"},
	{ "d221ap",	"iPhone X",	"10"},
	{ "n45ap",	"iPod touch",	"21" },
	{ "n72ap",	"iPod touch 2G","21" },
	{ "n18ap",	"iPod touch 3G","21" },
	{ "n81ap",	"iPod touch 4G","21" },
	{ "n78ap",	"iPod touch 5G","21" },
	{ "n78aap",	"iPod touch 5G","21" },
	{ "n102ap",	"iPod touch 6G","21" },
	{ "K48ap",	"iPad",		"21" },
	{ "K93ap",	"iPad 2",	"21" },
	{ "k94ap",	"iPad 2",	"21" },
	{ "k95ap",	"iPad 2",	"21" },
	{ "k93aap",	"iPad 2",	"21" },
	{ "j1ap",	"iPad 3",	"21" },
	{ "j2ap",	"iPad 3",	"21" },
	{ "j2aap",	"iPad 3",	"21" },
	{ "p101ap",	"iPad 4",	"21" },
	{ "p102ap",	"iPad 4",	"21" },
	{ "p103ap",	"iPad 4",	"21" },
	{ "j71ap",	"iPad Air",	"21" },
	{ "j72ap",	"iPad Air",	"21" },
	{ "j73ap",	"iPad Air",	"21" },
	{ "j81ap",	"iPad Air 2",	"21" },
	{ "j82ap",	"iPad Air 2",	"21" },
	{ "j98ap",	"iPad Pro",	"21" },
	{ "j99ap",	"iPad Pro",	"21" },
	{ "j127ap",	"iPad Pro",	"21" },
	{ "j128ap",	"iPad Pro",	"21" },
	{ "p105ap",	"iPad mini 1G",	"21" },
	{ "p106ap",	"iPad mini 1G",	"21" },
	{ "p107ap",	"iPad mini 1G",	"21" },
	{ "j85ap",	"iPad mini 2",	"21" },
	{ "j86ap",	"iPad mini 2",	"21" },
	{ "j87ap",	"iPad mini 2",	"21" },
	{ "j85map",	"iPad mini 3",	"21" },
	{ "j86map",	"iPad mini 3",	"21" },
	{ "j87map",	"iPad mini 3",	"21" },
	{ "j96ap",	"iPad mini 4",	"21" },
	{ "j97ap",	"iPad mini 4",	"21" },
	{ "k66ap",	"Apple TV 2G",	"11" },
	{ "j33ap",	"Apple TV 3G",	"11" },
	{ "j33iap",	"Apple TV 3G",	"11" },
	{ "j42dap",	"Apple TV 4G",	"11" },
	{ "rt288x",	"AiCam",	"5"  },
	{ NULL,		NULL,		NULL }
};

struct apple_name_handler apple_name_handlers[] = {
	{ "iPhone",	"10" },
	{ "MacBook",	"6"  },
	{ "MacMini",	"14" },
	{ "NAS-M25",	"4"  },
	{ "QNAP-TS210",	"4"  },
	{ NULL,		NULL }
};
#endif

#ifdef RTCONFIG_UPNPC
struct upnp_type_handler upnp_type_handlers[] = {
	{"Windows",	"1" },
	{NULL,		NULL}
};
#endif

struct vendorClass_handler {
	char *name;
	unsigned char type;
};

/*
        Unknown		0 //default
        andorid		1
        Window		2
        Linux/Unix	3
	ASUS		4 //from OUI
	Apple		5 //from OUI
*/
struct vendorClass_handler vendorClass_handlers[] = {
	{ "android-dhcp-10",	BASE_TYPE_ANDROID }, //android
	{ "android-dhcp-7.1.1",	BASE_TYPE_ANDROID }, //android
	{ "MSFT 5.0",		BASE_TYPE_WINDOW }, //Window
	{ "dhcpcd-5.5.6",	BASE_TYPE_LINUX }, //Linux/Unix
	{ NULL,			0}
};

extern void toLowerCase(char *str);
extern void Device_name_filter(P_CLIENT_DETAIL_INFO_TABLE p_client_detail_info_tab, int x);
extern void free_ac_state(ac_state *state);

void remove_client(int i);
void swap_client(P_CLIENT_DETAIL_INFO_TABLE p_client_detail_info_tab, int i, int j);


#ifdef RTCONFIG_NOTIFICATION_CENTER
void
call_notify_center(int sort, int event)
{
	extern int TRIGGER_FLAG;
	if(!(TRIGGER_FLAG>>sort & 1)){
		NOTIFY_EVENT_T *event_t = initial_nt_event();
		event_t->event = event;
		//snprintf(event_t->msg, sizeof(event_t->msg), "TRIGGER event: %08x", event);
		snprintf(event_t->msg, sizeof(event_t->msg), "");
		NMP_DEBUG("NT_CENTER: Send event ID:%08x !\n", event_t->event);
		send_trigger_event(event_t);
		nt_event_free(event_t);
		TRIGGER_FLAG |= (1<<sort);
		NMP_DEBUG("check TRIGGER_FLAG %d\n", TRIGGER_FLAG);
		nvram_set_int("networkmap_trigger_flag", TRIGGER_FLAG);
		nvram_commit();
	}
}

void
call_notify_center_DEV_UPDATE()
{
	struct json_object *nt_root = json_object_new_object();
	json_object_object_add(nt_root, "from", json_object_new_string("NETWORKMAP"));
	SEND_NT_EVENT(GENERAL_DEV_UPDATE, json_object_to_json_string(nt_root));
	if(nt_root) json_object_put(nt_root);
}
#endif

#ifdef RTCONFIG_AMAS
static int is_re_node(char *client_mac, int check_path) {
	int i;
	int ret = 0;
	int lock;
	int shm_client_tbl_id;
	P_CM_CLIENT_TABLE p_client_tbl;
	void *shared_client_info=(void *) 0;
	unsigned char mac_buf[6] = {0};

	lock = file_lock(CFG_FILE_LOCK);
	shm_client_tbl_id = shmget((key_t)KEY_SHM_CFG, sizeof(CM_CLIENT_TABLE), 0666|IPC_CREAT);
	if (shm_client_tbl_id == -1){
		fprintf(stderr, "is_re_node 1, shmget failed\n");
		file_unlock(lock);
		return 0;
	}

	shared_client_info = shmat(shm_client_tbl_id,(void *) 0,0);
	if (shared_client_info == (void *)-1){
		fprintf(stderr, "is_re_node 2,shmat failed\n");
		file_unlock(lock);
		return 0;
	}

	ether_atoe(client_mac, mac_buf);

	p_client_tbl = (P_CM_CLIENT_TABLE)shared_client_info;
	for(i = 1; i < p_client_tbl->count; i++) {
		if ((memcmp(p_client_tbl->sta2g[i], mac_buf, sizeof(mac_buf)) == 0 ||
			memcmp(p_client_tbl->sta5g[i], mac_buf, sizeof(mac_buf)) == 0) &&
			((check_path && p_client_tbl->activePath[i] == 1) || check_path == 0))
		{
			ret = 1;
			break;
		}
	}
	shmdt(shared_client_info);
	file_unlock(lock);

	return ret;
}

static int get_amas_client_mac(json_object *allClientList, char *ip, char *mac, int macBufSize) {
	int i;
	int lock;
	int shm_client_tbl_id;
	P_CM_CLIENT_TABLE p_client_tbl;
	void *shared_client_info=(void *) 0;
	unsigned char mac_buf[6] = {0};
	json_object *nodeEntry = NULL;
	json_object *bandEntry = NULL;
	json_object *macEntry = NULL;
	json_object *ipEntry = NULL;

	if (allClientList == NULL)
		return 0;

	/* get real mac for wireless client */
	json_object_object_foreach(allClientList, key, val) {
		nodeEntry = val;
		json_object_object_foreach(nodeEntry, key, val) {
			bandEntry = val;
			json_object_object_foreach(bandEntry, key, val) {
				macEntry = val;
				if (!is_re_node(key, 0)) {
					json_object_object_get_ex(macEntry, "ip", &ipEntry);
					if (ipEntry) {
						if (strcmp(ip, json_object_get_string(ipEntry)) == 0) {
							memset(mac, 0, macBufSize);
							snprintf(mac, macBufSize, "%s", key);
							break;
						}
					}
				}
			}
		}
	}

	/* check sta2g and sta5g, replace real mac for RE if client is RE */
	if (strlen(mac)) {
		lock = file_lock(CFG_FILE_LOCK);
		shm_client_tbl_id = shmget((key_t)KEY_SHM_CFG, sizeof(CM_CLIENT_TABLE), 0666|IPC_CREAT);
		if (shm_client_tbl_id == -1){
			fprintf(stderr, "get_amas_client_mac 1, shmget failed\n");
			file_unlock(lock);
			return 0;
		}

		shared_client_info = shmat(shm_client_tbl_id,(void *) 0,0);
		if (shared_client_info == (void *)-1){
			fprintf(stderr, "get_amas_client_mac 2, shmat failed\n");
			file_unlock(lock);
			return 0;
		}

		ether_atoe(mac, mac_buf);

		p_client_tbl = (P_CM_CLIENT_TABLE)shared_client_info;
		for(i = 1; i < p_client_tbl->count; i++) {
			if (memcmp(p_client_tbl->sta2g[i], mac_buf, sizeof(mac_buf)) == 0 ||
				memcmp(p_client_tbl->sta5g[i], mac_buf, sizeof(mac_buf)) == 0)
			{
				_dprintf("replace client mac (%s) by ", mac);
				memset(mac, 0, macBufSize);
				snprintf(mac, macBufSize, "%02X:%02X:%02X:%02X:%02X:%02X",
					p_client_tbl->realMacAddr[i][0], p_client_tbl->realMacAddr[i][1],
					p_client_tbl->realMacAddr[i][2], p_client_tbl->realMacAddr[i][3],
					p_client_tbl->realMacAddr[i][4], p_client_tbl->realMacAddr[i][5]);
				_dprintf("(%s)\n", mac);
				break;
			}
		}
		shmdt(shared_client_info);
		file_unlock(lock);
	}

	return strlen(mac);
}
#endif

CLIENT_DETAIL_INFO_TABLE *set_client_table_shm(CLIENT_DETAIL_INFO_TABLE *client_table, key_t key)
{
	int lock;
	int shm_id;

	//Initial Shared Memory
	//client tables
	lock = file_lock("networkmap");
	shm_id = shmget((key_t)key, sizeof(CLIENT_DETAIL_INFO_TABLE), 0666|IPC_CREAT);
	if (shm_id == -1){
		fprintf(stderr,"client info shmget failed\n");
		file_unlock(lock);
		exit(1);
	}

	client_table = (P_CLIENT_DETAIL_INFO_TABLE)shmat(shm_id,(void *) 0,0);
	memset(client_table, 0x00, sizeof(CLIENT_DETAIL_INFO_TABLE));
	client_table->ip_mac_num = 0;
	client_table->detail_info_num = 0;
	file_unlock(lock);
	return client_table;
}

/******** Build ARP Socket Function *********/
struct sockaddr_ll src_sockll, dst_sockll;
#ifdef RTCONFIG_TAGGED_BASED_VLAN
struct sockaddr_ll vlan_dst_sockll[8];
#endif
#ifdef RTCONFIG_CAPTIVE_PORTAL
struct sockaddr_ll fw_dst_sockll, cp_dst_sockll;
#endif
#ifdef RTCONFIG_AMAS_WGN
struct sockaddr_ll wgn_vlan_dst_sockll[4];
#endif

void set_arp_timeout(struct timeval *timeout, time_t tv_sec, suseconds_t tv_usec)
{
	timeout->tv_sec = tv_sec;
	timeout->tv_usec = tv_usec;
}

static int
iface_get_id(int fd, const char *device)
{
	struct ifreq	ifr;
	memset(&ifr, 0, sizeof(ifr));
	//iface NULL protection
	if (!device) {
		perror("iface_get_id ERR:\n");
		return -1;
	}
	NMP_DEBUG("interface %s\n", device);
	strlcpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
	if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1) {
		perror("iface_get_id ERR:\n");
		return -1;
	}

	return ifr.ifr_ifindex;
}
/*
 *  Bind the socket associated with FD to the given device.
 */
static int
iface_bind(int fd, int ifindex)
{
	int			err;
	socklen_t		errlen = sizeof(err);

	memset(&src_sockll, 0, sizeof(src_sockll));
	src_sockll.sll_family	       = AF_PACKET;
	src_sockll.sll_ifindex	       = ifindex;
	src_sockll.sll_protocol        = htons(ETH_P_ARP);

	if (bind(fd, (struct sockaddr *) &src_sockll, sizeof(src_sockll)) == -1) {
		perror("bind device ERR:\n");
		return -1;
	}
	/* Any pending errors, e.g., network is down? */
	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errlen) == -1) {
		return -2;
	}
	if (err > 0) {
		return -2;
	}
	int alen = sizeof(src_sockll);
	if (getsockname(fd, (struct sockaddr*)&src_sockll, (socklen_t *)&alen) == -1) {
		perror("getsockname");
		exit(2);
	}
	if (src_sockll.sll_halen == 0) {
		NMP_DEBUG("Interface is not ARPable (no ll address)\n");
		exit(2);
	}

	return 0;
}

int create_socket(char *device)
{
	/* create UDP socket */
	int sock_fd, device_id;
	sock_fd = socket(PF_PACKET, SOCK_DGRAM, 0);

	if(sock_fd < 0) 
		perror("create socket ERR:");

	device_id = iface_get_id(sock_fd, device);

	if (device_id == -1) {
		NMP_DEBUG("iface_get_id REEOR\n");
		return -1;
	}

	if ( iface_bind(sock_fd, device_id) < 0) {
		NMP_DEBUG("iface_bind ERROR\n");
		return -1;
	}

	return sock_fd;
}

int sent_arppacket(int raw_sockfd, unsigned char * src_ipaddr, unsigned char * dst_ipaddr, struct sockaddr_ll dst)
{
	ARP_HEADER * arp;
	char raw_buffer[46];

	memset(dst.sll_addr, -1, sizeof(dst.sll_addr)); //set dmac addr FF:FF:FF:FF:FF:FF

	if (raw_buffer == NULL)
	{
		perror("ARP: Oops, out of memory\r");
		return 1;
	}
	bzero(raw_buffer, 46);

	// Allow 14 bytes for the ethernet header
	arp = (ARP_HEADER *)(raw_buffer);// + 14);
	arp->hardware_type =htons(DIX_ETHERNET);
	arp->protocol_type = htons(IP_PACKET);
	arp->hwaddr_len = 6;
	arp->ipaddr_len = 4;
	arp->message_type = htons(ARP_REQUEST);
	// My hardware address and IP addresses
	memcpy(arp->source_hwaddr, my_hwaddr, sizeof(arp->source_hwaddr));
	memcpy(arp->source_ipaddr, src_ipaddr, sizeof(arp->source_ipaddr));
	// Destination hwaddr and dest IP addr
	memcpy(arp->dest_hwaddr, broadcast_hwaddr, sizeof(arp->source_hwaddr));
	memcpy(arp->dest_ipaddr, dst_ipaddr, sizeof(arp->source_ipaddr));

	if( (sendto(raw_sockfd, raw_buffer, 46, 0, (struct sockaddr *)&dst, sizeof(dst))) < 0 )
	{
		perror("sendto");
		return 1;
	}

	NMP_DEBUG("Send ARP Request success, src_ipaddr = %hhu.%hhu.%hhu.%hhu, to dst_ipaddr = %hhu.%hhu.%hhu.%hhu\n", src_ipaddr[0], src_ipaddr[1], src_ipaddr[2], src_ipaddr[3], dst_ipaddr[0], dst_ipaddr[1], dst_ipaddr[2], dst_ipaddr[3]);

	return 0;
}

/******* End of Build ARP Socket Function ********/
#if defined(RTCONFIG_QCA) && defined(RTCONFIG_WIRELESSREPEATER)
char *getStaMAC()
{
	char buf[512];
	FILE *fp;
	int len,unit;
	char *pt1,*pt2;
	unit=nvram_get_int("wlc_band");

	sprintf(buf, "ifconfig sta%d", unit);

	fp = popen(buf, "r");
	if (fp) {
		memset(buf, 0, sizeof(buf));
		len = fread(buf, 1, sizeof(buf), fp);
		pclose(fp);
		if (len > 1) {
			buf[len-1] = '\0';
			pt1 = strstr(buf, "HWaddr ");
			if (pt1)
			{
				pt2 = pt1 + strlen("HWaddr ");
				chomp(pt2);
				return pt2;
			}
		}
	}
	return NULL;
}
#endif

int sig_refresh_interval = 600;
time_t sig_refresh_start_ts = 0;

// avoid repeated refresh, 600s
void refresh_arp_scan() {

	time_t sig_refresh_end_ts = time(NULL);

	if((sig_refresh_end_ts - sig_refresh_start_ts) > sig_refresh_interval) {
		NMP_DEBUG("refresh_arp_scan, sig_refresh_end_ts(%lu) - sig_refresh_start_ts(%lu) > sig_refresh_interval(%d)\n", sig_refresh_end_ts, sig_refresh_start_ts, sig_refresh_interval);
		sig_refresh_start_ts = time(NULL);
		networkmap_fullscan = SCAN_INIT;
	} else {
		if (nvram_get_int("refresh_networkmap"))
			nvram_unset("refresh_networkmap");
	}
}

/*********** Signal function **************/
static void refresh_sig_on()
{
	if(networkmap_fullscan == SCAN_PROC) {
		NMP_DEBUG("Fullscan is already in process!\n");
		return;
	} else	
		NMP_DEBUG("Refresh network map!\n");

	if (nvram_match("refresh_networkmap", "9999"))
		networkmap_fullscan = SCAN_INIT;
	else
		refresh_arp_scan();
}

static void handlesigCleanShm()
{
	networkmap_fullscan = SCAN_CLEAN;
	NMP_DEBUG("SIGNAL clean share memory client list\n");
}


static void handlesigTerminal()
{
	terminated = 0;
	NMP_DEBUG("SIGNAL terminal\n");
}

static void safe_leave()
{
	file_unlock(lock);
	file_unlock(mdns_lock);
	file_unlock(nvram_lock);
#ifdef NMP_DB
	json_object_put(nmp_cl_json);
#endif
	unlink(NMP_VC_JSON_FILE);
	free_ac_state(acType);
	free_ac_state(dpiType);
	free_ac_state(vendorType);
	shmdt(p_client_detail_info_tab);
	if(oui_enable) json_object_put(oui_obj);

	close(arp_sockfd);
#ifdef RTCONFIG_TAGGED_BASED_VLAN
	int i;
	if(vlan_flag){
		for(i = 0; i < 8; i++){
			if(vlan_flag & (1<<i)){
				shmdt(vlan_client_detail_info_tab[i]);
				close(vlan_arp_sockfd[i]);
			}
		}
	}
#endif
#ifdef RTCONFIG_CAPTIVE_PORTAL
	if(fw_flag == 1){
		shmdt(fw_client_detail_info_tab);
		close(fw_arp_sockfd);
	}
	if(cp_flag == 1){
		shmdt(cp_client_detail_info_tab);
		close(cp_arp_sockfd);
	}
#endif
#ifdef RTCONFIG_AMAS_WGN
	int j;
	if(wgn_vlan_flag){
		for(j = 0; j < 4; j++){
			if(wgn_vlan_flag & (1<<j)){
				close(wgn_vlan_arp_sockfd[j]);
			}
		}
	}
#endif
	
	nvram_unset("rescan_networkmap");
	nvram_unset("refresh_networkmap");
}


void
convert_mac_to_upper_oui_string(unsigned char *mac, char *mac_str)
{
	sprintf(mac_str, "%02X%02X%02X",
			*mac,*(mac+1),*(mac+2));
}

#ifdef NMP_DB
int commit_no = 0;
int client_updated = 0;

int
check_database_size()
{
	FILE *fp;
	int ncl_sz = 0, ret = 0;
	NMP_DEBUG("check database size\n");
	if ((fp = fopen(NMP_CL_JSON_FILE, "r"))) {
		fseek(fp, 0L, SEEK_END);
		ncl_sz = ftell(fp);
		if(ncl_sz) {
			if(ncl_sz < NCL_LIMIT) ret =1;
		}
		fclose(fp);
	}
	else ret = 1; //no database

	return ret;
}

static void vendorClassCheck(char *name, unsigned char *type, unsigned char *dType)
{
	struct vendorClass_handler *vc_handler;

	NMP_DEBUG_VC("%s()\n", __FUNCTION__);
	/* find base type */
	if(!*type) {
		for (vc_handler = &vendorClass_handlers[0]; vc_handler->name; vc_handler++) {
			if((name) && strstr(name, vc_handler->name))
			{
				*type =  vc_handler->type;
				NMP_DEBUG_VC("vendor class Check name=%s, find type=%d\n", name, *type);
				break;
			}
		}

		//check more
		if(!*type) {
			if(name) {
				if(strstr(name, "android"))
					*type = BASE_TYPE_ANDROID;
				else if(strstr(name, "MSFT"))
					*type = BASE_TYPE_WINDOW;
				else if(strstr(name, "dhcpcd"))
					*type = BASE_TYPE_LINUX;
			}
			NMP_DEBUG_VC("find os type=%d\n", *type);
		}
	}
	/* write device type if not defined yet */
	if(!*dType) {
		if(*type == BASE_TYPE_ANDROID) *dType = TYPE_ANDROID;
		else if(*type == BASE_TYPE_WINDOW) *dType = TYPE_WINDOWS;
		else if(*type == BASE_TYPE_LINUX) *dType = TYPE_LINUX_DEVICE;
		NMP_DEBUG_VC("find device type=%d\n", *dType);
	}

	NMP_DEBUG_VC("vendor class Check name=%s, os_type=%d device_type=%d\n", name, *type, *dType);
	return;
}



int check_vendorclass(char *mac_buf, CLIENT_DETAIL_INFO_TABLE *p_client_tab, const int i, const char * parse_file)
{

	unsigned char typeID = 0, baseID = 0;

	struct json_object *nmp_vc_json = NULL, *vc_client = NULL, *t_vc_client = NULL;
	int status = -1;

	NMP_DEBUG("check_vendorclass: %s\n", mac_buf);

	// nmp_vc_json = json_object_from_file(NMP_VC_JSON_FILE);
	nmp_vc_json = json_object_from_file(parse_file);
	if(nmp_vc_json) {
		json_object_object_get_ex(nmp_vc_json, mac_buf, &vc_client);
		if(vc_client) {
			json_object_object_get_ex(vc_client, "vendorclass", &t_vc_client);
			if(t_vc_client) {

				strlcpy(p_client_tab->vendorClass[i], json_object_get_string(t_vc_client), sizeof(p_client_tab->vendorClass[i]));

				NMP_DEBUG("%s(): Get vendorClass = %s (len=%d), os_type = %d, type = %d\n", __FUNCTION__, p_client_tab->vendorClass[i], strlen(p_client_tab->vendorClass[i]), p_client_tab->os_type[i], p_client_tab->type[i]);

				// //skip NULL string vendor class check
				if(strncmp(p_client_tab->vendorClass[i], "", sizeof(p_client_tab->vendorClass[i]))) {


					if((typeID = full_search(vendorType, p_client_tab->vendorClass[i], &baseID))) {

						strlcpy(p_client_tab->device_name[i], p_client_tab->vendorClass[i], sizeof(p_client_tab->device_name[i]));
						strlcpy(p_client_tab->vendor_name[i], p_client_tab->vendorClass[i], sizeof(p_client_tab->vendor_name[i]));

						type_filter(p_client_tab, i, typeID, baseID, 0);			

						NMP_DEBUG("%s >> mac[%s] >> vendor_class data >> Find vendorType >> device name = %s, vendor_name = %s, index = %d, typeID = %d,  os_type = %d \n", __FUNCTION__, mac_buf, p_client_detail_info_tab->device_name[i], p_client_detail_info_tab->vendor_name[i], index, typeID, baseID);

						status = SUCCESS;
					}
				}
			}
		}
		json_object_put(nmp_vc_json);		
	}

	return status;
}


int check_oui(char *mac_buf, CLIENT_DETAIL_INFO_TABLE *p_client_tab, const int i)
{

	unsigned char typeID = 0, baseID = 0;
	const char *oui_str = NULL;
	int index = 0, status = -1;
	char dev_oui_mac[7], mac[4];

	NMP_DEBUG("%s >> mac_buf = %s \n", __FUNCTION__, mac_buf);

	struct json_object *vendor_obj;

	if(memcpy(mac, p_client_tab->mac_addr[i], 3)) {

		mac[4] = '\0';
		convert_mac_to_upper_oui_string(mac, dev_oui_mac);
		json_object_object_get_ex(oui_obj, dev_oui_mac, &vendor_obj);

		if((oui_str = json_object_get_string(vendor_obj))) {

			NMP_DEBUG("*** mac [ %s ] Find OUI data >> [%s] , typeID = %d , os_type = %d\n", mac_buf, oui_str, typeID, baseID);

			strlcpy(p_client_tab->vendorClass[i], oui_str, sizeof(p_client_tab->vendorClass[i]));

			NMP_DEBUG("%s >> OUI data >> vendor db keyword search >> prefix_search_index [%s] \n", __FUNCTION__, oui_str);

			if(index = prefix_search_index(vendorType, oui_str, &baseID, &typeID)) {

				strlcpy(p_client_detail_info_tab->vendor_name[i], oui_str, sizeof(p_client_detail_info_tab->vendor_name[i]));
				strlcpy(p_client_detail_info_tab->device_name[i], oui_str, index);
				strlcpy(p_client_detail_info_tab->vendorClass[i], oui_str, index);

				type_filter(p_client_detail_info_tab, i, typeID, baseID, 0);

				NMP_DEBUG("%s >> mac[%s] >> OUI data >> Find vendorType >> device name = %s, vendor_name = %s, index = %d, typeID = %d,  os_type = %d \n", __FUNCTION__, mac_buf, p_client_detail_info_tab->device_name[i], p_client_detail_info_tab->vendor_name[i], index, typeID, baseID);

				status = SUCCESS;

			} else {

				strlcpy(p_client_detail_info_tab->device_name[i], oui_str, sizeof(p_client_detail_info_tab->device_name[i]));
				strlcpy(p_client_detail_info_tab->vendor_name[i], oui_str, sizeof(p_client_detail_info_tab->vendor_name[i]));
				
				NMP_DEBUG("%s >> mac[%s] >> OUI data >> Not Find vendorType >> device name = %s, vendor_name = %s, index = %d, typeID = %d,  os_type = %d \n", __FUNCTION__, mac_buf, p_client_detail_info_tab->device_name[i], p_client_detail_info_tab->vendor_name[i], index, typeID, baseID);

			}

		} else {
			NMP_DEBUG("*** mac[ %s ] Not Find OUI data >> [%s] , typeID = %d , os_type = %d\n", mac_buf, oui_str, typeID, baseID);
		}
	}

	return status;
}

void write_vendorclass(char *mac_buf, CLIENT_DETAIL_INFO_TABLE *p_client_tab, struct json_object *client)
{
	struct json_object *nmp_vc_json = NULL, *vc_client = NULL, *t_vc_client = NULL;

	NMP_DEBUG("write_vendorclass, mac : %s\n", mac_buf);

	nmp_vc_json = json_object_from_file(NMP_VC_JSON_FILE);
	if(nmp_vc_json) {
		json_object_object_get_ex(nmp_vc_json, mac_buf, &vc_client);
		if(vc_client) {
			json_object_object_get_ex(vc_client, "vendorclass", &t_vc_client);
			if(t_vc_client) {
				strlcpy(p_client_tab->vendorClass[p_client_tab->detail_info_num], json_object_get_string(t_vc_client), sizeof(p_client_tab->vendorClass[p_client_tab->detail_info_num]));
				NMP_DEBUG("%s(): %s json:%s\n", __FUNCTION__, p_client_tab->vendorClass[p_client_tab->detail_info_num], json_object_get_string(t_vc_client));
				//skip NULL string vendor class check
				if(strncmp(p_client_tab->vendorClass[p_client_tab->detail_info_num], "", sizeof(p_client_tab->vendorClass[p_client_tab->detail_info_num]))) {
					//OUI prior to vendor class
					if(!p_client_tab->os_type[p_client_tab->detail_info_num] || !p_client_tab->type[p_client_tab->detail_info_num])
						vendorClassCheck(p_client_tab->vendorClass[p_client_tab->detail_info_num], &p_client_tab->os_type[p_client_tab->detail_info_num], &p_client_tab->type[p_client_tab->detail_info_num]);
				}
				json_object_object_add(client, "vendorclass", json_object_new_string(p_client_tab->vendorClass[p_client_tab->detail_info_num]));
				json_object_object_add(client, "os_type", json_object_new_int(p_client_tab->os_type[p_client_tab->detail_info_num]));
				client_updated = 1;
			}
		}
		json_object_put(nmp_vc_json);		
	}
}

void write_to_DB(CLIENT_DETAIL_INFO_TABLE *p_client_tab, struct json_object *clients)
{
	char mac_buf[32];
	struct json_object *client = NULL, *t_client = NULL;
	
	snprintf(mac_buf, sizeof(mac_buf), "%02X:%02X:%02X:%02X:%02X:%02X",
			p_client_tab->mac_addr[p_client_tab->detail_info_num][0],p_client_tab->mac_addr[p_client_tab->detail_info_num][1],
			p_client_tab->mac_addr[p_client_tab->detail_info_num][2],p_client_tab->mac_addr[p_client_tab->detail_info_num][3],
			p_client_tab->mac_addr[p_client_tab->detail_info_num][4],p_client_tab->mac_addr[p_client_tab->detail_info_num][5]);

	NMP_DEBUG("write_to_DB, write to mac: %s\n", mac_buf);

	json_object_object_get_ex(clients, mac_buf, &client);
	if(client) {
		json_object_object_get_ex(client, "mac", &t_client);
		if(t_client && strncmp(mac_buf, json_object_get_string(t_client), sizeof(mac_buf))) {
			json_object_object_add(client, "mac", json_object_new_string(mac_buf));
			client_updated = 1;
		}
		json_object_object_get_ex(client, "name", &t_client);
		if(t_client && strncmp(p_client_tab->device_name[p_client_tab->detail_info_num], json_object_get_string(t_client), sizeof(p_client_tab->device_name[p_client_tab->detail_info_num]))) {
			json_object_object_add(client, "name", json_object_new_string(p_client_tab->device_name[p_client_tab->detail_info_num]));
			client_updated = 1;
		}
		json_object_object_get_ex(client, "vendor", &t_client);
		if(t_client && strncmp(p_client_tab->vendor_name[p_client_tab->detail_info_num], json_object_get_string(t_client), sizeof(p_client_tab->vendor_name[p_client_tab->detail_info_num]))) {
			json_object_object_add(client, "vendor", json_object_new_string(p_client_tab->vendor_name[p_client_tab->detail_info_num]));
			client_updated = 1;
		}

		// write_vendorclass(mac_buf, p_client_tab, client);
		//write device type after write vendor class(probably fill in base type)


		json_object_object_get_ex(client, "vendorclass", &t_client);
		if(t_client && strncmp(p_client_tab->vendorClass[p_client_tab->detail_info_num], json_object_get_string(t_client), sizeof(p_client_tab->vendorClass[p_client_tab->detail_info_num]))) {
			json_object_object_add(client, "vendorclass", json_object_new_string(p_client_tab->vendorClass[p_client_tab->detail_info_num]));
			client_updated = 1;
		}

		json_object_object_get_ex(client, "type", &t_client);
		if(t_client && p_client_tab->type[p_client_tab->detail_info_num] != json_object_get_int(t_client)) {
			json_object_object_add(client, "type", json_object_new_int(p_client_tab->type[p_client_tab->detail_info_num]));
			client_updated = 1;
		}

		json_object_object_get_ex(client, "os_type", &t_client);
		if(t_client && p_client_tab->os_type[p_client_tab->detail_info_num] != json_object_get_int(t_client)) {
			json_object_object_add(client, "os_type", json_object_new_int(p_client_tab->os_type[p_client_tab->detail_info_num]));
			client_updated = 1;
		}

		json_object_object_get_ex(client, "sdn_idx", &t_client);
		if(t_client && p_client_tab->sdn_idx[p_client_tab->detail_info_num] != json_object_get_int(t_client)) {
			json_object_object_add(client, "sdn_idx", json_object_new_int(p_client_tab->sdn_idx[p_client_tab->detail_info_num]));
			client_updated = 1;
		}

		json_object_object_get_ex(client, "online", &t_client);
		if(t_client && p_client_tab->online[p_client_tab->detail_info_num] != json_object_get_int(t_client)) {
			json_object_object_add(client, "online", json_object_new_int(p_client_tab->online[p_client_tab->detail_info_num]));
			client_updated = 1;
		}

		json_object_object_get_ex(client, "wireless", &t_client);
		if(t_client && p_client_tab->wireless[p_client_tab->detail_info_num] != json_object_get_int(t_client)) {
			json_object_object_add(client, "wireless", json_object_new_int(p_client_tab->wireless[p_client_tab->detail_info_num]));
			client_updated = 1;
		}

		json_object_object_get_ex(client, "is_wireless", &t_client);
		if(t_client && p_client_tab->is_wireless[p_client_tab->detail_info_num] != json_object_get_int(t_client)) {
			// set : is wireless
			if( p_client_tab->is_wireless[p_client_tab->detail_info_num] != 0 ) {
				json_object_object_add(client, "is_wireless", json_object_new_int(p_client_tab->is_wireless[p_client_tab->detail_info_num]));
				client_updated = 1;
			}
		} 

		json_object_object_get_ex(client, "conn_ts", &t_client);
		if(t_client && p_client_tab->conn_ts[p_client_tab->detail_info_num] != json_object_get_int(t_client)) {

			if( p_client_tab->conn_ts[p_client_tab->detail_info_num] != 0 ) {
				json_object_object_add(client, "conn_ts", json_object_new_int(p_client_tab->conn_ts[p_client_tab->detail_info_num]));
				client_updated = 1;
			}
		}

	}
	else {
		/* json networkmap client list database */
		client = json_object_new_object();

		json_object_object_add(client, "mac", json_object_new_string(mac_buf));
		json_object_object_add(client, "name", json_object_new_string(p_client_tab->device_name[p_client_tab->detail_info_num]));
		json_object_object_add(client, "vendor", json_object_new_string(p_client_tab->vendor_name[p_client_tab->detail_info_num]));
		if(p_client_tab->vendorClass[p_client_tab->detail_info_num] != NULL) {
			json_object_object_add(client, "vendorclass", json_object_new_string(p_client_tab->vendorClass[p_client_tab->detail_info_num]));	
		} else {
			json_object_object_add(client, "vendorclass", json_object_new_string(""));	
		}
		json_object_object_add(client, "type", json_object_new_int(p_client_tab->type[p_client_tab->detail_info_num]));
		json_object_object_add(client, "os_type", json_object_new_int(p_client_tab->os_type[p_client_tab->detail_info_num]));
		json_object_object_add(client, "sdn_idx", json_object_new_int(p_client_tab->sdn_idx[p_client_tab->detail_info_num]));
		json_object_object_add(client, "online", json_object_new_int(p_client_tab->online[p_client_tab->detail_info_num]));
		json_object_object_add(client, "wireless", json_object_new_int(p_client_tab->wireless[p_client_tab->detail_info_num]));
		json_object_object_add(client, "is_wireless", json_object_new_int(p_client_tab->is_wireless[p_client_tab->detail_info_num]));
		json_object_object_add(client, "conn_ts", json_object_new_int(p_client_tab->conn_ts[p_client_tab->detail_info_num]));
		
		json_object_object_add(clients, mac_buf, client);
	}
}

int
DeletefromDB(CLIENT_DETAIL_INFO_TABLE *p_client_tab, struct json_object *clients)
{
	char *mac_str, mac_buf[32];
	struct json_object *client;
	int del_ret = 0;

	mac_str = p_client_tab->delete_mac;
	NMP_DEBUG("delete_from_database: %s\n", mac_str);
	memset(mac_buf, 0, sizeof(mac_buf));
	sprintf(mac_buf, "%C%C:%C%C:%C%C:%C%C:%C%C:%C%C",
			toupper(*mac_str), toupper(*(mac_str+1)), toupper(*(mac_str+2)), toupper(*(mac_str+3)), toupper(*(mac_str+4)), toupper(*(mac_str+5)), 
			toupper(*(mac_str+6)), toupper(*(mac_str+7)), toupper(*(mac_str+8)), toupper(*(mac_str+9)), toupper(*(mac_str+10)), 
			toupper(*(mac_str+11)), toupper(*(mac_str+12)));

	json_object_object_get_ex(clients, mac_buf, &client);
	if(client) {
		NMP_DEBUG("Delete json database\n");
		json_object_object_del(clients, mac_buf);
		del_ret = 1; 
	}
	return del_ret;
}
#endif

void
DeletefromShm(CLIENT_DETAIL_INFO_TABLE *p_client_tab)
{
	char *mac_str, tmp[2];
	unsigned char mac_buf[6];
	int i, j, n, count = 0;
	int lock;

	n = p_client_detail_info_tab->ip_mac_num;
	mac_str = p_client_tab->delete_mac;
	NMP_DEBUG("delete_from_share_memory: %s\n", mac_str);
	memset(mac_buf, 0, sizeof(mac_buf));

	for(i = 0; i < 6; i++) {
		strncpy(tmp, mac_str, 2);
		mac_str += 2;
		mac_buf[i] = strtol(tmp, NULL, 16);
	}
	NMP_DEBUG("%02x%02x%02x%02x%02x%02x, ", mac_buf[0], mac_buf[1], mac_buf[2], mac_buf[3], mac_buf[4], mac_buf[5]);
	for(i = 0; i < n; i++) {
		if(!memcmp(mac_buf, p_client_detail_info_tab->mac_addr[i], 6)) {
			lock = file_lock("networkmap");
			NMP_DEBUG("remove %d\n", i);
			remove_client(i);
			file_unlock(lock);
			break;
		}
	}
	NMP_DEBUG("SWAP client list\n");
	if (i < n) {
		lock = file_lock("networkmap");
		p_client_detail_info_tab->ip_mac_num--;
		p_client_detail_info_tab->detail_info_num--;
		p_client_detail_info_tab->commit_no--;
		if(p_client_detail_info_tab->device_flag[i] & (1<<FLAG_ASUS))
			p_client_detail_info_tab->asus_device_num--;

		n = p_client_detail_info_tab->ip_mac_num;

		for(j = i; j < n; j++)
			swap_client(p_client_detail_info_tab, j, j + 1);

		file_unlock(lock);
	}
}

void
delete_sig_on(int signo) {
	NMP_DEBUG("DELETE OFFLINE CLIENT\n");
	delete_sig = 1;
}

#ifdef RTCONFIG_BONJOUR
static void AppleModelCheck(char *model, char *name, unsigned char *type, char *shm_model)
{
	struct apple_model_handler *model_handler;
	struct apple_name_handler *name_handler;

	for (model_handler = &apple_model_handlers[0]; model_handler->phototype; model_handler++) {
		if((shm_model != NULL) && strstr(shm_model, model_handler->phototype))
		{
			strcpy(model, model_handler->model);
			*type =  atoi(model_handler->type);
			NMP_DEBUG("1. Apple Check get model=%s, type=%d\n", model, *type);
			return;
		}
	}
	for (name_handler = &apple_name_handlers[0]; name_handler->name; name_handler++) {
		if((name != NULL) && strstr(name, name_handler->name))
		{
			*type =  atoi(name_handler->type);
			NMP_DEBUG("2. Apple Check name=%s, find type=%d\n", name, *type);
			break;
		}
	}

	return;
}

static int QuerymDNSInfo(P_CLIENT_DETAIL_INFO_TABLE p_client_detail_info_tab, int x)
{
	unsigned char *a;
	int i;

	/*
	   printf("mDNS Query: %d?%d: %d.%d.%d.%d\n", x,
	   p_client_detail_info_tab->ip_mac_num,
	   p_client_detail_info_tab->ip_addr[x][0],
	   p_client_detail_info_tab->ip_addr[x][1],
	   p_client_detail_info_tab->ip_addr[x][2],
	   p_client_detail_info_tab->ip_addr[x][3]
	   );
	 */
	mdns_lock = file_lock("mDNSNetMonitor");

	i = 0;
	while (shmClientList->IPaddr[i][0] != '\0' && i < ARRAY_SIZE(shmClientList->IPaddr) ) {
		a = shmClientList->IPaddr[i];
		if(!memcmp(a,p_client_detail_info_tab->ip_addr[p_client_detail_info_tab->ip_mac_num],4)) {
			NMP_DEBUG("Query mDNS get: %d, %d.%d.%d.%d/%s/%s_\n", i,
					a[0],a[1],a[2],a[3], shmClientList->Name[i], shmClientList->Model[i]);
			if(shmClientList->Name[i]!=NULL && strcmp(shmClientList->Name[i],p_client_detail_info_tab->device_name[x]))
				strlcpy(p_client_detail_info_tab->device_name[x], shmClientList->Name[i], sizeof(p_client_detail_info_tab->device_name[x]));
			if(shmClientList->Model[i]!=NULL && strcmp(shmClientList->Name[i],p_client_detail_info_tab->apple_model[x]))
				toLowerCase(shmClientList->Model[i]);
			AppleModelCheck(p_client_detail_info_tab->apple_model[x],
					p_client_detail_info_tab->device_name[x],
					&p_client_detail_info_tab->type[x],
					shmClientList->Model[i]);
			break;
		}
		i++;
	}

	file_unlock(mdns_lock);

	return 0;
}
#endif

#ifdef RTCONFIG_UPNPC
static int QuerymUPnPCInfo(P_CLIENT_DETAIL_INFO_TABLE p_client_detail_info_tab, int x)
{
	char search_list[128], client_ip[16];
	char *nv, *nvp, *b;
	char *upnpc_ip, *upnpc_type, *upnpc_friendlyname;
	struct upnp_type_handler *upnp_handler;
	FILE *fp;

	sprintf(client_ip, "%d.%d.%d.%d",
	p_client_detail_info_tab->ip_addr[x][0],
	p_client_detail_info_tab->ip_addr[x][1],
	p_client_detail_info_tab->ip_addr[x][2],
	p_client_detail_info_tab->ip_addr[x][3]);

	if( (fp = fopen("/tmp/miniupnpc.log", "r")) != NULL )
	{
		while( fgets(search_list, sizeof(search_list), fp) )
		{
			if( strstr(search_list, client_ip) )
			{
				nvp = nv = search_list;
				while (nv && (b = strsep(&nvp, "<")) != NULL) {
					if (vstrsep(b, ">", &upnpc_ip, &upnpc_type, &upnpc_friendlyname) != 3) 
						continue;
				}

				if(p_client_detail_info_tab->type[x] == 0) {
					for (upnp_handler = &upnp_type_handlers[0]; upnp_handler->server; upnp_handler++) {
						if(!strcmp(upnpc_type, upnp_handler->server))
						{
							NMP_DEBUG("MiniUPnP get type!!! %s = %s\n", upnpc_type, upnp_handler->type);
							p_client_detail_info_tab->type[x] = atoi(upnp_handler->type);
							break;
						}
					}
				}

				
				if(p_client_detail_info_tab->device_name[x] == NULL) {
					if((strcmp(upnpc_friendlyname, "") && !strstr(upnpc_friendlyname, "UPnP Access Point"))) {
						NMP_DEBUG("MiniUPnP get name: %s\n", upnpc_friendlyname);
						strlcpy(p_client_detail_info_tab->device_name[x], upnpc_friendlyname, sizeof(p_client_detail_info_tab->device_name[x]));
					}
				}
			}
		}
		fclose(fp);
	}
}
#endif

void StringChk(char *chk_string)
{
	char *ptr = chk_string;
	while(*ptr!='\0') {
		if(*ptr<0x20 || *ptr>0x7E)
			*ptr = ' ';
		ptr++;
	}
}

#if (defined(RTCONFIG_BWDPI) || defined(RTCONFIG_BWDPI_DEP))
static int QueryBwdpiInfo(P_CLIENT_DETAIL_INFO_TABLE p_client_detail_info_tab, int x)
{
	bwdpi_device bwdpi_dev_info;
	char mac[18];
	char ipaddr[18];
	unsigned char typeID = 0, baseID = 0;
	char *host2lower;
	int spType = 0;

	sprintf(mac,"%02X:%02X:%02X:%02X:%02X:%02X",
			p_client_detail_info_tab->mac_addr[x][0],
			p_client_detail_info_tab->mac_addr[x][1],
			p_client_detail_info_tab->mac_addr[x][2],
			p_client_detail_info_tab->mac_addr[x][3],
			p_client_detail_info_tab->mac_addr[x][4],
			p_client_detail_info_tab->mac_addr[x][5]
	       );
	sprintf(ipaddr,"%d.%d.%d.%d",
			p_client_detail_info_tab->ip_addr[x][0],
			p_client_detail_info_tab->ip_addr[x][1],
			p_client_detail_info_tab->ip_addr[x][2],
			p_client_detail_info_tab->ip_addr[x][3]
	       );
	NMP_DEBUG("Bwdpi Query: %s, %s\n", mac, ipaddr);

	if(bwdpi_client_info(mac, ipaddr, &bwdpi_dev_info)) {

		NMP_DEBUG("Bwdpi  Get: hostname = [%s] / vendor_name = [%s] / type_name = [%s] / device_name = [%s]\n", bwdpi_dev_info.hostname, bwdpi_dev_info.vendor_name,
				bwdpi_dev_info.type_name, bwdpi_dev_info.device_name);

		strlcpy(p_client_detail_info_tab->bwdpi_host[x], bwdpi_dev_info.hostname, sizeof(p_client_detail_info_tab->bwdpi_host[x]));
		strlcpy(p_client_detail_info_tab->bwdpi_vendor[x], bwdpi_dev_info.vendor_name, sizeof(p_client_detail_info_tab->bwdpi_vendor[x]));
		strlcpy(p_client_detail_info_tab->bwdpi_type[x], bwdpi_dev_info.type_name, sizeof(p_client_detail_info_tab->bwdpi_type[x]));
		strlcpy(p_client_detail_info_tab->bwdpi_device[x], bwdpi_dev_info.device_name, sizeof(p_client_detail_info_tab->bwdpi_device[x]));
		StringChk(p_client_detail_info_tab->bwdpi_host[x]);
		StringChk(p_client_detail_info_tab->bwdpi_vendor[x]);
		StringChk(p_client_detail_info_tab->bwdpi_type[x]);
		StringChk(p_client_detail_info_tab->bwdpi_device[x]);

#if 0 //gateway infection vulnerability
		if (strcmp((char *)p_client_detail_info_tab->bwdpi_host[x], "")) {
			strlcpy(p_client_detail_info_tab->device_name[x], p_client_detail_info_tab->bwdpi_host[x], 
				sizeof(p_client_detail_info_tab->device_name[x]));
			Device_name_filter(p_client_detail_info_tab, x);
			NMP_DEBUG("*** Add BWDPI host %s\n", p_client_detail_info_tab->device_name[x]);
		}
#endif

		// if (strcmp((char *)p_client_detail_info_tab->bwdpi_device[x], "")) {
		// 	// write device type
		// 	if((typeID = prefix_search(dpiType, p_client_detail_info_tab->bwdpi_device[x], &baseID))) {
		// 		type_filter(p_client_detail_info_tab, x, typeID, baseID, 1);
		// 		NMP_DEBUG("*** BWDPI_DEVICE Find device type %d\n", typeID);
		// 	}
		// }


		if ((p_client_detail_info_tab->type[x] == 0) && strcmp((char *)p_client_detail_info_tab->bwdpi_device[x], "")) {

			NMP_DEBUG("Now type = 0, bwdpi_device = [%s], prefix_search dpiType DB, start\n", p_client_detail_info_tab->bwdpi_device[x]);

			// write device type
			if((typeID = prefix_search(dpiType, p_client_detail_info_tab->bwdpi_device[x], &baseID))) {
				type_filter(p_client_detail_info_tab, x, typeID, baseID, 1);
				NMP_DEBUG("*** BWDPI_DEVICE Find device type %d\n", typeID);
			}
		}

		// Get bwdpi vendor -> vendor_name
		if (!strcmp((char *)p_client_detail_info_tab->vendor_name[x], "") && strcmp((char *)p_client_detail_info_tab->bwdpi_vendor[x], "")) {

			strlcpy(p_client_detail_info_tab->vendor_name[x], p_client_detail_info_tab->bwdpi_vendor[x],
				sizeof(p_client_detail_info_tab->vendor_name[x]));
			NMP_DEBUG("*** Add BWDPI vendor %s\n", p_client_detail_info_tab->vendor_name[x]);
		}

		// if(!p_client_detail_info_tab->type[x] || p_client_detail_info_tab->type[x] == 9  || 
		// 	p_client_detail_info_tab->type[x] == 20 || p_client_detail_info_tab->type[x] == 23 || 
		// 	p_client_detail_info_tab->type[x] == 34 || isBaseType(p_client_detail_info_tab->type[x])) {
		if(p_client_detail_info_tab->type[x] == 0) {
			spType = 1;
		}
			
		if(spType == 1 && strcmp((char *)p_client_detail_info_tab->bwdpi_device[x], "")) {

			NMP_DEBUG("*** BWDPI_DEVICE full_search DB type, start \n");

			if((typeID = full_search(dpiType, p_client_detail_info_tab->bwdpi_device[x], &baseID))) {
				type_filter(p_client_detail_info_tab, x, typeID, baseID, 1);
				NMP_DEBUG("*** BWDPI_DEVICE Find device type %d\n", typeID);
			}
		}

		if((!p_client_detail_info_tab->type[x] || isBaseType(p_client_detail_info_tab->type[x])) && strcmp((char *)p_client_detail_info_tab->bwdpi_type[x], "")) {
			if((typeID = prefix_search(dpiType, p_client_detail_info_tab->bwdpi_type[x], &baseID))) {
				type_filter(p_client_detail_info_tab, x, typeID, baseID, 0);
				NMP_DEBUG("*** BWDPI_TYPE Find device type %d\n", typeID);
			}
		}


		if(strcmp((char *)p_client_detail_info_tab->bwdpi_host[x], "")) {
			
			strlcpy(p_client_detail_info_tab->device_name[x], p_client_detail_info_tab->bwdpi_host[x],
					sizeof(p_client_detail_info_tab->device_name[x]));

			NMP_DEBUG("*** Add BWDPI hostname to device_name > %s\n", p_client_detail_info_tab->device_name[x]);

			if(p_client_detail_info_tab->type[x] == 0) {

				host2lower = strdup(p_client_detail_info_tab->bwdpi_host[x]);
				toLowerCase(host2lower);
				if((typeID = full_search(acType, host2lower, &baseID))) {
					type_filter(p_client_detail_info_tab, x, typeID, baseID, 0);
					NMP_DEBUG("*** BWDPI_HOST Find device type %d\n", typeID);
				}
				free(host2lower);
			}

		}



		// if((!p_client_detail_info_tab->type[x] || isBaseType(p_client_detail_info_tab->type[x])) && strcmp((char *)p_client_detail_info_tab->bwdpi_host[x], "")) {
		// 	host2lower = strdup(p_client_detail_info_tab->bwdpi_host[x]);
		// 	toLowerCase(host2lower);
		// 	if((typeID = full_search(acType, host2lower, &baseID))) {
		// 		type_filter(p_client_detail_info_tab, x, typeID, baseID, 0);
		// 		NMP_DEBUG("*** BWDPI_HOST Find device type %d\n", typeID);
		// 	}
		// 	free(host2lower);
		// }

		NMP_DEBUG("bwdpi info: type = %d, bwdpi_device = %s, bwdpi_type = %s, bwdpi_host = %s \n", p_client_detail_info_tab->type[x], 
				p_client_detail_info_tab->bwdpi_device[x], p_client_detail_info_tab->bwdpi_type[x], p_client_detail_info_tab->bwdpi_host[x]);

#ifdef RTCONFIG_NOTIFICATION_CENTER
		if(p_client_detail_info_tab->type[x] == 7)
			call_notify_center(FLAG_XBOX_PS, HINT_XBOX_PS_EVENT);
		if(p_client_detail_info_tab->type[x] == 27)
			call_notify_center(FLAG_UPNP_RENDERER, HINT_UPNP_RENDERER_EVENT);
		if(p_client_detail_info_tab->type[x] == 6)
			call_notify_center(FLAG_OSX_INLAN, HINT_OSX_INLAN_EVENT);
#endif
	}

	return 0;
}
#endif

void swap(char *str1, char *str2, int size)
{
	unsigned char buffer[MAXDATASIZE] = {0};
	memcpy(buffer, str1, size);
	memcpy(str1, str2, size);
	memcpy(str2, buffer, size);
}

void swap_client(P_CLIENT_DETAIL_INFO_TABLE p_client_detail_info_tab, int i, int j)
{
	swap(p_client_detail_info_tab->ip_addr[j], p_client_detail_info_tab->ip_addr[i], sizeof(p_client_detail_info_tab->ip_addr[j]));
	swap(p_client_detail_info_tab->mac_addr[j], p_client_detail_info_tab->mac_addr[i], sizeof(p_client_detail_info_tab->mac_addr[j]));
	swap(p_client_detail_info_tab->user_define[j], p_client_detail_info_tab->user_define[i], sizeof(p_client_detail_info_tab->user_define[j]));
	swap(p_client_detail_info_tab->vendor_name[j], p_client_detail_info_tab->vendor_name[i], sizeof(p_client_detail_info_tab->vendor_name[j]));
	swap(p_client_detail_info_tab->device_name[j], p_client_detail_info_tab->device_name[i], sizeof(p_client_detail_info_tab->device_name[j]));
	swap(p_client_detail_info_tab->apple_model[j], p_client_detail_info_tab->apple_model[i], sizeof(p_client_detail_info_tab->apple_model[j]));
	swap(p_client_detail_info_tab->ipMethod[j], p_client_detail_info_tab->ipMethod[i], sizeof(p_client_detail_info_tab->ipMethod[j]));
#ifdef RTCONFIG_LANTIQ
	swapx(p_client_detail_info_tab->tstamp[j], p_client_detail_info_tab->tstamp[i]);
#endif
	swapx(p_client_detail_info_tab->type[j], p_client_detail_info_tab->type[i]);
	swapx(p_client_detail_info_tab->opMode[j], p_client_detail_info_tab->opMode[i]);
	swapx(p_client_detail_info_tab->device_flag[j], p_client_detail_info_tab->device_flag[i]);
	swapx(p_client_detail_info_tab->online[j], p_client_detail_info_tab->online[i]);
	swapx(p_client_detail_info_tab->sdn_idx[j], p_client_detail_info_tab->sdn_idx[i]);
	swapx(p_client_detail_info_tab->wireless[j], p_client_detail_info_tab->wireless[i]);
	swapx(p_client_detail_info_tab->is_wireless[j], p_client_detail_info_tab->is_wireless[i]);
	swapx(p_client_detail_info_tab->conn_ts[j], p_client_detail_info_tab->conn_ts[i]);
	swapx(p_client_detail_info_tab->offline_time[j], p_client_detail_info_tab->offline_time[i]);
	
	swapx(p_client_detail_info_tab->rssi[j], p_client_detail_info_tab->rssi[i]);
	swap(p_client_detail_info_tab->ssid[j], p_client_detail_info_tab->ssid[i], sizeof(p_client_detail_info_tab->ssid[j]));
	swap(p_client_detail_info_tab->txrate[j], p_client_detail_info_tab->txrate[i], sizeof(p_client_detail_info_tab->txrate[j]));
	swap(p_client_detail_info_tab->rxrate[j], p_client_detail_info_tab->rxrate[i], sizeof(p_client_detail_info_tab->rxrate[j]));
	swap(p_client_detail_info_tab->conn_time[j], p_client_detail_info_tab->conn_time[i], sizeof(p_client_detail_info_tab->conn_time[j]));
#if defined(RTCONFIG_FBWIFI) || defined(RTCONFIG_CAPTIVE_PORTAL)
	swapx(p_client_detail_info_tab->subunit[j], p_client_detail_info_tab->subunit[i]);
#endif
#if defined(RTCONFIG_BWDPI) || defined(RTCONFIG_BWDPI_DEP)
	swap(p_client_detail_info_tab->bwdpi_host[j], p_client_detail_info_tab->bwdpi_host[i], sizeof(p_client_detail_info_tab->bwdpi_host[j]));
	swap(p_client_detail_info_tab->bwdpi_vendor[j], p_client_detail_info_tab->bwdpi_vendor[i], sizeof(p_client_detail_info_tab->bwdpi_vendor[j]));
	swap(p_client_detail_info_tab->bwdpi_type[j], p_client_detail_info_tab->bwdpi_type[i], sizeof(p_client_detail_info_tab->bwdpi_type[j]));
	swap(p_client_detail_info_tab->bwdpi_device[j], p_client_detail_info_tab->bwdpi_device[i], sizeof(p_client_detail_info_tab->bwdpi_device[j]));
#endif
	NMP_DEBUG("**** swap client %d and %d\n", j, i);
}

void remove_client(int i)
{
	char delete_addr[16] = {0};
	sprintf(delete_addr, "%d.%d.%d.%d\0", p_client_detail_info_tab->ip_addr[i][0], p_client_detail_info_tab->ip_addr[i][1], p_client_detail_info_tab->ip_addr[i][2], p_client_detail_info_tab->ip_addr[i][3]);
	memset(p_client_detail_info_tab->ip_addr[i], 0x00, sizeof(p_client_detail_info_tab->ip_addr[i]));
	memset(p_client_detail_info_tab->mac_addr[i], 0x00, sizeof(p_client_detail_info_tab->mac_addr[i]));
	memset(p_client_detail_info_tab->user_define[i], 0x00, sizeof(p_client_detail_info_tab->user_define[i]));
	memset(p_client_detail_info_tab->vendor_name[i], 0x00, sizeof(p_client_detail_info_tab->vendor_name[i]));
	memset(p_client_detail_info_tab->device_name[i], 0x00, sizeof(p_client_detail_info_tab->device_name[i]));
	memset(p_client_detail_info_tab->apple_model[i], 0x00, sizeof(p_client_detail_info_tab->apple_model[i]));
	memset(p_client_detail_info_tab->ipMethod[i], 0x00, sizeof(p_client_detail_info_tab->ipMethod[i]));
#ifdef RTCONFIG_LANTIQ
	p_client_detail_info_tab->tstamp[i] = 0;
#endif
	p_client_detail_info_tab->type[i] = 0;
	p_client_detail_info_tab->opMode[i] = 0;
	p_client_detail_info_tab->device_flag[i] = 0;
	p_client_detail_info_tab->sdn_idx[i] = 0;
	p_client_detail_info_tab->online[i] = 0;
	p_client_detail_info_tab->wireless[i] = 0;
	p_client_detail_info_tab->is_wireless[i] = 0;
	p_client_detail_info_tab->conn_ts[i] = 0;
	p_client_detail_info_tab->offline_time[i] = 0;
	p_client_detail_info_tab->rssi[i] = 0;
	memset(p_client_detail_info_tab->ssid[0], 0x00, sizeof(p_client_detail_info_tab->ssid[i]));
	memset(p_client_detail_info_tab->txrate[i], 0x00, sizeof(p_client_detail_info_tab->txrate[i]));
	memset(p_client_detail_info_tab->rxrate[i], 0x00, sizeof(p_client_detail_info_tab->rxrate[i]));
	memset(p_client_detail_info_tab->conn_time[i], 0x00, sizeof(p_client_detail_info_tab->conn_time[i]));
#if defined(RTCONFIG_FBWIFI) || defined(RTCONFIG_CAPTIVE_PORTAL)
	p_client_detail_info_tab->subunit[i] = 0;
#endif
#if defined(RTCONFIG_BWDPI) || defined(RTCONFIG_BWDPI_DEP)
	memset(p_client_detail_info_tab->bwdpi_host[i], 0x00, sizeof(p_client_detail_info_tab->bwdpi_host[i]));
	memset(p_client_detail_info_tab->bwdpi_vendor[i], 0x00, sizeof(p_client_detail_info_tab->bwdpi_vendor[i]));
	memset(p_client_detail_info_tab->bwdpi_type[i], 0x00, sizeof(p_client_detail_info_tab->bwdpi_type[i]));
	memset(p_client_detail_info_tab->bwdpi_device[i], 0x00, sizeof(p_client_detail_info_tab->bwdpi_device[i]));
#endif
	//delete arp to avoid wireless client showing again
	eval("arp", "-d", delete_addr);
	NMP_DEBUG("**** remove client %d IP:%s\n", i, delete_addr);
}

void QueryAsusOuiInfo(P_CLIENT_DETAIL_INFO_TABLE p_client_detail_info_tab, int i)
{
	/* nothing to do if client has been recognized as ASUS device already*/
	if(p_client_detail_info_tab->device_flag[i] & (1<<FLAG_ASUS)) return;
	char dev_mac[18], dev_oui_mac[7], mac[4];
	char *search_list, *nv, *nvp, *b;
	char *dummy, *asus_ProductID, *asus_IP, *asus_Mac, *dummy2, *asus_SSID, *asus_subMask, *asus_type;
	char *IPCam;
	int index = 0, asus_found = 0;
	unsigned char tmpType, baseID = 0;

	snprintf(dev_mac, sizeof(dev_mac), "%02X:%02X:%02X:%02X:%02X:%02X",
			p_client_detail_info_tab->mac_addr[i][0], p_client_detail_info_tab->mac_addr[i][1],
			p_client_detail_info_tab->mac_addr[i][2], p_client_detail_info_tab->mac_addr[i][3],
			p_client_detail_info_tab->mac_addr[i][4], p_client_detail_info_tab->mac_addr[i][5]);

	NMP_DEBUG("check_asus_discovery:  search i = %d, MAC= %s\n", i, dev_mac);

	search_list = strdup(nvram_safe_get("asus_device_list"));
	if(!search_list) {
		NMP_DEBUG("strdup failed\n");
		return;
	}

	nvp = nv = search_list;

	if(search_list) {
		if(strstr(search_list, dev_mac)!=NULL) {
			while (nv && (b = strsep(&nvp, "<")) != NULL) {
				if (vstrsep(b, ">", &dummy, &asus_ProductID, &asus_IP, &asus_Mac, &dummy2, &asus_SSID, &asus_subMask, &asus_type) != 8) continue;

				NMP_DEBUG("Find MAC in Asus Discovery: %s, %s, %s, %s, %s, %s, %s, %s\n", dummy, asus_ProductID, asus_IP, asus_Mac, dummy2, asus_SSID, asus_subMask, asus_type);
				if(!strcmp(asus_Mac, dev_mac)) {
					IPCam = strdup(asus_ProductID);
					toLowerCase(IPCam);
					if(strstr(IPCam, "cam")) {
						p_client_detail_info_tab->type[i] = 5;
						NMP_DEBUG("***** Find AiCam****\n");
					}
					else if(asus_type != "")
					{
						tmpType = atoi(asus_type);
						if(tmpType == 2)
							p_client_detail_info_tab->type[i] = 24;
						else
							p_client_detail_info_tab->type[i] = 2;
					}
	
					strlcpy(p_client_detail_info_tab->device_name[i], asus_ProductID, sizeof(p_client_detail_info_tab->device_name[i]));
					strlcpy(p_client_detail_info_tab->vendor_name[i], "Asus", sizeof(p_client_detail_info_tab->vendor_name[i]));
					strlcpy(p_client_detail_info_tab->ssid[i], asus_SSID, sizeof(p_client_detail_info_tab->ssid[i]));
					p_client_detail_info_tab->opMode[i] = atoi(asus_type);
					p_client_detail_info_tab->device_flag[i] |= (1<<FLAG_HTTP);
					p_client_detail_info_tab->device_flag[i] |= (1<<FLAG_ASUS);
					free(IPCam);
					NMP_DEBUG("asus device: %d, %s, opMode:%d\n", p_client_detail_info_tab->type[i], p_client_detail_info_tab->device_name[i], 
							p_client_detail_info_tab->opMode[i]);
					// if(i != p_client_detail_info_tab->asus_device_num)
					// 	swap_client(p_client_detail_info_tab, i, p_client_detail_info_tab->asus_device_num);

					p_client_detail_info_tab->asus_device_num++;
					NMP_DEBUG("**** asus device num %d\n", p_client_detail_info_tab->asus_device_num);
					asus_found = 1;
					break;
				}
			}
		}
	}

	if(search_list)
		free(search_list);
}



// setting : nmp_cl_json.js param -> device name, vendor_name, vendorclass, type, os_type
int QueryVendorOuiInfo(P_CLIENT_DETAIL_INFO_TABLE p_client_detail_info_tab, int i)
{

	char mac_buf[32];
	int vendor_class_status = -1;
	int index = 0;
	char dev_oui_mac[7], mac[4];
	unsigned char typeID = 0, baseID = 0;
	char *oui_str = NULL;


	memset(mac_buf, 0, sizeof(mac_buf));
	sprintf(mac_buf, "%02X:%02X:%02X:%02X:%02X:%02X",
			p_client_detail_info_tab->mac_addr[i][0],p_client_detail_info_tab->mac_addr[i][1],
			p_client_detail_info_tab->mac_addr[i][2],p_client_detail_info_tab->mac_addr[i][3],
			p_client_detail_info_tab->mac_addr[i][4],p_client_detail_info_tab->mac_addr[i][5]);

	NMP_DEBUG("%s >> mac_buf : %s, check_vendorclass > %s \n", __FUNCTION__, mac_buf, NMP_VC_JSON_FILE);

	vendor_class_status = check_vendorclass(mac_buf, p_client_detail_info_tab, i, NMP_VC_JSON_FILE);

	if(vendor_class_status != SUCCESS) {
		NMP_DEBUG("%s >> mac_buf : %s, check_vendorclass > %s \n", __FUNCTION__, mac_buf, NMP_CL_JSON_FILE);
		vendor_class_status = check_vendorclass(mac_buf, p_client_detail_info_tab, i, NMP_CL_JSON_FILE);
	}


	NMP_DEBUG("%s(): vendor_class_status = %d, vendorClass =  %s, os_type = %d, type = %d\n", __FUNCTION__, vendor_class_status, p_client_detail_info_tab->vendorClass[i], p_client_detail_info_tab->os_type[i], p_client_detail_info_tab->type[i]);

	
	// vendor class : no data >> get mac oui info
	if(oui_enable  && (vendor_class_status != SUCCESS)){

		check_oui(mac_buf, p_client_detail_info_tab, i);

	}

	return 1;
}


void
refresh_client_list(P_CLIENT_DETAIL_INFO_TABLE p_client_detail_info_tab)
{
	int i;
	lock = file_lock("networkmap");
	for(i = 0; i < 255; i++)
		p_client_detail_info_tab->device_flag[i] &= (~(1<<FLAG_EXIST));
	file_unlock(lock);
}

void
reset_deep_scan(P_CLIENT_DETAIL_INFO_TABLE p_client_detail_info_tab)
{
	lock = file_lock("networkmap");
	p_client_detail_info_tab->detail_info_num = 0;
	file_unlock(lock);
}

char *strrpc(char *str,char *oldstr,char *newstr){
    char bstr[strlen(str)];
    memset(bstr,0,sizeof(bstr));
 	int i;
    for(i = 0;i < strlen(str);i++){
        if(!strncmp(str+i,oldstr,strlen(oldstr))){
            strcat(bstr,newstr);
            i += strlen(oldstr) - 1;
        }else{
        	strncat(bstr,str + i,1);
	    }
    }

    strcpy(str,bstr);
    return str;
} 

char *substring(char *dst,char *src,int start,int len)
{  
	char *p=dst;  
	char *q=src;  
	int length=strlen(src); 
	if(start>=length||start<0) 
		return NULL;  
	if(len>length) 
		len=length-start; 
	q+=start;
	while(len--)  
	{   
		*(p++)=*(q++); 
	}  
	*(p++)='\0'; 

	NMP_DEBUG("substring dst: %s\n", dst);
	strrpc(dst,"<","");
	strrpc(dst,">","");
	return dst;
}


#ifdef RTCONFIG_MULTILAN_CFG

int get_sdn_idx(const int subnet_idx){

	char *nv, *nvp, *b, *sepstr;
	int i, get_data = 0;
	int sdn_idx = 0;

	nv = nvp = strdup(nvram_safe_get("sdn_rl"));
	if(nv && strlen(nv) > 0){
		while((b = strsep(&nvp, "<")) != NULL){

			char *substr = NULL;
			sepstr = b;
			i = 0;
			substr = strsep(&sepstr, ">");

			do{
				// NMP_DEBUG("##### i == %d, substr = %s\n", i, substr);
				if(i == 0 && strlen(substr) > 0 ){
					sdn_idx = atoi(substr);
				}

				if(i == 4 && strlen(substr) > 0 ){
					if(subnet_idx == atoi(substr)) {
						get_data = 1;
						break;
					}
				}

				substr = strsep(&sepstr, ">");
				i++;
			} while(substr && i < 12);

			// NMP_DEBUG("##### from subnet_idx = %d, get sdn_idx = %d \n", subnet_idx, sdn_idx);

			if(get_data) {
				break;
			} else {
				sdn_idx = 0;
			}
		}
	}
	free(nv);

	return sdn_idx;
}


int get_subnet_idx(const char * subnet_ifname){

	char *nv, *nvp, *b, *sepstr;
	int i, get_data = 0;
	int subnet_idx = 0;

	nv = nvp = strdup(nvram_safe_get("subnet_rl"));
	if(nv && strlen(nv) > 0){
		while((b = strsep(&nvp, "<")) != NULL){

		    char *substr = NULL;
		    sepstr = b;
		    i = 0;
		    substr = strsep(&sepstr, ">");

		    do{
				// NMP_DEBUG("##### i == %d, substr = %s\n", i, substr);

				if(i == 0 && strlen(substr) > 0 ){
					subnet_idx = atoi(substr);
				}

				if(i == 1 && strlen(substr) > 0 ){
					if(strcmp(subnet_ifname, substr) == 0) {
						get_data = 1;
						break;
					}
				}

				substr = strsep(&sepstr, ">");
				i++;
		    } while(substr && i < 9);

			// NMP_DEBUG("##### from subnet_ifname = %s, get subnet_idx = %d \n", subnet_ifname, subnet_idx);

		    if(get_data) {
		    	break;
		    } else {
		    	subnet_idx = 0;
		    }
		}
	}
	free(nv);

	return subnet_idx;
}

#endif



void
handle_client_list_from_arp_table(P_CLIENT_DETAIL_INFO_TABLE p_client_detail_info_tab, const char *subnet)
{
	FILE *fp = NULL;
	int i, lock;
	int ip_dup, mac_dup, dhcp_mac = 0, dhcp_ip = 0;
	char line_buf_s[300], ipBuff[30], macBuff[20], lanIf[5], flags[5];
	char * line_buf = NULL;
	unsigned char cip[4]={0}, cmac[6]={0};
#ifdef RTCONFIG_AMAS
	struct json_object *allClientList = NULL;
	int is_RE_client = 0;
	char ipaddr[16], mac_buf[32], clientMac[18];
	memset(ipaddr, 0, sizeof(ipaddr));
	memset(mac_buf, 0, sizeof(mac_buf));
	memset(clientMac, 0, sizeof(clientMac));
#endif

	NMP_DEBUG("### Start ARP file parser scan\n");
	if ((fp = fopen(ARP_PATH, "r"))) {
		int arp_count = 0;
		while ( line_buf = fgets(line_buf_s, sizeof(line_buf_s), fp) ) {
			arp_count++;
			sscanf(line_buf, "%s%*s%s%s%*s%s\n", ipBuff, flags, macBuff, lanIf);

			if(strcmp(macBuff, "00:00:00:00:00:00") == 0) continue;

			NMP_DEBUG("arp check arp_count = %d : ipBuff = %s, flags = %s, macBuff = %s, lanIf = %s, subnet = %s\n\n", arp_count, ipBuff, flags, macBuff, lanIf, subnet);
			
			if(lanIf){
				// if(!strncmp(lanIf, subnet, 3) && strncmp(flags, "0x0", 3)) {   // (INTERFACE = br0 (Device) 
				if(!strcmp(lanIf, subnet) && strncmp(flags, "0x0", 3)) {
					sscanf(ipBuff, "%hhu.%hhu.%hhu.%hhu\0", &cip[0], &cip[1], &cip[2], &cip[3]);
					sscanf(macBuff, "%hhX:%hhX:%hhX:%hhX:%hhX:%hhX", &cmac[0], &cmac[1], &cmac[2], &cmac[3], &cmac[4], &cmac[5]);
					NMP_DEBUG("arp connect IP:%s, MAC:%s\n", ipBuff, macBuff);

					dhcp_mac = FindDevice(cip, cmac, 1);
#ifdef RTCONFIG_AMAS
					//only static client can't find MAC in dhcp list, search CFG
					if(!dhcp_mac) {
						int js_lock;
						js_lock = file_lock(CLIENTLIST_FILE_LOCK);
						allClientList = json_object_from_file(CLIENT_LIST_JSON_PATH);
						file_unlock(js_lock);

						sprintf(mac_buf, "%02X:%02X:%02X:%02X:%02X:%02X", cmac[0], cmac[1], cmac[2], cmac[3], cmac[4], cmac[5]);
						/* replace client mac if needed */
						sprintf(ipaddr, "%d.%d.%d.%d", cip[0], cip[1], cip[2], cip[3]);

						snprintf(clientMac, sizeof(clientMac), "%s", mac_buf);
						if (allClientList && (is_RE_client = get_amas_client_mac(allClientList, ipaddr, clientMac, sizeof(clientMac)))) {
							memset(mac_buf, 0, sizeof(mac_buf));
							snprintf(mac_buf, sizeof(mac_buf), "%s", clientMac);
						}
						json_object_put(allClientList);
						if (is_re_node(mac_buf, 1))
							continue;
						if(is_RE_client) {
							sscanf(mac_buf, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &cmac[0], &cmac[1], &cmac[2], &cmac[3], &cmac[4], &cmac[5]);
						}
						NMP_DEBUG("CFG filter IP:%d.%d.%d.%d, MAC:%s\n", cip[0], cip[1], cip[2], cip[3], mac_buf);
					}
#endif

					for(i = 0; i < p_client_detail_info_tab->ip_mac_num; i++) {

						NMP_DEBUG("*handle_client_list_from_arp, DBG dump client list, No.%d >> %d.%d.%d.%d-%02X:%02X:%02X:%02X:%02X:%02X\n", i + 1,
							p_client_detail_info_tab->ip_addr[i][0],p_client_detail_info_tab->ip_addr[i][1],
							p_client_detail_info_tab->ip_addr[i][2],p_client_detail_info_tab->ip_addr[i][3],
							p_client_detail_info_tab->mac_addr[i][0],p_client_detail_info_tab->mac_addr[i][1],
							p_client_detail_info_tab->mac_addr[i][2],p_client_detail_info_tab->mac_addr[i][3],
							p_client_detail_info_tab->mac_addr[i][4],p_client_detail_info_tab->mac_addr[i][5]);

						ip_dup = memcmp(p_client_detail_info_tab->ip_addr[i], cip, 4);
						mac_dup = memcmp(p_client_detail_info_tab->mac_addr[i], cmac, 6);
						if( ip_dup ) {
							if( mac_dup ) {
								continue;
							}	else { //MAC repeat
								dhcp_ip = FindDevice(cip, cmac, 0);
								if (dhcp_ip) {

									NMP_DEBUG("get dhcp_ip, IP changed. Refill client list.\n");
									NMP_DEBUG("*CMP %d.%d.%d.%d-%02X:%02X:%02X:%02X:%02X:%02X, device_flag = FLAG_EXIST\n",
										p_client_detail_info_tab->ip_addr[i][0],p_client_detail_info_tab->ip_addr[i][1],
										p_client_detail_info_tab->ip_addr[i][2],p_client_detail_info_tab->ip_addr[i][3],
										p_client_detail_info_tab->mac_addr[i][0],p_client_detail_info_tab->mac_addr[i][1],
										p_client_detail_info_tab->mac_addr[i][2],p_client_detail_info_tab->mac_addr[i][3],
										p_client_detail_info_tab->mac_addr[i][4],p_client_detail_info_tab->mac_addr[i][5]);

									lock = file_lock("networkmap");
									memcpy(p_client_detail_info_tab->ip_addr[i], cip, sizeof(p_client_detail_info_tab->ip_addr[i]));
									p_client_detail_info_tab->device_flag[i] |= (1<<FLAG_EXIST);
									file_unlock(lock);
									break;
								}
								else {
									/* duplicate entry upon static IP: replace IP when original arp entry not exist */
									if(!(p_client_detail_info_tab->device_flag[i] & (1<<FLAG_EXIST))) {
										NMP_DEBUG("duplicate entry upon static IP: replace IP when original arp entry not exist\n");
										memcpy(p_client_detail_info_tab->ip_addr[i], cip, sizeof(p_client_detail_info_tab->ip_addr[i]));
										p_client_detail_info_tab->device_flag[i] |= (1<<FLAG_EXIST);
									}
									break;
								}
							}
						}
						else if( !ip_dup ) {
							if( !mac_dup ) {
								lock = file_lock("networkmap");
								p_client_detail_info_tab->device_flag[i] |= (1<<FLAG_EXIST);
								file_unlock(lock);
								NMP_DEBUG("handle_client_list_from_arp , get same ip && mac, set device_flag = FLAG_EXIST\n");
								break;
							}
							else {
								NMP_DEBUG("handle_client_list_from_arp , IP assigned to another device. Refill client list.\n");
								NMP_DEBUG("*CMP %d.%d.%d.%d-%02X:%02X:%02X:%02X:%02X:%02X\n",
									p_client_detail_info_tab->ip_addr[i][0],p_client_detail_info_tab->ip_addr[i][1],
									p_client_detail_info_tab->ip_addr[i][2],p_client_detail_info_tab->ip_addr[i][3],
									p_client_detail_info_tab->mac_addr[i][0],p_client_detail_info_tab->mac_addr[i][1],
									p_client_detail_info_tab->mac_addr[i][2],p_client_detail_info_tab->mac_addr[i][3],
									p_client_detail_info_tab->mac_addr[i][4],p_client_detail_info_tab->mac_addr[i][5]);
								lock = file_lock("networkmap");
								memcpy(p_client_detail_info_tab->mac_addr[i], cmac, sizeof(p_client_detail_info_tab->mac_addr[i]));
								p_client_detail_info_tab->device_flag[i] |= (1<<FLAG_EXIST);
								file_unlock(lock);
								break;
							}
						}
					}

					/* i=0, table is empty.
					   i=num, no the same ip at table.*/
					if( i == p_client_detail_info_tab->ip_mac_num){
#if defined(RTCONFIG_NOTIFICATION_CENTER)
						call_notify_center_DEV_UPDATE();
#endif
						lock = file_lock("networkmap");

						// set mac, ip, device_flag
						memcpy(p_client_detail_info_tab->ip_addr[p_client_detail_info_tab->ip_mac_num], 
							cip, sizeof(p_client_detail_info_tab->ip_addr[p_client_detail_info_tab->ip_mac_num]));
						memcpy(p_client_detail_info_tab->mac_addr[p_client_detail_info_tab->ip_mac_num],
							cmac, sizeof(p_client_detail_info_tab->mac_addr[p_client_detail_info_tab->ip_mac_num]));
						p_client_detail_info_tab->device_flag[p_client_detail_info_tab->ip_mac_num] |= (1<<FLAG_EXIST);

						NMP_DEBUG("*No.%d, device_flag = FLAG_EXIST, ip_addr = %d.%d.%d.%d, mac_addr = %02X:%02X:%02X:%02X:%02X:%02X\n", i,
							p_client_detail_info_tab->ip_addr[i][0],p_client_detail_info_tab->ip_addr[i][1],
							p_client_detail_info_tab->ip_addr[i][2],p_client_detail_info_tab->ip_addr[i][3],
							p_client_detail_info_tab->mac_addr[i][0],p_client_detail_info_tab->mac_addr[i][1],
							p_client_detail_info_tab->mac_addr[i][2],p_client_detail_info_tab->mac_addr[i][3],
							p_client_detail_info_tab->mac_addr[i][4],p_client_detail_info_tab->mac_addr[i][5]);


#ifdef RTCONFIG_BONJOUR
						QuerymDNSInfo(p_client_detail_info_tab, i);
#endif
#ifdef RTCONFIG_UPNPC
						QuerymUPnPCInfo(p_client_detail_info_tab, i);
#endif
						//Find Asus Device, if not found, fill oui info
						QueryAsusOuiInfo(p_client_detail_info_tab, i);

						/* nothing to do if client is recognized as ASUS device already*/
						if(!(p_client_detail_info_tab->device_flag[i] & (1<<FLAG_ASUS))) {

							// Search vendor class or OUI DB
							QueryVendorOuiInfo(p_client_detail_info_tab, i);

							NMP_DEBUG("%s(): device_name = %s, vendor_name = %s, vendorClass :  %s, os_type = %d, type = %d \n", __FUNCTION__, p_client_detail_info_tab->device_name[i], p_client_detail_info_tab->vendor_name[i], p_client_detail_info_tab->vendorClass[i], p_client_detail_info_tab->os_type[i], p_client_detail_info_tab->type[i]);

#if (defined(RTCONFIG_BWDPI) || defined(RTCONFIG_BWDPI_DEP))
							if(nvram_get_int("sw_mode") == SW_MODE_ROUTER) {
								if(check_bwdpi_nvram_setting()) {
									NMP_DEBUG("BWDPI ON!\n");
									QueryBwdpiInfo(p_client_detail_info_tab, i);
								}
							}
#endif
							FindHostname(p_client_detail_info_tab, i);
						}
						StringChk(p_client_detail_info_tab->device_name[i]);

						// set is_wireless , conn_ts
						check_wrieless_info(p_client_detail_info_tab, i, 1, NULL);

#ifdef RTCONFIG_MULTILAN_CFG
						int subnet_idx = 0;
						if(!strncmp(lanIf, subnet, 4) && strncmp(flags, "0x0", 3)) {
							
							subnet_idx = get_subnet_idx(subnet);
							p_client_detail_info_tab->sdn_idx[i] = get_sdn_idx(subnet_idx);
						}
						NMP_DEBUG("##### p_client_detail_info_tab->subnet_idx = %d, sdn_idx = %d \n", subnet_idx, p_client_detail_info_tab->sdn_idx[i]);
#endif
						NMP_DEBUG("handle_client_list_from_arp_table, Fill: %d, ip : %d, -> %d.%d.%d.%d-%02X:%02X:%02X:%02X:%02X:%02X, wireless = %d, is_wireless = %d, conn_ts = %d\n",
						i, p_client_detail_info_tab->ip_mac_num,
						p_client_detail_info_tab->ip_addr[i][0], p_client_detail_info_tab->ip_addr[i][1],
						p_client_detail_info_tab->ip_addr[i][2], p_client_detail_info_tab->ip_addr[i][3],
						p_client_detail_info_tab->mac_addr[i][0],p_client_detail_info_tab->mac_addr[i][1],
						p_client_detail_info_tab->mac_addr[i][2],p_client_detail_info_tab->mac_addr[i][3],
						p_client_detail_info_tab->mac_addr[i][4],p_client_detail_info_tab->mac_addr[i][5],
						p_client_detail_info_tab->wireless[i],
						p_client_detail_info_tab->is_wireless[i],
						p_client_detail_info_tab->conn_ts[i]);

						p_client_detail_info_tab->online[i] = 1;
						p_client_detail_info_tab->ip_mac_num++;

						file_unlock(lock);
					}//if(i == p_client_detail_info_tab->ip_mac_num)
				}//if(!strncmp(lanIf, "br0", 3))
			}//if(lanIf)
		}//fgets
		fclose(fp);
	}//fopen
}

void
handle_client_list(P_CLIENT_DETAIL_INFO_TABLE p_client_detail_info_tab, char *buf, unsigned char *src_ip, int scanCount)
{
	int i, lock;
	ARP_HEADER * arp_ptr;
	unsigned short msg_type;
	int ip_dup, mac_dup, dhcp_mac = 0, dhcp_ip = 0;
	char gateway_ipaddr[17];
	struct sockaddr_in gateway_addr_ne;
	struct in_addr gateway_ipaddr_he;
	uint32_t gateway_ipaddr_ne;

#ifdef RTCONFIG_AMAS
	struct json_object *allClientList = NULL;
	int is_RE_client = 0;
	char ipaddr[16], mac_buf[32], clientMac[18];
	memset(ipaddr, 0, sizeof(ipaddr));
	memset(mac_buf, 0, sizeof(mac_buf));
	memset(clientMac, 0, sizeof(clientMac));
#endif

	arp_ptr = (ARP_HEADER*)(buf);

	if (nvram_get_int("sw_mode") == SW_MODE_AP || nvram_get_int("sw_mode") == SW_MODE_REPEATER)
	{
		//Get gateway's IP
		strcpy(gateway_ipaddr, nvram_safe_get("lan_gateway"));
		inet_aton(gateway_ipaddr, &gateway_addr_ne.sin_addr);
		gateway_ipaddr_he.s_addr = ntohl(gateway_addr_ne.sin_addr.s_addr);
		gateway_ipaddr_ne = htonl(gateway_ipaddr_he.s_addr);
	}

	//Check ARP packet if source ip and router ip at the same network
	if( !memcmp(src_ip, arp_ptr->source_ipaddr, 3) ) {
		msg_type = ntohs(arp_ptr->message_type);
		//ARP packet to router
		if(
			(arp_skt && msg_type == 0x02 &&					// do not handle response arp in router mode
			  memcmp(arp_ptr->dest_ipaddr, src_ip, 4) == 0 &&		// dest IP
			  memcmp(arp_ptr->dest_hwaddr, my_hwaddr, 6) == 0)		// dest MAC
			||
			(msg_type == 0x01 &&						// ARP request
			  memcmp(arp_ptr->dest_ipaddr, src_ip, 4) == 0)			// dest IP
			||
			(msg_type == 0x01 &&						// ARP request
			  memcmp(arp_ptr->dest_ipaddr, &gateway_ipaddr_ne, 4) == 0)	// dest IP PAP src IP
		){
			NMP_DEBUG("*It's an ARP Response to Router!\n");
			NMP_DEBUG("*RCV %d.%d.%d.%d-%02X, mac:%02X:%02X:%02X:%02X:%02X, scanCount : %d, msg_type: %02x,IP num:%d\n",
					arp_ptr->source_ipaddr[0],arp_ptr->source_ipaddr[1],
					arp_ptr->source_ipaddr[2],arp_ptr->source_ipaddr[3],
					arp_ptr->source_hwaddr[0],arp_ptr->source_hwaddr[1],
					arp_ptr->source_hwaddr[2],arp_ptr->source_hwaddr[3],
					arp_ptr->source_hwaddr[4],arp_ptr->source_hwaddr[5], scanCount, msg_type, p_client_detail_info_tab->ip_mac_num);
			NMP_DEBUG("*DEST IP %d.%d.%d.%d,  sw_mode = %d\n",
					arp_ptr->dest_ipaddr[0],arp_ptr->dest_ipaddr[1],
					arp_ptr->dest_ipaddr[2],arp_ptr->dest_ipaddr[3],
					nvram_get_int("sw_mode"));

			dhcp_mac = FindDevice(arp_ptr->source_ipaddr, arp_ptr->source_hwaddr, 1);

#ifdef RTCONFIG_AMAS
			//only static client can't find MAC in dhcp list, search CFG
			if(!dhcp_mac) {

				int js_lock;
				js_lock = file_lock(CLIENTLIST_FILE_LOCK);
				allClientList = json_object_from_file(CLIENT_LIST_JSON_PATH);
				file_unlock(js_lock);

				sprintf(mac_buf, "%02X:%02X:%02X:%02X:%02X:%02X",
					arp_ptr->source_hwaddr[0], arp_ptr->source_hwaddr[1], arp_ptr->source_hwaddr[2],
					arp_ptr->source_hwaddr[3], arp_ptr->source_hwaddr[4], arp_ptr->source_hwaddr[5]);
				/* replace client mac if needed */
				sprintf(ipaddr, "%d.%d.%d.%d",
					arp_ptr->source_ipaddr[0],arp_ptr->source_ipaddr[1],
					arp_ptr->source_ipaddr[2],arp_ptr->source_ipaddr[3]);

				snprintf(clientMac, sizeof(clientMac), "%s", mac_buf);
				if (allClientList && (is_RE_client = get_amas_client_mac(allClientList, ipaddr, clientMac, sizeof(clientMac)))) {
					memset(mac_buf, 0, sizeof(mac_buf));
					snprintf(mac_buf, sizeof(mac_buf), "%s", clientMac);
				}
				json_object_put(allClientList);
				if (is_re_node(mac_buf, 1))
					return;

				if(is_RE_client) {
					sscanf(mac_buf, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
					&arp_ptr->source_hwaddr[0], &arp_ptr->source_hwaddr[1], &arp_ptr->source_hwaddr[2],
					&arp_ptr->source_hwaddr[3], &arp_ptr->source_hwaddr[4], &arp_ptr->source_hwaddr[5]);
				}
				NMP_DEBUG("CFG filter IP:%s, MAC:%s, is_RE_client : %d\n", ipaddr, mac_buf, is_RE_client);
			}
#endif

			NMP_DEBUG("handle_client_list, detail_info_num : %d,  ip_mac_num : %d\n", p_client_detail_info_tab->detail_info_num, p_client_detail_info_tab->ip_mac_num);

			for(i = 0; i < p_client_detail_info_tab->ip_mac_num; i++) {

				NMP_DEBUG("handle_client_list : DBG dump client list, No.%d >> %d.%d.%d.%d-%02X:%02X:%02X:%02X:%02X:%02X, wireless = %d, is_wireless = %d, conn_ts = %d,\n", i,
						p_client_detail_info_tab->ip_addr[i][0],p_client_detail_info_tab->ip_addr[i][1],
						p_client_detail_info_tab->ip_addr[i][2],p_client_detail_info_tab->ip_addr[i][3],
						p_client_detail_info_tab->mac_addr[i][0],p_client_detail_info_tab->mac_addr[i][1],
						p_client_detail_info_tab->mac_addr[i][2],p_client_detail_info_tab->mac_addr[i][3],
						p_client_detail_info_tab->mac_addr[i][4],p_client_detail_info_tab->mac_addr[i][5],
						p_client_detail_info_tab->wireless[i],
						p_client_detail_info_tab->is_wireless[i],
						p_client_detail_info_tab->conn_ts[i]);

				ip_dup = memcmp(p_client_detail_info_tab->ip_addr[i], arp_ptr->source_ipaddr, 4);
				mac_dup = memcmp(p_client_detail_info_tab->mac_addr[i], arp_ptr->source_hwaddr, 6);
				if( ip_dup ) {
					if( mac_dup ) {
						continue;
					}
					else { //MAC repeat
						dhcp_mac = FindDevice(arp_ptr->source_ipaddr, arp_ptr->source_hwaddr, 0);
						if (dhcp_ip) {
							NMP_DEBUG("get dhcp_ip, IP changed. Refill client list.\n");
							NMP_DEBUG("*CMP %d.%d.%d.%d-%02X:%02X:%02X:%02X:%02X:%02X, , device_flag = FLAG_EXIST\n",
								p_client_detail_info_tab->ip_addr[i][0],p_client_detail_info_tab->ip_addr[i][1],
								p_client_detail_info_tab->ip_addr[i][2],p_client_detail_info_tab->ip_addr[i][3],
								p_client_detail_info_tab->mac_addr[i][0],p_client_detail_info_tab->mac_addr[i][1],
								p_client_detail_info_tab->mac_addr[i][2],p_client_detail_info_tab->mac_addr[i][3],
								p_client_detail_info_tab->mac_addr[i][4],p_client_detail_info_tab->mac_addr[i][5]);
							lock = file_lock("networkmap");
							memcpy(p_client_detail_info_tab->ip_addr[i], arp_ptr->source_ipaddr, sizeof(p_client_detail_info_tab->ip_addr[i]));
							p_client_detail_info_tab->device_flag[i] |= (1<<FLAG_EXIST);
							p_client_detail_info_tab->online[i] = 1;
							file_unlock(lock);
							break;
						}
						else {
							/* duplicate entry upon static IP: replace IP when original arp entry not exist */
							if(!(p_client_detail_info_tab->device_flag[i] & (1<<FLAG_EXIST))) {
								NMP_DEBUG("duplicate entry upon static IP: replace IP when original arp entry not exist\n");
								memcpy(p_client_detail_info_tab->ip_addr[i], arp_ptr->source_ipaddr, sizeof(p_client_detail_info_tab->ip_addr[i]));
								p_client_detail_info_tab->device_flag[i] |= (1<<FLAG_EXIST);
								p_client_detail_info_tab->online[i] = 1;
							}
							break;
						}
					}
				}
				if( !ip_dup ) {
					if( !mac_dup ) {
						lock = file_lock("networkmap");
						NMP_DEBUG("handle_client_list , get same ip && mac, set device_flag = FLAG_EXIST, check wireless type = %d, connect time = %d\n", p_client_detail_info_tab->is_wireless[i], p_client_detail_info_tab->conn_ts[i]);
						p_client_detail_info_tab->device_flag[i] |= (1<<FLAG_EXIST);
						p_client_detail_info_tab->online[i] = 1;
						file_unlock(lock);
						break;
					}
					else {
						NMP_DEBUG("handle_client_list : IP assigned to another device. Refill client list.\n");
						NMP_DEBUG("*CMP %d.%d.%d.%d-%02X:%02X:%02X:%02X:%02X:%02X\n",
								p_client_detail_info_tab->ip_addr[i][0],p_client_detail_info_tab->ip_addr[i][1],
								p_client_detail_info_tab->ip_addr[i][2],p_client_detail_info_tab->ip_addr[i][3],
								p_client_detail_info_tab->mac_addr[i][0],p_client_detail_info_tab->mac_addr[i][1],
								p_client_detail_info_tab->mac_addr[i][2],p_client_detail_info_tab->mac_addr[i][3],
								p_client_detail_info_tab->mac_addr[i][4],p_client_detail_info_tab->mac_addr[i][5]);
						lock = file_lock("networkmap");
						memcpy(p_client_detail_info_tab->mac_addr[i], arp_ptr->source_hwaddr, sizeof(p_client_detail_info_tab->mac_addr[i]));
						p_client_detail_info_tab->device_flag[i] |= (1<<FLAG_EXIST);
						p_client_detail_info_tab->online[i] = 1;
						file_unlock(lock);
						break;
					}
				}
			}

			/* i=0, table is empty.
			   i=num, no the same ip at table.*/
			if(i == p_client_detail_info_tab->ip_mac_num){

#if defined(RTCONFIG_NOTIFICATION_CENTER)
				call_notify_center_DEV_UPDATE();
#endif
				lock = file_lock("networkmap");
				memcpy(p_client_detail_info_tab->ip_addr[p_client_detail_info_tab->ip_mac_num], 
					arp_ptr->source_ipaddr, sizeof(p_client_detail_info_tab->ip_addr[p_client_detail_info_tab->ip_mac_num]));
				memcpy(p_client_detail_info_tab->mac_addr[p_client_detail_info_tab->ip_mac_num],
					arp_ptr->source_hwaddr, sizeof(p_client_detail_info_tab->mac_addr[p_client_detail_info_tab->ip_mac_num]));
				p_client_detail_info_tab->device_flag[p_client_detail_info_tab->ip_mac_num] |= (1<<FLAG_EXIST);

#ifdef RTCONFIG_BONJOUR
				QuerymDNSInfo(p_client_detail_info_tab, i);
#endif
#ifdef RTCONFIG_UPNPC
				QuerymUPnPCInfo(p_client_detail_info_tab, i);
#endif
				//Find Asus Device, if not found, fill oui info
				QueryAsusOuiInfo(p_client_detail_info_tab, i);

				/* nothing to do if client is recognized as ASUS device already*/
				if(!(p_client_detail_info_tab->device_flag[i] & (1<<FLAG_ASUS))) {
					// Search vendor class or OUI DB
					QueryVendorOuiInfo(p_client_detail_info_tab, i);

					NMP_DEBUG("%s(): device_name = %s, vendor_name = %s, vendorClass :  %s, os_type = %d, type = %d \n", __FUNCTION__, p_client_detail_info_tab->device_name[i], p_client_detail_info_tab->vendor_name[i], p_client_detail_info_tab->vendorClass[i], p_client_detail_info_tab->os_type[i], p_client_detail_info_tab->type[i]);

#if (defined(RTCONFIG_BWDPI) || defined(RTCONFIG_BWDPI_DEP))
					if(nvram_get_int("sw_mode") == SW_MODE_ROUTER) {
						if(check_bwdpi_nvram_setting()) {
							NMP_DEBUG("BWDPI ON!\n");
							QueryBwdpiInfo(p_client_detail_info_tab, i);
						}
					}
#endif
					FindHostname(p_client_detail_info_tab, i);
				}
				StringChk(p_client_detail_info_tab->device_name[i]);

				// set is_wireless , conn_ts
				check_wrieless_info(p_client_detail_info_tab, i, 1, NULL);

				NMP_DEBUG("Fill: %d-> %d.%d.%d.%d-%02X:%02X:%02X:%02X:%02X:%02X wireless = %d, is_wireless = %d, conn_ts = %d,\n", i,
						p_client_detail_info_tab->ip_addr[i][0],
						p_client_detail_info_tab->ip_addr[i][1],
						p_client_detail_info_tab->ip_addr[i][2],
						p_client_detail_info_tab->ip_addr[i][3],
						p_client_detail_info_tab->mac_addr[i][0],p_client_detail_info_tab->mac_addr[i][1],
						p_client_detail_info_tab->mac_addr[i][2],p_client_detail_info_tab->mac_addr[i][3],
						p_client_detail_info_tab->mac_addr[i][4],p_client_detail_info_tab->mac_addr[i][5],
						p_client_detail_info_tab->wireless[i],
						p_client_detail_info_tab->is_wireless[i],
						p_client_detail_info_tab->conn_ts[i]);

				p_client_detail_info_tab->online[i] = 1;
				p_client_detail_info_tab->ip_mac_num++;

				file_unlock(lock);
			}
		}//ARP packet to router
	}//Source IP in the same subnetwork
}

void handle_detail_client_list(P_CLIENT_DETAIL_INFO_TABLE p_client_detail_info_tab)
{
	int lock;

	if(p_client_detail_info_tab->detail_info_num < p_client_detail_info_tab->ip_mac_num) {

		NMP_DEBUG("handle_detail_client_list Scan ! detail_info_num = %d, ip_mac_num = %d\n", p_client_detail_info_tab->detail_info_num, p_client_detail_info_tab->ip_mac_num);
		
		lock = file_lock("networkmap");

		QueryAsusOuiInfo(p_client_detail_info_tab, p_client_detail_info_tab->detail_info_num);

		/* nothing to do if client is recognized as ASUS device already*/
		if(!(p_client_detail_info_tab->device_flag[p_client_detail_info_tab->detail_info_num] & (1<<FLAG_ASUS))) {
									
			// Search vendor class or OUI DB
			QueryVendorOuiInfo(p_client_detail_info_tab, p_client_detail_info_tab->detail_info_num);

			NMP_DEBUG("%s(): device_name = %s, vendor_name = %s, vendorClass :  %s, os_type = %d, type = %d \n", __FUNCTION__, p_client_detail_info_tab->device_name[p_client_detail_info_tab->detail_info_num], p_client_detail_info_tab->vendor_name[p_client_detail_info_tab->detail_info_num], p_client_detail_info_tab->vendorClass[p_client_detail_info_tab->detail_info_num], p_client_detail_info_tab->os_type[p_client_detail_info_tab->detail_info_num], p_client_detail_info_tab->type[p_client_detail_info_tab->detail_info_num]);

#if (defined(RTCONFIG_BWDPI) || defined(RTCONFIG_BWDPI_DEP))
			if(nvram_get_int("sw_mode") == SW_MODE_ROUTER) {
				if(check_bwdpi_nvram_setting()) {
					NMP_DEBUG("BWDPI ON!\n");
					QueryBwdpiInfo(p_client_detail_info_tab, p_client_detail_info_tab->detail_info_num);
				}
			}
#endif
			FindHostname(p_client_detail_info_tab, p_client_detail_info_tab->detail_info_num);
			if(!strcmp(p_client_detail_info_tab->ipMethod[p_client_detail_info_tab->detail_info_num], "")) {
				NMP_DEBUG("Static client found!\n");
				strlcpy(p_client_detail_info_tab->ipMethod[p_client_detail_info_tab->detail_info_num], "Static", 
					sizeof(p_client_detail_info_tab->ipMethod[p_client_detail_info_tab->detail_info_num]));
			}
		}

		StringChk(p_client_detail_info_tab->device_name[p_client_detail_info_tab->detail_info_num]);

		// set is_wireless : type  , conn_ts : last connet time 
		check_wrieless_info(p_client_detail_info_tab, p_client_detail_info_tab->detail_info_num, 1, NULL);

		//check wireless device & set flag
		find_wireless_device(p_client_detail_info_tab, 0);
		NMP_DEBUG("handle_detail_client_list, detail_info_num = %d, wireless: %d\n", p_client_detail_info_tab->detail_info_num, p_client_detail_info_tab->wireless[p_client_detail_info_tab->detail_info_num]);

		/* check android device with vendor ASUS -> ZenFone*/
		if(p_client_detail_info_tab->type[p_client_detail_info_tab->detail_info_num] == 9 &&
			strstr(p_client_detail_info_tab->vendor_name[p_client_detail_info_tab->detail_info_num], "ASUS"))
			p_client_detail_info_tab->type[p_client_detail_info_tab->detail_info_num] = 28;

		file_unlock(lock);

#ifdef NMP_DB
		/* Check if DB memory size over limit */
		if (check_database_size()) write_to_DB(p_client_detail_info_tab, nmp_cl_json);
#endif

		p_client_detail_info_tab->detail_info_num++;
		NMP_DEBUG("Finish Deep Scan no.%d!\n", p_client_detail_info_tab->detail_info_num);

	} else {

#ifdef NMP_DB
		if( (p_client_detail_info_tab->commit_no != p_client_detail_info_tab->detail_info_num) || client_updated ) {
			NMP_DEBUG("Write to DB file!\n");
			lock = file_lock("networkmap");
			p_client_detail_info_tab->commit_no = p_client_detail_info_tab->detail_info_num;
			file_unlock(lock);
			json_object_to_file(NMP_CL_JSON_FILE, nmp_cl_json); 
			client_updated = 0;
			NMP_DEBUG("Finish Write to DB file!\n");
		}
#endif

		if(networkmap_fullscan == SCAN_DONE) {

			// receive UI(web.c) message trigger
			if( nvram_match("nmp_wl_offline_check", "1")) {

				if( nvram_get_int("cfg_master") ) {

					if( (nvram_get_int("sw_mode") == SW_MODE_ROUTER) || (nvram_get_int("sw_mode") == SW_MODE_AP) ) {

						check_wireless_clientlist(p_client_detail_info_tab);
					}

				} else {

					if( nvram_get_int("sw_mode") == SW_MODE_ROUTER ) {
	
						check_wireless_clientlist(p_client_detail_info_tab);

					} else {

						// check if wireless device [online / offline]
						lock = file_lock("networkmap");
						find_wireless_device(p_client_detail_info_tab, 1);
						file_unlock(lock);

					}

				}

			} else {

				// check connect device : periodic time
				regularly_check_devices(p_client_detail_info_tab);

			}
		}
	}
}

#define CLIENT_WIRED 0
#define CLIENT_WLAN_2G 1
#define CLIENT_WLAN_5G_1 2
#define CLIENT_WLAN_5G_2 3

void count_num_of_clients(void)
{
	int index = 0;
	unsigned int client_amounts[4] = {0};

	NMP_CONSOLE_DEBUG("[count_num_of_clients]p_client_detail_info_tab->ip_mac_num=%d\n", p_client_detail_info_tab->ip_mac_num);
	NMP_CONSOLE_DEBUG("[count_num_of_clients]p_client_detail_info_tab->detail_info_num=%d\n", p_client_detail_info_tab->detail_info_num);

	if(p_client_detail_info_tab->detail_info_num < p_client_detail_info_tab->ip_mac_num)
	{
		return;
	}

	for(index = 0; index <MAX_NR_CLIENT_LIST; index++)
	{
		if(p_client_detail_info_tab->device_flag[index] & (1<<FLAG_EXIST))
		{
			NMP_CONSOLE_DEBUG("-----[%02d]-----\n", index);
			NMP_CONSOLE_DEBUG("[count_num_of_clients]p_client_detail_info_tab->device_flag=%d\n", p_client_detail_info_tab->device_flag[index]);
			NMP_CONSOLE_DEBUG("[count_num_of_clients]p_client_detail_info_tab->wireless=%d\n", p_client_detail_info_tab->wireless[index]);
			switch(p_client_detail_info_tab->wireless[index])
			{
				case CLIENT_WIRED:
					client_amounts[CLIENT_WIRED]++;
					break;
				case CLIENT_WLAN_2G:
					client_amounts[CLIENT_WLAN_2G]++;
					break;
				case CLIENT_WLAN_5G_1:
					client_amounts[CLIENT_WLAN_5G_1]++;
					break;
				case CLIENT_WLAN_5G_2:
					client_amounts[CLIENT_WLAN_5G_2]++;
					break;
				default:
					cprintf("[count_num_of_clients]Error!!Should not come here!!!\n");
					break;
			}
		}
	}

	NMP_CONSOLE_DEBUG("[count_num_of_clients]%d, %d, %d, %d\n", client_amounts[CLIENT_WIRED], client_amounts[CLIENT_WLAN_2G], client_amounts[CLIENT_WLAN_5G_1], client_amounts[CLIENT_WLAN_5G_2]);

	nvram_set_int("fb_nmp_wired", client_amounts[CLIENT_WIRED]);
	nvram_set_int("fb_nmp_wlan_2g", client_amounts[CLIENT_WLAN_2G]);
	nvram_set_int("fb_nmp_wlan_5g_1", client_amounts[CLIENT_WLAN_5G_1]);
	nvram_set_int("fb_nmp_wlan_5g_2", client_amounts[CLIENT_WLAN_5G_2]);

	nvram_set("fb_nmp_scan", "0");
}

#ifdef RTCONFIG_AMAS_WGN
static int get_wl_ifnames()
{
	char wl[128] = {0}, *next = NULL;

	int count = 0;
	foreach(wl, nvram_safe_get("wl_ifnames"), next) {
		count++;
	}
	return count;
}
#endif

static uint32 wl_assoclist(char *ifname, char * mac)
{
	char cmd[64], buf[1024], assoclist_mac[20] = {0};
	FILE *pfp = NULL;
	char *p;
	uint32 txframe = -1;

	snprintf(cmd, sizeof(cmd), "wl -i %s assoclist", ifname);
	NMP_DEBUG("cmd = %s\n", cmd);
	pfp = popen(cmd, "r");
	if (pfp != NULL) {
		while (fgets(buf, sizeof(buf), pfp) != NULL) {
			NMP_DEBUG("buf = %s\n", buf);

			p = strstr(buf, "assoclist");
			if (p != NULL) {
				sscanf(p, "%*[^ ] %17s", assoclist_mac);
				toLowerCase(assoclist_mac);
				if(strcmp(mac, assoclist_mac) == 0) {
					txframe = 0;
					break;
				}
			}
		}
		pclose(pfp);
	}
	NMP_DEBUG("txframe = %d, mac = %s, assoclist_mac = %s\n", txframe, mac, assoclist_mac);

	return txframe;
}

int get_brctl_macs(char * mac)
{
	FILE *fp;
	char line_buf[128]; // max 7x

	int uplink_port_no = -1;
	int ret = 0;
	char mac_buf[30] = {0}, is_local[8] = {0};


	toLowerCase(mac);


	char cmd[64] = {0};
	snprintf(cmd, sizeof(cmd), "brctl showmacs %s > %s", nvram_safe_get("lan_ifname"), BRCTL_TABLE_PATH);
	system(cmd);

	NMP_DEBUG("mac = %s, cmd = %s\n", mac, cmd);
	if ((fp = fopen(BRCTL_TABLE_PATH, "r"))) {
/*  brctl showmacs br0 list
port no mac addr                is local?       ageing timer
  6     04:42:1a:df:7f:b0       no                 0.00
  1     04:d9:f5:b5:93:e0       yes                0.00
  6     04:d9:f5:b5:93:e4       yes                0.00
*/
		int i = 0;
		while ( fgets(line_buf, sizeof(line_buf), fp) ) {
			i++;
			if(i == 1) continue;	// ignore header
			
			// sscanf(line_buf, "%d %17s", &uplink_port_no, mac);
	        sscanf(line_buf, "%d%s%s%*s[^\n]", &uplink_port_no, mac_buf, is_local);
	        if(!strcmp(is_local, "no") && !strcmp(mac, mac_buf)) {
	         	ret = 1;
	         	break;
	        }
		}
		fclose(fp);
		unlink(BRCTL_TABLE_PATH);
	}

	return ret;
}

// setting : nmp_cl_json.js param -> wireless, is_wireless, conn_ts
// is_file : 1: use json file (need free) , 0: input json data (json clients)
int check_wrieless_info(P_CLIENT_DETAIL_INFO_TABLE p_client_detail_info_tab, const int i, const int is_file, struct json_object *clients) {

	struct json_object *wlClietListObj = NULL;

	// check json file
	if(is_file) {
		if(!check_if_file_exist(ALLWCLIENT_LIST_JSON_PATH)) {
			return 0;
		}
		int lock;
		lock = file_lock(ALLWEVENT_FILE_LOCK);
		wlClietListObj = json_object_from_file(ALLWCLIENT_LIST_JSON_PATH);
		file_unlock(lock);
	} else {
		wlClietListObj = clients;
	}

	int ret = 0;
	char mac[18];
	struct json_object *brMacObj = NULL, *bandObj = NULL, *macObj = NULL, *tsObj = NULL;

	snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
			p_client_detail_info_tab->mac_addr[i][0], p_client_detail_info_tab->mac_addr[i][1],
			p_client_detail_info_tab->mac_addr[i][2], p_client_detail_info_tab->mac_addr[i][3],
			p_client_detail_info_tab->mac_addr[i][4], p_client_detail_info_tab->mac_addr[i][5] );

	if (wlClietListObj) {
		json_object_object_foreach(wlClietListObj, key, val) {
			brMacObj = val;
			if(strcmp(key, mac) == 0)
				ret = 1;

			json_object_object_foreach(brMacObj, key, val) {
				bandObj = val;
				unsigned char wireless_type = 0;

				// int wireless_type = 0;
				if (strstr(key, "2G")) {				wireless_type = 1;
				} else if (strstr(key, "5G1")) {		wireless_type = 3;
				} else if (strstr(key, "5G")) {		wireless_type = 2;
				} else if (strstr(key, "6G")) {		wireless_type = 4;		}

				json_object_object_foreach(bandObj, key, val) {
					macObj = val;
					if(strcmp(key, mac) == 0) {
						json_object_object_get_ex(macObj, "ts", &tsObj);
						if(tsObj) {
							int conn_ts = json_object_get_int(tsObj);
							if( p_client_detail_info_tab->conn_ts[i] != conn_ts ) {
								client_updated = 1;
							}
							if(conn_ts > 0) {
								p_client_detail_info_tab->conn_ts[i] = conn_ts;	
								p_client_detail_info_tab->wireless[i] = wireless_type;
								p_client_detail_info_tab->is_wireless[i] = wireless_type;
							}
						}
						ret = 1;
					}
					if(ret) break; 
				}
				if(ret) break; 
			}
		}
		if(is_file)
			json_object_put(wlClietListObj);
	}

	return ret;

}

// check connect device : periodic time
void regularly_check_devices(P_CLIENT_DETAIL_INFO_TABLE p_client_detail_info_tab) {

	if(!check_all_device) {

		int clients_end_ts = time(NULL);

		if((clients_end_ts - clients_start_ts) > check_clients_interval) {
			NMP_DEBUG("clients_end_ts(%d) - clients_start_ts(%d) = %d > check_clients_interval(%d)\n", clients_end_ts, clients_start_ts, (clients_end_ts - clients_start_ts), check_clients_interval);
			check_all_device = 1;	// reset check connect device
			clients_start_ts = time(NULL);
		}

	} else {

		check_all_device = 0;

		if( p_client_detail_info_tab->detail_info_num == p_client_detail_info_tab->ip_mac_num ) {
			check_clientlist_offline(p_client_detail_info_tab);
		}
	}
}

void check_clientlist_offline(CLIENT_DETAIL_INFO_TABLE *p_client_detail_info_tab) {

	int i;
	char cmd[128];

	lock = file_lock("networkmap");

	for(i = 0; i < p_client_detail_info_tab->ip_mac_num; i++) {

		char ipaddr[18], mac_buf[32];

		snprintf(ipaddr, sizeof(ipaddr), "%d.%d.%d.%d", p_client_detail_info_tab->ip_addr[i][0], p_client_detail_info_tab->ip_addr[i][1], p_client_detail_info_tab->ip_addr[i][2], p_client_detail_info_tab->ip_addr[i][3] );
		snprintf(mac_buf, sizeof(mac_buf), "%02X:%02X:%02X:%02X:%02X:%02X", p_client_detail_info_tab->mac_addr[i][0], p_client_detail_info_tab->mac_addr[i][1], p_client_detail_info_tab->mac_addr[i][2], p_client_detail_info_tab->mac_addr[i][3], p_client_detail_info_tab->mac_addr[i][4], p_client_detail_info_tab->mac_addr[i][5] );

		NMP_DEBUG("regularly_check_devices, No.%d >> ip = %s, mac = %s, wireless = %d, is_wireless = %d, online = %d, conn_ts = %d, offline_time = %d\n", i, ipaddr, mac_buf,
			p_client_detail_info_tab->wireless[i], p_client_detail_info_tab->is_wireless[i], p_client_detail_info_tab->online[i], p_client_detail_info_tab->conn_ts[i], p_client_detail_info_tab->offline_time[i]);

		// if( p_client_detail_info_tab->wireless[i] == 0 ) {

			if(get_brctl_macs(mac_buf)) {

				p_client_detail_info_tab->online[i] = 1;
				p_client_detail_info_tab->offline_time[i] = 0;
				NMP_DEBUG("get brctl table mac,  mac = %s, online = 1, offline_time = %d\n", mac_buf, p_client_detail_info_tab->offline_time[i]);
				continue;

			} else {
				NMP_DEBUG("brctl table not mac, mac = %s, offline_time = %d\n", mac_buf, p_client_detail_info_tab->offline_time[i]);
				p_client_detail_info_tab->online[i] = 0;
			}
		// }

		if(p_client_detail_info_tab->online[i] == 0) {
			p_client_detail_info_tab->offline_time[i] += check_clients_interval;
		}
	}
	file_unlock(lock);

#if 0
	// check online = 0, delete arp [ip]
	for(i = 0; i < p_client_detail_info_tab->ip_mac_num; i++) {
		// 0 -> not find device (packet, clientlist, brctl info)
		if( (p_client_detail_info_tab->online[i] == 0) && (p_client_detail_info_tab->offline_time[i] > DEL_SHM_INTERVAL) ) {
			char ipaddr[16], cmd[128];
			snprintf(ipaddr, sizeof(ipaddr), "%d.%d.%d.%d", p_client_detail_info_tab->ip_addr[i][0], p_client_detail_info_tab->ip_addr[i][1], p_client_detail_info_tab->ip_addr[i][2], p_client_detail_info_tab->ip_addr[i][3] );
			eval("arp", "-d", ipaddr);
			NMP_DEBUG("arp -d ipaddr = %s\n", ipaddr);
		}
	}
#endif

}

// web server trigger clientlist offline check
int check_wireless_clientlist(CLIENT_DETAIL_INFO_TABLE *p_client_detail_info_tab) {

	NMP_DEBUG("check_wireless_clientlist, web server trigger wireless list offline check\n");

	struct json_object *wlClietListObj = NULL;

	lock = file_lock(ALLWEVENT_FILE_LOCK);
	wlClietListObj = json_object_from_file(ALLWCLIENT_LIST_JSON_PATH);
	file_unlock(lock);

	lock = file_lock("networkmap");

	if(wlClietListObj) {

		int i, ret = 0;

		for(i = 0; i < p_client_detail_info_tab->ip_mac_num; i++) {

			char ipaddr[16], mac_buf[32];

			snprintf(ipaddr, sizeof(ipaddr), "%d.%d.%d.%d", p_client_detail_info_tab->ip_addr[i][0], p_client_detail_info_tab->ip_addr[i][1], p_client_detail_info_tab->ip_addr[i][2], p_client_detail_info_tab->ip_addr[i][3] );
			snprintf(mac_buf, sizeof(mac_buf), "%02X:%02X:%02X:%02X:%02X:%02X", p_client_detail_info_tab->mac_addr[i][0], p_client_detail_info_tab->mac_addr[i][1],  p_client_detail_info_tab->mac_addr[i][2], p_client_detail_info_tab->mac_addr[i][3], p_client_detail_info_tab->mac_addr[i][4], p_client_detail_info_tab->mac_addr[i][5] );

			NMP_DEBUG("check_wireless_clientlist, No.%d >> ip = %s, mac = %s, wireless = %d, is_wireless = %d, online = %d, conn_ts = %d\n", i, ipaddr, mac_buf,
			p_client_detail_info_tab->wireless[i], p_client_detail_info_tab->is_wireless[i], p_client_detail_info_tab->online[i], p_client_detail_info_tab->conn_ts[i] );

			// check wireless mac(cap)
			if( check_wrieless_info(p_client_detail_info_tab, i, 0, wlClietListObj) ) {
				p_client_detail_info_tab->online[i] = 1;
				p_client_detail_info_tab->offline_time[i] = 0;
				NMP_DEBUG("after, online = %d\n", p_client_detail_info_tab->online[i] );
				continue;
			}

			if(p_client_detail_info_tab->wireless[i] == 0) {
				continue;
			}

			p_client_detail_info_tab->online[i] = 0;
		}

		json_object_put(wlClietListObj);
	}

	// local cap, wireless 
	find_wireless_device(p_client_detail_info_tab, 1);

	file_unlock(lock);

	return 0;
}

void network_ip_scan() {

	int segment = 1;
	struct in_addr netmask_ne;
	char ping_ip[16], cmd[128];
	uint32_t scan_ip_subnet_he, scan_ip_subnet_ne;

	if(! (inet_aton(nvram_get("lan_netmask")? : nvram_default_get("lan_netmask"), &netmask_ne) ) )  {
		NMP_DEBUG("lan_netmask  = NULL \n");
		return;
	}

	NMP_DEBUG("lan_netmask = %s\n", nvram_get("lan_netmask"));
	
	if(strcmp(nvram_get("lan_netmask"), "255.255.255.0") == 0) { 
		segment = 1;
	} else if(strcmp(nvram_get("lan_netmask"), "255.255.254.0") == 0) { 
		segment = 2;
	} else if(strcmp(nvram_get("lan_netmask"), "255.255.252.0") == 0) { 
		segment = 4;
	}

	scan_ip_subnet_he = my_ipaddr_he.s_addr & ntohl(netmask_ne.s_addr);
	scan_ip_subnet_ne = htonl(scan_ip_subnet_he);
	unsigned char * p_scan_ip_subnet_ne = (unsigned char*) &scan_ip_subnet_ne;

	NMP_DEBUG("ipaddr = %hhu.%hhu.%hhu.%hhu, lan_netmask = %s\n", p_scan_ip_subnet_ne[0], p_scan_ip_subnet_ne[1], p_scan_ip_subnet_ne[2], p_scan_ip_subnet_ne[3], nvram_get("lan_netmask"));

	int i, j;
	for(i = 0; i < segment; i++) {

		for(j = 1; j < 255; j++) {

			snprintf(ping_ip, sizeof(ping_ip), "%hhu.%hhu.%hhu.%d", p_scan_ip_subnet_ne[0], p_scan_ip_subnet_ne[1], p_scan_ip_subnet_ne[2] + i, j);
			snprintf(cmd, sizeof(cmd), "ping -c1 -w1 -s32 %s >/dev/null &", ping_ip);
			NMP_DEBUG("ping cmd = %s\n", cmd);
			system(cmd);

		}
	}
}

/******************************************/
int main(int argc, char *argv[])
{


	// check version : new db type 
	// cloud_db_process();

	int arp_packet_rcv = 0, arp_getlen, max_scan_count, deep_scan = 0;
	struct sockaddr_in router_addr_ne;
	struct in_addr netmask_ne;
	char router_ipaddr[17], router_mac[17], buffer[ARP_BUFFER_SIZE];
	uint32_t scan_ipaddr_he, scan_ipaddr_ne;
	struct timeval *arp_timeout;
#ifdef RTCONFIG_TAGGED_BASED_VLAN
	int vlan_arp_getlen[8];
	char vlan_buffer[8][ARP_BUFFER_SIZE];
	unsigned char vlan_scan_ipaddr[8][4];
	struct sockaddr_in vlan_hw_ipaddr[8];
	int i, j;
#endif
#if defined(RTCONFIG_TAGGED_BASED_VLAN) || defined(RTCONFIG_CAPTIVE_PORTAL) || defined(RTCONFIG_AMAS_WGN)
	char prefix[32], subnet_ipaddr[20];
	char *netmask;
#endif
#ifdef RTCONFIG_CAPTIVE_PORTAL
	int fw_arp_getlen=0, cp_arp_getlen=0;
	char fw_buffer[ARP_BUFFER_SIZE], cp_buffer[ARP_BUFFER_SIZE];
	//free wifi & cpative portal scan subnet
	unsigned char fw_scan_ipaddr[4], cp_scan_ipaddr[4];
	struct sockaddr_in fw_hw_ipaddr, cp_hw_ipaddr;
#endif
#ifdef RTCONFIG_AMAS_WGN
	int AMAS_WGN_INTERFACE = get_wl_ifnames();
	int wgn_vlan_arp_getlen[AMAS_WGN_INTERFACE];
	char wgn_vlan_buffer[AMAS_WGN_INTERFACE][ARP_BUFFER_SIZE];
	unsigned char wgn_vlan_scan_ipaddr[AMAS_WGN_INTERFACE][4];
	struct sockaddr_in wgn_vlan_hw_ipaddr[AMAS_WGN_INTERFACE];
	int k;
#endif
#ifdef RTCONFIG_BONJOUR
	int shm_mdns_id;
#endif
	int lock;
#if defined(RTCONFIG_QCA) && defined(RTCONFIG_WIRELESSREPEATER)	
	char *mac;
#endif
	time_t t_start, t_scan;
	//set default deep scan interval to 5 mins
	int deep_scan_interval = 300, deep_scan_t;
	t_start = time(NULL);
	if (deep_scan_t = nvram_get_int("nmp_deep_scan")) deep_scan_interval = deep_scan_t;

	FILE *fp = fopen("/var/run/networkmap.pid", "w");
	if(fp != NULL){
		fprintf(fp, "%d", getpid());
		fclose(fp);
	}

#ifdef NMP_DB
	if (!(nmp_cl_json = json_object_from_file(NMP_CL_JSON_FILE))) {
		NMP_DEBUG("open networkmap client list json database ERR:\n");
		nmp_cl_json = json_object_new_object();
	}
#endif

	//unset client list nvram DB in older verion
	if (nvram_get("nmp_client_list")){
		nvram_unset("nmp_client_list");
	}

	// switch to arp sockets scan in AP/RP mode
	if (nvram_get_int("sw_mode") == SW_MODE_AP || nvram_get_int("sw_mode") == SW_MODE_REPEATER)
		arp_skt = 1;

	/********************************/
	/* start arp socket scan setting*/
	//Get Router's IP/Mac
	strcpy(router_ipaddr, nvram_safe_get("lan_ipaddr"));
	strcpy(router_mac, get_lan_hwaddr());
#if defined(RTCONFIG_QCA) && defined(RTCONFIG_WIRELESSREPEATER)
#ifndef RTCONFIG_CONCURRENTREPEATER
	if (sw_mode() == SW_MODE_REPEATER && (mac = getStaMAC()) != NULL)
		strncpy(router_mac, mac, sizeof(router_mac));
#endif  /* #ifndef RTCONFIG_CONCURRENTREPEATER */
#endif
	inet_aton(router_ipaddr, &router_addr_ne.sin_addr);
	my_ipaddr_he.s_addr = ntohl(router_addr_ne.sin_addr.s_addr);
	if (strlen(router_mac)!=0) ether_atoe(router_mac, my_hwaddr);

	//Get maximum scan count via netmask
	max_scan_count = 255;	//if netmask = 255.255.255.0
	if (inet_aton(nvram_get("lan_netmask")? : nvram_default_get("lan_netmask"), &netmask_ne)) {
		max_scan_count = 255;				//parse arp to handle huge clients in B class or bigger subnet
		//max_scan_count = ~ntohl(netmask_ne.s_addr);	// omit one IP address as original code.
	}
	scan_ipaddr_he = my_ipaddr_he.s_addr & ~ntohl(netmask_ne.s_addr);
	my_ipaddr_ne = htonl(my_ipaddr_he.s_addr);
	//limit scan range
	//if(max_scan_count > 1024) max_scan_count = 1024;
	NMP_DEBUG("check max scan count: %d clients capacity %d\n", max_scan_count, MAX_NR_CLIENT_LIST);

	// create UDP socket and bind to "br0" to get ARP packet//
	arp_sockfd = create_socket(INTERFACE);

	//arp_timeput initial
	arp_timeout = (struct timeval*)malloc(sizeof(struct timeval));
	if(!arp_timeout) {
		printf("%s, malloc failed\n", __func__);
		return 0;
	}
	memset(arp_timeout, 0, sizeof(struct timeval));
	set_arp_timeout(arp_timeout, 0, 5000);

	if(arp_sockfd < 0)
		perror("create socket ERR:");
	else {
		setsockopt(arp_sockfd, SOL_SOCKET, SO_RCVTIMEO, arp_timeout, sizeof(struct timeval)); //set receive timeout
		//Copy sockaddr info to dst
		memset(&dst_sockll, 0, sizeof(dst_sockll));
		memcpy(&dst_sockll, &src_sockll, sizeof(src_sockll));
		//set LAN subnet share memory
		p_client_detail_info_tab = set_client_table_shm(p_client_detail_info_tab, SHMKEY_LAN);
	}

#ifdef RTCONFIG_TAGGED_BASED_VLAN
	lock = file_lock("networkmap");
	if (nvram_match("vlan_enable", "1")){
		NMP_DEBUG("vlan enable\n");
		if (nvram_get_int("vlan_index")){
			NMP_DEBUG("vlan index %d\n", nvram_get_int("vlan_index"));
			int shm_key = 1003;
			for (i = 0, j = 0; i <= (nvram_get_int("vlan_index") - 3); i++){
				//same_subnet = 0;
				memset(prefix, 0x00, sizeof(prefix));
				snprintf(prefix, sizeof(prefix), "lan%d_subnet", (i + 3));
				NMP_DEBUG("i %d %s\n", i, prefix);
				if (nvram_get(prefix) && !(nvram_match(prefix, "default"))){
					NMP_DEBUG("prefix %s\n", prefix);

					/* set IP of vlan with subnet */
					memset(router_ipaddr, 0x00, sizeof(router_ipaddr));
					memset(subnet_ipaddr, 0x00, sizeof(subnet_ipaddr));
					strcpy(subnet_ipaddr, nvram_safe_get(prefix));
					netmask = strchr(subnet_ipaddr, '/');
					*netmask = '\0';
					strcpy(router_ipaddr, subnet_ipaddr);
					NMP_DEBUG("vlan IP %s!!\n", router_ipaddr);
					inet_aton(router_ipaddr, &vlan_hw_ipaddr[j].sin_addr);
					memcpy(vlan_ipaddr[j], &vlan_hw_ipaddr[j].sin_addr, sizeof(vlan_ipaddr[j]));
					/* end of setting IP */

					/* create UDP socket and bind to "vlan" to get ARP packet */
					snprintf(prefix, sizeof(prefix), "lan%d_ifname", (i + 3));
					NMP_DEBUG("interface %s\n", prefix);
					vlan_arp_sockfd[j] = create_socket(nvram_get(prefix));
					if(vlan_arp_sockfd[j] < 0)
						perror("create socket ERR:");
					else {
						set_arp_timeout(arp_timeout, 0, 5000);
						setsockopt(vlan_arp_sockfd[j], SOL_SOCKET, SO_RCVTIMEO, arp_timeout, sizeof(struct timeval)); //set receive timeout
						//Copy sockaddr info to dst
						memset(&vlan_dst_sockll[j], 0, sizeof(src_sockll));
						memcpy(&vlan_dst_sockll[j], &src_sockll, sizeof(src_sockll));
						/* set vlan subnet client list shm */
						vlan_client_detail_info_tab[j] = set_client_table_shm(vlan_client_detail_info_tab[i], shm_key);
						NMP_DEBUG("tagged vlan%d memory set\n", (i + 3));
						/* end of setting vlan subnet client list shm */
						NMP_DEBUG("vlan %s socket create success!!\n", nvram_get(prefix));
						vlan_flag |= 1<<(j);
						j++;
					}
					/* end of creating vlan socket */
				} //end of if (nvram_get(prefix))
			} //end of for loop
		} //end of if (nvram_get_int("vlan_index"))
	} //end of if (nvram_match("vlan_enable", "1"))
	//enable arp socket scan if tagged vlan enable
	if(vlan_flag)
		arp_skt = 1;
	nvram_set_int("vlan_flag", vlan_flag);
	NMP_DEBUG("***vlan subnet bitmap %d\n", nvram_get_int("vlan_flag"));
	file_unlock(lock);
#endif

#ifdef RTCONFIG_CAPTIVE_PORTAL
	if (nvram_match("captive_portal_enable", "on")){
		/* set IP of free-wifi with subnet */
		memset(router_ipaddr, 0x00, sizeof(router_ipaddr));
		memset(subnet_ipaddr, 0x00, sizeof(subnet_ipaddr));
		strcpy(subnet_ipaddr, nvram_safe_get("chilli_net"));
		netmask = strchr(subnet_ipaddr, '/');
		*netmask = '\0';
		strcpy(router_ipaddr, subnet_ipaddr);
		NMP_DEBUG("free-wifi IP %s!!\n", router_ipaddr);
		inet_aton(router_ipaddr, &fw_hw_ipaddr.sin_addr);
		memcpy(fw_ipaddr, &fw_hw_ipaddr.sin_addr, sizeof(fw_ipaddr));
		/* end of setting IP */

		/* create UDP socket and bind to free-wifi interface to get ARP packet */
		fw_arp_sockfd = create_socket(nvram_get("lan1_ifname"));
		if(fw_arp_sockfd < 0)
			perror("create socket ERR:");
		else {
			set_arp_timeout(arp_timeout, 0, 5000);
			setsockopt(fw_arp_sockfd, SOL_SOCKET, SO_RCVTIMEO, arp_timeout, sizeof(struct timeval)); //set receive timeout
			//Copy sockaddr info to dst
			memset(&fw_dst_sockll, 0, sizeof(src_sockll));
			memcpy(&fw_dst_sockll, &src_sockll, sizeof(src_sockll));
			/* set free-wifi subnet client list shm */
			fw_client_detail_info_tab = set_client_table_shm(fw_client_detail_info_tab, SHMKEY_FREEWIFI);
			NMP_DEBUG("free-wifi memory set\n");
			/* end of setting free-wifi subnet client list shm */
			NMP_DEBUG("free-wifi socket create success!!\n");
			fw_flag = 1;
			//enable arp socket scan if free-wifi enable
			arp_skt = 1;
		}
		/* end of creating free-wifi socket */
	}
	if (nvram_match("captive_portal_adv_enable", "on")){
		/* set IP of captive portal with subnet */
		memset(router_ipaddr, 0x00, sizeof(router_ipaddr));
		memset(subnet_ipaddr, 0x00, sizeof(subnet_ipaddr));
		strcpy(subnet_ipaddr, nvram_safe_get("cp_net"));
		netmask = strchr(subnet_ipaddr, '/');
		*netmask = '\0';
		strcpy(router_ipaddr, subnet_ipaddr);
		NMP_DEBUG("Captive portal IP %s!!\n", router_ipaddr);
		inet_aton(router_ipaddr, &cp_hw_ipaddr.sin_addr);
		memcpy(cp_ipaddr, &cp_hw_ipaddr.sin_addr, sizeof(cp_ipaddr));
		/* end of setting IP */

		/* create UDP socket and bind to captive portal interface to get ARP packet */
		cp_arp_sockfd = create_socket(nvram_get("lan2_ifname"));
		if(cp_arp_sockfd < 0)
			perror("create socket ERR:");
		else {
			set_arp_timeout(arp_timeout, 0, 5000);
			setsockopt(cp_arp_sockfd, SOL_SOCKET, SO_RCVTIMEO, arp_timeout, sizeof(struct timeval)); //set receive timeout
			//Copy sockaddr info to dst
			memset(&cp_dst_sockll, 0, sizeof(src_sockll));
			memcpy(&cp_dst_sockll, &src_sockll, sizeof(src_sockll));
			/* set captive portal subnet client list shm */
			cp_client_detail_info_tab = set_client_table_shm(cp_client_detail_info_tab, SHMKEY_CP);
			NMP_DEBUG("captive portal memory set\n");
			/* end of setting captive portal subnet client list shm */
			NMP_DEBUG("captive portal socket create success!!\n");
			cp_flag = 1;
			//enable arp socket scan if captive portal enable
			arp_skt = 1;
		}
		/* end of creating captive portal socket */
	}
#endif

#ifdef RTCONFIG_AMAS_WGN
	char word[256], *next;
	char *nv, *nvp, *b;
	char *br_idx, *ip;

	if (nvram_match("wgn_enabled", "1")){
		NMP_DEBUG("AMAS WGN enable\n");
		k = 0;
		foreach (word, nvram_safe_get("wgn_ifnames"), next)
		{
			NMP_DEBUG("wgn vlan %s\n", word);
			nv = nvp = strdup(nvram_safe_get("wgn_brif_rulelist"));
			if(!nv) continue;
			while ((b = strsep(&nvp, "<")) != NULL) {
				if (!strstr(b, word) || (vstrsep(b, ">", &br_idx, &ip) != 2))
					continue;

				/* set IP of vlan with subnet */
				memset(router_ipaddr, 0x00, sizeof(router_ipaddr));
				memset(subnet_ipaddr, 0x00, sizeof(subnet_ipaddr));
				strcpy(subnet_ipaddr, ip);
				netmask = strchr(subnet_ipaddr, '/');
				*netmask = '\0';
				strcpy(router_ipaddr, subnet_ipaddr);
				NMP_DEBUG("wgn vlan IP %s!!\n", router_ipaddr);
				inet_aton(router_ipaddr, &wgn_vlan_hw_ipaddr[k].sin_addr);
				memcpy(wgn_vlan_ipaddr[k], &wgn_vlan_hw_ipaddr[k].sin_addr, sizeof(wgn_vlan_ipaddr[k]));
				/* end of setting IP */

				/* create UDP socket and bind to "vlan" to get ARP packet */
				NMP_DEBUG("interface %s\n", word);
				wgn_vlan_arp_sockfd[k] = create_socket(word);
				if(wgn_vlan_arp_sockfd[k] < 0)
					perror("create socket ERR:");
				else {
					set_arp_timeout(arp_timeout, 0, 5000);
					setsockopt(wgn_vlan_arp_sockfd[k], SOL_SOCKET, SO_RCVTIMEO, arp_timeout, sizeof(struct timeval)); //set receive timeout
					//Copy sockaddr info to dst
					memset(&wgn_vlan_dst_sockll[k], 0, sizeof(src_sockll));
					memcpy(&wgn_vlan_dst_sockll[k], &src_sockll, sizeof(src_sockll));
					NMP_DEBUG("wgn vlan %s socket create success!!\n", ip);
					wgn_vlan_flag |= 1 << k;
					k++;
				}
				/* end of creating vlan socket */
			} //end of while
			free(nv);
		} //end of foreach
	} //end of if (nvram_match("wgn_enabled", "1"))
	//enable arp socket scan if wgn enabled
	if(wgn_vlan_flag) arp_skt = 1;
	nvram_set_int("wgn_vlan_flag", wgn_vlan_flag);
	NMP_DEBUG("***wgn subnet bitmap %d\n", nvram_get_int("wgn_vlan_flag"));
#endif
	/***************************************/
	/* end of start arp socket scan setting*/

#ifdef RTCONFIG_BONJOUR
	//mDNSNetMonitor
	mdns_lock = file_lock("mDNSNetMonitor");
	shm_mdns_id = shmget((key_t)SHMKEY_BONJOUR, sizeof(mDNSClientList), 0666|IPC_CREAT);

	if (shm_mdns_id == -1){
		fprintf(stderr,"mDNS shmget failed\n");
		file_unlock(mdns_lock);
		return 0;
	}
	shmClientList = (mDNSClientList *)shmat(shm_mdns_id,(void *) 0,0);
	if (shmClientList == (void *)-1){
		fprintf(stderr,"shmat failed\n");
		file_unlock(mdns_lock);
		return 0;
	}
	file_unlock(mdns_lock);
#endif

	//initial trigger flag
#ifdef RTCONFIG_NOTIFICATION_CENTER
	TRIGGER_FLAG = atoi(nvram_safe_get("networkmap_trigger_flag"));
	if(TRIGGER_FLAG < 0 || TRIGGER_FLAG > 15) TRIGGER_FLAG = 0;
	NMP_DEBUG(" Test networkmap trigger flag >>> %d!\n", TRIGGER_FLAG);	
#endif
	/***********************************/
	/* start json OUI DB loading	   */
	if (!(oui_obj = json_object_from_file(NEWORKMAP_OUI_FILE))) {
		NMP_DEBUG("open OUI database ERR:\n");
	}
	else oui_enable = 1;
	NMP_DEBUG(" OUI enable %d!\n", oui_enable);
	/* end json OUI DB loading	   */
	/***********************************/


	/* load string match automata	   */
	if(check_if_file_exist(merge_conv_type_path[0])) {
		acType = construct_ac_file(convTypes, merge_conv_type_path[0]);
	} else {
		acType = construct_ac_file(convTypes, NMP_CONV_TYPE_FILE);
	}

	if(check_if_file_exist(merge_vendor_type_path[0])) {
		vendorType = construct_ac_file(vendorTypes, merge_vendor_type_path[0]); 
	} else {
		vendorType = construct_ac_file(vendorTypes, NMP_VENDOR_TYPE_FILE); 
	}

	if(check_if_file_exist(merge_bwdpi_type_path[0])) {
		dpiType = construct_ac_file(bwdpiTypes, merge_bwdpi_type_path[0]); 
	} else {
		dpiType = construct_ac_file(bwdpiTypes, NMP_BWDPI_TYPE_FILE); 
	}
	
	// ## disable sm.c content
	// acType = construct_ac_trie(convTypes);
	// vendorType = construct_ac_trie(vendorTypes);
	// dpiType = construct_ac_trie(bwdpiTypes);

	clients_start_ts = time(NULL);

	/* end of loading automata	   */
	// NMP_DEBUG("end of loading automata\n");
	//move here to prevent rescan(ARP) too late

	//Prepare scan 
	networkmap_fullscan = SCAN_INIT;
	nvram_set("networkmap_fullscan", fullscan_state[SCAN_INIT]);
	

	if (argc > 1) {
		if (strcmp(argv[1], "--bootwait") == 0) {
			sleep(30);
		}
	}

	signal(SIGUSR1, refresh_sig_on); //catch UI refresh signal
	signal(SIGTERM, handlesigTerminal);
	delete_sig = 0;
	signal(SIGUSR2, delete_sig_on);
	signal(SIGALRM, handlesigCleanShm);

	eval("asusdiscovery");	//find asus device

	while(terminated)//main while loop
	{
		while(1) { //full scan and reflush recv buffer
			fullscan:
				if( (!clean_shm && networkmap_fullscan == SCAN_CLEAN) ){
					NMP_DEBUG("Clean share memory client list!\n");
					lock = file_lock("networkmap");
					memset(p_client_detail_info_tab, 0x00, sizeof(CLIENT_DETAIL_INFO_TABLE));
#ifdef RTCONFIG_TAGGED_BASED_VLAN
					if(vlan_flag){
						for(i = 0; i < 8; i++){
							if(vlan_flag & (1<<i)){
								NMP_DEBUG("vlan %d clean\n", i);
								memset(vlan_client_detail_info_tab[i], 0x00, sizeof(CLIENT_DETAIL_INFO_TABLE));
							}
						}
					}
#endif
#ifdef RTCONFIG_CAPTIVE_PORTAL
					if (fw_flag == 1){
						NMP_DEBUG("free-wifi shm clean\n");
						memset(fw_client_detail_info_tab, 0x00, sizeof(CLIENT_DETAIL_INFO_TABLE));
					}
					if (cp_flag == 1){
						NMP_DEBUG("captive portal shm clean\n");
						memset(cp_client_detail_info_tab, 0x00, sizeof(CLIENT_DETAIL_INFO_TABLE));
					}
#endif
					file_unlock(lock);
					clean_shm = 1; // Do not clean again
					networkmap_fullscan = SCAN_INIT;
				}

				

				if(networkmap_fullscan == SCAN_INIT) {
					NMP_DEBUG("start networkmap_fullscan = SCAN_INIT = %s\n", fullscan_state[SCAN_INIT]);
					network_ip_scan();
					sig_refresh_start_ts = time(NULL);
					scan_count = 0;
					networkmap_fullscan = SCAN_PROC;
					nvram_set("networkmap_fullscan", fullscan_state[SCAN_PROC]);
					//start arp parser scan
					handle_client_list_from_arp_table(p_client_detail_info_tab, INTERFACE);

#ifdef RTCONFIG_MULTILAN_CFG
					char apg[128] = {0}, *apg_next = NULL;
					foreach(apg, nvram_safe_get("apg_ifnames"), apg_next) {
						handle_client_list_from_arp_table(p_client_detail_info_tab, apg);
					}
#endif
				}

				if(networkmap_fullscan == SCAN_PROC) { //Scan all IP address in the subnetwork

					if(scan_count == 0) { 
						NMP_DEBUG("Starting full scan,  networkmap_fullscan == SCAN_PROC, scan_count == 0\n");
#ifdef RTCONFIG_BONJOUR
						eval("mDNSQuery"); //send mDNS service dicsovery
#endif
						/***********************************/
						/* start refresh/rescan client list */
						if (nvram_get_int("refresh_networkmap")) { //flush arp table
							NMP_DEBUG("Flush arp!\n");
							if(!arp_skt) {
								// NMP_DEBUG("run cmd,  ip -s -s neigh flush all\n");
								// system("ip -s -s neigh flush all");
							}
							//when user push refresh button then search for asus deive
							eval("asusdiscovery");	//find asus device
							nvram_unset("refresh_networkmap");
							//when user push refresh button then then try to find device type again
							deep_scan = 1;
						}

						NMP_DEBUG("networkmap: refresh_client_list\n");
						refresh_client_list(p_client_detail_info_tab);

#ifdef RTCONFIG_TAGGED_BASED_VLAN
						if(vlan_flag){
							for(i = 0; i < 8; i++){
								if(vlan_flag & (1<<i))
									refresh_client_list(vlan_client_detail_info_tab[i]);
							}
						}
#endif
#ifdef RTCONFIG_CAPTIVE_PORTAL
						if (fw_flag == 1)
							refresh_client_list(fw_client_detail_info_tab);
						if (cp_flag == 1)
							refresh_client_list(cp_client_detail_info_tab);
#endif

						NMP_DEBUG("reset client list over\n");
						/*******************************************/
						/*  end of start refresh/reset client list */

						// (re)-start from the begining
						scan_ipaddr_he = my_ipaddr_he.s_addr & ntohl(netmask_ne.s_addr);

						if(!arp_skt)
							set_arp_timeout(arp_timeout, 0, 5000);
						else
							set_arp_timeout(arp_timeout, 0, 10000);
						setsockopt(arp_sockfd, SOL_SOCKET, SO_RCVTIMEO, arp_timeout, sizeof(struct timeval)); //set receive timeout

#ifdef RTCONFIG_TAGGED_BASED_VLAN
						if(vlan_flag){
							for(i = 0; i < 8; i++){
								if(vlan_flag & (1<<i)){
									memset(vlan_scan_ipaddr[i], 0x00, sizeof(vlan_scan_ipaddr[i]));
									memcpy(vlan_scan_ipaddr[i], &vlan_hw_ipaddr[i].sin_addr, 3);
									setsockopt(vlan_arp_sockfd[i], SOL_SOCKET, SO_RCVTIMEO, 
											arp_timeout, sizeof(struct timeval)); //set receive timeout
									NMP_DEBUG("set vlan %d socket option\n", (i + 3));
								}
							}
						}
#endif
#ifdef RTCONFIG_CAPTIVE_PORTAL
						if (fw_flag == 1){
							memset(fw_scan_ipaddr, 0x00, sizeof(fw_scan_ipaddr));
							memcpy(fw_scan_ipaddr, &fw_hw_ipaddr.sin_addr, 3);
							NMP_DEBUG("set free-wifi socket option\n");
						}
						if (cp_flag == 1){
							memset(cp_scan_ipaddr, 0x00, sizeof(cp_scan_ipaddr));
							memcpy(cp_scan_ipaddr, &cp_hw_ipaddr.sin_addr, 3);
							NMP_DEBUG("set cpative portal socket option\n");
						}
#endif
#ifdef RTCONFIG_AMAS_WGN
						if(wgn_vlan_flag){
							for(k = 0; k < AMAS_WGN_INTERFACE; k++){
								if(wgn_vlan_flag & (1<<k)){
									memset(wgn_vlan_scan_ipaddr[k], 0x00, sizeof(wgn_vlan_scan_ipaddr[k]));
									memcpy(wgn_vlan_scan_ipaddr[k], &wgn_vlan_hw_ipaddr[k].sin_addr, 3);
									setsockopt(wgn_vlan_arp_sockfd[k], SOL_SOCKET, SO_RCVTIMEO, 
											arp_timeout, sizeof(struct timeval)); //set receive timeout
									NMP_DEBUG("set wgn vlan(br%d) socket option\n", k + 2);
								}
							}
						}
#endif
					}

					scan_count++;
					scan_ipaddr_he++;
					scan_ipaddr_ne = htonl(scan_ipaddr_he);

#ifdef RTCONFIG_TAGGED_BASED_VLAN
					if(vlan_flag){
						for(i = 0; i < 8; i++){
							if(vlan_flag & (1<<i)){
								vlan_scan_ipaddr[i][3]++;
							}
						}
					}
#endif
#ifdef RTCONFIG_CAPTIVE_PORTAL
					if (fw_flag == 1)
						fw_scan_ipaddr[3]++;
					if (cp_flag == 1)
						cp_scan_ipaddr[3]++;
#endif
#ifdef RTCONFIG_AMAS_WGN
					if(wgn_vlan_flag){
						for(k = 0; k < AMAS_WGN_INTERFACE; k++){
							if(wgn_vlan_flag & (1<<k)){
								wgn_vlan_scan_ipaddr[k][3]++;
							}
						}
					}
#endif
					if(scan_count < max_scan_count) {
						if(scan_ipaddr_he != my_ipaddr_he.s_addr) {
							sent_arppacket(arp_sockfd, (unsigned char*) &my_ipaddr_ne, (unsigned char*) &scan_ipaddr_ne, dst_sockll);
						}
						if(scan_count < 255) {
#ifdef RTCONFIG_TAGGED_BASED_VLAN
							if(vlan_flag){
								for(i = 0; i < 8; i++){
									if(vlan_flag & (1<<i)){
										if(memcmp(vlan_scan_ipaddr[i], vlan_ipaddr[i], 4))
											sent_arppacket(vlan_arp_sockfd[i], vlan_ipaddr[i], vlan_scan_ipaddr[i], vlan_dst_sockll[i]);
									}
								}
							}
#endif
#ifdef RTCONFIG_CAPTIVE_PORTAL
							if (fw_flag == 1)
								sent_arppacket(fw_arp_sockfd, fw_ipaddr, fw_scan_ipaddr, fw_dst_sockll);
							if (cp_flag == 1)
								sent_arppacket(cp_arp_sockfd, cp_ipaddr, cp_scan_ipaddr, cp_dst_sockll);
#endif
#ifdef RTCONFIG_AMAS_WGN
							if(wgn_vlan_flag){
								for(k = 0; k < AMAS_WGN_INTERFACE; k++){
									if(wgn_vlan_flag & (1<<k)){
										if(memcmp(wgn_vlan_scan_ipaddr[k], wgn_vlan_ipaddr[k], 4))
											sent_arppacket(wgn_vlan_arp_sockfd[k], wgn_vlan_ipaddr[k], wgn_vlan_scan_ipaddr[k], wgn_vlan_dst_sockll[k]);
									}
								}
							}
#endif
						}
					}	 
					else if(scan_count == max_scan_count) { //Scan completed
						set_arp_timeout(arp_timeout, 0, 10000); //Reset timeout at monitor state for decase cpu loading
						setsockopt(arp_sockfd, SOL_SOCKET, SO_RCVTIMEO, arp_timeout, sizeof(struct timeval));//set receive timeout
#ifdef RTCONFIG_TAGGED_BASED_VLAN
						if(vlan_flag){
							for(i = 0; i < 8; i++){
								if(vlan_flag & (1<<i)){
									setsockopt(vlan_arp_sockfd[i], SOL_SOCKET, SO_RCVTIMEO, arp_timeout, sizeof(struct timeval));//set receive timeout
								}
							}
						}
#endif
#ifdef RTCONFIG_CAPTIVE_PORTAL
						if (fw_flag == 1)
							setsockopt(fw_arp_sockfd, SOL_SOCKET, SO_RCVTIMEO, arp_timeout, sizeof(struct timeval));//set receive timeout
						if (cp_flag == 1)
							setsockopt(cp_arp_sockfd, SOL_SOCKET, SO_RCVTIMEO, arp_timeout, sizeof(struct timeval));//set receive timeout
#endif
						networkmap_fullscan = SCAN_DONE;
						nvram_set("networkmap_fullscan", fullscan_state[SCAN_DONE]);
						NMP_DEBUG("Finish full scan,  state[SCAN_DONE] = %d\n",  SCAN_DONE);
						//do arp parser scan after arp skt req flush arp
						handle_client_list_from_arp_table(p_client_detail_info_tab, INTERFACE);


#ifdef RTCONFIG_MULTILAN_CFG
						char apg[128] = {0}, *apg_next = NULL;
						foreach(apg, nvram_safe_get("apg_ifnames"), apg_next) {
							handle_client_list_from_arp_table(p_client_detail_info_tab, apg);
						}
#endif

#ifdef RTCONFIG_AMAS_WGN
						if(wgn_vlan_flag){
							for(k = 0; k < AMAS_WGN_INTERFACE; k++){
								if(wgn_vlan_flag & (1 << k)){
									if(k == 0)
										handle_client_list_from_arp_table(p_client_detail_info_tab, AMAS_WGN_BR_1);
									if(k == 1)
										handle_client_list_from_arp_table(p_client_detail_info_tab, AMAS_WGN_BR_2);
									if(k == 2)
										handle_client_list_from_arp_table(p_client_detail_info_tab, AMAS_WGN_BR_3);
									if(k == 3)
										handle_client_list_from_arp_table(p_client_detail_info_tab, AMAS_WGN_BR_4);
								}
							}
						}
#endif
					}
				} // End of full scan > if(networkmap_fullscan != SCAN_PROC)

				//start arp socket scan in AP/RP mode
				//arp buffer clean
				memset(buffer, 0, ARP_BUFFER_SIZE);
#ifdef RTCONFIG_TAGGED_BASED_VLAN
				if(vlan_flag){
					for(i = 0; i < 8; i++){
						if(vlan_flag & (1<<i))
							memset(vlan_buffer[i], 0, ARP_BUFFER_SIZE);
					}
				}
#endif
#ifdef RTCONFIG_CAPTIVE_PORTAL
				if (fw_flag == 1)
					memset(fw_buffer, 0, ARP_BUFFER_SIZE);
				if (cp_flag == 1)
					memset(cp_buffer, 0, ARP_BUFFER_SIZE);
#endif
#ifdef RTCONFIG_AMAS_WGN
				if(wgn_vlan_flag){
					for(k = 0; k < AMAS_WGN_INTERFACE; k++){
						if(wgn_vlan_flag & (1<<k))
							memset(wgn_vlan_buffer[k], 0, ARP_BUFFER_SIZE);
					}
				}
#endif
				//arp buffer clean end

				//receive arp packet
				arp_packet_rcv = 0;
				arp_getlen = recvfrom(arp_sockfd, buffer, ARP_BUFFER_SIZE, 0, NULL, NULL);
				if(arp_getlen > 0) {
					arp_packet_rcv = 1;
				}
#ifdef RTCONFIG_TAGGED_BASED_VLAN
				if(vlan_flag){
					for(i = 0; i < 8; i++){
						if(vlan_flag & (1<<i)){
							vlan_arp_getlen[i] = recvfrom(vlan_arp_sockfd[i], vlan_buffer[i], ARP_BUFFER_SIZE, 0, NULL, NULL);
							if(vlan_arp_getlen[i] > 0)
								arp_packet_rcv = 1;
						}
					}
				}
#endif
#ifdef RTCONFIG_CAPTIVE_PORTAL
				if (fw_flag == 1){
					fw_arp_getlen = recvfrom(fw_arp_sockfd, fw_buffer, ARP_BUFFER_SIZE, 0, NULL, NULL);
					if(fw_arp_getlen > 0)
						arp_packet_rcv = 1;
				}
				if (cp_flag == 1){
					cp_arp_getlen = recvfrom(cp_arp_sockfd, cp_buffer, ARP_BUFFER_SIZE, 0, NULL, NULL);
					if(cp_arp_getlen > 0)
						arp_packet_rcv = 1;
				}			
#endif
#ifdef RTCONFIG_AMAS_WGN
				if(wgn_vlan_flag){
					for(k = 0; k < AMAS_WGN_INTERFACE; k++){
						if(wgn_vlan_flag & (1<<k)){
							wgn_vlan_arp_getlen[k] = recvfrom(wgn_vlan_arp_sockfd[k], wgn_vlan_buffer[k], ARP_BUFFER_SIZE, 0, NULL, NULL);
							if(wgn_vlan_arp_getlen[k] > 0)
								arp_packet_rcv = 1;
						}
					}
				}
#endif
				//receive arp packet end

				if(arp_packet_rcv == 0) {
					if(scan_count < max_scan_count) goto fullscan;
					else break;
				}
				else {
					//protect memory overflow
					if(arp_getlen > 0){
						if(p_client_detail_info_tab->ip_mac_num >= MAX_NR_CLIENT_LIST) {
							handlesigCleanShm();
							nvram_set("refresh_networkmap", "1");
							goto fullscan;
						}
					}
#ifdef RTCONFIG_TAGGED_BASED_VLAN
					if(vlan_flag){
						for(i = 0; i < 8; i++){
							if(vlan_flag & (1<<i)){
								if(vlan_arp_getlen[i] > 0){
									if(vlan_client_detail_info_tab[i]->ip_mac_num >= 255) {
										handlesigCleanShm();
										nvram_set("refresh_networkmap", "1");
										goto fullscan;
									}
								}
							}
						}
					}
#endif
#ifdef RTCONFIG_CAPTIVE_PORTAL
					if (fw_flag == 1){
						if(fw_arp_getlen > 0){
							if(fw_client_detail_info_tab->ip_mac_num >= 255) {
								handlesigCleanShm();
								nvram_set("refresh_networkmap", "1");
								goto fullscan;
							}
						}
					}
					if (cp_flag == 1){
						if(cp_arp_getlen > 0){
							if(cp_client_detail_info_tab->ip_mac_num >= 255) {
								handlesigCleanShm();
								nvram_set("refresh_networkmap", "1");
								goto fullscan;
							}
						}
					}
#endif
					//protect memory overflow end

					if(arp_getlen > 0)
						handle_client_list(p_client_detail_info_tab, buffer, (unsigned char*) &my_ipaddr_ne, scan_count);
#ifdef RTCONFIG_TAGGED_BASED_VLAN
					if(vlan_flag){
						for(i = 0; i < 8; i++){
							if(vlan_flag & (1<<i)){
								if(vlan_arp_getlen[i] > 0){
									handle_client_list(vlan_client_detail_info_tab[i], 
											vlan_buffer[i], vlan_ipaddr[i], scan_count);
								}
							}
						}
					}
#endif
#ifdef RTCONFIG_CAPTIVE_PORTAL
					if (fw_flag == 1){
						if(fw_arp_getlen > 0)
							handle_client_list(fw_client_detail_info_tab, fw_buffer, fw_ipaddr, scan_count);
					}
					if (cp_flag == 1){
						if(cp_arp_getlen > 0)
							handle_client_list(cp_client_detail_info_tab, cp_buffer, cp_ipaddr, scan_count);
					}
#endif
#ifdef RTCONFIG_AMAS_WGN
					if(wgn_vlan_flag){
						for(k = 0; k < AMAS_WGN_INTERFACE; k++){
							if(wgn_vlan_flag & (1<<k)){
								if(wgn_vlan_arp_getlen[k] > 0){
									handle_client_list(p_client_detail_info_tab, 
											wgn_vlan_buffer[k], wgn_vlan_ipaddr[k], scan_count);
								}
							}
						}
					}
#endif
				} //End of arp_getlen != -1
			//End of fullscan:
		} // End of while for flush buffer

		//Rawny: check delete signal
		if(delete_sig) {
#ifdef NMP_DB
			client_updated = DeletefromDB(p_client_detail_info_tab, nmp_cl_json);
#endif
			DeletefromShm(p_client_detail_info_tab);
			memset(p_client_detail_info_tab->delete_mac, 0, sizeof(p_client_detail_info_tab->delete_mac));
			delete_sig = 0;
		}

		//if deep_scan not trigger by reset button, check deep scan time
		if(!deep_scan) {
			t_scan = time(NULL);
			//check deep scan time over setting value
			if((t_scan - t_start) > deep_scan_interval) {
				NMP_DEBUG("t_scan(%d) - t_start(%d) = %d > deep_scan_interval(%d)\n", t_scan, t_start, (t_scan - t_start), deep_scan_interval);
				//reset deep scan no.
				deep_scan = 1;
				t_start = time(NULL);
			}
		}
		else {
			reset_deep_scan(p_client_detail_info_tab);
#ifdef RTCONFIG_TAGGED_BASED_VLAN
			if(vlan_flag){
				for(i = 0; i < 8; i++){
					if(vlan_flag & (1<<i))
						reset_deep_scan(vlan_client_detail_info_tab[i]);
				}
			}
#endif
#ifdef RTCONFIG_CAPTIVE_PORTAL
			if (fw_flag == 1)
				reset_deep_scan(fw_client_detail_info_tab);
			if (cp_flag == 1)
				reset_deep_scan(cp_client_detail_info_tab);
#endif
			deep_scan = 0;
			eval("asusdiscovery");	//find asus device
		}	

		handle_detail_client_list(p_client_detail_info_tab);

		if(nvram_match("fb_nmp_scan", "1"))
		{
			count_num_of_clients();
		}

#ifdef RTCONFIG_TAGGED_BASED_VLAN
		if(vlan_flag){
			for(i = 0; i < 8; i++){
				if(vlan_flag & (1<<i)){
					handle_detail_client_list(vlan_client_detail_info_tab[i]);
				}
			}
		}
#endif
#ifdef RTCONFIG_CAPTIVE_PORTAL
		if (fw_flag == 1)
			handle_detail_client_list(fw_client_detail_info_tab);
		if (cp_flag == 1)
			handle_detail_client_list(cp_client_detail_info_tab);
#endif
#ifdef RTCONFIG_AMAS_WGN
		if(wgn_vlan_flag){
			for(k = 0; k < AMAS_WGN_INTERFACE; k++){
				if(wgn_vlan_flag & (1<<k)){
					handle_detail_client_list(p_client_detail_info_tab);
				}
			}
		}
#endif
		if(nvram_match("nmp_wl_offline_check", "1")) //web server trigger wl offline check
			nvram_unset("nmp_wl_offline_check");
		if(nvram_match("rescan_networkmap", "1")) // cache trigger
			nvram_unset("rescan_networkmap"); // rescan over cache clean
	
	} //End of main while loop

	safe_leave();
	return 0;
}
