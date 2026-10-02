#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <pthread.h>
#include <dlfcn.h>
#endif
#include <config.h>
#include <natnl_lib.h>

#ifdef WIN32
#define WINAPI __stdcall
#define GetCurrTID() GetCurrentThreadId()
#else
#define WINAPI
#define GetCurrTID() ((size_t)pthread_self())
#endif

//#define AAE_TEST 1 // Just for aae test.

extern char callee[128], registrar_uri[128], device_id_to_call[128];
int current_callid;
int hangup_ok;
int reinvite_callid = 0;
int inst_id = 0; 

/*The definition of global variables that are in natnl_dll.h*/
struct natnl_config natnl_config;
natnl_tnl_port natnl_tnl_ports[MAX_TUNNEL_PORT_COUNT];
natnl_tnl_port tnl_ports[MAX_TUNNEL_PORT_COUNT];
natnl_tnl_port tnl_ports2[MAX_TUNNEL_PORT_COUNT];
int natnl_tnl_port_count;
struct natnl_callback natnl_callback;

/* SDK function pointer*/
int (WINAPI *natnl_set_max_instances)   (int max_instances);
int (WINAPI *natnl_lib_init)       (struct natnl_config *cfg);
int (WINAPI *natnl_lib_init2)      (struct natnl_config *cfg, 
	void *app_data);
int (WINAPI *natnl_lib_init3)      (struct natnl_config *cfg, 
	struct natnl_callback *natnl_cb, 
	void *app_data);
int (WINAPI *natnl_lib_init_with_inst_id)       (struct natnl_config *cfg, 
	int *inst_id);
int (WINAPI *natnl_lib_init_with_inst_id2)       (struct natnl_config *cfg, 
	int *inst_id,
	void *app_data);
int (WINAPI *natnl_lib_init_with_inst_id3)       (struct natnl_config *cfg, 
	int *inst_id,
	struct natnl_callback *natnl_cb,
	void *app_data);

int (WINAPI *natnl_lib_deinit)     (void);
int (WINAPI *natnl_lib_deinit_with_inst_id)     (int inst_id);

int (WINAPI *natnl_lib_deinit_all) (void);

int (WINAPI *natnl_make_call)      (char *device_id, int tnl_port_count,
	natnl_tnl_port tnl_port[],
	char *user_id, int timeout_sec, int use_sctp, struct natnl_tnl_info *tnl_info);
int (WINAPI *natnl_make_call_with_inst_id)      (char *device_id, int tnl_port_count,
	natnl_tnl_port tnl_port[],
	char *user_id, int timeout_sec, int use_sctp, int inst_id, struct natnl_tnl_info *tnl_info);
int (WINAPI *natnl_make_call_with_inst_id2)      (char *device_id, int tnl_port_count,
	natnl_tnl_port tnl_port[],
	char *user_id, int timeout_sec, int use_sctp, int inst_id,
	char *caller_device_pwd, struct natnl_tnl_info *tnl_info);

int (WINAPI *natnl_hangup_call)    (int call_id);
int (WINAPI *natnl_hangup_call_with_inst_id)    (int call_id, int inst_id);

int (WINAPI *natnl_reg_device)     (void);
int (WINAPI *natnl_reg_device_with_inst_id)     (int inst_id);

int (WINAPI *natnl_unreg_device)   (void);
int (WINAPI *natnl_unreg_device_with_inst_id)   (int inst_id);

int (WINAPI *natnl_update_config)  (struct natnl_config *cfg);
int (WINAPI *natnl_update_config_with_inst_id)  (struct natnl_config *cfg, int inst_id);

int (WINAPI *natnl_call_reinvite)  (int call_id);
int (WINAPI *natnl_call_reinvite_with_inst_id)  (int call_id, int inst_id);

int (WINAPI *natnl_tunnel_port)    (int call_id, int action, int tnl_port_count, 
									natnl_tnl_port tunnel_port[]);
int (WINAPI *natnl_tunnel_port_with_inst_id)    (int call_id, int action, int tnl_port_count, 
												 natnl_tnl_port tunnel_port[], int inst_id);

int (WINAPI *natnl_instant_msg_port)(int action, 
												int im_port_cnt, 
												natnl_im_port im_ports[]);
int (WINAPI *natnl_instant_msg_port_with_inst_id)(int action, 
															 int im_port_cnt, 
															 natnl_im_port im_ports[],
															 int inst_id);

int (WINAPI *natnl_pool_dump)      (int detail);
int (WINAPI *natnl_pool_dump_with_inst_id)      (int detail, int inst_id);

void(WINAPI *natnl_dump_version)   (int argc, char *argv[]);
void(WINAPI *natnl_dump_version_with_inst_id)   (int argc, char *argv[], int inst_id);

int (WINAPI *natnl_read_tnl_status) (
	int call_id);

int (WINAPI *natnl_read_tnl_status_with_inst_id) (
	int call_id,
	int inst_id);

int (WINAPI *natnl_send_instant_msg) (
	char *dest_device_id,
	int msg_len,
	char *msg_content,
	int rport,
	int *resp_len,
	char *resp_msg);

int (WINAPI *natnl_send_instant_msg_with_inst_id) (
	char *dest_device_id,
	int msg_len,
	char *msg_content,
	int rport,
	int *resp_len,
	char *resp_msg,
	int inst_id);

int (WINAPI *natnl_send_instant_msg_to_remote_process) (
	char *dest_device_id,
	int msg_len,
	char *msg_content,
	char *proc_name,
	int *resp_len,
	char *resp_msg);

int (WINAPI *natnl_send_instant_msg_to_remote_process_with_inst_id) (
	char *dest_device_id,
	int msg_len,
	char *msg_content,
	char *proc_name,
	int *resp_len,
	char *resp_msg,
	int inst_id);

int (WINAPI *natnl_read_tnl_info) (
	int call_id,
	struct natnl_tnl_info *tnl_info);

int (WINAPI *natnl_read_tnl_info_with_inst_id) (
	int call_id,
	struct natnl_tnl_info *tnl_info,
	int inst_id);

int (WINAPI *natnl_read_tnl_transfer_speed) (int call_id,
										struct natnl_tnl_transfer_speed *transfer_speed);
int (WINAPI *natnl_read_tnl_transfer_speed_with_inst_id) (
										int call_id,
										struct natnl_tnl_transfer_speed *transfer_speed,
										int inst_id);

int (WINAPI *natnl_set_tnl_transfer_speed_limit) (int call_id,
										struct natnl_tnl_transfer_speed limit_speed);
int (WINAPI *natnl_set_tnl_transfer_speed_limit_with_inst_id) (
										int call_id,
										struct natnl_tnl_transfer_speed limit_speed,
										int inst_id);

int (WINAPI *natnl_detect_nat_type)   (char *stun_srv);
#ifdef SUPPORT_ARP
int (WINAPI *natnl_resolve_mac_by_arp) (char *targe_address, 
								 char *target_mac, 
								 int *target_mac_len, 
								 int timeout);
#endif
char * (WINAPI *natnl_lib_version) (void);

#ifdef WIN32
HMODULE hInst = NULL;
#define GET_PROC_ADDR_AND_CHECK(func_name) do { \
	int err_code; \
	(FARPROC)(natnl_ ## func_name) = GetProcAddress(hInst, "natnl_" #func_name); \
	if ((err_code = GetLastError()) != 0)  { \
	fprintf(stderr, "Failed to laod natnl_" #func_name ". error=%d\n", err_code); \
	exit(EXIT_FAILURE); \
	} \
} while(0);
#else
void *hInst = NULL;
#define GET_PROC_ADDR_AND_CHECK(func_name) do { \
	char *err_str; \
	*(void **) (&natnl_ ## func_name) = dlsym(hInst, "natnl_" #func_name); \
	if ((err_str = dlerror()) != NULL)  { \
	fprintf(stderr, "Failed to laod natnl_" #func_name ". error=%s\n", err_str); \
	exit(EXIT_FAILURE); \
	} \	
} while (0);
#endif

#ifdef WIN32
extern int tcp_server_run(DWORD *dwThreadId);
extern int tcp_server_stop();
extern int udp_server_run(DWORD *dwThreadId);
extern int udp_server_stop();
extern int send_data_test();
extern int put_local_file(char *file_name, int sock_type);
extern int get_remote_file(char *file_name, int sock_type);
extern int put_local_data(int data_size, int sock_type);
extern int get_remote_data(int data_size, int sock_type);

DWORD WINAPI natnl_init(LPVOID lpPara) {
	int status, call_id;
	status = natnl_lib_init_with_inst_id(&natnl_config, &inst_id);
	return 0;
}

DWORD WINAPI make_call(LPVOID lpPara) {
	int status, call_id;
	char *device_id = (char*)lpPara;
	struct	natnl_tnl_info	tnl_info;
	strcpy(tnl_ports[0].lport ,"7077");
	strcpy(tnl_ports[0].rport ,"8088");
	tnl_ports[0].qos_priority = 0;
	tnl_ports[0].disable_flow_control = 0;
	strcpy(tnl_ports[1].lport ,"7078");
	strcpy(tnl_ports[1].rport ,"8089");
	tnl_ports[1].qos_priority = 0;
	tnl_ports[1].disable_flow_control = 0;
	status = natnl_make_call_with_inst_id(device_id, 2, tnl_ports, 
		"asus", 60, 0, inst_id, &tnl_info);
	printf("make call current_callid=%d, ThreadId=[%08X]\n", tnl_info.call_id, GetCurrTID());
	return 0;
}

DWORD WINAPI make_call2(LPVOID lpPara) {
	int status, call_id;
	char *device_id = (char*)lpPara;
	struct	natnl_tnl_info	tnl_info;
	strcpy(tnl_ports2[0].lport ,"7079");
	strcpy(tnl_ports2[0].rport ,"8090");
	strcpy(tnl_ports2[1].lport ,"7080");
	strcpy(tnl_ports2[1].rport ,"8091");
	status = natnl_make_call_with_inst_id(device_id, 2, tnl_ports2, 
		"asus", 60, 0, inst_id, &tnl_info);
	printf("make call2 current_callid=%d, ThreadId=[%08X]\n", tnl_info.call_id, GetCurrTID());
	return 0;
}

DWORD WINAPI read_status(LPVOID lpPara) {
	int status;
	struct natnl_tnl_info *tnl_info = (struct natnl_tnl_info*)lpPara;
	int inst_id = tnl_info->inst_id;
	int call_id = tnl_info->call_id;
	while (1) {
		status = natnl_read_tnl_status_with_inst_id(call_id, inst_id);
		printf("read_status isnt_id=%d, call_id=%d, status=%d ThreadId=[%08X]\n", inst_id, call_id, status, GetCurrTID());
		if (status == NATNL_SC_TNL_TIMEOUT)
			break; // Make call again if any.
		if (status == PJ_SC_OK)
			break; // Make call again if any.
#ifndef WIN32
		sleep(1);
#else
		Sleep(1);
#endif
	}
	return 0;
}

DWORD WINAPI hang_up(LPVOID lpPara) {
	int status;
	struct natnl_tnl_info *tnl_info = (struct natnl_tnl_info*)lpPara;
	status = natnl_hangup_call_with_inst_id(tnl_info->call_id, tnl_info->inst_id);
	printf("hangup call current_callid=%d, ThreadId=[%08X]\n", tnl_info->call_id, GetCurrTID());
	return 0;
}

DWORD WINAPI pool_dump(int lpPara) {
	int status;
	status = natnl_pool_dump_with_inst_id(inst_id, lpPara, 0);
	return 0;
}

DWORD WINAPI natnl_deinit(LPVOID lpPara) {
	int status, call_id;
	status = natnl_lib_deinit_with_inst_id(inst_id);
	return 0;
}

DWORD WINAPI reg_device(LPVOID lpPara) {
	int status;
	status = natnl_reg_device_with_inst_id(inst_id);
	printf("reg_device status=%d, ThreadId=[%08X]\n", status, GetCurrTID());
	return 0;
}

DWORD WINAPI unreg_device(LPVOID lpPara) {
	int status;
	status = natnl_unreg_device_with_inst_id(inst_id);
	printf("unreg_device status=%d, ThreadId=[%08X]\n", status, GetCurrTID());
	return 0;
}

DWORD WINAPI get_file_tcp(LPVOID lpPara) {
	int status;
	char * buff = (char *)lpPara;
	status = get_remote_file(buff, SOCK_STREAM);
	return 0;
}

DWORD WINAPI get_data_tcp(LPVOID lpPara) {
	int status;
	int *buff = (int *)lpPara;
	status = get_remote_data(*buff, SOCK_STREAM);
	return 0;
}

DWORD WINAPI put_file_tcp(LPVOID lpPara) {
	int status;
	char * buff = (char *)lpPara;
	status = put_local_file(buff, SOCK_STREAM);
	return 0;
}

DWORD WINAPI put_data_tcp(LPVOID lpPara) {
	int status;
	int buff = atoi((char *)lpPara);
	status = put_local_data(buff, SOCK_STREAM);
	return 0;
}

DWORD WINAPI get_file_udp(LPVOID lpPara) {
	int status;
	char * buff = (char *)lpPara;
	status = get_remote_file(buff, SOCK_DGRAM);
	return 0;
}

DWORD WINAPI get_data_udp(LPVOID lpPara) {
	int status;
	int *buff = (int *)lpPara;
	status = get_remote_data(*buff, SOCK_DGRAM);
	return 0;
}

DWORD WINAPI put_file_udp(LPVOID lpPara) {
	int status;
	char * buff = (char *)lpPara;
	status = put_local_file(buff, SOCK_DGRAM);
	return 0;
}

DWORD WINAPI put_data_udp(LPVOID lpPara) {
	int status;
	int buff = atoi((char *)lpPara);
	status = put_local_data(buff, SOCK_DGRAM);
	return 0;
}

DWORD WINAPI natnl_version(LPVOID lpPara) {
	int nat_type = natnl_detect_nat_type("107.23.46.235");
	printf("[main.c] natnl_detect_nat_type=[%d]\n", nat_type);
}


DWORD WINAPI detect_nat(LPVOID lpPara) {
	natnl_dump_version(lpPara, lpPara, 0);
}
#endif

int lib_unload()
{
#ifdef WIN32
	FreeLibrary(hInst);
#else
	dlclose(hInst);
#endif
	hInst = NULL;
}

/*
 * Load dll and its APIs.
 * @return 0 for success, non-zero for windows error codes.
 */
int lib_load() {
#ifdef WIN32
	hInst = LoadLibrary("asusnatnl.dll");
#else
	hInst = dlopen("./libasusnatnl.so", RTLD_LAZY);
#endif
	if (hInst == 0) {
#ifdef WIN32
		fprintf(stderr, "%d\n", GetLastError());
		exit(EXIT_FAILURE);
#else
		fprintf(stderr, "%s\n", dlerror());
		exit(EXIT_FAILURE);
#endif
	} else {
		GET_PROC_ADDR_AND_CHECK(set_max_instances);
		GET_PROC_ADDR_AND_CHECK(lib_init);
		GET_PROC_ADDR_AND_CHECK(lib_init2);
		GET_PROC_ADDR_AND_CHECK(lib_init3);
		GET_PROC_ADDR_AND_CHECK(lib_init_with_inst_id);
		GET_PROC_ADDR_AND_CHECK(lib_init_with_inst_id2);
		GET_PROC_ADDR_AND_CHECK(lib_init_with_inst_id3);
		GET_PROC_ADDR_AND_CHECK(lib_deinit);
		GET_PROC_ADDR_AND_CHECK(lib_deinit_with_inst_id);
		GET_PROC_ADDR_AND_CHECK(lib_deinit_all);
		GET_PROC_ADDR_AND_CHECK(make_call);
		GET_PROC_ADDR_AND_CHECK(make_call_with_inst_id);
		GET_PROC_ADDR_AND_CHECK(make_call_with_inst_id2);
		GET_PROC_ADDR_AND_CHECK(hangup_call);
		GET_PROC_ADDR_AND_CHECK(hangup_call_with_inst_id);
		GET_PROC_ADDR_AND_CHECK(reg_device);
		GET_PROC_ADDR_AND_CHECK(reg_device_with_inst_id);
		GET_PROC_ADDR_AND_CHECK(unreg_device);
		GET_PROC_ADDR_AND_CHECK(unreg_device_with_inst_id);
		GET_PROC_ADDR_AND_CHECK(update_config);
		GET_PROC_ADDR_AND_CHECK(update_config_with_inst_id);
		GET_PROC_ADDR_AND_CHECK(call_reinvite);
		GET_PROC_ADDR_AND_CHECK(call_reinvite_with_inst_id);
		GET_PROC_ADDR_AND_CHECK(tunnel_port);
		GET_PROC_ADDR_AND_CHECK(tunnel_port_with_inst_id);
		GET_PROC_ADDR_AND_CHECK(instant_msg_port);
		GET_PROC_ADDR_AND_CHECK(instant_msg_port_with_inst_id);
		GET_PROC_ADDR_AND_CHECK(pool_dump);
		GET_PROC_ADDR_AND_CHECK(pool_dump_with_inst_id);
		GET_PROC_ADDR_AND_CHECK(dump_version);
		GET_PROC_ADDR_AND_CHECK(dump_version_with_inst_id);
#if 1
		//GET_PROC_ADDR_AND_CHECK(send_instant_msg);
		GET_PROC_ADDR_AND_CHECK(send_instant_msg_with_inst_id);
		GET_PROC_ADDR_AND_CHECK(send_instant_msg_to_remote_process_with_inst_id);
#endif
		
		GET_PROC_ADDR_AND_CHECK(read_tnl_status);
		GET_PROC_ADDR_AND_CHECK(read_tnl_status_with_inst_id);
		GET_PROC_ADDR_AND_CHECK(read_tnl_info);
		GET_PROC_ADDR_AND_CHECK(read_tnl_info_with_inst_id);
		GET_PROC_ADDR_AND_CHECK(read_tnl_transfer_speed);
		GET_PROC_ADDR_AND_CHECK(read_tnl_transfer_speed_with_inst_id);
		GET_PROC_ADDR_AND_CHECK(set_tnl_transfer_speed_limit);
		GET_PROC_ADDR_AND_CHECK(set_tnl_transfer_speed_limit_with_inst_id);
		GET_PROC_ADDR_AND_CHECK(detect_nat_type);
#ifdef SUPPORT_ARP
		GET_PROC_ADDR_AND_CHECK(resolve_mac_by_arp);
#endif
		GET_PROC_ADDR_AND_CHECK(lib_version);
	}
	return 0;
}


/*
 * Callback function for call state changed
 * @call_state The natnl_call_state structure
 */
void on_natnl_tnl_event(struct natnl_tnl_event *tnl_event) {
	char *tnl_type;
#ifdef WIN32
	HANDLE        hThread;
	int iThreadId2, iThreadId3;
#endif

	if (tnl_event->event_code == NATNL_INV_EVENT_NULL)
		printf("[main.c] event null. ThreadId=[%08X], status=%d\n", GetCurrTID(), tnl_event->status_code);
	else if (tnl_event->event_code == NATNL_TNL_EVENT_MAKECALL_OK)
		current_callid = tnl_event->call_id;

	if (tnl_event->tnl_type == 0)
		tnl_type = "UNKNOWN";
	else if (tnl_event->tnl_type == 1)
		tnl_type = "TCP";
	else if (tnl_event->tnl_type == 2)
		tnl_type = "TURN";
	else if (tnl_event->tnl_type == 3)
		tnl_type = "UDP";
#if 0
	printf("!!!!!!!!!!!!![main.c] on_natnl_tnl_event call_id=%d, "
		"event_code=%d, event_text=%s, status_code=%d, status_text=%s, "
		"ua_type=%d, nat_type=%d, tnl_type=%s\n", 
		tnl_event->call_id,
		tnl_event->event_code,
		tnl_event->event_text,
		tnl_event->status_code,
		tnl_event->status_text,
		tnl_event->ua_type,
		tnl_event->nat_type,
		tnl_type);
#endif

	if (tnl_event->event_code == NATNL_TNL_EVENT_INIT_OK) {
		printf("[main.c] natnl_lib_init ok. ThreadId=[%08X]\n", GetCurrTID());
		// 2013-03-20 DEAN Added.
#ifdef WIN32
		if (strlen(device_id_to_call) > 0) {
			hThread = CreateThread(NULL, 0, make_call,
								(LPVOID)device_id_to_call, 0, &iThreadId3);
		} else {
			//hThread = CreateThread(NULL, 0, make_call,
			//	(LPVOID)callee, 0, &iThreadId3);
		}
#endif
	} else if (tnl_event->event_code == NATNL_TNL_EVENT_INIT_FAILED) {
		printf("[main.c] natnl_lib_init failed. ThreadId=[%08X], status=%d\n", GetCurrTID(), tnl_event->status_code);
	} else if (tnl_event->event_code == NATNL_TNL_EVENT_MAKECALL_OK) {
		int nat_type;
		printf("********* TUNNEL START *********\n");
		printf("tunnel type : %s\n", tnl_type);
		printf("********* TUNNEL START *********\n");
		//hThread = CreateThread(NULL, 0, natnl_hangup,
		//	0, 0, &iThreadId3);
		//printf("[main.c] natnl_make_call ok. ThreadId=[%08X]\n", GetCurrTID());
	} else if (tnl_event->event_code == NATNL_TNL_EVENT_MAKECALL_FAILED) {
		printf("[main.c] natnl_make_call make call failed. ThreadId=[%08X], status=%d\n", GetCurrTID(), tnl_event->status_code);
	} else if (tnl_event->event_code == NATNL_TNL_EVENT_HANGUP_OK) {
		printf("[main.c] natnl_hangup_call ok. ThreadId=[%08X]\n", GetCurrTID());

		hangup_ok = 1;
	} else if (tnl_event->event_code == NATNL_TNL_EVENT_HANGUP_FAILED) {
		printf("[main.c] natnl_hangup_call failed. ThreadId=[%08X], status=%d\n", GetCurrTID(), tnl_event->status_code);
	} else if (tnl_event->event_code == NATNL_TNL_EVENT_DEINIT_OK) {
		printf("[main.c] natnl_lib_deinit ok. ThreadId=[%08X]\n", GetCurrTID());
		//hThread = CreateThread(NULL, 0, natnl_init,
		//	0, 0, &iThreadId3);
	} else if (tnl_event->event_code == NATNL_TNL_EVENT_DEINIT_FAILED) {
		printf("[main.c] natnl_lib_deinit failed. ThreadId=[%08X], status=%d\n", GetCurrTID(), tnl_event->status_code);
		//hThread = CreateThread(NULL, 0, natnl_init,
		//	0, 0, &iThreadId3);
	} else if (tnl_event->event_code == NATNL_TNL_EVENT_REG_OK) {
		printf("[main.c] natnl_reg_device ok. ThreadId=[%08X], status=%d\n", GetCurrTID(), tnl_event->status_code);
	} else if (tnl_event->event_code == NATNL_TNL_EVENT_REG_FAILED) {
		printf("[main.c] natnl_reg_device failed. ThreadId=[%08X], status=%d\n", GetCurrTID(), tnl_event->status_code);
	} else if (tnl_event->event_code == NATNL_TNL_EVENT_UNREG_OK) {
		printf("[main.c] natnl_unreg_device ok. ThreadId=[%08X], status=%d\n", GetCurrTID(), tnl_event->status_code);
	} else if (tnl_event->event_code == NATNL_TNL_EVENT_UNREG_FAILED) {
		printf("[main.c] natnl_unreg_device failed. ThreadId=[%08X], status=%d\n", GetCurrTID(), tnl_event->status_code);
	} else if (tnl_event->event_code == NATNL_TNL_EVENT_KA_TIMEOUT) {
		printf("[main.c] natnl tunnel timeout. ThreadId=[%08X], status=%d\n", GetCurrTID(), tnl_event->status_code);
		//hangup_ok = 0;
		//hThread = CreateThread(NULL, 0, hang_up,
		//	current_callid, 0, &iThreadId2);
		//hThread = CreateThread(NULL, 0, reg_device,
		//	0, 0, &iThreadId2);
		//while(!hangup_ok) {
		//	printf("\n");
		//	Sleep(1);
		//}
		//hThread = CreateThread(NULL, 0, natnl_deinit,
		//	0, 0, &iThreadId3);
	} else if (tnl_event->event_code == NATNL_TNL_EVENT_IP_CHANGED) {
		printf("[main.c] natnl ip changed. ThreadId=[%08X], status=%d\n", GetCurrTID(), tnl_event->status_code);
		//natnl_lib_deinit_with_inst_id(1);
		//hThread = CreateThread(NULL, 0, natnl_deinit,
		//	0, 0, &iThreadId3);
	}
}

int parse_tunnel_port(char *input, char *lport, char *rport, int *qos_priority, int *disable_flow_control, int *speed_limit)
{
	char *buff;
	buff = strtok(input, ",");
	if (buff == NULL) {
		printf("Argument \"%s\" is not valid. The format is [lport,rport,qos_priority]",
			input);
		return -1;
	}
	strcpy(lport, buff);

	buff = strtok(NULL, ",");
	if (buff == NULL) {
		printf("Argument \"%s\" is not valid. The format is [lport,rport,qos_priority]",
			input);
		return -1;
	}
	strcpy(rport, buff);

	if (qos_priority) {
		buff = strtok(NULL, ",");
		if (buff)
			*qos_priority = atoi(buff);
		else
			*qos_priority = 0;
	}

	if (disable_flow_control) {
		buff = strtok(NULL, ",");
		if (buff)
			*disable_flow_control = atoi(buff);
		else
			*disable_flow_control = 0;
	}

	if (speed_limit) {
		buff = strtok(NULL, ",");
		if (buff)
			*speed_limit = atoi(buff);
		else
			*speed_limit = 0;
	}

	return 0;
}

int parse_instant_msg_port(char *input, char *dest_deviceid, char *lport, char *rport, int *timeout)
{
	char *buff;
	buff = strtok(input, ",");
	if (buff == NULL) {
		printf("Argument \"%s\" is not valid. The format is [lport,rport,qos_priority]",
			input);
		return -1;
	}
	strcpy(dest_deviceid, buff);

	buff = strtok(input, ",");
	if (buff == NULL) {
		printf("Argument \"%s\" is not valid. The format is [lport,rport,qos_priority]",
			input);
		return -1;
	}
	strcpy(lport, buff);

	buff = strtok(NULL, ",");
	if (buff == NULL) {
		printf("Argument \"%s\" is not valid. The format is [lport,rport,qos_priority]",
			input);
		return -1;
	}
	strcpy(rport, buff);

	if (timeout) {
		buff = strtok(NULL, ",");
		if (buff)
			*timeout = atoi(buff);
		else
			*timeout = 0;
	}

	return 0;
}

int main(int argc, char *argv[]) {
	int status = 0;
	char *sdk_ver;
	int sdk_ver_len;
	char *message = "test";

	natnl_tnl_port_count = 0;
	status = lib_load();
	if (status != 0) {
		printf("[main.c] falied to load asusnatnl.dll. error=[%d]\n", status);
		return -3;
	}
	// parse config arguments
	status = my_parse_args(argc, argv, &natnl_config, &natnl_tnl_port_count, natnl_tnl_ports, &natnl_config.im_port_count, natnl_config.im_ports);
	if (status != 0) {
		printf("[main.c] main parse_args failed. error=[%d]\n", status);
		return -3;
	}

	printf("staus=%d\n", status);

	if (status == 0) {
		// Set callback function
		natnl_callback.on_natnl_tnl_event = &on_natnl_tnl_event;

		sdk_ver = natnl_lib_version();

		printf("SDK version = %s\n", sdk_ver);

		//Iinitialize natnl dll
		status = natnl_lib_init_with_inst_id3(&natnl_config, &inst_id, &natnl_callback, message);
#ifdef AAE_TEST
		struct natnl_tnl_info tnl_info;
		status = natnl_make_call_with_inst_id2(callee, natnl_tnl_port_count, natnl_tnl_ports, 
			"asus", 180, 0, 1, "", &tnl_info);
		status = natnl_hangup_call_with_inst_id(tnl_info.call_id, 1);

#else
		//natnl_dump_version_with_inst_id(argc, argv, inst_id);

		if (status == 0)
		{
			int cnt = 0;
			char buff[1024] = {0};
#ifdef WIN32
			int iThreadId, iThreadId2, iThreadId3;
			HANDLE        hThread;
			// Create a tcp server thread to process UAC's request.
			status = tcp_server_run(&iThreadId);
			if (status != 0) {
				printf("[main.c] tcp_server_run() failed. error=[%d]\n", status);
				goto on_error;
			}
			status = udp_server_run(&iThreadId);
			if (status != 0) {
				printf("[main.c] udp_server_run() failed. error=[%d]\n", status);
				goto on_error;
			}
#endif
			// Wait for command inputed by user.
			while(1) {
				// DEAN use fgets instead of gets and check return value.
				if (fgets(buff, sizeof(buff), stdin) == NULL) 
					continue;

				printf("cmd=[%s]\n", buff);
				if (buff[0] == 'm' && buff[1] == '2') { // Make call
					int iid;
					char callee_id[128];
					struct natnl_tnl_info tnl_info;
					printf("Please input the instance id that you want to use:\n)");
					if (fgets(buff, sizeof(buff), stdin) == NULL) 
						continue;
						break;
					iid = atoi(buff);

					printf("Please input the callee id that you want to call:\n)");
					if (fgets(callee_id, sizeof(callee_id), stdin) == NULL) 
						continue;
						break;
#if 1
					status = natnl_make_call_with_inst_id(callee_id, natnl_tnl_port_count, natnl_tnl_ports, 
						"asus", 10, natnl_config.use_sctp, iid, &tnl_info);
#else
					hThread = CreateThread(NULL, 0, make_call,
						(LPVOID)callee, 0, &iThreadId3);
					hThread = CreateThread(NULL, 0, make_call2,
						(LPVOID)callee, 0, &iThreadId3);
#endif
					printf("[main.c] >>>>>>>>>>>> natnl_make_call=[%d], call_id=[%d]\n", status, tnl_info.call_id);
				} else if (buff[0] == 'm') { // Make call
					int iid = 1;
					int use_sctp = 1;
					struct natnl_tnl_info tnl_info;
					printf("Please input the instance id that you want to use:\n)");
					if (fgets(buff, sizeof(buff), stdin) == NULL) 
						break;
					iid = atoi(buff);
					printf("Please input 0 for use UDT, 1 for use SCTP:\n)");
					if (fgets(buff, sizeof(buff), stdin) == NULL) 
						break;
					use_sctp = atoi(buff);
#if 1
					status = natnl_make_call_with_inst_id2(callee, natnl_tnl_port_count, natnl_tnl_ports, 
						"asus", 180, use_sctp, iid, "", &tnl_info);
					printf("[main.c] >>>>>>>>>>>> natnl_make_call=[%d], call_id=[%d]\n", status, tnl_info.call_id);
#else
					hThread = CreateThread(NULL, 0, make_call,
						(LPVOID)callee, 0, &iThreadId3);
					hThread = CreateThread(NULL, 0, make_call2,
						(LPVOID)callee, 0, &iThreadId3);
#endif
#ifdef WIN32
					if (status == 0)
						hThread = CreateThread(NULL, 0, read_status, (LPVOID)&tnl_info, 0, &iThreadId3);
#endif

				}  else if (buff[0] == 'h') { // Hangup call
					int call_id = 0, iid = 1;
					printf("Please input the instance id that you want to use:\n)");
					if (fgets(buff, sizeof(buff), stdin) == NULL) 
						break;
					iid = atoi(buff);

					printf("Please input the call id you want to hanup. \n");
					if (fgets(buff, sizeof(buff), stdin) == NULL) 
						break;

					call_id = atoi(buff);
					status = natnl_hangup_call_with_inst_id(call_id, iid);
					printf("[main.c] >>>>>>>>>>>> natnl_hangup_call=[%d]\n", status);
				} else if (buff[0] == 'q') { // Quit the test program.
					status = natnl_lib_deinit_all();
					printf("[main.c] natnl_lib_deinit=[%d]\n", status);
#ifdef WIN32
					status = tcp_server_stop();
					printf("[main.c] tcp_server_stop=[%d]\n", status);
#endif
					break;
				} else if (buff[0] == 'r' && buff[1] == 'i') { // read tunnel information
					int call_id, iid;
					struct natnl_tnl_info tnl_info;
					printf("Please input the instance id that you want to use:\n)");
					if (fgets(buff, sizeof(buff), stdin) == NULL) 
						break;
					iid = atoi(buff);

					printf("Please input the call id you want to read information. \n");
					if (fgets(buff, sizeof(buff), stdin) == NULL) 
						break;
					call_id = atoi(buff);
					status = natnl_read_tnl_info_with_inst_id(call_id, &tnl_info, iid);
					printf("[main.c] >>>>>>>>>>>> natnl_read_tnl_info_with_inst_id=[%d]\n", status);
				} else if (buff[0] == 'r') { // Re-register to SIP server.
					status = natnl_reg_device_with_inst_id(inst_id);
					printf("[main.c] >>>>>>>>>>>> natnl_register_device=[%d]\n", status);
				} else if (buff[0] == 'u') { // Un-register from SIP server.
					status = natnl_unreg_device_with_inst_id(inst_id);
					printf("[main.c] >>>>>>>>>>>> natnl_unregister_device=[%d]\n", status);
				} else if (buff[0] == 'c') { // Update configuration to SDK.
					//strcpy(natnl_config.stun_srv, "stun.voip.aebc.com");

					//strcpy(natnl_config.device_id, "0010019000000000000138@aaerelay.asuscomm.com");
					//strcpy(natnl_config.device_pwd, "001001");
					//strcpy(natnl_config.sip_srv, "sgsip001001.asuscomm.com");
					//strcpy(natnl_config.turn_srv, "54.245.141.42:80");
					natnl_config.use_turn = 0;
					natnl_config.use_stun = 0;
					natnl_config.upnp_cfg.flag = 0;
					natnl_config.log_cfg.log_level = 4;
					status = natnl_update_config_with_inst_id(&natnl_config, inst_id);
					printf("[main.c] >>>>>>>>>>>> natnl_update_config=[%d]\n", status); 
				} else if (buff[0] == 'v') { // Dump SDK memory data.
					natnl_pool_dump_with_inst_id(1, inst_id);
#ifdef WIN32
				} else if (buff[0] == 'g' && buff[1] == 'u') { // Get a file from remote by using udp loopback.
					printf("Please input the file name you want to get from remote:\n)");
					if (fgets(buff, sizeof(buff), stdin) == NULL) 
						break;
					//status = get_romote_file(buff);
					hThread = CreateThread(NULL, 0, get_file_udp,
						buff, 0, &iThreadId3);
					printf("[main.c] get_romote_file=[%d]\n", status);
				} else if (buff[0] == 'G' && buff[1] == 'u') { // Get a fixed length data from remote by using udp loopback.
					printf("Please input the data size you want to get from remote:\n)");
					if (fgets(buff, sizeof(buff), stdin) == NULL) 
						break;
					//status = get_romote_file(buff);
					hThread = CreateThread(NULL, 0, get_data_udp,
						buff, 0, &iThreadId3);
					printf("[main.c] get_romote_file=[%d]\n", status);
				} else if (buff[0] == 'p' && buff[1] == 'u') { // Send a file to remote by using udp loopback.
					printf("Please input the file name you want to put to remote:\n)");
					if (fgets(buff, sizeof(buff), stdin) == NULL) 
						break;
					//status = put_local_file(buff);
					hThread = CreateThread(NULL, 0, put_file_udp,
						buff, 0, &iThreadId3);
					printf("[main.c] put_local_file=[%d]\n", status);
				} else if (buff[0] == 'P' && buff[1] == 'u') { // Repeat to send a fixed length data to remote by using udp loopback.
					printf("Please input the data size you want to test with remote endpoint:\n)");
					if (fgets(buff, sizeof(buff), stdin) == NULL) 
						break;
					//status = put_local_file(buff);
					hThread = CreateThread(NULL, 0, put_data_udp,
						buff, 0, &iThreadId3);
					printf("[main.c] put_local_file=[%d]\n", status);
				} else if (buff[0] == 'g') { // Get a file from remote by using tcp loopback
					printf("Please input the file name you want to get from remote:\n)");
					if (fgets(buff, sizeof(buff), stdin) == NULL) 
						break;
					//status = get_romote_file(buff);
					hThread = CreateThread(NULL, 0, get_file_tcp,
						buff, 0, &iThreadId3);
					printf("[main.c] get_romote_file=[%d]\n", status);
				} else if (buff[0] == 'G') { // Repeat to get a fixed length data from remote by using tcp loopback
					printf("Please input the data size you want to get from remote:\n)");
					if (fgets(buff, sizeof(buff), stdin) == NULL) 
						break;
					//status = get_romote_file(buff);
					hThread = CreateThread(NULL, 0, get_data_tcp,
						buff, 0, &iThreadId3);
					printf("[main.c] get_romote_file=[%d]\n", status);
				} else if (buff[0] == 'p') { // Send a file to remote by using tcp loopback
					printf("Please input the file name you want to put to remote:\n)");
					if (fgets(buff, sizeof(buff), stdin) == NULL) 
						break;
					//status = put_local_file(buff);
					hThread = CreateThread(NULL, 0, put_file_tcp,
						buff, 0, &iThreadId3);
					printf("[main.c] put_local_file=[%d]\n", status);
				} else if (buff[0] == 'P') { // Repeate to send fixed length data to remote by using tcp loopback
					printf("Please input the data size you want to test with remote endpoint:\n)");
					if (fgets(buff, sizeof(buff), stdin) == NULL) 
						break;
					//status = put_local_file(buff);
					hThread = CreateThread(NULL, 0, put_data_tcp,
						buff, 0, &iThreadId3);
					printf("[main.c] put_local_file=[%d]\n", status);
				} else if (buff[0] == 's' && buff[1] == 'l') { // Set transfer speed limit.
					struct natnl_tnl_transfer_speed limit_speed;
					int call_id;
					int iid;
					int status;
					printf("Please input the instance id that you want to set transfer speed limit:\n)");
					if (fgets(buff, sizeof(buff), stdin) == NULL) 
						break;
					iid = atoi(buff);

					printf("Please input the call id you want to set transfer speed limit. \nIf there is no tunnel please input -1.\n)");
					if (fgets(buff, sizeof(buff), stdin) == NULL) 
						break;
					call_id = atoi(buff);

					printf("Please input the rx limit in bytes/s unit. 0 reprsents no limit.\n)");
					if (fgets(buff, sizeof(buff), stdin) == NULL) 
						break;
					limit_speed.rx_speed = atoi(buff);

					printf("Please input the tx limit in bytes/s unit. 0 reprsents no limit.\n)");
					if (fgets(buff, sizeof(buff), stdin) == NULL) 
						break;
					limit_speed.tx_speed = atoi(buff);

					status = natnl_set_tnl_transfer_speed_limit_with_inst_id(call_id, limit_speed, iid);
					if (status == 0)
						printf("[main.c] natnl_set_tnl_transfer_speed_limit_with_inst_id success.\n");
					else if (status == 70004)
						printf("Invalid Arguments!!\n");
					else if (status == NATNL_SC_NOT_INITED)
						printf("SDK didn't be initialized!\n!");
					else
						printf("Error occur!! code=[%d]\n", status);
				} else if (buff[0] == 's' && buff[1] == 'i') { // Send test data to remote
					int max_instance;
					printf("Please input the number of instance you want to set:\n)");
					if (fgets(buff, sizeof(buff), stdin) == NULL) 
						break;
					max_instance = atoi(buff);
					status = natnl_set_max_instances(max_instance);
					printf("[main.c] >>>>>>>>>>>> natnl_set_max_instance=[%d]\n", status);
				} else if (buff[0] == 's') { // Send test data to remote
					status = send_data_test(buff);
					printf("[main.c] Send data test=[%d]\n", status);
#endif
				} else if (buff[0] == 'i' && buff[1] == 'm' && buff[2] == '2') { // Initialize SDK
					char *device_id;
					char user_msg[1024] = {0};
					char resp_msg[1024] = {0};
					int resp_msg_len = sizeof(resp_msg);
					char *default_msg = "TEST MESSAGE";
					char *gets_buf;
					printf("Please input the device_id you want to send message:\n)");
					if ((fgets(buff, sizeof(buff), stdin)) == NULL) 
						break;

					printf("Please input the message you want to send out:\n)");
					if ((fgets(user_msg, sizeof(user_msg), stdin)) == NULL) 
						break;

					if (buff[0] == '\n')
						device_id = &callee[0];
					else
						device_id = &buff[0];

					status = natnl_send_instant_msg_to_remote_process_with_inst_id(
						(device_id),
						(user_msg[0] == '\n' ? strlen("TEST MESSAGE") : strlen(user_msg)),
						(user_msg[0] == '\n' ? default_msg : user_msg), "aaews",
						&resp_msg_len,
						resp_msg, 1);

					if (buff[0] == '\n')
						device_id = &callee[0];
					else
						device_id = &buff[0];
					printf("[main.c] >>>>>>>>>>>> natnl_send_instant_msg_with_inst_id() ret=[%d], resp_msg=%.*s\n", status, resp_msg_len, resp_msg);
				} else if (buff[0] == 'i' && buff[1] == 'm') { // Initialize SDK
#define NATNL_IM_MAX_LEN 13000
					char *device_id;
					char user_msg[NATNL_IM_MAX_LEN] = {0};
					char resp_msg[NATNL_IM_MAX_LEN] = {0};
					int resp_msg_len = sizeof(resp_msg);
					char *default_msg = "GET /12k.txt HTTP/1.1\r\nHost: 192.168.1.150\r\nCache-Control: no-cache\r\n\r\n";
					char *gets_buf;
					printf("Please input the device_id you want to send message:\n)");
					if ((fgets(buff, sizeof(buff), stdin)) == NULL) 
						break;

					printf("Please input the message you want to send out:\n)");
					if ((fgets(user_msg, sizeof(user_msg), stdin)) == NULL) 
						break;

					if (buff[0] == '\n')
						device_id = &callee[0];
					else
						device_id = &buff[0];

					status = natnl_send_instant_msg_with_inst_id(
						(device_id),
						(user_msg[0] == '\n' ? strlen(default_msg) : strlen(user_msg)),
						(user_msg[0] == '\n' ? default_msg : user_msg), 80,
						&resp_msg_len,
						resp_msg, 1);

					/*if (buff[0] == '\n')
						device_id = &callee[0];
					else
						device_id = &buff[0];

					status = natnl_send_instant_msg_with_inst_id(
						(device_id),
						(user_msg[0] == '\n' ? strlen("TEST MESSAGE") : strlen(user_msg)),
						(user_msg[0] == '\n' ? default_msg : user_msg), 443,
						&resp_msg_len,
						resp_msg, 1);

					if (buff[0] == '\n')
						device_id = &callee[0];
					else
						device_id = &buff[0];

					status = natnl_send_instant_msg_with_inst_id(
						(callee),
						(user_msg[0] == '\n' ? strlen("TEST MESSAGE") : strlen(user_msg)),
						(user_msg[0] == '\n' ? default_msg : user_msg), 443,
						&resp_msg_len,
						resp_msg, 1);*/
					printf("[main.c] >>>>>>>>>>>> natnl_send_instant_msg_with_inst_id() ret=[%d], resp_msg=%.*s\n", status, resp_msg_len, resp_msg);
				} else if (buff[0] == 'i') { // Initialize SDK
					status = natnl_lib_init_with_inst_id(&natnl_config, &inst_id);
					printf("[main.c] >>>>>>>>>>>> natnl_lib_init=[%d]\n", status);
				} else if (buff[0] == 'd' && buff[1] == 'a') { // De-initialize all instances of SDK
					status = natnl_lib_deinit_all();
					printf("[main.c] >>>>>>>>>>>> natnl_lib_deinit_all=[%d\n", status);
				} else if (buff[0] == 'd') { // De-initialize SDK
					int iid;
					printf("Please input the instance id that you want to de-initialize:\n)");
					if (fgets(buff, sizeof(buff), stdin) == NULL) 
						break;
					iid = atoi(buff);
					status = natnl_lib_deinit_with_inst_id(iid);
					printf("[main.c] >>>>>>>>>>>> natnl_lib_deinit=[%d\n", status);
				} else if (buff[0] == 'y') { // Reinvite call
					status = natnl_call_reinvite_with_inst_id(reinvite_callid, inst_id);
					reinvite_callid = !reinvite_callid;
					printf("[main.c] >>>>>>>>>>>> natnl_call_reinvite=[%d\n", status);
				} else if (buff[0] == 't' && buff[1] == 'a') { // Add tunnel port
					natnl_tnl_port tnl_ports[1];
					char lport[6], rport[6];
					int qos_priority;
					int disable_flow_control;
					int speed_limit;
					int call_id;
					int iid;
					printf("Please input the instance id that you want to add tunnel port:\n)");
					if (fgets(buff, sizeof(buff), stdin) == NULL) 
						break;
					iid = atoi(buff);

					printf("Please input the call id you want to add tunnel port. \nIf there is no tunnel please input -1.\n)");
					if (fgets(buff, sizeof(buff), stdin) == NULL) 
						break;

					call_id = atoi(buff);

					printf("Please input the tunnel port you want to add. (format : lport,rport[,qos_priority,disable_flow_control]):\n)");
					if (fgets(buff, sizeof(buff), stdin) == NULL) 
						break;

					status = parse_tunnel_port(buff, lport, rport, &qos_priority, &disable_flow_control, &speed_limit);
					if (status != 0)
						break;

					strcpy(tnl_ports[0].lport, lport);
					strcpy(tnl_ports[0].rport, rport);
					tnl_ports[0].qos_priority = qos_priority;
					tnl_ports[0].disable_flow_control = disable_flow_control;
					tnl_ports[0].speed_limit = speed_limit;
					status = natnl_tunnel_port_with_inst_id(call_id, 1, 1, tnl_ports, iid);
					reinvite_callid = !reinvite_callid;
					printf("[main.c] >>>>>>>>>>>> natnl_tunnel_port=[%d\n", status);
				} else if (buff[0] == 't' && buff[1] == 'r') { // Remove tunnel port
					natnl_tnl_port tnl_ports[1];
					char lport[6], rport[6];
					int qos_priority;
					int disable_flow_control;
					int speed_limit;
					int call_id;
					int iid;
					printf("Please input the instance id that you want to remove tunnel port:\n)");
					if (fgets(buff, sizeof(buff), stdin) == NULL) 
						break;
					iid = atoi(buff);

					printf("Please input the call id you want to remove from tunnel port. \nIf there is no tunnel please input -1.\n)");
					if (fgets(buff, sizeof(buff), stdin) == NULL) 
						break;

					call_id = atoi(buff);

					printf("Please input the tunnel port you want to remove. (format : lport,rport[,qos_priority]):\n)");
					if (fgets(buff, sizeof(buff), stdin) == NULL) 
						break;

					status = parse_tunnel_port(buff, lport, rport, &qos_priority, &disable_flow_control, &speed_limit);
					if (status != 0)
						break;

					strcpy(tnl_ports[0].lport, lport);
					strcpy(tnl_ports[0].rport, rport);
					tnl_ports[0].qos_priority = qos_priority;
					tnl_ports[0].disable_flow_control = disable_flow_control;
					tnl_ports[0].speed_limit = speed_limit;
					status = natnl_tunnel_port_with_inst_id(call_id, 2, 1, tnl_ports, iid);
					reinvite_callid = !reinvite_callid;
					printf("[main.c] >>>>>>>>>>>> natnl_tunnel_port=[%d]\n", status);
				} else if (buff[0] == 't' && buff[1] == 'i' && buff[2] == 'm') { // Add instant message port
					natnl_im_port im_ports[1];
					char dest_deviceid[128], lport[6], rport[6];
					int iid, timeout;
					printf("Please input the instance id that you want to add im port:\n)");
					if (fgets(buff, sizeof(buff), stdin) == NULL) 
						break;
					iid = atoi(buff);

					printf("Please input the im port you want to add. (format : dest_deviceid,lport,rport,timeout\n)");
					if (fgets(buff, sizeof(buff), stdin) == NULL) 
						break;

					if (buff[0] == '\n') {
						strcpy(dest_deviceid, &callee[0]);
						strcpy(lport, "50800");
						strcpy(rport, "80");
						timeout = 30;
					} else {
						status = parse_instant_msg_port(buff, dest_deviceid, lport, rport, &timeout);
						if (status != 0)
							break;
					}

					strcpy(im_ports[0].dest_device_id, dest_deviceid);
					strcpy(im_ports[0].lport, lport);
					strcpy(im_ports[0].rport, rport);
					im_ports[0].timeout_sec = timeout;
					status = natnl_instant_msg_port_with_inst_id(1, 1, im_ports, iid);
					reinvite_callid = !reinvite_callid;
					printf("[main.c] >>>>>>>>>>>> natnl_tunnel_port=[%d\n", status);
				} else if (buff[0] == 't' && buff[1] == 'i' && buff[2] == 'r') { // Remove instant message port
					natnl_im_port im_ports[1];
					char dest_deviceid[128], lport[6], rport[6];
					int qos_priority;
					int disable_flow_control;
					int iid, timeout;
					printf("Please input the instance id that you want to remove tunnel port:\n)");
					if (fgets(buff, sizeof(buff), stdin) == NULL) 
						break;
					iid = atoi(buff);

					printf("Please input the tunnel port you want to remove. (format : lport,rport):\n)");
					if (fgets(buff, 
						sizeof(buff), stdin) == NULL) 
						break;
					if (buff[0] == '\n') {
						strcpy(dest_deviceid, &callee[0]);
						strcpy(lport, "7000");
						strcpy(rport, "8088");
						timeout = 30;
					} else {
						status = parse_instant_msg_port(buff, dest_deviceid, lport, rport, &timeout);
						if (status != 0)
							break;
					}

					strcpy(im_ports[0].lport, lport);
					strcpy(im_ports[0].rport, rport);
					status = natnl_instant_msg_port_with_inst_id(2, 1, im_ports, iid);
					reinvite_callid = !reinvite_callid;
					printf("[main.c] >>>>>>>>>>>> natnl_tunnel_port=[%d]\n", status);
				} else if (buff[0] == 'n') {
					int nat_type = natnl_detect_nat_type("sgstun001.asuscomm.com");
					printf("[main.c] natnl_detect_nat_type=[%d]\n", nat_type);
				} else if (buff[0] == 'b') { // Read transfer speed
					struct natnl_tnl_transfer_speed transfer_speed;
					int call_id;
					int iid;
					int status;
					printf("Please input the instance id that you want to read transfer speed:\n)");
					if (fgets(buff, sizeof(buff), stdin) == NULL) 
						break;
					iid = atoi(buff);

					printf("Please input the call id you want to read transfer speed. \nIf there is no tunnel please input -1.\n)");
					if (fgets(buff, sizeof(buff), stdin) == NULL) 
						break;
					call_id = atoi(buff);

					status = natnl_read_tnl_transfer_speed_with_inst_id(call_id, &transfer_speed, iid);
					if (status == 0)
						printf("[main.c] rx_speed=[%dBps], tx_speed=[%dBps]\n", transfer_speed.rx_speed, transfer_speed.tx_speed);
					else if (status == 70004)
						printf("Invalid Arguments!!\n");
					else if (status == NATNL_SC_NOT_INITED)
						printf("SDK didn't be initialized!\n!");
					else
						printf("Error occur!! code=[%d]\n", status);
				}
				printf("cnt=[%d]\n", cnt);
		#ifndef WIN32
				sleep(1);
		#else
				Sleep(1);
		#endif
				cnt++;
			}
			lib_unload();
			return 0;
		}
#endif  // AAE_TEST
	}
on_error:
	//natnl_lib_deinit_all();
	lib_unload();
	return 0;
}
