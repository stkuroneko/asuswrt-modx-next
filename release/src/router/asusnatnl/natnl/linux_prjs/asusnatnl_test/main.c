#include <stdio.h>
#include <stdlib.h>

#include <config.h>
#include <natnl_lib.h>

char callee[128], registrar_uri[128];

/*The definition of global variables that are in natnl_dll.h*/
struct natnl_config natnl_config;
struct natnl_srv_port natnl_srv_ports[MAX_SRV_PORT_COUNT];
int natnl_srv_port_count;
struct natnl_callback natnl_callback;

#if 0
/*The function pointer of APIs type definition*/
typedef int WINAPI fp_natnl_lib_init(struct natnl_config *cfg, 
						   struct natnl_callback *natnl_cb);
typedef int WINAPI fp_natnl_lib_deinit(void);
typedef int WINAPI fp_natnl_make_call(char *device_id, int srv_port_count, 
							struct natnl_srv_port srv_port[], int *call_id, 
							char *user_id);
typedef int WINAPI fp_natnl_hangup_call(int call_id);

/*The APIs variable definition*/
static fp_natnl_lib_init *natnl_lib_init = 0;
static fp_natnl_lib_deinit *natnl_lib_deinit = 0;
static fp_natnl_make_call *natnl_make_call = 0;
static fp_natnl_hangup_call *natnl_hangup_call = 0;

extern int tcp_server_run(DWORD *dwThreadId);
extern int tcp_server_stop();
extern int put_local_file(char *file_name);
extern int get_romote_file(char *file_name);
#endif
/*
 * Callback function for call state changed
 * @call_state The natnl_call_state structure
 */
void on_natnl_tnl_event(struct natnl_tnl_event *tnl_event) {
	printf("!!!!!!!!!!!!![main.c] on_natnl_tnl_event call_id=%d, "
		"event_code=%d, event_text=%s, status_code=%d, status_text=%s\n", 
		tnl_event->call_id,
		tnl_event->event_code,
		tnl_event->event_text,
		tnl_event->status_code,
		tnl_event->status_text);
}
#if 0
/*
 * Load dll and its APIs.
 * @return 0 for success, non-zero for windows error codes.
 */
int lib_load() {
	HMODULE hInst;
	hInst = LoadLibrary("asusnatnl.dll");
	if (hInst == 0) {
		return GetLastError();
	} else {
		(FARPROC)(natnl_lib_init) = GetProcAddress(hInst, "natnl_lib_init");
		(FARPROC)(natnl_lib_deinit) = GetProcAddress(hInst, "natnl_lib_deinit");
		(FARPROC)(natnl_make_call) = GetProcAddress(hInst, "natnl_make_call");
		(FARPROC)(natnl_hangup_call) = GetProcAddress(hInst, "natnl_hangup_call");

		if (natnl_lib_init == NULL ||
			natnl_lib_deinit == NULL ||
			natnl_make_call == NULL ||
			natnl_hangup_call == NULL) {
			return -1; // Failed to Load Library
		}
	}
	return 0 ;
}
#endif

int main(int argc, char *argv[]) {
	int status = 0;
	int call_id;

	natnl_srv_port_count = 0;
	// parse config arguments
	status = my_parse_args(argc, argv, &natnl_config, &natnl_srv_port_count, natnl_srv_ports);
	if (status != 0) {
		printf("[main.c] main parse_args failed. error=[%d]\n", status);
		return -3;
	}
#if 0
	status = lib_load();
	printf("staus=%d\n", status);
	if (status == 0) {
#endif
		// Set callback function
		natnl_callback.on_natnl_tnl_event = &on_natnl_tnl_event;

		//Iinitialize natnl dll
		status = natnl_lib_init(&natnl_config, &natnl_callback);
		if (status == 0) {
			int cnt = 0;
			char buff[1024] = {0};
			int iThreadId;
			// Create a tcp server thread to process UAC's request.
			printf("[main.c] natnl_lib_init ok.\n");
#if 0
            status = tcp_server_run(&iThreadId);
			if (status != 0) {
				printf("[main.c] tcp_server_run() failed. error=[%d]\n", status);
				goto on_error;
			}
#endif
			// Wait for command inputed by user.
			while(cnt < 200) {
				// DEAN use fgets instead of gets and check return value.
				if (fgets(buff, sizeof(buff), stdin) == NULL) 
					continue;

				printf("cmd=[%s]\n", buff);
				if (buff[0] == 'm') {
					status = natnl_make_call(callee, natnl_srv_port_count, natnl_srv_ports, 
						&call_id, "asus");
					printf("[main.c] natnl_make_call=[%d], call_id=[%d]\n", status, call_id);
				} else if (buff[0] == 'h') {
					status = natnl_hangup_call(call_id);
					printf("[main.c] natnl_hangup_call=[%d]\n", status);
				} else if (buff[0] == 'q') {
					status = natnl_lib_deinit();
					printf("[main.c] natnl_dll_deinit=[%d]\n", status);
                    #if 0
					status = tcp_server_stop();
					printf("[main.c] tcp_server_stop=[%d]\n", status);
                    #endif
					break;
				}
                #if 0 
                else if (buff[0] == 'g') {
					printf("Please input the file name you want to get from remote:\n)");
					if (gets(buff) == NULL) 
						break;
					status = get_romote_file(buff);
				} else if (buff[0] == 'p') {
					printf("Please input the file name you want to put to remote:\n)");
					if (gets(buff) == NULL) 
						break;
					status = put_local_file(buff);
				}
                #endif
				printf("cnt=[%d]\n", cnt);
		#ifndef WIN32
				sleep(1);
		#else
				Sleep(1);
		#endif
				cnt++;
			}
			natnl_lib_deinit();
			return 0;
		}
#if 0
	}
#endif
on_error:
	natnl_lib_deinit();
	return 0;
}