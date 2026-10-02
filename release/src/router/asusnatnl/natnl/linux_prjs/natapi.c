#include <stdio.h>
#include <stdlib.h>

#include <config.h>
#include <natnl_lib.h>
#include <dlfcn.h>
#include "server.h"
#include <client.h>
#include "natapi.h"
#include <j_log.h>


char callee[128], registrar_uri[128];
#define THIS_FILE "natapi.c"
#define DEFAULT_PORT        "5678"
#ifdef WIN32 

/*The definition of global variables that are in natnl_dll.h*/
struct natnl_config natnl_config;
struct natnl_srv_port natnl_srv_ports[MAX_SRV_PORT_COUNT];
int natnl_srv_port_count;

/*The function pointer of APIs type definition*/
typedef int WINAPI fp_natnl_lib_init(struct natnl_config *cfg);
typedef int WINAPI fp_natnl_lib_deinit(void);
typedef int WINAPI fp_natnl_make_call(char *device_id, int srv_port_count, struct natnl_srv_port srv_port[], int *call_id);
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
#else

//struct natnl_func
//{
	int (*fp_natnl_lib_init)	(struct natnl_config *cfg);
	int (*fp_natnl_lib_deinit)	(void);
	int (*fp_natnl_make_call)	(char *device_id, int srv_port_count, struct natnl_srv_port srv_port[], int *call_id);
	int (*fp_natnl_hangup_call)	(int call_id);
//};


int lib_load()
{
	void *handle=NULL;
    char *error;
	LOG_E(THIS_FILE, "lib_load............1");

	handle = dlopen("libnatnl.so", RTLD_LAZY);
	if (!handle) {
        fprintf(stderr, "%s\n", dlerror());
        exit(EXIT_FAILURE);
	}
	LOG_E(THIS_FILE, "lib_load............2");

	LOG_E(THIS_FILE, "lib_load............2-1, error=%s", dlerror());

   /* Writing: cosine = (double (*)(double)) dlsym(handle, "cos");
       would seem more natural, but the C99 standard leaves
       casting from "void *" to a function pointer undefined.
       The assignment used below is the POSIX.1-2003 (Technical
       Corrigendum 1) workaround; see the Rationale for the
       POSIX specification of dlsym(). */

//   *(void **) (&cosine) = dlsym(handle, "cos");
	LOG_E(THIS_FILE, "lib_load............3");
	*(void **) (&fp_natnl_lib_init)		=	dlsym(handle, "natnl_lib_init");
	LOG_E(THIS_FILE, "lib_load............3-1");
	*(void **) (&fp_natnl_lib_deinit)	=	dlsym(handle, "natnl_lib_deinit");
	LOG_E(THIS_FILE, "lib_load............3-2");
	*(void **) (&fp_natnl_make_call)	=	dlsym(handle, "natnl_make_call");
	LOG_E(THIS_FILE, "lib_load............3-3");
	*(void **) (&fp_natnl_hangup_call)	=	dlsym(handle, "natnl_hangup_call");
	LOG_E(THIS_FILE, "lib_load............3-4");

	if ((error = dlerror()) != NULL)  {
	LOG_E(THIS_FILE, "lib_load............4, error=%s", error);
        fprintf(stderr, "%s\n", error);
        exit(EXIT_FAILURE);
    }

//	printf("%f\n", (*cosine)(2.0));
	LOG_E(THIS_FILE, "lib_load............5");
	dlclose(handle);
	return error;
}
#endif

int nat_config_init_replace_temp(struct natnl_config * nat_cfg ,struct natnl_srv_port* pnat_srvport)
{
#if 0
	strcpy(natnl_config.device_id,"b1dcad856a21d0198dd3a2a352d329a7");
	strcpy(natnl_config.sip_srv,"ec2-50-17-15-111.compute-1.amazonaws.com");
	strcpy(natnl_config.stun_srv,"stun.voip.aebc.com");
	natnl_config.force_to_use_ice=1;
	natnl_config.use_turn = 0;
	strcpy(natnl_config.turn_usr, "dean_li@asus.com");
	strcpy(natnl_config.turn_pwd, "asus");
	strcpy(natnl_srv_ports[0].lport ,"5555"); 
	strcpy(natnl_srv_ports[0].rport ,"8000"); 
#else
	strcpy(nat_cfg->device_id,"b1dcad856a21d0198dd3a2a352d329a7");
	strcpy(nat_cfg->sip_srv,"ec2-50-17-15-111.compute-1.amazonaws.com");
	//strcpy(nat_cfg->sip_srv,"50.17.15.111");
	strcpy(nat_cfg->stun_srv,"stun.voip.aebc.com");
	nat_cfg->force_to_use_ice=1;
	nat_cfg->use_turn = 0;
//	strcpy(nat_cfg->turn_usr, "dean_li@asus.com");
//	strcpy(nat_cfg->turn_pwd, "asus");
//	strcpy(nat_srvports[0].lport ,"5555"); 
	strcpy(pnat_srvport->lport ,"5678"); 
	strcpy(pnat_srvport->rport ,"8000"); 

#endif
	return 0;
}

int g_call_id;

int natapi_init(struct natnl_config * nat_cfg, struct natnl_srv_port* pnat_srvports,char* n_callee, struct natnl_callback* pnatnl_callback)
{
	int status = 0;
//	strcpy(callee, "3305595e6d05afbe4dfa39472786beb1"  );
	LOG_E(THIS_FILE, "natapi_init()	=>	1");
#if 1 
	if(natapi_init_server()){
		LOG_E(THIS_FILE, "natapi_init : init server failed");
		goto natapi_init_error;
	}
#endif
	strcpy(callee, n_callee);

#if 0 
	//if(status = nat_config_init_replace_temp(nat_cfg, pnat_srvport))	goto natapi_init_error;
	char *cmd[]={"andorid-app", "--config-file=/mnt/sdcard/natnl02-relay.cfg"};
	status = my_parse_args(2, cmd, nat_cfg,&natnl_srv_port_count, pnat_srvports);
#else
	int i =0;
	for(i=0;i<MAX_SRV_PORT_COUNT;i++){
		strcpy(natnl_srv_ports[i].lport, pnat_srvports[i].lport);
		strcpy(natnl_srv_ports[i].rport, pnat_srvports[i].rport);
	}


	LOG_E(THIS_FILE, "natapi...........srv_ports=(%s,%s), callee=%s",pnat_srvports[0].lport, pnat_srvports[0].rport, callee );
	if(status <0) goto natapi_init_error;
	//	no init config file here
#endif

#if 0
	    LOG_E(THIS_FILE, "device id : %s", nat_cfg->device_id);
		    LOG_E(THIS_FILE, "device  pwd: %s", nat_cfg->device_pwd);
			    LOG_E(THIS_FILE, "callee: %s", callee);
				    LOG_E(THIS_FILE, "sip srv : %s", nat_cfg->sip_srv);
					    LOG_E(THIS_FILE, "stun srv : %s", nat_cfg->stun_srv);
						    LOG_E(THIS_FILE, "force_to_use_ice : %d", nat_cfg->force_to_use_ice);
							    LOG_E(THIS_FILE, "use turn : %d", nat_cfg->use_turn);
								    LOG_E(THIS_FILE, "turn srv : %s", nat_cfg->turn_srv);
#endif

	LOG_E(THIS_FILE, "natapi_init()	=>	2");
//	if(status = natnl_lib_init(&natnl_config))							goto natapi_init_error;
	if(status = natnl_lib_init(nat_cfg,pnatnl_callback) )							goto natapi_init_error;
natapi_init_error:
	LOG_E(THIS_FILE, "natapi............return status error code = %d, callee=%s", status, callee);
	return status;
}

int natapi_make_call(struct natnl_srv_port* nat_srvports )
{
	int status = 0;
	LOG_E(THIS_FILE, "natap_make_call()	=>	1");
	LOG_E(THIS_FILE, "*****************************************************************************srv_ports[0].lport=%s, callee =%s", nat_srvports[0].lport, callee);
//	if(status = natnl_make_call(callee, 1,natnl_srv_ports,&g_call_id))	goto natapi_make_call_error;
	if(status = natnl_make_call(callee, 1,nat_srvports,&g_call_id))	goto natapi_make_call_error;
	LOG_E(THIS_FILE, "*****************************************************************************srv_ports=%s", nat_srvports[0].lport);
natapi_make_call_error:
	return status;
}

int natapi_deinit()
{
//	natapi_deinit_server();
	return natnl_lib_deinit(); 
}

int natapi_hangup_call()
{
	return  natnl_hangup_call(g_call_id);
}

int natapi_getfile(char* d_filename)
{
	LOG_E(THIS_FILE, "natapi_getfile()-- filename=%s, natnl_srv_ports[0].lport=%s", d_filename,  natnl_srv_ports[0].lport);
//	return get_remote_file(d_filename, natnl_srv_ports[0].lport);
	return get_remote_file(d_filename, DEFAULT_PORT);
}

int natapi_putfile(char* d_filename)
{
	LOG_E(THIS_FILE, "natapi_putfile()-- filename=%s, natnl_srv_ports[0].lport=%s", d_filename,  natnl_srv_ports[0].lport);
	//return get_remote_file(d_filename, natnl_srv_ports[0].lport);
	return put_local_file(d_filename,natnl_srv_ports[0].lport);
}

int natapi_quit()
{
	int status=0;
	if(status = natnl_lib_deinit()) goto natapi_quit_error;
//	status = tcp_server_stop();
natapi_quit_error:
	LOG_E(THIS_FILE, "natapi_quit()	=>	status=%d", status);
	return status;
}


int natapi_init_server()
{
	int err = start_tcp_server_thread();
	return err;
}

int natapi_deinit_server()
{	
	int err = stop_tcp_server_thread();
	return err;
}

#if 0
//int main(int argc, char *argv[]) {
//int main(char* buff, char* d_filename) {// buff = command of natnl 
int natapi(char* buff, char* d_filename) {// buff = command of natnl 
	int status = 0;
	int call_id;

	// parse config arguments
//	status = my_parse_args(argc, argv, &natnl_config, &natnl_srv_ports[0]);
	LOG_E(THIS_FILE, "natapi............1");
	// charles bug , calling parameter
	status = nat_config_init_replace_temp();

	if (status != 0) {
		printf("[main.c] main parse_args failed. error=[%d]\n", status);
		return -3;
	}

	LOG_E(THIS_FILE, "natapi............2");
#if 0 // failed to load library in Android
	status = lib_load();
#endif
//	printf("staus=%d\n", status);
	if (status == 0) {
		//Iinitialize natnl dll
	LOG_E(THIS_FILE, "natapi............3");
		//status = fp_natnl_lib_init(&natnl_config);
		status = natnl_lib_init(&natnl_config);
		if (status == 0) {
			int cnt = 0;
			char buff[1024] = {0};
			int iThreadId;
			// Create a tcp server thread to process UAC's request.
	LOG_E(THIS_FILE, "natapi............4");
#if 0	// don't init tcp server thread
			status = tcp_server_run(&iThreadId);
			if (status != 0) {
				printf("[main.c] tcp_server_run() failed. error=[%d]\n", status);
				goto on_error;
			}
#endif
			// Wait for command inputed by user.
//			while(cnt < 200) {
				// DEAN use fgets instead of gets and check return value.
//				if (fgets(buff, sizeof(buff), stdin) == NULL) 
//					continue;
	LOG_E(THIS_FILE, "natapi............5");
				printf("cmd=[%s]\n", buff);
				if (buff[0] == 'm') {
	LOG_E(THIS_FILE, "natapi............m");
					//status = fp_natnl_make_call(callee, 1, natnl_srv_ports, &call_id);
					status = natnl_make_call(callee, 1, natnl_srv_ports, &call_id);
					printf("[main.c] natnl_make_call=[%d], call_id=[%d]\n", status, call_id);
				} else if (buff[0] == 'h') {
	LOG_E(THIS_FILE, "natapi............h");
					//status = fp_natnl_hangup_call(call_id);
					status = natnl_hangup_call(call_id);
					printf("[main.c] natnl_hangup_call=[%d]\n", status);
				} else if (buff[0] == 'q') {
	LOG_E(THIS_FILE, "natapi............q");
					//status = fp_natnl_lib_deinit();
					status = natnl_lib_deinit();
					printf("[main.c] natnl_dll_deinit=[%d]\n", status);
					status = tcp_server_stop();
					printf("[main.c] tcp_server_stop=[%d]\n", status);
					//break;
				} else if (buff[0] == 'g') {
			//		printf("Please input the file name you want to get from remote:\n)");
			//		if (gets(buff) == NULL) 
			//			break;
	LOG_E(THIS_FILE, "natapi............g");
					status = get_remote_file(d_filename, natnl_srv_ports[0].lport);
				} else if (buff[0] == 'p') {
//					printf("Please input the file name you want to put to remote:\n)");
//					if (gets(buff) == NULL) 
//						break;
//					status = put_local_file(buff);
				}
				printf("cnt=[%d]\n", cnt);
		#ifndef WIN32
				sleep(1);
		#else
				Sleep(1);
		#endif
				cnt++;
//			}
	LOG_E(THIS_FILE, "natapi............return 0");
			return 0;
		}
	}
on_error:
	LOG_E(THIS_FILE, "natapi............on_error deinit");
	//fp_natnl_lib_deinit();
	natnl_lib_deinit();
	return 0;
}
#endif
