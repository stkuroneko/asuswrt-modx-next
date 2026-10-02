#include <parse_arg.h>
#include <stdio.h>
#include <string.h>

struct user_debug{
	char aaews_log_path[PATH_LEN];
	char vip_id[ID_MAX_LEN];
	char vip_pwd[PWD_MAX_LEN];
	char device_id[ID_MAX_LEN];
	char device_pwd[PWD_MAX_LEN];
	char sip_srvs[URL_MAX_LEN];
	char stun_srvs[URL_MAX_LEN];
	char turn_srvs[URL_MAX_LEN];
	char disable_aae[FLAG_LEN];
	char sdk_log_dir[PATH_LEN];
	char sdk_log_level[FLAG_LEN];
	char sdk_control_port[PORT_LEN];
};
struct user_debug ud;

struct debug_var{
	char* field;
};

struct debug_var  fd[] = {	{"--aaews_log_path"}		, // vlid for directory 
				{"--asus_vip_id"}	,	// xxxx@email 
				{"--asus_vip_pwd"}	, 
				{"--device_id"}		, 
				{"--device_pwd"}	, 
				{"--sip_srvs"},			// ip1,ip2,ip3
				{"--stun_srvs"},		// ip1,ip2,ip3
				{"--turn_srvs"},		// ip1,ip2,ip3
				{"--disable_aae"},
				{"--sdk_log_dir"},
				{"--sdk_log_level"},
				{"--sdk_control_port"},
				};


char* get_arg_ptr(int index)
{
	switch (index){
		case 0: return ud.aaews_log_path;
		case 1: return ud.vip_id;
		case 2: return ud.vip_pwd;
		case 3: return ud.device_id;
		case 4: return ud.device_pwd ;
		case 5: return ud.sip_srvs;
		case 6: return ud.stun_srvs;
		case 7: return ud.turn_srvs;
		case 8: return ud.disable_aae;
		case 9: return ud.sdk_log_dir;
		case 10: return ud.sdk_log_level;
		case 11:return ud.sdk_control_port;
		default: return NULL;
	}
	return NULL;
}

char* find_eq(char* arg)
{
	char*	pch = NULL;
	if(!arg) goto _PARSE_ARG_EXIT ;
	
	pch = strchr(arg, '=');
	if(!pch){
		goto _PARSE_ARG_EXIT;
	}
_PARSE_ARG_EXIT:
	return pch;
}


int parse_arg(int argc, char* argv[] )
{
	if(argc <=1) return -1;
	memset(&ud, 0, sizeof(struct user_debug));
	int i = 0, j=0;
	char* pch=NULL;
//	fprintf(stderr, "argc =%d\n", argc);
	//fprintf(stderr, "argc = %d, elements = %d\n", argc, sizeof(fd)/sizeof(fd[0]));
	int elements = sizeof(fd)/sizeof(fd[0]);
	for(i = 1; i< argc ;i++){
//		while(debug_var[j]){
		for(j = 0; j<elements; j++){
//			fprintf(stderr, "argv = %s, field = %s\n", argv[i], fd[j].field);
			pch = strstr(argv[i], fd[j].field);
			if(!pch) 	continue;
			else{
				// find '=' 
				char* eq_pos = find_eq(argv[i]);
				if(eq_pos) {
					char* arg_value = eq_pos+1;
					strcpy(get_arg_ptr(j), arg_value );
//					fprintf(stderr, "arg_value = %s\n", arg_value);
				}else{
					fprintf(stderr, "argument [%s] could not be configured\n", argv[i] );
				}
			}	
//			j++;	
		}	
		continue;
	}	
	return 0;
}


int get_arg_field(char* field , char* ret_val)
{
	int status = -1;
	//fprintf(stderr, "get field [%s]\n", field);
	if(!field || !ret_val) goto _GET_ARG_FIELD_EXIT;
	
	int i =0;
	int elements =sizeof(fd)/sizeof(fd[0]); 
//	while(debug_var[i]){
//	fprintf(stderr, "elements = %d , field =%s\n", elements, field);
	for(i =0 ; i< elements; i++){
//		fprintf(stderr, "compare with %s\n", fd[i].field);
		if(!strcmp(fd[i].field, field)){
//			fprintf(stderr, "FIT argument\n");
			if(strlen(get_arg_ptr(i))){
//				fprintf(stderr, "get arg value =%s\n", get_arg_ptr(i));
				strcpy(ret_val, get_arg_ptr(i));
				break;
			}
		}
//		i++;
	}
	if(strlen(ret_val)) status = 0;
_GET_ARG_FIELD_EXIT:
	return status;
}

void dump_arg()
{
	char arg_p[PATH_LEN];
	memset(arg_p, 0, PATH_LEN);
	int i =0;
	//fprintf(stderr, "total arg counts =%d \n",sizeof(fd)/sizeof(fd[0]));
	//for(i=0; i<=5; i++)
	//	fprintf(stderr, " fd[i] =%p\n", fd[i]);

	for(i = 0; i<sizeof(fd)/sizeof(fd[0]); i++){
		get_arg_field(fd[i].field, arg_p);
		fprintf(stderr, "%s====%s\n",fd[i].field, arg_p );
	}
}
