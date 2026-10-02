/*
	NOTIFY_DATABASE_T *input;
	notification center database
	- command API
	- write / read / delete
*/

#include <libnt.h>

#define MyDBG(fmt,args...) \
	if(isFileExist(NOTIFY_DB_DEBUG) > 0) { \
		Debug2Console("[nt_db][%s:(%d)]"fmt, __FUNCTION__, __LINE__, ##args); \
	}

static void show_help()
{
	printf("Usage :\n");
	printf("  nt_db -[w/r/d], option : t/e/m/s\n");
	printf("  nt_db -w -t [timestamp] -e [event] -s [status] -m [msg]\n");
	printf("  nt_db -r\n");
	printf("  nt_db -d -t [timestamp] -e [event]\n");
	printf("  nt_db -c\n");
}

int main(int argc, char **argv)
{
	int c;
	char *action = NULL, *t = NULL, *e = NULL, *s = NULL, *m = NULL;
	
	/* initial */
	NOTIFY_DATABASE_T *input = initial_db_input();
	
	if (argc == 1){
		show_help();
		return 0;
	}
	
	while ((c = getopt(argc, argv, "wrdt:e:s:m:c")) != -1)
	{
		switch(c)
		{
			case 'w':
				action = "write";
				break;
			case 'r':
				action = "read";
				break;
			case 'd':
				action = "delete";
				break;
			case 't':
				t = optarg;
				break;
			case 'e':
				e = optarg;
				break;
			case 's':
				s = optarg;
				break;
			case 'm':
				m = optarg;
				break;
			case 'c':
				action = "count";
				break;
			case '?':
				printf("[nt_db] option %c has wrong command\n", optopt);
				return -1;
			default:
				show_help();
				break;
		}
	}
	
	if(t == NULL) input->tstamp = 0;
	else input->tstamp = strtol(t, NULL, 10);
	
	if(e == NULL) input->event = 0;
	else input->event = strtol(e, NULL, 16);
	
	if(s == NULL) input->status = 0;
	else input->status = strtol(s, NULL, 10);
	
	if(m == NULL) strncpy(input->msg, "", sizeof(input->msg)-1);
	else strncpy(input->msg, m, sizeof(input->msg)-1);
	
	MyDBG("t=%ld, e=%x, s=%s, m=%s\n", input->tstamp, input->event, input->status, input->msg);
	
	/* call API */
	NT_DBCommand(action, input);
	
	/* free input */
	db_input_free(input);
	
	return 1;
}
