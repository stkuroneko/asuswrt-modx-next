/*
	test linked list function
*/

#include <libnt.h>

/* global */
struct list *event_list = NULL;

void NT_DBPrintf(struct list *event_list)
{
	NOTIFY_DATABASE_T *listevent;
	struct listnode *ln;

	LIST_LOOP(event_list, listevent, ln)
	{
		printf("[nt_db_test][\"%ld\", \"%8x\", \"%d\", \"%20s\"][%s]\n",
			listevent->tstamp, listevent->event, listevent->status, listevent->msg, eInfo_get_eName(listevent->event));
	}
}

int main(int argc, char **argv)
{
	int c;
	int count = 0;
	char *action = NULL, *a = NULL, *t = NULL, *e = NULL, *s = NULL, *n = NULL, *p = NULL, *m = NULL;

	/* initial */
	NOTIFY_DATABASE_T *input = initial_db_input();

	if (argc == 1) return 0;

	while ((c = getopt(argc, argv, "a:t:e:s:cn:p:m:")) != -1)
	{
		switch(c)
		{
			case 'a':
				a = optarg;
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
			case 'c':
				count = NT_DBCount();
				printf("count = %d\n", count);
				return 0;
			case 'n':
				n = optarg;
				break;
			case 'p':
				p = optarg;
				break;
			case 'm':
				m = optarg;
				break;
			case '?':
				printf("[nt_db_test] option %c has wrong command\n", optopt);
				return 0;
			default:
				break;
		}
	}

	if (!strcmp(a, "write")
	 || !strcmp(a, "read")
	 || !strcmp(a, "delete")
	 || !strcmp(a, "wan_stat")
	) {
		action = a;
	}
	else {
		action = "NOTHING";
	}

	if(t == NULL) input->tstamp = 0;
	else input->tstamp = strtol(t, NULL, 10);
	
	if(e == NULL) input->event = 0;
	else input->event = strtol(e, NULL, 16);

	if(s == NULL) input->status = 0;
	else input->status = strtol(s, NULL, 10);

	strncpy(input->msg, "", sizeof(input->msg)-1);

	printf("[nt_db_test] t=%ld, e=%x, s=%d, p=%s, m=%s, n=%s\n", input->tstamp, input->event, input->status, p, m, n);

	/* initial linked list */
	event_list = list_new();

	/* database API */
	//NT_DBAction(event_list, action, input, n);
	NT_DBActionAPP(event_list, action, input, p, m);

	/* free input */
	db_input_free(input);

	/* print all linked list */
	NT_DBPrintf(event_list);

	/* free memory */
	NT_DBFree(event_list);

	return 1;
}
