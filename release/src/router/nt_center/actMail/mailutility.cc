/* Global */
static char CONTENT_BUFF[STRLEN];
/* ------------------------------
    ### PROTECTION EVENT ###
---------------------------------*/
static void erase_symbol(char *old, char *sym)
{
	char buf[20];
	int strLen;
	
	char *FindPos = strstr(old, sym);
	if ((!FindPos) || (!sym)) {
		printf("can't found symbol\n");
		return;
	}
	
	while (FindPos != NULL) {
		memset(buf, 0, sizeof(buf));
		strLen = FindPos - old;
		strncpy(buf, old, strLen);
		strcat(buf, FindPos+1);
		strcpy(old, buf);
		FindPos = strstr(old, sym);
	}
}

static void get_hostname_from_NMP(char *mac, char *hostname)
{
	char *buf, *g, *p, *a;
	char *hw = NULL, *host = NULL;
	char mac_p[18];
	char str[NMP_BUFF];
	int count = 0;
	
	if (mac == NULL) return;
	
	memset(mac_p, 0, sizeof(mac_p));
	strncpy(mac_p, mac, 18);
	erase_symbol(mac_p, ":");
	memset(str, 0, sizeof(str));
	f_read_string(NMP_PATH, str, sizeof(str));
	g = buf = strdup(&str[0]);
	
	while (g) {
		if((p = strsep(&g, "<")) == NULL) break;
		while ((a = strsep(&p, ">")) != NULL) {
			count++;
			if(count == 1) hw = a;
			if(count == 3) host = a;
			if(count > 3) break;
		}
		if(strcasecmp(hw, mac_p)) continue;
		if(!strcasecmp(hw, mac_p)){
			strcpy(hostname, host);
			break;
		}
	}
	
	free(buf);
}

static void print_mail_list(mail_s *head)
{
	mail_s *current;
	current = head;
	int i = 0;
	char buf[60];
	
	printf("=======================================================================================================\n");
	while(current != NULL)
	{
		memset(buf, 0, sizeof(buf));
		if (current->type == 3)
			snprintf(buf, sizeof(buf), "Vulnerability Protection");
		else if (current->type == 2)
			snprintf(buf, sizeof(buf), "Malicious Sites Blocking");
		else if (current->type == 1)
			snprintf(buf, sizeof(buf), "Infected Device Prevention and Blocking");
		
		printf("%5d %40s %10s %18s %s %s\n", i, buf, current->date, current->src, current->hostname, current->dst);
		current = current->next;
		i++;
	}
}

static void print_mail_list_fp(mail_s *head, FILE *fp)
{
	mail_s *current;
	current = head;
	int i = 1;
	char buf[60];
	
	while (current != NULL)
	{
		memset(buf, 0, sizeof(buf));
		if (current->type == 3)
			snprintf(buf, sizeof(buf), "Vulnerability Protection");
		else if (current->type == 2)
			snprintf(buf, sizeof(buf), "Malicious Sites Blocking");
		else if (current->type == 1)
			snprintf(buf, sizeof(buf), "Infected Device Prevention and Blocking");
		
		fprintf(fp, "Event number : %d\n", i);
		fprintf(fp, "Alert type : %s\n", buf);
		fprintf(fp, "Source : %s (%s)\n", current->hostname, current->src);
		fprintf(fp, "Destination : %s\n", current->dst);
		
		fprintf(fp, "\n");
		current = current->next;
		i++;
	}
}

static void free_mail_list(mail_s *head)
{
	mail_s *current, *prev;
	current = head;
	while (current != NULL) {
		prev = current;
		current = current->next;
		free(prev);
	}
}

static void extract_data(const char *path, FILE *new_f)
{
	FILE *fp;
	int i = 0;
	char buf[300];
	char date[40], date1[20], date2[20], src[32], dst[128], hostname[100];
	mail_s *head = NULL;
	mail_s *current = NULL;
	mail_s *prev = NULL;
	
	if ((fp = fopen(path, "r")) == NULL)
		return;
	
	while (fgets(buf, sizeof(buf), fp))
	{
		current = (struct mail_info *)malloc(sizeof(struct mail_info));
		
		memset(date, 0, sizeof(date));
		memset(date1, 0, sizeof(date1));
		memset(date2, 0, sizeof(date2));
		memset(src, 0, sizeof(src));
		memset(dst, 0, sizeof(dst));
		memset(hostname, 0, sizeof(hostname));
		
		if (strstr(buf, "Infected")) // CC
		{
			sscanf(buf, "%s %s %*s %*s %*s %*s %*s %s %s\n", date1, date2, src, dst);
			current->type = 1;
		}
		else if (strstr(buf, "Malicious")) // Mals
		{
			sscanf(buf, "%s %s %*s %*s %*s %s %s\n", date1, date2, src, dst);
			current->type = 2;
		}
		else if (strstr(buf, "Vulnerability")) // VP
		{
			sscanf(buf, "%s %s %*s %*s %s %s\n", date1, date2, src, dst);
			current->type = 3;
		}
		else
		{
			// do nothing, just for loop
			continue;
		}
		
		// mac to hostname
		memset(hostname, 0, sizeof(hostname));
		get_hostname_from_NMP(src, hostname);
		
		// structure
		snprintf(date, sizeof(date), "%s %s", date1, date2);
		strcpy(current->date, date);
		strcpy(current->src, src);
		strcpy(current->dst, dst);
		strcpy(current->hostname, hostname);
		
		current->next = NULL;
		if (head == NULL)
			head = current;
		else
			prev->next = current;
		
		prev = current;
		
		i++;
	}
	
	if(GetDebugValue(NOTIFY_ACTION_MAIL_DEBUG)) {
		print_mail_list(head); // DEBUG
	}
	
	if (new_f != NULL) {
		print_mail_list_fp(head, new_f);
	}
	free_mail_list(head);
}

/* ------------------------------
    ### TRAFFIC METER EVENT ###
---------------------------------*/
static void SET_TRAFFICMETER_INFO(const char *name, int unit)
{
	char path[STRLEN];
	char buf[sizeof("4294967295")];
	unsigned int val = 0;
	
	snprintf(path, sizeof(path), "%stl_%s", NT_TLD_PATH, name);
	
	if (f_read_string(path, buf, sizeof(buf)) > 0)
		val = atoi(buf);
	
	val |= (1U << unit);
	snprintf(buf, sizeof(buf), "%u", val);
	f_write_string(path, buf, 0, 0);
}

static char *GET_TRAFFICMETER_INFO(const char *name, int unit)
{
	char path[STRLEN];
	char buf[STRLEN];
	
	memset(CONTENT_BUFF, 0, sizeof(CONTENT_BUFF));
	memset(buf, 0, sizeof(buf));
	snprintf(path, sizeof(path), "/tmp/tl%d_%s", unit, name);
	if (f_read_string(path, buf, sizeof(buf)) > 0)
		strcpy(CONTENT_BUFF, buf);
	else
		strcpy(CONTENT_BUFF, "");
	
	return CONTENT_BUFF;
}

