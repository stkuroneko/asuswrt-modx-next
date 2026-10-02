#include <stdio.h>
#include <malloc.h>
#include <curl/curl.h>
#include <curl/easy.h>
#include "cJSON.h"
#include <bcmnvram.h>
#include <shutils.h>
#include <unistd.h>
#include <shared.h>
typedef struct FB_Tokens
{
	char token[128];
	int valid;
        struct FB_Tokens *next;
}fb_r;

struct guest_info {
	char user_ip[20];
	char mac_addr[20];
	char token[128];
	char incoming[20];
	char outgoing[20];
        int valid;
};


void free_list(fb_r * head);
int send_request(char *tokens,char *fb_gid,char *fb_secret);
cJSON *doit(char *text);
cJSON *dofile(char *filename);
fb_r * cJSON_printf(cJSON *json);
void get_traffic_file();
int get_curl_data()
{
//'tokens={"1431914283757932":{"incoming":"0","outgoing":"336559"},"<x1>":{""incoming"":"<i1>","outgoing":"<o1>"}}'
        const int count = nvram_get_int("fbwifi_user_conut");
        fprintf(stderr,"count:%d\n",count);
        if(!count)
            return 0;
        char *data = NULL;
        char *data_r = NULL;
	int i;
	char name[128]="";
	char user_info[256] = "";
//get tokens
        struct guest_info user[count];
	for (i=0 ; i< count ; i++)
	{
		memset(name, 0x0, sizeof(name));
		sprintf(name, "fbwifi_user_%d", i);
		strcpy(user_info, nvram_safe_get(name));
		sscanf(user_info, "%[^'>']>%[^'>']>%s", user[i].user_ip, user[i].mac_addr, user[i].token);
		//nvram_unset(name);
	}
//get traffic counters
	const int VALUELEN = 20;
	const int MAX = 256;
	char buffer[MAX], values[14][VALUELEN];

        FILE *fp = fopen("/tmp/fbwifi/fb_outgoing.txt", "r");
	if (fp){
		memset(buffer, 0, MAX);
                memset(values, 0, 14*VALUELEN);
		int hang = 1;
		while (fgets(buffer, MAX, fp)){
                        if(hang <= 2)
			{
				hang++;
				continue;
			}
                        if (sscanf(buffer, "%s%s%s%s%s%s%s%s%s%s%s%s%s%s", values[0], values[1], values[2], values[3], values[4], values[5],values[6], values[7], values[8], values[9], values[10], values[11],values[12],values[13]) == 14){
                            fprintf(stderr,"ip:%s,mac:%s\n",values[7],values[10]);
                            for(i=0 ; i< count ; i++)
                            {
                                if (!strcasecmp(values[10], user[i].mac_addr)){
                                    strcpy(user[i].outgoing,values[1]);
                                    strcpy(user[i].incoming,"0");
                                    //break;
                                }
                            }
                        }

                        memset(values, 0, 14*VALUELEN);

			memset(buffer, 0, MAX);
		}

		fclose(fp);
	}
 //get data
        int len = 0;
        for (i=0 ; i< count ; i++)
        {
            len += strlen(user[i].token) + strlen(user[i].incoming) + strlen(user[i].outgoing) + 64;
            if(!data)
            {
                data = (char *)malloc(sizeof(char)*len);
                memset(data,'\0',len);
                sprintf(data,"\"%s\":{\"incoming\":\"%s\",\"outgoing\":\"%s\"}",user[i].token,user[i].incoming,user[i].outgoing);
                fprintf(stderr,"data:%s len:%d\n",data,strlen(data));
            }
            else
            {
                data = realloc(data,len);
                sprintf(data,"%s,\"%s\":{\"incoming\":\"%s\",\"outgoing\":\"%s\"}",data,user[i].token,user[i].incoming,user[i].outgoing);
                fprintf(stderr,"data:%s len:%d\n",data,strlen(data));
            }
        }
//send request to get data

#if 0
        char *fb_gid = nvram_safe_get("wl0.1_fbwifi_id");
        char *fb_secret = nvram_safe_get("wl0.1_fbwifi_secret");
#else
		char *fb_gid = nvram_safe_get("fbwifi_id");
        char *fb_secret = nvram_safe_get("fbwifi_secret");
#endif

        int res;
        res = send_request(data,fb_gid,fb_secret);

        free(data);

        fb_r *head = NULL;

        if(res == 0)
        {
            cJSON *json = dofile("/tmp/fbwifi/fb_wifi_check_data.txt");
            head = cJSON_printf(json);
            cJSON_Delete(json);

            int nvram_change = 0;
            for(i = 0 ; i < count ; i++)
            {
                fb_r *tail = head->next;
                while(tail != NULL)
                {
                    fprintf(stderr,"%s %s\n",tail->token,user[i].token);
                    if(strcmp(tail->token,user[i].token) == 0)
                    {
                        user[i].valid = tail->valid;
                        if(!tail->valid)
                            nvram_change = 1;
                        break;
                    }
                    tail = tail->next;
                }
            }

            free_list(head);
//updata fbwifi_user_* & fbwifi_user_conut
            if(nvram_change)
            {
                fprintf(stderr,"has token valid fase\n");

                FILE *fp;
                fp = fopen("/tmp/fbwifi/fb_wifi_check.txt","w");
                if(fp)
                    fclose(fp);


                if(access("/tmp/fbwifi/fbwifi_auth_cgi.txt",0) == 0)
                {
                    fprintf(stderr,"fb_wifi_cgi is runing\n");
                    unlink("/tmp/fbwifi/fb_wifi_check.txt");
                    return 1;
                }

                for (i=0 ; i< count ; i++)
                {
                    memset(name, 0x0, sizeof(name));
                    sprintf(name, "fbwifi_user_%d", i);
                    nvram_unset(name);
                }

                int j = 0;
                for (i = 0 ; i < count ; i++)
                {
                    fprintf(stderr,"token %s is %d\n",user[i].token,user[i].valid);
                    if(user[i].valid)
                    {
                        memset(name, 0x0, sizeof(name));
                        sprintf(name, "fbwifi_user_%d", j);
                        sprintf(user_info,"%s>%s>%s", user[i].user_ip,user[i].mac_addr,user[i].token);
                        nvram_set(name,user_info);
                        j++;
                    }
                    else
                    {
			char mark[32];
			snprintf(mark, sizeof(mark), "0x%x/0x%x", FBWIFI_MARK_SET(2), FBWIFI_MARK_MASK);
			eval("iptables", "-t", "mangle", "-D", "CLIENT_TO_INTERNET", "-s", user[i].user_ip, "-m", "mac", "--mac-source", user[i].mac_addr, "-j", "MARK", "--set-mark", mark);

			eval("iptables", "-t", "mangle", "-D", "INTERNET_TO_CLIENT", "-d", user[i].user_ip, "-j", "MARK", "--set-mark", mark);
                    }
                }

                nvram_set_int("fbwifi_user_conut", j);

                nvram_commit();

                unlink("/tmp/fbwifi/fb_wifi_check.txt");
            }
            else
                unlink("/tmp/fbwifi/fb_wifi_check.txt");
            return 0;

        }
        else
            return res;
}

void free_list(fb_r * head)
{
    fb_r *tail = head;
    fb_r *cur;
    while(tail != NULL)
    {
        cur = tail;
        tail = tail->next;
        free(cur);
    }
}

int send_request(char *tokens,char *fb_gid,char *fb_secret)
{
    CURL *curl;
    CURLcode res;
    FILE *fp;
    fp=fopen("/tmp/fbwifi/fb_wifi_check_data.txt","w");

    /*curl --data "name=Router-Lobby-01" --data "vendor_key=h24a2Ed1VuTIJytQ_V6jNtqFmfZYyJNB5bG1fBbbqsY" --data "hw_version=1.0" --data "sw_version=2.0.0.5" https://graph.facebook.com/wifiauth*/

    int len = strlen(tokens) + strlen(fb_secret) + 20;
    char *data=(char *)malloc(len);
    memset(data,0,len);
    sprintf(data,"tokens={%s}&secret=%s",tokens,fb_secret);

    len = strlen(fb_gid) + strlen("https://graph.facebook.com//wifiauth") + 1;
    char *url = (char *)malloc(len);
    memset(url,0,len);
    sprintf(url,"https://graph.facebook.com/%s/wifiauth",fb_gid);
    fprintf(stderr,"data:%s,url:%s\n",data,url);
    curl=curl_easy_init();

    if(curl){
        curl_easy_setopt(curl,CURLOPT_SSL_VERIFYHOST,0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl,CURLOPT_URL,url);

        curl_easy_setopt(curl,CURLOPT_POSTFIELDS,data);
        //curl_easy_setopt(curl,CURLOPT_SSL_VERIFYPEER,0);
        curl_easy_setopt(curl,CURLOPT_VERBOSE,1);
        curl_easy_setopt(curl,CURLOPT_TIMEOUT,90);
        curl_easy_setopt(curl,CURLOPT_WRITEDATA,fp);
        //curl_easy_setopt(curl,CURLOPT_WRITEHEADER,fp_hd);
        res=curl_easy_perform(curl);

        curl_easy_cleanup(curl);
        fclose(fp);
        free(data);
        free(url);
        return res;
    }
}

cJSON *doit(char *text)
{
    char *out;cJSON *json;

    json=cJSON_Parse(text);
    if (!json) {printf("Error before: [%s]\n",cJSON_GetErrorPtr());return NULL;}
    else
    {
        return json;
    }
}

/* Read a file, parse, render back, etc. */
cJSON *dofile(char *filename)
{
    cJSON *json;
    FILE *f=fopen(filename,"rb");fseek(f,0,SEEK_END);long len=ftell(f);fseek(f,0,SEEK_SET);
    char *data=malloc(len+1);fread(data,1,len,f);fclose(f);
    json=doit(data);
    free(data);
    if(json)
        return json;
    else
        return NULL;
}

fb_r * cJSON_printf(cJSON *json)
{
    if(json)
    {
        fb_r *head = NULL;
        head = (fb_r *)malloc(sizeof(fb_r));
        memset(head,0,sizeof(head));
        head->next = NULL;

        fb_r *current = NULL;
        fb_r *trail = head;

        cJSON *p,*q,*m;
        q=json->child;
        while(q!=NULL)
        {
            if(strcmp(q->string,"tokens")==0)
            {
                if(q->child!=NULL){
                    p=q->child;m=p->child;
                    while(p!=NULL)
                    {
                        current = (fb_r *)malloc(sizeof(fb_r));
                        memset(current,0,sizeof(current));
                        strcpy(current->token,p->string);

                        printf("%s\n",p->string);
                        m=p->child;
                        while(m!=NULL)
                        {
                            current->valid = m->type;
                            printf("%s:%d\n",m->string,m->type);
                            m=m->next;
                        }
                        p=p->next;

                        trail->next = current;
                        trail = current;
                        trail ->next = NULL;
                    }
                    break;
                }
                else
                    printf("this is empty file\n");
            }
            q=q->next;
        }
        return head;
    }
}

void get_traffic_file()
{
        char cmd_out[] = "iptables -t mangle -L CLIENT_TO_INTERNET -v -x -n > /tmp/fbwifi/fb_outgoing.txt";
	system(cmd_out);
        char cmd_in[] = "iptables -t mangle -L INTERNET_TO_CLIENT -v -x -n > /tmp/fbwifi/fb_incoming.txt";
	system(cmd_in);
}

void init_base_date()
{
    int count = nvram_get_int("fbwifi_user_conut");

    char name[128] = {0};
    int i = 0;
    for (i=0 ; i< count ; i++)
    {
        memset(name, 0x0, sizeof(name));
        sprintf(name, "fbwifi_user_%d", i);
        nvram_unset(name);
    }
    nvram_set_int("fbwifi_user_conut", 0);

    nvram_commit();
}

int main(int args,char *argc[])
{
        fprintf(stderr,"coming into fbwifi check tokens valid\n");

        //init_base_date();

	int is_shutdown = 0;
	time_t prv_ts = time(NULL);
	while (!is_shutdown) {
                sleep(300); //60--> 300
		time_t cur_ts = time(NULL);
		
		//-every 300 sec 
                if(cur_ts - prv_ts >= 100){
			get_traffic_file();
                        int res;
                        do{
                            res = get_curl_data();
                        }
                        while(res);
			prv_ts = cur_ts;
		}
	}
	return 0;
}
