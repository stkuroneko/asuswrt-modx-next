#include <stdio.h>
#include <malloc.h>
#include <curl/curl.h>
#include <curl/easy.h>
#include "cJSON.h"
#include <bcmnvram.h>
#include <shutils.h>

char gw_id[32],gw_secret[32];

cJSON *doit(char *text)
{
    char *out;cJSON *json;

    json=cJSON_Parse(text);
    if (!json) {printf("Error before: [%s]\n",cJSON_GetErrorPtr());return NULL;}
    else
    {
        return json;
        //cJSON_printf(json);
        //cJSON_Delete(json);
        //printf("%s\n",out);
        //free(out);
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

void cJSON_printf(cJSON *json)
{
    if(json)
    {
        cJSON *q;
        q=json->child;
		char *value;
        while(q!=NULL)
        {
            if(strcmp(q->string,"id") == 0)
            {
                nvram_set(gw_id,q->valuestring);
		nvram_commit();
            }
            else if(strcmp(q->string,"secret") == 0)
            {
               	nvram_set(gw_secret,q->valuestring);
		nvram_commit();
            }
            q=q->next;
        }
    }
}
void main(int argc,char *argv[])
{
	char gw_name[32];
#if 0
	sprintf(gw_id,"wl%s.%s_fbwifi_id",argv[1],argv[2]);
	sprintf(gw_secret,"wl%s.%s_fbwifi_secret",argv[1],argv[2]);
	sprintf(gw_name,"wl%s.%s_fbwifi_name",argv[1],argv[2]);
	char *fbwifi_name = nvram_safe_get(gw_name);
#else
	sprintf(gw_id,"fbwifi_id");
	sprintf(gw_secret,"fbwifi_secret");
	char *fbwifi_name = nvram_safe_get("productid");
#endif
	
	
	CURL *curl;
    CURLcode res;
    FILE *fp;
    fp=fopen("/tmp/fbwifi/fb_wifi_register.txt","w");

/*curl --data "name=Router-Lobby-01" --data "vendor_key=h24a2Ed1VuTIJytQ_V6jNtqFmfZYyJNB5bG1fBbbqsY" --data "hw_version=1.0" --data "sw_version=2.0.0.5" https://graph.facebook.com/wifiauth*/

    char *data=(char *)malloc(512);
    memset(data,0,512);
    sprintf(data,"name=%s&%s&%s&%s",fbwifi_name!=""?fbwifi_name:"Router-Lobby-01","vendor_key=h24a2Ed1VuTIJytQ_V6jNtqFmfZYyJNB5bG1fBbbqsY","hw_version=1.0","sw_version=2.0.0.5");
	fprintf(stderr,"data:%s\n",data);
    curl=curl_easy_init();

    if(curl){
        curl_easy_setopt(curl,CURLOPT_SSL_VERIFYHOST,0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl,CURLOPT_URL,"https://graph.facebook.com/wifiauth");

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
        if(res==0){
                        cJSON *json = dofile("/tmp/fbwifi/fb_wifi_register.txt");
			cJSON_printf(json);
			cJSON_Delete(json);
        }
	}
}
