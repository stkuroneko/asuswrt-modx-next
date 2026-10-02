#include<stdio.h>
#include<string.h>
#include<malloc.h>

#include <bcmnvram.h>
#include <shutils.h>
#include <shared.h>

#include"fbwifi.h"
#include <arpa/inet.h>

#include "md5.h"
#include "hmac_sha256.h"


char *md5_hash(unsigned char *in)
{
    //unsigned char encrypt[] ="00:11:22:33:44:55||http://www.espn.com";
    unsigned char decrypt[16];
    MD5_CTX md5;
    MD5Init(&md5);
    MD5Update(&md5,in,strlen((char *)in));
    MD5Final(&md5,decrypt);

	int max=16;
	char *out;
	int n;
	if ((out = malloc(base64_encoded_len(max) + 128)) != NULL) {
                        n = base64_encode(decrypt, out, max);
                        out[n] = 0;
                }
    return out;
}
char *tr_delete(char *in)
{
	char *c = in;
	int m = 0;
	while(*c != '\0')
	{
		if(*c == '=')
			in[m] = '\0';
		m++;
		c++;	
	}
    return in;
}
char *tr_replace(char *in)
{
	char *c = in;
	int m = 0;
	while(*c != '\0')
	{
		if(*c == '+')
			in[m] = '-';
		else if(*c == '/')
			in[m] = '_';
		m++;
		c++;	
	}
    return in;
}

void fbwifi_forwad(char *host,char *mac)
{
	fprintf(stderr,"host:%s,mac:%s\n",host,mac);

	unsigned char *in;
	char *out;
	int len = strlen(host)+strlen(mac)+16;
	in = malloc(len);
	memset(in, 0, len);
	sprintf(in,"%s||http://%s",mac,host);
	
	out = md5_hash(in);
	tr_delete(out);
	tr_replace(out);
	printf("apply: %s\n", out);
	nvram_set("0_guestuser_cookie_0",out);

	free(in);
	//free(out);
#if 0
	char *fb_gid = nvram_safe_get("wl0.1_fbwifi_id");
	char *fb_secret = nvram_safe_get("wl0.1_fbwifi_secret");
#else
	char *fb_gid = nvram_safe_get("fbwifi_id");
	char *fb_secret = nvram_safe_get("fbwifi_secret");
#endif
	char *lan_ip = nvram_safe_get("lan_ipaddr");
	char *redirect_mac;
	
	len = strlen(fb_gid) + strlen(lan_ip) + strlen(out) + 128;
	redirect_mac = malloc(len);
	memset(redirect_mac, 0, len);
	sprintf(redirect_mac,"%s||http://%s:8084/fbwifi/auth.asp?c=%s",fb_gid,lan_ip,out);
	printf("redirect_mac: %s\n", redirect_mac);
	
	free(out);out = NULL;
	out = oauth_sign_hmac_sha256(redirect_mac,fb_secret);
	tr_delete(out);
	tr_replace(out);
	printf("out: %s\n", out);
	nvram_set("0_guestuser_redirectmac_0",out);
	free(redirect_mac);
	free(out);
}

char *fbwifi_auth(char *ip_str,char *mac,char *token,char *guest_cookie)
{
	char user_value[128] = "0", mark[32];
	sprintf(user_value,"%s>%s>%s",ip_str,mac,token);

        while(-1!=access("/tmp/fbwifi/fb_wifi_check.txt",F_OK))
    {
	}

        FILE *fp_lock = fopen("/tmp/fbwifi/fbwifi_auth_cgi.txt","w");

	if(fp_lock == NULL)
	{
		printf("new file failed\n");
	}
	else
		fclose(fp_lock);

	const int count = nvram_get_int("fbwifi_user_conut");
	char name[128]="";
	memset(name, 0x0, sizeof(name));
	sprintf(name, "fbwifi_user_%d", count);
	nvram_set(name,user_value);
	nvram_set_int("fbwifi_user_conut", count+1);
	nvram_commit();
	
        unlink("/tmp/fbwifi/fbwifi_auth_cgi.txt");

	//notify_rc("restart_firewall");
	snprintf(mark, sizeof(mark), "0x%x/0x%x", FBWIFI_MARK_SET(2), FBWIFI_MARK_MASK);
	eval("iptables", "-t", "mangle", "-A", "CLIENT_TO_INTERNET", "-s", ip_str,"-m", "mac", "--mac-source", mac, "-j", "MARK", "--set-mark", mark);
	eval("iptables", "-t", "mangle", "-A", "INTERNET_TO_CLIENT", "-d", ip_str,"-j", "MARK", "--set-mark", mark);

	char *out;
	int len;
#if 0
	char *fb_gid = nvram_safe_get("wl0.1_fbwifi_id");
	char *fb_secret = nvram_safe_get("wl0.1_fbwifi_secret");
#else
	char *fb_gid = nvram_safe_get("fbwifi_id");
	char *fb_secret = nvram_safe_get("fbwifi_secret");
#endif
	char *lan_ip = nvram_safe_get("lan_ipaddr");
	//char *guest_cookie = nvram_safe_get("0_guestuser_cookie_0");
	char *redirect_mac;
	
	len = strlen(fb_gid) + strlen(lan_ip) + strlen(guest_cookie) + 128;
	redirect_mac = malloc(len);
	memset(redirect_mac, 0, len);
	sprintf(redirect_mac,"%s||http://%s:8084/fbwifi/continue.asp?c=%s",fb_gid,lan_ip,guest_cookie);
	printf("redirect_mac: %s\n", redirect_mac);
	
	out = oauth_sign_hmac_sha256(redirect_mac,fb_secret);
	tr_delete(out);
	tr_replace(out);
	free(redirect_mac);
	return out;
}
void fbwifi_mangle()
{
#if 0
	char *if_wifi_on;
		char fbwifi[32];
		char if_name[32];

		int i=1;
		while(i<4)
		{
			sprintf(fbwifi,"wl0.%d_fbwifi",i);
			if_wifi_on = nvram_safe_get(fbwifi);
			fprintf(stderr,"if_wifi_on:%s\n",if_wifi_on);

			sprintf(if_name,"wl0.%d_ifname",i);

			if(strcmp(if_wifi_on,"on") ==0)
			{
				eval("iptables", "-t", "mangle", "-N", "CLIENT_TO_INTERNET");
				eval("iptables", "-t", "mangle", "-I", "PREROUTING", "1", "-m", "mark", "--mark", "0x1", "-j", "CLIENT_TO_INTERNET");
				eval("iptables", "-t", "mangle", "-N", "INTERNET_TO_CLIENT");
				eval("iptables", "-t", "mangle", "-I", "PREROUTING", "-m", "mark", "--mark", "0x1", "-j", "INTERNET_TO_CLIENT");
				break;
			}
			i++;
		}
#else
	if(nvram_match("fbwifi_enable","on"))
	{
		char mark[32];

		snprintf(mark, sizeof(mark), "0x%x/0x%x", FBWIFI_MARK_SET(1), FBWIFI_MARK_MASK);
		eval("iptables", "-t", "mangle", "-N", "CLIENT_TO_INTERNET");
		eval("iptables", "-t", "mangle", "-D", "PREROUTING", "-m", "mark", "--mark", mark, "-j", "CLIENT_TO_INTERNET");
		eval("iptables", "-t", "mangle", "-I", "PREROUTING", "1", "-m", "mark", "--mark", mark, "-j", "CLIENT_TO_INTERNET");
		eval("iptables", "-t", "mangle", "-N", "INTERNET_TO_CLIENT");
		eval("iptables", "-t", "mangle", "-D", "PREROUTING", "-m", "mark", "--mark", mark, "-j", "INTERNET_TO_CLIENT");
		eval("iptables", "-t", "mangle", "-I", "PREROUTING", "-m", "mark", "--mark", mark, "-j", "INTERNET_TO_CLIENT");
		
		int count;
		count = nvram_get_int("fbwifi_user_conut");
		char name[128]="";
		char user_info[256] = "";
		struct guest_info user[count];
		int i;
		for (i=0 ; i< count ; i++)
		{
			memset(name, 0x0, sizeof(name));
			sprintf(name, "fbwifi_user_%d", i);
			strcpy(user_info, nvram_safe_get(name));
			sscanf(user_info, "%[^'>']>%[^'>']>%s", user[i].user_ip, user[i].mac_addr, user[i].token);
			
			snprintf(mark, sizeof(mark), "0x%x/0x%x", FBWIFI_MARK_SET(2), FBWIFI_MARK_MASK);
			eval("iptables", "-t", "mangle", "-A", "CLIENT_TO_INTERNET", "-s", user[i].user_ip, "-m", "mac", "--mac-source", user[i].mac_addr, "-j", "MARK", "--set-mark", mark);
			eval("iptables", "-t", "mangle", "-A", "INTERNET_TO_CLIENT", "-d", user[i].user_ip, "-j", "MARK", "--set-mark", mark);
		}
	}
#endif

}

void
ip2class(char *lan_ip, char *netmask, char *buf)
{
	unsigned int val, ip;
	struct in_addr in;
	int i=0;

	// only handle class A,B,C
	val = (unsigned int)inet_addr(netmask);
	ip = (unsigned int)inet_addr(lan_ip);
/*
	in.s_addr = ip & val;
	if (val==0xff00000) sprintf(buf, "%s/8", inet_ntoa(in));
	else if (val==0xffff0000) sprintf(buf, "%s/16", inet_ntoa(in));
	else sprintf(buf, "%s/24", inet_ntoa(in));
*/
	// oleg patch ~
	in.s_addr = ip & val;

	for (val = ntohl(val); val; i++)
		val <<= 1;

	sprintf(buf, "%s/%d", inet_ntoa(in), i);
	// ~ oleg patch
	//_dprintf("ip2class output: %s\n", buf);
}

void fbwifi_nat(FILE *fp)
{
	int band, j, max_mssid;
	char mark[16], inv_mask[16];	/* for ebtables mark, inverse mask */
	char *wl_if, wl_ifname[IFNAMSIZ] = "", lan_class[32];
	char *fbwifi_iface[3] = { "fbwifi_2g", "fbwifi_5g", "fbwifi_5g_2" };

	if (!fp || (!nvram_match("fbwifi_enable","on") && !nvram_match("fbwifi_enable", "off")))
		return;

	snprintf(mark, sizeof(mark), "0x%x", FBWIFI_MARK_SET(1));
	snprintf(inv_mask, sizeof(inv_mask), "0x%x", FBWIFI_MARK_INV_MASK);
	for (band = 0; band < ARRAYSIZE(fbwifi_iface); ++band) {
#if !defined(HAVE_5g_2)
		/* Skip band 2, 5G-2, if DUT not support 2-nd 5G band. */
		if (band == 2)
			continue;
#endif

		max_mssid = num_of_mssid_support(band);
		for (j = 1; j <= max_mssid; ++j) {
			wl_if = get_wlxy_ifname(band, j, wl_ifname);
			eval("ebtables", "-D", "INPUT", "-i", wl_if, "-j", "mark", "--mark-and", inv_mask, "--mark-target", "CONTINUE");
			eval("ebtables", "-D", "INPUT", "-i", wl_if, "-j", "mark", "--mark-or", mark, "--mark-target", "ACCEPT");
		}

		if (sscanf(nvram_safe_get(fbwifi_iface[band]), "wl%*d.%d", &j) != 1)
			continue;

		if (nvram_match(fbwifi_iface[band], "off"))
			continue;

		wl_if = get_wlxy_ifname(band, j, wl_ifname);
		if (!wl_if || *wl_if == '\0')
			continue;

		eval("ebtables", "-A", "INPUT", "-i", wl_if, "-j", "mark", "--mark-and", inv_mask, "--mark-target", "CONTINUE");
		eval("ebtables", "-A", "INPUT", "-i", wl_if, "-j", "mark", "--mark-or", mark, "--mark-target", "ACCEPT");

	}

	fprintf(fp, "-A PREROUTING -m mark --mark 0x%x/0x%x -j CLIENT_TO_INTERNET\n", FBWIFI_MARK_SET(1), FBWIFI_MARK_MASK);
	fprintf(fp, "-A PREROUTING -m mark --mark 0x%x/0x%x -j CLIENT_TO_INTERNET\n", FBWIFI_MARK_SET(2), FBWIFI_MARK_MASK);
	fprintf(fp, "-I CLIENT_TO_INTERNET -p tcp --dport 80 -m mark --mark 0x%x/0x%x -j ACCEPT\n", FBWIFI_MARK_SET(2), FBWIFI_MARK_MASK);
	strlcpy(lan_class, "0", sizeof(lan_class));
	ip2class(nvram_safe_get("lan_ipaddr"), nvram_safe_get("lan_netmask"), lan_class);
	fprintf(fp, "-A CLIENT_TO_INTERNET -p tcp --dport 80 ! -d %s -j DNAT --to-destination %s:8084\n", lan_class, nvram_safe_get("lan_ipaddr"));
}

void getUrlVars(webs_t wp)
{
	websWrite(wp, T("function getUrlVars()\n{\n"));
	websWrite(wp, T("var vars = [], hash;\n"));
	websWrite(wp, T("var hashes = window.location.href.slice(window.location.href.indexOf('?') + 1).split('&');\n"));
	websWrite(wp, T("for(var i = 0; i < hashes.length; i++){\n"));
	websWrite(wp, T("hash = hashes[i].split('=');\n"));
	websWrite(wp, T("vars.push(hash[0]);\n"));
	websWrite(wp, T("vars[hash[0]] = hash[1];\n}\n"));
	websWrite(wp, T("return vars;\n}\n"));
}

void getCookie(webs_t wp)
{
	websWrite(wp, T("function getCookie(name)\n{\n"));
	websWrite(wp, T("var arr,reg=new RegExp(\"(^| )\"+name+\"=([^;]*)(;|$)\");\n"));
	websWrite(wp, T("if(arr=document.cookie.match(reg))\n"));
	websWrite(wp, T("return (unescape(arr[2]));\n"));
	websWrite(wp, T("else\n"));
	websWrite(wp, T("return null;\n}"));
}

void fbwifi_continue(webs_t wp, char_t *urlPrefix, char_t *webDir, int arg,
		char_t *url, char_t *path, char_t *query)
{
	websWrite(wp, T("<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\">\n"));
	websWrite(wp, T("<html xmlns=\"http://www.w3.org/1999/xhtml\">\n"));
	websWrite(wp, T("<html xmlns:v>\n"));
	websWrite(wp, T("<meta http-equiv=\"X-UA-Compatible\" content=\"IE=EmulateIE8\" />\n"));
	websWrite(wp, T("<meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\" />\n"));
	websWrite(wp, T("<meta http-equiv=\"Expires\" content=\"-1\" />\n"));
	websWrite(wp, T("<meta HTTP-EQUIV=\"Cache-Control\" CONTENT=\"no-cache\">\n"));
	websWrite(wp, T("<meta http-equiv=\"Pragma\" content=\"no-cache\" />\n"));
	websWrite(wp, T("<title>Redirecting to origle url</title>\n"));
	//websWrite(wp, T("<script type=\"text/javascript\" src=\"jquery.js\"></script>\n"));
	websWrite(wp, T("<script>\n"));
	getCookie(wp);
	getUrlVars(wp);
	websWrite(wp, T("var cookie =  getUrlVars()[\"c\"];\n"));
	websWrite(wp, T("var href = getCookie(\"c_\"+cookie);\n"));
	websWrite(wp, T("self.location = decodeURIComponent(href);\n"));
	websWrite(wp, T("</script>\n"));
	websWrite(wp, T("</head>\n"));
	websWrite(wp, T("</html>\n"));
	

	websDone(wp, 200);
}

void fbwifi_auth_asp(webs_t wp, char_t *urlPrefix, char_t *webDir, int arg,
		char_t *url, char_t *path, char_t *query)
{
	websWrite(wp, T("<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\">\n"));
	websWrite(wp, T("<html xmlns=\"http://www.w3.org/1999/xhtml\">\n"));
	websWrite(wp, T("<html xmlns:v>\n"));
	websWrite(wp, T("<meta http-equiv=\"X-UA-Compatible\" content=\"IE=EmulateIE8\" />\n"));
	websWrite(wp, T("<meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\" />\n"));
	websWrite(wp, T("<meta http-equiv=\"Expires\" content=\"-1\" />\n"));
	websWrite(wp, T("<meta HTTP-EQUIV=\"Cache-Control\" CONTENT=\"no-cache\">\n"));
	websWrite(wp, T("<meta http-equiv=\"Pragma\" content=\"no-cache\" />\n"));
	websWrite(wp, T("<title>Redirecting to Facebook Fans Page</title>\n"));
	websWrite(wp, T("<script type=\"text/javascript\" src=\"../jquery.js\"></script>\n"));
	websWrite(wp, T("<script>\n"));
	getUrlVars(wp);
	websWrite(wp, T("var $j = jQuery.noConflict();\n"));
#if 0
	websWrite(wp, T("var fb_gid = '%s';\n"), nvram_get("wl0.1_fbwifi_id"));
	websWrite(wp, T("var fb_secret = '%s';\n"), nvram_get("wl0.1_fbwifi_secret"));
#else
	websWrite(wp, T("var fb_gid = '%s';\n"), nvram_get("fbwifi_id"));
	websWrite(wp, T("var fb_secret = '%s';\n"), nvram_get("fbwifi_secret"));
#endif
	websWrite(wp, T("var lan_ip= '%s';\n"), nvram_get("lan_ipaddr"));
	websWrite(wp, T("var redirect_mac = '';\n"));
	websWrite(wp, T("var cookie =  getUrlVars()[\"c\"];\n"));
	websWrite(wp, T("var token =  getUrlVars()[\"token\"];\n"));
	websWrite(wp, T("$j.ajax({\n"));
	websWrite(wp, T("url: 'fbwifi_auth.cgi?token=' + token + '&c=' + cookie,\n"));
	websWrite(wp, T("async:false,\n"));
	websWrite(wp, T("success: function(response) {\n"));
	websWrite(wp, T("redirect_mac = response;\n}\n});\n"));
	websWrite(wp, T("var redirect_url = \"http://\" + lan_ip + \":8084/fbwifi/continue.asp?c=\" + cookie; \n"));
	websWrite(wp, T("var u = \"https://www.facebook.com/wifiauth/portal/?gw_id=\" + fb_gid + \"&token=\" + token + \"&redirect_url=\" +  encodeURIComponent(redirect_url) + \"&redirect_mac=\" + redirect_mac;\n"));
	websWrite(wp, T("self.location.href = u;\n"));
	websWrite(wp, T("</script>\n"));
	websWrite(wp, T("</head>\n"));
	websWrite(wp, T("</html>\n"));
	

	websDone(wp, 200);
}

void fbwifi_forward(webs_t wp, char_t *urlPrefix, char_t *webDir, int arg,
		char_t *url, char_t *path, char_t *query)
{
	websWrite(wp, T("<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\">\n"));
	websWrite(wp, T("<html xmlns=\"http://www.w3.org/1999/xhtml\">\n"));
	websWrite(wp, T("<html xmlns:v>\n"));
	websWrite(wp, T("<meta http-equiv=\"X-UA-Compatible\" content=\"IE=EmulateIE8\" />\n"));
	websWrite(wp, T("<meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\" />\n"));
	websWrite(wp, T("<meta http-equiv=\"Expires\" content=\"-1\" />\n"));
	websWrite(wp, T("<meta HTTP-EQUIV=\"Cache-Control\" CONTENT=\"no-cache\">\n"));
	websWrite(wp, T("<meta http-equiv=\"Pragma\" content=\"no-cache\" />\n"));
	websWrite(wp, T("<title>Redirecting to Facebook Auth</title>\n"));
	//websWrite(wp, T("<script type=\"text/javascript\" src=\"jquery.js\"></script>\n"));
	websWrite(wp, T("<script>\n"));
	//websWrite(wp, T("var $j = jQuery.noConflict();\n"));
#if 0
	websWrite(wp, T("var fb_gid = '%s';\n"), nvram_get("wl0.1_fbwifi_id"));
	websWrite(wp, T("var fb_secret = '%s';\n"), nvram_get("wl0.1_fbwifi_secret"));
#else
	websWrite(wp, T("var fb_gid = '%s';\n"), nvram_get("fbwifi_id"));
	websWrite(wp, T("var fb_secret = '%s';\n"), nvram_get("fbwifi_secret"));
#endif
	websWrite(wp, T("var lan_ip= '%s';\n"), nvram_get("lan_ipaddr"));
	websWrite(wp, T("var cookie = '%s';\n"), nvram_get("0_guestuser_cookie_0"));
	websWrite(wp, T("var redirect_mac = '%s';\n"), nvram_get("0_guestuser_redirectmac_0"));
	websWrite(wp, T("function getsec(str)\n{\n"));
	websWrite(wp, T("var str1=str.substring(1,str.length)*1;\n"));
	websWrite(wp, T("var str2=str.substring(0,1);\n"));
	websWrite(wp, T("if (str2==\"s\"){\n"));
	websWrite(wp, T(" return str1*1000;\n}\n"));
	websWrite(wp, T("else if (str2==\"h\"){\n"));
	websWrite(wp, T("return str1*60*60*1000;}\n"));
	websWrite(wp, T("else if (str2==\"d\"){\n"));
	websWrite(wp, T("return str1*24*60*60*1000;}\n}\n"));
	websWrite(wp, T("function setCookie(name,value,time)\n{\n"));
	websWrite(wp, T("var strsec = getsec(time);\n"));
	websWrite(wp, T(" var exp = new Date();\n"));
	websWrite(wp, T("exp.setTime(exp.getTime() + strsec*1);\n"));
	websWrite(wp, T("document.cookie = name + \"=\"+ escape (value) + \";Expires=\" + exp.toGMTString();\n}\n"));
	websWrite(wp, T("var redirect_url = \"http://\" + lan_ip + \":8084/fbwifi/auth.asp?c=\" + cookie; \n"));
	websWrite(wp, T("var u = \"https://www.facebook.com/wifiauth/login/?gw_id=\" + fb_gid + \"&redirect_url=\" +  encodeURIComponent(redirect_url) +\"&redirect_mac=\" + redirect_mac;\n"));
	websWrite(wp, T("var url_org = self.location.search.substring(self.location.search.lastIndexOf('=')+1);\n"));
	websWrite(wp, T("var value_c = encodeURIComponent(\"http://\" + url_org);\n"));
	websWrite(wp, T("setCookie(\"c_\"+cookie,value_c,\"h12\");\n"));
	websWrite(wp, T("self.location.href = u;\n"));
	websWrite(wp, T("</script>\n"));
	websWrite(wp, T("</head>\n"));
	websWrite(wp, T("</html>\n"));
	

	websDone(wp, 200);
}
