#if 0 // #ifdef ASUSWRT_SDK
#include <bcmnvram.h>
#define nvram_get_int(name) atoi(nvram_safe_get(name))

static char *get_webui_url(void)
{
	static char buf[64], *proto;
	int port;

//#ifdef RTCONFIG_HTTPS
	if (nvram_get_int("http_enable") == 1) {
		proto = "https";
		if ((port = nvram_get_int("https_lanport")) == 443)
			port = 0;
	} else
//#endif
	{
		proto = "http";
		if ((port = nvram_get_int("http_lanport")) == 80)
			port = 0;
	}

	snprintf(buf, sizeof(buf), port ? "%s://%s:%d" : "%s://%s", proto, "router.asus.com", port);
	return buf;
}
#else
static char *get_webui_url(void)
{
	return "http://router.asus.com";
}
#endif

void exec_send_mail(MAIL_INFO_T *mInfo, int format, char *contentPath, char *attrPath1, char *attrPath2)
{
	char Cmdbuf[2048];
	char attrtmp1[128];
	char attrtmp2[128];
	
	memset(&Cmdbuf, 0, sizeof(Cmdbuf));
	memset(&attrtmp1, 0, sizeof(attrtmp1));
	memset(&attrtmp2, 0, sizeof(attrtmp2));
	
	snprintf(Cmdbuf, sizeof(Cmdbuf), "cat %s | email -V %s -z %d -s \"ASUS %s Notice - %s\" \"%s\"",
		contentPath,
		(format == HTML) ? "-html" : "",
		mInfo->MsendId,
		mInfo->modelName,
		mInfo->subject,
		mInfo->toMail);
	
	if (attrPath1 != NULL) {
		snprintf(attrtmp1, sizeof(attrtmp1), " -a %s", attrPath1);
		strcat(Cmdbuf, attrtmp1);
	}
	if (attrPath2 != NULL) {
		snprintf(attrtmp2, sizeof(attrtmp2), " -a %s", attrPath2);
		strcat(Cmdbuf, attrtmp2);
	}
	MyDBG("[Cmd:] %s\n", Cmdbuf);
	system(Cmdbuf);
}

static char *get_json_value(json_object *obj, char *name)
{
	json_object *json_value = NULL;
	json_value = json_object_object_get(obj, name);
	
	if(json_value != NULL)
		return (char *)json_object_get_string(json_value);
	else
		return NULL;
}

/*##########################################################
                    ### Reservation ###
###########################################################*/
/* ------------------------------
    ### RESERVATION MAIL EVENT ###
---------------------------------*/
MAIL_INFO_T *RESERVATION_MAIL_CONFIRM_EN_FUNC(MAIL_INFO_T *mInfo)
{
	FILE *fp;
	fp = fopen(MAIL_CONTENT_INFO_PATH, "w");
	if (fp) {
		fputs("Dear user,\n\n", fp);
		fputs("This is for your mail address confirmation and please click below link to go back firmware page for configuration.\n\n", fp);
		fprintf(fp, "%s\n\n", get_webui_url());
		fputs("Thanks, \n", fp);
		fputs("ASUSTeK Computer Inc.\n", fp);
		fclose(fp);
	} else {
		ErrorMsg("Error, Cant open %s ,send mail fail.\n", MAIL_CONTENT_INFO_PATH);
		return mInfo;
	}
	
	strncpy(mInfo->subject, "Notify Mail Verify", sizeof(mInfo->subject));
	exec_send_mail(mInfo, TXT, MAIL_CONTENT_INFO_PATH, NULL, NULL);
	return mInfo;
}

/*##########################################################
                       ### System ###
###########################################################*/
/* ------------------------------
    ### WAN EVENT ###
---------------------------------*/
MAIL_INFO_T *SYS_WAN_DISCONN_EN_FUNC(MAIL_INFO_T *mInfo)
{
	return mInfo;
}

MAIL_INFO_T *SYS_WAN_BLOCK_EN_FUNC(MAIL_INFO_T *mInfo)
{
	return mInfo;
}

MAIL_INFO_T *SYS_WAN_CABLE_UNPLUGGED_EN_FUNC(MAIL_INFO_T *mInfo)
{
	return mInfo;
}

MAIL_INFO_T *SYS_WAN_PPPOE_AUTH_FAILURE_EN_FUNC(MAIL_INFO_T *mInfo)
{
	return mInfo;
}

MAIL_INFO_T *SYS_WAN_USB_MODEM_UNREADY_EN_FUNC(MAIL_INFO_T *mInfo)
{
	return mInfo;
}

MAIL_INFO_T *SYS_WAN_IP_CONFLICT_EN_FUNC(MAIL_INFO_T *mInfo)
{
	return mInfo;
}

MAIL_INFO_T *SYS_WAN_UNABLE_CONNECT_PARENT_AP_EN_FUNC(MAIL_INFO_T *mInfo)
{
	return mInfo;
}

MAIL_INFO_T *SYS_WAN_MODEM_OFFLINE_EN_FUNC(MAIL_INFO_T *mInfo)
{
	return mInfo;
}

MAIL_INFO_T *SYS_WAN_GOT_PROBLEMS_FROM_ISP_EN_FUNC(MAIL_INFO_T *mInfo)
{
	return mInfo;
}

MAIL_INFO_T *SYS_WAN_UNPUBLIC_IP_EN_FUNC(MAIL_INFO_T *mInfo)
{
	return mInfo;
}
/* ------------------------------
    ### PASSWORD EVENT ###
---------------------------------*/
MAIL_INFO_T *SYS_PASSWORD_SAME_WITH_LOGIN_WIFI_EN_FUNC(MAIL_INFO_T *mInfo)
{
	return mInfo;
}

MAIL_INFO_T *SYS_PASSWORD_WIFI_WEAK_EN_FUNC(MAIL_INFO_T *mInfo)
{
	return mInfo;
}

MAIL_INFO_T *SYS_PASSWORD_LOGIN_STRENGTH_CHECK_EN_FUNC(MAIL_INFO_T *mInfo)
{
	return mInfo;
}
/* ------------------------------
    ### GUEST NETWORK EVENT ###
---------------------------------*/
MAIL_INFO_T *SYS_GUESTWIFI_ONE_ENABLE_EN_FUNC(MAIL_INFO_T *mInfo)
{
	return mInfo;
}
MAIL_INFO_T *SYS_GUESTWIFI_MORE_ENABLE_EN_FUNC(MAIL_INFO_T *mInfo)
{
	return mInfo;
}
/* ------------------------------
    ### RSSI EVENT ###
---------------------------------*/
MAIL_INFO_T *SYS_RSSI_LOW_SIGNAL_EN_FUNC(MAIL_INFO_T *mInfo)
{
	return mInfo;
}
MAIL_INFO_T *SYS_RSSI_LOW_SIGNAL_AGAIN_EN_FUNC(MAIL_INFO_T *mInfo)
{
	return mInfo;
}
/* ------------------------------
    ### DUALWAN EVENT ###
---------------------------------*/
MAIL_INFO_T *SYS_DUALWAN_FAILOVER_EN_FUNC(MAIL_INFO_T *mInfo)
{
	FILE *fp;
	fp = fopen(MAIL_CONTENT_INFO_PATH, "w");
	if (fp) {
		fputs("Dear user,\n\n", fp);
		fprintf(fp, "Primary WAN of %s is diconnected. Connection switched to backup network.\n\n\n", mInfo->modelName);
		fputs("Thanks, \n", fp);
		fputs("ASUSTeK Computer Inc.\n", fp);
		fclose(fp);
	} else {
		ErrorMsg("Error, Cant open %s ,send mail fail.\n", MAIL_CONTENT_INFO_PATH);
		return mInfo;
	}
	strncpy(mInfo->subject, "Dual WAN Failover", sizeof(mInfo->subject));
	exec_send_mail(mInfo, TXT, MAIL_CONTENT_INFO_PATH, NULL, NULL);
	return mInfo;
}
MAIL_INFO_T *SYS_DUALWAN_FAILBACK_EN_FUNC(MAIL_INFO_T *mInfo)
{
	FILE *fp;
	fp = fopen(MAIL_CONTENT_INFO_PATH, "w");
	if (fp) {
		fputs("Dear user,\n\n", fp);
		fprintf(fp, "Primary WAN connection of %s has been restored..\n\n\n", mInfo->modelName);
		fputs("Thanks, \n", fp);
		fputs("ASUSTeK Computer Inc.\n", fp);
		fclose(fp);
	} else {
		ErrorMsg("Error, Cant open %s ,send mail fail.\n", MAIL_CONTENT_INFO_PATH);
		return mInfo;
	}
	strncpy(mInfo->subject, "Dual WAN Failback", sizeof(mInfo->subject));
	exec_send_mail(mInfo, TXT, MAIL_CONTENT_INFO_PATH, NULL, NULL);
	return mInfo;
}
/* ------------------------------
    ### SYS DETECT EVENT  ###
---------------------------------*/
MAIL_INFO_T *SYS_SCAN_DLNA_PLAYER_EN_FUNC(MAIL_INFO_T *mInfo)
{
	return mInfo;
}
MAIL_INFO_T *SYS_DETECT_ASUS_SSID_UNENCRYPT_EN_FUNC(MAIL_INFO_T *mInfo)
{
	return mInfo;
}
MAIL_INFO_T *SYS_ECO_MODE_EN_FUNC(MAIL_INFO_T *mInfo)
{
	return mInfo;
}
MAIL_INFO_T *SYS_GAME_MODE_EN_FUNC(MAIL_INFO_T *mInfo)
{
	return mInfo;
}
MAIL_INFO_T *SYS_NEW_DEVICE_WIFI_CONNECTED_EN_FUNC(MAIL_INFO_T *mInfo)
{
	return mInfo;
}
MAIL_INFO_T *SYS_WIFI_DEVICE_DISCONNECTED_EN_FUNC(MAIL_INFO_T *mInfo)
{
	return mInfo;
}
MAIL_INFO_T *SYS_EXISTED_DEVICE_WIFI_CONNECTED_EN_FUNC(MAIL_INFO_T *mInfo)
{
	return mInfo;
}
/* ------------------------------
    ### FIRMWARE EVENT ###
---------------------------------*/
MAIL_INFO_T *SYS_FW_NWE_VERSION_AVAILABLE_EN_FUNC(MAIL_INFO_T *mInfo)
{
	FILE *fp;
	char ver[64];
	json_object *root = NULL;
	root = json_tokener_parse(mInfo->msg);

	if (root != NULL) {
		snprintf(ver, sizeof(ver), "%s", get_json_value(root, "fw_ver"));
	} else {
		snprintf(ver, sizeof(ver), "%s", "");
	}
	
	fp = fopen(MAIL_CONTENT_INFO_PATH, "w");
	if (fp) {
		fputs("<i>Dear user,\n<br><p>\n", fp);
		fprintf(fp, "%s release new firmware version %s. You can find release note as attached. Welcome to upgrade firmware to enjoy new functions and better user experience.\n<br><p>\n",mInfo->modelName, ver);
		fprintf(fp, "<a href=\"%s/Advanced_FirmwareUpgrade_Content.asp\">Go to update new firmware</a>\n<p>\n", get_webui_url());
		fputs("Thanks, \n<br>\n", fp);
		fputs("ASUSTeK Computer Inc.\n</i>", fp);
		fclose(fp);
	} else {
		ErrorMsg("Error, Cant open %s ,send mail fail.\n", MAIL_CONTENT_INFO_PATH);
		json_object_put(root);
		return mInfo;
	}

	strncpy(mInfo->subject, "New Firmware Available", sizeof(mInfo->subject));
	exec_send_mail(mInfo, HTML, MAIL_CONTENT_INFO_PATH, (isFileExist(FW_RELEASE_NOTE_PATH) > 0) ? FW_RELEASE_NOTE_PATH : NULL, NULL);
	json_object_put(root);
	return mInfo;
}
MAIL_INFO_T *SYS_NEW_SIGNATURE_UPDATED_EN_FUNC(MAIL_INFO_T *mInfo)
{
	return mInfo;
}
/*##########################################################
                   ### Administration ###
###########################################################*/
/* ------------------------------
    ### LOGIN EVENT ###
---------------------------------*/
MAIL_INFO_T *ADMIN_LOGIN_FAIL_LAN_WEB_EN_FUNC(MAIL_INFO_T *mInfo)
{
	FILE *fp;
	char date[30];
	json_object *root = NULL;
	
	memset(date, 0, sizeof(date));
	StampToDate(mInfo->tstamp, date);
	
	root = json_tokener_parse(mInfo->msg);
	
	fp = fopen(MAIL_CONTENT_INFO_PATH, "w");
	if (fp) {
		fputs("<i>\nDear user,\n<br>\n<p>\n", fp);
		fprintf(fp, "<strong><font color=#FF0000>%s</font></strong> is failed login to %s. \
		If this is not your log in activity, please go to change administration password for \
		your inormation and privacy safety.\n<br>\n<p>\n", get_json_value(root, "IP"), mInfo->modelName);
		fputs("Thanks, \n<br>\n", fp);
		fputs("ASUSTeK Computer Inc.\n</i>", fp);
		fclose(fp);
	} else {
		ErrorMsg("Error, Cant open %s ,send mail fail.\n", MAIL_CONTENT_INFO_PATH);
		json_object_put(root);
		return mInfo;
	}
	strncpy(mInfo->subject, "Unusual Login Activity", sizeof(mInfo->subject));
	exec_send_mail(mInfo, HTML, MAIL_CONTENT_INFO_PATH, NULL, NULL);
	json_object_put(root);
	return mInfo;
}
MAIL_INFO_T *ADMIN_LOGIN_FAIL_SSH_EN_FUNC(MAIL_INFO_T *mInfo)
{
	return mInfo;
}
MAIL_INFO_T *ADMIN_LOGIN_FAIL_TELNET_EN_FUNC(MAIL_INFO_T *mInfo)
{
	return mInfo;
}
MAIL_INFO_T *ADMIN_LOGIN_FAIL_SSID_EN_FUNC(MAIL_INFO_T *mInfo)
{
	return mInfo;
}
MAIL_INFO_T *ADMIN_LOGIN_FAIL_AICLOUD_EN_FUNC(MAIL_INFO_T *mInfo)
{
	return mInfo;
}
MAIL_INFO_T *ADMIN_LOGIN_DEVICE_DOUBLE_EN_FUNC(MAIL_INFO_T *mInfo)
{
	return mInfo;
}
MAIL_INFO_T *ADMIN_LOGIN_ACCOUNT_DOBLE_EN_FUNC(MAIL_INFO_T *mInfo)
{
	return mInfo;
}
MAIL_INFO_T *ADMIN_LOGIN_FAIL_VPNSERVER_EN_FUNC(MAIL_INFO_T *mInfo)
{
	return mInfo;
}
/*##########################################################
                     ### Security ###
###########################################################*/
/* ------------------------------
    ### PROTECTION EVENT ###
---------------------------------*/
MAIL_INFO_T *PROTECTION_INTO_MONITORMODE_EN_FUNC(MAIL_INFO_T *mInfo)
{
	return mInfo;
}

MAIL_INFO_T *PROTECTION_VULNERABILITY_EN_FUNC(MAIL_INFO_T *mInfo)
{
	FILE *fp;
	fp = fopen(MAIL_CONTENT_INFO_PATH, "w");
	
	if (fp) {
		extract_data(PROTECTION_VULNERABILITY_LOG, fp);
		
		fprintf(fp, "%s\'s AiProtection detected suspicious networking behavior and prevented your device making a connection to a malicious website (see above and the attached log for details).", mInfo->modelName);
		fprintf(fp, "Suggested actions:\n");
		fprintf(fp, "1. If you know that the cause of this attempted connection was a proprietary app or program and not a web browser, we recommend that you uninstall it from your device.\n");
		fprintf(fp, "2. Ensure your device is up to time in all its operating system patches as well as updates to all apps or programs.\n");
		fprintf(fp, "3. You should take this opportunity to check for, and install, any router firmware updates.\n");
		fprintf(fp, "4. If you continue to receive such alerts for similar attempted connections, investigation into the cause will be necessary.\n");
		fprintf(fp, "Meanwhile, rest assured that AiProtection continues to help keep you safe on the Internet.\n\n");
		fprintf(fp, "You also can link to trend micro website to download security trial software for your client device protection.\n");
		fprintf(fp, "http://www.trendmicro.com/\n\n");
		fprintf(fp, "ASUS AiProtection FAQ:\n");
		fprintf(fp, "http://www.asus.com/support/FAQ/1012070/\n");
		fclose(fp);
	} else {
		ErrorMsg("Error, Cant open %s ,send mail fail.\n", MAIL_CONTENT_INFO_PATH);
		return mInfo;
	}
	
	strncpy(mInfo->subject, "Vulnerability Protection", sizeof(mInfo->subject));
	exec_send_mail(mInfo, TXT,MAIL_CONTENT_INFO_PATH, PROTECTION_VULNERABILITY_LOG, NULL);
	unlink(PROTECTION_VULNERABILITY_LOG);
	return mInfo;
}

MAIL_INFO_T *PROTECTION_CC_EN_FUNC(MAIL_INFO_T *mInfo)
{
	FILE *fp;
	fp = fopen(MAIL_CONTENT_INFO_PATH, "w");
	
	if (fp) {
		extract_data(PROTECTION_CC_LOG, fp);
		
		fprintf(fp, "%s\'s AiProtection detected suspicious networking behavior and prevented your device making a connection to a malicious website (see above and the attached log for details).", mInfo->modelName);
		fprintf(fp, "Suggested actions:\n");
		fprintf(fp, "1. If you know that the cause of this attempted connection was a proprietary app or program and not a web browser, we recommend that you uninstall it from your device.\n");
		fprintf(fp, "2. Ensure your device is up to time in all its operating system patches as well as updates to all apps or programs.\n");
		fprintf(fp, "3. You should take this opportunity to check for, and install, any router firmware updates.\n");
		fprintf(fp, "4. If you continue to receive such alerts for similar attempted connections, investigation into the cause will be necessary.\n");
		fprintf(fp, "Meanwhile, rest assured that AiProtection continues to help keep you safe on the Internet.\n\n");
		fprintf(fp, "You also can link to trend micro website to download security trial software for your client device protection.\n");
		fprintf(fp, "http://www.trendmicro.com/\n\n");
		fprintf(fp, "ASUS AiProtection FAQ:\n");
		fprintf(fp, "http://www.asus.com/support/FAQ/1012070/\n");
		fclose(fp);
	} else {
		ErrorMsg("Error, Cant open %s ,send mail fail.\n", MAIL_CONTENT_INFO_PATH);
		return mInfo;
	}
	
	strncpy(mInfo->subject, "Infected device detection&Block", sizeof(mInfo->subject));
	exec_send_mail(mInfo, TXT,MAIL_CONTENT_INFO_PATH, PROTECTION_CC_LOG, NULL);
	unlink(PROTECTION_CC_LOG);
	return mInfo;
}

MAIL_INFO_T *PROTECTION_DOS_EN_FUNC(MAIL_INFO_T *mInfo)
{
	FILE *fp;
	fp = fopen(MAIL_CONTENT_INFO_PATH, "w");
	if (fp) {
		fputs("Dear user,\n\n", fp);
		fprintf(fp, "You receive %s from Asus Router.\n\n\n", eInfo_get_eName(mInfo->event));
		fprintf(fp, "%s\n\n", get_webui_url());
		fputs("Thanks, \n", fp);
		fputs("ASUSTeK Computer Inc.\n", fp);
		fclose(fp);
	} else {
		ErrorMsg("Error, Cant open %s ,send mail fail.\n", MAIL_CONTENT_INFO_PATH);
		return mInfo;
	}
	
	strncpy(mInfo->subject, "DDoS Protetion", sizeof(mInfo->subject));
	exec_send_mail(mInfo, TXT, MAIL_CONTENT_INFO_PATH, NULL, NULL);
	return mInfo;
}
MAIL_INFO_T *PROTECTION_SAMBA_GUEST_ENABLE_EN_FUNC(MAIL_INFO_T *mInfo)
{
	return mInfo;
}
MAIL_INFO_T *PROTECTION_FTP_GUEST_ENABLE_EN_FUNC(MAIL_INFO_T *mInfo)
{
	return mInfo;
}
MAIL_INFO_T *PROTECTION_FIREWALL_DISABLE_EN_FUNC(MAIL_INFO_T *mInfo)
{
	return mInfo;
}
MAIL_INFO_T *PROTECTION_MALICIOUS_SITE_EN_FUNC(MAIL_INFO_T *mInfo)
{
	FILE *fp;
	fp = fopen(MAIL_CONTENT_INFO_PATH, "w");
	
	if (fp) {
		extract_data(PROTECTION_MALS_LOG, fp);
		
		fprintf(fp, "%s\'s AiProtection detected suspicious networking behavior and prevented your device making a connection to a malicious website (see above and the attached log for details).", mInfo->modelName);
		fprintf(fp, "Suggested actions:\n");
		fprintf(fp, "1. If you know that the cause of this attempted connection was a proprietary app or program and not a web browser, we recommend that you uninstall it from your device.\n");
		fprintf(fp, "2. Ensure your device is up to time in all its operating system patches as well as updates to all apps or programs.\n");
		fprintf(fp, "3. You should take this opportunity to check for, and install, any router firmware updates.\n");
		fprintf(fp, "4. If you continue to receive such alerts for similar attempted connections, investigation into the cause will be necessary.\n");
		fprintf(fp, "Meanwhile, rest assured that AiProtection continues to help keep you safe on the Internet.\n\n");
		fprintf(fp, "You also can link to trend micro website to download security trial software for your client device protection.\n");
		fprintf(fp, "http://www.trendmicro.com/\n\n");
		fprintf(fp, "ASUS AiProtection FAQ:\n");
		fprintf(fp, "http://www.asus.com/support/FAQ/1012070/\n");
		fclose(fp);
	} else {
		ErrorMsg("Error, Cant open %s ,send mail fail.\n", MAIL_CONTENT_INFO_PATH);
		return mInfo;
	}
	
	strncpy(mInfo->subject, "Malicious Sites Blocking", sizeof(mInfo->subject));
	exec_send_mail(mInfo, TXT,MAIL_CONTENT_INFO_PATH, PROTECTION_MALS_LOG, NULL);
	unlink(PROTECTION_MALS_LOG);
	return mInfo;
}
MAIL_INFO_T *PROTECTION_WEB_CROSS_SITE_EN_FUNC(MAIL_INFO_T *mInfo)
{
	return mInfo;
}
MAIL_INFO_T *PROTECTION_IIS_VULNERABILITY_EN_FUNC(MAIL_INFO_T *mInfo)
{
	return mInfo;
}
MAIL_INFO_T *PROTECTION_DNS_AMPLIFICATION_ATTACK_EN_FUNC(MAIL_INFO_T *mInfo)
{
	return mInfo;
}
MAIL_INFO_T *PROTECTION_SUSPICIOUS_HTML_TAG_EN_FUNC(MAIL_INFO_T *mInfo)
{
	return mInfo;
}
MAIL_INFO_T *PROTECTION_BITCOIN_MINING_ACTIVITY_EN_FUNC(MAIL_INFO_T *mInfo)
{
	return mInfo;
}
MAIL_INFO_T *PROTECTION_MALWARE_RANSOM_THREAT_EN_FUNC(MAIL_INFO_T *mInfo)
{
	return mInfo;
}
MAIL_INFO_T *PROTECTION_MALWARE_MIRAI_THREAT_EN_FUNC(MAIL_INFO_T *mInfo)
{
	return mInfo;
}
/*##########################################################
                   ### Parental Contorl ###
###########################################################*/
/* ------------------------------
    ### PERMISSION REQUEST EVENT ###
---------------------------------*/
MAIL_INFO_T *PERMISSION_FROM_BLOCKPAGE_EN_FUNC(MAIL_INFO_T *mInfo)
{
	return mInfo;
}
MAIL_INFO_T *PERMISSION_FROM_TIME_SCHEDULE_EN_FUNC(MAIL_INFO_T *mInfo)
{
	return mInfo;
}
/*##########################################################
                 ### Traffic Management ###
###########################################################*/
MAIL_INFO_T *TRAFFICMETER_ALERT_EN_FUNC(MAIL_INFO_T *mInfo)
{
	FILE *fp;
	char buf[STRLEN];
	int flag = 0, val = 0;
	
	if (f_read_string(NT_TLD_PATH"tl_alert", buf, sizeof(buf)) > 0)
		flag = atoi(buf);
	if (f_read_string(NT_TLD_PATH"tl_count", buf, sizeof(buf)) > 0)
		val = atoi(buf);
	
	fp = fopen(MAIL_CONTENT_INFO_PATH, "w");
	if (fp) {
		fputs("Dear user,\n\n", fp);
		fputs("Traffic limiter configuration as below:\n\n", fp);
		if ((flag & 0x1) && !(val & 0x1)) {
			fprintf(fp, "\t<Primary WAN>\n");
			fprintf(fp, "\tRouter Current Traffic: %s GB\n", GET_TRAFFICMETER_INFO("realtime", 0));
			fprintf(fp, "\tAlert Traffic: %s GB\n", GET_TRAFFICMETER_INFO("alert_max", 0)) ;
			fprintf(fp, "\tMAX Traffic: %s GB\n\n", GET_TRAFFICMETER_INFO("limit_max", 0));
			SET_TRAFFICMETER_INFO("count", 0);
		}
		if ((flag & 0x2) && !(val & 0x2)) {
			fprintf(fp, "\t<Secdonary WAN>\n");
			fprintf(fp, "\tRouter Current Traffic: %s GB\n", GET_TRAFFICMETER_INFO("realtime", 1));
			fprintf(fp, "\tAlert Traffic: %s GB\n", GET_TRAFFICMETER_INFO("alert_max", 1)) ;
			fprintf(fp, "\tMAX Traffic: %s GB\n\n", GET_TRAFFICMETER_INFO("limit_max", 1));
			SET_TRAFFICMETER_INFO("count", 1);
		}
		fputs("Your internet traffic usage have reached the alert vlaue. If you are in limited traffic usage, please get more attention.\n\n", fp);
		fputs("Thanks, \n", fp);
		fputs("ASUSTeK Computer Inc.\n", fp);
		fclose(fp);
	} else {
		ErrorMsg("Error, Cant open %s ,send mail fail.\n", MAIL_CONTENT_INFO_PATH);
		return mInfo;
	}
	
	strncpy(mInfo->subject, "Traffic Limiter Alert", sizeof(mInfo->subject));
	exec_send_mail(mInfo, TXT, MAIL_CONTENT_INFO_PATH, NULL, NULL);
	return mInfo;
}

MAIL_INFO_T *TRAFFICMETER_BW_LIMITER_EN_FUNC(MAIL_INFO_T *mInfo)
{
	return mInfo;
}
MAIL_INFO_T *TRAFFIC_REDUCE_LAG_EN_FUNC(MAIL_INFO_T *mInfo)
{
	return mInfo;
}
/*##########################################################
                   ### USB Function ###
###########################################################*/
/* ------------------------------
    ### USB EVENT ###
---------------------------------*/
MAIL_INFO_T *USB_DM_TASK_FINISHED_EN_FUNC(MAIL_INFO_T *mInfo)
{
	return mInfo;
}
MAIL_INFO_T *USB_DISK_SCAN_FAIL_EN_FUNC(MAIL_INFO_T *mInfo)
{
	return mInfo;
}
MAIL_INFO_T *USB_DISK_EJECTED_FAIL_EN_FUNC(MAIL_INFO_T *mInfo)
{
	return mInfo;
}
MAIL_INFO_T *USB_DISK_PARTITION_FULL_EN_FUNC(MAIL_INFO_T *mInfo)
{
	return mInfo;
}
MAIL_INFO_T *USB_DISK_FULL_EN_FUNC(MAIL_INFO_T *mInfo)
{
	return mInfo;
}
