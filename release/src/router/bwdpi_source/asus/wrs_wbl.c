 /*
 * Copyright 2019, ASUSTeK Inc.
 * All Rights Reserved.
 * 
 * THIS SOFTWARE IS OFFERED "AS IS", AND ASUS GRANTS NO WARRANTIES OF ANY
 * KIND, EXPRESS OR IMPLIED, BY STATUTE, COMMUNICATION OR OTHERWISE. ASUS
 * SPECIFICALLY DISCLAIMS ANY IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A SPECIFIC PURPOSE OR NONINFRINGEMENT CONCERNING THIS SOFTWARE.
 *
 */

/*
	wrs_wbl.c : white and black list API
*/

#include <bwdpi.h>

#define WLIST_G       BWDPI_WBL_PATH"/wlist_g"
#define BLIST_G       BWDPI_WBL_PATH"/blist_g"
#define WLIST_M       BWDPI_WBL_PATH"/wlist_m"
#define BLIST_M       BWDPI_WBL_PATH"/blist_m"
#define REPLACE       BWDPI_WBL_PATH"/replace.txt"
#define PROFILE_COUNT BWDPI_WBL_PATH"/wbl_profile_count"
#define MIN_DOMAIN    4
#define MAX_DOMAIN    256
#define MAX_PROFILE   15
#define MAX_COUNT     64

/*
	enum : error code
*/
enum {
	WRS_DEFAULT = 0,    // 0 : Original status, no changed
	WRS_SUCCESS = 1,    // 1 : Sucess
	WRS_URL_INVALID,    // 2 : Input is not URL or IPv4
	WRS_FILE_CANT_FIND, // 3 : Illegal path, can't find file to open
	WRS_MAX_COUNT,      // 4 : The rules in profile is over MAX_COUNT
	WRS_FAIL_WRITE_DATA,// 5 : Data can't write into database
	WRS_ILLEGAL_PARAS,  // 6 : No such action to execute
	WRS_FILE_CANT_OPEN, // 7 : Can't fopen
	WRS_WRONG_MAC_FORMAT// 8 : The MAC is illegal format
};

/*
	check file exists, if not, create this file
*/
static void WRS_WBL_FILE(char *path)
{
	if (!f_exists(path)) eval("touch", path);
}

/*
	check folder exists, if not, create this folder
*/
static void WRS_WBL_FOLDER(const char *path)
{
	if (!f_exists(path)) mkdir(path, 0666);
}

/*
	toUpperString and check mac format
*/
int wbl_mac_format(char *str)
{
	int ret = 1;

	if (str == NULL) {
		ret = -1;
		goto END;
	}

	if (strcmp(str, "")) {
		toUpperCase(str);
		if (isValidMacAddress(str) == 0) {
			printf("[%s] mac format is invalid %s\n", __FUNCTION__, str);
			ret = 0;
		}
	}

END:
	return ret;
}

/*
	get wrs wbl data path
*/
int WRS_WBL_GET_PATH(int bflag, char *mac, char *path, int len)
{
	int ret = 1;

	/* check mac format */
	if (wbl_mac_format(mac) < 0) return WRS_WRONG_MAC_FORMAT;

	WRS_WBL_FOLDER(BWDPI_WBL_PATH);

	if (bflag == 0 && !strcmp(mac, "")) {
		strncpy(path, WLIST_G, len);
		WRS_WBL_FILE(path);
	}
	else if (bflag == 1 && !strcmp(mac, "")) {
		strncpy(path, BLIST_G, len);
		WRS_WBL_FILE(path);
	}
	else if (bflag == 0 && strcmp(mac, "")) {
		snprintf(path, len, WLIST_M"/%s", mac);
		WRS_WBL_FOLDER(WLIST_M);
		WRS_WBL_FILE(path);
	}
	else if (bflag == 1 && strcmp(mac, "")) {
		snprintf(path, len, BLIST_M"/%s", mac);
		WRS_WBL_FOLDER(BLIST_M);
		WRS_WBL_FILE(path);
	}
	else {
		strncpy(path, "", len);
	}

	return ret;
}

/*
	Check profile size, if no data, no need to add into wbl.conf
*/
static int WRS_WBL_SIZE_STAT(int bflag, char *mac)
{
	int ret = 0;
	char path[256] = {0};
	int len = sizeof(path);
	struct stat st;
	off_t cursize;

	/* check mac format */
	if (wbl_mac_format(mac) < 0) return WRS_WRONG_MAC_FORMAT;

	if (bflag == 0 && !strcmp(mac, "")) {
		strncpy(path, WLIST_G, len);
	}
	else if (bflag == 1 && !strcmp(mac, "")) {
		strncpy(path, BLIST_G, len);
	}
	else if (bflag == 0 && strcmp(mac, "")) {
		snprintf(path, len, WLIST_M"/%s", mac);
	}
	else if (bflag == 1 && strcmp(mac, "")) {
		snprintf(path, len, BLIST_M"/%s", mac);
	}

	stat(path, &st);
	cursize = st.st_size;

	if (cursize > 0) ret = 1;
	WBL_DBG(" path=%s, cursize=%ld, ret=%d\n", path, cursize, ret);

	return ret;
}

/*
	check input format is domain name
*/
int check_domain_format(const char *input)
{
	int len = 0;
	int i = 0;
	unsigned char c;

	if (!input || !strcmp(input, "")) goto END;

	len = strlen(input);
	for (i = 0; i < len; i++) {
		c = input[i];
		if (((c | 0x20) < 'a' || (c | 0x20) > 'z') &&
		    ((c < '0' || c > '9')) &&
		    (c != '.' && c != '-' && c != '_')) {
			len = 0;
			break;
		}
	}

END:
	return (len < MAX_DOMAIN && len > MIN_DOMAIN) ? 1 : 0;
}

/*
	check input format is ipv4 address
*/
int check_ipv4_format(char *input)
{
	return (illegal_ipv4_address(input) == 0) ? 1 : 0;
}

/*
	check the number of rules in the profile
*/
int check_max_count(const char *path)
{
	FILE *fp = NULL;
	char buf[256] = {0};
	int count = 0;

	if ((fp = fopen(path, "r")) != NULL) {
		while (fgets(buf, sizeof(buf), fp) != NULL) {
			count++;
		}
	}
	if (fp) fclose(fp);

	if (count >= MAX_COUNT) {
		printf("[%s] forbid to add new rule due to over %d\n", __FUNCTION__, MAX_COUNT);
		return -1;
	}

	return count;
}

/*
	write data into file
*/
int WRS_WBL_WRITE_LIST(int bflag, char *mac, char *input_type, char *input)
{
	char path[256] = {0};
	char string[264] = {0};
	int len = sizeof(path);
	int checked = 0;
	int ret = 0;

	WBL_DBG(" %d, %s, %s, %s\n", bflag, mac, input_type, input);

	if (!strcmp(input_type, "url")) {
		checked = check_domain_format(input);
	}
	else if (!strcmp(input_type, "ip4")) {
		checked = check_ipv4_format(input);
	}

	if (checked == 0) {
		printf("[%s] input %s, %s is invalid\n", __FUNCTION__, input_type, input);
		return WRS_URL_INVALID;
	}

	WRS_WBL_GET_PATH(bflag, mac, path, len);

	if (!strcmp(path, "")) {
		printf("[%s] fail to find %s\n", __FUNCTION__, path);
		return WRS_FILE_CANT_FIND;
	}

	if (check_max_count(path) == -1) return WRS_MAX_COUNT;

	snprintf(string, sizeof(string), "%s %s\n", input_type, input);

	ret = f_write_string(path, string, FW_APPEND, 0);

	if (ret < 0) return WRS_FAIL_WRITE_DATA;

	WBL_DBG(" bflag=%d, mac=%s, string=%s", bflag, mac, string);
	return WRS_SUCCESS;
}

/*
	delete data from file
*/
int WRS_WBL_DEL_LIST(int bflag, char *mac, char *input_type, char *input)
{
	FILE *fp1 = NULL;
	FILE *fp2 = NULL;
	char string[MAX_DOMAIN+8] = {0};
	char buf[MAX_DOMAIN+8] = {0};
	char new[MAX_DOMAIN+8] = {0};
	char new_r[MAX_DOMAIN+8] = {0};
	char path[256] = {0};
	int len = sizeof(path);
	int is_rename = 0;
	int ret = 0;		// error code
	int checked = 0;	// check format and f_write_string

	printf("[%s] %d, %s, %s, %s\n", __FUNCTION__, bflag, mac, input_type, input);

	if (!strcmp(input_type, "url")) {
		checked = check_domain_format(input);
	}
	else if (!strcmp(input_type, "ip4")) {
		checked = check_ipv4_format(input);
	}

	if (checked == 0) {
		printf("[%s] input %s, %s is invalid\n", __FUNCTION__, input_type, input);
		return WRS_URL_INVALID;
	}

	unlink(REPLACE);
	WRS_WBL_GET_PATH(bflag, mac, path, len);
	WRS_WBL_FILE(REPLACE);

	if (!strcmp(path, "")) {
		printf("[%s] fail to find %s\n", __FUNCTION__, path);
		return WRS_FILE_CANT_FIND;
	}

	snprintf(string, sizeof(string), "%s %s", input_type, input);

	if ((fp1 = fopen(path, "r")) == NULL) {
		printf("[%s] fail to open %s\n", __FUNCTION__, path);
		ret = WRS_FILE_CANT_OPEN;
		goto END;
	}

	if ((fp2 = fopen(REPLACE, "r")) == NULL) {
		printf("[%s] fail to open %s\n", __FUNCTION__, REPLACE);
		ret = WRS_FILE_CANT_OPEN;
		goto END;
	}

	while (fgets(buf, sizeof(buf), fp1) != NULL) {
		// strip "\n"
		snprintf(new, strlen(buf), "%s", buf);

		// find the keyword
		if (!strcmp(new, string)) is_rename = 1;

		// mismatched, copy into new file
		if (strcmp(new, string)) {
			snprintf(new_r, sizeof(new_r), "%s\n", new); // append "\n" back
			WBL_DBG(" new=%s, new_r=%sm string=%s\n", new, new_r, string);
			checked = f_write_string(REPLACE, new_r, FW_APPEND, 0); // write string into REPLACE file

			// if can't f_write_string, should stop to append / copy / rename
			if (checked < 0) {
				ret = WRS_FAIL_WRITE_DATA;
				is_rename = 0;
				goto END;
			}
		}
	}

END:
	if (fp2) fclose(fp2);
	if (fp1) fclose(fp1);
	if (is_rename == 1) {
		if (rename(REPLACE, path) == 0) ret = WRS_SUCCESS;
	}

	WBL_DBG(" bflag=%d, mac=%s, string=%s, is_rename=%d, ret=%d\n", bflag, mac, string, is_rename, ret);
	return ret;
}

/*
	read data from file
*/
void WRS_WBL_READ_LIST(int bflag, char *mac, FILE *file)
{
	char buf[256] = {0};
	char path[256] = {0};
	int len = sizeof(path);
	FILE *fp = NULL;

	WRS_WBL_GET_PATH(bflag, mac, path, len);

	if (!strcmp(path, "")) {
		printf("[%s] fail to find %s\n", __FUNCTION__, path);
		return;
	}

	if ((fp = fopen(path, "r")) == NULL) {
		printf("[%s] fail to open %s\n", __FUNCTION__, path);
		return;
	}

	/* dump data into file; if no file pointer, dump debug message */
	if (file == NULL) {
		while (fgets(buf, sizeof(buf), fp) != NULL) {
			WBL_DBG(" %s", buf);
		}
	}
	else {
		while (fgets(buf, sizeof(buf), fp) != NULL) {
			fprintf(file, "%s", buf);
		}
	}

	/* safe close */
	if (fp) fclose(fp);
}

int wrs_wbl_main(char *action, int type, char *mac, char *input_type, char *input)
{
	int ret = 0;

	if (action == NULL) {
		printf("[%s] action is invalid\n", __FUNCTION__);
		return 0;
	}

	if (input_type == NULL) {
		input_type = "url";
	}

	if (mac == NULL) {
		mac = "";
	}

	if (!strcmp(action, "add") && input != NULL) {
		/* write data into file, input can't be NULL */
		ret = WRS_WBL_WRITE_LIST(type, mac, input_type, input);
	}
	else if (!strcmp(action, "del") && input != NULL) {
		/* delete data from file, input can't be NULL */
		ret = WRS_WBL_DEL_LIST(type, mac, input_type, input);
	}
	else if (!strcmp(action, "get")) {
		WRS_WBL_READ_LIST(type, mac, NULL);
	}
	else {
		printf("[%s] illegal parameters\n", __FUNCTION__);
		ret = WRS_ILLEGAL_PARAS;
	}

	WBL_DBG(" ret = %d\n", ret);
	return ret;
}

/*
	get profile number
*/
int GET_WBL_PROFILE_COUNT()
{
	int ret = 1;
	char buf[4] = {0};

	if (f_read_string(PROFILE_COUNT, buf, sizeof(buf)) > 0) {
		ret = atoi(buf);
	}

	WBL_DBG(" count = %d\n", ret);
	return ret;
}

static void SET_WBL_PROFILE_COUNT(int count)
{
	char buf[4] = {0};

	/* reset count if it's over the profile max number */
	if (count > MAX_PROFILE) count = 1;

	snprintf(buf, sizeof(buf), "%d", count);
	f_write_string(PROFILE_COUNT, buf, 0, 0);

	WBL_DBG(" count = %d\n", count);
}

int wbl_setup_global_rule(char *mac)
{
	FILE *fp = NULL;
	int count = 0;

	if (WRS_WBL_SIZE_STAT(0, mac) == 0 && WRS_WBL_SIZE_STAT(1, mac) == 0) {
		WBL_DBG(" There is no rules in whitelist and blacklist\n");
		return 0;
	}

	WRS_WBL_FILE(WBL_CONF);

	if ((fp = fopen(WBL_CONF, "a")) == NULL) {
		printf("fail to open %s.\n", WBL_CONF);
		return 0;
	}

	count = GET_WBL_PROFILE_COUNT();
	fprintf(fp, "[PROFILE %d]\n[ALL DEVS]\n", count);
	fprintf(fp, "[WHITE LIST]\n");
	WRS_WBL_READ_LIST(0, mac, fp);
	fprintf(fp, "[BLACK LIST]\n");
	WRS_WBL_READ_LIST(1, mac, fp);

	/* add count */
	count ++;
	SET_WBL_PROFILE_COUNT(count);

	/* safe close */
	if (fp) fclose(fp);

	return 1;
}

#define MAC_FMT_T "%c%c:%c%c:%c%c:%c%c:%c%c:%c%c"
#define MAC_EXPAND_T(o) \
	(uint8_t) o[0], (uint8_t) o[1], (uint8_t) o[2], (uint8_t) o[3], (uint8_t) o[4], (uint8_t) o[5] ,(uint8_t) o[6], (uint8_t) o[7], (uint8_t) o[8], (uint8_t) o[9], (uint8_t) o[10], (uint8_t) o[11]

int wbl_setup_mac_rule(char *mac)
{
	FILE *fp = NULL;
	int count = 0;

	char *dst = strdup(mac);
	char buf[20] = {0};

	if (strcmp(dst, "") && strstr(dst, ":") == NULL) {
		snprintf(buf, sizeof(buf), MAC_FMT_T, MAC_EXPAND_T(mac));
	}
	else {
		snprintf(buf, sizeof(buf), "%s", mac);
	}
	WBL_DBG(" buf = %s\n", buf);
	if (dst) free(dst);

	if (WRS_WBL_SIZE_STAT(0, buf) == 0 && WRS_WBL_SIZE_STAT(1, buf) == 0) {
		WBL_DBG(" There is no rules in whitelist and blacklist\n");
		return 0;
	}

	WRS_WBL_FILE(WBL_CONF);

	if ((fp = fopen(WBL_CONF, "a")) == NULL) {
		printf("fail to open %s.\n", WBL_CONF);
		return 0;
	}

	count = GET_WBL_PROFILE_COUNT();
	fprintf(fp, "[PROFILE %d]\n[MAC ONLY]\n[MAC LIST]\n%s\n", count, buf);
	fprintf(fp, "[WHITE LIST]\n");
	WRS_WBL_READ_LIST(0, buf, fp);
	fprintf(fp, "[BLACK LIST]\n");
	WRS_WBL_READ_LIST(1, buf, fp);

	/* add count */
	count ++;
	SET_WBL_PROFILE_COUNT(count);

	/* safe close */
	if (fp) fclose(fp);

	return 1;
}

int clean_wbl_conf()
{
	int ret = 0;

	if (f_exists(WBL_CONF)) {
		SET_WBL_PROFILE_COUNT(1);
		unlink(WBL_CONF);
		ret = 1;
	}

	return ret;
}

int setup_wbl_conf(int type, char *mac)
{
	int is_g = 0;
	int is_m = 0;
	int ret __attribute__((unused)) = 0;

	if (mac == NULL) {
		mac = "";
	}

	/* check mac format */
	if (wbl_mac_format(mac) < 0) return WRS_WRONG_MAC_FORMAT;

	/* check */
	if (!strcmp(mac, "")) is_g = 1;
	if (strcmp(mac, ""))  is_m = 1;

	if (is_g == 0 && is_m == 0) {
		printf("[%s] illegal input\n", __FUNCTION__);
		return 0;
	}

	WRS_WBL_FOLDER(BWDPI_WBL_PATH);
	WRS_WBL_FOLDER(TMP_BWDPI);

	/* setup global or mac rule into wbl.conf */
	if (is_g) ret = wbl_setup_global_rule(mac);
	if (is_m) ret = wbl_setup_mac_rule(mac);

	return 1;
}
