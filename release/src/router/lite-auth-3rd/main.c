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
	app.c is the sample code for daemon or app usage
*/

/* common header */
#include <auth_common.h>

/* APP DEFINE */
#define APP_ID    "85432915"
#define APP_KEY   "f352564ceb50ec7e731"

int main(int argc, char* argv[])
{
	time_t timestamp = time(NULL);
	char in_buf[128];
	char out_buf[65];
	char hw_out_buf[65];
	char *hw_auth_code = NULL;

	// initial
	memset(in_buf, 0, sizeof(in_buf));
	memset(out_buf, 0, sizeof(out_buf));
	memset(hw_out_buf, 0, sizeof(hw_out_buf));

	// use timestamp + APP_KEY to get auth_code
	snprintf(in_buf, sizeof(in_buf)-1, "%ld|%s", timestamp, APP_KEY);

	hw_auth_code = hw_auth_check(APP_ID, get_auth_code(in_buf, out_buf, sizeof(out_buf)), timestamp, hw_out_buf, sizeof(hw_out_buf));

	// use timestamp + APP_KEY + APP_ID to get auth_code
	snprintf(in_buf, sizeof(in_buf)-1, "%ld|%s|%s", timestamp, APP_KEY, APP_ID);

	// debug
	//printf("hw_auth_code1=%s\n", hw_auth_code);
	//printf("hw_auth_code2=%s\n", get_auth_code(in_buf, out_buf, sizeof(out_buf)));

	if (strcmp(hw_auth_code, get_auth_code(in_buf, out_buf, sizeof(out_buf))) == 0) {
		;
		//printf("This is ASUS Router\n");
	}
	else {
		;
		//printf("This is not ASUS Router\n");
		return 0;
	}
	return 0;
}
