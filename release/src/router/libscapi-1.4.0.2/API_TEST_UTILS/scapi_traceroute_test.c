/*
 * =====================================================================================
 *
 *       Filename:  scapi_insmod_test.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  06/24/15 17:16:44
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Lantiq Communications (), 
 *   Organization:  Lantiq Communications
 *
 * =====================================================================================
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>

#include <ltq_api_include.h>

/* TESTS
 * -----
 *
 * 1. scapi_traceroute("-m 10 -w 5000 www.google.com",40, &trace_route_resp);
 * 2. scapi_traceroute("-w 500 www.google.com",40, &trace_route_resp);
 *
 *
 *
 */


int main(int argc, char** argv){
	
	TraceRouteResp_D trace_route_resp = {0};
	int nRet = scapi_traceroute(argv[1], 40, &trace_route_resp);

	int i = 0;

	for( i = 0; i < trace_route_resp.iRouteHopsNumberOfEntries; ++i){
		printf("@@@@@@@@@@@@@@@@@ HOP %d @@@@@@@@@@@@@@@@@\n", i + 1);
		printf("hop host name = %s\n", trace_route_resp.pxRouteHops->hophost);
		printf("hop host address = %s\n", trace_route_resp.pxRouteHops->hophost_address);
		printf("hop rtt = %s\n", trace_route_resp.pxRouteHops->hop_rtt_time);
	}
	printf("Return = %d\n", nRet);
	free(trace_route_resp.pxRouteHops);
	return 0;
}
