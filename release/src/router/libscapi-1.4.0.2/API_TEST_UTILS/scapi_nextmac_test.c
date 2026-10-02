#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ltq_api_include.h>


int main(int argc, char** argv){
	char mac[SCAPI_MAC_LEN] = {0};

	/************************* TEST 1 **************************/

	int nRet = scapi_setIfcMacaddr(argv[1], "AA:BB:CC:00:00:00", -1);

	if( nRet != 0)
		printf("Test 1. Failure to set mac\n");
	else{
		scapi_getIfcMacaddr(argv[1], mac);
		if(!strcasecmp("AA:BB:CC:00:00:00", mac))
			printf("--> Test 1 pass\n");
	}


	/************************* TEST 2 **************************/

	nRet = scapi_setIfcMacaddr(argv[1], "AA:BB:CC:00:E0:FF", 5);
	if(nRet < 0){
		printf("Test 2. Failure to set mac\n");
	}
	else{
		scapi_getIfcMacaddr(argv[1], mac);
		if(!strcasecmp("AA:BB:CC:00:E1:00", mac))
			printf("--> Test 2 pass\n");
	}

	/************************* TEST 3 **************************/

	nRet = scapi_setIfcMacaddr(argv[1], "AA:BB:CC:00:FF:FF", 5);
	if(nRet < 0){
		printf("Test 3. Failure to set mac\n");
	}
	else{
		scapi_getIfcMacaddr(argv[1], mac);
		if(!strcasecmp("AA:BB:CC:01:00:00", mac))
			printf("--> Test 3 pass\n");
	}


	/************************* TEST 4 **************************/

	nRet = scapi_setIfcMacaddr(argv[1], "AA:BB:CC:FF:FF:FF", 5);
	if(nRet < 0){
		printf("Test 4. Failure to set mac\n");
	}
	else{
		scapi_getIfcMacaddr(argv[1], mac);
		if(!strcasecmp("AA:BB:CC:00:00:00", mac))
			printf("--> Test 4 pass\n");
	}

	return 0;
}
