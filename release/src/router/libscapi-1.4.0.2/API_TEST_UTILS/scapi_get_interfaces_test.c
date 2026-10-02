#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>

#include <ltq_api_include.h>

int main(int argc, char** argv){
	Ifc* pxIfc = NULL;
	int nIfcCount = 0, nRet = -EXIT_FAILURE;

	nRet = scapi_getIfcs(&pxIfc, &nIfcCount);

	if(nRet < 0){
		printf("Error getting interfaces\n");
		return -1;
	}

	int nCount = 0;
	for(;nCount < nIfcCount; ++nCount, ++pxIfc){
		printf("Interface Name --> %s\n", pxIfc->ifname);
	}
	return 0;
}
