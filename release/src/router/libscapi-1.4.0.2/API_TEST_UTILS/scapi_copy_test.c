#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>

#include <ltq_api_include.h>


int main(int argc, char** argv){
	int nRet = -EXIT_FAILURE;

	nRet = scapi_copy(argv[1], argv[2]);

	if(nRet == 0)
		printf("Success. Copied\n");
	else
		printf("Failed to copy\n");
	return 0;
}
