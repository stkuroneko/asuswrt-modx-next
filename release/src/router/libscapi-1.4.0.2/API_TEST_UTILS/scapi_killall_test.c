#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>

#include <ltq_api_include.h>

int main(int argc, char** argv)
{
	int nRet = scapi_killAll(argv[1], atoi(argv[2]));
	printf("nRet = %d\n", nRet);
	return nRet;
}
