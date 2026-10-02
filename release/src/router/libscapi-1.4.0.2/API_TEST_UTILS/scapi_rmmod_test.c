/*
 * =====================================================================================
 *
 *       Filename:  scapi_rmmod_test.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  06/24/15 17:25:16
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
 * Test 1: module name with full path + .ko           --> not supported
 * Test 2: module name with full path + without .ko   --> not supported
 * Test 3: Just module name + with .ko                --> working
 * Test 4: Just module name + with out .ko            --> working
 */

int main(int argc, char** argv){
	int nRet = scapi_rmmod(argv[1], atoi(argv[2]));

	if(nRet != 0){
		printf("Failed to remove module\n");
	}
	else
		printf("Successfully removed the module\n");
	return 0;
}
