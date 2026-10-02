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
 * Test 1: module name with full path + .ko           --> working
 * Test 2: module name with full path + without .ko   --> working
 * Test 3: Just module name + with .ko                --> working
 * Test 4: Just module name + with out .ko            --> working
 * Test 5: With wildcard                              --> working
 */


int main(int argc, char** argv){
	printf("@@@@ Insert %s\n", argv[1]);
	
	int nRet = scapi_insmod(argv[1], NULL);

	if(nRet == 0){
		printf("1. Working. Module inserted\n");
	}
	else{
		printf("1. Failed to insert module\n");
	}

	return 0;
}
