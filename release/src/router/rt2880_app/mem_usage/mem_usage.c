/*
 * memory allocator --  memory usage test
 *
 * # mem_alloc [allocate_unit]
 *
 * ex:
 * # mem_alloc
 * # mem_alloc 1024
 * # mem_alloc 300
 */

#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#define DEFAULT_UNIT		(4096)
#define RETRY_MAX	10

int stop_flag = 0;

void ctrl_c_handler(int signo)
{
	stop_flag = 1;
}

int main(int argc, char *argv[])
{
	int i, retry=0;

	unsigned int memory = 0;
	unsigned int unit = DEFAULT_UNIT;
	unsigned char *alloc;

	setbuf(stdout, NULL);
	signal(SIGINT, ctrl_c_handler);

	if(argc == 2){
		unit = atoi(argv[1]);
		if(!unit)
			unit = DEFAULT_UNIT;
	}

	while(1){
		if(!retry)
			alloc = (unsigned char *)malloc(unit);


		if(alloc){
			// access memory to make sure linux to do page allocation.
			for(i=0; i<unit;i++)
				*(alloc+i) = i % 256;	

			memory = memory + unit;
			printf("%d: %d(%.2fMB)\n", getpid(), memory, (float)memory/1024.0/1024.0);
		}else
			retry++;

		if(retry > RETRY_MAX || stop_flag )
			break;
	}
	printf("\n\nThe total allocated memory size is %d(%.2fMB)\n", memory, (float)memory/1024.0/1024.0);
	return 0;
}

