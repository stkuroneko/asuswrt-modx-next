#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <error.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/netlink.h>

#include    <sys/stat.h>
#include    <time.h>

#include "csr_test.h"
#include "csr_netlink.h"
#include "csr_table.h"
#include "csr_sysinfo.h"

#define min(a,b) 	( ( a > b) ? b : a )

#define GMAC_PROC	"/proc/rt2880/gmac"

void help( char* argv0, char* reason, int status_code)
{

  if (status_code == CMD_ERROR)
	printf("!! ERROR: %s !!\n", reason);
printf(""
"csr_test vesion %s\n"
"Usage: %s [options] address value...\n"
"  address:\taddress (must be heximal) to read/write the corresponding system register.\n"
"  value:\tthe value (must be heximal) to be written to the specific corresponding system register.\n"
"\n"
"Options:\n"
"  %s\t\tread system register"
"  %s\t\twrite system register"
"  %ssrtest\t\tPerform CSR Test"
"\n"
"\n"
"Example:\n"
"        %s %s 0xa0300010 \\\n"
"        %s %s 0xa0300010 0xffff1234\\\n"
"        %s %s\\\n"
"\n",
	CSRTEST_VERSION,
	argv0,
	cmd_option[CMD_READ], cmd_option[CMD_WRITE], cmd_option[CMD_CSRTEST],
	argv0, cmd_option[CMD_READ], argv0, cmd_option[CMD_WRITE], argv0, cmd_option[CMD_CSRTEST]);
}

/*
 *  mathStrtol() -- enhanced strtol(), supporting plus and minus operation.
 *
 *	Return: uint32   -- converted value
 *
 */
unsigned long mathStrtol(char* szSrc )
{
	char szTemp[256];
	char *pszToken;
	unsigned long retVal = 0;
	char prevOperator = '\0';

	printf("debug - input string %s\n", szSrc);
	strncpy( szTemp, szSrc, min( strlen(szSrc), sizeof(szTemp)-1 ) + 1 );

	for( pszToken = strtok( szTemp, "+-" );
	     pszToken;
	     pszToken = strtok( NULL, "+-" ) )
	{
		char chDeletedChar;

		/* find out what character was deleted by strtok(). */
		chDeletedChar = szSrc[pszToken-szTemp+strlen(pszToken)];
		
		switch( prevOperator )
		{
			case '+':
				retVal += strtol( pszToken, NULL, 16 );
				break;
			case '-':
				retVal -= strtol( pszToken, NULL, 16 );
				break;
			default:
				/* initial value */
				retVal = strtol( pszToken, NULL, 16 );
				break;
		}

		prevOperator = chDeletedChar;
	}

	printf("--- debug : 0x%08x\n", retVal);
	return retVal;
}

unsigned int hard_csr_rw_test(RT2880_CSR_MSG* csrmsg)
{
	int test;
	int reg_addr = 0;
	unsigned int reg_value = 0;
	pid_t pid, main;
	main = getpid();
	switch (pid = fork())
	{
		case -1:
			perror("Error process creation!\n");
			break;
		case 0:
			// for ( test = 0; test < 3; test++);
			csr_msg_send(csrmsg);
			_exit(0);	
		default:
			reg_value = csr_msg_recv(csrmsg);
	}
	for ( test = 0; test < 10; test++);
	return reg_value;
}

unsigned int reg_rw_test(RT2880_CSR_MSG* read_csrmsg)
{
		int counter, test;
		unsigned long reg_value;
		reg_value = hard_csr_rw_test(read_csrmsg);
		return reg_value;
}

unsigned int set_xor_reg(unsigned int address, unsigned int value, unsigned int mask)
{
	RT2880_CSR_MSG csr_msg;
	unsigned int set_value = (value ^ mask);
	
	csr_msg.enable = CSR_WRITE;
	csr_msg.address = address;
	csr_msg.default_value = set_value;
	printf(" --0x%08x--\t", set_value);

	csr_msg_send(&csr_msg);
	return set_value;
}

int csr_test()
{
	int i, j, ret = 0;
	unsigned long csr_reg_value;
	RT2880_CSR_MSG csr_msg;
	for ( i = 0; i < MAX; i++) {

		for ( j = 0; j < 100000; j++)
			;

		csr_msg = csr_msg_table[i];
		csr_reg_value = reg_rw_test(&csr_msg);
		csr_reg_value = reg_rw_test(&csr_msg);

		if ( csr_reg_value == 0) {
			for ( j = 0; j < 100000; j++)
				;
			csr_reg_value = reg_rw_test(&csr_msg);
		}
		if ( strncmp("dummy", csr_msg_table[i].reg_name, 5) != 0)
			printf("[%s]\t : address - 0x%08x, value - 0x%08x ", csr_msg_table[i].reg_name,csr_msg.address, csr_reg_value);
		else 
			printf("####\t");
		if ( csr_msg_table[i].write_mask != 0 ) {
			set_xor_reg( csr_msg_table[i].address, csr_reg_value, csr_msg_table[i].write_mask);
			csr_msg = csr_msg_table[i];

			for ( j = 0; j < 100000; j++)
				;

			csr_reg_value = reg_rw_test(&csr_msg);
			if ( csr_reg_value == 0) {
				for ( j = 0; j < 100000; j++)
					;
				csr_reg_value = reg_rw_test(&csr_msg);
			}
			printf("\t0x%08x", csr_reg_value);
		}

		printf("\n");
		if (csr_msg_table[i].default_value == IGNORE_VALUE )
			continue;
			
		if( csr_msg_table[i].default_value != csr_reg_value )
		{
			
			ret++;
			printf("---> ***Value mismatch!\n");
		}

	}	// csr table traversal		
	return ret;

}

int detect_drv()
{
	int i = 0; 
	FILE *gmac_proc;

	gmac_proc = fopen(GMAC_PROC, "r");
	if( gmac_proc == NULL) {
		// printf("proc not exist\n");
		i = -1;
	}
#if 0
	else
		printf("proc ok\n");
#endif
	return i;
}

int main(int argc, char* argv[])
{
	int ret;
	int parsingArgc;
	char parsingArgv[32];
	unsigned long csr_reg_value;
	int i, test, counter = 0;
	int cmd = 0;
	unsigned int n_addr = 0, n_val = 0;
	unsigned long addr2;
	
	RT2880_CSR_MSG read_csrmsg;

	/* check gmac driver whether install or not */
	i = detect_drv();
	if ( i < 0 )
	{
		printf("Please install raeth.o driver to get the program run!\n");
		return 0;
	}


	/* Parse parameter input */

	if ( argc == 1 ) {
		help(argv[0], "input option muse be given!", CMD_HELP);
		return -1;
	}

	if ( argc == 2) {
		if ( strncmp( "-i", argv[1], 2)  == 0) {
			printf("system information for RT2880-\n");
			show_sysinfo();
			return 0;
		} /* else {
			
			help(argv[0], "input option muse be given!");
			return -1;
		}
		*/
	}
	
	if ( strncmp( cmd_option[CMD_READ], argv[1], 2)  == 0) {
		cmd = CMD_READ;
		memcpy(parsingArgv, argv[2], strlen(argv[2]));
		n_addr = strtoll(parsingArgv, NULL, 16);
	}
	else if ( strncmp(cmd_option[CMD_WRITE], argv[1], 2) == 0 ) {
		if ( argc == 4 ) {	
			cmd = CMD_WRITE;
			n_addr = strtoll(argv[2], NULL, 16);
			n_val  = strtoll(argv[3], NULL, 16);
			// printf("0x%08x, 0x%08x\n", n_addr, n_val);
		} else {
			printf("error!\n");
			return -1;
		}
	} else if ( strncmp( cmd_option[CMD_CSRTEST] , argv[1], 8) == 0 )
				cmd = CMD_CSRTEST;
	else {
		help(argv[0], "input option incorrect!", CMD_ERROR);
		return -1;	
	}

	switch (cmd) {
		case CMD_CSRTEST:
		{
				ret = csr_test();
				if ( ret == 0 )
					printf("\n\nCSR Test --- Passed!\n\n");
				else
					printf("\n\nCSR Test --- %d register value mismatched in csr test!\n\n", ret);
				show_sysinfo();
		}
				break;
		case CMD_READ:
				read_csrmsg.enable = CSR_TEST;
				read_csrmsg.address = n_addr;
				n_val = reg_rw_test(&read_csrmsg);
				break;
		case CMD_WRITE:
				printf("register write 0x%08x(address) : 0x%08x ", n_addr, n_val);
				read_csrmsg.enable = CSR_WRITE;
				read_csrmsg.address = n_addr;
				n_val = reg_rw_test(&read_csrmsg);
				printf("Done!\n");
				break;		
		default :
			printf("Format not correct!\n");
			break;
	};

	return 0;
}
