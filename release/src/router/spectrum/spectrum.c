/*
	spectrum.c

	    This program executes commands and outputs the command results.
	When getting SIGUSR1 signal, it will ...
	When getting SIGUSR2 signal, it will ...

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/types.h>
#include <sys/sysinfo.h>
#include <sys/stat.h>
#include <stdint.h>
#include <syslog.h>

#include <bcmnvram.h>
#include <shutils.h>

#include <shared.h>


#define ADSL1_TONE 256
#define ADSL2_TONE 512

volatile int gotuser1 = 0;
volatile int gotterm = 0;

#define TMP_FILE_NAME_GET_BPC "/tmp/adsl/tc_bits_per_carrier.tmp"
#define TMP_FILE_NAME_GET_SNR "/tmp/adsl/tc_snr.tmp"
#define TMP_FILE_NAME_GET_ADSL1 "/tmp/adsl/tc_snr_adsl1.tmp"
#define TMP_FILE_NAME_GET_ADSL2_PLUS "/tmp/adsl/tc_snr_adsl2_plus.tmp"

typedef enum{
	T1_413 = 0
	, G_LITE = 1
	, G_DMT = 2
	, ADSL2 = 3
	, ADSL2PLUS = 4
	, NOT_AVAILABLE = 5
}DSL_Modulation;


int getModulation(void)
{
	char buf[256] = {0};
	char *ptr = NULL;
	FILE *logFile = fopen( "/tmp/adsl/adsllog.log", "r" );
	int mode = 5;
	
	if( !logFile )
	{
		printf("Error: adsllog.log does not exist.\n");
		return mode;
	}
	while( fgets(buf, sizeof(buf), logFile) )
	{
		if( (ptr=strstr(buf, "Modulation :")) != NULL )
		{
			ptr += strlen("Modulation :")+1;
			mode = atoi(ptr);
			break;
		}
	}

	fclose(logFile);
	return mode;

}

int getOffset(FILE *fp)
{
	char buf[ADSL2_TONE] = {0};
	int count = 0;

	count = 0;
	while(fgets(buf, sizeof(buf), fp)&&(count < ADSL2_TONE))
	{
		count++;
	}
	rewind(fp); //reset file pointer to the beginning of the file.
	return ((ADSL2_TONE-count)%256);
}

static void execute_command(int option)
{
	char syscmd[128] = {0};

	if(option == 1)
	{
		sprintf(syscmd, "adslate getbpc" );
	}
	else if(option == 2)
	{
		sprintf(syscmd, "adslate getadsl1snr" );
	}
	else
	{
		sprintf(syscmd, "adslate getadsl2snr" );
	}
	system(syscmd);
}

static void write_snr(float *output, int count)
{
	int i;
	FILE *f = NULL;

	f = fopen("/var/tmp/spectrum-snr", "w");
	if(!f) return;
	
	for(i = 0; i < count; i++)
	{
		fprintf(f, "\"%.2f\"", output[i] );
		if( i != count-1 )
		{
			fprintf(f, "," );
		}
	}
	fclose(f);
}

//snr : signal to noise ratio
static void save_snr(void)
{
	FILE *fsnr = NULL;
	int line_count = 0;
	static int runFlag = 0;
	char buf[256] = {0};
	float output[ADSL2_TONE] = {0.0};
	float snr = 0;
	int mode = 5;

	if(runFlag == 1)
	{
		//skip this time.
		return;
	}

	runFlag = 1;
	mode = getModulation();
	if(mode == 5)
	{
		memset(output, 0, sizeof(output));
		write_snr( output, sizeof(output)/sizeof(float) );
		goto snr_end;
	}
	
	system("adslate getsnr");
	if ((fsnr = fopen(TMP_FILE_NAME_GET_SNR, "r")) == NULL)
	{
		printf("Error: cannot read %s.\n", TMP_FILE_NAME_GET_SNR );
		goto snr_end;
	}

	line_count = getOffset(fsnr);
	while(fgets(buf, sizeof(buf), fsnr)&&(line_count < ADSL2_TONE))
	{
		sscanf(buf, "%f", &snr);
		output[line_count++] = snr;
	}
	fclose(fsnr);

	write_snr( output, line_count );

snr_end:
	runFlag = 0;
}

static void write_bpc1(unsigned int output[ADSL1_TONE])
{
	int i;
	FILE *fp_upStream = NULL, *fp_downStream = NULL;
	
	fp_upStream = fopen("/var/tmp/spectrum-bpc-us", "w");
	if(!fp_upStream) return;

	for(i = 0; i < ADSL1_TONE; i++)
	{
		if( i < 32 )
		{
			fprintf(fp_upStream, "\"%d\"", output[i] );
		}
		else
		{
			fprintf(fp_upStream, "\"%d\"", 0 );
		}
		
		if( i != ADSL1_TONE-1 )
		{
			fprintf(fp_upStream, "," );
		}
	}
	fclose(fp_upStream);

	fp_downStream = fopen("/var/tmp/spectrum-bpc-ds", "w");
	if(!fp_downStream) return;
	for(i = 0; i < ADSL1_TONE; i++)
	{
		if( i < 32 )
		{
			fprintf(fp_downStream, "\"%d\"", 0 );
		}
		else
		{
			fprintf(fp_downStream, "\"%d\"", output[i] );
		}
		
		if( i != ADSL1_TONE-1 )
		{
			fprintf(fp_downStream, "," );
		}
	}
	fclose(fp_downStream);

}

static void write_bpc2(unsigned int output[ADSL2_TONE])
{
	int i;
	FILE *fp_upStream = NULL, *fp_downStream = NULL;

	fp_upStream = fopen("/var/tmp/spectrum-bpc-us", "w");
	if(!fp_upStream) return;

	for(i = 0; i < ADSL2_TONE; i++)
	{
		if( i < 32 )
		{
			fprintf(fp_upStream, "\"%d\"", output[i] );
		}
		else
		{
			fprintf(fp_upStream, "\"%d\"", 0 );
		}
		
		if( i != ADSL2_TONE-1 )
		{
			fprintf(fp_upStream, "," );
		}
	}
	fclose(fp_upStream);

	fp_downStream = fopen("/var/tmp/spectrum-bpc-ds", "w");
	if(!fp_downStream) return;
	for(i = 0; i < ADSL2_TONE; i++)
	{
		if( i < 32 )
		{
			fprintf(fp_downStream, "\"%d\"", 0 );
		}
		else
		{
			fprintf(fp_downStream, "\"%d\"", output[i] );
		}
		
		if( i != ADSL2_TONE-1 )
		{
			fprintf(fp_downStream, "," );
		}
	}
	fclose(fp_downStream);
}

//bpc : bits per carrier
static void save_bpc(void)
{
	FILE *fbpc = NULL;
	int mode, i, row;
	unsigned int bits = 0;
	static int runFlag = 0;
	char buf[256] = {0};
	unsigned int output1[ADSL1_TONE] = {0};
	unsigned int output2[ADSL2_TONE] = {0};

	if(runFlag == 1)
	{
		//skip this time.
		return;
	}

	runFlag = 1;
	mode = getModulation();
	if( mode == 5 ) //N/A
	{
		printf("Warn: adsl modem not up.\n");
		memset(output2, 0, ADSL2_TONE);
		write_bpc2(output2);
	}
	else if( (mode == 4) || (mode == 3) ) //ADSL2+ or ADSL2
	{
		execute_command(1);

		if ((fbpc = fopen(TMP_FILE_NAME_GET_BPC, "r")) == NULL)
		{
			printf("Error: cannot read %s.\n", TMP_FILE_NAME_GET_BPC );
			memset(output2, 0, ADSL2_TONE);
			write_bpc2(output2);
			goto bpc_end;
		}

		i = 0;
		while( fgets(buf, sizeof(buf), fbpc) && (i < ADSL2_TONE) )
		{
			sscanf(buf, "%x", &bits );
			output2[i++] = bits;
		}
		fclose(fbpc);
		write_bpc2(output2);
	}
	else if( mode <= 2 ) //ADSL1
	{
		execute_command(1);

		if ((fbpc = fopen(TMP_FILE_NAME_GET_BPC, "r")) == NULL)
		{
			printf("Error: cannot read %s.\n", TMP_FILE_NAME_GET_BPC );
			memset(output1, 0, ADSL1_TONE);
			write_bpc1(output1);
			goto bpc_end;
		}

		i = 0;
		while( fgets(buf, sizeof(buf), fbpc) && (i < ADSL1_TONE) )
		{
			sscanf(buf, "%x", &bits );
			output1[i++] = bits;
		}
		fclose(fbpc);
		write_bpc1(output1);
	}
	else
	{
		printf("Warn: adsl modem not up.\n");
		memset(output2, 0, ADSL2_TONE);
		write_bpc2(output2);
	}

bpc_end:
	runFlag = 0;
}

static void sig_handler(int sig)
{
	switch (sig) {
	case SIGTERM:
	case SIGINT:
		gotterm = 1;
		break;
	case SIGUSR1:
		gotuser1 = 1;
		nvram_set("spectrum_hook_is_running","1");
		break;
	}
}

int main(int argc, char *argv[])
{
	struct sigaction sa;
	pid_t fpid;

	printf("spectrum\nCopyright (C) 2012-2012 ASUSWRT\n\n");

	nvram_set("spectrum_hook_is_running","0"); //initial, 0:NotRunning, 1: Running

	sa.sa_handler = sig_handler;
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGUSR1, &sa, NULL);
	sigaction(SIGUSR2, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);

	/* tell parent process to ignore the terminated child process. 
       ** Or there will be zombie process.
       */
	signal(SIGCHLD, SIG_IGN);

	while (1) {
		sleep(20);
		if (gotterm) {
			exit(0);
		}
		if (gotuser1) {
			gotuser1 = 0;
			fpid = fork();
			if(fpid == 0) {
				//child
				save_bpc();
				save_snr();
				nvram_set("spectrum_hook_is_running","0");
				_exit(0);
			}
			else {
				//parent, do nothing.
				continue;
			}
		}
	}
	return 0;
}
