/*===========================================================================
FILE: 
   GobiConnectionMgmt.cpp

DESCRIPTION:
   QUALCOMM Connection Management API for Gobi 3000

PUBLIC CLASSES AND FUNCTIONS:
   cGobiConnectionMgmtDLL
   cGobiConnectionMgmt

Copyright (c) 2012, Code Aurora Forum. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of Code Aurora Forum nor
      the names of its contributors may be used to endorse or promote
      products derived from this software without specific prior written
      permission.


THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
==========================================================================*/

//---------------------------------------------------------------------------
// Include Files
//---------------------------------------------------------------------------
#include "StdAfx.h"
#include "GobiConnectionMgmtAPI.h"

//---------------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------------
#define cprintf(fmt,args...) {FILE *fp = fopen("/dev/console", "w"); if(fp != NULL) { fprintf(fp, fmt, ##args); fflush(fp); fflush(fp); fclose(fp); }}
#define LOGE(...) printf(__VA_ARGS__)

#define GOBI_DEVICE	"qcqmi0"
#define FULL_DUPLEX_PIPE	"/tmp/pipe"
#define MAX_BUF_SIZE	100

ULONG SessionId_ipv4_1 = 0;
ULONG SessionId_ipv4 = 0;
ULONG SessionId_ipv6 = 0;

int main_test(char *input);


#if 0
void FNNewSMS(ULONG storageType, ULONG messageIndex){
	ULONG ret;
	ULONG MessageTag;
	ULONG MessageFormat;
	BYTE  Message[256] = {0};
	ULONG MessageSize = sizeof(Message);
	BYTE  MessageMode = 1;//WCDMA

	ret = GetSMS(storageType,
			messageIndex,
			&MessageTag,
			&MessageFormat,
			&MessageSize,
			Message,
			&MessageMode);
	if(ret == 0){
		printf(printf("GetSMS success\n");
		printf("MessageTag = %ld\n", MessageTag);
		printf("MessageFormat = %ld\n", MessageFormat);
		printf("MessageSize = %ld\n", MessageSize);
		for(int i = 0; i < MessageSize; i++)
			printf("%02x ", *(Message+i));
		printf("\n");
	}
	else
		printf("GetSMS fail ret = %ld\n", ret);
}
#endif

static void ap_query_parse_status(char *buf){
	printf("receive buf = %s\n", buf);
	main_test(buf);
}

static void ap_query_staus_thread_proc(void){
	int rdfd, ret_val, numread;
	char buf_rd[MAX_BUF_SIZE];
	FILE *fp;

	while(TRUE){
		unlink(FULL_DUPLEX_PIPE);
		if(access(FULL_DUPLEX_PIPE, R_OK) != 0){
			ret_val = mkfifo(FULL_DUPLEX_PIPE, 0666);
		}

		if(ret_val == -1 && errno != EEXIST){
			LOGE("ap_service Error creating the 1st named pipe %d ",errno);
			exit(1);
		}

		/* Open the first named pipe for reading */
		rdfd = open(FULL_DUPLEX_PIPE, O_RDONLY);
		LOGE("ap_query_staus_thread_proc rdfd = %d",rdfd);
		if(rdfd <= 0){
			LOGE("ap_service error in opening RD FIFO");
			remove(FULL_DUPLEX_PIPE);
			exit(1);
		}

		fp = fdopen(rdfd, "r");
		while(TRUE){
			/* Read from the first pipe */
			//LOGV("ap_query_staus_thread_proc, parentID = %d", getpid());
			if(fp != NULL){
				if(fgets(buf_rd, MAX_BUF_SIZE, fp) == NULL){
					fclose(fp);
					close(rdfd);
					break;
				}
				else {
					numread = strlen(buf_rd);
				}
			}
			else {
				numread = read(rdfd, buf_rd, MAX_BUF_SIZE - 1);
			}
			if(numread <= 0){
				close(rdfd);
				break;
			}

			buf_rd[numread] = 0;
			cprintf("%s %d: rdfd(%d) numread(%d) (%s)\n", __func__, getpid(), rdfd, numread, buf_rd);
			if(numread > 0){
				ap_query_parse_status(buf_rd);
			}
		}
	}
}

int trimR(char *str){
	char cc;
	int ii;
	int liLen = strlen(str);

	for(ii = liLen-1; ii >= 0; --ii){
		cc = str[ii];
		//if(cc == 10 || cc == 13 || cc == ' ' || cc == 9)
		if(cc == 10 || cc == 13)
			str[ii] = '\0';
		else
			break;	
	}

	return ii;
}

void FNSessionState_cb( 
ULONG                      state,
ULONG					   sessionEndReason,
ULONG					   ipfamily)
{
	printf("state=%ld,sessionEndReason=%ld,ipfamily=%d\n",state,sessionEndReason,ipfamily);
	//printf("sessionEndReason = %ld\n",sessionEndReason);
	//printf("ipfamily = %ld\n",ipfamily);	
}


int main_test(CHAR *input){
	int i, opt = atoi(input);
	CHAR scan_string[MAX_BUF_SIZE] = {0};
	ULONG ret;
	char *para[6] = {0};
	const char *delim = ",";
	char *pch;

	pch = strtok(input, delim);
	for(i = 0; pch != NULL && i < 6; ++i){
		para[i] = pch;
		trimR(para[i]);
		pch = strtok(NULL, delim);
		printf("para[%d] = %s***\n", i, para[i]);
	}
 
	opt = atoi(para[0]);

	if(opt == 1){
		ret = QCWWANConnect(para[1], (CHAR *)"");
		if(ret == 0){
			printf("QCWWANConnect success\n");
		ret=SetSessionStateCallback(FNSessionState_cb); 
		fprintf(stderr,"SetSessionStateCallback ret 14 = %ld\n",ret);			
#if 0
			ret = SetNewSMSCallback(FNNewSMS);
			if(ret == 0)
				printf("SetNewSMSCallback success!\n");
			else
				printf("SetNewSMSCallback fail ret = %ld\n", ret);
#endif
		}
		else
			printf("QCWWANConnect fail ret = %ld\n", ret);
	}
	else if(opt == 2){
		ret = QCWWANDisconnect();
		if(ret == 0)
			printf("QCWWANDisconnect success\n");
		else
			printf("QCWWANDisconnect fail ret = %ld\n", ret);
	}
	else if(opt == 3){
		ULONG FailureReason;
		CHAR *apn, *user, *pass;

		SessionId_ipv4_1 = 0;

		if(para[1] != NULL && strlen(para[1]) > 0)
			apn = para[1];
		else
			apn = NULL;
		if(para[2] != NULL && strlen(para[2]) > 0)
			user = para[2];
		else
			user = NULL;
		if(para[3] != NULL && strlen(para[3]) > 0)
			pass = para[3];
		else
			pass = NULL;

		ret = StartDataSession(
				NULL,//ULONG *					pTechnology,
				NULL,//ULONG *					pPrimaryDNS,
				NULL,//ULONG *					pSecondaryDNS,
				NULL,//ULONG *					pPrimaryNBNS,
				NULL,//ULONG *					pSecondaryNBNS,
				apn,//CHAR * 					pAPNName,
				NULL,//ULONG *					pIPAddress,
				NULL,//ULONG *					pAuthentication,
				user,//CHAR * 					pUsername, 
				pass,//CHAR * 					pPassword,
				&SessionId_ipv4_1,//ULONG *				pSessionId,
				&FailureReason// *					pFailureReason
				);
		printf("SessionId_ipv4_1 = 0x%lx\n", SessionId_ipv4_1);

		if(ret == 0){
			printf("StartDataSession IPV4 success\n");
#if 0	//skip udhcpc
			sleep(2);
			system("udhcpc -i usb0");
#endif
		}
		else{
			printf("StartDataSession IPV4 fail ret = %ld\n", ret);
			printf("FailureReason = %lx\n", FailureReason);
		}
	}
	else if(opt == 4){
		ret = StopDataSession(SessionId_ipv4_1 /*ULONG SessionId*/);
		printf("SessionId = 0x%lx\n", SessionId_ipv4_1);

		if(ret == 0){
			printf("StopDataSession IPV4 success\n");
			SessionId_ipv4_1 = 0;
#if 0	//skip udhcpc
			sleep(2);
			system("udhcpc -i usb0");   
#endif
		}
		else
			printf("StopDataSession IPV4 fail ret = %ld\n", ret);
	}
	else if(opt == 5){
		ULONG profileType = 0;//3GPP
		ULONG PDPType = atoi(para[1]);
		ULONG authmode = atoi(para[4]);
		//ULONG SecondaryDNS = 0x12345678;

		//if(strlen(para[1]) > 0)
			ret = SetDefaultProfile(profileType,
					&PDPType,// 0: PDP-IP(IPv4), 1: PDP-PPP, 2: PDP-IPv6, 3: PDP-IPv4v6.
					NULL,
					NULL,
					NULL,//&SecondaryDNS,
					&authmode,
					para[2],
					para[3],
					para[5],
					para[6]
					);
#if 0
		else
			ret = SetDefaultProfile(profileType,
					&PDPType,// 0: PDP-IP(IPv4), 1: PDP-PPP, 2: PDP-IPv6, 3: PDP-IPv4v6.
					NULL,
					NULL,
					NULL,//&SecondaryDNS,
					atoi(para[4]),
					NULL,
					para[3],
					para[5],
					para[6]
					);
#endif
		if(ret == 0)
			printf("SetDefaultProfile success\n");
		else
			printf("SetDefaultProfile fail ret = %ld\n", ret);
	}
	else if(opt == 6){
		ULONG profileType = 0;//3GPP
		ULONG PDPType = 0;
		ULONG IPAddress = 0;
		ULONG PrimaryDNS = 0;
		ULONG SecondaryDNS = 0;
		ULONG Authentication = 0;
		BYTE nameSize = MAX_BUF_SIZE;
		CHAR Name[MAX_BUF_SIZE] = {0};
		BYTE apnSize = MAX_BUF_SIZE;
		CHAR APNName[MAX_BUF_SIZE] = {0};
		BYTE userSize = MAX_BUF_SIZE;
		CHAR UserName[MAX_BUF_SIZE] = {0};

		ret = GetDefaultProfile(profileType,
				&PDPType,
				&IPAddress,
				&PrimaryDNS,
				&SecondaryDNS,
				&Authentication,
				nameSize,
				Name,
				apnSize,
				APNName,
				userSize,
				UserName);
		if(ret == 0){
			printf("GetDefaultProfile success\n");
			printf("profileType = %ld\n", profileType);
			printf("PDPType = %ld\n", PDPType);
			printf("Name = %s\n", Name);
			printf("APNName = %s\n", APNName);
			printf("Authmode = %d\n", Authentication);
			printf("Username = %s\n", UserName);
		}
		else
			printf("GetDefaultProfile fail ret = %ld\n", ret);
	}
	else if(opt == 7){
		ULONG num1, num2;

		num1 = strtoul(para[1], NULL, 10);
		num2 = strtoul(para[2], NULL, 10);

		ret = SetEnhancedAutoconnect(num1, &num2);
		if(ret == 0){
			printf("SetEnhancedAutoconnect success:\n");
			printf("autoconnect %lu.\n", num1);
			printf("    roaming %lu.\n", num2);
		}
		else
			printf("SetEnhancedAutoconnect fail ret = %ld\n", ret);
	}
	else if(opt == 8){
		ULONG autoconnect, roaming;

		ret = GetEnhancedAutoconnect(&autoconnect, &roaming);
		if(ret == 0){
			printf("GetEnhancedAutoconnect success:\n");
			printf("autoconnect %lu.\n", autoconnect);
			printf("    roaming %lu.\n", roaming);
		}
		else
			printf("GetEnhancedAutoconnect fail ret = %ld\n", ret);
	}
	else if(opt == 9){
		ULONG pCurrentChannelTXRate, pCurrentChannelRXRate, pMaxChannelTXRate, pMaxChannelRXRate;

		ret = GetConnectionRate(&pCurrentChannelTXRate, &pCurrentChannelRXRate, &pMaxChannelTXRate, &pMaxChannelRXRate);
		if(ret == 0){
			printf("GetConnectionRate success:\n");
			printf("current Tx %lu, Rx %lu.\n", pCurrentChannelTXRate, pCurrentChannelRXRate);
			printf("    Max Tx %lu, Rx %lu.\n", pMaxChannelTXRate, pMaxChannelRXRate);
		}
		else
			printf("GetConnectionRate fail ret = %ld\n", ret);
	}
	else if(opt == 10){
		ULONGLONG pTXTotalBytes, pRXTotalBytes;

		ret = GetByteTotals(&pTXTotalBytes, &pRXTotalBytes);
		if(ret == 0){
			printf("GetByteTotals success:\n");
			printf("Total Bytes: Tx %llu, Rx %llu.\n", pTXTotalBytes, pRXTotalBytes);
		}
		else
			printf("GetByteTotals fail ret = %ld\n", ret);
	}
	else if(opt == 11){
		ULONG FailureReason;
		ULONG ret;
		ULONG Ipfamily = 8;//4:IPv4 6:IPv6 8:Unspecified
		ULONG *SessionId = NULL;
		CHAR *apn, *user, *pass;

		SessionId_ipv4 = 0;
		SessionId_ipv6 = 0;

		Ipfamily = atoi(para[1]);
		if(Ipfamily == 4)
			SessionId = &SessionId_ipv4;
		else if(Ipfamily == 6)
			SessionId = &SessionId_ipv6;
		else
			SessionId = &SessionId_ipv4;

		if(para[2] != NULL && strlen(para[2]) > 0)
			apn = para[2];
		else
			apn = NULL;
		if(para[3] != NULL && strlen(para[3]) > 0)
			user = para[3];
		else
			user = NULL;
		if(para[4] != NULL && strlen(para[4]) > 0)
			pass = para[4];
		else
			pass = NULL;

		ret = StartDataSessionWithIPFamily(
				NULL,//ULONG *					pTechnology, 
				NULL,//ULONG *					pPrimaryDNS, 
				NULL,//ULONG *					pSecondaryDNS, 
				NULL,//ULONG *					pPrimaryNBNS, 
				NULL,//ULONG *					pSecondaryNBNS, 
				apn,//CHAR * 				pAPNName, 
				NULL,//ULONG *					pIPAddress, 
				NULL,//ULONG *					pAuthentication, 
				user,//CHAR * 				pUsername, 
				pass,//CHAR * 				pPassword,
				&Ipfamily,
				SessionId,//ULONG *				pSessionId,
				&FailureReason// *					pFailureReason
				);
		printf("SessionId(Ipfamily %s) = 0x%lx\n", (Ipfamily == 8)?"Unspecified":para[1], *SessionId);

		if(ret == 0){
			printf("StartDataSession success\n");
			//sleep(2);
			//system("udhcpc -i usb0");
		}
		else
		{
			printf("StartDataSession fail ret = %ld\n", ret);
			printf("FailureReason = %lx\n", FailureReason);
		}
	}
	else if(opt == 12){
		ret = StopDataSession(SessionId_ipv6 /*ULONG SessionId*/);
		printf("SessionId = 0x%lx\n", SessionId_ipv6);

		if(ret == 0){
			printf("StopDataSession IPV6 success\n");
			SessionId_ipv6 = 0;
#if 0	//skip udhcpc
			sleep(2);
			system("udhcpc -i usb0");   
#endif
		}
		else
			printf("StopDataSession IPV6 fail ret = %ld\n", ret);
	}
#if 0
	else if(!strncmp(input, "7", 1)){
		ULONG messageFormat = 6;
		ULONG MessageFailureCode;
		BYTE Message[] = {
				0x07, 0x91, 0x88, 0x96, 0x23, 0x04, 0x80, 0x12,//SMSC
				0x01,// SMS Submit Type
				0x00,// SMS Message Reference
				0x0a, 0x81, 0x90, 0x87, 0x31, 0x20, 0x07,// Sending Address 0978130270 Chunhwa test sim
				0x00,// Pid
				0x08,// Dcs
				0x0c,// UD
				0x00, 0x53, 0x00, 0x4d, 0x00, 0x53, 0x6e, 0x2c, 0x8a, 0x66, 0x00, 0x21// content-->  SMS測試!
				};
		ULONG messageSize = sizeof(Message);

		ret = SendSMS(messageFormat,
				messageSize,
				Message,
				&MessageFailureCode);
		if(ret == 0)
			printf("SendSMS success\n");
		else
			printf("SendSMS fail ret = %ld\n", ret);
	}
	else if(!strncmp(input, "8", 1)){
		ULONG storageType = 0x00;//UIM
		ULONG messageIndex = 5;
		ULONG MessageTag;
		ULONG MessageFormat;
		ULONG MessageSize = 256;
		BYTE  Message[256]={0};
		BYTE  MessageMode = 1;//WCDMA

		ret = GetSMS(storageType,
				messageIndex,
				&MessageTag,
				&MessageFormat,
				&MessageSize,
				Message,
				&MessageMode);
		if(ret == 0){
			printf("GetSMS success\n");
			printf("MessageTag = %ld\n", MessageTag);
			printf("MessageFormat = %ld\n", MessageFormat);
			printf("MessageSize = %ld\n", MessageSize);
			for(int i = 0; i < MessageSize; i++)
				printf("%02x ", *(Message+i));
			printf("\n");
		}
		else
			printf("GetSMS fail ret = %ld\n", ret);
	}
#endif
	else if(opt == 99){
		ret = QCWWANDisconnect();
		if(ret == 0)
			printf("QCWWANDisconnect success\n");
		else
			printf("QCWWANDisconnect fail ret = %ld\n", ret);
		printf("user enter exit!!\n");
		exit(0);
	}
	/* Invalid integer entered. */
	else
		printf("Invalid response %d\n", opt);

	printf("\n");  
	return 0;
}

int main(int argc, char **argv){
	int opt = 0;
	char scan_string[MAX_BUF_SIZE] = {0};

	if(argc >= 2 && !strncasecmp(argv[1], "d", 1)){
		ap_query_staus_thread_proc();
	}
	else{ 
		while(TRUE){
			/* Display menu of options. */
			printf("Please select an option to test from the items listed below.\n\n");
			printf(" 1. Connect to GobiNet. flags: ,dev name,.\n");
			printf(" 2. Disconnect to GobiNet.\n");
			printf(" 3. WDS Start IPV4 DATA SESSION. no flag or flags: ,apn,user,pass,.\n");
			printf(" 4. WDS Stop  IPV4 DATA SESSION.\n");
			printf(" 5. WDS Set Default Profile. flags: ,PDP,isp,apn,authmode,user,pass,.\n");
			printf(" 6. WDS Get Default Profile.\n");
			printf(" 7. Set the autoconnect data session setting. flags: ,autoconnect,roaming,.\n");
			printf(" 8. Get the current autoconnect data session setting.\n");
			printf(" 9. Get connection rate information.\n");
			printf("10. Get returns the RX/TX byte.\n");
			printf("11. WDS Start IPV4V6 DATA SESSION. no flag or flags: ,IP type,apn,user,pass,.\n");
			printf("12. WDS Stop  IPV6 DATA SESSION.\n");
			printf("99. Exit\n");

			/* Read the option from the standard input. */
			if(fgets(scan_string, sizeof(scan_string), stdin) == NULL)
				continue;

			main_test(scan_string);
		}
	}
	return 0;
}
