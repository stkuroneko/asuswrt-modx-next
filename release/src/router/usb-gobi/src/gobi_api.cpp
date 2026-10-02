#include "StdAfx.h"
#include "GobiConnectionMgmtAPI.h"


//---------------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------------
#define MAX_BUF_SIZE	100

#define DEBUG_USB

#ifdef DEBUG_USB
#define LOGFILE "/tmp/usb.log"
#define usb_dbg(fmt, args...) do{ \
		FILE *fp = fopen(LOGFILE, "a+"); \
		if(fp){ \
			fprintf(fp, "[usb_dbg: ] "fmt, ## args); \
			fclose(fp); \
		} \
	}while(0)
#else
#define usb_dbg printf
#endif


int main(int argc, char **argv){
	ULONG ret;
	ULONG FailureReason;
	CHAR dev[MAX_BUF_SIZE];

	if(argc < 3){
		usb_dbg("Usage: gobi_api GOBI_DEVICE command\n");
		exit(0);
	}

	ret = QCWWANConnect((CHAR *)argv[1], (CHAR *)"");
	if(ret != 0){
		usb_dbg("QCWWANConnect fail ret = %ld\n", ret);
		exit(ret);
	}

	if(!strcmp(argv[2], "rate")){
		ULONG pCurrentChannelTXRate, pCurrentChannelRXRate, pMaxChannelTXRate, pMaxChannelRXRate;

		ret = GetConnectionRate(&pCurrentChannelTXRate, &pCurrentChannelRXRate, &pMaxChannelTXRate, &pMaxChannelRXRate);
		if(ret == 0)
			usb_dbg("    Max Tx %lu, Rx %lu.\n", pMaxChannelTXRate, pMaxChannelRXRate);
		else
			usb_dbg("GetConnectionRate fail ret = %ld\n", ret);
	}
	else if(!strcmp(argv[2], "byte")){
		ULONGLONG pTXTotalBytes, pRXTotalBytes;

		ret = GetByteTotals(&pTXTotalBytes, &pRXTotalBytes);
		if(ret == 0)
			usb_dbg("Total Bytes: Tx %llu, Rx %llu.\n", pTXTotalBytes, pRXTotalBytes);
		else
			usb_dbg("GetByteTotals fail ret = %ld\n", ret);
	}
	else if(!strcmp(argv[2], "hw")){
		CHAR str[MAX_BUF_SIZE];

		ret = GetHardwareRevision(MAX_BUF_SIZE, (CHAR *)str);
		if(ret == 0)
			usb_dbg("Hardware Revision: %s.\n", str);
		else
			usb_dbg("GetHardwareRevision fail ret = %ld\n", ret);
	}
	else if(!strcmp(argv[2], "icc")){
		CHAR str[MAX_BUF_SIZE];

		ret = UIMGetICCID(MAX_BUF_SIZE, (CHAR *)str);
		if(ret == 0)
			usb_dbg("ICCID: %s.\n", str);
		else
			usb_dbg("UIMGetICCID fail ret = %ld\n", ret);
	}
	else if(!strcmp(argv[2], "SetDefaultProfile")){
		// gobi_api $qcqmi SetDefaultProfile "$modem_pdp" "$modem_isp" "$modem_apn" "$modem_authmode" "$modem_user" "$modem_pass"
		ULONG profileType = 0;//3GPP
		ULONG PDPType = atoi(argv[3]); // 0: PDP-IP(IPv4), 1: PDP-PPP, 2: PDP-IPv6, 3: PDP-IPv4v6.
		ULONG authmode = atoi(argv[6]);

		ret = SetDefaultProfile(profileType,
				&PDPType,// 0: PDP-IP(IPv4), 1: PDP-PPP, 2: PDP-IPv6, 3: PDP-IPv4v6.
				NULL,
				NULL,
				NULL,//&SecondaryDNS,
				&authmode,
				argv[4],
				argv[5],
				argv[7],
				argv[8]
				);
		if(ret == 0)
			usb_dbg("SetDefaultProfile done.\n");
		else
			usb_dbg("SetDefaultProfile fail ret = %ld\n", ret);
	}
	else if(!strcmp(argv[2], "GetDefaultProfile")){
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
				UserName
				);
		if(ret == 0){
			usb_dbg("profileType = %ld\n", profileType);
			usb_dbg("PDPType = %ld\n", PDPType);
			usb_dbg("Name = %s\n", Name);
			usb_dbg("APNName = %s\n", APNName);
			usb_dbg("Authmode = %d\n", Authentication);
			usb_dbg("Username = %s\n", UserName);
		}
		else
			usb_dbg("GetDefaultProfile fail ret = %ld\n", ret);
	}
	else if(!strcmp(argv[2], "SetEnhancedAutoconnect")){
		ULONG autoconnect = atoi(argv[3]);
		ULONG roaming = atoi(argv[4]);

		ret = SetEnhancedAutoconnect(autoconnect, &roaming);
		if(ret == 0)
			usb_dbg("SetEnhancedAutoconnect(%u, %u) done.\n", autoconnect, roaming);
		else
			usb_dbg("SetEnhancedAutoconnect(%u, %u) fail ret = %ld\n", autoconnect, roaming, ret);
	}
	else if(!strcmp(argv[2], "GetEnhancedAutoconnect")){
		ULONG autoconnect, roaming;

		ret = GetEnhancedAutoconnect(&autoconnect, &roaming);
		if(ret == 0){
			usb_dbg("autoconnect %lu.\n", autoconnect);
			usb_dbg("    roaming %lu.\n", roaming);
		}
		else
			usb_dbg("GetEnhancedAutoconnect fail ret = %ld\n", ret);
	}
	else if(!strcmp(argv[2], "StartDataSession")){
		// gobi_api $qcqmi StartDataSession "$modem_apn" "$modem_authmode" "$modem_user" "$modem_pass"
		CHAR *pAPNName, *pUsername, *pPassword;
		ULONG authmode = atoi(argv[4]);
		ULONG SessionId = 0;

		if(argv[3] != NULL && strlen(argv[3]) > 0)
			pAPNName = argv[3];
		else
			pAPNName = NULL;

		if(argv[5] != NULL && strlen(argv[5]) > 0)
			pUsername = argv[5];
		else
			pUsername = NULL;

		if(argv[6] != NULL && strlen(argv[6]) > 0)
			pPassword = argv[6];
		else
			pPassword = NULL;

		ret = StartDataSession(
				NULL,//ULONG *					pTechnology,
				NULL,//ULONG *					pPrimaryDNS,
				NULL,//ULONG *					pSecondaryDNS,
				NULL,//ULONG *					pPrimaryNBNS,
				NULL,//ULONG *					pSecondaryNBNS,
				pAPNName,//CHAR * 					pAPNName,
				NULL,//ULONG *					pIPAddress,
				&authmode,//ULONG *					pAuthentication,
				pUsername,//CHAR * 					pUsername,
				pPassword,//CHAR * 					pPassword,
				&SessionId,//ULONG *				pSessionId,
				&FailureReason// *					pFailureReason
				);
		usb_dbg("APN=%s, authmode=%d, pUsername=%s, pPassword=%s.\n", pAPNName, authmode, pUsername, pPassword);
		usb_dbg("SessionId = %lu\n", SessionId);

		if(ret == 0)
			usb_dbg("StartDataSession done.\n");
		else{
			usb_dbg("StartDataSession fail ret = %ld\n", ret);
			usb_dbg("FailureReason = %lx\n", FailureReason);
		}
	}
	else if(!strcmp(argv[2], "StartDataSessionWithIPFamily")){
		// gobi_api $qcqmi StartDataSessionWithIPFamily [ 4|6 ] "$modem_apn" "$modem_authmode" "$modem_user" "$modem_pass"
		ULONG Ipfamily = atoi(argv[3]); // 4: IPv4, 6: IPv6, 8: Unspecified
		CHAR *pAPNName, *pUsername, *pPassword;
		ULONG authmode = atoi(argv[5]);
		ULONG SessionId = 0;

		if(argc < 4){
			usb_dbg("Usage: gobi_api GOBI_DEVICE StartDataSessionWithIPFamily 4|6 [apn auth user pass]\n");
			exit(0);
		}

		if(Ipfamily != 4 && Ipfamily != 6 && Ipfamily != 8)
			Ipfamily = 4;

		if(argc > 4 && argv[4] != NULL && strlen(argv[4]) > 0)
			pAPNName = argv[4];
		else
			pAPNName = NULL;

		if(argc > 6 && argv[6] != NULL && strlen(argv[6]) > 0)
			pUsername = argv[6];
		else
			pUsername = NULL;

		if(argc > 7 && argv[7] != NULL && strlen(argv[7]) > 0)
			pPassword = argv[7];
		else
			pPassword = NULL;

		ret = StartDataSessionWithIPFamily(
				NULL,//ULONG *					pTechnology,
				NULL,//ULONG *					pPrimaryDNS,
				NULL,//ULONG *					pSecondaryDNS,
				NULL,//ULONG *					pPrimaryNBNS,
				NULL,//ULONG *					pSecondaryNBNS,
				pAPNName,//CHAR * 				pAPNName,
				NULL,//ULONG *					pIPAddress,
				&authmode,//ULONG *					pAuthentication,
				pUsername,//CHAR * 				pUsername,
				pPassword,//CHAR * 				pPassword,
				&Ipfamily,
				&SessionId,//ULONG *				pSessionId,
				&FailureReason// *					pFailureReason
				);
		usb_dbg("Ipfamily=%d, APN=%s, authmode=%d, pUsername=%s, pPassword=%s.\n", Ipfamily, pAPNName, authmode, pUsername, pPassword);
		usb_dbg("SessionId(Ipfamily %lu) = %lu\n", Ipfamily, SessionId);

		if(ret == 0){
			usb_dbg("StartDataSessionWithIPFamily done.\n");
			while(1) sleep(3600); // need to keep alive. After exit this process, the session will be shut down.
		}
		else{
			usb_dbg("StartDataSessionWithIPFamily fail ret = %ld\n", ret);
			usb_dbg("FailureReason = %lx\n", FailureReason);
		}
	}
	else if(!strcmp(argv[2], "StartDataSessionV4V6")){
		// gobi_api $qcqmi StartDataSessionV4V6 "$modem_apnv4" "$modem_authmodev4" "$modem_userv4" "$modem_passv4" "$modem_apnv6" "$modem_authmodev6" "$modem_userv6" "$modem_passv6"
		ULONG Ipfamily = 4; // 4: IPv4, 6: IPv6, 8: Unspecified
		CHAR *pAPNName, *pUsername, *pPassword;
		ULONG authmode = atoi(argv[4]);
		ULONG SessionId = 0;
		ULONG success = 0;

		if(argv[3] != NULL && strlen(argv[3]) > 0)
			pAPNName = argv[3];
		else
			pAPNName = NULL;

		if(argv[5] != NULL && strlen(argv[5]) > 0)
			pUsername = argv[5];
		else
			pUsername = NULL;

		if(argv[6] != NULL && strlen(argv[6]) > 0)
			pPassword = argv[6];
		else
			pPassword = NULL;

		ret = StartDataSessionWithIPFamily(
				NULL,//ULONG *					pTechnology,
				NULL,//ULONG *					pPrimaryDNS,
				NULL,//ULONG *					pSecondaryDNS,
				NULL,//ULONG *					pPrimaryNBNS,
				NULL,//ULONG *					pSecondaryNBNS,
				pAPNName,//CHAR * 				pAPNName,
				NULL,//ULONG *					pIPAddress,
				&authmode,//ULONG *					pAuthentication,
				pUsername,//CHAR * 				pUsername,
				pPassword,//CHAR * 				pPassword,
				&Ipfamily,
				&SessionId,//ULONG *				pSessionId,
				&FailureReason// *					pFailureReason
				);
		usb_dbg("Ipfamily=%d, APN=%s, authmode=%d, pUsername=%s, pPassword=%s.\n", Ipfamily, pAPNName, authmode, pUsername, pPassword);
		usb_dbg("SessionId(Ipfamily %lu) = %lu\n", Ipfamily, SessionId);

		if(ret == 0){
			usb_dbg("StartDataSessionV4 done.\n");
			++success;
		}
		else{
			usb_dbg("StartDataSessionV4 fail ret = %ld\n", ret);
			usb_dbg("FailureReason = %lx\n", FailureReason);
		}

		Ipfamily = 6;
		authmode = atoi(argv[8]);

		if(argv[7] != NULL && strlen(argv[7]) > 0)
			pAPNName = argv[7];
		else
			pAPNName = NULL;

		if(argv[9] != NULL && strlen(argv[9]) > 0)
			pUsername = argv[9];
		else
			pUsername = NULL;

		if(argv[10] != NULL && strlen(argv[10]) > 0)
			pPassword = argv[10];
		else
			pPassword = NULL;

		ret = StartDataSessionWithIPFamily(
				NULL,//ULONG *					pTechnology,
				NULL,//ULONG *					pPrimaryDNS,
				NULL,//ULONG *					pSecondaryDNS,
				NULL,//ULONG *					pPrimaryNBNS,
				NULL,//ULONG *					pSecondaryNBNS,
				pAPNName,//CHAR * 				pAPNName,
				NULL,//ULONG *					pIPAddress,
				&authmode,//ULONG *					pAuthentication,
				pUsername,//CHAR * 				pUsername,
				pPassword,//CHAR * 				pPassword,
				&Ipfamily,
				&SessionId,//ULONG *				pSessionId,
				&FailureReason// *					pFailureReason
				);
		usb_dbg("Ipfamily=%d, APN=%s, authmode=%d, pUsername=%s, pPassword=%s.\n", Ipfamily, pAPNName, authmode, pUsername, pPassword);
		usb_dbg("SessionId(Ipfamily %lu) = %lu\n", Ipfamily, SessionId);

		if(ret == 0){
			usb_dbg("StartDataSessionV6 done.\n");
			++success;
		}
		else{
			usb_dbg("StartDataSessionV6 fail ret = %ld\n", ret);
			usb_dbg("FailureReason = %lx\n", FailureReason);
		}

		if(success == 2){
			usb_dbg("Process(%d) keeps alive!\n", getpid());
			while(1) sleep(3600); // need to keep alive. After exit this process, the session will be shut down.
		}
	}
	else if(!strcmp(argv[2], "StopDataSession")){
		ULONG SessionId = atoi(argv[3]);

		ret = StopDataSession(SessionId /*ULONG SessionId*/);
		usb_dbg("SessionId = 0x%lx\n", SessionId);

		if(ret == 0)
			usb_dbg("StopDataSession %s success\n", argv[3]);
		else
			usb_dbg("StopDataSession %s fail ret = %ld\n", argv[3], ret);
	}
	else
		usb_dbg("Invalid command %s.\n", argv[2]);

	ret = QCWWANDisconnect();
	if(ret != 0)
		usb_dbg("QCWWANDisconnect fail ret = %ld\n", ret);

	return 0;
}
