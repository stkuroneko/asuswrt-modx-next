#include <ctype.h>
#include "libsmspdu.h"


int main(int argc, const char *argv[]){
	unsigned char buf[MAX_BUF_SIZE];
	int len;

	if(strstr(argv[0], "send_AT")){
		// $1: TTY node, $2: AT cmd, $3: waited sec, $4: output file, $5.
		if(argc == 6 && argv[1] != NULL && argv[2] != NULL && argv[3] != NULL && argv[4] != NULL && argv[5] != NULL){
			len = strtod(argv[3], NULL);
			len = send_AT(argv[1], argv[2], len, (char *)argv[4], (char *)argv[5]);

			printf("%s: ret=%d\n", argv[0], len);
		}
	}
	else if(strstr(argv[0], "initial_smspdu")){
		// $1: TTY node.
		if(argc == 2 && argv[1] != NULL){
			initial_smspdu(argv[1]);
		}
	}
	else if(strstr(argv[0], "listSMSIndex")){
		// $1: TTY node.
		if(argc == 2 && argv[1] != NULL){
			len = listSMSIndex(argv[1], buf, MAX_BUF_SIZE);
			printf("%s: total=%d\n", argv[0], len);
			printf("%s: index=%s\n", argv[0], buf);
		}
	}
	else if(strstr(argv[0], "getSMSPDUbyType")){
		// $1: TTY node, $2: SMS type. (0: "REC UNREAD", 1: "REC READ", 2: "STO UNSENT", 3: "STO SENT", 4: "ALL")
		if(argc == 3 && argv[1] != NULL && argv[2] != NULL){
			len = getSMSPDUbyType(argv[1], strtod(argv[2], NULL), buf, MAX_BUF_SIZE);
			printf("%s: index_num=%d.\n", argv[0], len);
			printf("%s: indexs=%s.\n", argv[0], buf);
		}
		else
			printf("%s: failed.\n", argv[0]);
	}
	else if(strstr(argv[0], "getSMSPDUbyIndex")){
		// $1: TTY node, $2: SMS index.
		if(argc == 3 && argv[1] != NULL && argv[2] != NULL){
			len = getSMSPDUbyIndex(argv[1], strtod(argv[2], NULL), buf, MAX_BUF_SIZE);
			printf("%s: type=%s.\n", argv[0], getSMSTypeStr(len));
			printf("%s: SMS=%s.\n", argv[0], buf);
		}
	}
	else if(strstr(argv[0], "getallSMSPDU")){
		// $1: TTY node.
		if(argc == 2 && argv[1] != NULL){
			len = getallSMSPDU(argv[1]);
			printf("%s: ret=%d.\n", argv[0], len);
		}
	}
	else if(strstr(argv[0], "saveSMSPDU")){
		// $1: TTY node, $2: SMSC, $3: Destination, $4: String file.
		if(argc == 5 && argv[1] != NULL && argv[2] != NULL && argv[3] != NULL && argv[4] != NULL){
			int sms_index;

			if((sms_index = saveSMSPDUtoSIM(argv[1], argv[2], argv[3], argv[4], buf, MAX_BUF_SIZE)) < 0)
				printf("%s: SMS-SUBMIT: Failed to saveSMS.\n", argv[0]);
			else if((len = getSMSPDUbyIndex(argv[1], sms_index, NULL, 0)) < 0)
				printf("%s: SMS-SUBMIT: Failed to getSMS.\n", argv[0]);
			else{
				printf("%s: index=%d.\n", argv[0], sms_index);
				printf("%s: type=%s.\n", argv[0], getSMSTypeStr(len));
				printf("%s: SMS=%s.\n", argv[0], buf);
			}
		}
	}
	else if(strstr(argv[0], "sendSMSPDU2")){
		// $1: TTY node, $2: SMS's index.
		if(argc == 3 && argv[1] != NULL && argv[2] != NULL){
			int sms_index = strtod(argv[2], NULL);
#ifdef SAVESMS
			char sms_file[PATH_MAX], sms_file2[PATH_MAX];
#endif

			if((len = sendSMSPDUfromSIM(argv[1], sms_index)) < 0)
				printf("%s: SMS-SUBMIT: Failed to send the index(%d) SMS.\n", argv[0], sms_index);
			else{
				printf("%s: done.\n", argv[0]);

#ifdef SAVESMS
				if(getSMSFileName(2, sms_index, sms_file, PATH_MAX) > 0 && getSMSFileName(3, sms_index, sms_file2, PATH_MAX) > 0)
					rename(sms_file, sms_file2);
#endif
			}
		}
	}
	else if(strstr(argv[0], "sendSMSPDU")){
		// $1: TTY node, $2: SMSC, $3: Destination, $4: String file.
		if(argc == 5 && argv[1] != NULL && argv[2] != NULL && argv[3] != NULL && argv[4] != NULL){
			int sms_index;
#ifdef SAVESMS
			char sms_file[PATH_MAX], sms_file2[PATH_MAX];
#endif

			if((sms_index = saveSMSPDUtoSIM(argv[1], argv[2], argv[3], argv[4], buf, MAX_BUF_SIZE)) < 0)
				printf("%s: SMS-SUBMIT: Failed to saveSMS.\n", argv[0]);
			else if((len = getSMSPDUbyIndex(argv[1], sms_index, NULL, 0)) < 0)
				printf("%s: SMS-SUBMIT: Failed to getSMS.\n", argv[0]);
			else if((len = sendSMSPDUfromSIM(argv[1], sms_index)) < 0)
				printf("%s: SMS-SUBMIT: Failed to sendSMS.\n", argv[0]);
			else{
				printf("%s: SMS-SUBMIT(%d)=%s.\n", argv[0], len, buf);

#ifdef SAVESMS
				if(getSMSFileName(2, sms_index, sms_file, PATH_MAX) > 0 && getSMSFileName(3, sms_index, sms_file2, PATH_MAX) > 0)
					rename(sms_file, sms_file2);
#endif
			}
		}
	}
	else if(strstr(argv[0], "delSMSPDU")){
		// $1: TTY node, $2: SMS's index.
		if(argc == 3 && argv[1] != NULL && argv[2] != NULL){
			int sms_index = strtod(argv[2], NULL);
			int sms_type;
#ifdef SAVESMS
			char sms_file[PATH_MAX];
#endif

			if((sms_type = getSMSPDUbyIndex(argv[1], sms_index, NULL, 0)) < 0)
				printf("%s: Failed to get the type of index(%d)'s SMS.\n", argv[0], sms_index);
			else if((len = delSMSPDUbyIndex(argv[1], sms_index)) < 0)
				printf("%s: Failed to delSMS.\n", argv[0]);
#ifdef SAVESMS
			else if((len = getSMSFileName(sms_type, sms_index, sms_file, PATH_MAX)) < 0)
				printf("%s: Failed to getSMSFile.\n", argv[0]);
#endif
			else{
#ifdef SAVESMS
				unlink(sms_file);
				if(sms_type == 0){
					if(getSMSFileName(1, sms_index, sms_file, PATH_MAX) > 0)
						unlink(sms_file);
				}
				else if(sms_type == 1){
					if(getSMSFileName(0, sms_index, sms_file, PATH_MAX) > 0)
						unlink(sms_file);
				}
#endif

				printf("%s: done.\n", argv[0]);
			}
		}
	}
	else if(strstr(argv[0], "modSMSdraft")){
		// $1: TTY node, $2: SMS's index, $3: SMSC, $4: Destination, $5: String file.
		if(argc == 6 && argv[1] != NULL && argv[2] != NULL && argv[3] != NULL && argv[4] != NULL && argv[5] != NULL){
			int sms_index = strtod(argv[2], NULL);
			int sms_type;
#ifdef SAVESMS
			char sms_file[PATH_MAX];
#endif

			if((sms_type = getSMSPDUbyIndex(argv[1], sms_index, NULL, 0)) < 0)
				printf("%s: Failed to get the type of index(%d)'s SMS.\n", argv[0], sms_index);
			else if((len = delSMSPDUbyIndex(argv[1], sms_index)) < 0)
				printf("%s: Failed to delSMS.\n", argv[0]);
#ifdef SAVESMS
			else if((len = getSMSFileName(sms_type, sms_index, sms_file, PATH_MAX)) < 0)
				printf("%s: Failed to getSMSFile.\n", argv[0]);
#endif
			else{
#ifdef SAVESMS
				unlink(sms_file);
				if(sms_type == 0){
					if(getSMSFileName(1, sms_index, sms_file, PATH_MAX) > 0)
						unlink(sms_file);
				}
				else if(sms_type == 1){
					if(getSMSFileName(0, sms_index, sms_file, PATH_MAX) > 0)
						unlink(sms_file);
				}
#endif
			}

			if((sms_index = saveSMSPDUtoSIM(argv[1], argv[3], argv[4], argv[5], buf, MAX_BUF_SIZE)) < 0)
				printf("%s: SMS-SUBMIT: Failed to saveSMS.\n", argv[0]);
			else if((len = getSMSPDUbyIndex(argv[1], sms_index, NULL, 0)) < 0)
				printf("%s: SMS-SUBMIT: Failed to getSMS.\n", argv[0]);
			else{
				printf("%s: index=%d.\n", argv[0], sms_index);
				printf("%s: type=%s.\n", argv[0], getSMSTypeStr(len));
				printf("%s: SMS=%s.\n", argv[0], buf);

				printf("%s: done.\n", argv[0]);
			}
		}
	}
	else if(strstr(argv[0], "decomposeSMSPDU")){
		// $1: SMS type, $2: PDU String.
		if(argc == 3 && argv[1] != NULL && argv[2] != NULL){
			char OA[MAX_BUF_SIZE], SCTS[MAX_BUF_SIZE];

			len = decomposeSMSPDU(strtod(argv[1], NULL), argv[2], buf, MAX_BUF_SIZE, OA, MAX_BUF_SIZE, SCTS, MAX_BUF_SIZE);
			printf("%s: data_len=%d\n", argv[0], len);
			printf("%s: data=%s\n", argv[0], buf);
		}
	}
	else if(strstr(argv[0], "composeSMSPDU")){
		// $1: SMS type, $2: String file.
		char smsc[] = "+886932400821";
		char dest[] = "+886955894529";

		if(argc == 3 && argv[1] != NULL && argv[2] != NULL){
			len = composeSMSPDU(strtod(argv[1], NULL), smsc, dest, argv[2], buf, MAX_BUF_SIZE);
			printf("%s: data_len=%d\n", argv[0], len);
			printf("%s: data=%s\n", argv[0], buf);
		}
	}
#ifdef SAVESMS
	else if(strstr(argv[0], "hasNewSMS")){
		len = hasNewSMS(buf, MAX_BUF_SIZE);
		printf("%s: new_sms_num=%d\n", argv[0], len);
		printf("%s: new_sms_index=%s.\n", argv[0], buf);
	}
#endif
	else if(strstr(argv[0], "initial_phonebook")){
		// $1: TTY node.
		if(argc == 2 && argv[1] != NULL){
			len = initial_phonebook(argv[1]);
			printf("%s: ret=%d.\n", argv[0], len);
		}
	}
	else if(strstr(argv[0], "savePhonenum")){
		// $1: TTY node, $2: phone number, $3: name.
		if(argc == 4 && argv[1] != NULL && argv[2] != NULL && argv[3] != NULL){
			int phone_index;

			if((phone_index = savePhonenum(argv[1], argv[2], argv[3])) < 0)
				printf("%s: Failed to savePhonenum.\n", argv[0]);
			else
				printf("%s: done.\n", argv[0]);
		}
	}
	else if(strstr(argv[0], "getPhonenum")){
		// $1: TTY node, $2: Phone's index.
		if(argc == 3 && argv[1] != NULL && argv[2] != NULL){
			int phone_index = strtod(argv[2], NULL);
			char phone[MAX_BUF_SIZE], name[MAX_BUF_SIZE];

			if((len = getPhonenumbyIndex(argv[1], phone_index, phone, MAX_BUF_SIZE, name, MAX_BUF_SIZE)) < 0)
				printf("%s: Failed to getPhonenumbyIndex.\n", argv[0]);
			else{
				printf("%s: phone=%s.\n", argv[0], phone);
				printf("%s: name=%s.\n", argv[0], name);
			}
		}
	}
	else if(strstr(argv[0], "delPhonenum")){
		// $1: TTY node, $2: Phone's index.
		if(argc == 3 && argv[1] != NULL && argv[2] != NULL){
			int phone_index = strtod(argv[2], NULL);

			if((len = delPhonenum(argv[1], phone_index)) < 0)
				printf("%s: Failed to delPhonenum.\n", argv[0]);
			else
				printf("%s: done.\n", argv[0]);
		}
	}
	else if(strstr(argv[0], "modPhonenum")){
		// $1: TTY node, $2: Phone's index, $3: phone number, $4: name.
		if(argc == 5 && argv[1] != NULL && argv[2] != NULL && argv[3] != NULL && argv[4] != NULL){
			int phone_index = strtod(argv[2], NULL);

			if((len = modPhonenum(argv[1], phone_index, argv[3], argv[4])) < 0)
				printf("%s: Failed to modPhonenum.\n", argv[0]);
			else
				printf("%s: done.\n", argv[0]);
		}
	}
	else if(strstr(argv[0], "listPhonenum")){
		// $1: TTY node.
		if(argc == 2 && argv[1] != NULL){
			char phones[MAX_BUF_SIZE], names[MAX_BUF_SIZE];

			len = listPhonenum(argv[1], buf, MAX_BUF_SIZE, phones, MAX_BUF_SIZE, names, MAX_BUF_SIZE);
			printf("%s: index_num=%d.\n", argv[0], len);
			printf("%s: indexs=%s.\n", argv[0], buf);
			printf("%s: phones=%s.\n", argv[0], phones);
			printf("%s: names=%s.\n", argv[0], names);
		}
	}

	return 0;
}
