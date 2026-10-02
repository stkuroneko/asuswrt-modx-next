#include "libsmspdu.h"


int send_AT(const char *ttynode, const char *at_cmd, int wait_sec, char *out_file, char *ok_str){
	char cmd[MAX_BUF_SIZE], buf[MAX_BUF_SIZE];
	FILE *fp;

	if(ttynode == NULL || at_cmd == NULL || wait_sec <= 0)
		return -1;

	if(out_file == NULL)
		out_file = AT_RET_FILE;
	if(ok_str == NULL)
		ok_str = DEF_AT_OK;
	unlink(out_file);

	snprintf(cmd, MAX_BUF_SIZE, "chat -t %d -e '' '%s' '%s' >> /dev/%s < /dev/%s 2>%s", wait_sec, at_cmd, ok_str, ttynode, ttynode, out_file);
	system(cmd);

	if((fp = fopen(out_file, "r")) != NULL){
		while(fgets(buf, MAX_BUF_SIZE, fp)){
			if(!strncmp(buf, ok_str, strlen(ok_str))){
				fclose(fp);
				return 0;
			}
		}

		fclose(fp);
	}

	return -1;
}

int at_lock(const char *lock_path){
	int fd;
	int n, owner = -1;
	char tmp[16];

	while((fd = open(lock_path, O_CREAT | O_RDWR, 0666)) < 0 || flock(fd, LOCK_EX /*| LOCK_NB*/) < 0){
		if(fd >= 0){
			if(owner < 0){
				if((n = read(fd, tmp, 16-1)) < 0)
					n = 0;
				tmp[n] = '\0';
				owner = strtod(tmp, NULL);
			}
			close(fd);
		}
		printf("# %s wait process(%d): fd(%d) pid(%d)!\n", __func__, owner, fd, getpid());
		sleep(1);
	}
	snprintf(tmp, 16, "%d", getpid());
	write(fd, tmp, 16);

	return fd;
}

void at_unlock(const int lock_fd){
	flock(lock_fd, LOCK_UN);
	close(lock_fd);
}

int f_exists(const char *path){
	struct stat st;

	return (stat(path, &st) == 0) && (!S_ISDIR(st.st_mode));
}

int d_exists(const char *path){
	struct stat st;

	return (stat(path, &st) == 0) && (S_ISDIR(st.st_mode));
}

int mkdir_if_none(const char *path){
	char cmd[PATH_MAX];

	if(!d_exists(path)){
		snprintf(cmd, PATH_MAX, "mkdir -m 0777 -p '%s'", (char *)path);
		system(cmd);
		return 1;
	}

	return 0;
}

FILE *createfile(const char *path){
	struct stat st;
	char cmd[PATH_MAX];

	if(stat(path, &st) == 0){
		snprintf(cmd, PATH_MAX, "rm -rf '%s'", (char *)path);
		system(cmd);
	}

	return fopen(path, "w");
}

int remove_plus(const char *smsc, char *buf, int buf_max){
	int is_plus;
	char *ptr;

	if(smsc[0] == '+'){
		is_plus = 1;
		ptr = (char *)smsc+1;
	}
	else{
		is_plus = 0;
		ptr = (char *)smsc;
	}

	snprintf(buf, buf_max, "%s", ptr);

	return is_plus;
}

int AddF(const char *string, char *buf, int buf_max){
	int slen;
	char *ptr;

	slen = strlen(string);
	if(slen > buf_max-1)
		slen = buf_max-1;

	ptr = (char *)string;
	snprintf(buf, buf_max, "%s%c", ptr, (slen%2)?'F':0x0);
	slen = strlen(buf);

	return slen;
}

int ReadFileBytes(const char *filename, unsigned char *bytes, int bytes_max){
	int fd, n;

	memset(bytes, 0, bytes_max);

	if((fd = open(filename, O_RDONLY))){
		n = read(fd, bytes, bytes_max);

		close(fd);
	}
	else
		n = 0;

	return n;
}

int WriteFileBytes(const char *filename, unsigned char *bytes, int n){
	int fd, w;

	if((fd = open(filename, O_WRONLY))){
		w = write(fd, bytes, n);

		close(fd);
	}
	else
		w = 0;

	return w;
}

void ShowBytes(const unsigned char *bytes, int n){
	unsigned char *ptr;
	int i;

	printf("%d bytes = ", n);
	ptr = (unsigned char *)bytes;
	for(i = 0; i < n; ++i)
		printf("%02X", *(ptr+i));
	printf("\n");
}

int Swap2Bytes(const char *string, unsigned char *buf, int buf_max){
	int slen;
	int i;
	char *ptr, *buf_ptr;

	memset(buf, 0, buf_max);

	slen = strlen(string);
	if(slen > buf_max-1)
		slen = buf_max-1;

	ptr = (char *)string;
	buf_ptr = buf;
	for(i = 0; i < slen; i += 2){
		if(*(ptr+i+1) != '\0')
			*(buf_ptr+i) = *(ptr+i+1);
		else
			*(buf_ptr+i) = 0;
		*(buf_ptr+i+1) = *(ptr+i);
		*(buf_ptr+i+2) = '\0';
	}

	return slen;
}

int Bytes2String(const char *bytes, const int n, unsigned char *str, int str_max){
	unsigned char *ptr, *str_ptr;
	int i, w;

	ptr = (unsigned char *)bytes;
	str_ptr = str;
	for(i = 0, w = 0; i < n; ++i){
		snprintf(str_ptr, str_max-w, "%02X", *(ptr+i));

		str_ptr += 2;
		w += 2;
	}

	return n*2;
}

int String2Bytes(const char *string, char *bytes, int bytes_max){
	int slen;
	int i;
	char *ptr, *bytes_ptr;

	memset(bytes, 0, bytes_max);

	slen = strlen(string);
	if(slen/2 > bytes_max)
		slen = bytes_max*2;

	ptr = (char *)string;
	bytes_ptr = bytes;
	for(i = 0; i < slen; i += 2){
		// output the High byte
		if(*ptr >= '0' && *ptr <= '9')
			*bytes_ptr = (*ptr-'0');
		else if(*ptr >= 'A' && *ptr <= 'F')
			*bytes_ptr = (*ptr-'A'+10);
		else
			*bytes_ptr = (*ptr-'a'+10);
		*bytes_ptr = (*bytes_ptr)<<4;

		++ptr;
		// output the Low byte
		if(*ptr >= '0' && *ptr <= '9')
			*bytes_ptr |= *ptr-'0';
		else if(*ptr >= 'A' && *ptr <= 'F')
			*bytes_ptr |= *ptr-'A'+10;
		else
			*bytes_ptr |= *ptr-'a'+10;

		++ptr;
		++bytes_ptr;
	}
	*bytes_ptr = '\0';

	return slen/2;
}

int gsm2char(const char ch, char *newch, int which_table){
	int table_row = 0;
	char *table;

	if(which_table == 1)
		table = charset;
	else if(which_table == 2)
		table = ext_charset;
	else
		return 0;

	while(table[table_row*2]){
		if(table[table_row*2+1] == ch){
			*newch = table[table_row *2];
			return 1;
		}

		table_row++;
	}

	return 0;
}

int gsm2iso(const char *source, const int size, char *destination, int max){
	int source_count = 0;
	int dest_count = 0;
	char newch;

	if(source == NULL || size <= 0){
		destination[0] = 0;
		return -1;
	}

	// Convert each character untl end of string
	while(source_count < size && dest_count < max){
		if(source[source_count] != 0x1B){
			// search in normal translation table
			if(gsm2char(source[source_count], &newch, 1))
				destination[dest_count++] = newch;
			else if(source[source_count] == 0x24)
				destination[dest_count++] = (char)GSM_CURRENCY_SYMBOL_TO_ISO;
			else{
				printf("Cannot convert GSM character 0x%2X to ISO, you might need to update the 1st translation table.", source[source_count]);
			}
		}
		else if(++source_count < size){
			// search in extended translation table
			if(gsm2char(source[source_count], &newch, 2))
				destination[dest_count++] = newch;
			else{
				printf("Cannot convert extended GSM character 0x1B 0x%2X, you might need to update the 2nd translation table.", source[source_count]);
			}
		}

		source_count++;
	}
	
	// Terminate destination string with 0, however 0x00 are also allowed within the string.
	destination[dest_count] = 0;
	return dest_count;
}

//
// Converts to the buffer. Returns -1 in case of error, >= 0 = length of dest.
//
int iso2utf8(char *ascii, const int userdatalength, const int ascii_max){
	int result = 0;
	int idx;
	unsigned int c;
	char tmp[10];
	int len;
	char buffer[MAX_BUF_SIZE];

	if(userdatalength < 0)
		return -1;

	for(idx = 0; idx < userdatalength; ++idx){
		len = 0;
		c = ascii[idx]&0xFF;
		// Euro character is 20AC in UTF-8, but A4 in ISO-8859-15:
		if(c == 0xA4)
			c = 0x20AC;

		if(c <= 0x7F)
			tmp[len++] = (char)c;
		else if(c <= 0x7FF){
			tmp[len++] = (char)(0xC0|((c>>6)&0x1F));
			tmp[len++] = (char)(0x80|(c&0x3F));
		}
		else if(c <= 0x7FFF){	// or <= 0xFFFF ?
			tmp[len++] = (char)(0xE0|((c>>12)&0x0F));
			tmp[len++] = (char)(0x80|((c>>6)&0x3F));
			tmp[len++] = (char)(0x80|(c&0x3F));
		}

		if(len == 0){
			printf("UTF-8 conversion error with %i. ch 0x%2X %c.", idx+1, c, (char)c);
		}
		else{
			if(result+len < ascii_max-1){
				strncpy(buffer+result, tmp, len);
				result += len;
			}
			else{
				printf("Fatal error (buffer too small) in UTF-8 conversion");
				result = -1;
				break;
			}
		}
	}

	if(result >= 0){
		memcpy(ascii, buffer, result);
		ascii[result] = 0;
	}

	return result;
}

int isXdigit(char ch){
	if((ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'F'))
		return 1;

	return 0;
}

 // converts an octet to a 8-Bit value
int octet2bin(char *octet){
	int result = 0;

	if(octet[0] > 57)
		result += octet[0]-55;
	else
		result += octet[0]-48;

	result = result<<4;
	if(octet[1] > 57)
		result += octet[1]-55;
	else
		result += octet[1]-48;

	return result;
}

// Converts an octet to a 8bit value,
// returns < in case of error.
int octet2bin_check(char *octet){
	if(octet[0] == 0)
		return -1;
	if(octet[1] == 0)
		return -2;
	if(!isXdigit(octet[0]))
		return -3;
	if(!isXdigit(octet[1]))
		return -4;

	return octet2bin(octet);
}

/* converts a PDU-String to text, text might contain zero values! */
/* the first octet is the length */
/* return the length of text, -1 if there is a PDU error, -2 if PDU is too short */
/* with_udh must be set already if the message has an UDH */
/* this function does not detect the existance of UDH automatically. */
int pdu2text(char *pdu, char *text, int *text_length){
	int bitposition;
	int byteposition;
	int byteoffset;
	int charcounter;
	int bitcounter;
	int septets;
	int octets;
	int octetcounter;
	int skip_characters = 0;
	char c;
	char binary = 0;
	int i;

	if((septets = octet2bin_check(pdu)) < 0){
		return (septets >= -2)?-2:-1;
	}

	// Convert from 8-Bit to 7-Bit encapsulated in 8 bit 
	// skipping storing of some characters used by UDH.
	// 3.1beta7: Simplified handling to allow partial decodings to be shown.
	octets = (septets*7+7)/8;     
	bitposition = 0;
	octetcounter = 0;
	for(charcounter = 0; charcounter < septets; charcounter++){
		c = 0;
		for(bitcounter = 0; bitcounter < 7; bitcounter++){
			byteposition = bitposition/8;
			byteoffset = bitposition%8;
			while(byteposition >= octetcounter && octetcounter < octets){
				if((i = octet2bin_check(pdu+(octetcounter<<1)+2)) < 0){
					if(text_length)
						*text_length = charcounter-skip_characters;
					return (i >= -2)?-2:-1;
				}

				binary = i;
				octetcounter++;
			}

			if(binary & (1<<byteoffset))
				c = c | 128;
			bitposition++;
			c = (c>>1)&127; // The shift fills with 1, but 0 is wanted.
		}

		if(charcounter >= skip_characters)
			text[charcounter-skip_characters] = c; 
	}

	if(text_length)
		*text_length = charcounter-skip_characters;

	if(charcounter-skip_characters >= 0)
		text[charcounter-skip_characters] = 0;

	return charcounter-skip_characters;
}

#ifdef SAVESMS
void initial_sms_directory(void){
	mkdir_if_none(SMS_ROOT);
	mkdir_if_none(SMS_UNREAD);
	mkdir_if_none(SMS_READ);
	mkdir_if_none(SMS_UNSENT);
	mkdir_if_none(SMS_SENT);
}
#endif

int initial_smspdu(const char *ttynode){
	int fd;
	int ret;

#ifdef SAVESMS
	initial_sms_directory();
#endif

	fd = at_lock(AT_LOCK_FILE);

	if((ret = send_AT(ttynode, "AT+CMGF=0", 1, NULL, NULL)) < 0){
		printf("%s: Failed to execute \"AT+CMGF=0\"", __func__);

		at_unlock(fd);
		return ret;
	}
	if((ret = send_AT(ttynode, "AT+CPMS=\"SM\",\"SM\"", 1, NULL, NULL)) < 0)
		printf("%s: Failed to execute AT+CPMS=\"SM\",\"SM\"", __func__);

	at_unlock(fd);
	return ret;
}

int listSMSIndex(const char *ttynode, char *sms_indexs, int indexs_max){
	char *ptr, *token;
	int fd;
	int n;
	char tmp[MAX_BUF_SIZE];
	FILE *fp;
	int ret;
	int total;
	char *ok_str = "$CWMSL:";

	fd = at_lock(AT_LOCK_FILE);

	if((ret = send_AT(ttynode, "AT$CWMSL", 1, NULL, NULL)) < 0){
		printf("%s: Failed to execute \"AT$CWMSL\"", __func__);

		at_unlock(fd);
		return ret;
	}

	if((fp = fopen(AT_RET_FILE, "r")) != NULL){
		while(fgets(tmp, MAX_BUF_SIZE, fp)){
			if(!strncmp(tmp, ok_str, strlen(ok_str))){
				ptr = tmp;
				ptr += strlen(ok_str);

				token = strtok(ptr, ",");
				total = strtod(token, NULL);

				if(total > 0){
					ptr += strlen(token)+strlen(",");
					snprintf(sms_indexs, indexs_max, "%s", ptr);
					n = strlen(sms_indexs);
					sms_indexs[n-1] = '\0';
				}

				fclose(fp);
				at_unlock(fd);
				return total;
			}
		}

		fclose(fp);
	}

	at_unlock(fd);
	return -1;
}

int getSMSCHeader(const char *smsc, char *buf, int buf_max){
	char tmp[MAX_BUF_SIZE], tmp_F[MAX_BUF_SIZE], swap[MAX_BUF_SIZE];
	unsigned char type;
	int is_plus;
	int len;

	is_plus = remove_plus(smsc, tmp, MAX_BUF_SIZE);
	if(is_plus)
		type = NUM_TYPE_IN;
	else
		type = NUM_TYPE_NA;

	len = AddF(tmp, tmp_F, MAX_BUF_SIZE);
	len = (len+2)/2;

	Swap2Bytes(tmp_F, swap, MAX_BUF_SIZE);

	snprintf(buf, buf_max, "%02X%02X%s", len, type, swap);

	len = strlen(buf);

	return len;
}

int getDestHeader(const char *dest, char *buf, int buf_max){
	char tmp[MAX_BUF_SIZE], tmp_F[MAX_BUF_SIZE], swap[MAX_BUF_SIZE];
	unsigned char type;
	int is_plus;
	int len;

	is_plus = remove_plus(dest, tmp, MAX_BUF_SIZE);
	if(is_plus)
		type = NUM_TYPE_IN;
	else
		type = NUM_TYPE_NA;
	len = strlen(tmp);

	AddF(tmp, tmp_F, MAX_BUF_SIZE);

	Swap2Bytes(tmp_F, swap, MAX_BUF_SIZE);

	snprintf(buf, buf_max, "%02X%02X%s", len, type, swap);

	len = strlen(buf);

	return len;
}

int EncodeStr8(const char *STR_FILE, char *buf, int buf_max){
	unsigned char bytes[MAX_BUF_SIZE];
	int n;

	n = ReadFileBytes(STR_FILE, bytes, MAX_BUF_SIZE);

	Bytes2String(bytes, n, buf, buf_max);

	return n;
}

int EncodeStr16(const char *fromcode, const char *tocode, const char *STR_FILE, unsigned char *buf, int buf_max){
	int fd;
	char tmpfile[] = "/tmp/SMS_encode_XXXXXX";
	char cmd[MAX_BUF_SIZE];
	unsigned char bytes[MAX_BUF_SIZE];
	int n;

	fd = mkstemp(tmpfile);
	close(fd);

	snprintf(cmd, MAX_BUF_SIZE, "/usr/bin/iconv -f %s -t %s %s > %s", fromcode, tocode, STR_FILE, tmpfile);
	system(cmd);

	n = ReadFileBytes(tmpfile, bytes, MAX_BUF_SIZE);

	Bytes2String(bytes, n, buf, buf_max);

	unlink(tmpfile);

	return n;
}

int DecodeStr7(const char *pdu_str, char *buf, int buf_max){
	int len_pdu_str, len_7bit, len_str;
	int i;
	char buffer[MAX_BUF_SIZE];
	char buffer2[MAX_BUF_SIZE];
	int padding = '\r';

	len_pdu_str = strlen(pdu_str);
	if(len_pdu_str%2){
		printf("%s: The string's lenght is not even", __func__);
		return -1;
	}

	snprintf(buffer, MAX_BUF_SIZE, "%s", pdu_str);
	for(i = 0; buffer[i]; ++i)
		buffer[i] = toupper((int)buffer[i]);

	len_7bit = len_pdu_str/2*8/7;
	snprintf(buffer2, MAX_BUF_SIZE, "%02X%s", len_7bit, buffer);

	printf("len_7bit: %i (0x%02X)\n", len_7bit, len_7bit);
	printf("len_7bit %% 8: %i\n", len_7bit%8);
	printf("orig %s\n", buffer2);

	memset(buffer, 0, MAX_BUF_SIZE);
	pdu2text(buffer2, buffer, &len_str);

	if((len_7bit%8 == 0 && len_str && buffer[len_str-1] == padding)
			|| (len_7bit%8 == 1 && len_str > 1 && buffer[len_str-1] == padding && buffer[len_str-2] == padding)
			){
		len_str--;
		printf("removing padding, characters: %i\n", len_str);
	}

	i = gsm2iso(buffer, len_str, buffer2, MAX_BUF_SIZE);
	i = iso2utf8(buffer2, i, MAX_BUF_SIZE);
	snprintf(buf, buf_max, "%s", buffer2);

	return i;
}

int DecodeStr8(const char *pdu_str, char *buf, int buf_max){
	snprintf(buf, buf_max, "%s", pdu_str);

	return strlen(pdu_str);
}

int DecodeStr16(const char *fromcode, const char *tocode, const char *pdu_str, unsigned char *buf, int buf_max){
	int fd;
	char tmpfile1[] = "/tmp/SMS_pdu_XXXXXX", tmpfile2[] = "/tmp/SMS_tran_XXXXXX";
	char cmd[MAX_BUF_SIZE], bytes[MAX_BUF_SIZE];
	int n;

	n = String2Bytes(pdu_str, bytes, MAX_BUF_SIZE);

	fd = mkstemp(tmpfile1);
	close(fd);

	WriteFileBytes(tmpfile1, bytes, n);

	fd = mkstemp(tmpfile2);
	close(fd);

	snprintf(cmd, MAX_BUF_SIZE, "/usr/bin/iconv -f %s -t %s %s > %s", fromcode, tocode, tmpfile1, tmpfile2);
	system(cmd);

	n = ReadFileBytes(tmpfile2, buf, buf_max);

	unlink(tmpfile1);
	unlink(tmpfile2);

	return n;
}

int composeSMSPDU(const int sms_type, const char *smsc, const char *dest, const char *STR_FILE, unsigned char *buf, int buf_max){
	char *ptr;
	int smsc_len, len;
	unsigned char buf_str[MAX_BUF_SIZE], swap[MAX_BUF_SIZE];
	int n;

	if(sms_type < 0 || sms_type > 3){
		printf("%s: SMS type is inputed incorrectly.\n", __func__);
		return -1;
	}

	ptr = (char *)buf;
	if((smsc_len = getSMSCHeader(smsc, ptr, buf_max)) <= 0){
		printf("Fail to get the SMSC header.\n");
		return smsc_len;
	}

	if(sms_type == 2 || sms_type == 3){
		// first octet & MR
		len = smsc_len;
		ptr = (char *)(buf+len);
		strncpy(ptr, "1100", buf_max-len);
		len += 4;
	}
	else{
		// first octet
		len = smsc_len;
		ptr = (char *)(buf+len);
		strncpy(ptr, "04", buf_max-len);
		len += 2;
	}

	// add the Destination
	ptr = (char *)(buf+len);
	len += getDestHeader(dest, ptr, buf_max-len);

	// add the PID
	ptr = (char *)(buf+len);
	strncpy(ptr, "00", buf_max-len);
	len += 2;

	// add the DCS
	ptr = (char *)(buf+len);
	strncpy(ptr, "08", buf_max-len);
	len += 2;

	if(sms_type == 2 || sms_type == 3){
		// add the VP
		ptr = (char *)(buf+len);
		strncpy(ptr, "A7", buf_max-len);
		len += 2;
	}
	else{
		// add the SCTS
		// add the year
		Swap2Bytes("16", swap, MAX_BUF_SIZE);
		ptr = (char *)(buf+len);
		strncpy(ptr, swap, buf_max-len);
		len += 2;
		// add the month
		Swap2Bytes("03", swap, MAX_BUF_SIZE);
		ptr = (char *)(buf+len);
		strncpy(ptr, swap, buf_max-len);
		len += 2;
		// add the day
		Swap2Bytes("17", swap, MAX_BUF_SIZE);
		ptr = (char *)(buf+len);
		strncpy(ptr, swap, buf_max-len);
		len += 2;
		// add the hour
		Swap2Bytes("14", swap, MAX_BUF_SIZE);
		ptr = (char *)(buf+len);
		strncpy(ptr, swap, buf_max-len);
		len += 2;
		// add the min
		Swap2Bytes("39", swap, MAX_BUF_SIZE);
		ptr = (char *)(buf+len);
		strncpy(ptr, swap, buf_max-len);
		len += 2;
		// add the sec
		Swap2Bytes("33", swap, MAX_BUF_SIZE);
		ptr = (char *)(buf+len);
		strncpy(ptr, swap, buf_max-len);
		len += 2;
		// add the zone
		Swap2Bytes("32", swap, MAX_BUF_SIZE);	// +08:00 = 8+24
		ptr = (char *)(buf+len);
		strncpy(ptr, swap, buf_max-len);
		len += 2;
	}

	// add the Data
	n = EncodeStr16("utf-8", "ucs-2", STR_FILE, buf_str, MAX_BUF_SIZE);

	ptr = (char *)(buf+len);
	sprintf(ptr, "%02X%s", n, buf_str);
	len += 2+n*2;

	len = (len-smsc_len)/2;

	return len;
}

int decomposeSMSPDU(const int sms_type, const unsigned char *pdu,
		unsigned char *data, int data_max,
		unsigned char *OA, int OA_max,
		unsigned char *SCTS, int SCTS_max){
	unsigned char buf[MAX_BUF_SIZE], swap[MAX_BUF_SIZE], *ptr;
	int smsc_len, smsc_type;
	char SMSC[32];
	char first_octet, MTI, MMS, LP, SRI, UDHI, RP;
	int oa_len, oa_type;
	int PID, DCS;
	int year, month, day, hour, min, sec, zone;
	int ud_len;
	int data_len;
	char RD, VPF, MR;
	int VP;

	if(sms_type < 0 || sms_type > 3){
		printf("%s: SMS type is inputed incorrectly.\n", __func__);
		return -1;
	}

	ptr = (unsigned char *)pdu;

	// len of SMSC's address
	snprintf(buf, 3, "%s", ptr);
	ptr += 2;
	smsc_len = strtol(buf, NULL, 16)*2;

	// type of SMSC's address
	smsc_type = (!strncmp(ptr, "91", 2))?NUM_TYPE_IN:NUM_TYPE_NA;
	ptr += 2;

	// address of SMSC
	snprintf(buf, smsc_len-2+1, "%s", ptr);
	ptr += smsc_len-2;
	Swap2Bytes(buf, swap, MAX_BUF_SIZE);
	snprintf(SMSC, 32, "%s%s", ((smsc_type == NUM_TYPE_IN)?"+":""), swap);
printf("SMSC: %s\n", SMSC);

	snprintf(buf, 3, "%s", ptr);
	ptr += 2;
	// Send
	// TP-RP   TP-UDHI TP-SRR  TP-VPF  TP-VPF  TP-RD   TP-MTI  TP-MTI
	first_octet = (char)strtod(buf, NULL);
	MTI = first_octet&3;
	SRI = (first_octet&32)>>5;
	UDHI = (first_octet&64)>>6;
	RP = (first_octet&128)>>7;
	if(sms_type == 2 || sms_type == 3){
		RD = (first_octet&4)>>2;
		VPF = (first_octet&24)>>3;
printf("SUBMIT: MTI=%x, RD=%x, VPF=%x, SRR=%x, UDHI=%x, RP=%x.\n", MTI, RD, VPF, SRI, UDHI, RP);
	}
	else{
		// Receive
		// TP-RP   TP-UDHI TP-SRI  TP-LP   TP-LP   TP-MMS  TP-MTI  TP-MTI
		MMS = (first_octet&4)>>2;
		LP = (first_octet&24)>>3;
printf("DELIVER: MTI=%x, MMS=%x, LP=%x, SRI=%x, UDHI=%x, RP=%x.\n", MTI, MMS, LP, SRI, UDHI, RP);
	}

	if(sms_type == 2 || sms_type == 3){
		// MR
		snprintf(buf, 3, "%s", ptr);
		ptr += 2;
		MR = strtol(buf, NULL, 16);
printf("SUBMIT: MR=%x.\n", MR);
	}

	// len of OA's address
	snprintf(buf, 3, "%s", ptr);
	ptr += 2;
	oa_len = strtol(buf, NULL, 16);

	// type of OA's address
	oa_type = (!strncmp(ptr, "91", 2))?NUM_TYPE_IN:NUM_TYPE_NA;
	ptr += 2;

	// address of OA
	snprintf(buf, oa_len+1, "%s", ptr);
	ptr += oa_len;
	Swap2Bytes(buf, swap, MAX_BUF_SIZE);
	if(OA != NULL && OA_max > 0)
		snprintf(OA, OA_max, "%s%s", ((oa_type == NUM_TYPE_IN)?"+":""), swap);
printf("OA: %s%s\n", ((oa_type == NUM_TYPE_IN)?"+":""), swap);

	// PID
	snprintf(buf, 3, "%s", ptr);
	ptr += 2;
	PID = strtol(buf, NULL, 16);
printf("PID: %x\n", PID);

	// DCS
	snprintf(buf, 3, "%s", ptr);
	ptr += 2;
	DCS = strtol(buf, NULL, 16);
printf("DCS: %d\n", DCS);

	if(sms_type == 2 || sms_type == 3){
		// VP
		snprintf(buf, 3, "%s", ptr);
		ptr += 2;
		VP = strtol(buf, NULL, 16);
printf("SUBMIT: VP=%d.\n", VP);
	}
	else{
		// SCTS
		snprintf(buf, 3, "%s", ptr);
		ptr += 2;
		Swap2Bytes(buf, swap, MAX_BUF_SIZE);
		year = strtod(swap, NULL);

		snprintf(buf, 3, "%s", ptr);
		ptr += 2;
		Swap2Bytes(buf, swap, MAX_BUF_SIZE);
		month = strtod(swap, NULL);

		snprintf(buf, 3, "%s", ptr);
		ptr += 2;
		Swap2Bytes(buf, swap, MAX_BUF_SIZE);
		day = strtod(swap, NULL);

		snprintf(buf, 3, "%s", ptr);
		ptr += 2;
		Swap2Bytes(buf, swap, MAX_BUF_SIZE);
		hour = strtod(swap, NULL);

		snprintf(buf, 3, "%s", ptr);
		ptr += 2;
		Swap2Bytes(buf, swap, MAX_BUF_SIZE);
		min = strtod(swap, NULL);

		snprintf(buf, 3, "%s", ptr);
		ptr += 2;
		Swap2Bytes(buf, swap, MAX_BUF_SIZE);
		sec = strtod(swap, NULL);

		snprintf(buf, 3, "%s", ptr);
		ptr += 2;
		Swap2Bytes(buf, swap, MAX_BUF_SIZE);
		zone = strtod(swap, NULL)-24;

		if(SCTS != NULL && SCTS_max > 0)
			snprintf(SCTS, SCTS_max, "20%02d/%02d/%02d %02d:%02d:%02d %s%02d:00", year, month, day, hour, min, sec, (zone > 0)?"+":"", zone);
printf("DELIVER: SCTS=20%02d/%02d/%02d %02d:%02d:%02d %s%02d:00\n", year, month, day, hour, min, sec, (zone > 0)?"+":"", zone);
	}

	// UDL
	snprintf(buf, 3, "%s", ptr);
	ptr += 2;
	ud_len = strtol(buf, NULL, 16);
printf("UD len: %d\n", ud_len);

	// UD
	ptr[ud_len*2] = '\0';
	switch(DCS){
		case GSM_UCS2:
			data_len = DecodeStr16("ucs-2", "utf-8", ptr, data, data_max);
			break;
		case GSM_8BIT:
			data_len = DecodeStr8(ptr, data, data_max);
			break;
		default:
			data_len = DecodeStr7(ptr, data, data_max);
			break;
	}

	return data_len;
}

char *getSMSTypeStr(int sms_type){
	if(sms_type == 0)
		return "unread";
	else if(sms_type == 1)
		return "read";
	else if(sms_type == 2)
		return "unsent";
	else if(sms_type == 3)
		return "sent";
	else
		return "all";
}

#ifdef SAVESMS
int getSMSFileName(const int sms_type, const int sms_index, char *sms_file, int name_max){
	if(sms_type < 0 || sms_type > 3)
		return -1;

	if(sms_index >= 0)
		snprintf(sms_file, name_max, "%s/%s/%d", SMS_ROOT, getSMSTypeStr(sms_type), sms_index);
	else
		snprintf(sms_file, name_max, "%s/%s/all", SMS_ROOT, getSMSTypeStr(sms_type));

	return strlen(sms_file);
}

int hasNewSMS(char *sms_indexs, int buf_max){
	DIR *dir;
	struct dirent *dent;
	char *ptr;
	int len, tmp;
	int index_num;

	if((dir = opendir(SMS_UNREAD)) == NULL)
		return -1;

	memset(sms_indexs, 0, buf_max);

	index_num = 0;
	ptr = sms_indexs;
	len = 0;
	while((dent = readdir(dir)) != NULL){
		if(!strcmp(dent->d_name, ".") || !strcmp(dent->d_name, ".."))
			continue;

		if(index_num){
			tmp = 1;
			if(buf_max <= len+tmp){
				closedir(dir);

				return index_num;
			}

			strncpy(ptr, ",", 1);
			++ptr;
			++len;
		}

		tmp = strlen(dent->d_name);
		if(buf_max <= len+tmp){
			closedir(dir);

			return index_num;
		}

		snprintf(ptr, tmp+1, "%s", dent->d_name);
		ptr += tmp;
		len += tmp;

		++index_num;
	}
	closedir(dir);

	return index_num;
}
#endif

int getSMSPDUbyType(const char *ttynode, const int sms_type, char *sms_indexs, int indexs_max){
	// 0: "REC UNREAD", 1: "REC READ", 2: "STO UNSENT", 3: "STO SENT", 4: "ALL".
	char send_at[MAX_BUF_SIZE], *ptr;
	int fd;
	int n;
	char tmp[MAX_BUF_SIZE];
	FILE *fp;
	int ret;
	int sms_index;
#ifdef SAVESMS
	FILE *sms_fp;
	char sms_file[PATH_MAX];
	char buf[PATH_MAX];
	char index_buf2[MAX_BUF_SIZE];
#endif
	char *ok_str = "+CMGL: ";
	int indexs_len;
	char index_buf[MAX_BUF_SIZE], *index_ptr;
	int index_num;

	if(sms_type == 4){
		for(n = 0; n < 4; ++n)
			getSMSPDUbyType(ttynode, n, NULL, 0);

		return 0;
	}

	fd = at_lock(AT_LOCK_FILE);

	snprintf(send_at, MAX_BUF_SIZE, "AT+CMGL=%d", sms_type);
	if((ret = send_AT(ttynode, send_at, 1, AT_RET_FILE, NULL)) < 0){
		printf("%s: Failed to execute \"%s\"", __func__, send_at);

		at_unlock(fd);
		return ret;
	}

	if((fp = fopen(AT_RET_FILE, "r")) != NULL){
		if(sms_indexs != NULL && indexs_max > 0)
			memset(sms_indexs, 0, indexs_max);
		memset(index_buf, 0, MAX_BUF_SIZE);

		index_num = 0;
		index_ptr = index_buf;
		indexs_len = 0;
		while(fgets(tmp, MAX_BUF_SIZE, fp)){
			if(!strncmp(tmp, ok_str, strlen(ok_str))){
				ptr = tmp;
				ptr += strlen(ok_str);

				sms_index = strtod(ptr, NULL);
				ptr += 2;

#ifdef SAVESMS
				if(getSMSFileName(sms_type, sms_index, sms_file, PATH_MAX) > 0
						&& !f_exists(sms_file)
						&& (sms_fp = createfile(sms_file)) != NULL){
					snprintf(buf, PATH_MAX, "AT+CMGR=%d\n\n\n", sms_index);
					fputs(buf, sms_fp);

					snprintf(buf, PATH_MAX, "+CMGR: %s\n", ptr);
					fputs(buf, sms_fp);

					for(n = 0; n < 2; ++n)
						fgets(tmp, MAX_BUF_SIZE, fp);
					snprintf(buf, PATH_MAX, "%s\n\n\nOK\n", tmp);
					fputs(buf, sms_fp);				

					fclose(sms_fp);
				}
#endif

				if(sms_indexs != NULL && indexs_max > 0){
					if(index_num){
						strncpy(index_ptr, ",", 1);
						++index_ptr;
						++indexs_len;
					}

					snprintf(index_ptr, MAX_BUF_SIZE-indexs_len+1, "%d", sms_index);
					indexs_len = strlen(index_buf);
					index_ptr = index_buf+indexs_len;
				}

				++index_num;
			}
		}

		fclose(fp);
	}

#ifdef SAVESMS
	if(sms_type == 0){
		if((index_num = hasNewSMS(index_buf2, MAX_BUF_SIZE)) > 0){
			printf("hasNewSMS: %d, %s.\n", index_num, index_buf2);
		}
	}
#endif

	at_unlock(fd);

	if(sms_indexs != NULL && indexs_max > 0){
		if(indexs_len+1 <= indexs_max){
			snprintf(sms_indexs, indexs_len+1, "%s", index_buf);
			//return indexs_len;
		}
		else{
			snprintf(sms_indexs, indexs_max, "%s", index_buf);
			//return indexs_max-1;
		}
	}

	return index_num;
}

int getSMSPDUbyIndex(const char *ttynode, const int sms_index, unsigned char *pdu, int pdu_max){
	char send_at[MAX_BUF_SIZE], *ptr;
	int fd;
	int n;
	char tmp[MAX_BUF_SIZE];
	FILE *fp;
	int ret;
	int sms_type;
#ifdef SAVESMS
	char sms_file[PATH_MAX];
#endif
	char *ok_str = "+CMGR: ";

	fd = at_lock(AT_LOCK_FILE);

	snprintf(send_at, MAX_BUF_SIZE, "AT+CMGR=%d", sms_index);
	if((ret = send_AT(ttynode, send_at, 10, AT_RET_FILE, NULL)) < 0){
		printf("%s: Failed to execute \"%s\"", __func__, send_at);

		at_unlock(fd);
		return ret;
	}

	if((fp = fopen(AT_RET_FILE, "r")) != NULL){
		while(fgets(tmp, MAX_BUF_SIZE, fp)){
			if(!strncmp(tmp, ok_str, strlen(ok_str))){
				ptr = tmp;
				ptr += strlen(ok_str);

				sms_type = strtod(ptr, NULL);

#ifdef SAVESMS
				if(getSMSFileName(sms_type, sms_index, sms_file, PATH_MAX) > 0
						&& !f_exists(sms_file))
					rename(AT_RET_FILE, sms_file);
#endif

				if(pdu != NULL && pdu_max > 0){
					for(n = 0; n < 2; ++n)
						fgets(tmp, MAX_BUF_SIZE, fp);

					snprintf(pdu, pdu_max, "%s", tmp);
				}

				fclose(fp);
				at_unlock(fd);
				return sms_type;
			}
		}

		fclose(fp);
	}

	at_unlock(fd);
	return -1;
}

int getallSMSPDU(const char *ttynode){
	int ret = getSMSPDUbyType(ttynode, 4, NULL, 0);

	return ret;
}

int saveSMSPDUtoSIM(const char *ttynode, const char *smsc, const char *dest, const char *STR_FILE, unsigned char *buf, int buf_max){
	int len;
	char send_at[MAX_BUF_SIZE], *ptr;
	int fd;
	char tmp[MAX_BUF_SIZE];
	FILE *fp;
	int ret;
	int sms_index;
	char *ok_str = "+CMGW: ";

	if((len = composeSMSPDU(2, smsc, dest, STR_FILE, buf, buf_max)) < 0){
		printf("%s: Failed to composeSMSPDU: %s.\n", __func__, STR_FILE);
		return len;
	}

	fd = at_lock(AT_LOCK_FILE);

	snprintf(send_at, MAX_BUF_SIZE, "AT+CMGW=%d", len);
	if((ret = send_AT(ttynode, send_at, 1, AT_RET_FILE, ">")) < 0){
		printf("%s: Failed to execute \"%s\"", __func__, send_at);

		at_unlock(fd);
		return ret;
	}
	snprintf(send_at, MAX_BUF_SIZE, "%s^z", buf);
	if((ret = send_AT(ttynode, send_at, 10, AT_RET_FILE, NULL)) < 0){
		printf("%s: Failed to execute \"%s\"", __func__, send_at);

		at_unlock(fd);
		return ret;
	}

	if((fp = fopen(AT_RET_FILE, "r")) != NULL){
		while(fgets(tmp, MAX_BUF_SIZE, fp)){
			if(!strncmp(tmp, ok_str, strlen(ok_str))){
				ptr = tmp;
				ptr += strlen(ok_str);

				sms_index = strtod(ptr, NULL);

				unlink(STR_FILE);
				fclose(fp);
				at_unlock(fd);
				return sms_index;
			}
		}

		fclose(fp);
	}

	at_unlock(fd);
	return -1;
}

int sendSMSPDUfromSIM(const char *ttynode, const int sms_index){
	char send_at[MAX_BUF_SIZE];
	int fd;
	int ret;

	fd = at_lock(AT_LOCK_FILE);

	snprintf(send_at, MAX_BUF_SIZE, "AT+CMSS=%d", sms_index);
	if((ret = send_AT(ttynode, send_at, 10, AT_RET_FILE, NULL)) < 0)
		printf("%s: Failed to execute \"%s\"", __func__, send_at);

	at_unlock(fd);
	return ret;
}

int sendSMSPDU(const char *ttynode, const char *smsc, const char *dest, const char *STR_FILE, unsigned char *buf, int buf_max){
	int len;
	char send_at[MAX_BUF_SIZE];
	int fd;
	int ret;

	if((len = composeSMSPDU(2, smsc, dest, STR_FILE, buf, buf_max)) < 0){
		printf("%s: Failed to composeSMSPDU: %s.\n", __func__, STR_FILE);
		return len;
	}
	unlink(STR_FILE);

	fd = at_lock(AT_LOCK_FILE);

	snprintf(send_at, MAX_BUF_SIZE, "AT+CMGS=%d", len);
	if((ret = send_AT(ttynode, send_at, 1, AT_RET_FILE, ">")) < 0){
		printf("%s: Failed to execute \"%s\"", __func__, send_at);

		at_unlock(fd);
		return ret;
	}
	snprintf(send_at, MAX_BUF_SIZE, "%s^z", buf);
	if((ret = send_AT(ttynode, send_at, 10, AT_RET_FILE, NULL)) < 0)
		printf("%s: Failed to execute \"%s\"", __func__, send_at);

	at_unlock(fd);
	return ret;
}

int delSMSPDUbyIndex(const char *ttynode, const int sms_index){
	char send_at[MAX_BUF_SIZE];
	int fd;
	int ret;

	fd = at_lock(AT_LOCK_FILE);

	snprintf(send_at, MAX_BUF_SIZE, "AT+CMGD=%d", sms_index);
	if((ret = send_AT(ttynode, send_at, 1, AT_RET_FILE, NULL)) < 0)
		printf("%s: Failed to execute \"%s\"", __func__, send_at);

	at_unlock(fd);
	return ret;
}

int initial_phonebook(const char *ttynode){
	int fd;
	int ret;

	fd = at_lock(AT_LOCK_FILE);

	if((ret = send_AT(ttynode, "AT+CPBS=\"SM\"", 1, NULL, NULL)) < 0)
		printf("%s: Failed to execute AT+CPBS=\"SM\"", __func__);

	at_unlock(fd);
	return ret;
}

int savePhonenum(const char *ttynode, const char *phone, const char *name){
	int fd;
	char tmp[MAX_BUF_SIZE];
	int type;
	int ret = 0;

	fd = at_lock(AT_LOCK_FILE);

	if(phone[0] == '+')
		type = 145;
	else
		type = 129;

	snprintf(tmp, MAX_BUF_SIZE, "AT+CPBW=,\"%s\",%d,\"%s\"", phone, type, name);
	if((ret = send_AT(ttynode, tmp, 1, NULL, NULL)) < 0)
		printf("%s: Failed to execute %s", __func__, tmp);

	at_unlock(fd);
	return ret;
}

int getPhonenumbyIndex(const char *ttynode, const int index, char *phone, int phone_max, char *name, int name_max){
	char *ptr, *token;
	int fd, n;
	char tmp[MAX_BUF_SIZE];
	FILE *fp;
	int ret = 0;
	char *ok_str = "+CPBR: ";

	fd = at_lock(AT_LOCK_FILE);

	snprintf(tmp, MAX_BUF_SIZE, "AT+CPBR=%d", index);
	if((ret = send_AT(ttynode, tmp, 1, NULL, NULL)) < 0){
		printf("%s: Failed to execute %s", __func__, tmp);

		at_unlock(fd);
		return ret;
	}

	if((fp = fopen(AT_RET_FILE, "r")) != NULL){
		while(fgets(tmp, MAX_BUF_SIZE, fp)){
			if(!strncmp(tmp, ok_str, strlen(ok_str))){
				ptr = tmp;
				ptr += strlen(ok_str);

				token = strtok(ptr, ",");
				token = strtok(NULL, ",");
				snprintf(phone, phone_max, "%s", token+1);
				n = strlen(phone);
				phone[n-1] = '\0';
				token = strtok(NULL, ",");
				token = strtok(NULL, ",");
				snprintf(name, name_max, "%s", token+1);
				n = strlen(name);
				name[n-1] = '\0';
			}
		}

		fclose(fp);
	}

	at_unlock(fd);
	return ret;
}

int delPhonenum(const char *ttynode, const int index){
	int fd;
	char tmp[MAX_BUF_SIZE];
	int ret = 0;

	fd = at_lock(AT_LOCK_FILE);

	snprintf(tmp, MAX_BUF_SIZE, "AT+CPBW=%d", index);
	if((ret = send_AT(ttynode, tmp, 1, NULL, NULL)) < 0)
		printf("%s: Failed to execute %s", __func__, tmp);

	at_unlock(fd);
	return ret;
}

int modPhonenum(const char *ttynode, const int index, const char *phone, const char *name){
	int fd;
	char tmp[MAX_BUF_SIZE];
	int type;
	int ret = 0;

	fd = at_lock(AT_LOCK_FILE);

	if(phone[0] == '+')
		type = 145;
	else
		type = 129;

	snprintf(tmp, MAX_BUF_SIZE, "AT+CPBW=%d,\"%s\",%d,\"%s\"", index, phone, type, name);
	if((ret = send_AT(ttynode, tmp, 1, NULL, NULL)) < 0)
		printf("%s: Failed to execute %s", __func__, tmp);

	at_unlock(fd);
	return ret;
}

int listPhonenum(const char *ttynode, char *phone_indexs, int indexs_max, char *phones, int phones_max, char *names, int names_max){
	char *ptr, *token;
	int fd;
	int n;
	char tmp[MAX_BUF_SIZE];
	FILE *fp;
	int ret;
	int total, max;
	int indexs_len, phone_index;
	char index_buf[MAX_BUF_SIZE], *index_ptr;
	int index_num;
	int phones_len;
	char phone[MAX_BUF_SIZE], phone_buf[MAX_BUF_SIZE], *phone_ptr;
	int names_len;
	char name[MAX_BUF_SIZE], name_buf[MAX_BUF_SIZE], *name_ptr;
	char *ok_str = "+CPBS: ";

	fd = at_lock(AT_LOCK_FILE);

	if((ret = send_AT(ttynode, "AT+CPBS?", 1, NULL, NULL)) < 0){
		printf("%s: Failed to execute \"AT+CPBS?\"", __func__);

		at_unlock(fd);
		return ret;
	}

	total = max = 0;
	if((fp = fopen(AT_RET_FILE, "r")) != NULL){
		while(fgets(tmp, MAX_BUF_SIZE, fp)){
			if(!strncmp(tmp, ok_str, strlen(ok_str))){
				ptr = tmp;
				ptr += strlen(ok_str);

				token = strtok(ptr, ",");
				token = strtok(NULL, ",");
				total = strtod(token, NULL);
				token = strtok(NULL, ",");
				max = strtod(token, NULL);

				break;
			}
		}

		fclose(fp);
	}

	if(phone_indexs != NULL && indexs_max > 0)
		memset(phone_indexs, 0, indexs_max);
	if(phones != NULL && phones_max > 0)
		memset(phones, 0, phones_max);
	if(names != NULL && names_max > 0)
		memset(names, 0, names_max);

	if(total < 0 || max <= 0){
		printf("%s: total or max number of phonebook are too small.\n", __func__);

		at_unlock(fd);
		return -1;
	}
	else if(total == 0){
		at_unlock(fd);
		return total;
	}

	snprintf(tmp, MAX_BUF_SIZE, "AT+CPBR=1,%d", max);
	if((ret = send_AT(ttynode, tmp, 2, NULL, NULL)) < 0){
		printf("%s: Failed to execute \"%s\"", __func__, tmp);

		at_unlock(fd);
		return ret;
	}

	ok_str = "+CPBR: ";
	if((fp = fopen(AT_RET_FILE, "r")) != NULL){
		memset(index_buf, 0, MAX_BUF_SIZE);
		memset(phone_buf, 0, MAX_BUF_SIZE);
		memset(name_buf, 0, MAX_BUF_SIZE);

		index_num = 0;
		index_ptr = index_buf;
		phone_ptr = phone_buf;
		name_ptr = name_buf;
		indexs_len = 0;
		phones_len = 0;
		names_len = 0;
		while(fgets(tmp, MAX_BUF_SIZE, fp)){
			if(!strncmp(tmp, ok_str, strlen(ok_str))){
				ptr = tmp;
				ptr += strlen(ok_str);

				token = strtok(ptr, ",");
				phone_index = strtod(token, NULL);
				token = strtok(NULL, ",");
				snprintf(phone, MAX_BUF_SIZE, "%s", token+1);
				n = strlen(phone);
				phone[n-1] = '\0';
				token = strtok(NULL, ",");
				token = strtok(NULL, ",");
				snprintf(name, MAX_BUF_SIZE, "%s", token+1);
				n = strlen(name);
				name[n-1] = '\0';

				if(phone_indexs != NULL && indexs_max > 0){
					if(index_num){
						strncpy(index_ptr, ",", 1);
						++index_ptr;
						++indexs_len;
					}

					snprintf(index_ptr, MAX_BUF_SIZE-indexs_len+1, "%d", phone_index);
					indexs_len = strlen(index_buf);
					index_ptr = index_buf+indexs_len;
				}

				if(phones != NULL && phones_max > 0){
					if(index_num){
						strncpy(phone_ptr, ",", 1);
						++phone_ptr;
						++phones_len;
					}

					snprintf(phone_ptr, MAX_BUF_SIZE-phones_len+1, "%s", phone);
					phones_len = strlen(phone_buf);
					phone_ptr = phone_buf+phones_len;
				}

				if(names != NULL && names_max > 0){
					if(index_num){
						strncpy(name_ptr, ",", 1);
						++name_ptr;
						++names_len;
					}

					snprintf(name_ptr, MAX_BUF_SIZE-names_len+1, "%s", name);
					names_len = strlen(name_buf);
					name_ptr = name_buf+names_len;
				}

				++index_num;
			}
		}

		fclose(fp);
	}

	if(phone_indexs != NULL && indexs_max > 0){
		if(indexs_len+1 <= indexs_max){
			snprintf(phone_indexs, indexs_len+1, "%s", index_buf);
			//return indexs_len;
		}
		else{
			snprintf(phone_indexs, indexs_max, "%s", index_buf);
			//return buf_max-1;
		}
	}

	if(phones != NULL && phones_max > 0){
		if(phones_len+1 <= phones_max){
			snprintf(phones, phones_len+1, "%s", phone_buf);
			//return phones_len;
		}
		else{
			snprintf(phones, phones_max, "%s", phone_buf);
			//return buf_max-1;
		}
	}

	if(names != NULL && names_max > 0){
		if(names_len+1 <= names_max){
			snprintf(names, names_len+1, "%s", name_buf);
			//return names_len;
		}
		else{
			snprintf(names, names_max, "%s", name_buf);
			//return buf_max-1;
		}
	}

	at_unlock(fd);
	return index_num;
}
