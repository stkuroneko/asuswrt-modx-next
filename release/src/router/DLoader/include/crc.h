#ifndef _CRC_H_
#define _CRC_H_
 
//////////////////////////////////////////////////////////
//CRC
#define CRC_16_POLYNOMIAL       0x1021
#define CRC_16_L_POLYNOMIAL     0x8408
#define CRC_16_L_SEED           0xFFFF
#define CRC_TAB_SIZE            256             /* 2^CRC_TAB_BITS      */
#define CRC_16_L_OK             0x0
#define HDLC_FLAG               0x7E
#define HDLC_ESCAPE             0x7D
#define HDLC_ESCAPE_MASK        0x20
#define CRC_CHECK_SIZE          0x02


///////////////////////////////////////////////////////////
unsigned int crc_16_l_calc(char* buf_ptr,unsigned int len);

////////////////////////////////////////////////////////////
//return data length after decoding
int decode_msg(char* input_buf, int input_size,  
                char **output_buf, int *output_len, int bcrc);

/////////////////////////////////////////////////////////////
//return data length after coding
int encode_msg(char* input_buf, int input_szie, 
                       char **output_buf, int *output_len, int bcrc);

unsigned short frm_chk(unsigned short *src, int len);

unsigned int crc_32_l_calc(char* buf_ptr,unsigned int len);

#endif //_CRC_H_