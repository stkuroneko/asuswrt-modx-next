#include <stdlib.h>
#include "crc.h"
#include <memory.h>
//#include "global.h"

const unsigned int  crc_16_l_table[ CRC_TAB_SIZE ] = {
  0x0000, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf,
  0x8c48, 0x9dc1, 0xaf5a, 0xbed3, 0xca6c, 0xdbe5, 0xe97e, 0xf8f7,
  0x1081, 0x0108, 0x3393, 0x221a, 0x56a5, 0x472c, 0x75b7, 0x643e,
  0x9cc9, 0x8d40, 0xbfdb, 0xae52, 0xdaed, 0xcb64, 0xf9ff, 0xe876,
  0x2102, 0x308b, 0x0210, 0x1399, 0x6726, 0x76af, 0x4434, 0x55bd,
  0xad4a, 0xbcc3, 0x8e58, 0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5,
  0x3183, 0x200a, 0x1291, 0x0318, 0x77a7, 0x662e, 0x54b5, 0x453c,
  0xbdcb, 0xac42, 0x9ed9, 0x8f50, 0xfbef, 0xea66, 0xd8fd, 0xc974,
  0x4204, 0x538d, 0x6116, 0x709f, 0x0420, 0x15a9, 0x2732, 0x36bb,
  0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3,
  0x5285, 0x430c, 0x7197, 0x601e, 0x14a1, 0x0528, 0x37b3, 0x263a,
  0xdecd, 0xcf44, 0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72,
  0x6306, 0x728f, 0x4014, 0x519d, 0x2522, 0x34ab, 0x0630, 0x17b9,
  0xef4e, 0xfec7, 0xcc5c, 0xddd5, 0xa96a, 0xb8e3, 0x8a78, 0x9bf1,
  0x7387, 0x620e, 0x5095, 0x411c, 0x35a3, 0x242a, 0x16b1, 0x0738,
  0xffcf, 0xee46, 0xdcdd, 0xcd54, 0xb9eb, 0xa862, 0x9af9, 0x8b70,
  0x8408, 0x9581, 0xa71a, 0xb693, 0xc22c, 0xd3a5, 0xe13e, 0xf0b7,
  0x0840, 0x19c9, 0x2b52, 0x3adb, 0x4e64, 0x5fed, 0x6d76, 0x7cff,
  0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad, 0xc324, 0xf1bf, 0xe036,
  0x18c1, 0x0948, 0x3bd3, 0x2a5a, 0x5ee5, 0x4f6c, 0x7df7, 0x6c7e,
  0xa50a, 0xb483, 0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5,
  0x2942, 0x38cb, 0x0a50, 0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd,
  0xb58b, 0xa402, 0x9699, 0x8710, 0xf3af, 0xe226, 0xd0bd, 0xc134,
  0x39c3, 0x284a, 0x1ad1, 0x0b58, 0x7fe7, 0x6e6e, 0x5cf5, 0x4d7c,
  0xc60c, 0xd785, 0xe51e, 0xf497, 0x8028, 0x91a1, 0xa33a, 0xb2b3,
  0x4a44, 0x5bcd, 0x6956, 0x78df, 0x0c60, 0x1de9, 0x2f72, 0x3efb,
  0xd68d, 0xc704, 0xf59f, 0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232,
  0x5ac5, 0x4b4c, 0x79d7, 0x685e, 0x1ce1, 0x0d68, 0x3ff3, 0x2e7a,
  0xe70e, 0xf687, 0xc41c, 0xd595, 0xa12a, 0xb0a3, 0x8238, 0x93b1,
  0x6b46, 0x7acf, 0x4854, 0x59dd, 0x2d62, 0x3ceb, 0x0e70, 0x1ff9,
  0xf78f, 0xe606, 0xd49d, 0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330,
  0x7bc7, 0x6a4e, 0x58d5, 0x495c, 0x3de3, 0x2c6a, 0x1ef1, 0x0f78
};

///////////////////////////////////////////////////////////////////
//CRC Table
///////////////////////////////////////////////////////////////////

/*********************************************************************/

unsigned int crc_16_l_calc(char* buf_ptr,unsigned int len)
{
    unsigned int i;
    unsigned short crc = 0;
    
    while (len--!=0)
    {
        for(i = 0x80; i !=0 ; i = i>>1)
        {
            if((crc & 0x8000) !=0 )
            {
                crc = crc << 1 ;
                crc = crc ^ 0x1021;
            }
            else
            {
                crc = crc << 1 ;
            } 
            
            if((*buf_ptr & i) != 0 )
            {
                crc = crc ^ 0x1021;
            }
        }
        buf_ptr++;
    }
	
	return (crc);

}

/**---------------------------------------------------------------------------*
 ** FUNCTION                                                                  *
 **     unsigned short cm_decode_msg(uchar_ptr *dest, byte *src)              * 
 **                                                                           *	 
 ** DESCRIPTION                                                               *
 **     This function decodes the message of the source and restore the       *
 **     decoded message to the destination buffer.                            *
 **                                                                           *
 ** INPUT                                                                     *
 **     size:       Size of the source buffer in byte.                        *
 **     src:        Pointer of the input message.                             *
 **                                                                           *
 ** OUTPUT                                                                    *
 **     dest:       Pointer of the decoded message.                           *
 **                                                                           *
 ** RETURN VALUE                                                              *
 **    If the function is successful, return the size of the decoded message. *
 **    Else it returns CRC_ERROR : 0 or NO_END_FLAG : 0.                      *
 **                                                                           *	 
 ** DEPENDENCIES                                                              *
 **    extern word crc_16_l_calc(const void *src, word size);                 *
 **---------------------------------------------------------------------------*/
int decode_msg(char* input_buf, int input_size, 
                         char **output_buf, int *output_len,int bcrc)
{
	unsigned short           crc;               /* CRC value*/	
	char            *src_ptr;          /* source buffer pointer*/
  	int             dest_len;          /* output buffer length*/
    char            *dest_ptr;         /* dest buffer pointer*/
    register int    curr;

    /* Check if exist End Flag.*/
	src_ptr   = input_buf;	

	dest_len   = 0;

    if( input_size < 4 )
    {
        return 0;
    }
    
    /* Get the total size to be allocated for decoded message.*/
    for( curr = 1; curr < input_size - 1; curr++)
    {
        switch(*(src_ptr + curr))
        {
        case HDLC_ESCAPE:
            curr++;
            dest_len ++;
            break;
        default:
            dest_len++;
            break;        
        }
    }   

	/* Allocate meomory for decoded message*/
    dest_ptr = NULL;
    dest_ptr = (char *)malloc(dest_len);
    /* Memory Free fail.*/
    if(dest_ptr == NULL)
    {
        return 0;
    }
    
    memset(dest_ptr, 0, dest_len);

	curr = 0;
	dest_len = 0;
    /* Do de-escape.*/
    for( curr = 1; curr < input_size - 1; curr++)
    {
        switch(*(src_ptr + curr))
        {
        case HDLC_ESCAPE:
            curr++;
            *(dest_ptr + dest_len) = *(src_ptr + curr) ^ HDLC_ESCAPE_MASK;
            break;
        default:
            *(dest_ptr + dest_len) = *(src_ptr + curr);
            break;        
        }

		dest_len = dest_len + 1;
    }
	
    /*  CRC Check. */	
    if(bcrc)
    {
        crc = crc_16_l_calc(dest_ptr, dest_len);
        if (crc != CRC_16_L_OK)
        {
            free(dest_ptr);	        
            return 0;
        }
    }
    else
    {
        /*
        crc = crc_32_l_calc(dest_ptr, dest_len);
        if ((crc & 0xFFFF) != CRC_16_L_OK)
        {
            free(dest_ptr);	        
            return FALSE;
        }
        */ 
        

        crc = frm_chk((unsigned short *)dest_ptr, dest_len);
        if (0 != crc)
        {
            free(dest_ptr);	        
            return 0;
        }
    }	
    
    *(output_buf) = dest_ptr;
    *(output_len) = dest_len - CRC_CHECK_SIZE ;
	
    return 1;
}

/**---------------------------------------------------------------------------*
 ** FUNCTION                                                                  *
 **     word cm_encode_msg()                                                  * 
 **                                                                           *	 
 ** DESCRIPTION                                                               *
 **     This function encodes the message of the input message and restore    *
 **     the  encoded message to the dest bufffer.                             *
 **                                                                           *
 ** INPUT                                                                     *
 **     size:       Size of the source buffer in byte.                        *
 **     src:        Pointer of the input message.                             *
 **                                                                           *
 ** OUTPUT                                                                    *
 **     dest:       Pointer of the encoded message.                           *
 **                                                                           *
 ** RETURN VALUE                                                              *
 **     Return the size of the coded message.                                 *
 **                                                                           *	 
 ** DEPENDENCIES                                                              *
 **    extern word crc_16_l_calc(const void *src, word size);                 *
 **---------------------------------------------------------------------------*/
int encode_msg(char* input_buf, int input_size, 
                         char **output_buf, int *output_len, int bcrc)
{
	unsigned short           crc;               /* CRC value*/
	char            *src_ptr;          /* source buffer pointer*/
  	int             dest_len;          /* output buffer length*/
    char            *dest_ptr;         /* dest buffer pointer*/
    char            high_crc, low_crc;
    register int    curr;

    /* CRC Check. */
    src_ptr  = input_buf;
    /*  CRC Check. */	
    if(bcrc)
    {
        crc = crc_16_l_calc(src_ptr, input_size);
    }
    else
    {
        //crc = crc_32_l_calc(src_ptr, input_size);

        crc = frm_chk((unsigned short *)src_ptr, input_size);

        /*
        unsigned short SoruceValue, DestValue;
        
        SoruceValue = crc;
        DestValue   = 0;      
        CONVERT_SHORT(SoruceValue, DestValue);  
        crc = DestValue;*/
    }  

	high_crc = (crc>>8) & 0xFF;
	low_crc  = crc & 0xFF;

    /* Get the total size to be allocated.*/
	dest_len = 0;

	for (curr = 0; curr < input_size; curr++)
	{
		switch (*(src_ptr+curr))
		{
		case HDLC_FLAG:
		case HDLC_ESCAPE:
			dest_len += 2;
			break;
		default:
			dest_len++;
			break;
		}
	}
	
	switch (low_crc)
	{
	case HDLC_FLAG:
	case HDLC_ESCAPE:
		dest_len += 2;
		break;
	default:
		dest_len++;
	}
	
	switch (high_crc)
	{
	case HDLC_FLAG:
	case HDLC_ESCAPE:
		dest_len += 2;
		break;
	default:
		dest_len++;
	}

    dest_ptr = (char *)malloc((dest_len + 2));
    /* Memory Allocate fail.*/
    if(dest_ptr == NULL)
    {
        return 0;
    }

	*dest_ptr = HDLC_FLAG;
    dest_len  = 1;
    
    /* do escape*/
    for (curr = 0; curr < input_size; curr++)
	{
		switch (*(src_ptr+curr))
		{
		case HDLC_FLAG:
		case HDLC_ESCAPE:
			*(dest_ptr + dest_len++) = HDLC_ESCAPE;
			*(dest_ptr + dest_len++) = *(src_ptr + curr) ^ HDLC_ESCAPE_MASK;
			break;
		default:
			*(dest_ptr + dest_len++) = *(src_ptr + curr);
			break;
		}
	}
	
	switch (high_crc)
	{
	case HDLC_FLAG:
    case HDLC_ESCAPE:
		*(dest_ptr + dest_len++) = HDLC_ESCAPE;
		*(dest_ptr + dest_len++) = high_crc ^ HDLC_ESCAPE_MASK;
		break;
	default:
		*(dest_ptr + dest_len++) = high_crc;
	}

	switch (low_crc)
	{
	case HDLC_FLAG:
    case HDLC_ESCAPE:
		*(dest_ptr + dest_len++) = HDLC_ESCAPE;
		*(dest_ptr + dest_len++) = low_crc ^ HDLC_ESCAPE_MASK;
		break;
	default:
		*(dest_ptr + dest_len++) = low_crc;
	}
	
	
	*(dest_ptr + dest_len++) = HDLC_FLAG;
    
    *output_buf = dest_ptr;
    *output_len = dest_len;

	return 1;
}

unsigned short frm_chk(unsigned short *src, int len)
{
    unsigned int sum = 0;
    unsigned short SourceValue, DestValue;
    unsigned short lowSourceValue, hiSourceValue;

    /* Get sum value of the source.*/
    while (len > 1)
    {
        
        SourceValue = *src++;
        DestValue   = 0;      
        lowSourceValue = ( SourceValue & 0xFF00 ) >> 8;
        hiSourceValue = ( SourceValue & 0x00FF ) << 8;
        DestValue = lowSourceValue | hiSourceValue;

        sum += DestValue;
        len -= 2;
    }

    if (len == 1)
    {
        sum += *( (unsigned char *) src );
    }

    sum = (sum >> 16) + (sum & 0x0FFFF);
    sum += (sum >> 16);

    return (~sum);   
}


/*********************************************************************/
unsigned int crc_32_l_calc(char* buf_ptr,unsigned int len)
{
  unsigned int data, crc_16;
  len *= 8;

  for (crc_16 = CRC_16_L_SEED ; len >= 8; len -= 8, buf_ptr++) 
  {
    crc_16 = crc_16_l_table[ (crc_16 ^ *buf_ptr) & 0x00ff ] ^ (crc_16 >> 8);
  }

  if (len != 0) 
  {

    data = ((unsigned short) (*buf_ptr)) << (16-8);

    while (len-- != 0) 
    {
      if ( ((crc_16 ^ data) & 0x01) != 0 )
      {
        crc_16 >>= 1;
        crc_16 ^= CRC_16_L_POLYNOMIAL;
      } 
      else 
      {
        crc_16 >>= 1;
      }

      data >>= 1;
    }
  }

  return( ~crc_16 );

}