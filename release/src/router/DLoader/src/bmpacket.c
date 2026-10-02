#include "bmpacket.h"
#include "crc.h"

int decode_bmmsg( unsigned char* lpSrcMsg, 
                 int nSrcMsgLen,
                 unsigned char** lppDestMsg,
                 int* pnDestMsg ,
                 int bCrc )
{
    int nStartPos = -1;
    int nEndPos = -1;
    int iSuccess = 0;
    int i = 0;
    
    if( lpSrcMsg == 0 || nSrcMsgLen == 0 )
        return ERROR_PACKET;
    
    for( ; i < nSrcMsgLen; i++ )
    {
        if( lpSrcMsg[ i ] == HDLC_FLAG)
        {
            if( nStartPos == -1 )
            {
                nStartPos = i;
            }
            else
            {
                nEndPos = i;
                iSuccess = decode_msg( lpSrcMsg + nStartPos  , 
                    nEndPos - nStartPos + 1,  lppDestMsg, pnDestMsg, bCrc );
                
                if( iSuccess != 0)                    
                    break;
                
                nStartPos = i; 
                nEndPos = -1;
            }
        }
    }
    
    if( nStartPos == -1 )
    {
        return ERROR_PACKET;
    }

    if( nEndPos == -1)
    {
        return PART_PACKET + nStartPos;
    }

    return GOOD_PACKET;
}


int encode_bmmsg(  unsigned char* lpSrcMsg, 
                 int nSrcMsgLen,
                 unsigned char** lppDestMsg,
                 int *pnDestMsg,
                 int bCrc )
{
    
    return encode_msg( lpSrcMsg, nSrcMsgLen, lppDestMsg, pnDestMsg, bCrc );
}

int  GetVerifyType(char* buf_ptr,unsigned int len)
{
	int nVerifyType = -1;
	do 
	{
		if(0 == buf_ptr || 0 ==len )	break;
		
		if( CRC_16_L_OK == crc_16_l_calc(buf_ptr, len) )
		{
			nVerifyType = 1; // CRC
			break;

		}

		if( 0 == frm_chk((unsigned short *)buf_ptr, len) )
		{
			nVerifyType = 0; // CheckSum
			break;
		}

	} while(0);
	
	return nVerifyType;
}