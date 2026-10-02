#include "Calibration.h"

#include "Calibration_Struct.h"
#include <string.h>
#include <stdio.h>

#define IMEI_LEN			(8)
#define GSM_CALI_VER_A      0xFF0A
#define GSM_CALI_VER_B      0xFF0B
#define GSM_CALI_VER_C      0xFF0C
#define GSM_CALI_VER_MIN    GSM_CALI_VER_A
#define GSM_CALI_VER_MAX    GSM_CALI_VER_C

int g_nGSMCaliVaPolicy = 0;

const std::string szErrDescTable[] =
{
	_T(""),
    _T("Can not find nv id in nvitem.bin!"),
    _T("Can not find nv id in device!"),
    _T("Structure change,Length of nv id does not match in device and nvitem.bin!"),
    _T("Unknown or unsurpport version in Device!"),
    _T("Use a older version of nv item to Update a new one is not permitted!"),
    _T("Unknown version in nvitem.bin!"), 
	_T("Structure change,Length of nv id in nvitem.bin does not match its structure definition!"),
	_T("NV item structure version mismatched!"),
};

enum
{
	ERR_NONE,
    ERR_NOT_FIND_PARAM_IN_FILE,
    ERR_NOT_FIND_PARAM_IN_MODULE,
    ERR_PARAM_LEN_NOT_MATCH,
    ERR_UNKNOWN_VER_IN_MODULE,
    ERR_OLD_VERSION,
    ERR_UNKNOWN_VER_IN_FILE,  
	ERR_PARAM_LEN_NOT_MATCH_DEF,
	ERR_STRUCT_VER_NOT_MATCH
};
 
std::string GetErrorDesc( UINT dwID  )
{
    if( (int)dwID < 0 )
        return _T("");

    return szErrDescTable[ dwID ];
}

#define PRESERVE_CALIBRATION(lpSrc,nSrc,lpDst,nDst,nSize,nLen)  memcpy(lpSrc + nSrc,lpDst + nDst,nSize);    \
                                                                nSrc += nSize;                              \
                                                                nDst += nSize;                              \
                                                                nLen += nSize;

#define SKIP_UNUSED(nOffset,nSize,nLen)    nOffset += nSize;   \
                                           nLen += nSize;


// DWORD ConvEdnDWORD ( DWORD dwData )
// {
//      return MAKELONG( MAKEWORD(HIBYTE(HIWORD(dwData)), LOBYTE(HIWORD(dwData))),
//                       MAKEWORD(HIBYTE(LOWORD(dwData)), LOBYTE(LOWORD(dwData)))); 
// }


#define  CONV_SHORT(w)    (MAKEWORD(HIBYTE(w),LOBYTE(w)))


#define  CONV_DWORD(dw)   (MAKELONG(MAKEWORD(HIBYTE(HIWORD(dw)),LOBYTE(HIWORD(dw))),\
                                    MAKEWORD(HIBYTE(LOWORD(dw)),LOBYTE(LOWORD(dw)))))

static void ConvSHORTBuf(uint16 *pBuf,int nNum)
{
	if(pBuf == NULL || nNum == 0)
	{
		return;
	}

	for( int i = 0; i < nNum; ++i, ++pBuf )
	{
		*pBuf = CONV_SHORT(*pBuf);
	}
}

static void ConvDWORDBuf(uint32 *pBuf,int nNum)
{
	if(pBuf == NULL || nNum == 0)
	{
		return;
	}

	for( int i = 0; i < nNum; ++i, ++pBuf )
	{
		*pBuf = CONV_DWORD(*pBuf);
	}
}
                           

static void GSMCaliEndianConvVerA(calibration_struct_va::calibration_param_T &para)
{
/*
	uint16              calibration_param_version;
    RF_param_DSP_use_T  rf_param_dsp_use;    // all uint16
    RF_param_MCU_use_T  rf_param_mcu_use;    // all uint8
    Misc_cal_MCU_use_T  misc_cal_mcu_use;
    int16                   mic_gain;        
    int16                   auxi_mic_gain;   
    uint16                  PM_version;  
    uint16                  software_version; 
    uint16                  station_num;
    uint8                   operate_code[ 16 ];
    uint32                  date;    
    ADC_T                   adc;             // all uint32    
*/
	// calibration_param_version
	para.calibration_param_version = CONV_SHORT(para.calibration_param_version);

	// rf_param_dsp_use
	ConvSHORTBuf((uint16 *)&para.rf_param_dsp_use,sizeof(para.rf_param_dsp_use)/sizeof(uint16));

	// rf_param_mcu_use, need not convert

	// misc_cal_mcu_use
	para.misc_cal_mcu_use.batt_mV_per_4bits		= CONV_DWORD(para.misc_cal_mcu_use.batt_mV_per_4bits);
	para.misc_cal_mcu_use.clock_32k_cal_duration= CONV_SHORT(para.misc_cal_mcu_use.clock_32k_cal_duration);
	para.misc_cal_mcu_use.clock_32k_cal_interval= CONV_SHORT(para.misc_cal_mcu_use.clock_32k_cal_interval);

	para.mic_gain			= CONV_SHORT(para.mic_gain);
	para.auxi_mic_gain		= CONV_SHORT(para.auxi_mic_gain);
	para.PM_version			= CONV_SHORT(para.PM_version);
	para.software_version	= CONV_SHORT(para.software_version);
	para.station_num		= CONV_SHORT(para.station_num);
	para.date				= CONV_DWORD(para.date);

	// adc
	ConvDWORDBuf((uint32 *)&para.adc,sizeof(para.adc)/sizeof(uint32));	
}

static void GSMCaliEndianConvVerB(calibration_struct_vb::calibration_param_T &para)
{
	// calibration_param_version
	para.calibration_param_version = CONV_SHORT(para.calibration_param_version);

	// rf_param_dsp_use
	ConvSHORTBuf((uint16 *)&para.rf_param_dsp_use,sizeof(para.rf_param_dsp_use)/sizeof(uint16));

	// rf_param_mcu_use, need not convert

	// misc_cal_mcu_use
	para.misc_cal_mcu_use.batt_mV_per_4bits		= CONV_DWORD(para.misc_cal_mcu_use.batt_mV_per_4bits);
	para.misc_cal_mcu_use.clock_32k_cal_duration= CONV_SHORT(para.misc_cal_mcu_use.clock_32k_cal_duration);
	para.misc_cal_mcu_use.clock_32k_cal_interval= CONV_SHORT(para.misc_cal_mcu_use.clock_32k_cal_interval);

	para.mic_gain			= CONV_SHORT(para.mic_gain);
	para.auxi_mic_gain		= CONV_SHORT(para.auxi_mic_gain);
	para.PM_version			= CONV_SHORT(para.PM_version);
	para.software_version	= CONV_SHORT(para.software_version);
	para.station_num		= CONV_SHORT(para.station_num);
	para.date				= CONV_DWORD(para.date);

	// adc
	ConvDWORDBuf((uint32 *)&para.adc,sizeof(para.adc)/sizeof(uint32));	
}


static void BTConvEndian(BT_CONFIG &para)
{
	para.xtal_dac = CONV_SHORT(para.xtal_dac); 
}

static void XTDCaliEndianConvVer3(td_calibration_struct_v3::td_calibration_T &para)
{
/*
       uint16   cali_version;
       uint16   antenna_switch_pin_control;
       uint16   Antenna_switch_truth_table[8];
       uint16   rf_afc_dac;
       uint16   rf_afc_slope;
       uint16   agc_ctl_word[AGC_CTL_LEN_QS3200];
       uint16   agc_gain_word[AGC_GAIN_LEN_QS3200]; // 115*3+115+115*8+115
       uint16   AGC_compensation[AGC_COMP_LEN_QS3200];// 1+30*2
       uint16   tdpa_pin_control;
       uint16   TDPA_APC_control_word_index[APC_CTL_LEN_QS3200]; // 100*4+100*9
       uint16   APC_compensation[APC_COMP_LEN_QS3200]; // 30 + 30 + 60 + 60 + 30 + 1 + (4*13+20)*2 + 1 + 1 + 256
       uint16   rf_register_num;
       uint32   rf_Register_Initial[50];
       uint32   rf_action_tbl[281];
       uint8    reserved[500];
*/
	ConvSHORTBuf((uint16 *)&para.cali_version, (sizeof(para)-sizeof(uint32)*(50+281) -500*sizeof(uint8))/sizeof(uint16));
	ConvDWORDBuf((uint32 *)&para.rf_Register_Initial, (sizeof(uint32)*(50+281))/sizeof(uint32));
}

static void XTDCaliEndianConvVer4(td_calibration_struct_v4::td_calibration_T &para)
{
/*
       uint16   cali_version;
       uint16   rf_afc_dac;
       uint16   rf_afc_slope;
	   uint16   slope_length;
	   uint16   CDAC;
	   uint16   CAFC;
       uint16   agc_gain_word[AGC_GAIN_LEN_QS3200]; // 115*12 + 115*4 + 115*9
       uint16   TDPA_APC_control_word_index[APC_CTL_LEN_QS3200]; // 100*12 + 100*4 + 100*9
*/
	ConvSHORTBuf((uint16 *)&para.cali_version, sizeof(para)/sizeof(uint16));
}

static void LTECaliEndianConvVer1(lte_calibration_struct_v1::LTE_NV_CALI_PARAM_T &para)
{
/* lte_calibration_struct_v1::LTE_NV_CALI_PARAM_T all members are short type	*/
	ConvSHORTBuf((uint16 *)&para.CALI_PARAM_VERSION, sizeof(para)/sizeof(uint16));
}

BOOL XFindNVOffset(WORD wId,LPBYTE lpCode,DWORD dwCodeSize,
				   DWORD& dwOffset,DWORD& dwLength,BOOL bBigEndian)
{
    if(lpCode == NULL || (int)dwCodeSize < 0)
    {
        return FALSE;
    }
    
    dwOffset = 4;     // Skip first four bytes,that is time stamp
    WORD wCurID;
    dwLength = 0;
    BYTE* pTemp = lpCode + dwOffset;
    
    while(dwOffset < dwCodeSize)
    {
		wCurID = *(uint16*)pTemp;
		if(bBigEndian)
		{
			wCurID = CONV_SHORT(wCurID);
		}
        pTemp += 2;

		dwLength = *(uint16*)pTemp;
		if(bBigEndian)
		{
			dwLength = CONV_SHORT(dwLength);
		}

        pTemp += 2;
        dwOffset += 4;
        // Must be four byte aligned
        BYTE bRet = (BYTE)(dwLength % 4);
        if(bRet != 0)
        {
            dwLength += 4 - bRet;
        }

		// 0xFFFF is end-flag.
		if(wCurID == 0xFFFF)
		{
			return FALSE;
		}
        
        if(wCurID == wId)
        {
			//check length
			if( (dwOffset+dwLength-bRet) <= dwCodeSize )
			{
				return TRUE;
			}
			else
			{
				return FALSE;
			}
        }
        else
        {
            dwOffset += dwLength;
            pTemp += dwLength;
        }
    }
    
    return FALSE;
}

static void GSM_VerAToA( LPBYTE pFileBuf,DWORD dwOffsetFile,BOOL bFileBigEndian,LPBYTE pModuBuf,DWORD dwOffsetModu,BOOL bModuBigEndian )
{
	int i=0;
    calibration_struct_va::calibration_param_T para_modu,para_file;
    memcpy( &para_modu,pModuBuf+dwOffsetModu,sizeof( para_modu ) );
    memcpy( &para_file,pFileBuf+dwOffsetFile,sizeof( para_file ) );

	if( bFileBigEndian != bModuBigEndian)
	{
		GSMCaliEndianConvVerA(para_modu);
	}
    
	if(g_nGSMCaliVaPolicy == 0 || g_nGSMCaliVaPolicy == 1 )
	{
		// not backup RF_ramp_delta_timing
		for( i=0;i<calibration_struct_va::NUM_TX_LEVEL;i++ )
		{
			para_modu.rf_param_dsp_use.rf_gsm_param_dsp_use.RF_ramp_delta_timing[i] = para_file.rf_param_dsp_use.rf_gsm_param_dsp_use.RF_ramp_delta_timing[i];
			para_modu.rf_param_dsp_use.rf_dcs_param_dsp_use.RF_ramp_delta_timing[i] = para_file.rf_param_dsp_use.rf_dcs_param_dsp_use.RF_ramp_delta_timing[i];
			para_modu.rf_param_dsp_use.rf_pcs_param_dsp_use.RF_ramp_delta_timing[i] = para_file.rf_param_dsp_use.rf_pcs_param_dsp_use.RF_ramp_delta_timing[i];
			para_modu.rf_param_dsp_use.rf_gsm850_param_dsp_use.RF_ramp_delta_timing[i] = para_file.rf_param_dsp_use.rf_gsm850_param_dsp_use.RF_ramp_delta_timing[i];
		}

		if(g_nGSMCaliVaPolicy == 1) // For HTC
		{
			// not backup RF_ramp_PA_power_on_duration
			for( i=0;i<calibration_struct_va::NUM_TX_LEVEL;i++ )
			{
				para_modu.rf_param_dsp_use.rf_gsm_param_dsp_use.RF_ramp_PA_power_on_duration[i] = para_file.rf_param_dsp_use.rf_gsm_param_dsp_use.RF_ramp_PA_power_on_duration[i];
				para_modu.rf_param_dsp_use.rf_dcs_param_dsp_use.RF_ramp_PA_power_on_duration[i] = para_file.rf_param_dsp_use.rf_dcs_param_dsp_use.RF_ramp_PA_power_on_duration[i];
				para_modu.rf_param_dsp_use.rf_pcs_param_dsp_use.RF_ramp_PA_power_on_duration[i] = para_file.rf_param_dsp_use.rf_pcs_param_dsp_use.RF_ramp_PA_power_on_duration[i];
				para_modu.rf_param_dsp_use.rf_gsm850_param_dsp_use.RF_ramp_PA_power_on_duration[i] = para_file.rf_param_dsp_use.rf_gsm850_param_dsp_use.RF_ramp_PA_power_on_duration[i];
			}
			// not backup RF_ramp_table
			memcpy(&para_modu.rf_param_dsp_use.rf_gsm_param_dsp_use.RF_ramp_table,
				   &para_file.rf_param_dsp_use.rf_gsm_param_dsp_use.RF_ramp_table,
				   sizeof(para_modu.rf_param_dsp_use.rf_gsm_param_dsp_use.RF_ramp_table));
			
			memcpy(&para_modu.rf_param_dsp_use.rf_dcs_param_dsp_use.RF_ramp_table,
				   &para_file.rf_param_dsp_use.rf_dcs_param_dsp_use.RF_ramp_table,
				   sizeof(para_modu.rf_param_dsp_use.rf_dcs_param_dsp_use.RF_ramp_table));

			memcpy(&para_modu.rf_param_dsp_use.rf_pcs_param_dsp_use.RF_ramp_table,
				   &para_file.rf_param_dsp_use.rf_pcs_param_dsp_use.RF_ramp_table,
				   sizeof(para_modu.rf_param_dsp_use.rf_pcs_param_dsp_use.RF_ramp_table));

			memcpy(&para_modu.rf_param_dsp_use.rf_gsm850_param_dsp_use.RF_ramp_table,
				   &para_file.rf_param_dsp_use.rf_gsm850_param_dsp_use.RF_ramp_table,
				   sizeof(para_modu.rf_param_dsp_use.rf_gsm850_param_dsp_use.RF_ramp_table));

			// not backup reserved "temperature_and_voltage_composate_structure"
			memcpy(&(para_modu.rf_param_dsp_use.rf_gsm_param_dsp_use.reserved[0]),
				   &(para_file.rf_param_dsp_use.rf_gsm_param_dsp_use.reserved[0]),
				   sizeof(para_modu.rf_param_dsp_use.rf_gsm_param_dsp_use.reserved));
			
			memcpy(&(para_modu.rf_param_dsp_use.rf_dcs_param_dsp_use.reserved[0]),
				   &(para_file.rf_param_dsp_use.rf_dcs_param_dsp_use.reserved[0]),
				   sizeof(para_modu.rf_param_dsp_use.rf_dcs_param_dsp_use.reserved));
			
			memcpy(&(para_modu.rf_param_dsp_use.rf_pcs_param_dsp_use.reserved[0]),
				   &(para_file.rf_param_dsp_use.rf_pcs_param_dsp_use.reserved[0]),
				   sizeof(para_modu.rf_param_dsp_use.rf_pcs_param_dsp_use.reserved));
			
			memcpy(&(para_modu.rf_param_dsp_use.rf_gsm850_param_dsp_use.reserved[0]),
				   &(para_file.rf_param_dsp_use.rf_gsm850_param_dsp_use.reserved[0]),
				   sizeof(para_modu.rf_param_dsp_use.rf_gsm850_param_dsp_use.reserved));

		}

		memcpy( pFileBuf + dwOffsetFile,&para_modu,sizeof( para_modu ) );
	}
	else if( g_nGSMCaliVaPolicy == 2 )
	{
		//adc
		memcpy(&para_file.adc,&para_modu.adc,sizeof(para_file.adc));

		//afc
		memcpy(&para_file.rf_param_dsp_use.rf_common_param_dsp_use,
			   &para_modu.rf_param_dsp_use.rf_common_param_dsp_use,
	     sizeof(para_file.rf_param_dsp_use.rf_common_param_dsp_use));

		calibration_struct_va::RF_param_band_DSP_use_T *pFile = NULL;
		calibration_struct_va::RF_param_band_DSP_use_T *pModu = NULL;

		for(int i = 0; i< 4; i++)
		{	
			switch(i)
			{
			case 0:
				pFile = &para_file.rf_param_dsp_use.rf_gsm_param_dsp_use;
				pModu = &para_modu.rf_param_dsp_use.rf_gsm_param_dsp_use;
				break;
			case 1:
				pFile = &para_file.rf_param_dsp_use.rf_dcs_param_dsp_use;
				pModu = &para_modu.rf_param_dsp_use.rf_dcs_param_dsp_use;
				break;
			case 2:
				pFile = &para_file.rf_param_dsp_use.rf_pcs_param_dsp_use;
				pModu = &para_modu.rf_param_dsp_use.rf_pcs_param_dsp_use;
			    break;
			case 3:
				pFile = &para_file.rf_param_dsp_use.rf_gsm850_param_dsp_use;
				pModu = &para_modu.rf_param_dsp_use.rf_gsm850_param_dsp_use;
			    break;
			default:
			    break;
			}
			
			//agc
			/* agc_ctrl_word */
			memcpy( pFile->agc_ctrl_word,
					pModu->agc_ctrl_word,
			 sizeof(pFile->agc_ctrl_word));

			/* RX_compensate_value */
			memcpy( pFile->RX_compensate_value,
					pModu->RX_compensate_value,
			 sizeof(pFile->RX_compensate_value));

			/* max_rf_gain_index */
			memcpy(&pFile->max_rf_gain_index,
				   &pModu->max_rf_gain_index,
			 sizeof(pFile->max_rf_gain_index));	

			//apc
			/* rf_ramp_param_constant_value */
			memcpy( pFile->rf_ramp_param_constant_up,
					pModu->rf_ramp_param_constant_up,
			 sizeof(pFile->rf_ramp_param_constant_up));

			/* rf_edge_tx_gain_table */
			memcpy( pFile->rf_ramp_param_constant_down,
					pModu->rf_ramp_param_constant_down,
			 sizeof(pFile->rf_ramp_param_constant_down));

			/* RF_ramppwr_step_factor */
			memcpy( pFile->RF_ramppwr_step_factor,
					pModu->RF_ramppwr_step_factor,
			 sizeof(pFile->RF_ramppwr_step_factor));

			/* rf_8psk_tx_compensation */
			memcpy( pFile->reserved1,
					pModu->reserved1,
			 sizeof(pFile->reserved1));
		}

		memcpy( pFileBuf + dwOffsetFile,&para_file,sizeof( para_file ) );
	}  
	else//g_nGSMCaliVaPolicy == 3 backup all data for GSM calibration Ver FF0A 
	{
		memcpy( pFileBuf + dwOffsetFile,&para_modu,sizeof( para_modu ) );
	}
}

void GSM_VerBToB( LPBYTE pFileBuf,DWORD dwOffsetFile,BOOL bFileBigEndian,LPBYTE pModuBuf,DWORD dwOffsetModu,BOOL bModuBigEndian )
{
	int i=0;
	calibration_struct_vb::calibration_param_T para_modu,para_file;
	memcpy( &para_modu,pModuBuf+dwOffsetModu,sizeof( para_modu ) );
	memcpy( &para_file,pFileBuf+dwOffsetFile,sizeof( para_file ) );

	if( bFileBigEndian != bModuBigEndian)
	{
		GSMCaliEndianConvVerB(para_modu);
	}

	if(g_nGSMCaliVaPolicy == 0 || g_nGSMCaliVaPolicy == 1 )
	{
		// not backup RF_ramp_delta_timing
		for( i=0;i<calibration_struct_vb::NUM_TX_LEVEL;i++ )
		{
			para_modu.rf_param_dsp_use.rf_gsm_param_dsp_use.RF_ramp_delta_timing[i] = para_file.rf_param_dsp_use.rf_gsm_param_dsp_use.RF_ramp_delta_timing[i];
			para_modu.rf_param_dsp_use.rf_dcs_param_dsp_use.RF_ramp_delta_timing[i] = para_file.rf_param_dsp_use.rf_dcs_param_dsp_use.RF_ramp_delta_timing[i];
			para_modu.rf_param_dsp_use.rf_pcs_param_dsp_use.RF_ramp_delta_timing[i] = para_file.rf_param_dsp_use.rf_pcs_param_dsp_use.RF_ramp_delta_timing[i];
			para_modu.rf_param_dsp_use.rf_gsm850_param_dsp_use.RF_ramp_delta_timing[i] = para_file.rf_param_dsp_use.rf_gsm850_param_dsp_use.RF_ramp_delta_timing[i];
		}

		if(g_nGSMCaliVaPolicy == 1) // For HTC
		{
			// not backup RF_ramp_PA_power_on_duration
			for( i=0;i<calibration_struct_vb::NUM_TX_LEVEL;i++ )
			{
				para_modu.rf_param_dsp_use.rf_gsm_param_dsp_use.RF_ramp_PA_power_on_duration[i] = para_file.rf_param_dsp_use.rf_gsm_param_dsp_use.RF_ramp_PA_power_on_duration[i];
				para_modu.rf_param_dsp_use.rf_dcs_param_dsp_use.RF_ramp_PA_power_on_duration[i] = para_file.rf_param_dsp_use.rf_dcs_param_dsp_use.RF_ramp_PA_power_on_duration[i];
				para_modu.rf_param_dsp_use.rf_pcs_param_dsp_use.RF_ramp_PA_power_on_duration[i] = para_file.rf_param_dsp_use.rf_pcs_param_dsp_use.RF_ramp_PA_power_on_duration[i];
				para_modu.rf_param_dsp_use.rf_gsm850_param_dsp_use.RF_ramp_PA_power_on_duration[i] = para_file.rf_param_dsp_use.rf_gsm850_param_dsp_use.RF_ramp_PA_power_on_duration[i];
			}
			// not backup RF_ramp_table
			memcpy(&para_modu.rf_param_dsp_use.rf_gsm_param_dsp_use.RF_ramp_table,
				&para_file.rf_param_dsp_use.rf_gsm_param_dsp_use.RF_ramp_table,
				sizeof(para_modu.rf_param_dsp_use.rf_gsm_param_dsp_use.RF_ramp_table));

			memcpy(&para_modu.rf_param_dsp_use.rf_dcs_param_dsp_use.RF_ramp_table,
				&para_file.rf_param_dsp_use.rf_dcs_param_dsp_use.RF_ramp_table,
				sizeof(para_modu.rf_param_dsp_use.rf_dcs_param_dsp_use.RF_ramp_table));

			memcpy(&para_modu.rf_param_dsp_use.rf_pcs_param_dsp_use.RF_ramp_table,
				&para_file.rf_param_dsp_use.rf_pcs_param_dsp_use.RF_ramp_table,
				sizeof(para_modu.rf_param_dsp_use.rf_pcs_param_dsp_use.RF_ramp_table));

			memcpy(&para_modu.rf_param_dsp_use.rf_gsm850_param_dsp_use.RF_ramp_table,
				&para_file.rf_param_dsp_use.rf_gsm850_param_dsp_use.RF_ramp_table,
				sizeof(para_modu.rf_param_dsp_use.rf_gsm850_param_dsp_use.RF_ramp_table));

			// not backup reserved "temperature_and_voltage_composate_structure"
			memcpy(&(para_modu.rf_param_dsp_use.rf_gsm_param_dsp_use.reserved[0]),
				&(para_file.rf_param_dsp_use.rf_gsm_param_dsp_use.reserved[0]),
				sizeof(para_modu.rf_param_dsp_use.rf_gsm_param_dsp_use.reserved));

			memcpy(&(para_modu.rf_param_dsp_use.rf_dcs_param_dsp_use.reserved[0]),
				&(para_file.rf_param_dsp_use.rf_dcs_param_dsp_use.reserved[0]),
				sizeof(para_modu.rf_param_dsp_use.rf_dcs_param_dsp_use.reserved));

			memcpy(&(para_modu.rf_param_dsp_use.rf_pcs_param_dsp_use.reserved[0]),
				&(para_file.rf_param_dsp_use.rf_pcs_param_dsp_use.reserved[0]),
				sizeof(para_modu.rf_param_dsp_use.rf_pcs_param_dsp_use.reserved));

			memcpy(&(para_modu.rf_param_dsp_use.rf_gsm850_param_dsp_use.reserved[0]),
				&(para_file.rf_param_dsp_use.rf_gsm850_param_dsp_use.reserved[0]),
				sizeof(para_modu.rf_param_dsp_use.rf_gsm850_param_dsp_use.reserved));

		}

		memcpy( pFileBuf + dwOffsetFile,&para_modu,sizeof( para_modu ) );
	}
	else if( g_nGSMCaliVaPolicy == 2 )
	{
		//adc
		memcpy(&para_file.adc,&para_modu.adc,sizeof(para_file.adc));

		//afc
		memcpy(&para_file.rf_param_dsp_use.rf_common_param_dsp_use,
			&para_modu.rf_param_dsp_use.rf_common_param_dsp_use,
			sizeof(para_file.rf_param_dsp_use.rf_common_param_dsp_use));

		calibration_struct_vb::RF_param_band_DSP_use_T *pFile = NULL;
		calibration_struct_vb::RF_param_band_DSP_use_T *pModu = NULL;

		for(int i = 0; i< 4; i++)
		{	
			switch(i)
			{
			case 0:
				pFile = &para_file.rf_param_dsp_use.rf_gsm_param_dsp_use;
				pModu = &para_modu.rf_param_dsp_use.rf_gsm_param_dsp_use;
				break;
			case 1:
				pFile = &para_file.rf_param_dsp_use.rf_dcs_param_dsp_use;
				pModu = &para_modu.rf_param_dsp_use.rf_dcs_param_dsp_use;
				break;
			case 2:
				pFile = &para_file.rf_param_dsp_use.rf_pcs_param_dsp_use;
				pModu = &para_modu.rf_param_dsp_use.rf_pcs_param_dsp_use;
				break;
			case 3:
				pFile = &para_file.rf_param_dsp_use.rf_gsm850_param_dsp_use;
				pModu = &para_modu.rf_param_dsp_use.rf_gsm850_param_dsp_use;
				break;
			default:
				break;
			}

			//agc
			/* agc_ctrl_word */
			memcpy( pFile->agc_ctrl_word,
				pModu->agc_ctrl_word,
				sizeof(pFile->agc_ctrl_word));

			/* RX_compensate_value */
			memcpy( pFile->RX_compensate_value,
				pModu->RX_compensate_value,
				sizeof(pFile->RX_compensate_value));

			/* max_rf_gain_index */
			memcpy(&pFile->max_rf_gain_index,
				&pModu->max_rf_gain_index,
				sizeof(pFile->max_rf_gain_index));	

			//apc
			/* rf_ramp_param_constant_value */
			memcpy( pFile->rf_ramp_param_constant_up,
				pModu->rf_ramp_param_constant_up,
				sizeof(pFile->rf_ramp_param_constant_up));

			/* rf_edge_tx_gain_table */
			memcpy( pFile->rf_ramp_param_constant_down,
				pModu->rf_ramp_param_constant_down,
				sizeof(pFile->rf_ramp_param_constant_down));

			/* RF_ramppwr_step_factor */
			memcpy( pFile->RF_ramppwr_step_factor,
				pModu->RF_ramppwr_step_factor,
				sizeof(pFile->RF_ramppwr_step_factor));

			/* rf_8psk_tx_compensation */
			memcpy( pFile->reserved1,
				pModu->reserved1,
				sizeof(pFile->reserved1));
		}

		memcpy( pFileBuf + dwOffsetFile,&para_file,sizeof( para_file ) );
	}  
	else//g_nGSMCaliVaPolicy == 3 backup all data for GSM calibration Ver FF0A 
	{
		memcpy( pFileBuf + dwOffsetFile,&para_modu,sizeof( para_modu ) );
	}
}

DWORD  GSMCaliPreserve( WORD wID,LPBYTE lpCode, DWORD dwCodeSize, 
                         LPBYTE lpReadBuffer, DWORD dwReadSize,
                         BOOL bOldReplaceNew , BOOL bContinue )
{
	UNUSED_ALWAYS(bOldReplaceNew);

	BOOL bFileBigEndian = FALSE;
	BOOL bModuBigEndian = FALSE;
    DWORD dwOffsetFile=0,dwLengthFile=0;
    BYTE* pFileBuf = lpCode;
	BYTE* pModuBuf = lpReadBuffer;

    if(!XFindNVOffsetEx( wID, pFileBuf,dwCodeSize,dwOffsetFile,dwLengthFile,bFileBigEndian,FALSE))
    {		
		return ERR_NOT_FIND_PARAM_IN_FILE;		
    }

	WORD wVerFile = *(WORD*)(pFileBuf+dwOffsetFile);
	if(bFileBigEndian)
	{
		wVerFile = CONV_SHORT(wVerFile);
	}

    // Find calibration
    DWORD dwOffsetModu=0,dwLengthModu=0;
    if(!XFindNVOffsetEx( wID, pModuBuf,dwReadSize,dwOffsetModu,dwLengthModu,bModuBigEndian,TRUE))
    {		
		if( bContinue )
		{
			return ERR_NONE;
		}
		else
		{
			return ERR_NOT_FIND_PARAM_IN_MODULE;
		}	
    }

    WORD wVerModu = *(WORD*)(pModuBuf+dwOffsetModu);
	if(bModuBigEndian)
	{
		wVerModu = CONV_SHORT(wVerModu);
	}

	DWORD dwSizeAligned = 0;

	if(GSM_CALI_VER_A == wVerFile)
	{ 
		dwSizeAligned = sizeof( calibration_struct_va::calibration_param_T );	
		dwSizeAligned = ((DWORD)((dwSizeAligned + 3)/4)) * 4;
		if( dwLengthFile != dwSizeAligned )
        {
            return ERR_PARAM_LEN_NOT_MATCH_DEF;
        }
		
        if(GSM_CALI_VER_A == wVerModu)
		{
			if( dwLengthFile == dwLengthModu )
			{
				GSM_VerAToA(pFileBuf,dwOffsetFile,bFileBigEndian,pModuBuf,dwOffsetModu,bModuBigEndian);
				return ERR_NONE;
			}
			else
			{
				return ERR_PARAM_LEN_NOT_MATCH;
			}
		}
		else if (GSM_CALI_VER_B == wVerModu)
		{
			return ERR_STRUCT_VER_NOT_MATCH;
		}
		else
        {
            return ERR_UNKNOWN_VER_IN_MODULE;
        }		
	}   
	else if(GSM_CALI_VER_B == wVerFile)
	{
		dwSizeAligned = sizeof( calibration_struct_vb::calibration_param_T );	
		dwSizeAligned = ((DWORD)((dwSizeAligned + 3)/4)) * 4;
		if( dwLengthFile != dwSizeAligned )
		{
			return ERR_PARAM_LEN_NOT_MATCH_DEF;
		}

		if(GSM_CALI_VER_B == wVerModu)
		{
			if( dwLengthFile == dwLengthModu )
			{
				GSM_VerBToB(pFileBuf,dwOffsetFile,bFileBigEndian,pModuBuf,dwOffsetModu,bModuBigEndian);
				return ERR_NONE;
			}
			else
			{
				return ERR_PARAM_LEN_NOT_MATCH;
			}
		}
		else if (GSM_CALI_VER_A == wVerModu)
		{
			return ERR_STRUCT_VER_NOT_MATCH;
		}
		else
		{
			return ERR_UNKNOWN_VER_IN_MODULE;
		}		
	}
	else if(GSM_CALI_VER_C == wVerFile) //backup all contents
	{
		if (GSM_CALI_VER_C == wVerModu)
		{
			if( dwLengthFile == dwLengthModu )
			{
				memcpy( lpCode + dwOffsetFile,lpReadBuffer + dwOffsetModu,dwLengthModu);
				return ERR_NONE;
			}
			else
			{
				return ERR_PARAM_LEN_NOT_MATCH;
			}
		}
		else
		{
			return ERR_STRUCT_VER_NOT_MATCH;
		}
	}
	else
	{
		return ERR_UNKNOWN_VER_IN_FILE;
	}
	
}



static void XTD_Ver3To3( LPBYTE pFileBuf,DWORD dwOffsetFile,BOOL bFileBigEndian,LPBYTE pModuBuf,DWORD dwOffsetModu,BOOL bModuBigEndian )
{
	// 结构部分备份
    td_calibration_struct_v3::td_calibration_T para_modu;
    td_calibration_struct_v3::td_calibration_T para_file;

    memcpy( &para_modu,pModuBuf+dwOffsetModu,sizeof( para_modu ) );
    memcpy( &para_file,pFileBuf+dwOffsetFile,sizeof( para_file ) );

	if( bFileBigEndian != bModuBigEndian)
	{
		XTDCaliEndianConvVer3(para_modu);
	}

	para_file.rf_afc_dac = para_modu.rf_afc_dac;
	para_file.rf_afc_slope = para_modu.rf_afc_slope;

    memcpy(&(para_file.agc_ctl_word[0]),&(para_modu.agc_ctl_word[0]),
		(BYTE*)&(para_modu.agc_ctl_word[td_calibration_struct_v3::AGC_CTL_LEN_QS3200 - 1])-(BYTE*)&(para_modu.agc_ctl_word[0])+sizeof(uint16));

    memcpy(&(para_file.agc_gain_word[0]),&(para_modu.agc_gain_word[0]),
		(BYTE*)&(para_modu.agc_gain_word[td_calibration_struct_v3::AGC_GAIN_LEN_QS3200-1])-(BYTE*)&(para_modu.agc_gain_word[0])+sizeof(uint16));

	memcpy(&(para_file.TDPA_APC_control_word_index[0]),&(para_modu.TDPA_APC_control_word_index[0]),
		(BYTE*)&(para_modu.TDPA_APC_control_word_index[td_calibration_struct_v3::APC_CTL_LEN_QS3200-1])-(BYTE*)&(para_modu.TDPA_APC_control_word_index[0])+sizeof(uint16));

	memcpy( pFileBuf + dwOffsetFile,&para_file,sizeof( para_file ) );
}

static void XTD_Ver4To4( LPBYTE pFileBuf,DWORD dwOffsetFile,BOOL bFileBigEndian,LPBYTE pModuBuf,DWORD dwOffsetModu,BOOL bModuBigEndian )
{
	// 结构全备份
    td_calibration_struct_v4::td_calibration_T para_modu;
    td_calibration_struct_v4::td_calibration_T para_file;

    memcpy( &para_modu,pModuBuf+dwOffsetModu,sizeof( para_modu ) );
    memcpy( &para_file,pFileBuf+dwOffsetFile,sizeof( para_file ) );

	if( bFileBigEndian != bModuBigEndian)
	{
		XTDCaliEndianConvVer4(para_modu);
	}

	memcpy( pFileBuf + dwOffsetFile,&para_modu,sizeof( para_modu ) );
}

static void LTE_Ver1To1( LPBYTE pFileBuf,DWORD dwOffsetFile,BOOL bFileBigEndian,LPBYTE pModuBuf,DWORD dwOffsetModu,BOOL bModuBigEndian )
{
	// 结构全备份
    lte_calibration_struct_v1::LTE_NV_CALI_PARAM_T para_modu;
    lte_calibration_struct_v1::LTE_NV_CALI_PARAM_T para_file;
	
    memcpy( &para_modu,pModuBuf+dwOffsetModu,sizeof( para_modu ) );
    memcpy( &para_file,pFileBuf+dwOffsetFile,sizeof( para_file ) );
	
	if( bFileBigEndian != bModuBigEndian)
	{
		LTECaliEndianConvVer1(para_modu);
	}
	
	memcpy( pFileBuf + dwOffsetFile,&para_modu,sizeof( para_modu ) );
}


DWORD  XTDCaliPreserve(  WORD wID,LPBYTE lpCode, DWORD dwCodeSize, 
                         LPBYTE lpReadBuffer, DWORD dwReadSize,
                         BOOL bOldReplaceNew , BOOL bContinue )
{
	UNUSED_ALWAYS(bOldReplaceNew);


	BOOL bFileBigEndian = FALSE;
	BOOL bModuBigEndian = FALSE;
    DWORD dwOffsetFile=0,dwLengthFile=0;
    BYTE* pFileBuf = lpCode;
	BYTE* pModuBuf = lpReadBuffer;

    // Find calibration
    DWORD dwOffsetModu=0,dwLengthModu=0;
    if(!XFindNVOffsetEx(wID, pModuBuf,dwReadSize,dwOffsetModu,dwLengthModu,bModuBigEndian,TRUE))
    {	
		if( bContinue )
		{
			return ERR_NONE;
		}
		else
		{
			return ERR_NOT_FIND_PARAM_IN_MODULE;
		}	
    }

    WORD wVerModu = *(WORD*)(pModuBuf+dwOffsetModu);
	if(bModuBigEndian)
	{
		wVerModu = CONV_SHORT(wVerModu);
	}

	if(!XFindNVOffsetEx( wID, pFileBuf,dwCodeSize,dwOffsetFile,dwLengthFile,bFileBigEndian,FALSE))
    {		
		return ERR_NOT_FIND_PARAM_IN_FILE;	
    }
	
	WORD wVerFile = *(WORD*)(pFileBuf+dwOffsetFile);
	if(bFileBigEndian)
	{
		wVerFile = CONV_SHORT(wVerFile);
	}

#define XTD_CALI_VER_3            0x0003
#define XTD_CALI_VER_4            0x0004
#define XTD_CALI_VER_5            0x0005
	
	/* Update the timestamp to force nv manager to reload it */
	(*(DWORD*)lpCode) = (DWORD)GetCycleCount();

	DWORD dwSizeAligned = 0;

	if(XTD_CALI_VER_4 == wVerFile)
	{ 
		dwSizeAligned = sizeof( td_calibration_struct_v4::td_calibration_T);
		dwSizeAligned = ((DWORD)((dwSizeAligned + 3)/4)) * 4;
		if( dwLengthFile != dwSizeAligned )
        {
            return ERR_PARAM_LEN_NOT_MATCH_DEF;
        }
		
        if(XTD_CALI_VER_4 == wVerModu)
		{
			if( dwLengthFile == dwLengthModu )
			{
				// Version and length are both equal,just do copying
				//memcpy( pSrc + dwOffsetFile,lpReadBuffer + dwOffset,dwLength );
				XTD_Ver4To4(pFileBuf,dwOffsetFile,bFileBigEndian,pModuBuf,dwOffsetModu,bModuBigEndian);
				return ERR_NONE;
			}
			else
			{
				return ERR_PARAM_LEN_NOT_MATCH;
			}
		}
		else
        {
            return ERR_UNKNOWN_VER_IN_MODULE;
        }		
	} 
	else if(XTD_CALI_VER_3 == wVerFile)
	{ 
		dwSizeAligned = sizeof( td_calibration_struct_v3::td_calibration_T);
		dwSizeAligned = ((DWORD)((dwSizeAligned + 3)/4)) * 4;
		if( dwLengthFile != dwSizeAligned )
        {
            return ERR_PARAM_LEN_NOT_MATCH_DEF;
        }
		
        if(XTD_CALI_VER_3 == wVerModu)
		{
			if( dwLengthFile == dwLengthModu )
			{
				// Version and length are both equal,just do copying
				//memcpy( pSrc + dwOffsetFile,lpReadBuffer + dwOffset,dwLength );
				XTD_Ver3To3(pFileBuf,dwOffsetFile,bFileBigEndian,pModuBuf,dwOffsetModu,bModuBigEndian);
				return ERR_NONE;
			}
			else
			{
				return ERR_PARAM_LEN_NOT_MATCH;
			}
		}
		else
        {
            return ERR_UNKNOWN_VER_IN_MODULE;
        }		
	}   
	else if(XTD_CALI_VER_5 == wVerFile) //backup all contents
	{
		if (XTD_CALI_VER_5 == wVerModu)
		{
			if( dwLengthFile == dwLengthModu )
			{
				memcpy( lpCode + dwOffsetFile,lpReadBuffer + dwOffsetModu,dwLengthModu);
				return ERR_NONE;
			}
			else
			{
				return ERR_PARAM_LEN_NOT_MATCH;
			}
		}
		else
		{
			return ERR_STRUCT_VER_NOT_MATCH;
		}
	}
	else
	{
		return ERR_UNKNOWN_VER_IN_FILE;
	}
	
//	return ERR_NONE;
}

DWORD XPreserveNVItem(  WORD wID, LPBYTE lpCode, DWORD dwCodeSize, 
					  LPBYTE lpReadBuffer, DWORD dwReadSize,
					  BOOL bOldReplaceNew/*=FALSE*/, BOOL bContinue/*=FALSE*/ )
{
	UNUSED_ALWAYS(bOldReplaceNew);

    if( wID == GSM_CALI_ITEM_ID || wID == XTD_CALI_ITEM_ID ) // CALI 结构复杂单独处理
	{
        return ERR_NONE;    
	}    
    
    DWORD dwOffsetFile,dwLengthFile;
	DWORD dwOffsetModu,dwLengthModu;
	BOOL  bFileBigEndian = FALSE;
	BOOL  bModuBigEndian = FALSE;

    if(!XFindNVOffsetEx( wID, lpReadBuffer,dwReadSize,dwOffsetModu,dwLengthModu,bModuBigEndian,TRUE))
    {		
		if( bContinue )
		{
			return ERR_NONE;
		}
		else
		{
			return ERR_NOT_FIND_PARAM_IN_MODULE;
		}	
	}
	
	if(!XFindNVOffsetEx( wID, lpCode, dwCodeSize,dwOffsetFile,dwLengthFile,bFileBigEndian,FALSE))
    {		
		return ERR_NOT_FIND_PARAM_IN_FILE;
	}

    if(dwLengthModu != dwLengthFile)
    {        
        return ERR_PARAM_LEN_NOT_MATCH;
    }

	if(wID == BT_ITEM_ID && bModuBigEndian != bFileBigEndian ) // BT
	{
		DWORD dwSizeAligned = sizeof(BT_CONFIG);
		dwSizeAligned = ((DWORD)((dwSizeAligned + 3)/4)) * 4;		
		if(dwLengthFile != dwSizeAligned)
		{
			return ERR_PARAM_LEN_NOT_MATCH_DEF;
		}

		BT_CONFIG para = {0};
		memcpy(&para,lpReadBuffer+dwOffsetModu,dwLengthModu);
		if(bModuBigEndian != bFileBigEndian)
		{
			BTConvEndian(para);
		}

		memcpy( lpCode + dwOffsetFile, &para,dwLengthModu);
	}
	else
	{
		memcpy( lpCode + dwOffsetFile,
				lpReadBuffer + dwOffsetModu,
				dwLengthModu);
	}

    
    return ERR_NONE;    
}

BOOL XCheckGSMCali(WORD wId,LPBYTE lpPhoBuf,DWORD dwPhoSize,std::string &strErr,BOOL bModule)
{
	char szErr[MAX_PATH] = {0};
	DWORD dwPhoCaliFlag=0;
	DWORD dwOffsetPho=0;
	DWORD dwLengthPho=0;
    BYTE* pSrcPho = lpPhoBuf;

	BOOL bBigEndian = FALSE;

    if(!XFindNVOffsetEx( wId,pSrcPho,dwPhoSize,dwOffsetPho,dwLengthPho,bBigEndian,bModule))
    {      
		sprintf(szErr,_T("!!!Not found GSM cali in phone,[ID=0x%x]"),wId);
		strErr  = szErr;
		return FALSE;

    }
	LPBYTE pCaliBuf = pSrcPho + dwOffsetPho;
	WORD wVerPho = *(WORD*)pCaliBuf;

	if(bBigEndian)
	{
		wVerPho = CONV_SHORT(wVerPho);
	}

	if (GSM_CALI_VER_A == wVerPho) //0xFF0A
	{
		calibration_struct_va::calibration_param_T paraPho;	
		if(dwLengthPho != sizeof(paraPho))
		{
			sprintf(szErr,_T("!!!GSM Cali length in phone is wrong,[Ver=0xFF0A,ID=0x%x]"),wId);
	    		strErr  = szErr;
			return FALSE;
		} 
		
		memcpy( &paraPho,pSrcPho+dwOffsetPho,sizeof( paraPho ) );
		dwPhoCaliFlag = paraPho.adc.reserved[7];
	}
	else if ( GSM_CALI_VER_B == wVerPho )//0xFF0B
	{
		calibration_struct_vb::calibration_param_T paraPho;	
		if(dwLengthPho != sizeof(paraPho))
		{
			sprintf(szErr,_T("!!!GSM Cali length in phone is wrong,[Ver=0xFF0B,ID=0x%x]"),wId);
	    	strErr  = szErr;
			return FALSE;
		} 
		memcpy( &paraPho,pSrcPho+dwOffsetPho,sizeof( paraPho ) );
		dwPhoCaliFlag = paraPho.adc.reserved[7];
	}
	else
	{
	    sprintf(szErr,_T("!!!GSM Cali version in phone is wrong,[ID=0x%x]"),wId);
	    strErr  = szErr;
		return FALSE;
	}

	if(bBigEndian)
	{
		dwPhoCaliFlag = CONV_DWORD(dwPhoCaliFlag);
	}

	//not calibrated : In addition to the bit27, other bits is 0  
	if( (dwPhoCaliFlag & 0xF7FFFFFF) == 0)
	{	
		sprintf(szErr,_T("!!!GSM Cali in phone is not calibrated,Reserved[7]:0x%08X,[ID=0x%x]"),dwPhoCaliFlag,wId);
	    strErr  = szErr;
			
		return FALSE;
	}

	return TRUE;
}

BOOL XFindNVOffsetEx(WORD wId,LPBYTE lpCode,DWORD dwCodeSize,
                      DWORD& dwOffset,DWORD& dwLength,BOOL &bBigEndian,BOOL bModule)
{
	BOOL bOK = FALSE;
	BOOL _bBigEndian = FALSE;
	if( XCheckNVStructEx(lpCode,dwCodeSize,_bBigEndian,bModule) )
	{
		if(XFindNVOffset(wId,lpCode,dwCodeSize,dwOffset,dwLength, _bBigEndian))
		{
			bOK = TRUE;
		}
	}

	bBigEndian = _bBigEndian;

	return bOK;
}

static BOOL XCheckNVStruct(const LPBYTE lpPhoBuf, DWORD dwPhoSize,BOOL bBigEndian, BOOL bModule )
{
	UNUSED_ALWAYS(bModule);

    DWORD dwOffset=0,dwLength=0;
	BYTE* lpCode = lpPhoBuf;
	DWORD dwCodeSize = dwPhoSize;
	WORD wCurID;
	dwOffset = 4;     // Skip first four bytes,that is time stamp 
    dwLength = 0;
    BYTE* pTemp = lpCode + dwOffset;

	BOOL bIMEI = FALSE;
	BOOL bGSMCali = FALSE;
	WORD wGSMCaliVer = 0;
    
    while(dwOffset < dwCodeSize)
    {
		wCurID = *(uint16*)pTemp;
		if(bBigEndian)
		{
			wCurID = CONV_SHORT(wCurID);
		}
        pTemp += 2;

		dwLength = *(uint16*)pTemp;
		if(bBigEndian)
		{
			dwLength = CONV_SHORT(dwLength);
		}

		if(wCurID == GSM_IMEI_ITEM_ID)
		{
			if(dwLength != IMEI_LEN)
			{
				return FALSE;
			}
			else
			{
				bIMEI = TRUE;
			}
		}
		else if(wCurID == GSM_CALI_ITEM_ID)
		{
			wGSMCaliVer =  *(uint16*)(pTemp+2); // pTemp+2: skip length
			if(bBigEndian)
			{
				wGSMCaliVer = CONV_SHORT(wGSMCaliVer);
			}	
			
			if( wGSMCaliVer > GSM_CALI_VER_MAX || wGSMCaliVer < GSM_CALI_VER_MIN )
			{
				return FALSE;
			}
			else
			{
				bGSMCali = TRUE;
			}
			
		}

		// 0xFFFF is end-flag in module (NV in phone device)
		if( wCurID == 0xFFFF)
		{
			if(!bIMEI || !bGSMCali)
			{
				return FALSE;
			}
			return TRUE;
		} 

		if(wCurID == 0 && dwLength == 0)
		{
			break;
		}

        pTemp += 2;
        dwOffset += 4;
        // Must be four byte aligned
        BYTE bRet = (BYTE)(dwLength % 4);
        if(bRet != 0)
        {
            dwLength += 4 - bRet;
        }	       
        
        dwOffset += dwLength;
        pTemp += dwLength;
		
		// (dwOffset == dwCodeSize) is end condition in File
		if( dwOffset == dwCodeSize)
		{
			if(!bIMEI || !bGSMCali)
			{
				return FALSE;
			}
			return TRUE;
		}        
    }

	return FALSE;
    
//  if(bStrict)
// 	{
// 		return FALSE;
// 	}
// 	else
// 	{
// 		if(bIMEI)
// 		{
// 			return TRUE;
// 		}
// 		else
// 		{
// 			return FALSE;
// 		}
// 	}
}

BOOL  XCheckNVStructEx(LPBYTE lpPhoBuf, DWORD dwPhoSize,BOOL &bBigEndian,BOOL bModule )
{
    BOOL bOK = TRUE;
	BOOL _bBigEndian = FALSE;
	if(!XCheckNVStruct(lpPhoBuf,dwPhoSize,_bBigEndian,bModule))
	{
		_bBigEndian = TRUE;
		if(!XCheckNVStruct(lpPhoBuf,dwPhoSize,_bBigEndian,bModule))
		{
			bOK = FALSE;
		}
	}
	if(!bOK && bModule)
	{
		bOK = TRUE;
		_bBigEndian = FALSE;
		
		LPBYTE pBuf = new BYTE[dwPhoSize];		
		memcpy(pBuf,lpPhoBuf,dwPhoSize);

		LPDWORD pdwBuf = (LPDWORD)pBuf;
		DWORD dwSize = dwPhoSize / 4;
		for(UINT i = 0; i< dwSize; i++)
		{
			DWORD dwTmp = *(pdwBuf+i);
			*(pdwBuf+i) = CONV_DWORD(dwTmp);
		}
		if(!XCheckNVStruct(pBuf,dwPhoSize,_bBigEndian,bModule))
		{
			_bBigEndian = TRUE;
			if(!XCheckNVStruct(pBuf,dwPhoSize,_bBigEndian,bModule))
			{
				bOK = FALSE;
			}
		}
		if(bOK)
		{
			memcpy(lpPhoBuf,pBuf,dwPhoSize);
			delete[] pBuf;
		}
	}
    bBigEndian = _bBigEndian;
    return bOK;
}

/*
BOOL  XSetRandomBT( WORD wId, LPBYTE lpCode, DWORD dwCodeSize, const BT_CONFIG &bt)
{
    DWORD dwOffsetFile=0,dwLengthFile=0;
	BOOL  bFileBigEndian = TRUE;

    if(!XFindNVOffsetEx( wId, lpCode, dwCodeSize,dwOffsetFile,dwLengthFile,bFileBigEndian))
    {		
		return FALSE;
	}

	memcpy( lpCode + dwOffsetFile + ((DWORD)&bt.bt_addr[0] - (DWORD)&bt), &bt.bt_addr[0], BT_ADDR_LEN);

	return TRUE;
}*/

DWORD  XPreserveIMEIs( std::vector<UINT> &agIMEIID,LPBYTE lpCode, DWORD dwCodeSize,
					  LPBYTE lpReadBuffer, DWORD dwReadSize, int &nFailedIMEIIndex,
					  BOOL bOldReplaceNew/*=FALSE*/, BOOL bContinue/*=FALSE*/)
{
	DWORD dwRet = ERR_NONE;
	nFailedIMEIIndex = -1;

	int nIDCount = agIMEIID.size();
	for(int i = 0; i< nIDCount; i++)
	{
		WORD wID = (WORD)agIMEIID[i];
		if( wID == GSM_IMEI_ITEM_ID)
		{
			dwRet = XPreserveNVItem(wID,lpCode,dwCodeSize,
				                    lpReadBuffer,dwReadSize,bOldReplaceNew,bContinue);
		}
		else
		{
			dwRet = XPreserveNVItem(wID,lpCode,dwCodeSize,
				                    lpReadBuffer,dwReadSize,bOldReplaceNew,TRUE);
		}

		if(dwRet != ERR_NONE)
		{
			nFailedIMEIIndex = i;
			break;
		}
	}

	return dwRet;
}


DWORD  LTECaliPreserve(  LPBYTE lpCode, DWORD dwCodeSize,
                         LPBYTE lpReadBuffer, DWORD dwReadSize,
                         BOOL bOldReplaceNew , BOOL bContinue )
{
	UNUSED_ALWAYS(bOldReplaceNew);


	BOOL bFileBigEndian = TRUE;
	BOOL bModuBigEndian = TRUE;
    DWORD dwOffsetFile=0,dwLengthFile=0;
    BYTE* pFileBuf = lpCode;
	BYTE* pModuBuf = lpReadBuffer;

    if(!XFindNVOffsetEx( LTE_CALI_ITEM_ID, pFileBuf,dwCodeSize,dwOffsetFile,dwLengthFile,bFileBigEndian,FALSE))
    {
		return ERR_NOT_FIND_PARAM_IN_FILE;
    }

	WORD wVerFile = *(WORD*)(pFileBuf+dwOffsetFile);
	if(bFileBigEndian)
	{
		wVerFile = CONV_SHORT(wVerFile);
	}

    // Find calibration
    DWORD dwOffsetModu=0,dwLengthModu=0;
    if(!XFindNVOffsetEx(LTE_CALI_ITEM_ID, pModuBuf,dwReadSize,dwOffsetModu,dwLengthModu,bModuBigEndian,TRUE))
    {
		if( bContinue )
		{
			return ERR_NONE;
		}
		else
		{
			return ERR_NOT_FIND_PARAM_IN_MODULE;
		}
    }

    WORD wVerModu = *(WORD*)(pModuBuf+dwOffsetModu);
	if(bModuBigEndian)
	{
		wVerModu = CONV_SHORT(wVerModu);
	}

#define LTE_CALI_VER_1            0x0001

	/* Update the timestamp to force nv manager to reload it */
	(*(DWORD*)lpCode) = (DWORD)GetCycleCount();

	DWORD dwSizeAligned = 0;

	if(LTE_CALI_VER_1 == wVerFile)
	{
		dwSizeAligned = sizeof( lte_calibration_struct_v1::LTE_NV_CALI_PARAM_T);
		dwSizeAligned = ((DWORD)((dwSizeAligned + 3)/4)) * 4;
		if( dwLengthFile != dwSizeAligned )
        {
            return ERR_PARAM_LEN_NOT_MATCH_DEF;
        }

        if(LTE_CALI_VER_1 == wVerModu)
		{
			if( dwLengthFile == dwLengthModu )
			{
				// Version and length are both equal,just do copying
				//memcpy( pSrc + dwOffsetFile,lpReadBuffer + dwOffset,dwLength );
				LTE_Ver1To1(pFileBuf,dwOffsetFile,bFileBigEndian,pModuBuf,dwOffsetModu,bModuBigEndian);
				return ERR_NONE;
			}
			else
			{
				return ERR_PARAM_LEN_NOT_MATCH;
			}
		}
		else
        {
            return ERR_UNKNOWN_VER_IN_MODULE;
        }
	}
	else
	{
		return ERR_UNKNOWN_VER_IN_FILE;
	}

//	return ERR_NONE;
}
