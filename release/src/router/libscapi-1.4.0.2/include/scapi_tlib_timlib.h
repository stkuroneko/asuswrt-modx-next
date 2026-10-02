/******************************************************************************
 **   SRC_FILE			: UGW_TLIB_Timelib.h
 **   PROJECT			: EasyPort/IAD, DC BANGALORE
 **   MODULES			:   
 **   SRC VERSION		: Version 1.0
 **   DATE				: 11-02-2003
 **   AUTHOR			: Bharathraj Shetty
 **   DESCRIPTION		:  
 **   FUNCTIONS			: None
 **   COMPILER			: 
 **   REFERENCE			: 
						Coding Guidelines (Easyport-VSS-COD-V1.0)
                    	Author: EasyPort Team
 **   COPYRIGHT			: Infineon Technologies AG 1999-2003
 **  Version Control Section  **        
 **   $Author$    
 **   $Date$      
 **   $Revisions$ 
 **   $Log$     
 *****************************************************************************/

#ifndef _UGW_TLIB_TIMLIB_H_
# define _UGW_TLIB_TIMLIB_H_

#define UGW_TLIB_ONE_TIME_TIMER 0
#define UGW_TLIB_PERIODIC_TIMER 1

#define UGW_TLIB_FAIL 0
#define UGW_TLIB_SUCCESS 1
#define UGW_TLIB_INVALID_TIMER_ID 2

/*Timer Notify Type*/
#define UGW_TLIB_NOTIFY_VIA_SIGNAL 1
#define UGW_TLIB_NOTIFY_VIA_FD 2
#define TIMER_DRV_MODE_CHANGE 2

#define TRUE 1
#define FALSE 0

typedef void (* pfnVoidFunctPtr)(void *);

typedef struct  {
	
					uint8 ucFree;
					uint16 unTimerIndex;
					uint32 uiTimerValue;
					uint32 uiTimerTick;
					uint8 ucTimerType;
					pfnVoidFunctPtr pfn_UGW_TLIB_CallBackfn;
					void *pCallBackFnParm;
					uint16 unPrevIndex;
					uint16 unNextIndex;
				 }x_UGW_TLIB_TimerInfo;
						  
x_UGW_TLIB_TimerInfo *pxTimerList;
	
					
struct x_UGW_TLIB_TimMgtInfo{
				x_UGW_TLIB_TimerInfo *pxTimerList;
				uint16 unActTimLstHeadIndex;
				uint16 unFreeTimLstHeadIndex;
				uint16 unFreeTimLstTailIndex;
				uint16 unMaxNumOfTimer;
			 }vx_UGW_TLIB_TimMgtInfo;


int8 UGW_TLIB_TimersInit(uint16 unNumOfTimers,uchar8);

int8 UGW_TLIB_StartTimer(uint16 *punTimerId,uint32 uiTimerValue,
		uint8 ucTimerType, pfnVoidFunctPtr pfn_UGW_TLIB_CallBackfn,
	  void *pCallBackFnParm);

int32 UGW_TLIB_StopTimer(uint16 unTimerId);

int8 UGW_TLIB_TimersDelete(void);						

void UGW_TLIB_InitializeTimerList(uint16 unNumOfTimers);

void UGW_TLIB_InsertTimerIntoActList(x_UGW_TLIB_TimerInfo *pxTempNode,
		uint32 uiTimerValue,uint8 ucTimerType,
		pfnVoidFunctPtr pfn_UGW_TLIB_CallBackfn, void *pCallBackFnParm);

int8 UGW_TLIB_GetTimerNode(x_UGW_TLIB_TimerInfo **pxTimerNode);

void UGW_TLIB_InitializeTimerNode(x_UGW_TLIB_TimerInfo *pxTimerNode,
		uint32 uiTimerValue,uint8 ucTimerType,
		pfnVoidFunctPtr pfn_UGW_TLIB_CallBackfn, void *pCallBackFnParm);

void UGW_TLIB_SetTimer(uint32 uiUsec);

void UGW_TLIB_FreeListHandler(x_UGW_TLIB_TimerInfo *pxTempNode);

void  UGW_TLIB_CurrTimerExpiry(int);
int8 IFIN_TLIB_TimersInit(uint16);
int8 IFIN_TLIB_TimersDelete(void);

uint32 UGW_TLIB_GetCurrTime(void);

int8 UGW_TLIB_CheckForEqualTimer(uint32 uiCurrTime);
int8 IFIN_TLIB_StartTimer(uint16 *, uint32, uint8, pfnVoidFunctPtr, void *);
int32 IFIN_TLIB_StopTimer(uint16);



#endif
