/******************************************************************************
 **  SRC_FILE			: UGW_TLIB_Timelib.c
 **   PROJECT			: EasyPort/IAD, DC BANGALORE
 **   MODULES				:
 **   SRC VERSION		: Version 1.0
 **   DATE				: 11-02-2003
 **   AUTHOR			: Bharathraj Shetty
 **   DESCRIPTION		:  
 **   FUNCTIONS			: None
 **   COMPILER			: 
 **   REFERENCE			: 
						Coding Guidelines (Easyport-VSS-COD-V2.0)
                    	Author: EasyPort Team
 **   COPYRIGHT			: Infineon Technologies AG 1999-2003
 **  Version Control Section  **        
 **   $Author$    
 **   $Date$      
 **   $Revisions$ 
 **   $Log$     
 *****************************************************************************/
#include <sys/time.h>
#include <sys/times.h>
#include <time.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/ioctl.h>		/* ioctl */
#include <fcntl.h>
#include "scapi_basic_types.h"
#include "scapi_tlib_timlib.h"
#ifdef DMALLOC
#include<dmalloc.h>
#endif

#define printf(...)
pthread_mutex_t global_timer_mutex = PTHREAD_MUTEX_INITIALIZER;
uchar8 vucTimerNotifyType;
uint32 vuiTimerLibFd;  				
uint32 UGW_TLIB_ConvertTicksToTime(uint32 uiTicks);
uint32 UGW_TLIB_ConvertTimeToTicks(uint32 uiTime);

static void UGW_TLIB_PrintTimerList(void)
{
	uint16 unIi;
	printf("----------------Timers in use are-----------------\n");
	printf("| INDEX   |TimerId     | IsFree          | TimerTick  |\n");
	for(unIi=1;unIi<=vx_UGW_TLIB_TimMgtInfo.unMaxNumOfTimer;unIi++)
	{
		if(vx_UGW_TLIB_TimMgtInfo.pxTimerList[unIi-1].ucFree != TRUE){
			 printf("|%d  | %d          |%d                | %d   |\n",
					   unIi-1,vx_UGW_TLIB_TimMgtInfo.pxTimerList[unIi-1].unTimerIndex,
						 vx_UGW_TLIB_TimMgtInfo.pxTimerList[unIi-1].ucFree,
							vx_UGW_TLIB_TimMgtInfo.pxTimerList[unIi-1].uiTimerTick);
		}
	}
	printf("----------------------------------------------------\n");

}
/*****************************************************************************
*  Name: UGW_TLIB_TimerInit
*  Function: This routine is initializes timer data structure
*  Input: unNumOfTimers
*  Output: None
*  Return Value: INT16 returns success or fail.
******************************************************************************/						
int8 UGW_TLIB_TimersInit(uint16 unNumOfTimers, uchar8 ucTimerNotifyType)
{
	vucTimerNotifyType = ucTimerNotifyType;
	int32 iflag;
	if(vucTimerNotifyType == UGW_TLIB_NOTIFY_VIA_SIGNAL){
		struct sigaction act, oact;
		/* Call the signal catching function */		
		act.sa_handler = UGW_TLIB_CurrTimerExpiry;
		sigemptyset(&act.sa_mask);
		act.sa_flags = 0;
		act.sa_flags |= SA_RESTART;
		sigaction(SIGALRM,&act,&oact);
	}
	else if(vucTimerNotifyType == UGW_TLIB_NOTIFY_VIA_FD)
	{
		if (access ("/dev/voip_timer_driver", O_RDWR) != 0){         
			system("mknod /dev/voip_timer_driver c 229 0");
		}
		iflag = open("/dev/voip_timer_driver",O_RDWR);
		if(iflag < 0)
		{
			printf("TimerInit Failed ErrCd = %d\n",iflag);			 
			return UGW_TLIB_FAIL;
		}
		vuiTimerLibFd = iflag;
	}
          
	vx_UGW_TLIB_TimMgtInfo.unMaxNumOfTimer = unNumOfTimers;
	
	/* Allocate memory for the Timer node data structure,
	here the number of timer nodes = Num of timers  */
	if((vx_UGW_TLIB_TimMgtInfo.pxTimerList =
		 (x_UGW_TLIB_TimerInfo *)calloc(1,unNumOfTimers * 
		 (sizeof(x_UGW_TLIB_TimerInfo)))) != NULL)
	{
		/* Initialize the free timer list */
		UGW_TLIB_InitializeTimerList(unNumOfTimers);
		
		/* Initialize the active list header to zero */
		vx_UGW_TLIB_TimMgtInfo.unActTimLstHeadIndex = 0;	
		
		return UGW_TLIB_SUCCESS;
	}
	else
	{
		return UGW_TLIB_FAIL;
	}
}

/******************************************************************************
*  Name: UGW_TLIB_InitlializeTimerList
*  Function: This routine is initializes all Timer nodes in a free timer list
*  Input: unNumOfTimers
*  Output: None
*  Return Value: None
******************************************************************************/	
void UGW_TLIB_InitializeTimerList(uint16 unNumOfTimers)
{
	uint16 unIi;
	
	for(unIi=1;unIi<=unNumOfTimers;unIi++)
	{
		vx_UGW_TLIB_TimMgtInfo.pxTimerList[unIi-1].ucFree = TRUE;
		vx_UGW_TLIB_TimMgtInfo.pxTimerList[unIi-1].unTimerIndex = unIi;
		vx_UGW_TLIB_TimMgtInfo.pxTimerList[unIi-1].unPrevIndex = unIi-1;
		vx_UGW_TLIB_TimMgtInfo.pxTimerList[unIi-1].uiTimerValue = 0;
		vx_UGW_TLIB_TimMgtInfo.pxTimerList[unIi-1].uiTimerTick = 0;
		if(unIi == unNumOfTimers)
		{
			vx_UGW_TLIB_TimMgtInfo.pxTimerList[unIi-1].unNextIndex = 0;
			vx_UGW_TLIB_TimMgtInfo.unFreeTimLstTailIndex =
					vx_UGW_TLIB_TimMgtInfo.pxTimerList[unIi-1].unTimerIndex;
				
		}
		else
		{
			vx_UGW_TLIB_TimMgtInfo.pxTimerList[unIi-1].unNextIndex = unIi+1;
		}
	
	}
	vx_UGW_TLIB_TimMgtInfo.unFreeTimLstHeadIndex =
			vx_UGW_TLIB_TimMgtInfo.pxTimerList[0].unTimerIndex;

	return;
}

/******************************************************************************
*  Name: UGW_TLIB_StartTimer
*  Function: This routine starts the timer.
*  Input: uiTimerValue,ucTimerType, pfn_UGW_TLIB_CallBackfn, pCallBackFnParm
*  Output: punTimerId
*  Return Value: None
******************************************************************************/
int8 UGW_TLIB_StartTimer(uint16 *punTimerId,uint32 uiTimerValue,
						uint8 ucTimerType, pfnVoidFunctPtr pfn_UGW_TLIB_CallBackfn,
						void *pCallBackFnParm)
{
	x_UGW_TLIB_TimerInfo *pxTempNode = NULL;	

	if(uiTimerValue == 0)
	{
		return UGW_TLIB_FAIL;
	}
	if(vucTimerNotifyType == UGW_TLIB_NOTIFY_VIA_SIGNAL){	
		pthread_mutex_lock(&global_timer_mutex);
	}else{
		UGW_TLIB_PrintTimerList();
	}
  /* Get the fresh node from free list of timers */
	if(UGW_TLIB_GetTimerNode(&pxTempNode) != UGW_TLIB_FAIL)
	{
		*punTimerId = pxTempNode->unTimerIndex;

		/* Insert new node in an appropriate position in active list */
		UGW_TLIB_InsertTimerIntoActList(pxTempNode,uiTimerValue,ucTimerType,
				pfn_UGW_TLIB_CallBackfn,pCallBackFnParm);

		if(vucTimerNotifyType == UGW_TLIB_NOTIFY_VIA_SIGNAL){	
			pthread_mutex_unlock(&global_timer_mutex);
		}
			return UGW_TLIB_SUCCESS;
	}
	else
	{
		if(vucTimerNotifyType == UGW_TLIB_NOTIFY_VIA_SIGNAL){	
			pthread_mutex_unlock(&global_timer_mutex);
		}
			return UGW_TLIB_FAIL;
	}
}

/*****************************************************************************
*  Name: UGW_TLIB_InsertTimerIntoActList
*  Function: This routine inserts the timer into active list of timers
*  Input: pxTempNode,uiTimerValue,ucTimerType, pfn_UGW_TLIB_CallBackfn,
					pCallBackFnParm
*  Output:None
*  Return Value: success or fail.
******************************************************************************/
					 
void UGW_TLIB_InsertTimerIntoActList(x_UGW_TLIB_TimerInfo *pxTempNode,
			uint32 uiTimerValue,uint8 ucTimerType,
			pfnVoidFunctPtr pfn_UGW_TLIB_CallBackfn, void *pCallBackFnParm)

{

	x_UGW_TLIB_TimerInfo *pxTempNextNode,*pxTempActLstNode;
	uint32 uiTimeElapse,uiTempTimeElapse,uiTimeLeft,uiNextTimeLeft,uiCurrTick;

	/* Initialize the new timer node */	
	UGW_TLIB_InitializeTimerNode(pxTempNode,uiTimerValue,ucTimerType,
			pfn_UGW_TLIB_CallBackfn,pCallBackFnParm);
		
	/* CLOCKT_CurrTick is number of milliseconds expired since
				system is started */
	uiCurrTick = UGW_TLIB_GetCurrTime();
		
	/* The active list is empty */
	if(vx_UGW_TLIB_TimMgtInfo.unActTimLstHeadIndex == 0)
	{
		printf("Active List Empty\n");
		vx_UGW_TLIB_TimMgtInfo.unActTimLstHeadIndex = pxTempNode->unTimerIndex;
		pxTempActLstNode = vx_UGW_TLIB_TimMgtInfo.pxTimerList +
					(vx_UGW_TLIB_TimMgtInfo.unActTimLstHeadIndex - 1);		

		pxTempActLstNode->uiTimerTick = uiCurrTick;
		pxTempActLstNode->unPrevIndex = 0;
		pxTempActLstNode->unNextIndex = 0;
		printf("Timer started for %d ms\n",uiTimerValue/1000);
		/*Start the Timer */
		UGW_TLIB_SetTimer(uiTimerValue);
					
	}
	else
	{
		printf("Active list not empty\n");
		pxTempActLstNode = vx_UGW_TLIB_TimMgtInfo.pxTimerList +
					(vx_UGW_TLIB_TimMgtInfo.unActTimLstHeadIndex - 1);		
			
		uiTimeElapse = UGW_TLIB_ConvertTicksToTime((uiCurrTick - pxTempActLstNode->uiTimerTick));
			
		/* Check whether timer in an active list is already elapsed or not */
		if(pxTempActLstNode->uiTimerValue > uiTimeElapse)
		{
			uiTimeLeft = pxTempActLstNode->uiTimerValue - uiTimeElapse;
		}
		else
		{
			uiTimeLeft = 0;
		}
		printf("Time Left with old timer is %d us\n",uiTimeLeft);
		/*Insert timer at the beginning of active list */
		if(uiTimerValue < uiTimeLeft)
		{
			printf("New timer value is less than time left\n");		
			/* Store the Timer tick at creation of timer node */
			pxTempNode->uiTimerTick = uiCurrTick;
			/*adjust the prev index * next index for 1st and 2nd nodes */
			pxTempNode->unPrevIndex = 0;
			pxTempNode->unNextIndex = pxTempActLstNode->unTimerIndex;
			pxTempActLstNode->unPrevIndex = pxTempNode->unTimerIndex;
			/* Time elapse for the 2nd node = Time Elapse for 2nd node +
						 Timervalue of 1st node */
			pxTempActLstNode = pxTempNode;
			/* The active timer list header points to first node */
				
			vx_UGW_TLIB_TimMgtInfo.unActTimLstHeadIndex =
						pxTempActLstNode->unTimerIndex;

			printf("Timer started for %d ms\n",uiTimerValue/1000);
			UGW_TLIB_SetTimer(uiTimerValue);
		}
		else
		{
			printf("Inserted the new timer in b/w\n");
			/*Traverse the Active list of timers to insert the list in
						an appropriate position */
			while(pxTempActLstNode != NULL)
			{

				/* Add at the end of list */
				if(pxTempActLstNode->unNextIndex == 0)
				{

					/* Store the Timer tick at creation of timer node */
					pxTempNode->uiTimerTick = uiCurrTick;

					pxTempActLstNode->unNextIndex = pxTempNode->unTimerIndex;
					pxTempNode->unPrevIndex = pxTempActLstNode->unTimerIndex;
					pxTempNode->unNextIndex = 0;
			
					break;
				}
				else
				{

					pxTempNextNode = vx_UGW_TLIB_TimMgtInfo.pxTimerList +
						(pxTempActLstNode->unNextIndex - 1);
					uiTempTimeElapse = UGW_TLIB_ConvertTicksToTime(
                                                            (uiCurrTick - pxTempNextNode->uiTimerTick));
						
					/* Check whether next timer in an active list
							is already elapsed or not*/
					if(pxTempNextNode->uiTimerValue > uiTempTimeElapse)
					{
						uiNextTimeLeft = pxTempNextNode->uiTimerValue - uiTempTimeElapse;
					}
					else
					{
						uiNextTimeLeft = 0;
					}

					/*Insert timer at the Middle of active list */
					if((uiTimerValue >= uiTimeLeft) && (uiTimerValue < uiNextTimeLeft))
					{
							
						/* Store the Timer tick at creation of timer node */
						pxTempNode->uiTimerTick = uiCurrTick;

						pxTempActLstNode->unNextIndex = pxTempNode->unTimerIndex;
						pxTempNode->unPrevIndex = pxTempActLstNode->unTimerIndex;
						pxTempNode->unNextIndex = pxTempNextNode->unTimerIndex;
						pxTempNextNode->unPrevIndex = pxTempNode->unTimerIndex;
						break;

					}
					/*Traverse to next node in an active list */
					else
					{
						/* Go to next node */
						pxTempActLstNode=pxTempNextNode;
						/* Time elapse and time left of next node becomes current node */
						uiTimeElapse = uiTempTimeElapse;
						uiTimeLeft = uiNextTimeLeft;
					}
				}
			}
		}

	}
}

/****************************************************************************
*  Name: UGW_TLIB_GetTimerNode
*  Function: This node gets the fresh node from the Free list of timers
*  Input: pxTimerNode
*  Output:pxTimerNode
*  Return Value: either success or fail. 
*****************************************************************************/

int8 UGW_TLIB_GetTimerNode(x_UGW_TLIB_TimerInfo **pxTimerNode)
{
	uint16 unTempFreeTimLstHeadIndex;
	/* If the Free list of timers is not NULL */
	if((vx_UGW_TLIB_TimMgtInfo.unFreeTimLstHeadIndex != 0) &&
		 (vx_UGW_TLIB_TimMgtInfo.unFreeTimLstTailIndex != 0))
	{
		unTempFreeTimLstHeadIndex=vx_UGW_TLIB_TimMgtInfo.unFreeTimLstHeadIndex-1;
		/* Attach free node to pxTimerNode */
		*pxTimerNode = vx_UGW_TLIB_TimMgtInfo.pxTimerList +
					unTempFreeTimLstHeadIndex;

		(*pxTimerNode)->ucFree = FALSE;
		
		
		/*Update free list */
		if(vx_UGW_TLIB_TimMgtInfo.pxTimerList  
			[unTempFreeTimLstHeadIndex].unNextIndex != 0)
		{
			vx_UGW_TLIB_TimMgtInfo.unFreeTimLstHeadIndex = vx_UGW_TLIB_TimMgtInfo 
						.pxTimerList[unTempFreeTimLstHeadIndex].unNextIndex;

			vx_UGW_TLIB_TimMgtInfo.pxTimerList
				[vx_UGW_TLIB_TimMgtInfo.unFreeTimLstHeadIndex-1].unPrevIndex = 0;
		}
		else
		{
			vx_UGW_TLIB_TimMgtInfo.unFreeTimLstHeadIndex = 0;
			vx_UGW_TLIB_TimMgtInfo.unFreeTimLstTailIndex = 0;
		}
		return UGW_TLIB_SUCCESS;
	}
	else
	{
		/* return fail for out of memory  */
		return UGW_TLIB_FAIL;
	}

}

/*************************************************************************
*  Name: UGW_TLIB_InitializeTimerNode
*  Function: This function initializes the Timer Node
*  Input: pxTimerNode,uiTimerValue,ucTimerType, pfn_UGW_TLIB_CallBackfn,
					pCallBackFnParm
*  Output:None
*  Return Value: none. 
**************************************************************************/
void UGW_TLIB_InitializeTimerNode(x_UGW_TLIB_TimerInfo *pxTimerNode,
			uint32 uiTimerValue,uint8 ucTimerType,
			pfnVoidFunctPtr pfn_UGW_TLIB_CallBackfn, void *pCallBackFnParm)

{
	/* Set the Timer node fields */
	pxTimerNode->uiTimerValue = uiTimerValue;
	pxTimerNode->ucTimerType = ucTimerType;
	pxTimerNode->pfn_UGW_TLIB_CallBackfn = pfn_UGW_TLIB_CallBackfn;
	pxTimerNode->pCallBackFnParm = pCallBackFnParm;
	
}

/****************************************************************************
*  Name: UGW_TLIB_StopTimer
*  Function: This functions stops the timer
*  Input: unTimerId
*  Output:None
*  Return Value: success or fail. 
*****************************************************************************/
int32 UGW_TLIB_StopTimer(uint16 unTimerId)
{
	x_UGW_TLIB_TimerInfo *pxTempNode,*pxPrevTempNode,*pxNextTempNode;
	clock_t CLOCKT_CurrTick;
	uint32 uiTimeLeft;

	/* Check for valid timer id */ 	
	if((unTimerId <= 0) || (unTimerId > vx_UGW_TLIB_TimMgtInfo.unMaxNumOfTimer))
	{
		return UGW_TLIB_INVALID_TIMER_ID;

	}

	pxTempNode = vx_UGW_TLIB_TimMgtInfo.pxTimerList + (unTimerId - 1);

	if(vucTimerNotifyType == UGW_TLIB_NOTIFY_VIA_SIGNAL){	
		pthread_mutex_lock(&global_timer_mutex);
	}else{
		printf("Timer ID that got stoped is %d\n",pxTempNode->unTimerIndex);
	}
	
	/* Check whether node is already freed */
	if(pxTempNode->ucFree == FALSE)
	{
  
		CLOCKT_CurrTick = UGW_TLIB_GetCurrTime();
		/*Return Time left */
		uiTimeLeft = UGW_TLIB_ConvertTicksToTime((CLOCKT_CurrTick - pxTempNode->uiTimerTick));
		if(uiTimeLeft > pxTempNode->uiTimerValue)
		{
			uiTimeLeft = 0;
		}
		else
		{
			uiTimeLeft = pxTempNode->uiTimerValue - uiTimeLeft;
		}
		
		/*Delete the node from beginning of active list */
		if(pxTempNode->unPrevIndex == 0)
		{
			/*Only one node in the active timer list */
			if(pxTempNode->unNextIndex == 0)
			{
				vx_UGW_TLIB_TimMgtInfo.unActTimLstHeadIndex = 0;
				printf("In Stop timer, timer called with 0 value\n");
				/*Stop the timer */
				UGW_TLIB_SetTimer(0);
			}
			/* Delete from the beginning of a list */
			else
			{
				
				vx_UGW_TLIB_TimMgtInfo.unActTimLstHeadIndex = pxTempNode->unNextIndex;
				pxNextTempNode = vx_UGW_TLIB_TimMgtInfo.pxTimerList +
					(vx_UGW_TLIB_TimMgtInfo.unActTimLstHeadIndex - 1);

				pxNextTempNode->unPrevIndex = 0;
				CLOCKT_CurrTick = UGW_TLIB_ConvertTicksToTime((CLOCKT_CurrTick-pxNextTempNode->uiTimerTick));
				if((int)pxNextTempNode->uiTimerValue > CLOCKT_CurrTick)
				{
					printf("In Stop timer, next timer is %d ms\n",(pxNextTempNode->uiTimerValue -CLOCKT_CurrTick)/1000);
					UGW_TLIB_SetTimer(pxNextTempNode->uiTimerValue -CLOCKT_CurrTick);
				}
			}

		}
		else
		{
			pxPrevTempNode = vx_UGW_TLIB_TimMgtInfo.pxTimerList +
					(pxTempNode->unPrevIndex - 1);

			/* Delete the node from end of list */
			if(pxTempNode->unNextIndex == 0)
			{
				pxPrevTempNode->unNextIndex = 0;
			}
			/* Delete from the middle of a list */
			else

			{
				pxNextTempNode = vx_UGW_TLIB_TimMgtInfo.pxTimerList +
						(pxTempNode->unNextIndex - 1);
				pxPrevTempNode->unNextIndex = pxNextTempNode->unTimerIndex;
				pxNextTempNode->unPrevIndex = pxPrevTempNode->unTimerIndex;

			}
			
		}
		
		
		/* Free the timer of active list and add it to free list of timers */
		UGW_TLIB_FreeListHandler(pxTempNode);

                if(vucTimerNotifyType == UGW_TLIB_NOTIFY_VIA_SIGNAL){	
		  pthread_mutex_unlock(&global_timer_mutex);
                }
                if(uiTimeLeft == 0){
                  return UGW_TLIB_SUCCESS;
                }else{
		  return uiTimeLeft;
                }
	}      
	else
	{
		
             if(vucTimerNotifyType == UGW_TLIB_NOTIFY_VIA_SIGNAL){	
               pthread_mutex_unlock(&global_timer_mutex);
             }
		return UGW_TLIB_FAIL;
	}

	
}
/******************************************************************************
*  Name: UGW_TLIB_ConvertTimeToTicks
*  Function: This function is called when timer has been expired
*  Input: None
*  Output:None
*  Return Value: none. 
******************************************************************************/

uint32 UGW_TLIB_ConvertTimeToTicks(uint32 uiTime){
	uint32 uiTimeinmsec =uiTime/1000;
	uint32 HZ = sysconf(_SC_CLK_TCK);
	if(uiTimeinmsec <= 1000){
		return  HZ/(1000/uiTimeinmsec); 
	}
	else{
		return  HZ*(uiTimeinmsec/1000);
	}
}
/******************************************************************************
*  Name: UGW_TLIB_ConvertTicksToTicks
*  Function: This function is called when timer has been expired
*  Input: None
*  Output:None
*  Return Value: none. 
******************************************************************************/

uint32 UGW_TLIB_ConvertTicksToTime(uint32 uiTicks){
	if(vucTimerNotifyType == UGW_TLIB_NOTIFY_VIA_SIGNAL){
		return uiTicks * 10000;
	}else{
		uint32 HZ = sysconf(_SC_CLK_TCK);
		return (uiTicks *1000/HZ)*1000; //Usec
	}   
}
/******************************************************************************
*  Name: CurrTimerExpiry
*  Function: This function is called when timer has been expired
*  Input: None
*  Output:None
*  Return Value: none. 
******************************************************************************/

void UGW_TLIB_CurrTimerExpiry( __attribute__((unused)) int signo)
{
	x_UGW_TLIB_TimerInfo *pxTempNode,*pxTempActTimLstHead;
	uint32 uiGetCurrTime;
       	//clock_t CLOCKT_TimeDiff;

	/* Get the current timer tick */
	uiGetCurrTime = UGW_TLIB_GetCurrTime();
		
	if(vucTimerNotifyType == UGW_TLIB_NOTIFY_VIA_SIGNAL){	
		pthread_mutex_lock(&global_timer_mutex);
	}
		
	if(vx_UGW_TLIB_TimMgtInfo.unActTimLstHeadIndex != 0)
	{
                
		pxTempActTimLstHead = vx_UGW_TLIB_TimMgtInfo.pxTimerList +
				(vx_UGW_TLIB_TimMgtInfo.unActTimLstHeadIndex - 1);
		if(vucTimerNotifyType != UGW_TLIB_NOTIFY_VIA_SIGNAL){
			printf("Timer ID that got fired is %d\n",pxTempActTimLstHead->unTimerIndex);
			printf(" The Current Time is %u	 and in the list is %u\n",
			uiGetCurrTime,pxTempActTimLstHead->uiTimerTick);
		}

			pxTempNode = pxTempActTimLstHead;
	
			if(pxTempNode->unNextIndex == 0)
			{
				vx_UGW_TLIB_TimMgtInfo.unActTimLstHeadIndex = 0;
			
				/* Noitfy timer expiry to the corresponding process */
				pxTempNode->pfn_UGW_TLIB_CallBackfn(pxTempNode->pCallBackFnParm);

				/* if the timer is periodic then restart it */	
				if(pxTempNode->ucTimerType == UGW_TLIB_PERIODIC_TIMER)
			 	{
					uiGetCurrTime = UGW_TLIB_GetCurrTime();
					pxTempNode->uiTimerTick = uiGetCurrTime;
					UGW_TLIB_InsertTimerIntoActList(pxTempNode,pxTempNode->uiTimerValue,
						pxTempNode->ucTimerType, pxTempNode->pfn_UGW_TLIB_CallBackfn,
						pxTempNode->pCallBackFnParm);
				}
				else
				{

					/* Free the timer from active list and add it to
						 free list of timers */
					UGW_TLIB_FreeListHandler(pxTempNode);
				}
			}
			else
			{
				UGW_TLIB_CheckForEqualTimer(uiGetCurrTime);

			}
	}

  if(vucTimerNotifyType == UGW_TLIB_NOTIFY_VIA_SIGNAL){	
	   pthread_mutex_unlock(&global_timer_mutex);
  }

}

/******************************************************************************
*  Name: UGW_TLIB_FreeListHandler
*  Function: This function adds released timer node at the end of
						 free list of timers
*  Input: pxTempNode
*  Output:None
*  Return Value: none. 
******************************************************************************/
void UGW_TLIB_FreeListHandler(x_UGW_TLIB_TimerInfo *pxTempNode)
{
	/*Reinitialize all fields in timer node */
	pxTempNode->ucFree = TRUE;
	pxTempNode->uiTimerValue = 0;
	pxTempNode->uiTimerTick = 0;
	pxTempNode->ucTimerType = 0;
	pxTempNode->pfn_UGW_TLIB_CallBackfn = NULL;
	pxTempNode->pCallBackFnParm = NULL;
	pxTempNode->unNextIndex = 0;

	/* If the Free list is empty */
	if((vx_UGW_TLIB_TimMgtInfo.unFreeTimLstHeadIndex == 0) &&
		 (vx_UGW_TLIB_TimMgtInfo.unFreeTimLstHeadIndex == 0))
	{
		pxTempNode->unPrevIndex = 0;
		vx_UGW_TLIB_TimMgtInfo.unFreeTimLstHeadIndex = pxTempNode->unTimerIndex;
	}
	else
	{
		vx_UGW_TLIB_TimMgtInfo.pxTimerList[vx_UGW_TLIB_TimMgtInfo. 
				unFreeTimLstTailIndex-1].unNextIndex = pxTempNode->unTimerIndex;
		pxTempNode->unPrevIndex = vx_UGW_TLIB_TimMgtInfo. 
			pxTimerList[vx_UGW_TLIB_TimMgtInfo.unFreeTimLstTailIndex-1]. 
								unTimerIndex;
	}
	/*Tail of free list should point to last node in a list */
	vx_UGW_TLIB_TimMgtInfo.unFreeTimLstTailIndex = pxTempNode->unTimerIndex;
	
	return;

}

/***************************************************************************
*  Name: UGW_TLIB_SetTimer
*  Function: This function starts the timer
*  Input: uiUsec
*  Output:None
*  Return Value: none. 
****************************************************************************/

void UGW_TLIB_SetTimer(uint32 uiUsec)
{
	if(vucTimerNotifyType == UGW_TLIB_NOTIFY_VIA_SIGNAL){
		struct itimerval nval,oval;
		sigset_t newmask,oldmask;

		nval.it_interval.tv_sec =0 ;
		nval.it_interval.tv_usec =0;		

		nval.it_value.tv_sec = uiUsec / 1000000;
		nval.it_value.tv_usec = uiUsec % 1000000;
	
		sigemptyset(&newmask);
		sigaddset(&newmask,SIGALRM);
		sigprocmask(SIG_BLOCK,&newmask,&oldmask);

		/*Set the Timer */
		setitimer(ITIMER_REAL, &nval, &oval);

		sigprocmask(SIG_SETMASK,&oldmask,NULL);
	}else{
		ioctl(vuiTimerLibFd,TIMER_DRV_MODE_CHANGE,(uiUsec/1000));//converting into msec
	}
}

/****************************************************************************
*  Name: UGW_TLIB_TimersDelete
*  Function: This function deletes the memory allocated for timers
*  Output:None
*  Return Value: none. 
*****************************************************************************/
int8 UGW_TLIB_TimersDelete(void)
{
	free(vx_UGW_TLIB_TimMgtInfo.pxTimerList);
	return UGW_TLIB_SUCCESS;
}

/****************************************************************************
*  Name: GetCurrTime
*  Function: This function gets the current tick since system has been started
*  Input : None
*  Output:None
*  Return Value: Current Tick
******************************************************************************/
uint32 UGW_TLIB_GetCurrTime(void)
{
	clock_t CLOCKT_Time;
	CLOCKT_Time = times(NULL);
	return ((uint32)CLOCKT_Time);
}

/*****************************************************************************
*  Name: UGW_TLIB_CheckForEqualTimer
*  Function: This function gets the current tick since system has been started
*  Input : uiCurrTime
*  Output:None
*  Return Value: success or fail.
******************************************************************************/
int8 UGW_TLIB_CheckForEqualTimer(uint32 uiCurrTime)
{
	x_UGW_TLIB_TimerInfo *pxTempNode,*pxTempActTimLstHead;
	uint32 uiCurrTimerValue,uiTimeDelay;	
	
	pxTempNode = vx_UGW_TLIB_TimMgtInfo.pxTimerList +
				(vx_UGW_TLIB_TimMgtInfo.unActTimLstHeadIndex - 1);
	printf("In Check for equal timers\n");
	while(pxTempNode->unNextIndex != 0)
	{
		
		/* Noitfy timer expiry to the corresponding process */
		pxTempNode->pfn_UGW_TLIB_CallBackfn(pxTempNode->pCallBackFnParm);
               /* Get the current timer tick - Without this you will face issue, if callback 
			function takes some time in execution */	
		uiCurrTime = UGW_TLIB_GetCurrTime();

		vx_UGW_TLIB_TimMgtInfo.unActTimLstHeadIndex = pxTempNode->unNextIndex;
		pxTempActTimLstHead = vx_UGW_TLIB_TimMgtInfo.pxTimerList +
				(vx_UGW_TLIB_TimMgtInfo.unActTimLstHeadIndex - 1);
		pxTempActTimLstHead->unPrevIndex = 0;

		
		/*Calculate Time elapsed for the next node */
		uiTimeDelay = UGW_TLIB_ConvertTicksToTime((uiCurrTime - pxTempActTimLstHead->uiTimerTick));
		
		/*Check next timer also been elapsed */
		if(pxTempActTimLstHead->uiTimerValue > uiTimeDelay)
		{
			uiCurrTimerValue = pxTempActTimLstHead->uiTimerValue - uiTimeDelay ;
		}
		else
		{
			uiCurrTimerValue = 0;
		}
		
		/* Checking for threshold of 1ms */
		if (uiCurrTimerValue > 1000) 
		{
			
			UGW_TLIB_SetTimer(uiCurrTimerValue);
			printf("CET - new timer started with %d ms\n",uiCurrTimerValue/1000);
			/* if the timer is periodic then restart it */			
			if(pxTempNode->ucTimerType == UGW_TLIB_PERIODIC_TIMER)
		 	{
				uiCurrTime = UGW_TLIB_GetCurrTime();
				pxTempNode->uiTimerTick = uiCurrTime;
				UGW_TLIB_InsertTimerIntoActList(pxTempNode,pxTempNode->uiTimerValue,
						pxTempNode->ucTimerType, pxTempNode->pfn_UGW_TLIB_CallBackfn,
						pxTempNode->pCallBackFnParm);
			}
			/* Free the timer from active list and add it to free list of timers */
			else
			{
			
				UGW_TLIB_FreeListHandler(pxTempNode);
			}

			
			break;
		}
		/* The next timer also been elapsed , so release that timer */
	  /* if the timer is periodic then restart it */
		if(pxTempNode->ucTimerType == UGW_TLIB_PERIODIC_TIMER)
		{
			pxTempNode->uiTimerTick = uiCurrTime;
			UGW_TLIB_InsertTimerIntoActList(pxTempNode,pxTempNode->uiTimerValue,
						pxTempNode->ucTimerType, pxTempNode->pfn_UGW_TLIB_CallBackfn,
					  pxTempNode->pCallBackFnParm);
		}
		/* Free the timer from active list and add it to free list of timers */
		else
		{
			
			UGW_TLIB_FreeListHandler(pxTempNode);
		}

		pxTempNode = pxTempActTimLstHead;

		/* The last node in the active list of timer */
		if(pxTempActTimLstHead->unNextIndex == 0)
		{
			vx_UGW_TLIB_TimMgtInfo.unActTimLstHeadIndex = 0;
			
			/* Noitfy timer expiry to the corresponding process */
		
			pxTempNode->pfn_UGW_TLIB_CallBackfn(pxTempNode->pCallBackFnParm);
			/* if the timer is periodic then restart it */
			if(pxTempNode->ucTimerType == UGW_TLIB_PERIODIC_TIMER)
			{
				pxTempNode->uiTimerTick = uiCurrTime;
				UGW_TLIB_InsertTimerIntoActList(pxTempNode,pxTempNode->uiTimerValue,
						pxTempNode->ucTimerType, pxTempNode->pfn_UGW_TLIB_CallBackfn,
					  pxTempNode->pCallBackFnParm);
			}
			/* Free the timer from active list and add it to free list of timers */
			else
			{
			
				UGW_TLIB_FreeListHandler(pxTempNode);
			}
			break;
		}
		
	}


	return UGW_TLIB_SUCCESS;
}

int8 IFIN_TLIB_TimersInit(uint16 unNumOfTimers)
{
	return UGW_TLIB_TimersInit( unNumOfTimers, UGW_TLIB_NOTIFY_VIA_SIGNAL);
}


int8 IFIN_TLIB_TimersDelete(void)
{
	return UGW_TLIB_TimersDelete();
}

int8 IFIN_TLIB_StartTimer(uint16 *punTimerId,uint32 uiTimerValue,
		uint8 ucTimerType, pfnVoidFunctPtr pfn_UGW_TLIB_CallBackfn,
		void *pCallBackFnParm)
{
		return UGW_TLIB_StartTimer(punTimerId, uiTimerValue,
		ucTimerType, pfn_UGW_TLIB_CallBackfn,
		pCallBackFnParm);
}

int32 IFIN_TLIB_StopTimer(uint16 unTimerId)
{
	return UGW_TLIB_StopTimer( unTimerId);
}
