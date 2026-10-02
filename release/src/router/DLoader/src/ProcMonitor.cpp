#include "ProcMonitor.h"
#include <stdio.h>
#include <cstdlib>

static std::string StatusString[] =
{
	"Waiting",
	"Checking baudrate",
	"Connecting",
	"Repartition...",
	"Erasing flash",
	"Downloading...",
	"Reading Flash...",
	"Reseting",
	"Read Chip Type",
	"Read NV Item",
	"Change Baud",
	"Finish",
	"Unplugged",
	"Paused",
	"KeepCharge",
	"PowerOff"
};

IBMProcObserver::IBMProcObserver()
{

}

IBMProcObserver::~IBMProcObserver()
{

}

CProcMonitor::CProcMonitor()
{
    //ctor
    m_stageLast = DL_NONE_STAGE;
    m_nCurMin = 0;
    m_nCurMax = 1;
    m_nCurStep = -1;
}

CProcMonitor::~CProcMonitor()
{
    //dtor
}

int CProcMonitor::OnMessage(UINT msgID,UINT wParam, void* lParam)
{
    switch(msgID)
    {
    case BM_CHECK_BAUDRATE:
        SetStatus( wParam, DL_CHK_BAUD,FALSE,0,0);
        break;
    case BM_CONNECT:
        SetStatus( wParam, DL_CONNECT,FALSE,0,0);
        break;
    case BM_REPARTITION:
        SetStatus( wParam, DL_REPARTITION_STAGE,FALSE,0,0);
        break;
    case BM_ERASE_FLASH:
        SetStatus( wParam, DL_ERASE_FLASH,FALSE,0,0);
        break;
    case BM_DOWNLOAD:
        SetStatus( wParam, DL_DL_STAGE,TRUE,0,(DWORD)lParam);
        break;
    case BM_DOWNLOAD_PROCESS:
        SetProgPos(wParam,(DWORD)lParam);
        break;
    case BM_READ_FLASH:
        SetStatus( wParam, DL_READ_STAGE,TRUE,0,(DWORD)lParam);
        break;
    case BM_READ_FLASH_PROCESS:
        SetProgPos( wParam, (DWORD)lParam );
        break;
    case BM_RESET:
        SetStatus( wParam, DL_RESET_STAGE,FALSE,0,0);
        break;
    case BM_CHANGE_BAUD:
        SetStatus( wParam, DL_CHANGEBUAD_STAGE,FALSE,0,0);
        break;
    case BM_BEGIN:
        m_nCurStep = -1;
        SetStatus( wParam, DL_NONE_STAGE,FALSE,0,0);
        break;
    case BM_FILE_BEGIN:
        SetStep( wParam );
        break;
    case BM_END:
        SetResult( wParam, TRUE, (LPCTSTR)lParam );
        break;
    case BM_KEEPCHARGE:
        SetStatus( wParam, DL_KEEPCHARGE_STAGE,FALSE,0,0);
        break;
      case BM_POWEROFF:
	{
		int nCount = m_agStepDesc.size();

		if(nCount > 0)
		{
			m_nCurStep = nCount - 1;
		}
		
		SetStatus( wParam, DL_POWEROFF_STAGE,FALSE,0,0);
	}
        break;
    }
    fflush(stdout);

    //Allen
printf("\033[?25h"); //显示光标
//printf("\033[?25l"); //隐藏光标
    return 0;
}

BOOL CProcMonitor::SetStatus(int nPort,DL_STAGE stage, BOOL bNeedProc,
                             uint32_t nMin /* = 0 */,uint32_t nMax /* = 0 */)
{
    //printf("Allen [%s] enter.\n", __func__);

    if( m_stageLast == DL_FINISH_STAGE && m_stageLast == DL_UNPLUGGED_STAGE )
    {
        // Ignore this message
        return TRUE;
    }

    m_stageLast = stage;
    m_nCurMin = nMin;
    m_nCurMax = nMax;

    int nStep = m_nCurStep;
    if(nStep == -1)
    {
        nStep = 0;
    }

    if(!bNeedProc)
    {
        printf("\n");

        //printf("Allen [%s] if nStep = %d, stage = %d.\n", __func__, nStep, stage);
        printf("%-20s %s ",m_agStepDesc[nStep].c_str(),StatusString[stage].c_str());
    }
    else
    {
        printf("\n");
        //printf("Allen [%s] else nStep = %d, stage = %d.\n", __func__, nStep, stage);
        printf("%-20s %s      ",m_agStepDesc[nStep].c_str(),StatusString[stage].c_str());
    }

    return TRUE;
}

void CProcMonitor::SetProgPos(uint32_t nPort, uint32_t nPos)
{
    if(m_nCurMax>0)
    {
        printf("\b\b\b\b\b(%02d%%)", nPos);//(uint32_t)(((uint64_t)nPos)*100/(uint64_t)m_nCurMax));
    }

}

void CProcMonitor::SetStep(int nPort)
{
    m_nCurStep++;
    int nCount = m_agStepDesc.size();
    unsigned int percent = 0;
    char nvramcmd[128];

    if(nCount > 0)
    {
       
        m_nCurStep = m_nCurStep%nCount;
    }
    percent = (m_nCurStep*100/nCount);
    /*printf("[%s] m_nCurStep = %d, nCount = %d.\n", __func__, m_nCurStep, nCount);*/
    /*printf("[%s] percent = %d%.\n", __func__, percent);*/
    memset(nvramcmd,'\0',sizeof(nvramcmd));
    snprintf(nvramcmd, sizeof(nvramcmd), "nvram set mobile_upgrade_process=%d", percent);
    system(nvramcmd);
}

void CProcMonitor::SetResult(int nPort,BOOL bSuccess, LPCTSTR lpszErrMsg)
{
    bSuccess = FALSE;
    if(lpszErrMsg == NULL)
    {
        bSuccess = TRUE;
    }

    if(bSuccess)
    {
        printf("\n\ndownload success.\n\n");
        system("nvram set mobile_upgrade_process=100");
    }
    else
    {
        if(lpszErrMsg != NULL && strlen(lpszErrMsg)!=0)
        {
            printf("\n\ndownload fail: [%s] %s\n\n",m_agStepDesc[m_nCurStep].c_str(),lpszErrMsg);
        }
        else
        {
            printf("\n\ndownload fail.\n\n");
        }
        system("nvram set mobile_upgrade_now=1");

    }
}
