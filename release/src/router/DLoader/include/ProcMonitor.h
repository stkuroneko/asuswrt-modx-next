#ifndef CPROCMONITOR_H
#define CPROCMONITOR_H
#include "BootModeitf.h"

#include <string>
#include <vector>

using namespace std;

typedef enum DL_STAGE_ENUM
{
    DL_NONE_STAGE,
    DL_CHK_BAUD,
    DL_CONNECT,
    DL_REPARTITION_STAGE,
    DL_ERASE_FLASH,
    DL_DL_STAGE,
    DL_READ_STAGE,
    DL_RESET_STAGE,
    DL_READCHIPTYPE_STAGE,
    DL_READNVITEM_STAGE,
    DL_CHANGEBUAD_STAGE,
    DL_FINISH_STAGE,
    DL_UNPLUGGED_STAGE,
    DL_PAUSED,
    DL_KEEPCHARGE_STAGE,
    DL_POWEROFF_STAGE
}DL_STAGE;


class CProcMonitor:public IBMProcObserver
{
public:
    CProcMonitor();
    virtual ~CProcMonitor();
    virtual int OnMessage(UINT msgID,UINT wParam, void* lParam);
    BOOL SetStatus(int nPort,DL_STAGE stage, BOOL bNeedProc,
                   uint32_t nMin /* = 0 */,uint32_t nMax /* = 0 */);
    //void SetDLoader(CDLoader *pLoader){m_pDLoader = pLoader;}

    void AddStepDescription(char * str) {m_agStepDesc.push_back(str);}
    void SetProgPos(uint32_t nPort, uint32_t nPos);
    void SetStep(int nPort);
    void SetResult(int nPort,BOOL bSuccess, LPCTSTR lpszErrMsg = NULL);

protected:
    //CDLoader *m_pDLoader;
    vector<string> m_agStepDesc;
    DL_STAGE       m_stageLast;
    int            m_nCurMin;
    DWORD          m_nCurMax;
    int            m_nCurStep;
private:
};

#endif // CPROCMONITOR_H
