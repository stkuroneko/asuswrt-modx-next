#ifndef CSETTINGS_H
#define CSETTINGS_H

#include "typedef.h"
#include "BMAGlobal.h"
#include "BinPack.h"

#include <string>
#include <vector>

// Do repartition always
#define REPAR_STRATEGY_ALWAYS           0
// Stop actions and report error when incompatible partition error occured
#define REPAR_STRATEGY_STOP             1
// Ignore incompatible partition error
#define REPAR_STRATEGY_IGNORE           2
// Do repartion action when imcompatible partition error occured
#define REPAR_STRATEGY_DO               3

enum _FDL2_FALG{
	FDL2F_OMADM,
	FDL2F_PRELOAD,
	FDL2F_KERNELIMG2,
	FDL2F_ROMDISK
};

class CSettings
{
public:
    CSettings();
    virtual ~CSettings();
    //void SetDLoader(CDLoader *pLoader){m_pDLoader = pLoader;}
    BOOL LoadSettings(std::string &strErrorMsg);
    BOOL LoadPacket(LPCTSTR pFileName);
    void SetReplaceDLFiles(std::map<std::string,std::string>& mapReplaceDLFile);
    void SetReplacePolicy(int nReplacePolicy) {m_nReplacePolicy = nReplacePolicy;}
	void SetBackupFilePolicy(int nPolicy) {m_nBackupProdnvMiscdata = nPolicy;}
    BOOL LoadConfig();
    void SetNvBkFlag(BOOL bBackUp){m_bNvBkFlg=bBackUp;}
    void SetFileBkFlag(BOOL bBackup){m_bFileBkFlg = bBackup;}
    void SetPhaseCheckFlag(BOOL bPhaseCheck){m_bNeedPhaseCheck = bPhaseCheck;}
    void InitBackupFiles(FILE_INFO_T *pFileInfo, int nCount);
	BOOL NeedBackupMiscAndProdnvFile(){ return m_bFileBkFlg;}

    std::string GetCurProduct()
    {
        return m_strCurProduct;
    }

    int     GetDownloadFile( std::vector<std::string>& agFile );
    int		GetAllRFChipName(std::vector<std::string>& agChipNames,std::vector<DWORD> &agChipIDs);
    BOOL	GetRFChipID(const std::string& strName,DWORD& dwChipID);
    BOOL	GetRFChipName(const DWORD& dwChipID, std::string& strName);

    int     GetRepartitionFlag();
    int     GetFlashPageType();
    int     GetNvNewBasePosition();
    int     GetFileInfo(LPCTSTR lpszFileID, void** ppFileInfo);

    std::string GetDownloadFilePath(LPCTSTR lpszFileID);
    int     GetNvBkpItemCount();
    PNV_BACKUP_ITEM_T GetNvBkpItemInfo(int nIndex);

    BOOL    IsNandFlash();  // if NAND return true, NOR return false
    BOOL    IsMainPageInit();
    BOOL    IsBackupNV();         //for NV page
    BOOL    IsNvBaseChange();
    BOOL    IsReadFlashInFDL2();

    BOOL    IsNVSaveToLocal();
    std::string GetNVSavePath();

    BOOL    IsBackupLang();
    BOOL    IsHasLang();
    WORD    GetLangNVItemID();

    BOOL    IsNVOrgDownload();
    int     GetNVOrgBasePosition();

    BOOL    IsOmaDM();

    int     GetAllFileID(std::vector<std::string> &agFileID);

    BOOL    IsEraseAll();

    BOOL    IsReset();

    BOOL    IsNeedCheckNV();

    int     GetBackupFiles(std::vector<std::string> &agID);

    int     IsBackupFile(LPCTSTR lpszFileID);

    BOOL    IsNeedRebootByAT();
    BOOL    IsNeedPhaseCheck();
    BOOL    IsDoReport();
    BOOL    IsNeedEnableWriteFlash(){ return m_bEnableWriteFlash;}

    void    GetIMEIIDs(std::vector<UINT> &agID);
    DWORD   GetMaxNVLength();

    void    DelTmpDir();

    int     GetDLNVID(std::vector<std::string> &agID);
    int     GetDLNVIDIndex(LPCTSTR lpszFileID);

    BOOL    IsKeepCharge();
    BOOL	  IsPowerOff();
    BOOL    IsBackupNVFile(LPCTSTR lpszFileID);
    BOOL    HasPartitionInfo();
    LPBYTE  GetPartitionData(DWORD &dwSize);

	BOOL HasExtTblInfo();
	LPBYTE GetExtTblData(DWORD &dwSize);
	BOOL ConvertPtnInfoID(PARTITION_INFO_PTR pPart);

    void    SetResetFlag(BOOL bReset);
    void    SetKeepChargeFlag(BOOL bKeepCharge);
    void  	SetPowerOff(BOOL bPowerOff);
    BOOL    ConvertPartID(PARTITION_T *pPart);
    BOOL    IsMapPBFileBuf();
    BOOL    IsEnableRFChipType();
    int      GetAllFileInfo(void** ppFileInfo);
	int 	_GetBackupFiles(std::vector<std::string> &agID, BOOL bNV);
	BOOL 	GetFdl2Flag(LPCTSTR lpszFilePath,UINT nType);

    std::string m_strCurProduct;
    std::string m_strSpecConfig;
    std::string m_strReleaseDir;


protected:
    //CDLoader *m_pDLoader;
    std::map<std::string,std::string> m_mapDLFiles;
    std::map<std::string,UINT> m_mapDLState;
    std::map<std::string,__int64> m_mapDLSize;
    std::string m_strPrdVersion;
    BIN_PACKET_HEADER_T m_bph;

    PPRODUCT_INFO_T  m_pCurProductInfo;
    std::vector<FILE_INFO_T> m_vBackupFiles;

private:
    BOOL m_bReset;
    BOOL m_bKeepCharge;
    BOOL m_bRepart;
    BOOL m_bNvBkFlg;
    BOOL m_bFileBkFlg;
    BOOL m_bNeedPhaseCheck;
    BOOL m_bOmaDM;
    BOOL m_bPowerOff;
    BOOL m_bEnableWriteFlash;
    DWORD m_dwMaxNVLength;
    int 	  m_nReplacePolicy;
    int       m_nBackupProdnvMiscdata;
	
private:
	void 				LoadConfigFile();

};

#endif // CSETTINGS_H
