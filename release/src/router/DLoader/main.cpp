/*#include <QtCore/QCoreApplication>
#include <QString>*/

#include <stdlib.h>
#include <stdio.h>

#include <iostream>
#include <unistd.h>
#include "TTYComm.h"
#include "Test.h"
#include <string.h>
#include <DLoader.h>
#include <stdarg.h>
#include <dirent.h>

#include <errno.h>
#include "typedef.h"
#include <string>
#include <fcntl.h>
#include <sys/file.h>
#define TRUE     1
#define FALSE    0
#define _T(x)     x
#define _tprintf   printf

//-pac "/mnt/hgfs/ubuntu-share/Linux/pac/sp6821a_gonk4.0_user.pac" -dev "/dev/ttyUSB0" -baud 460800 -reset -nvbk false

using namespace std;

enum
{
	DOWNLOAD_OK = 0,
	DOWNLOAD_ERRPARAM,
	DOWNLOAD_ERRLSTARTDLOADER,
	DOWNLOAD_ERRDOWNLOAD,
	DOWNLOAD_ERR_DETECT_DUT,
	/* insert here new errors */
	DOWNLOAD_ERRMAX
};

typedef void *(*PTHREAD_START_ROUTINE) (void *);
const char SZDLVERINFO[100] = "DLoader version is R1.20.1101,build on 20200309.\n";

bool readline(const char *mbuf, int maxlen,char *buf, int& nstartPos);
BOOL IsAvailableDev(char* szDevPath);
std::string find_dl_device(char* szDevKeyWord);
#if 1
void WaitExit(void * param)
{
    CDLoader *pdl = (CDLoader *)param;
    char c;

    do{
        c = getchar();
    }while(c != 'q' && c != 'Q' && !pdl->IsEnd());

    pdl->SetEnd(TRUE);
}


void ShowUsage()
{
	printf(SZDLVERINFO);
    	printf("\nusage: sudo ./DLoader <command> [ <option> ]; e.g.  sudo ./DLoader -pac ./test.pac\n\n");
	printf("commands and option:\n");
	printf("-pac <pac-path>			*download pac file\n");
	printf("[-dev <dev-path>]		download port,default auto find the available device. e.g. /dev/ttyUSB0\n");
	printf("[-baud <baud-rate>]            	set baud-rate,invalid for usb downlad\n");
	printf("[-nvbk false|true]		backup nv option,default backup nv\n");
	printf("[-filebk false|true]		backup need backup partition\n");
	printf("[-phasecheck]			flash phasecheck,default randomly generated SN\n");
	printf("[-SN sn]			set a sn\n");
	printf("[-KeepCharge] 	              	support usb power supply\n");	
	printf("[-PowerOff]			power off device after download\n");
	printf("[-reset]			reset device to normal after download\n");
	printf("[-auto]		             	auto download mode\n\n");
}

static int nPortCookie = 0;
BOOL IsNum(string str)
{
	for(int i=0;i<str.length();i++)
	{
		if(str[i]<'0' || str[i]>'9')
		{
			return FALSE;
		}

	}
	return TRUE;
}
BOOL IsValidSN(const char* pszSN)
{
	BOOL bValid = FALSE;
	do
	{
		if(strlen(pszSN) > X_SN_LEN)
		{
			printf("SN maximum length can't more than 24 bytes!\n");
			break;
		}
		/*
		if(!IsNum(pszSN))
		{
			printf("Invalid SN, Must be full for the digital SN!\n");
			break;
		}*/
		bValid = TRUE;
	}while(0);
	return bValid;
}

std::string CReplace(std::string& strOrg,std::string strFind,std::string strReplace)
{
	std::string::size_type nPos			= 0;
	std::string::size_type nFindLen		= strFind.size();
	std::string::size_type nReplaceLen	= strReplace.size();
	
	while( (nPos = strOrg.find(strFind,nPos) ) != std::string::npos )
	{
		strOrg.replace(nPos,nFindLen,strReplace);
		nPos += nReplaceLen;
	}
	return strOrg;
}

int main(int argc, char *argv[])
{
	int nRetCode 			= 1;
	char szDev[MAX_PATH] 	= {0};
	char szPac[MAX_PATH] 	= {0};
	int  nBaudRate 			= DEFAULT_BAUDRATE;
	BOOL bReset 				= FALSE;
	BOOL bKeepCharge		= FALSE;
	BOOL bPowerOff			= FALSE;
	BOOL bBackUpNv			= TRUE;
	BOOL bBackupFile 		= TRUE;
	bool bManualDl 			= true;
	BOOL bPhaseCheck 		= FALSE;
	char   szSN[X_SN_LEN+1] 	= {0};
	int i = 0;
	std::map<std::string,std::string> mapReplaceDLFiles;
    	if(argc>=2 &&_tcsicmp(argv[1],_T("version")) == 0)
	{
		printf(SZDLVERINFO);
		return 0;
	}
	for(i = 1; i< argc; i++)
	{
		if(_tcsicmp(argv[i],_T("-dev")) == 0)
		{
			if( (i+1) < argc )
			{
			    //strDev = argv[++i];
			    strcpy(szDev,argv[++i]);
			}
			else
			{
			    printf("parameters error -dev.\n\n");
			    ShowUsage();
			    return 1;
			}
		}
		else if(_tcsicmp(argv[i],_T("-pac")) == 0)
		{
			if( (i+1) < argc )
			{
			    //strPac = argv[++i];
			    strcpy(szPac,argv[++i]);
			}
			else
			{
			    printf("parameters error -pac.\n\n");
			    ShowUsage();
			    return 1;
			}
		}
		else if(_tcsicmp(argv[i],_T("-baud")) == 0)
		{
			if( (i+1) < argc )
			{
			    //strPac = argv[++i];
			    nBaudRate = atoi(argv[++i]);
			    if(nBaudRate <= 15200)
			    {
			        printf("parameters error -baud.\n\n");
			        ShowUsage();
			        return 1;
			    }
			}
			else
			{
			    printf("parameters error -baud.\n\n");
			    ShowUsage();
			    return 1;
			}
		}
		else if(_tcsicmp(argv[i],_T("-reset")) == 0)
		{
			bReset = TRUE;
		}
		else if(_tcsicmp(argv[i],_T("-KeepCharge")) == 0)
		{
			bKeepCharge = TRUE;
		}
		else if(_tcsicmp(argv[i],_T("-PowerOff")) == 0)
		{
			bPowerOff = TRUE;
		}
		else if(_tcsicmp(argv[i],_T("-nvbk")) == 0)
		{
			if((i+1) < argc && _tcsicmp(argv[++i],_T("false") )==0)
			{
			 	bBackUpNv = FALSE;
			}
		}
		else if(_tcsicmp(argv[i],_T("-auto")) == 0)
		{
			bManualDl = false;
		}
		else if(_tcsicmp(argv[i],_T("-filebk")) == 0)
		{
			if((i+1) < argc && _tcsicmp(argv[++i],_T("false") )==0)
			{
				bBackupFile = FALSE;
			}
		}
		else if(_tcsicmp(argv[i],_T("-phasecheck")) == 0)
		{
			bPhaseCheck = TRUE;
		}
		else if(_tcsicmp(argv[i],_T("-SN")) == 0)
		{
			if( (i+1) < argc  && IsValidSN(argv[++i]))
			{
				strcpy(szSN,argv[i]);
				printf("szSN=%s\n",szSN);
			}
			else
			{
				printf("parameters error -SN.\n\n");
				ShowUsage();
				return 1;
			}
		}
		else
		{
			TCHAR* pszPara = argv[i];
			if ( pszPara[0] == _T('-'))  // -FileID File
			{
				++pszPara;
				TCHAR szID[MAX_PATH] = {0};
				strcpy(szID,pszPara);
				if( (i+1) < argc && 0 == access(argv[i+1], NULL) )
				{
					mapReplaceDLFiles[strupr(szID)] = argv[++i];
				}
				else	// -FileID
				{
				    mapReplaceDLFiles[strupr(szID)] = "";
				}
			}
		}

	}
	if( 0 == strlen(szPac) || 0 != access(szPac, NULL) )
	{
        //printf("parameters error,Mustbe input pac file.\n");
        ShowUsage();
        return DOWNLOAD_ERRPARAM;
	}

	int nDownloadRet = DOWNLOAD_ERRLSTARTDLOADER;
	printf("PAC: %s\nBAUD: %d,bBackUpNv=%d\n\n", szPac,nBaudRate,bBackUpNv);


	//stop modemmanager services
	//system("sudo apt-get remove modemmanager");

	system("nvram set mobile_upgrade_process=-1");

	pthread_t nThread = 0;
	CDLoader dl;
	dl.m_Settings.SetResetFlag(bReset);
	dl.m_Settings.SetKeepChargeFlag(bKeepCharge);
	dl.m_Settings.SetPowerOff(bPowerOff);
	dl.m_Settings.SetNvBkFlag(bBackUpNv);
	dl.m_Settings.SetFileBkFlag(bBackupFile);
	dl.m_Settings.SetPhaseCheckFlag(bPhaseCheck);
	dl.SetSNString(szSN);
	//char c;
	printf("Init Downloading...\n");
	//printf("Allen: fibocom debug............................................\n");
	if( dl.LoadPacket(szPac) )
	{
        /*====================================================================*/
	    //printf("dl.LoadPacket(szPac) is TRUE\n");
		char c;

        // Opened by allen 2020-9-9
#if 0
	     if (bManualDl)
		{
		    printf("if ----- Opened by allen 2020-9-9\n");
		    printf("Please make the device enter download mode and plugin it.\n");
		    printf("Then input 'enter' key to start downloading.\n");
		    c = getchar();
		} else {
		    printf("else ----- Opened by allen 2020-9-9\n");
		    printf("auto mode.\n");
		    printf("Then input 'enter' key to continue.\n");
		    c = getchar();
        }
        /*====================================================================*/
#endif
		//printf("[%s]: mapReplaceDLFiles.size\n", __func__);
		if( mapReplaceDLFiles.size() )
		{
		   // printf("[%s]: SetReplaceDLFiles...\n", __func__);
			dl.SetReplaceDLFiles( mapReplaceDLFiles);
		}
		if ( dl.InitDownload() )
		{
			if (!bManualDl)
			{
				char szEntryCmd[MAX_PATH] 	= {0};
				strcpy(szEntryCmd,dl.GetEntryCmd().c_str());
				if( 0 == strlen(szEntryCmd) )
				{
					strcpy(szEntryCmd,"./adb shell reboot autodloader");
				}
				else
				{
				    std::string strTmp = dl.GetEntryCmd();// ./adb %s shell reboot autodloader
				    char szTempSN[MAX_PATH] = {0};
					   
					if ( strlen(szSN) )
					{					
						sprintf(szTempSN,"-s %s ",szSN);			
					}
					strTmp = CReplace(strTmp,"%s",szTempSN);
					strcpy(szEntryCmd,strTmp.c_str());
				}
				system(szEntryCmd);
				_sleep(1000);
			}
			else
			{
				printf("Please make the device enter download mode and plugin it.\n");
			}

			printf("\033[?25l"); //���ع��
			UINT nCookie = ++nPortCookie;
			//clock_t c_start, c_end;
			//c_start = clock();

			///Find DL Dev
			BOOL bFindDev = FALSE;
			std::string strDevPath;
		
			if( 0 == strlen(szDev) )
			{
			    strcpy(szDev,dl.GetDLDevCfg().c_str());
				if( 0 == strlen(szDev) )
				{
					strcpy(szDev,"/dev/ttyUSB");
				}
			}
			
            //Allen
           // char c;

           // printf("Then input 'enter' key to continue...\n");
            //c = getchar();
            //===================

			pthread_create(&nThread,NULL,(PTHREAD_START_ROUTINE)WaitExit, (void*)&dl);
			printf("Detecting download devices [%s]...\n",szDev);
			do
			{
				strDevPath = find_dl_device(szDev);
				
				if(!strDevPath.empty())
				{
					bFindDev = TRUE;
					printf("Dev:%s\n",strDevPath.c_str());
				}
				else if (dl.IsEnd())
				{
					nDownloadRet = DOWNLOAD_ERR_DETECT_DUT;
					break;
				}
				else
				{
					_sleep(500);
				}
					
			}while(!bFindDev);
			///end find dev
			unsigned long uStart = GetTickCount();
			BOOL bSecondEnum= dl.m_bPortSecondEnum;
		       if( bFindDev && dl.StartDownload(strDevPath.c_str(),nBaudRate,nCookie))
		       {
		       	printf("Dev [%s] is StartDownloading...\n", szDev);

	_SECOND_ENUM:
		            while(!dl.IsEnd())
		            {
		                _sleep(1000);
		            }

		            dl.StopDownload(nCookie);
				if(dl.IsDownloadPass())
				{
					nDownloadRet = DOWNLOAD_OK;
				}

				if(bSecondEnum)
				{	
					nDownloadRet = DOWNLOAD_ERRLSTARTDLOADER;
					bSecondEnum = FALSE;
					dl.SetEnd(FALSE);
					_sleep(dl.m_nEnumPortTimeOut);
					dl.StartDownload(strDevPath.c_str(),nBaudRate,nCookie);
					goto _SECOND_ENUM;
				}

			            
		            // c_end = clock();
		            printf( "CPS=%d\n", CLOCKS_PER_SEC );
		            //printf( "Download elapsed time is %.3f s\n", (double)( c_end - c_start )/CLOCKS_PER_SEC );
		            //printf( "Download elapsed time is %d s\n",(int)((GetTickCount() -uStart)/1000));

		        }

			pthread_cancel(nThread);
			pthread_join(nThread,NULL);
			nThread = NULL;
		}
  	} else {
	    printf("dl.LoadPacket(szPac) = false\n");
    }

	dl.m_Settings.DelTmpDir();
	printf("\033[?25h"); //��ʾ���
	return nDownloadRet;
}
#endif



bool readline(const char *mbuf, int maxlen,char *buf, int& nstartPos)
{
	bool bOK = false;
	int nLen = 0;
	while(nstartPos+nLen<maxlen-1 && *(mbuf+nstartPos+nLen)!='\n')
	{
	    *(buf+nLen)=*(mbuf+nstartPos+nLen);
	    ++nLen;
	}
	*(buf+nLen)='\0';
	nstartPos += nLen;
	nstartPos += 1;
	bOK = (nstartPos<maxlen) ? true : false;
	return bOK;
}

BOOL IsAvailableDev(char* szDevPath)
{
	BOOL bAvailable = FALSE;
	int fd = -1;
	//printf("Check IsAvailableDev:%s\n",szDevPath);
	char szChmod[MAX_PATH] = {0};
	sprintf(szChmod,_T("chmod 777 %s"),szDevPath);
	system(szChmod);
	fd = open(szDevPath,O_RDWR|O_NOCTTY);
	
	int nRet = -1;
	
	if (fd  != -1 ) 
	{
		if(-1 !=flock(fd,LOCK_EX|LOCK_NB))
		{
			bAvailable = TRUE;
			flock(fd, LOCK_UN);
		}
		close(fd);
		fd = -1;	
	}
	else
	{
		//printf("Can not open device \"%s\", error code: %d,\"%s\"\n",szDevPath,errno,strerror(errno));
	}
	return bAvailable;
}
std::string find_dl_device(char* szDevKeyWord)
{
	std::string strDlDev;
    char szPara[MAX_PATH] 	= {0};
    char szLsDevFile[MAX_PATH] = {0};
	sprintf(szLsDevFile,_T("/tmp/_List_dev_%d.dev"),GetCycleCount());

	remove(szLsDevFile);
	string strKey("/dev/ttyUSB");
	if(szDevKeyWord && 0 < strlen(szDevKeyWord))
	{
		sprintf(szPara, _T("ls /dev/* | grep %s > %s"),szDevKeyWord,szLsDevFile);
	}
	else
	{
		sprintf(szPara, _T("ls /dev/* > %s"),szLsDevFile);
	}
	//sprintf(szPara, _T("ls /dev/* > %s"),szLsDevFile);
	if(szDevKeyWord && 0 < strlen(szDevKeyWord))
	{	
		strKey = szDevKeyWord;
		int nIndex = strKey.find("*");
		if(string::npos != nIndex)
		{
			strKey = strKey.substr(0,nIndex);
		}
		
	}
	system(szPara);

	FILE* pFile = NULL;
	BYTE* pBuf  = NULL;
	do
	{
		//Open file
		pFile = fopen(szLsDevFile,_T("r"));
		if(NULL == pFile)
		{
		   // _tprintf(_T("Open file [%s] failed,error code: %d,\"%s\""),szLsDevFile,errno,strerror(errno));
		    break;
		}

		//Get File Size
		__int64   llSize = 0;
		fseek(pFile,0,SEEK_END);
		llSize =  ftello64(pFile);
		if(-1 == llSize || 0 == llSize)
		{
		    //_tprintf(_T("GetFileSize [%s] failed,error code: %d,\"%s\""),szLsDevFile,errno,strerror(errno));
		    break;
		}

		fseek(pFile,0,SEEK_SET);
		//_tprintf(_T("size=%lld\n"),llSize);
	    /*
		pBuf = new BYTE[llSize];
		if(NULL == pBuf)
		{
			break;
		}
		fread(pBuf,1,llSize,pFile);

		int nStartPos = 0;
		int i = 1;
		BYTE    byReadBuf[MAX_PATH] = {0};
		while(readline((char *)pBuf,llSize,(char *)&byReadBuf,nStartPos) )
		{
			//printf("line%d=%s,key=%s\n",i,(char *)byReadBuf,strKey.c_str());
			string strTmp((char *)&byReadBuf);
			if( string::npos != strTmp.find(strKey.c_str())  && IsAvailableDev((char *)&byReadBuf))
			{
				strDlDev = (char *)&byReadBuf;
				break;
			}
			memset(byReadBuf,0,MAX_PATH);
			++i;
		}
		*/
		//* 02
		char ch;
    	int len = 0;
		int i = 1;
		char szLine[1024] 	= {0};
		while((ch = getc(pFile) ) != EOF)
		{
			if(ch == '\n')
		    {
		    	//printf("Line%d=%s,key=%s\n",i,szLine,strKey.c_str());
				string strTmp(szLine);
				if( string::npos != strTmp.find(strKey.c_str()) && IsAvailableDev(szLine) )
				{
					//printf("Find line%d=%s\n",i,szLine);
					strDlDev = szLine;
					break;
				}
		        memset(szLine,0,1024);
				len = 0;
				++i;
		    }
			else
			{	
				szLine[len++] = ch;
		        szLine[len] = '\0';
			}
		}


	} while (0);


	if(NULL != pFile)
	{
	    fclose(pFile);
	    pFile = NULL;
	}
	if(NULL != pBuf)
	{
	    delete[] pBuf;
	    pBuf = NULL;
	}
	remove(szLsDevFile);
	return strDlDev;
}
