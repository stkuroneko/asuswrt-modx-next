// XmlConfigParse.h: interface for the CXmlConfigParse class.
//
//////////////////////////////////////////////////////////////////////
#include "tinyxml.h"
#include "BMAGlobal.h"

#if !defined(AFX_XMLCONFIGPARSE_H__ED2C6C55_63AC_4CF2_9635_79D9D4D4E5A5__INCLUDED_)
#define AFX_XMLCONFIGPARSE_H__ED2C6C55_63AC_4CF2_9635_79D9D4D4E5A5__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

class CXmlConfigParse
{
public:
    CXmlConfigParse();
    virtual ~CXmlConfigParse();
    CXmlConfigParse(LPCTSTR strFileName);
    BOOL Success();//导入XML文件是否成功，在调用CXmlConfigParse(LPCSTR strFileName)后调用


public:
    virtual BOOL    Init(LPCTSTR lpszFileName,int nFlag = 0);
    virtual DWORD   GetProductCount();
    virtual void    GetProductNameList(LPTSTR pProductNameList,DWORD dwSize,DWORD &dwRealSize);
    virtual PPRODUCT_INFO_T  GetProdInfo(LPCTSTR lpszProductName);
    virtual LPCTSTR  GetConfigFile(LPCTSTR lpszProductName);
    virtual void    Release();

protected:
//  BOOL  LoadAllProductInfo(LPCTSTR lpszConfigBase);
    BOOL  _Init(LPCTSTR lpszConfigName);
    BOOL  _LoadProductInfo(LPCTSTR lpszConfigName,BOOL bChangePrdName= FALSE);
    void  _Close();
    void  Clear();

private:
    //XNode       m_xmlConfig;
    typedef std::map<std::string, int>   PRODUCT_ENABLE_MAP;
    PRODUCT_ENABLE_MAP m_mapProductEnable;
    typedef std::map<std::string, std::string> PRODUCT_CONFIG_FILE_MAP;
    PRODUCT_CONFIG_FILE_MAP m_mapPrdCfg;

    PRODUCT_MAP m_mapProductInfo;
    std::vector<std::string> m_aProductList;
    PPRODUCT_INFO_T m_pCurProduct;
    std::string m_strBaseConfig;


    BOOL        m_bOK;

};

#endif // !defined(AFX_XMLCONFIGPARSE_H__ED2C6C55_63AC_4CF2_9635_79D9D4D4E5A5__INCLUDED_)
